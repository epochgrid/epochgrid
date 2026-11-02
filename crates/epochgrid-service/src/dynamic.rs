use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    auth_callout::{self, Callout, Config},
    identity::IdentityStore,
    identity_model::AuthRegistry,
    revocation, transparency, transport,
    wire::{self, Body},
};
use futures_util::StreamExt;
use std::{path::Path, time::Duration};

pub fn init(home: &Path, options: &crate::deployment_setup::InitOptions) -> Result<()> {
    crate::deployment_setup::initialize(home, options)
}
/// Repair durable lifecycle state before opening admission after a partial operation.
async fn repair_state(
    registry: &AuthRegistry,
    client: &async_nats::Client,
    log: &async_nats::jetstream::kv::Store,
    directory: &async_nats::jetstream::kv::Store,
    key: &nkeys::KeyPair,
) -> Result<()> {
    let registrations = transparency::read(log).await?;
    for revoked in revocation::read(log, &registrations).await?.keys() {
        registry.revoke(&revoked)?;
    }
    let enrollment = registry.historical_enrollment()?;
    for registration in registry.registrations()? {
        publish_registration(
            registry,
            log,
            directory,
            &enrollment,
            key,
            registration.clone(),
            false,
        )
        .await?;
        registry.activate(&registration.payload.nats_public_key)?;
    }
    epochgrid_core::authorization::reconcile_consumers(registry, client).await
}

struct AuthTask(tokio::task::JoinHandle<Result<()>>);
impl Drop for AuthTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub async fn serve(home: &Path, url: &str, path: &Path) -> Result<()> {
    if epochgrid_core::tls::TlsConfig::from_env()?.profile
        == epochgrid_core::tls::Profile::Production
    {
        let report = epochgrid_core::validation::offline(home, path, Some(url));
        ensure!(
            report.success,
            "production startup local validation failed:\n{}",
            report.human()
        );
    }
    ensure!(
        epochgrid_core::tls::TlsConfig::from_env()?.profile
            == epochgrid_core::tls::Profile::Development,
        "production requires separate authority/control accounts: run role-bind, worker-configure, serve-authority and serve-control; see docs/backend-role-contract.md"
    );
    ensure!(
        !home.join(crate::roles::BINDINGS).exists(),
        "role-bound homes require serve-authority"
    );
    serve_inner(home, url, path, None).await
}

pub async fn authority(home: &Path, url: &str, path: &Path) -> Result<()> {
    let bindings = crate::roles::Bindings::load(home)?;
    serve_inner(home, url, path, Some(bindings)).await
}

async fn serve_inner(
    home: &Path,
    url: &str,
    path: &Path,
    bindings: Option<crate::roles::Bindings>,
) -> Result<()> {
    let production = epochgrid_core::tls::TlsConfig::from_env()?.profile
        == epochgrid_core::tls::Profile::Production;
    let manifest = if production {
        let report = epochgrid_core::validation::offline(home, path, Some(url));
        ensure!(
            report.success,
            "production startup local validation failed:\n{}",
            report.human()
        );
        Some(epochgrid_core::deployment::DeploymentManifest::load(home)?)
    } else {
        None
    };
    let _runtime = crate::roles::runtime_lock(home)?;
    let config = Config::load(path)?;
    config.check_transport(url)?;
    if config.development_plaintext {
        tracing::warn!("DEVELOPMENT ONLY: unencrypted client transport enabled");
    }
    // Resolve every local credential before opening subscriptions/admission.
    let capacity = epochgrid_core::capacity::Capacity::load_or_default(home)?;
    let mut control_rate = epochgrid_core::capacity::RateLimit::new(
        capacity.requests_per_second,
        capacity.request_burst,
        std::time::Instant::now(),
    );
    let mut revocation_rate =
        epochgrid_core::capacity::RateLimit::new(4, 8, std::time::Instant::now());
    let mut callout = Callout::new(config.clone())?.with_capacity(&capacity);
    if let Some(bindings) = &bindings {
        callout = callout.with_worker(bindings.worker_nkey.clone())?;
    }
    // Bind and lock before opening network subscriptions. The listener never
    // receives signing keys, registry handles or credential references.
    let admission = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let diagnostics = std::sync::Arc::new(crate::diagnostics::Runtime::new(admission.clone())?);
    callout = callout.with_diagnostics(diagnostics.auth.clone());
    let mut local = bindings
        .as_ref()
        .map(|bindings| crate::roles::Server::bind(bindings, diagnostics.clone()))
        .transpose()?;
    let separated = local.is_some();
    let identity = IdentityStore::open(&home.join("control"))?;
    let key = identity.nkey()?;
    ensure!(
        key.public_key() == config.control_nkey,
        "control identity does not match callout configuration"
    );
    let auth_client = tokio::time::timeout(Duration::from_secs(5), config.connect(url)).await??;
    if production {
        ensure!(
            auth_client.server_info().max_payload == wire::MAX_WIRE,
            "capacity contract requires server max_payload 65536"
        );
    }
    let mut requests = auth_client
        .queue_subscribe(auth_callout::SUBJECT, "epochgrid-auth".into())
        .await?;
    tokio::time::timeout(Duration::from_secs(5), auth_client.flush()).await??;
    let auth_registry = AuthRegistry::open(home)?;
    let admission_worker = admission.clone();
    let auth_diagnostics = diagnostics.clone();
    let status_auth_client = auth_client.clone();
    let mut auth_task = AuthTask(tokio::spawn(async move {
        while let Some(message) = requests.next().await {
            let Some(reply) = message.reply else { continue };
            if !reply.as_str().starts_with("$SYS._INBOX.") {
                continue;
            }
            let response = message
                .headers
                .as_ref()
                .and_then(|h| h.get("Nats-Server-Xkey"))
                .context("encrypted callout header required")
                .and_then(|key| {
                    callout.respond(
                        &auth_registry,
                        key.as_str(),
                        &message.payload,
                        if separated {
                            auth_diagnostics.ready()
                        } else {
                            admission_worker.load(std::sync::atomic::Ordering::Acquire)
                        },
                    )
                });
            match response {
                Ok(bytes) => auth_client.publish(reply, bytes.into()).await?,
                Err(error) => {
                    // Context is a fixed enum, never the potentially sensitive cause.
                    let stage = error.downcast_ref::<auth_callout::FailureStage>();
                    tracing::warn!(
                        stage = %stage.map_or_else(|| "missing_server_xkey".to_owned(), ToString::to_string),
                        storage = auth_callout::storage_failure_code(&error),
                        "Auth Callout response failed; admission denied"
                    );
                }
            }
        }
        anyhow::bail!("auth subscription ended")
    }));
    let mut registry = AuthRegistry::open(home)?;
    registry.audit_repair(epochgrid_core::audit::Event::committed(
        epochgrid_core::audit::Kind::AuthorityStarted,
    ));
    let monitor = epochgrid_core::validation::PermissionMonitor::default();
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        monitor
            .configure(transport::connection_options(url, &key)?)
            .connect(url),
    )
    .await??;
    diagnostics.connections(status_auth_client, client.clone(), monitor.clone());
    drop(identity);
    if let Some(manifest) = &manifest {
        let report =
            epochgrid_core::validation::inspect_resources(&client, manifest, &monitor).await;
        ensure!(
            report.success,
            "production resource admission gate failed:\n{}",
            report.human()
        );
    }
    let enrollment = registry.historical_enrollment()?;
    let (directory, log) = if production || local.is_some() {
        // Lookups only: never create or alter operator resources, including on errors.
        let (directory, log) = tokio::time::timeout(Duration::from_secs(10), async {
            Ok::<_, anyhow::Error>((
                transport::lookup_resources(client.clone()).await?,
                transparency::lookup_resource(client.clone()).await?,
            ))
        })
        .await??;
        transparency::reconcile(&log, &directory, &enrollment, &key).await?;
        (directory, log)
    } else {
        let directory = transport::provision(client.clone()).await?;
        let log = transparency::provision(client.clone(), &directory, &enrollment, &key).await?;
        (directory, log)
    };
    let registrations = transparency::read(&log).await?;
    revocation::initialize(&log, &registrations, &key).await?;
    for revoked in revocation::read(&log, &registrations).await?.keys() {
        registry.revoke(&revoked)?;
    }
    // Repair an enrollment interrupted after local commit but before projection/response.
    for registration in registry.registrations()? {
        publish_registration(
            &registry,
            &log,
            &directory,
            &enrollment,
            &key,
            registration.clone(),
            false,
        )
        .await?;
        registry.activate(&registration.payload.nats_public_key)?;
    }
    epochgrid_core::authorization::reconcile_consumers(&registry, &client).await?;
    let mut controls = if local.is_none() {
        Some(futures_util::stream::select(
            client.subscribe("epochgrid.v1.identity.*").await?,
            client.subscribe("epochgrid.v1.channel.*").await?,
        ))
    } else {
        None
    };
    client.flush().await?;
    diagnostics.gate(true);
    diagnostics.repair(true);
    diagnostics.refresh(&registry);
    tracing::info!("EpochGrid dynamic identity and Auth Callout service ready");
    let mut repair = tokio::time::interval(Duration::from_secs(1));
    repair.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut observations = tokio::time::interval(Duration::from_secs(
        epochgrid_core::diagnostics::REFRESH_SECONDS,
    ));
    observations.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut audit_denials = epochgrid_core::audit::Denials::default();
    loop {
        tokio::select! {
            biased;
            _=observations.tick()=> { diagnostics.refresh(&registry); },
            _=repair.tick(), if !admission.load(std::sync::atomic::Ordering::Acquire)=> {
                if matches!(tokio::time::timeout(Duration::from_secs(5),repair_state(&registry, &client, &log, &directory, &key)).await, Ok(Ok(()))) {
                    diagnostics.gate(true);
                    diagnostics.repair(true);
                } else { diagnostics.repair(false); }
            },
            signal=tokio::signal::ctrl_c()=>{signal?;break},
            result=&mut auth_task.0=>{result??;anyhow::bail!("auth handler stopped")},
            incoming=async {
                if let Some(local) = &mut local {
                    let request = crate::roles::next_request(&mut local.requests).await?;
                    Ok::<_, anyhow::Error>((request.subject, request.payload, None, Some(request.response)))
                } else {
                    let message = controls.as_mut().unwrap().next().await.context("control subscription ended")?;
                    Ok((message.subject.to_string(), message.payload.to_vec(), message.reply, None))
                }
            }=>{
                let (subject, payload, reply, response_sender) = incoming?;
                if response_sender.is_none() && !reply.as_ref().is_some_and(|r| r.as_str().starts_with("_INBOX.")) {continue}
                diagnostics.control.received.increment();
                let response=tokio::time::timeout(Duration::from_secs(5),async {
                    if payload.len() > wire::MAX_WIRE {diagnostics.control.malformed.increment();}
                    ensure!(payload.len() <= wire::MAX_WIRE, "oversized control request");
                    let permitted = if subject == wire::REVOKE {
                        revocation_rate.allow(std::time::Instant::now())
                    } else { control_rate.allow(std::time::Instant::now()) };
                    if !permitted {diagnostics.control.rate_limited.increment();}
                    ensure!(permitted, "control overload");
                    let request = wire::decode(&payload).inspect_err(|_| diagnostics.control.malformed.increment())?;
                    let mutating = matches!(&request, Body::GroupPolicy(_) | Body::Enroll {..} | Body::Revoke(_) | Body::Register(_));
                    if mutating {diagnostics.gate(false);}
                    let registrations=transparency::read(&log).await?;
                    let revocations=revocation::read(&log,&registrations).await?;
                    for key in revocations.keys() {registry.revoke(&key)?;}
                    let active=registry.enrollment()?;
                    let body = match (subject.as_str(),request) {
                        (epochgrid_core::authorization::SUBJECT, Body::PolicyQuery {gid}) => Body::PolicyState(registry.policy_state(&gid)?),
                        (epochgrid_core::authorization::RELAY, Body::RelayWelcome(relay)) => {
                            let subject = relay.validate(&registry)?;
                            let mut headers = async_nats::HeaderMap::new();
                            headers.insert("Nats-Msg-Id", format!("welcome:{}:{}", relay.sender, relay.id));
                            async_nats::jetstream::new(client.clone()).publish_with_headers(subject, headers, relay.payload.into()).await?.await?;
                            Body::WelcomeRelayed
                        },
                        (wire::KEYPACKAGE,Body::ClaimKeyPackage {user,device,group})=>transport::claim(&directory,&active,&user,&device,&group).await?,
                        (epochgrid_core::authorization::SUBJECT, Body::GroupPolicy(policy)) => {
                            Body::PolicyApplied { generation: registry.apply_policy(&policy)? }
                        },
                        (auth_callout::ENROLL,Body::Enroll{token,registration})=>{

                            registry.enroll(token.as_str(),&registration)?;
                            publish_registration(&registry,&log,&directory,&registry.enrollment()?,&key,registration.clone(),true).await?;
                            registry.activate(&registration.payload.nats_public_key)?;
                            Body::Registered
                        },
                        (wire::REGISTER,Body::Register(registration))=>{
                            registry.authorize(&registration.payload.nats_public_key)?;
                            publish_registration(&registry,&log,&directory,&active,&key,registration,true).await?;Body::Registered
                        },
                        (wire::AUDIT,Body::RegistrationAudit)=>Body::AuditLog(registrations),
                        (wire::AUDIT,Body::Audit) if revocations.entries.is_empty()=>Body::AuditLog(registrations),
                        (wire::REVOCATIONS,Body::RevocationAudit)=>Body::RevocationLog(revocations),
                        (wire::REVOKE,Body::Revoke(request))=>{
                            request.validate(&registrations, &revocations.entries)?;
                            let operation = registry.audit_revocation_intent(&request.nkey, &request.author);
                            let cutoff=revocation::chat_cutoff(&client).await?;
                            let result=revocation::append(&log,&registrations,&key,request,cutoff).await;
                            registry.audit_effect_result(epochgrid_core::audit::Kind::RevocationPublication,operation,result.is_ok());
                            let revoked=result?;
                            for key in revoked.keys(){registry.revoke(&key)?;}
                            Body::Revoked
                        },
                        (wire::LOOKUP,Body::Lookup{user,device})=>transport::find(&directory,&active,&user,&device).await?,
                        (wire::DEVICES,Body::ListDevices{user})=>epochgrid_core::devices::find_devices(&directory,&active,&user).await?,
                        _=>Body::Rejected,
                    };
                    if mutating {
                        epochgrid_core::authorization::reconcile_consumers(&registry, &client).await?;
                        diagnostics.gate(true);
                        diagnostics.repair(true);
                    }
                    Ok::<Body, anyhow::Error>(body)
                }).await;
                if !admission.load(std::sync::atomic::Ordering::Acquire) {
                    let repaired = matches!(tokio::time::timeout(Duration::from_secs(5), repair_state(&registry, &client, &log, &directory, &key)).await, Ok(Ok(())));
                    diagnostics.repair(repaired);
                    if repaired {diagnostics.gate(true);}
                }
                let body=match response {
                    Ok(Ok(body)) if !matches!(body,Body::Rejected) => {diagnostics.control.accepted.increment();body},
                    result => {
                        diagnostics.control.denied.increment();
                        audit_denials.observe(&registry);
                        if result.is_err() {diagnostics.control.timeout.increment();}
                        tracing::warn!("dynamic identity operation rejected"); Body::Rejected
                    }
                };
                let bytes=wire::encode(body).or_else(|_|wire::encode(Body::Rejected))?;
                if let Some(sender) = response_sender {
                    let _ = sender.send(bytes);
                } else if let Some(reply) = reply {
                    client.publish(reply,bytes.into()).await?;
                }
            }
        }
    }
    client.flush().await?;
    Ok(())
}

async fn publish_registration(
    registry: &AuthRegistry,
    log: &async_nats::jetstream::kv::Store,
    directory: &async_nats::jetstream::kv::Store,
    enrollment: &transport::Enrollment,
    key: &nkeys::KeyPair,
    registration: wire::DeviceRegistration,
    required: bool,
) -> Result<()> {
    let operation = registry.audit_effect_target(
        epochgrid_core::audit::Kind::RegistrationPublication,
        &registration.payload.nats_public_key,
        required,
    )?;
    let result = transparency::register(log, directory, enrollment, key, registration).await;
    registry.audit_effect_result(
        epochgrid_core::audit::Kind::RegistrationPublication,
        operation,
        result.is_ok(),
    );
    result
}
