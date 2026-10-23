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
        transparency::register(log, directory, &enrollment, key, registration.clone()).await?;
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
    let production = epochgrid_core::tls::TlsConfig::from_env()?.profile
        == epochgrid_core::tls::Profile::Production;
    let manifest = if production {
        let report = epochgrid_core::validation::offline(home, path, Some(url));
        ensure!(
            report.success,
            "production startup local validation failed:\n{}",
            report.human()
        );
        Some(serde_json::from_slice::<
            epochgrid_core::deployment::DeploymentManifest,
        >(&std::fs::read(
            home.join(epochgrid_core::deployment::MANIFEST_FILE),
        )?)?)
    } else {
        None
    };
    let config = Config::load(path)?;
    config.check_transport(url)?;
    if config.development_plaintext {
        tracing::warn!("DEVELOPMENT ONLY: unencrypted client transport enabled");
    }
    // Resolve every local credential before opening subscriptions/admission.
    let mut callout = Callout::new(config.clone())?;
    let identity = IdentityStore::open(&home.join("control"))?;
    let key = identity.nkey()?;
    ensure!(
        key.public_key() == config.control_nkey,
        "control identity does not match callout configuration"
    );
    let auth_client = tokio::time::timeout(Duration::from_secs(5), config.connect(url)).await??;
    let mut requests = auth_client
        .queue_subscribe(auth_callout::SUBJECT, "epochgrid-auth".into())
        .await?;
    tokio::time::timeout(Duration::from_secs(5), auth_client.flush()).await??;
    let auth_registry = AuthRegistry::open(home)?;
    let admission = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let admission_worker = admission.clone();
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
                        admission_worker.load(std::sync::atomic::Ordering::Acquire),
                    )
                });
            match response {
                Ok(bytes) => auth_client.publish(reply, bytes.into()).await?,
                Err(error) => {
                    tracing::warn!(%error, "invalid encrypted Auth Callout request denied");
                }
            }
        }
        anyhow::bail!("auth subscription ended")
    }));
    let mut registry = AuthRegistry::open(home)?;
    let monitor = epochgrid_core::validation::PermissionMonitor::default();
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        monitor
            .configure(transport::connection_options(url, &key)?)
            .connect(url),
    )
    .await??;
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
    let (directory, log) = if production {
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
        transparency::register(&log, &directory, &enrollment, &key, registration.clone()).await?;
        registry.activate(&registration.payload.nats_public_key)?;
    }
    epochgrid_core::authorization::reconcile_consumers(&registry, &client).await?;
    let mut controls = futures_util::stream::select(
        client.subscribe("epochgrid.v1.identity.*").await?,
        client.subscribe("epochgrid.v1.channel.*").await?,
    );
    client.flush().await?;
    admission.store(true, std::sync::atomic::Ordering::Release);
    tracing::info!("EpochGrid dynamic identity and Auth Callout service ready");
    let mut repair = tokio::time::interval(Duration::from_secs(1));
    repair.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=repair.tick(), if !admission.load(std::sync::atomic::Ordering::Acquire)=> {
                if matches!(tokio::time::timeout(Duration::from_secs(5),repair_state(&registry, &client, &log, &directory, &key)).await, Ok(Ok(()))) {
                    admission.store(true, std::sync::atomic::Ordering::Release);
                }
            },
            signal=tokio::signal::ctrl_c()=>{signal?;break},
            result=&mut auth_task.0=>{result??;anyhow::bail!("auth handler stopped")},
            message=controls.next()=>{
                let Some(message)=message else {anyhow::bail!("control subscription ended")};
                let Some(reply)=message.reply else {continue};
                if !reply.as_str().starts_with("_INBOX.") {continue}
                let response=tokio::time::timeout(Duration::from_secs(5),async {
                    let request = wire::decode(&message.payload)?;
                    let mutating = matches!(&request, Body::GroupPolicy(_) | Body::Enroll {..} | Body::Revoke(_) | Body::Register(_));
                    if mutating {admission.store(false, std::sync::atomic::Ordering::Release);}
                    let registrations=transparency::read(&log).await?;
                    let revocations=revocation::read(&log,&registrations).await?;
                    for key in revocations.keys() {registry.revoke(&key)?;}
                    let active=registry.enrollment()?;
                    let body = match (message.subject.as_str(),request) {
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
                            transparency::register(&log,&directory,&registry.enrollment()?,&key,registration.clone()).await?;
                            registry.activate(&registration.payload.nats_public_key)?;
                            Body::Registered
                        },
                        (wire::REGISTER,Body::Register(registration))=>{
                            registry.authorize(&registration.payload.nats_public_key)?;
                            transparency::register(&log,&directory,&active,&key,registration).await?;Body::Registered
                        },
                        (wire::AUDIT,Body::RegistrationAudit)=>Body::AuditLog(registrations),
                        (wire::AUDIT,Body::Audit) if revocations.entries.is_empty()=>Body::AuditLog(registrations),
                        (wire::REVOCATIONS,Body::RevocationAudit)=>Body::RevocationLog(revocations),
                        (wire::REVOKE,Body::Revoke(request))=>{
                            let cutoff=revocation::chat_cutoff(&client).await?;
                            let revoked=revocation::append(&log,&registrations,&key,request,cutoff).await?;
                            for key in revoked.keys(){registry.revoke(&key)?;}
                            Body::Revoked
                        },
                        (wire::LOOKUP,Body::Lookup{user,device})=>transport::find(&directory,&active,&user,&device).await?,
                        (wire::DEVICES,Body::ListDevices{user})=>epochgrid_core::devices::find_devices(&directory,&active,&user).await?,
                        _=>Body::Rejected,
                    };
                    if mutating {
                        epochgrid_core::authorization::reconcile_consumers(&registry, &client).await?;
                        admission.store(true, std::sync::atomic::Ordering::Release);
                    }
                    Ok::<Body, anyhow::Error>(body)
                }).await;
                if !admission.load(std::sync::atomic::Ordering::Acquire)
                    && matches!(tokio::time::timeout(Duration::from_secs(5), repair_state(&registry, &client, &log, &directory, &key)).await, Ok(Ok(()))) {
                    admission.store(true, std::sync::atomic::Ordering::Release);
                }
                let body=match response {Ok(Ok(body))=>body,_=>{tracing::warn!("dynamic identity operation rejected");Body::Rejected}};
                let bytes=wire::encode(body).or_else(|_|wire::encode(Body::Rejected))?;
                client.publish(reply,bytes.into()).await?;
            }
        }
    }
    client.flush().await?;
    Ok(())
}
