use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    auth_callout::{self, Callout, Config},
    identity::IdentityStore,
    identity_model::AuthRegistry,
    revocation, transparency, transport,
    wire::{self, Body},
};
use futures_util::StreamExt;
use std::{io::Write, path::Path, time::Duration};

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
pub fn init(home: &Path) -> Result<()> {
    AuthRegistry::open(home)?;
    ensure!(
        !home.join("auth.json").exists(),
        "authentication configuration already exists"
    );
    let issuer = nkeys::KeyPair::new_account();
    let encryption = nkeys::XKey::new();
    let connection = nkeys::KeyPair::new_user();
    let mut control = IdentityStore::open(&home.join("control"))?;
    if control.registration().is_err() {
        control.init("service", "laptop")?;
    }
    let config = Config {
        version: 1,
        issuer_seed: "issuer.seed".into(),
        encryption_seed: "encryption.seed".into(),
        connection_seed: "auth.seed".into(),
        target_account: "EPOCHGRID".into(),
        control_nkey: control.nkey()?.public_key(),
        authorization_ttl_seconds: 30,
        development_plaintext: false,
    };
    private_file(&home.join("issuer.seed"), issuer.seed()?.as_bytes())?;
    private_file(&home.join("encryption.seed"), encryption.seed()?.as_bytes())?;
    private_file(&home.join("auth.seed"), connection.seed()?.as_bytes())?;
    private_file(
        &home.join("auth.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    let snippet = format!(
        r#"# Reference only: integrate with operator-owned configuration; do not replace it.
# Add operator-managed TLS and JetStream. No static device users.
accounts {{
  EPOCHGRID_AUTH {{ users: [{{nkey: "{}", permissions: {{subscribe: ["$SYS.REQ.USER.AUTH", "_INBOX.>"], publish: ["$SYS._INBOX.>"]}}}}] }}
  EPOCHGRID {{ jetstream: enabled }}
}}
authorization {{
  timeout: 2
  auth_callout {{ issuer: "{}", xkey: "{}", account: EPOCHGRID_AUTH, auth_users: ["{}"], allowed_accounts: [EPOCHGRID] }}
}}
"#,
        connection.public_key(),
        issuer.public_key(),
        encryption.public_key(),
        connection.public_key()
    );
    private_file(&home.join("nats-reference.conf"), snippet.as_bytes())?;
    println!(
        "EpochGrid integration keys initialized; review auth.json and nats-reference.conf. NATS was not modified."
    );
    Ok(())
}
struct AuthTask(tokio::task::JoinHandle<Result<()>>);
impl Drop for AuthTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub async fn serve(home: &Path, url: &str, path: &Path) -> Result<()> {
    let config = Config::load(path)?;
    config.check_transport(url)?;
    if config.development_plaintext {
        tracing::warn!("DEVELOPMENT ONLY: unencrypted client transport enabled");
    }
    let auth_client = config.connect(url).await?;
    let mut requests = auth_client
        .queue_subscribe(auth_callout::SUBJECT, "epochgrid-auth".into())
        .await?;
    auth_client.flush().await?;
    let auth_registry = AuthRegistry::open(home)?;
    let mut callout = Callout::new(config.clone())?;
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
    let identity = IdentityStore::open(&home.join("control"))?;
    let key = identity.nkey()?;
    ensure!(
        key.public_key() == config.control_nkey,
        "control identity does not match callout configuration"
    );
    let client = transport::connect(url, &identity).await?;
    drop(identity);
    let directory = transport::provision(client.clone()).await?;
    let enrollment = registry.historical_enrollment()?;
    let log = transparency::provision(client.clone(), &directory, &enrollment, &key).await?;
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
    let mut controls = futures_util::stream::select(
        client.subscribe("epochgrid.v1.identity.*").await?,
        client
            .subscribe(epochgrid_core::authorization::SUBJECT)
            .await?,
    );
    client.flush().await?;
    admission.store(true, std::sync::atomic::Ordering::Release);
    tracing::info!("EpochGrid dynamic identity and Auth Callout service ready");
    loop {
        tokio::select! {
            signal=tokio::signal::ctrl_c()=>{signal?;break},
            result=&mut auth_task.0=>{result??;anyhow::bail!("auth handler stopped")},
            message=controls.next()=>{
                let Some(message)=message else {anyhow::bail!("control subscription ended")};
                let Some(reply)=message.reply else {continue};
                if !reply.as_str().starts_with("_INBOX.") {continue}
                let response=tokio::time::timeout(Duration::from_secs(5),async {
                    let registrations=transparency::read(&log).await?;
                    let revocations=revocation::read(&log,&registrations).await?;
                    for key in revocations.keys() {registry.revoke(&key)?;}
                    let active=registry.enrollment()?;
                    Ok::<Body,anyhow::Error>(match (message.subject.as_str(),wire::decode(&message.payload)?) {
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
                    })
                }).await;
                let body=match response {Ok(Ok(body))=>body,_=>{tracing::warn!("dynamic identity operation rejected");Body::Rejected}};
                let bytes=wire::encode(body).or_else(|_|wire::encode(Body::Rejected))?;
                client.publish(reply,bytes.into()).await?;
            }
        }
    }
    client.flush().await?;
    Ok(())
}
