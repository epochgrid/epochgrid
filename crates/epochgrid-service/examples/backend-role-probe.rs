//! Destructive-denial probes for disposable qualification fixtures ONLY.
//! Never run against a real deployment: a broken permission boundary can mutate it.
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    secrets::{Kind, Vault},
    transport,
};
use futures_util::StreamExt;
use std::{path::Path, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 5 && args[1] == "--disposable-fixture",
        "disposable fixture arguments required"
    );
    let worker = match args[2].as_str() {
        "worker" => true,
        "authority" => false,
        _ => anyhow::bail!("unknown role"),
    };
    let home = Path::new(&args[3]);
    let reference = if worker {
        Vault::new(home).existing("worker", Kind::User)?
    } else {
        Vault::new(&home.join("control")).existing("device", Kind::User)?
    };
    let key = nkeys::KeyPair::from_seed(&reference.read()?)?;
    let (errors, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let options = transport::connection_options(&args[4], &key)?.event_callback(move |event| {
        let errors = errors.clone();
        async move {
            if let async_nats::Event::ServerError(error) = event {
                let _ = errors.send(error.to_string());
            }
        }
    });
    let client = options.connect(&args[4]).await?;
    if worker {
        let subject = format!("_INBOX.{}.fixture", key.public_key());
        let mut inbox = client.subscribe(subject.clone()).await?;
        client.flush().await?;
        client.publish(subject, "probe".into()).await?;
        let message = tokio::time::timeout(Duration::from_secs(5), inbox.next())
            .await?
            .context("probe inbox ended")?;
        ensure!(message.payload == "probe", "worker round trip failed");
    } else {
        let reply = client.request("$JS.API.INFO", "{}".into()).await?;
        let response: serde_json::Value = serde_json::from_slice(&reply.payload)?;
        ensure!(
            response.get("error").is_none(),
            "authority inspection denied"
        );
    }
    let mut probes = vec![
        (false, "$JS.API.STREAM.CREATE.UNRELATED"),
        (false, "$JS.API.STREAM.UPDATE.CHAT"),
        (false, "$JS.API.STREAM.DELETE.CHAT"),
        (false, "$JS.API.STREAM.PURGE.CHAT"),
        (false, "$JS.API.STREAM.MSG.GET.CHAT"),
        (false, "$JS.API.STREAM.MSG.GET.MAILBOX"),
        (false, "$JS.API.CONSUMER.CREATE.UNRELATED.arbitrary"),
        (false, "$KV.UNRELATED.key"),
        (false, "$SYS.REQ.USER.AUTH"),
        (true, "$SYS.REQ.USER.AUTH"),
        (true, "epochgrid.v1.group.private.message"),
    ];
    if worker {
        probes.extend([
            (false, "$JS.API.CONSUMER.CREATE.CHAT.arbitrary"),
            (false, "$JS.API.CONSUMER.DELETE.MAILBOX.arbitrary"),
            (false, "$KV.TRANSPARENCY.snapshot"),
            (false, "epochgrid.v1.user.other.device.inbox"),
        ]);
    }
    for (subscribe, subject) in probes {
        let _subscription = if subscribe {
            Some(client.subscribe(subject).await?)
        } else {
            client.publish(subject, "{}".into()).await?;
            None
        };
        client.flush().await?;
        let error = tokio::time::timeout(Duration::from_secs(3), observed.recv())
            .await
            .context("missing explicit role permission denial")?
            .context("permission observer ended")?;
        ensure!(
            error.to_ascii_lowercase().contains("permissions violation") && error.contains(subject),
            "unexpected role permission result"
        );
    }
    println!("ROLE_PERMISSION_PROBES=passed");
    Ok(())
}
