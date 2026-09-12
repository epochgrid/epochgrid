use super::{
    Process, connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{identity::IdentityStore, participants::STATUS_RESPONSE, transport};
use std::{
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

fn runner(root: &Path, url: &str) -> Result<Process> {
    Ok(Process(
        Command::new(
            Path::new(env!("CARGO_BIN_EXE_epochgrid-service")).with_file_name("epochgrid"),
        )
        .arg("--home")
        .arg(root.join("status"))
        .arg("--server")
        .arg(url)
        .args(["participant", "run", "engineering"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?,
    ))
}
#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn explicit_service_participant_restart_and_removal() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), workflow())
        .await
        .context("participant workflow exceeded 90s")?
}
async fn workflow() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    let mut status = IdentityStore::open(&root.join("status"))?;
    let binding = status.init("status", "service")?.payload.nats_public_key;
    drop(status);
    transport::dev_config_with_enrollment(root, port, &[format!("status/service={binding}")])?;
    let _nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let _backend = daemon(root, &url)?;
    ready(root, &url, true).await?;
    for user in ["bob", "status"] {
        cli(root, &url, user, &["identity", "register"], None).await?;
    }
    cli(
        root,
        &url,
        "alice",
        &["channel", "create", "engineering"],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "alice",
        &["channel", "invite", "engineering", "bob"],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "bob",
        &["channel", "join", "--from", "alice"],
        None,
    )
    .await?;
    let before_secret = b"EPOCHGRID_SERVICE_PREJOIN_91F3";
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(before_secret),
    )
    .await?;
    let js = async_nats::jetstream::new(observer);
    let mut stream = js.get_stream("CHAT").await?;
    let before_sequence = stream.info().await?.state.last_sequence;
    let before = stream.get_raw_message(before_sequence).await?.payload;
    ensure!(
        cli(
            root,
            &url,
            "status",
            &["participant", "run", "engineering", "--once"],
            None
        )
        .await
        .is_err()
    );
    cli(
        root,
        &url,
        "alice",
        &[
            "channel",
            "invite",
            "engineering",
            "status",
            "--device",
            "service",
        ],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "status",
        &["channel", "join", "--from", "alice"],
        None,
    )
    .await?;
    let status = IdentityStore::open(&root.join("status"))?;
    ensure!(
        status.decrypt_message("engineering", &before).is_err(),
        "pre-join ciphertext decrypted"
    );
    drop(status);
    let members = cli(
        root,
        &url,
        "alice",
        &["channel", "members", "engineering", "--users"],
        None,
    )
    .await?;
    ensure!(members.contains("@status [service]"));
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(b"/status"),
    )
    .await?;
    cli(
        root,
        &url,
        "status",
        &["participant", "run", "engineering", "--once"],
        None,
    )
    .await?;
    let first = cli(
        root,
        &url,
        "bob",
        &["message", "history", "engineering"],
        None,
    )
    .await?;
    ensure!(first.contains(STATUS_RESPONSE) && first.contains("reply to alice/laptop"));
    let after_reply = stream.info().await?.state.last_sequence;
    cli(
        root,
        &url,
        "status",
        &["participant", "run", "engineering", "--once"],
        None,
    )
    .await?;
    ensure!(
        stream.info().await?.state.last_sequence == after_reply,
        "restart duplicated a response"
    );
    // Exercise the persistent runner rather than only one-shot operation.
    let mut participant = runner(root, &url)?;
    cli(
        root,
        &url,
        "bob",
        &["message", "send", "engineering"],
        Some(b"/status"),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            ensure!(
                participant.0.try_wait()?.is_none(),
                "participant exited early"
            );
            if stream.info().await?.state.last_sequence >= after_reply + 2 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("no persistent service response")??;
    let second = cli(
        root,
        &url,
        "alice",
        &["message", "history", "engineering"],
        None,
    )
    .await?;
    ensure!(second.matches("EpochGrid service online").count() == 2);
    ensure!(
        cli(
            root,
            &url,
            "bob",
            &[
                "channel",
                "remove",
                "engineering",
                "status",
                "--device",
                "service"
            ],
            None
        )
        .await
        .is_err()
    );
    let epoch = IdentityStore::open(&root.join("alice"))?.group_epoch("engineering")?;
    cli(
        root,
        &url,
        "alice",
        &[
            "channel",
            "remove",
            "engineering",
            "status",
            "--device",
            "service",
        ],
        None,
    )
    .await?;
    ensure!(IdentityStore::open(&root.join("alice"))?.group_epoch("engineering")? == epoch + 1);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(exit) = participant.0.try_wait()? {
                ensure!(!exit.success());
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("removed participant did not stop")??;
    let future_secret = b"EPOCHGRID_SERVICE_REMOVED_91F3";
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(future_secret),
    )
    .await?;
    let future_sequence = stream.info().await?.state.last_sequence;
    let future = stream.get_raw_message(future_sequence).await?.payload;
    let status = IdentityStore::open(&root.join("status"))?;
    ensure!(!status.group_active("engineering")?);
    ensure!(status.decrypt_message("engineering", &future).is_err());
    ensure!(status.encrypt_message("engineering", b"forbidden").is_err());
    drop(status);
    let remaining = cli(
        root,
        &url,
        "bob",
        &["message", "history", "engineering"],
        None,
    )
    .await?;
    ensure!(remaining.contains(std::str::from_utf8(future_secret)?));
    for seq in 1..=stream.info().await?.state.last_sequence {
        let payload = stream.get_raw_message(seq).await?.payload;
        for secret in [
            before_secret.as_slice(),
            future_secret.as_slice(),
            STATUS_RESPONSE.as_bytes(),
            b"/status",
        ] {
            ensure!(
                !payload.windows(secret.len()).any(|w| w == secret),
                "plaintext stored by NATS"
            );
        }
    }
    Ok(())
}
