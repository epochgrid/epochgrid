//! CLI acceptance: destroy the original home, restore administration, retire old
//! credentials and resume with a fresh leaf. Every subprocess and outer test is bounded.
use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{identity::IdentityStore, transport};
use std::{net::TcpListener, path::Path, time::Duration};

const BEFORE: &[u8] = b"EPOCHGRID_RECOVERY_HISTORY_EXCLUDED_91F3";
const AFTER: &[u8] = b"EPOCHGRID_RECOVERY_FRESH_LEAF_91F3";

fn absent(bytes: &[u8], secrets: &[&[u8]]) -> Result<()> {
    for secret in secrets {
        ensure!(
            !bytes.windows(secret.len()).any(|w| w == *secret),
            "private recovery data or application plaintext reached infrastructure"
        );
    }
    Ok(())
}
fn scan(path: &Path, secrets: &[&[u8]]) -> Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            scan(&entry.path(), secrets)?;
        } else if entry.file_type()?.is_file() {
            absent(&std::fs::read(entry.path())?, secrets)?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn encrypted_identity_recovery_and_fresh_device_messaging() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(120), workflow())
        .await
        .context("recovery workflow exceeded 120s")?
}
async fn workflow() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    let mut desktop = IdentityStore::open(&root.join("desktop"))?;
    let desktop_registration = desktop.init("alice", "desktop")?;
    drop(desktop);
    transport::dev_config_with_enrollment(
        root,
        port,
        &[format!(
            "alice/desktop={}",
            desktop_registration.payload.nats_public_key
        )],
    )?;
    let nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root, &url)?;
    ready(root, &url, true).await?;
    for device in ["bob", "desktop"] {
        cli(root, &url, device, &["identity", "register"], None).await?;
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
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(BEFORE),
    )
    .await?;
    cli(root, &url, "bob", &["channel", "sync", "engineering"], None).await?;
    let alice = IdentityStore::open(&root.join("alice"))?;
    let original = alice.registration()?;
    let original_seed = alice.nkey()?.seed()?;
    let bob = IdentityStore::open(&root.join("bob"))?;
    let bob_registration = bob.registration()?;
    let fingerprint = epochgrid_core::trust::fingerprint(&bob_registration)?;
    drop(bob);
    drop(alice);
    cli(
        root,
        &url,
        "alice",
        &[
            "device",
            "verify",
            "bob",
            "laptop",
            "--fingerprint",
            &fingerprint,
        ],
        None,
    )
    .await?;
    let package_path = root.join("alice.egrecovery");
    let key_path = root.join("alice.egsecret");
    let package = package_path.to_str().context("path")?;
    let key = key_path.to_str().context("path")?;
    let export_output = cli(
        root,
        &url,
        "alice",
        &[
            "recovery",
            "export",
            "--output",
            package,
            "--secret-file",
            key,
        ],
        None,
    )
    .await?;
    let key_bytes = std::fs::read(&key_path)?;
    let secret_text = std::str::from_utf8(&key_bytes)?.trim();
    let secrets = [
        BEFORE,
        AFTER,
        original_seed.as_bytes(),
        secret_text.as_bytes(),
    ];
    absent(export_output.as_bytes(), &secrets)?;
    absent(&std::fs::read(&package_path)?, &secrets)?;
    // No preserved copy of Alice's SQLite/MLS state is used after this point.
    std::fs::remove_dir_all(root.join("alice"))?;
    cli(
        root,
        &url,
        "alice",
        &[
            "recovery",
            "restore",
            "--input",
            package,
            "--secret-file",
            key,
        ],
        None,
    )
    .await?;
    ensure!(
        cli(root, &url, "alice", &["recovery", "status"], None)
            .await?
            .contains("recovery-only")
    );
    cli(root, &url, "alice", &["transparency", "audit"], None).await?;
    let alice = IdentityStore::open(&root.join("alice"))?;
    ensure!(alice.registration()? == original);
    ensure!(alice.nkey()?.public_key() == original.payload.nats_public_key);
    ensure!(
        alice
            .device_trust("bob", "laptop")?
            .context("trust missing")?
            .state
            == "verified"
    );
    ensure!(alice.groups()?.is_empty());
    ensure!(alice.decrypt_message("engineering", b"anything").is_err());
    drop(alice);
    for args in [
        vec!["channel", "create", "unsafe"],
        vec!["identity", "register"],
        vec!["channel", "join", "--from", "bob"],
        vec!["tui"],
    ] {
        ensure!(cli(root, &url, "alice", &args, None).await.is_err());
    }
    // The recovered NKey really authorizes a signed same-user control operation.
    cli(
        root,
        &url,
        "alice",
        &["device", "revoke", "alice", "desktop"],
        None,
    )
    .await?;
    let desktop = IdentityStore::open(&root.join("desktop"))?;
    ensure!(transport::connect(&url, &desktop).await.is_err());
    drop(desktop);
    cli(
        root,
        &url,
        "replacement",
        &["device", "add", "alice", "--device", "replacement"],
        None,
    )
    .await?;
    let replacement = IdentityStore::open(&root.join("replacement"))?;
    let new_key = replacement.nkey()?.public_key();
    ensure!(new_key != original.payload.nats_public_key);
    ensure!(replacement.registration()?.payload.mls_credential != original.payload.mls_credential);
    drop(replacement);
    // Ordinary public operator enrollment remains authoritative; no recovery bypass.
    drop(service);
    drop(nats);
    drop(observer);
    transport::dev_config_with_enrollment(root, port, &[format!("alice/replacement={new_key}")])?;
    let nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root, &url)?;
    ready(root, &url, false).await?;
    cli(root, &url, "replacement", &["identity", "register"], None).await?;
    cli(
        root,
        &url,
        "replacement",
        &["device", "revoke", "alice", "laptop"],
        None,
    )
    .await?;
    // An authentic old backup cannot undo credential revocation.
    cli(
        root,
        &url,
        "stale",
        &[
            "recovery",
            "restore",
            "--input",
            package,
            "--secret-file",
            key,
        ],
        None,
    )
    .await?;
    let stale = IdentityStore::open(&root.join("stale"))?;
    ensure!(transport::connect(&url, &stale).await.is_err());
    drop(stale);
    cli(root, &url, "bob", &["channel", "sync", "engineering"], None).await?;
    cli(
        root,
        &url,
        "bob",
        &[
            "channel",
            "invite",
            "engineering",
            "alice",
            "--device",
            "replacement",
        ],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "replacement",
        &["channel", "join", "--from", "bob"],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "bob",
        &["message", "send", "engineering"],
        Some(AFTER),
    )
    .await?;
    cli(
        root,
        &url,
        "replacement",
        &["channel", "sync", "engineering"],
        None,
    )
    .await?;
    // Each CLI invocation reopens the home, exercising restore/join/send persistence.
    let history = cli(
        root,
        &url,
        "replacement",
        &["message", "history", "engineering", "--offline"],
        None,
    )
    .await?;
    ensure!(history.contains(std::str::from_utf8(AFTER)?));
    ensure!(!history.contains(std::str::from_utf8(BEFORE)?));
    cli(
        root,
        &url,
        "replacement",
        &["message", "send", "engineering"],
        Some(AFTER),
    )
    .await?;
    cli(root, &url, "bob", &["channel", "sync", "engineering"], None).await?;
    let bob = IdentityStore::open(&root.join("bob"))?;
    ensure!(
        bob.history("engineering", 100, None)?
            .iter()
            .any(|m| !m.outgoing && m.plaintext.as_deref() == Some(AFTER))
    );
    ensure!(
        bob.members("engineering")? == vec!["alice/replacement", "bob/laptop"]
            || bob.members("engineering")? == vec!["bob/laptop", "alice/replacement"]
    );
    drop(bob);
    let js = async_nats::jetstream::new(observer.clone());
    for name in ["CHAT", "MAILBOX"] {
        let mut stream = js.get_stream(name).await?;
        let state = stream.info().await?.state.clone();
        for sequence in state.first_sequence..=state.last_sequence {
            absent(&stream.get_raw_message(sequence).await?.payload, &secrets)?;
        }
    }
    drop(service);
    drop(nats);
    drop(observer);
    scan(&root.join("jetstream"), &secrets)?;
    scan(&root.join("service"), &secrets)?;
    absent(&std::fs::read(root.join("service.log"))?, &secrets)?;
    Ok(())
}
