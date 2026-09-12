//! Fresh, isolated acceptance flow through the shipped CLI. Stores opened here
//! only inspect outcomes; identity, group and message mutations use subprocesses.
use super::{Process, connect};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    identity::{IdentityStore, SUITE},
    wire::{self, Body},
};
use futures_util::StreamExt;
use openmls::prelude::{tls_codec::Deserialize as _, *};
use openmls_traits::{OpenMlsProvider, crypto::OpenMlsCrypto};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    time::Duration,
};

const SECRETS: [&[u8]; 4] = [
    b"EPOCHGRID_TEST_SECRET_91F3_ALICE_OFFLINE",
    b"EPOCHGRID_TEST_SECRET_91F3_BOB_REPLY",
    b"EPOCHGRID_TEST_SECRET_91F3_ALICE_RESTART",
    b"EPOCHGRID_TEST_SECRET_91F3_BOB_RESTART",
];

pub(super) async fn cli(
    root: &Path,
    url: &str,
    user: &str,
    args: &[&str],
    input: Option<&[u8]>,
) -> Result<String> {
    let binary = Path::new(env!("CARGO_BIN_EXE_epochgrid-service"))
        .with_file_name(format!("epochgrid{}", std::env::consts::EXE_SUFFIX));
    let mut stdin_file = tempfile::tempfile()?;
    if let Some(input) = input {
        stdin_file.write_all(input)?;
    }
    stdin_file.seek(SeekFrom::Start(0))?;
    let mut stdout_file = tempfile::tempfile()?;
    let mut stderr_file = tempfile::tempfile()?;
    let mut process = Process(
        Command::new(binary)
            .arg("--home")
            .arg(root.join(user))
            .arg("--server")
            .arg(url)
            .args(args)
            .stdin(stdin_file)
            .stdout(stdout_file.try_clone()?)
            .stderr(stderr_file.try_clone()?)
            .spawn()
            .context("build host binaries with cargo build --workspace before the MVP test")?,
    );
    let status = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(status) = process.0.try_wait()? {
                return Ok::<_, anyhow::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("CLI timed out")??;
    // Files cannot fill a pipe while the parent waits for process exit. Reads do
    // not wait for EOF from an inherited descriptor in a surviving descendant.
    stdout_file.seek(SeekFrom::Start(0))?;
    stderr_file.seek(SeekFrom::Start(0))?;
    let mut stdout = String::new();
    stdout_file.take(1_048_576).read_to_string(&mut stdout)?;
    let mut stderr = String::new();
    stderr_file.take(1_048_576).read_to_string(&mut stderr)?;
    ensure!(
        status.success(),
        "CLI command failed: {user} {args:?}: {stderr}"
    );
    Ok(stdout)
}
pub(super) fn daemon(root: &Path, url: &str) -> Result<Process> {
    let log = File::options()
        .create(true)
        .append(true)
        .open(root.join("service.log"))?;
    Ok(Process(
        Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
            .arg("--dev-static")
            .arg("--home")
            .arg(root.join("service"))
            .arg("--enrollment")
            .arg(root.join("enrollment.json"))
            .arg("--server")
            .arg(url)
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    ))
}
pub(super) async fn ready(root: &Path, url: &str, register: bool) -> Result<()> {
    let args: &[&str] = if register {
        &["identity", "register"]
    } else {
        &["identity", "lookup", "bob"]
    };
    for _ in 0..30 {
        if cli(root, url, "alice", args, None).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("identity service did not become ready")
}
fn no_secrets(bytes: &[u8], seeds: &[String]) -> Result<()> {
    for secret in SECRETS
        .iter()
        .copied()
        .chain(seeds.iter().map(|s| s.as_bytes()))
    {
        ensure!(
            !bytes.windows(secret.len()).any(|w| w == secret),
            "application plaintext or client NKey seed found in infrastructure data"
        );
    }
    Ok(())
}
fn scan_files(path: &Path, seeds: &[String]) -> Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            count += scan_files(&entry.path(), seeds)?;
        } else if entry.file_type()?.is_file() {
            no_secrets(&std::fs::read(entry.path())?, seeds)?;
            count += 1;
        }
    }
    Ok(count)
}

#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn cli_mvp_ciphertext_only_and_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    for user in ["alice", "bob"] {
        cli(
            root,
            &url,
            user,
            &["identity", "init", user, "--device", "laptop"],
            None,
        )
        .await?;
    }
    let alice = IdentityStore::open(&root.join("alice"))?;
    let bob = IdentityStore::open(&root.join("bob"))?;
    let identities = [alice.registration()?, bob.registration()?];
    ensure!(identities[0].payload.nats_public_key != identities[1].payload.nats_public_key);
    let seeds = [alice.nkey()?.seed()?, bob.nkey()?.seed()?];
    let mut mls_keys = Vec::new();
    for store in [&alice, &bob] {
        let package =
            KeyPackageIn::tls_deserialize_exact(&store.registration()?.payload.mls_key_package)?
                .validate(store.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| anyhow::anyhow!("invalid local KeyPackage"))?;
        let public = package.leaf_node().signature_key().as_slice().to_vec();
        let challenge = b"EpochGrid key separation acceptance test";
        let signature = store.nkey()?.sign(challenge)?;
        store.nkey()?.verify(challenge, &signature)?;
        ensure!(
            store
                .provider
                .crypto()
                .verify_signature(SUITE.signature_algorithm(), challenge, &public, &signature)
                .is_err(),
            "NATS and MLS signing keys must be independent"
        );
        mls_keys.push(public);
    }
    ensure!(mls_keys[0] != mls_keys[1]);
    drop(alice);
    drop(bob);
    cli(
        root,
        &url,
        "alice",
        &[
            "dev-config",
            "--root",
            root.to_str().context("non-UTF8 test root")?,
            "--port",
            &port.to_string(),
        ],
        None,
    )
    .await?;
    let nats = super::server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let probe = connect(&url, &admin).await?;
    drop(probe);
    drop(admin);
    let service = daemon(root, &url)?;
    ready(root, &url, true).await?;
    cli(root, &url, "bob", &["identity", "register"], None).await?;
    for (user, peer) in [("alice", 1), ("bob", 0)] {
        let found = cli(
            root,
            &url,
            user,
            &["identity", "lookup", &identities[peer].payload.user_id],
            None,
        )
        .await?;
        ensure!(
            serde_json::from_str::<wire::RegistrationPayload>(&found)? == identities[peer].payload
        );
    }
    cli(
        root,
        &url,
        "alice",
        &["channel", "create", "engineering"],
        None,
    )
    .await?;
    let original_groups = cli(root, &url, "alice", &["channel", "list"], None).await?;
    cli(
        root,
        &url,
        "alice",
        &["channel", "invite", "engineering", "bob"],
        None,
    )
    .await?;
    // Bob has no client process while Welcome and the first application are published.
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(SECRETS[0]),
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
    let received = cli(
        root,
        &url,
        "bob",
        &["message", "receive", "engineering", "--timeout", "5"],
        None,
    )
    .await?;
    ensure!(received.trim_end() == format!("alice/laptop> {}", std::str::from_utf8(SECRETS[0])?));
    cli(
        root,
        &url,
        "bob",
        &["message", "send", "engineering"],
        Some(SECRETS[1]),
    )
    .await?;
    let received = cli(
        root,
        &url,
        "alice",
        &["message", "receive", "engineering", "--timeout", "5"],
        None,
    )
    .await?;
    ensure!(received.trim_end() == format!("bob/laptop> {}", std::str::from_utf8(SECRETS[1])?));

    // All CLI processes have exited. Restart both infrastructure processes on disk state.
    drop(service);
    drop(nats);
    let nats = super::server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let admin_client = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root, &url)?;
    ready(root, &url, false).await?; // Lookup only: no registration/group recreation.
    for (user, index) in [("alice", 2), ("bob", 3)] {
        cli(
            root,
            &url,
            user,
            &["message", "send", "engineering"],
            Some(SECRETS[index]),
        )
        .await?;
    }
    for (index, user) in ["alice", "bob"].into_iter().enumerate() {
        cli(root, &url, user, &["channel", "sync", "engineering"], None).await?;
        ensure!(cli(root, &url, user, &["channel", "list"], None).await? == original_groups);
        let members = cli(
            root,
            &url,
            user,
            &["channel", "members", "engineering"],
            None,
        )
        .await?;
        ensure!(members.lines().collect::<Vec<_>>() == ["alice/laptop", "bob/laptop"]);
        let store = IdentityStore::open(&root.join(user))?;
        ensure!(store.registration()? == identities[index]);
        let entries = store.history("engineering", 10, None)?;
        ensure!(entries.len() == SECRETS.len());
        for (position, (entry, secret)) in entries.iter().zip(SECRETS).enumerate() {
            ensure!(entry.plaintext.as_deref() == Some(secret));
            let sender = if position % 2 == 0 {
                "alice/laptop"
            } else {
                "bob/laptop"
            };
            ensure!(entry.sender.as_deref() == Some(sender));
            ensure!(entry.outgoing == (position % 2 == index));
        }
        ensure!(entries.windows(2).all(|w| w[0].sequence < w[1].sequence));
        ensure!(store.rejected_history("engineering")? == 0);
    }
    ensure!(
        IdentityStore::open(&root.join("service"))?
            .groups()?
            .is_empty()
    );
    // Inspect everything persisted by this fresh server, not just one selected payload.
    let js = async_nats::jetstream::new(admin_client.clone());
    let mut streams = js.streams();
    let mut names = Vec::new();
    while let Some(info) = streams.next().await {
        names.push(info?.config.name);
    }
    names.sort();
    ensure!(
        names
            == [
                "CHAT",
                "KV_CHANNELS",
                "KV_IDENTITIES",
                "KV_TRANSPARENCY",
                "MAILBOX",
                "OBJ_ATTACHMENTS"
            ]
    );
    let group = IdentityStore::open(&root.join("alice"))?.group("engineering")?;
    let expected_mls_id = format!("epochgrid/v1/engineering/{}", group.gid);
    let mut applications = 0;
    let mut commits = 0;
    let mut welcomes = 0;
    for name in names {
        let mut stream = js.get_stream(&name).await?;
        let last = stream.info().await?.state.last_sequence;
        let first = stream.cached_info().state.first_sequence.max(1);
        for sequence in first..=last {
            let message = match stream.get_raw_message(sequence).await {
                Ok(message) => message,
                Err(error)
                    if name.starts_with("KV_")
                        && matches!(
                            error.kind(),
                            async_nats::jetstream::stream::RawMessageErrorKind::NoMessageFound
                        ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            no_secrets(&message.payload, &seeds)?;
            no_secrets(message.subject.as_bytes(), &seeds)?;
            no_secrets(format!("{:?}", message.headers).as_bytes(), &seeds)?;
            if name == "CHAT" {
                let mls = MlsMessageIn::tls_deserialize_exact(&message.payload)?;
                ensure!(mls.wire_format() == WireFormat::PrivateMessage);
                let protocol = mls
                    .try_into_protocol_message()
                    .map_err(|_| anyhow::anyhow!("invalid CHAT MLS framing"))?;
                ensure!(protocol.group_id().as_slice() == expected_mls_id.as_bytes());
                match protocol.content_type() {
                    ContentType::Application => {
                        ensure!(message.subject.as_str() == group.subject("message"));
                        applications += 1;
                    }
                    ContentType::Commit => {
                        ensure!(message.subject.as_str() == group.subject("handshake"));
                        commits += 1;
                    }
                    _ => anyhow::bail!("unexpected CHAT content"),
                }
            } else if name == "MAILBOX" {
                ensure!(message.subject.as_str() == "epochgrid.v1.user.bob.laptop.inbox");
                let Body::Welcome { payload } = wire::decode(&message.payload)? else {
                    anyhow::bail!("invalid mailbox envelope");
                };
                ensure!(matches!(
                    MlsMessageIn::tls_deserialize_exact(&payload)?.extract(),
                    MlsMessageBodyIn::Welcome(_)
                ));
                welcomes += 1;
            }
        }
    }
    ensure!(applications == 4 && commits == 1 && welcomes == 1);
    let directory = js.get_key_value("IDENTITIES").await?;
    for identity in identities {
        let value = directory
            .get(identity.payload.key())
            .await?
            .context("public registration missing")?;
        ensure!(matches!(wire::decode(&value)?, Body::Register(r) if r == identity));
    }
    drop(streams);
    drop(js);
    drop(admin_client);
    drop(service);
    drop(nats);
    // Offline history also works after infrastructure stops, without another decryption.
    for user in ["alice", "bob"] {
        let text = cli(
            root,
            "nats://127.0.0.1:1",
            user,
            &["message", "history", "engineering", "--offline"],
            None,
        )
        .await?;
        for secret in SECRETS {
            ensure!(text.matches(std::str::from_utf8(secret)?).count() == 1);
        }
    }
    ensure!(scan_files(&root.join("jetstream"), &seeds)? > 0);
    ensure!(scan_files(&root.join("service"), &seeds)? > 0);
    no_secrets(&std::fs::read(root.join("service.log"))?, &seeds)?;
    Ok(())
}
