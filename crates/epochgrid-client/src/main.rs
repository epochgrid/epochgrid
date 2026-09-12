mod chat;
mod participant;
mod recovery;
mod tui;
use anyhow::Result;
use clap::{Parser, Subcommand};
use epochgrid_core::{identity::IdentityStore, transparency, transport, trust};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "epochgrid", about = "EpochGrid secure group communications")]
struct Args {
    #[arg(long, env = "EPOCHGRID_HOME", default_value = ".dev/alice")]
    home: PathBuf,
    #[arg(
        long,
        env = "EPOCHGRID_NATS_URL",
        default_value = "nats://127.0.0.1:4222"
    )]
    server: String,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run an explicitly invited MLS service participant (separate from the backend).
    Participant {
        #[command(subcommand)]
        command: participant::Command,
    },
    /// Send, list or explicitly save encrypted attachments.
    Attachment {
        #[command(subcommand)]
        command: Attachment,
    },
    /// Client-encrypted identity administration recovery (no MLS history backup).
    Recovery {
        #[command(subcommand)]
        command: recovery::Command,
    },
    /// Audit the registration log or inspect/pin its local checkpoint.
    Transparency {
        #[command(subcommand)]
        command: Transparency,
    },
    /// Persistent terminal client with history and automatic reconnect.
    Tui,
    /// Initialize an independent device or list a user's registered devices.
    Device {
        #[command(subcommand)]
        command: Device,
    },
    /// MLS encrypted chat with automatic offline catch-up; /quit exits.
    Chat { name: String },
    Message {
        #[command(subcommand)]
        command: Message,
    },
    Identity {
        #[command(subcommand)]
        command: Identity,
    },
    Channel {
        #[command(subcommand)]
        command: Channel,
    },
    /// Generate local development identities, enrollment and NATS configuration.
    DevConfig {
        #[arg(long, default_value = ".dev")]
        root: PathBuf,
        #[arg(long, default_value_t = 4222)]
        port: u16,
        /// Operator-authorized public binding, USER/DEVICE=NKEY; repeat for multiple devices.
        #[arg(long)]
        enroll: Vec<String>,
    },
}
#[derive(Subcommand)]
enum Transparency {
    Audit,
    Status,
    /// Pin the service public NKey obtained independently before first use.
    Pin {
        key: String,
    },
}
#[derive(Subcommand)]
enum Device {
    /// Irreversibly revoke another device of this user (or any device as operator).
    Revoke {
        user: String,
        device: String,
    },
    /// Show your own fingerprint, or discover a specific remote device.
    Fingerprint {
        user: Option<String>,
        device: Option<String>,
        /// Inspect retained fingerprints and warnings without contacting the directory.
        #[arg(long)]
        offline: bool,
    },
    /// Compare a full fingerprint obtained over an independent channel.
    Verify {
        user: String,
        device: String,
        #[arg(long)]
        fingerprint: String,
    },
    Add {
        user: String,
        #[arg(long)]
        device: String,
    },
    List {
        user: Option<String>,
    },
}
#[derive(Subcommand)]
enum Identity {
    Verify {
        user: String,
        #[arg(long, default_value = "laptop")]
        device: String,
        #[arg(long)]
        fingerprint: String,
    },
    Init {
        user: String,
        #[arg(long, default_value = "laptop")]
        device: String,
    },
    Show,
    Register,
    Lookup {
        user: String,
        #[arg(long, default_value = "laptop")]
        device: String,
    },
}
#[derive(Subcommand)]
enum Channel {
    /// Coordinator removes one device from this channel and advances its MLS epoch.
    Remove {
        name: String,
        user: String,
        #[arg(long)]
        device: String,
    },
    Create {
        name: String,
    },
    Members {
        name: String,
        /// Collapse device leaves into logical user membership.
        #[arg(long)]
        users: bool,
    },
    List,
    /// Retry queued ciphertext, then fetch and decrypt the current durable backlog.
    Sync {
        name: String,
    },
    /// Retry queued ciphertext without encrypting it again.
    Flush,
    Invite {
        name: String,
        user: String,
        #[arg(long, default_value = "laptop")]
        device: String,
    },
    Join {
        #[arg(long)]
        from: String,
        #[arg(long, default_value = "laptop")]
        device: String,
    },
}
#[derive(Subcommand)]
enum Attachment {
    Send {
        name: String,
        file: PathBuf,
        #[arg(long, default_value = "application/octet-stream")]
        mime: String,
    },
    List {
        name: String,
    },
    Save {
        name: String,
        id: String,
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum Message {
    /// Inspect immutable event content and full stable IDs.
    Events {
        name: String,
        #[arg(long)]
        offline: bool,
    },
    /// Reply to a message ID (an unambiguous prefix is accepted).
    Reply {
        name: String,
        target: String,
        text: String,
    },
    /// Append a replacement for a text message sent by this device.
    Edit {
        name: String,
        target: String,
        text: String,
    },
    /// Add a reaction, or remove this device's reaction with --remove.
    React {
        name: String,
        target: String,
        value: String,
        #[arg(long)]
        remove: bool,
    },
    /// Exchange encrypted device receipts, or show locally retained status.
    Receipts {
        name: String,
        #[arg(long, default_value_t = 5)]
        wait: u64,
        #[arg(long)]
        offline: bool,
    },
    /// Read one UTF-8 message from stdin and publish MLS ciphertext.
    Send { name: String },
    /// Read retained history, fetching the current backlog unless --offline is set.
    History {
        name: String,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        before: Option<u64>,
        #[arg(long)]
        offline: bool,
    },
    /// Receive the next undisplayed message, including messages sent while offline.
    Receive {
        name: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(if matches!(args.command, Command::Tui) {
            tracing_subscriber::EnvFilter::new("off")
        } else {
            tracing_subscriber::EnvFilter::from_default_env()
        })
        .init();
    if matches!(
        args.command,
        Command::Tui
            | Command::Chat { .. }
            | Command::Message { .. }
            | Command::Channel { .. }
            | Command::Attachment { .. }
    ) {
        IdentityStore::open(&args.home)?.ensure_messaging_identity()?;
    }
    match args.command {
        Command::Attachment { command } => {
            use epochgrid_core::attachments::{self, Limits};
            let store = IdentityStore::open(&args.home)?;
            match command {
                Attachment::List { name } => {
                    for manifest in store.attachments(&name)? {
                        println!("{}", manifest.summary());
                    }
                }
                Attachment::Send { name, file, mime } => {
                    let client = transport::connect(&args.server, &store).await?;
                    let id = attachments::send_file(
                        &store,
                        &client,
                        &name,
                        &file,
                        &mime,
                        Limits::from_env()?,
                    )
                    .await?;
                    println!("EpochGrid encrypted attachment sent: {id}");
                }
                Attachment::Save { name, id, output } => {
                    let client = transport::connect(&args.server, &store).await?;
                    attachments::save_file(
                        &store,
                        &client,
                        &name,
                        &id,
                        &output,
                        Limits::from_env()?,
                    )
                    .await?;
                    println!(
                        "EpochGrid authenticated attachment saved: {}",
                        output.display()
                    );
                }
            }
        }

        Command::Participant { command } => {
            participant::run(&args.home, &args.server, command).await?
        }
        Command::Recovery { command } => recovery::run(&args.home, command)?,
        Command::Transparency { command } => {
            let store = IdentityStore::open(&args.home)?;
            match command {
                Transparency::Pin { key } => {
                    store.pin_directory(&key)?;
                    println!("EpochGrid directory key pinned: {key}");
                }
                Transparency::Audit => {
                    let client = transport::connect(&args.server, &store).await?;
                    let snapshot = transparency::audit(&client, &store).await?;
                    println!(
                        "EpochGrid transparency audit passed: {} registrations; signer {}",
                        snapshot.checkpoint.size, snapshot.checkpoint.signer
                    );
                    println!(
                        "First contact is trust-on-first-use unless the signer was pinned independently."
                    );
                }
                Transparency::Status => {
                    if let Some(checkpoint) = store.checkpoint()? {
                        println!(
                            "EpochGrid transparency checkpoint: {} registrations; signer {}",
                            checkpoint.size, checkpoint.signer
                        );
                        println!(
                            "Root: {}",
                            checkpoint
                                .root
                                .iter()
                                .map(|b| format!("{b:02X}"))
                                .collect::<String>()
                        );
                    } else {
                        println!("EpochGrid transparency: no audited checkpoint");
                        if let Some(key) = store.directory_key()? {
                            println!("Pinned signer: {key}");
                        }
                    }
                    if let Some(checkpoint) = store.revocation_checkpoint()? {
                        println!(
                            "Revocation checkpoint: {} devices; signer {}",
                            checkpoint.size, checkpoint.signer
                        );
                    }
                    for group in store.groups()? {
                        if store.rekey_pending(&group.name)? {
                            println!("MLS rekey pending: {}", group.name);
                        }
                    }
                    if let Some(warning) = store.trust_warning()? {
                        println!("{warning}");
                    }
                }
            }
        }
        Command::Device { command } => {
            let mut store = IdentityStore::open(&args.home)?;
            match command {
                Device::Revoke { user, device } => {
                    let client = transport::connect(&args.server, &store).await?;
                    epochgrid_core::revocation::revoke(&client, &store, &user, &device).await?;
                    println!(
                        "EpochGrid NATS access revoked: {user}/{device}. MLS groups rekey as their active coordinators sync."
                    );
                    for group in store.groups()? {
                        if store.rekey_pending(&group.name)? {
                            println!("Rekey pending: {}", group.name);
                        }
                    }
                }
                Device::Fingerprint {
                    user,
                    device,
                    offline,
                } => {
                    if offline && let Some(user) = &user {
                        let observed = store
                            .device_trust(user, device.as_deref().unwrap_or("laptop"))?
                            .ok_or_else(|| anyhow::anyhow!("device has not been observed"))?;
                        println!(
                            "EpochGrid device: {}/{} [{}]",
                            observed.user, observed.device, observed.state
                        );
                        println!(
                            "Pinned fingerprint: {}",
                            trust::display_fingerprint(&observed.fingerprint)
                        );
                        println!(
                            "Latest fingerprint: {}",
                            trust::display_fingerprint(&observed.latest_fingerprint)
                        );
                        return Ok(());
                    }
                    let registration = if let Some(user) = user {
                        let client = transport::connect(&args.server, &store).await?;
                        transparency::lookup(
                            &client,
                            &store,
                            &user,
                            device.as_deref().unwrap_or("laptop"),
                        )
                        .await?
                    } else {
                        store.registration()?
                    };
                    println!(
                        "EpochGrid device: {}/{}",
                        registration.payload.user_id, registration.payload.device_id
                    );
                    println!(
                        "Fingerprint: {}",
                        trust::display_fingerprint(&trust::fingerprint(&registration)?)
                    );
                }
                Device::Verify {
                    user,
                    device,
                    fingerprint,
                } => {
                    verify_device(&store, &args.server, &user, &device, &fingerprint).await?;
                }
                Device::Add { user, device } => {
                    let registration = store.init(&user, &device)?;
                    println!("EpochGrid device initialized: {user}/{device}");
                    println!(
                        "Operator enrollment: {user}/{device}={}",
                        registration.payload.nats_public_key
                    );
                }
                Device::List { user } => {
                    let user = user.unwrap_or(store.registration()?.payload.user_id);
                    let client = transport::connect(&args.server, &store).await?;
                    for registration in transparency::devices(&client, &store, &user).await? {
                        let p = registration.payload;
                        let state = store
                            .device_trust(&p.user_id, &p.device_id)?
                            .map_or("unverified".into(), |t| t.state);
                        let authorization = if store.is_revoked(&p.nats_public_key)? {
                            "revoked"
                        } else {
                            "active"
                        };
                        println!(
                            "{}/{} {} [{authorization}] [{state}]",
                            p.user_id, p.device_id, p.nats_public_key
                        );
                    }
                }
            }
        }
        Command::Tui => {
            tui::run(args.home, args.server)?;
        }
        Command::Chat { name } => {
            chat::interactive(&args.home, &args.server, &name).await?;
        }
        Command::Message { command } => match command {
            Message::Events { name, offline } => {
                chat::events(&args.home, &args.server, &name, offline).await?
            }
            Message::Reply { name, target, text } => {
                chat::relate(&args.home, &args.server, &name, &target, &text, "reply").await?
            }
            Message::Edit { name, target, text } => {
                chat::relate(&args.home, &args.server, &name, &target, &text, "edit").await?
            }
            Message::React {
                name,
                target,
                value,
                remove,
            } => {
                chat::relate(
                    &args.home,
                    &args.server,
                    &name,
                    &target,
                    &value,
                    if remove { "unreact" } else { "react" },
                )
                .await?
            }
            Message::Receipts {
                name,
                wait,
                offline,
            } => {
                anyhow::ensure!(
                    (1..=60).contains(&wait),
                    "receipt wait must be 1–60 seconds"
                );
                let store = IdentityStore::open(&args.home)?;
                if !offline {
                    let client = transport::connect(&args.server, &store).await?;
                    epochgrid_core::receipts::exchange(
                        &store,
                        &client,
                        &name,
                        std::time::Duration::from_secs(wait),
                    )
                    .await?;
                }
                for entry in store
                    .history(&name, 100, None)?
                    .into_iter()
                    .filter(|e| e.outgoing)
                {
                    println!(
                        "[{}] {}",
                        entry
                            .sequence
                            .map_or_else(|| "pending".into(), |s| s.to_string()),
                        store.message_status(entry.id)?.summary()
                    );
                }
            }
            Message::Send { name } => {
                use std::io::Read;
                let mut text = String::new();
                std::io::stdin()
                    .take((epochgrid_core::messaging::MAX_PLAINTEXT + 1) as u64)
                    .read_to_string(&mut text)?;
                let store = IdentityStore::open(&args.home)?;
                let client = transport::connect(&args.server, &store).await?;
                epochgrid_core::messaging::send(&store, &client, &name, text.as_bytes()).await?;
                println!("EpochGrid encrypted message accepted by server");
            }
            Message::History {
                name,
                limit,
                before,
                offline,
            } => {
                chat::history(&args.home, &args.server, &name, limit, before, offline).await?;
            }
            Message::Receive { name, timeout } => {
                chat::receive(&args.home, &args.server, &name, timeout).await?;
            }
        },
        Command::DevConfig { root, port, enroll } => {
            transport::dev_config_with_enrollment(&root, port, &enroll)?;
            println!(
                "EpochGrid development configuration ready in {}",
                root.display()
            );
        }
        Command::Channel { command } => {
            let store = IdentityStore::open(&args.home)?;
            match command {
                Channel::Remove { name, user, device } => {
                    let client = transport::connect(&args.server, &store).await?;
                    tokio::time::timeout(std::time::Duration::from_secs(15), async {
                        epochgrid_core::history::resume(&store, &client, &name).await?;
                        store.remove_member(&name, &user, &device)?;
                        epochgrid_core::delivery::flush_outbox(&store, &client).await
                    })
                    .await??;
                    println!("EpochGrid removed {user}/{device}; channel epoch advanced");
                }
                Channel::Create { name } => {
                    let group = store.create_group(&name)?;
                    println!("EpochGrid channel created: {} ({})", group.name, group.gid);
                }
                Channel::Members { name, users } => {
                    for member in if users {
                        store.users(&name)?
                    } else {
                        store.members(&name)?
                    } {
                        println!("{member}");
                    }
                }
                Channel::Invite { name, user, device } => {
                    let client = transport::connect(&args.server, &store).await?;
                    epochgrid_core::delivery::invite(&store, &client, &name, &user, &device)
                        .await?;
                    println!("EpochGrid invitation delivered to {user}/{device}");
                }
                Channel::Join { from, device } => {
                    let client = transport::connect(&args.server, &store).await?;
                    let group =
                        epochgrid_core::delivery::join_next(&store, &client, &from, &device)
                            .await?;
                    println!("EpochGrid channel joined: {} ({})", group.name, group.gid);
                }
                Channel::Sync { name } => {
                    let client = transport::connect(&args.server, &store).await?;
                    let report = epochgrid_core::history::resume(&store, &client, &name).await?;
                    println!(
                        "EpochGrid caught up: {} decrypted, {} rejected, {} unavailable",
                        report.decrypted, report.rejected, report.unavailable
                    );
                }
                Channel::Flush => {
                    let client = transport::connect(&args.server, &store).await?;
                    epochgrid_core::delivery::flush_outbox(&store, &client).await?;
                    println!("EpochGrid outbox delivered");
                }
                Channel::List => {
                    for group in store.groups()? {
                        println!("{} {}", group.name, group.gid);
                    }
                }
            }
        }
        Command::Identity { command } => {
            let mut store = IdentityStore::open(&args.home)?;
            match command {
                Identity::Verify {
                    user,
                    device,
                    fingerprint,
                } => {
                    verify_device(&store, &args.server, &user, &device, &fingerprint).await?;
                }
                Identity::Init { user, device } => {
                    let r = store.init(&user, &device)?;
                    println!(
                        "EpochGrid identity initialized: {}/{} ({})",
                        r.payload.user_id, r.payload.device_id, r.payload.nats_public_key
                    );
                }
                Identity::Show => println!(
                    "{}",
                    serde_json::to_string_pretty(&store.registration()?.payload)?
                ),
                Identity::Lookup { user, device } => {
                    let client = transport::connect(&args.server, &store).await?;
                    let registration =
                        transparency::lookup(&client, &store, &user, &device).await?;
                    println!("{}", serde_json::to_string_pretty(&registration.payload)?);
                }
                Identity::Register => {
                    store.ensure_messaging_identity()?;
                    let client = transport::connect(&args.server, &store).await?;
                    transport::register(&client, store.registration()?).await?;
                    let own = store.registration()?;
                    let logged = transparency::lookup(
                        &client,
                        &store,
                        &own.payload.user_id,
                        &own.payload.device_id,
                    )
                    .await?;
                    anyhow::ensure!(
                        logged == own,
                        "own registration differs from authenticated log"
                    );
                    println!("EpochGrid device registered");
                }
            }
        }
    }
    Ok(())
}

async fn verify_device(
    store: &IdentityStore,
    server: &str,
    user: &str,
    device: &str,
    fingerprint: &str,
) -> Result<()> {
    let client = transport::connect(server, store).await?;
    transparency::lookup(&client, store, user, device).await?;
    store.verify_device(user, device, fingerprint)?;
    println!("EpochGrid device verified: {user}/{device}");
    Ok(())
}
