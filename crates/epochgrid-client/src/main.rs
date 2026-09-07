mod chat;
use anyhow::Result;
use clap::{Parser, Subcommand};
use epochgrid_core::{identity::IdentityStore, transport};
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
    },
}
#[derive(Subcommand)]
enum Identity {
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
    Create {
        name: String,
    },
    Members {
        name: String,
    },
    List,
    /// Fetch and decrypt the current durable backlog.
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
enum Message {
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    match args.command {
        Command::Chat { name } => {
            chat::interactive(&args.home, &args.server, &name).await?;
        }
        Command::Message { command } => match command {
            Message::Send { name } => {
                use std::io::Read;
                let mut text = String::new();
                std::io::stdin()
                    .take((epochgrid_core::messaging::MAX_PLAINTEXT + 1) as u64)
                    .read_to_string(&mut text)?;
                let store = IdentityStore::open(&args.home)?;
                let client = transport::connect(&args.server, &store).await?;
                epochgrid_core::messaging::send(&store, &client, &name, text.as_bytes()).await?;
                println!("EpochGrid encrypted message delivered");
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
        Command::DevConfig { root, port } => {
            transport::dev_config(&root, port)?;
            println!(
                "EpochGrid development configuration ready in {}",
                root.display()
            );
        }
        Command::Channel { command } => {
            let store = IdentityStore::open(&args.home)?;
            match command {
                Channel::Create { name } => {
                    let group = store.create_group(&name)?;
                    println!("EpochGrid channel created: {} ({})", group.name, group.gid);
                }
                Channel::Members { name } => {
                    for member in store.members(&name)? {
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
                    let report = epochgrid_core::history::catch_up(&store, &client, &name).await?;
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
                    let registration = transport::lookup(&client, &user, &device).await?;
                    println!("{}", serde_json::to_string_pretty(&registration.payload)?);
                }
                Identity::Register => {
                    let client = transport::connect(&args.server, &store).await?;
                    transport::register(&client, store.registration()?).await?;
                    println!("EpochGrid device registered");
                }
            }
        }
    }
    Ok(())
}
