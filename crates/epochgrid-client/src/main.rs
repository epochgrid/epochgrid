use anyhow::Result;
use clap::{Parser, Subcommand};
use epochgrid_core::{identity::IdentityStore, transport};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "epochgrid",
    about = "EpochGrid secure communications — identity foundation"
)]
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
    Create { name: String },
    Members { name: String },
    List,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    match args.command {
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
