use std::{io, path::PathBuf};

use clap::{Parser, Subcommand};
use cynet::{
    config::{Config, decode_key, encode_key},
    daemon, show,
};
use eyre::Context;
use gotatun::x25519::{PublicKey, StaticSecret};
use tracing_subscriber::EnvFilter;

/// A WireGuard mesh, routed with Babel.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Brings up an interface from a config file, and runs until a signal
    Run {
        /// The TOML config file
        config: PathBuf,
    },
    /// Shows the peers and routes of an interface, or of every running one
    Show {
        /// The interface
        name: Option<String>,
    },
    /// Generates a private key and prints it in base64, as `wg genkey` does
    Genkey,
    /// Reads a private key in base64 and prints its public key, as `wg pubkey` does
    Pubkey,
    /// Generates a preshared key and prints it in base64, as `wg genpsk` does
    Genpsk,
}

/// Returns 32 random octets from the operating system.
fn random_key() -> eyre::Result<[u8; 32]> {
    let mut key = [0; 32];
    getrandom::fill(&mut key).map_err(|error| eyre::eyre!("no random numbers: {error}"))?;
    Ok(key)
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(io::stderr)
        .init();

    match Cli::parse().command {
        Command::Run { config } => daemon::run(Config::load(&config)?).await,
        Command::Show { name } => show::show(name.as_deref()).await,
        Command::Genkey => {
            let mut key = random_key()?;
            // Clamped as Curve25519 expects, as `wg genkey` does.
            key[0] &= 248;
            key[31] = (key[31] & 127) | 64;
            println!("{}", encode_key(&key));
            Ok(())
        }
        Command::Pubkey => {
            let mut line = String::new();
            io::stdin()
                .read_line(&mut line)
                .wrap_err("failed to read the private key")?;
            let key = decode_key(line.trim()).wrap_err("invalid private key")?;
            let key = PublicKey::from(&StaticSecret::from(key));
            println!("{}", encode_key(key.as_bytes()));
            Ok(())
        }
        Command::Genpsk => {
            println!("{}", encode_key(&random_key()?));
            Ok(())
        }
    }
}
