/* smokeless_flame - implant/src/main.rs
*
*   Purpose: Reimagine NFS with security in mind using a memory safe programming language, Rust.
*               This will be re-build from the bottom up. Striving first for functionality with security by default,
*               then focusing on user experience.
*
*   Author: Mauzy0x00
*   Start Date: 10-14-2025
*
*   File Description: This is the main function of the implant. Supporting functions and loops will be called here
*/

use lib::async_io;
use lib::encryption;
use lib::error;
use lib::protocol;

mod client;
// mod filesystem_linux;
// mod filesystem_windows;

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

    // Generate encryption keypair
    let keypair = encryption::KeyPair::generate();

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
        let mut client = client::NfsClient::new(server, mount_point, keypair);

        smol::block_on(async {
            client.connect().await?;

            log::info!("Connected to server. Press Ctrl+C to disconnect.");

            // TODO:
            // Implement input loop for the client
            client.run().await?;

            // // Create remote directory
            // let remote_dir_path = "remote_test_dir";
            // let mode: u32 = 0o755;
            // match client.create_directory(remote_dir_path, mode).await {
            //     Ok(_) => log::info!("Successfully created directory: {}", remote_dir_path),
            //     Err(e) => log::error!("Error creating directory: {}", e),
            // }

            // // Wait for Ctrl+C
            // let (tx, rx) = async_std::channel::bounded(1);
            // ctrlc::set_handler(move || {
            //     let _ = tx.try_send(());
            // })?;

            // let _ = rx.recv().await;

            client.disconnect().await?;
            log::info!("Disconnected from server");

            Ok::<(), error::NfsError>(())
        })?;
    }

    Ok(())
}
