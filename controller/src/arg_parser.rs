/*  Smokeless Flame
*
*   Uses the clap library to parse user CLI input.
*   Args: Single command arguments that produce an output
*   Commands: These are command 'modes' that take many inputs to perform a task and output to the user.
*             Some of the arguments for each mode are optional; Defined with 'default_value = "foobar"'
*/

use clap::{Parser, Subcommand};
use std::{net::Ipv4Addr, path::PathBuf};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help(true))]
pub struct Args {
    // the subcommands for different modules
    #[command(subcommand)]
    pub command: Option<Commands>,

    // global commands
    #[arg(
        short = 'l',
        long = "list",
        help = "List available hashing algorithms."
    )]
    pub list: bool,
}