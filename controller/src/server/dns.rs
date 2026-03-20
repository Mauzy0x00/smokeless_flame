use std::time::SystemTime;

/// DNS Header structure (12 bytes)
// See RFC 1035 Section 4.1.1
pub struct DnsHeader {
    pub id: u16,       // Transaction ID
    pub flags: u16,    // Flags field
    pub qd_count: u16, // Number of questions
    pub an_count: u16, // Number of answers
    pub ns_count: u16, // Number of authority records
    pub ar_count: u16, // Number of additional records
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

/// DNS Question Type
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
}

/// Parsed DNS Question
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QType,
    pub qclass: u16,
    pub name_length: usize,
}

/// Parse DNS domain name from query (RFC 1035 Section 4.1.2)
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

/// Parse DNS question section
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

/// Build DNS A record response
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

/// Build DNS TXT record response
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
    response.extend_from_slice(&16u16.to_be_bytes()); // Type TXT
    response.extend_from_slice(&1u16.to_be_bytes()); // Class IN
    response.extend_from_slice(&60u32.to_be_bytes()); // TTL

    let txt_bytes = txt_data.as_bytes();
    let data_len = (txt_bytes.len() + 1) as u16;
    response.extend_from_slice(&data_len.to_be_bytes());
    response.push(txt_bytes.len() as u8);
    response.extend_from_slice(txt_bytes);

    response
}
