//! AIPP edge broker.
//!
//! One TCP listener, one thread per connection, one mutex over the
//! routing state. The design goal of v0.1 is *legibility*: an operator
//! must be able to `telnet` into the broker, type `NICK`/`JOIN`/
//! `PRIVMSG`, and see the same lines the agents see.
//!
//! Responsibilities:
//! * control-plane command dispatch (IRC surface),
//! * presence bookkeeping + heartbeat TTL eviction (ICQ surface),
//! * channel membership and operator flags,
//! * binary TLV multiplexing (`BIN_FRAME` announce + frame forwarding),
//! * an append-only JSONL log so a run can be audited after the fact.
//!
//! Deliberate v0.1 limits (see README): one process, in-memory state, no
//! federation between brokers, blocking writes to slow peers.

use aipp_core::channel::Registry;
use aipp_core::control::is_pool;
use aipp_core::control::Command;
use aipp_core::flow::{FlowError, Outbox};
use aipp_core::presence::AgentRecord;
use aipp_core::security::{cap, Authority, Identity, RateLimiter};
use aipp_core::tlv::{tlv_label, Frame};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// What the reader pulled off the wire.
enum Item {
    Line(String),
    Frame(Frame),
}

/// A `BIN_FRAME` announcement waiting for its payload bytes.
#[derive(Clone, Debug)]
struct PendingFrame {
    target: String,
    tlv_type: u16,
    length: u32,
}

struct Conn {
    id: u64,
    /// Set by `NICK`; `None` until the agent identifies itself.
    name: Mutex<Option<String>>,
    /// bounded output queue with its own writer thread: a stalled peer
    /// produces `ERR 509` instead of parking the broker
    out: Arc<Outbox>,
    pending: Mutex<Option<PendingFrame>>,
    /// Verified identity, when the broker requires one.
    identity: Mutex<Option<Identity>>,
    /// advertised capabilities from `USER`
    caps: Mutex<u32>,
    limiter: Mutex<RateLimiter>,
}

impl Conn {
    fn send_bytes(&self, bytes: &[u8]) {
        // the Outbox serialises writes on its own thread, so two threads
        // can never interleave fragments of a line on the same socket
        let _ = self.out.send(bytes.to_vec());
    }

    /// Same, but the caller learns that the peer is not draining.
    fn send_line_checked(&self, line: &str) -> Result<(), FlowError> {
        self.out.send(format!("{line}\r\n").into_bytes())
    }

    fn send_line(&self, line: &str) {
        self.send_bytes(format!("{line}\r\n").as_bytes());
    }
}

/// One held message: who sent it, what it said, and when it expires.
struct Stored {
    at: Instant,
    from: String,
    text: String,
}

struct Broker {
    conns: BTreeMap<u64, Arc<Conn>>,
    agents: BTreeMap<String, AgentRecord>,
    reg: Registry,
    ttl: Duration,
    log: Option<PathBuf>,
    /// `Some` = AUTH is required before NICK and the AG-ID comes from the
    /// token, not from the claim
    auth: Option<Authority>,
    /// per-connection limits; 0 = unlimited
    max_cmds_per_sec: u32,
    max_bytes_per_sec: u32,
    /// agents that asked to drain: no new tasks are dispatched to them
    draining: BTreeSet<String>,
    /// STORE_FORWARD: messages held for an agent that is not connected
    store: BTreeMap<String, Vec<Stored>>,
    store_ttl: Duration,
    store_max: usize,
    /// channels survive a restart; connections never do
    state_path: Option<PathBuf>,
}

impl Broker {
    fn new(ttl: Duration, log: Option<PathBuf>) -> Self {
        Self {
            conns: BTreeMap::new(),
            agents: BTreeMap::new(),
            reg: Registry::new(),
            ttl,
            log,
            auth: None,
            max_cmds_per_sec: 0,
            max_bytes_per_sec: 0,
            draining: BTreeSet::new(),
            store: BTreeMap::new(),
            store_ttl: Duration::from_secs(900),
            store_max: 256,
            state_path: None,
        }
    }

    /// Hold a message for an agent that is not connected (the wire form is
    /// the `STORE_FORWARD` TLV in the payload plane; here it is the
    /// control-plane courtesy that keeps a dispatch from being lost).
    fn store_for(&mut self, target: &str, from: &str, text: &str) -> usize {
        let q = self.store.entry(target.to_string()).or_default();
        q.push(Stored {
            at: Instant::now(),
            from: from.to_string(),
            text: text.to_string(),
        });
        while q.len() > self.store_max {
            q.remove(0);
        }
        self.store.get(target).map(|q| q.len()).unwrap_or(0)
    }

    /// Hand the backlog over at registration, then forget it.
    fn drain_store(&mut self, agent: &str) -> Vec<(String, String)> {
        self.store
            .remove(agent)
            .map(|q| {
                q.into_iter()
                    .filter(|m| m.at.elapsed() < self.store_ttl)
                    .map(|m| (m.from, m.text))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn sweep_store(&mut self) -> usize {
        let ttl = self.store_ttl;
        let mut dropped = 0;
        for q in self.store.values_mut() {
            let before = q.len();
            q.retain(|m| m.at.elapsed() < ttl);
            dropped += before - q.len();
        }
        self.store.retain(|_, q| !q.is_empty());
        dropped
    }

    fn save_state(&self) {
        let Some(path) = &self.state_path else { return };
        let chans: Vec<serde_json::Value> = self
            .reg
            .snapshot()
            .into_iter()
            .map(|c| {
                json!({"name": c.name, "moderated": c.moderated,
                       "invite_only": c.invite_only, "topic_locked": c.topic_locked,
                       "topic": c.topic, "bans": c.bans})
            })
            .collect();
        let doc = json!({"version": 1, "channels": chans});
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, doc.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    fn load_state(&mut self) {
        let Some(path) = &self.state_path else { return };
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
            eprintln!("[aipp] state file {path:?} is not valid JSON; ignoring it");
            return;
        };
        if let Some(chans) = doc.get("channels").and_then(|c| c.as_array()) {
            for c in chans {
                let name = c.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                self.reg.restore(
                    name,
                    c.get("moderated")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    c.get("invite_only")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    c.get("topic_locked")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    c.get("topic").and_then(|v| v.as_str()).map(str::to_string),
                    c.get("bans")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|b| b.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default(),
                );
            }
        }
    }

    fn journal(&self, ev: &str, detail: serde_json::Value) {
        if let Some(path) = &self.log {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let line = json!({"ts_ms": ts, "ev": ev, "detail": detail});
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{line}");
            }
        }
    }

    /// Resolve a target (`#channel` or `nick`) to the connections that
    /// must receive a message, excluding the sender.
    fn targets(&self, target: &str, sender: &str) -> Vec<Arc<Conn>> {
        let names: Vec<String> = if target.starts_with('#') {
            self.reg.members(target)
        } else {
            vec![target.to_string()]
        };
        names
            .into_iter()
            .filter(|n| n != sender)
            .filter_map(|n| self.conn_of(&n))
            .collect()
    }

    fn conn_of(&self, name: &str) -> Option<Arc<Conn>> {
        self.conns
            .values()
            .find(|c| c.name.lock().unwrap().as_deref() == Some(name))
            .cloned()
    }

    /// Broadcast one control line to every agent sharing a channel with
    /// `agent` (presence is only visible to peers that can act on it).
    fn broadcast_presence(&self, agent: &str, line: &str) {
        let mut peers: BTreeMap<String, Arc<Conn>> = BTreeMap::new();
        for chan in self.reg.channel_names() {
            let members = self.reg.members(&chan);
            if members.iter().any(|m| m == agent) {
                for m in members {
                    if m != agent {
                        if let Some(c) = self.conn_of(&m) {
                            peers.insert(m, c);
                        }
                    }
                }
            }
        }
        for c in peers.values() {
            c.send_line(line);
        }
    }

    /// All live connections (used for QUIT broadcasts).
    fn everyone(&self) -> Vec<Arc<Conn>> {
        self.conns.values().cloned().collect()
    }

    /// Heartbeat TTL: evict what stopped talking and say so out loud. An
    /// agent wedged in a GC pause cannot renew its own lease.
    fn sweep(&mut self, now: Instant) -> Vec<String> {
        let expired: Vec<String> = self
            .agents
            .iter()
            .filter(|(_, a)| a.expired(self.ttl, now))
            .map(|(n, _)| n.clone())
            .collect();
        for name in &expired {
            self.agents.remove(name);
            self.reg.remove_agent(name);
            if let Some(conn) = self.conn_of(name) {
                self.conns.remove(&conn.id);
            }
            self.journal(
                "presence_expired",
                json!({"agent": name, "ttl_ms": self.ttl.as_millis() as u64}),
            );
        }
        expired
    }
}

fn reply_err(conn: &Conn, code: u16, text: &str) {
    conn.send_line(&format!("ERR {code} :{text}"));
}

fn main() {
    let mut host = "0.0.0.0".to_string();
    let mut port = 6669u16;
    let mut ttl_ms = 15_000u64;
    let mut log: Option<PathBuf> = None;
    let mut auth_key: Option<String> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut max_cmds_per_sec: u32 = 0;
    let mut max_bytes_per_sec: u32 = 0;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => host = args.next().unwrap_or(host),
            "--port" => port = args.next().and_then(|p| p.parse().ok()).unwrap_or(port),
            "--ttl-ms" => ttl_ms = args.next().and_then(|p| p.parse().ok()).unwrap_or(ttl_ms),
            "--log" => log = args.next().map(PathBuf::from),
            "--auth-key" => auth_key = args.next(),
            "--state" => state_path = args.next().map(PathBuf::from),
            "--max-cmds-per-sec" => {
                max_cmds_per_sec = args.next().and_then(|p| p.parse().ok()).unwrap_or(0)
            }
            "--max-bytes-per-sec" => {
                max_bytes_per_sec = args.next().and_then(|p| p.parse().ok()).unwrap_or(0)
            }
            "-h" | "--help" => {
                println!(
                    "aipp-broker [--host 0.0.0.0] [--port 6669] [--ttl-ms 15000] [--log <jsonl>]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument '{other}'");
                std::process::exit(2);
            }
        }
    }

    let listener = match TcpListener::bind((host.as_str(), port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("aipp-broker: cannot bind {host}:{port}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[aipp] broker listening on {host}:{port} (ttl {ttl_ms} ms)");

    let mut broker_state = Broker::new(Duration::from_millis(ttl_ms), log);
    if let Some(key) = auth_key.clone() {
        broker_state.auth = Some(Authority::new(key));
    }
    broker_state.max_cmds_per_sec = max_cmds_per_sec;
    broker_state.max_bytes_per_sec = max_bytes_per_sec;
    broker_state.state_path = state_path;
    broker_state.load_state();
    let broker = Arc::new(Mutex::new(broker_state));
    let next_id = Arc::new(AtomicU64::new(1));

    // TTL sweeper: the only clock in the system.
    {
        let broker = broker.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(200));
            let expired = {
                let mut b = broker.lock().unwrap();
                let dropped = b.sweep_store();
                if dropped > 0 {
                    b.journal("store_expired", json!({"dropped": dropped}));
                }
                b.sweep(Instant::now())
            };
            for name in expired {
                let b = broker.lock().unwrap();
                let line = format!("QUIT {name} :Heartbeat timeout - dropping session");
                for c in b.everyone() {
                    c.send_line(&line);
                }
                b.journal("presence_quit", json!({"agent": name, "reason": "ttl"}));
            }
        });
    }

    for stream in listener.incoming().flatten() {
        let id = next_id.fetch_add(1, Ordering::SeqCst);
        let _ = stream.set_nodelay(true);
        let out = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let limits = {
            let b = broker.lock().unwrap();
            (b.max_cmds_per_sec, b.max_bytes_per_sec)
        };
        let conn = Arc::new(Conn {
            id,
            name: Mutex::new(None),
            out: Arc::new(Outbox::spawn(out, 256)),
            pending: Mutex::new(None),
            identity: Mutex::new(None),
            caps: Mutex::new(0),
            limiter: Mutex::new(RateLimiter::new(limits.0, limits.1)),
        });
        {
            let mut b = broker.lock().unwrap();
            b.conns.insert(id, conn.clone());
            b.journal("connect", json!({"conn": id}));
        }
        let broker = broker.clone();
        std::thread::spawn(move || serve(broker, conn, stream));
    }
}

fn serve(broker: Arc<Mutex<Broker>>, conn: Arc<Conn>, stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    loop {
        match read_item(&mut reader) {
            Ok(Some(Item::Line(line))) => {
                if line.trim().is_empty() {
                    continue;
                }
                if handle_line(&broker, &conn, &line).is_err() {
                    break;
                }
            }
            Ok(Some(Item::Frame(frame))) => {
                if handle_frame(&broker, &conn, frame).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    disconnect(&broker, &conn);
}

/// Read one item: a CRLF line, or a binary frame.
///
/// The demux rule is the first two bytes (`0x41 0x01` = frame). Reading
/// them one at a time through the BufReader costs a memcpy, not a
/// syscall, and keeps the rule exact even when a frame is split across
/// TCP segments.
fn read_item(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<Item>> {
    let mut first = [0u8; 1];
    if reader.read(&mut first)? == 0 {
        return Ok(None);
    }
    if first[0] != aipp_core::tlv::MAGIC {
        let mut line = Vec::new();
        line.push(first[0]);
        reader.read_until(b'\n', &mut line)?;
        return Ok(Some(Item::Line(
            String::from_utf8_lossy(&line).trim_end().to_string(),
        )));
    }
    // magic seen: the next byte decides frame vs. text line
    let mut second = [0u8; 1];
    if reader.read(&mut second)? == 0 {
        return Ok(None);
    }
    if second[0] != aipp_core::tlv::VERSION {
        let mut line = vec![first[0], second[0]];
        reader.read_until(b'\n', &mut line)?;
        return Ok(Some(Item::Line(
            String::from_utf8_lossy(&line).trim_end().to_string(),
        )));
    }
    let mut header = [0u8; aipp_core::tlv::HEADER_LEN - 2];
    reader.read_exact(&mut header)?;
    let mut full = Vec::with_capacity(aipp_core::tlv::HEADER_LEN);
    full.push(first[0]);
    full.push(second[0]);
    full.extend_from_slice(&header);
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len > aipp_core::tlv::MAX_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame payload {len} exceeds cap"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    full.extend_from_slice(&payload);
    match Frame::decode(&full) {
        Ok(Some((f, _))) => Ok(Some(Item::Frame(f))),
        Ok(None) => Ok(None),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        )),
    }
}

fn name_of(conn: &Conn) -> Option<String> {
    conn.name.lock().unwrap().clone()
}

fn handle_line(broker: &Arc<Mutex<Broker>>, conn: &Arc<Conn>, line: &str) -> Result<(), ()> {
    let cmd = match Command::parse(line) {
        Ok(c) => c,
        Err(e) => {
            reply_err(conn, 421, &e);
            return Ok(());
        }
    };

    // flood defence: a refusal costs the sender its command, not the broker
    {
        let mut lim = conn.limiter.lock().unwrap();
        if let Err(e) = lim.allow(line.len() + 2) {
            reply_err(conn, e.numeric(), &e.message);
            return Ok(());
        }
    }

    // everything except AUTH/NICK/USER/PING/CAP requires an identity
    let needs_identity = !matches!(
        cmd,
        Command::Nick(_)
            | Command::User { .. }
            | Command::Ping(_)
            | Command::Auth(_)
            | Command::Cap
    );
    if needs_identity && name_of(conn).is_none() {
        reply_err(conn, 451, "You have not registered (NICK first)");
        return Ok(());
    }

    match cmd {
        Command::Nick(nick) => {
            let mut b = broker.lock().unwrap();
            if conn.name.lock().unwrap().is_some() {
                drop(b);
                reply_err(conn, 462, "You are already registered");
                return Ok(());
            }
            if let Some(auth) = b.auth.clone() {
                let id = conn.identity.lock().unwrap().clone();
                match id {
                    None => {
                        drop(b);
                        reply_err(conn, 464, "AUTH required before NICK");
                        return Ok(());
                    }
                    Some(id) if id.ag_id != nick => {
                        drop(b);
                        reply_err(
                            conn,
                            464,
                            &format!("this token authenticates '{}', not '{nick}'", id.ag_id),
                        );
                        return Ok(());
                    }
                    Some(_) => {}
                }
                let _ = auth;
            }
            if b.agents.contains_key(&nick) {
                drop(b);
                reply_err(conn, 433, &format!("Agent id '{nick}' is already in use"));
                return Ok(());
            }
            *conn.name.lock().unwrap() = Some(nick.clone());
            b.agents
                .insert(nick.clone(), AgentRecord::new(nick.clone(), "unknown", 0));
            b.journal("nick", json!({"conn": conn.id, "ag_id": nick}));
            drop(b);
            conn.send_line(&format!(
                "ACK 001 :Welcome to the Agent Mesh Network, {nick}"
            ));
            // store-and-forward: whatever was held while this agent was
            // away is delivered now, before any new work
            let backlog = {
                let mut b = broker.lock().unwrap();
                b.drain_store(&nick)
            };
            if !backlog.is_empty() {
                conn.send_line(&format!("STORED_INBOX {nick} {}", backlog.len()));
                for (from, text) in backlog {
                    conn.send_line(&format!(":{from} PRIVMSG {nick} :{text}"));
                }
            }
        }
        Command::User { class, caps } => {
            let name = name_of(conn).unwrap();
            // the self-declared mask is intersected with what the token
            // granted: announcing a capability is not being granted one
            let effective = match conn.identity.lock().unwrap().clone() {
                Some(id) => caps & id.caps,
                None => caps,
            };
            *conn.caps.lock().unwrap() = effective;
            let mut b = broker.lock().unwrap();
            if let Some(a) = b.agents.get_mut(&name) {
                a.class = class.clone();
                a.caps = effective;
                a.touch(Instant::now());
            }
            b.journal(
                "user",
                json!({"ag_id": name, "class": class, "caps": effective}),
            );
        }
        Command::Status {
            agent,
            state,
            vram_free_mb,
            active_tasks,
        } => {
            let me = name_of(conn).unwrap();
            if agent != me {
                reply_err(conn, 502, "STATUS must describe your own AG-ID");
                return Ok(());
            }
            let line_out;
            {
                let mut b = broker.lock().unwrap();
                if let Some(a) = b.agents.get_mut(&me) {
                    a.set_status(state, vram_free_mb, active_tasks);
                    a.touch(Instant::now());
                }
                line_out = b
                    .agents
                    .get(&me)
                    .map(|a| a.status_line())
                    .unwrap_or_default();
                b.journal(
                    "status",
                    json!({"ag_id": me, "state": state.label(),
                           "vram_free_mb": vram_free_mb, "active_tasks": active_tasks}),
                );
                b.broadcast_presence(&me, &line_out);
            }
            conn.send_line(&format!("STATS_OK {me}"));
        }
        Command::Join(chan) => {
            let me = name_of(conn).unwrap();
            let names;
            let others;
            {
                let mut b = broker.lock().unwrap();
                if !b.reg.exists(&chan) {
                    b.journal("channel_created", json!({"channel": chan, "by": me}));
                }
                let joined = b.reg.join(&chan, &me);
                if !joined {
                    drop(b);
                    reply_err(conn, 442, &format!("You are already on {chan}"));
                    return Ok(());
                }
                names = b.reg.names(&chan).unwrap_or_default();
                others = b.reg.members(&chan);
                b.journal("join", json!({"ag_id": me, "channel": chan}));
                b.save_state();
            }
            conn.send_line(&format!("JOINED {chan} {me}"));
            conn.send_line(&format!("NAMES {chan} :{names}"));
            for member in others.iter().filter(|m| **m != me) {
                let b = broker.lock().unwrap();
                if let Some(c) = b.conn_of(member) {
                    c.send_line(&format!(":{me} JOIN {chan} {me}"));
                }
            }
        }
        Command::Names(chan) => {
            let b = broker.lock().unwrap();
            if !b.reg.exists(&chan) {
                drop(b);
                reply_err(conn, 403, &format!("No such channel {chan}"));
                return Ok(());
            }
            let names = b.reg.names(&chan).unwrap_or_default();
            drop(b);
            conn.send_line(&format!("NAMES {chan} :{names}"));
        }
        Command::Part { channel, reason } => {
            let me = name_of(conn).unwrap();
            let members;
            {
                let mut b = broker.lock().unwrap();
                if !b.reg.part(&channel, &me) {
                    drop(b);
                    reply_err(conn, 442, &format!("You are not on {channel}"));
                    return Ok(());
                }
                members = b.reg.members(&channel);
                b.journal(
                    "part",
                    json!({"ag_id": me, "channel": channel, "reason": reason}),
                );
            }
            conn.send_line(&format!("PARTED {channel}"));
            let line = match &reason {
                Some(r) => format!(":{me} PART {channel} :{r}"),
                None => format!(":{me} PART {channel}"),
            };
            for member in members {
                let b = broker.lock().unwrap();
                if let Some(c) = b.conn_of(&member) {
                    c.send_line(&line);
                }
            }
        }
        Command::Privmsg { target, text } | Command::Notice { target, text } => {
            let is_notice = line.to_ascii_uppercase().starts_with("NOTICE");
            let me = name_of(conn).unwrap();
            let recipients;
            {
                let mut b = broker.lock().unwrap();
                // `@pool:<class>` is presence-aware: the broker picks a
                // member of that class that is actually taking work
                if is_pool(&target) {
                    let pool = target.trim_start_matches("@pool:").to_string();
                    let pick = b
                        .agents
                        .values()
                        .filter(|a| a.class == pool)
                        .filter(|a| a.state.accepts_tasks())
                        .filter(|a| !b.draining.contains(&a.ag_id))
                        .min_by_key(|a| a.active_tasks)
                        .map(|a| a.ag_id.clone());
                    match pick {
                        Some(ag) => {
                            drop(b);
                            let line = format!(":{me} PRIVMSG {ag} :{text}");
                            let c = {
                                let b = broker.lock().unwrap();
                                b.conn_of(&ag)
                            };
                            match c {
                                Some(c) => {
                                    if c.send_line_checked(&line).is_err() {
                                        reply_err(conn, 509, &format!("{ag} is not draining"));
                                    }
                                }
                                None => {
                                    reply_err(conn, 401, &format!("No live connection for {ag}"))
                                }
                            }
                            return Ok(());
                        }
                        None => {
                            drop(b);
                            reply_err(conn, 401, &format!("no live agent in {target}"));
                            return Ok(());
                        }
                    }
                }
                if target.starts_with('#') && !b.reg.exists(&target) {
                    drop(b);
                    reply_err(conn, 403, &format!("No such channel {target}"));
                    return Ok(());
                }
                // a direct message to an agent that is not connected is
                // held, not lost: store-and-forward is the point of knowing
                // an agent is OFFLINE
                if !target.starts_with('#') && b.conn_of(&target).is_none() {
                    let n = b.store_for(&target, &me, &text);
                    b.journal("stored", json!({"from": me, "to": target, "queued": n}));
                    drop(b);
                    conn.send_line(&format!("STORED {target} {n}"));
                    return Ok(());
                }
                b.journal(
                    if is_notice { "notice" } else { "privmsg" },
                    json!({"from": me, "to": target, "text": text}),
                );
                // `+m`: the rule that gives `+v` its meaning
                if target.starts_with('#') && !b.reg.may_speak(&target, &me) {
                    drop(b);
                    reply_err(conn, 404, &format!("{target} :you are not voiced (+m)"));
                    return Ok(());
                }
                recipients = b.targets(&target, &me);
            }
            let verb = if is_notice { "NOTICE" } else { "PRIVMSG" };
            let out = format!(":{me} {verb} {target} :{text}");
            for c in recipients {
                c.send_line(&out);
            }
        }
        Command::Mode {
            channel,
            flag,
            on,
            target,
        } => {
            let me = name_of(conn).unwrap();
            let members;
            {
                let mut b = broker.lock().unwrap();
                if !b.reg.is_op(&channel, &me) {
                    drop(b);
                    reply_err(
                        conn,
                        482,
                        &format!("You're not channel operator on {channel}"),
                    );
                    return Ok(());
                }
                // `+m`/`+i`/`+t` are channel flags, not member flags
                let result = if matches!(flag, 'm' | 'i' | 't') {
                    b.reg.set_flag(&channel, flag, on)
                } else {
                    b.reg.set_mode(&channel, &target, flag, on)
                };
                if let Err(e) = result {
                    drop(b);
                    reply_err(conn, 441, &e);
                    return Ok(());
                }
                members = b.reg.members(&channel);
                b.journal(
                    "mode",
                    json!({"from": me, "channel": channel, "mode": format!("{}{flag}", if on {"+"} else {"-"}), "target": target}),
                );
            }
            let line = format!(
                ":{me} MODE {channel} {}{flag} {target}",
                if on { '+' } else { '-' }
            );
            for member in members {
                let b = broker.lock().unwrap();
                if let Some(c) = b.conn_of(&member) {
                    c.send_line(&line);
                }
            }
        }
        Command::Kick {
            channel,
            target,
            reason,
        } => {
            let me = name_of(conn).unwrap();
            let members;
            let kicked;
            {
                let mut b = broker.lock().unwrap();
                if !b.reg.is_op(&channel, &me) {
                    drop(b);
                    reply_err(
                        conn,
                        482,
                        &format!("You're not channel operator on {channel}"),
                    );
                    return Ok(());
                }
                if let Err(e) = b.reg.kick(&channel, &target) {
                    drop(b);
                    reply_err(conn, 441, &e);
                    return Ok(());
                }
                members = b.reg.members(&channel);
                kicked = b.conn_of(&target);
                b.journal(
                    "kick",
                    json!({"from": me, "channel": channel, "target": target, "reason": reason}),
                );
            }
            let line = format!(":{me} KICK {channel} {target} :{reason}");
            if let Some(c) = kicked {
                c.send_line(&line);
            }
            for member in members {
                let b = broker.lock().unwrap();
                if let Some(c) = b.conn_of(&member) {
                    c.send_line(&line);
                }
            }
        }
        Command::Auth(token) => {
            let auth = {
                let b = broker.lock().unwrap();
                b.auth.clone()
            };
            let Some(auth) = auth else {
                reply_err(
                    conn,
                    464,
                    "this broker runs open (start it with --auth-key to require AUTH)",
                );
                return Ok(());
            };
            match auth.verify(&token) {
                Ok(id) => {
                    *conn.caps.lock().unwrap() = id.caps;
                    *conn.identity.lock().unwrap() = Some(id.clone());
                    {
                        let b = broker.lock().unwrap();
                        b.journal(
                            "auth_ok",
                            json!({"conn": conn.id, "ag_id": id.ag_id, "caps": id.caps}),
                        );
                    }
                    conn.send_line(&format!("AUTH_OK {} caps=0x{:x}", id.ag_id, id.caps));
                }
                Err(e) => {
                    {
                        let b = broker.lock().unwrap();
                        b.journal("auth_fail", json!({"conn": conn.id}));
                    }
                    reply_err(conn, e.numeric(), &e.message);
                }
            }
        }
        Command::Cap => {
            // extensions are advertised, never assumed: an old client keeps
            // working because it simply ignores this line
            conn.send_line(&format!(
                "CAP LS :aipp=1.0 AUTH FRAGMENT CREDIT POOL TOPIC MODES=mitb DRAIN \
                 TLVS=0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007 CAPS={}",
                cap::explain()
            ));
        }
        Command::Topic { channel, topic } => {
            let me = name_of(conn).unwrap();
            let mut b = broker.lock().unwrap();
            if !b.reg.exists(&channel) {
                drop(b);
                reply_err(conn, 403, &format!("No such channel {channel}"));
                return Ok(());
            }
            match topic {
                None => {
                    let t = b.reg.topic(&channel).unwrap_or_default();
                    drop(b);
                    conn.send_line(&format!("TOPIC {channel} :{t}"));
                }
                Some(t) => {
                    if !b.reg.is_op(&channel, &me) {
                        drop(b);
                        reply_err(conn, 482, &format!("{channel} :you are not an operator"));
                        return Ok(());
                    }
                    if let Err(e) = b.reg.set_topic(&channel, Some(t.clone())) {
                        drop(b);
                        reply_err(conn, 403, &e);
                        return Ok(());
                    }
                    let members = b.reg.members(&channel);
                    b.journal(
                        "topic",
                        json!({"ag_id": me, "channel": channel, "topic": t}),
                    );
                    b.save_state();
                    drop(b);
                    conn.send_line(&format!("TOPIC_SET {channel}"));
                    for m in members {
                        let b = broker.lock().unwrap();
                        if let Some(c) = b.conn_of(&m) {
                            c.send_line(&format!(":{me} TOPIC {channel} :{t}"));
                        }
                    }
                }
            }
        }
        Command::List => {
            let rows: Vec<String> = {
                let b = broker.lock().unwrap();
                if !cap::has(*conn.caps.lock().unwrap(), cap::INSPECT) {
                    drop(b);
                    reply_err(conn, 482, "LIST requires the INSPECT capability");
                    return Ok(());
                }
                b.reg.list()
            };
            conn.send_line(&format!("LIST_START {}", rows.len()));
            for row in rows {
                conn.send_line(&row);
            }
            conn.send_line("LIST_END");
        }
        Command::Who(target) => {
            let rows: Vec<String> = {
                let b = broker.lock().unwrap();
                if !cap::has(*conn.caps.lock().unwrap(), cap::INSPECT) {
                    drop(b);
                    reply_err(conn, 482, "WHO requires the INSPECT capability");
                    return Ok(());
                }
                match &target {
                    Some(t) if is_pool(t) => b
                        .agents
                        .values()
                        .filter(|a| t == &format!("@pool:{}", a.class))
                        .map(|a| {
                            format!(
                                "WHO {} {} {} {}",
                                a.ag_id,
                                a.class,
                                a.state.hex(),
                                if b.draining.contains(&a.ag_id) {
                                    "DRAINING"
                                } else {
                                    "ACTIVE"
                                }
                            )
                        })
                        .collect(),
                    Some(t) if t.starts_with('#') => b
                        .reg
                        .members(t)
                        .into_iter()
                        .filter_map(|m| b.agents.get(&m).cloned())
                        .map(|a| format!("WHO {} {} {} ACTIVE", a.ag_id, a.class, a.state.hex()))
                        .collect(),
                    _ => b
                        .agents
                        .values()
                        .map(|a| format!("WHO {} {} {} ACTIVE", a.ag_id, a.class, a.state.hex()))
                        .collect(),
                }
            };
            conn.send_line(&format!("WHO_START {}", rows.len()));
            for row in rows {
                conn.send_line(&row);
            }
            conn.send_line("WHO_END");
        }
        Command::Drain => {
            let me = name_of(conn).unwrap();
            {
                let mut b = broker.lock().unwrap();
                b.draining.insert(me.clone());
                if let Some(a) = b.agents.get_mut(&me) {
                    a.set_status(
                        aipp_core::presence::PresenceState::Away,
                        a.vram_free_mb,
                        a.active_tasks,
                    );
                }
                b.journal("drain", json!({"ag_id": me}));
            }
            conn.send_line(&format!(
                "DRAINING {me} :new tasks will not be dispatched to you"
            ));
        }
        Command::Quit { reason } => {
            let me = name_of(conn).unwrap();
            {
                let b = broker.lock().unwrap();
                b.journal("quit", json!({"ag_id": me, "reason": reason}));
            }
            announce_quit(broker, &me, &reason);
            return Err(());
        }
        Command::Ping(token) => {
            let me = name_of(conn).clone();
            if let Some(me) = me {
                let mut b = broker.lock().unwrap();
                if let Some(a) = b.agents.get_mut(&me) {
                    a.touch(Instant::now());
                }
            }
            match token {
                Some(t) => conn.send_line(&format!("PONG :{t}")),
                None => conn.send_line("PONG"),
            }
        }
        Command::Pong(_) => {
            if let Some(me) = name_of(conn) {
                let mut b = broker.lock().unwrap();
                if let Some(a) = b.agents.get_mut(&me) {
                    a.touch(Instant::now());
                }
            }
        }
        Command::BinFrame {
            target,
            tlv_type,
            length,
        } => {
            let me = name_of(conn).unwrap();
            {
                let b = broker.lock().unwrap();
                if target.starts_with('#') && !b.reg.exists(&target) {
                    drop(b);
                    reply_err(conn, 403, &format!("No such channel {target}"));
                    return Ok(());
                }
                if !target.starts_with('#') && !b.agents.contains_key(&target) {
                    drop(b);
                    reply_err(conn, 401, &format!("No such agent {target}"));
                    return Ok(());
                }
            }
            *conn.pending.lock().unwrap() = Some(PendingFrame {
                target,
                tlv_type,
                length,
            });
            let _ = me;
        }
    }
    Ok(())
}

fn handle_frame(broker: &Arc<Mutex<Broker>>, conn: &Arc<Conn>, frame: Frame) -> Result<(), ()> {
    let me = match name_of(conn) {
        Some(n) => n,
        None => {
            reply_err(conn, 451, "You have not registered (NICK first)");
            return Ok(());
        }
    };
    let pending = conn.pending.lock().unwrap().take();
    let Some(p) = pending else {
        reply_err(conn, 412, "Binary frame without a BIN_FRAME announcement");
        return Ok(());
    };
    if frame.tlv_type != p.tlv_type || frame.payload.len() as u32 != p.length {
        reply_err(
            conn,
            409,
            &format!(
                "Frame does not match its announcement (tlv 0x{:04X} {} B)",
                frame.tlv_type,
                frame.payload.len()
            ),
        );
        return Ok(());
    }
    let recipients;
    {
        let b = broker.lock().unwrap();
        b.journal(
            "bin_frame",
            json!({"from": me, "to": p.target, "tlv": p.tlv_type,
                   "tlv_label": tlv_label(p.tlv_type), "bytes": p.length}),
        );
        recipients = b.targets(&p.target, &me);
    }
    let wire = frame.encode();
    for c in &recipients {
        c.send_bytes(&wire);
    }
    conn.send_line(&format!("BIN_ACK {} {}", p.target, p.length));
    Ok(())
}

fn announce_quit(broker: &Arc<Mutex<Broker>>, name: &str, reason: &str) {
    let line = format!("QUIT {name} :{reason}");
    let (others, left) = {
        let mut b = broker.lock().unwrap();
        b.agents.remove(name);
        let left = b.reg.remove_agent(name);
        b.journal("quit_broadcast", json!({"agent": name, "channels": left}));
        let others = b.everyone();
        (others, left)
    };
    let _ = left;
    for c in others {
        if c.name.lock().unwrap().as_deref() != Some(name) {
            c.send_line(&line);
        }
    }
}

fn disconnect(broker: &Arc<Mutex<Broker>>, conn: &Arc<Conn>) {
    let name = name_of(conn);
    {
        let mut b = broker.lock().unwrap();
        b.conns.remove(&conn.id);
        b.journal("disconnect", json!({"conn": conn.id, "ag_id": name}));
    }
    if let Some(n) = name {
        // only announce if the agent is really gone (not a TTL eviction
        // that already announced it)
        let still = {
            let b = broker.lock().unwrap();
            b.agents.contains_key(&n)
        };
        if still {
            announce_quit(broker, &n, "Connection closed");
        }
    }
}
