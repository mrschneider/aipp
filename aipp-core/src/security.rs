//! Identity, authorization, rate limiting and the audit chain.
//!
//! AIPP's control plane is telnet-shaped, which is great for debugging and
//! terrible for identity: without this module any peer can type
//! `NICK supervisor_agent` and be believed. The design here mirrors what
//! IRC learned late and what every agent mesh needs on day one:
//!
//! * **`AUTH <token>`** proves who you are *before* `NICK`, and the AG-ID
//!   is taken from the token, not from the claim.
//! * **Capabilities** (`USER <class> <mask>`) gate privileged verbs
//!   instead of being decorative.
//! * **Rate limiting** per connection (commands/s and bytes/s) so a
//!   flood cannot starve the broker.
//! * **Hash chain** over the audit log, so tampering is detectable.

use crate::error::{AippError, ErrorKind};
use digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

/// Capability bits carried in `USER <class> <mask>`.
pub mod cap {
    /// may speak in a moderated (`+m`) channel without `+v`
    pub const SPEAK: u32 = 0x01;
    /// may change channel modes and topic
    pub const MODERATE: u32 = 0x02;
    /// may kick
    pub const KICK: u32 = 0x04;
    /// may query operator views (LIST/WHO/WHOIS)
    pub const INSPECT: u32 = 0x08;
    /// may push schema/store-forward frames
    pub const PAYLOAD: u32 = 0x10;

    pub const ALL: u32 = SPEAK | MODERATE | KICK | INSPECT | PAYLOAD;

    pub fn has(mask: u32, c: u32) -> bool {
        mask & c == c
    }

    pub fn explain() -> &'static str {
        "SPEAK=0x01 MODERATE=0x02 KICK=0x04 INSPECT=0x08 PAYLOAD=0x10"
    }
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

/// What a valid `AUTH` token asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// the AG-ID the peer is allowed to use — never what it typed
    pub ag_id: String,
    /// capability mask granted by the issuer
    pub caps: u32,
    pub expires_at_ms: u128,
}

impl Identity {
    pub fn can(&self, c: u32) -> bool {
        cap::has(self.caps, c)
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Issues and verifies `AUTH` tokens: `<ag_id>.<expires_ms>.<hex hmac>`.
#[derive(Clone)]
pub struct Authority {
    key: Vec<u8>,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authority(<redacted>)")
    }
}

impl Authority {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    fn mac(&self, ag_id: &str, caps: u32, expires: u128) -> Vec<u8> {
        let canonical = format!("aipp1|{ag_id}|{caps}|{expires}");
        let mut m = HmacSha256::new_from_slice(&self.key).expect("hmac accepts any key");
        m.update(canonical.as_bytes());
        m.finalize().into_bytes().to_vec()
    }

    /// Mint a token (the operator side; `aipp-token` uses this).
    pub fn issue(&self, ag_id: &str, caps: u32, ttl_ms: u64) -> String {
        if !valid_ag_id(ag_id) {
            return String::new();
        }
        let expires = now_ms() + ttl_ms as u128;
        let sig = hex(&self.mac(ag_id, caps, expires));
        format!("{ag_id}.{expires}.{caps:x}.{sig}")
    }

    /// Verify a token. Expiry and signature are both mandatory: a token
    /// without an expiry is a password.
    pub fn verify(&self, token: &str) -> Result<Identity, AippError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            return Err(AippError::new(
                ErrorKind::Auth,
                "token must be <ag_id>.<expires_ms>.<caps_hex>.<signature>",
            ));
        }
        let ag_id = parts[0];
        if !valid_ag_id(ag_id) {
            return Err(AippError::new(
                ErrorKind::Auth,
                "token names an invalid AG-ID",
            ));
        }
        let expires: u128 = parts[1]
            .parse()
            .map_err(|_| AippError::new(ErrorKind::Auth, "token expiry is not a number"))?;
        let caps = u32::from_str_radix(parts[2], 16)
            .map_err(|_| AippError::new(ErrorKind::Auth, "token capabilities are not hex"))?;
        let expected = hex(&self.mac(ag_id, caps, expires));
        let got = parts[3];
        // constant-time compare: a timing oracle here is a forgery kit
        let ok = got.len() == expected.len()
            && got
                .bytes()
                .zip(expected.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        if !ok {
            return Err(AippError::new(
                ErrorKind::Auth,
                "token signature does not verify",
            ));
        }
        if now_ms() >= expires {
            return Err(AippError::new(ErrorKind::Auth, "token expired"));
        }
        Ok(Identity {
            ag_id: ag_id.to_string(),
            caps,
            expires_at_ms: expires,
        })
    }
}

pub fn valid_ag_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Sliding-window limiter: N commands per second, M bytes per second.
#[derive(Debug)]
pub struct RateLimiter {
    max_cmds_per_sec: u32,
    max_bytes_per_sec: u32,
    cmds: VecDeque<Instant>,
    bytes: VecDeque<(Instant, usize)>,
}

impl RateLimiter {
    pub fn new(max_cmds_per_sec: u32, max_bytes_per_sec: u32) -> Self {
        Self {
            max_cmds_per_sec,
            max_bytes_per_sec,
            cmds: VecDeque::new(),
            bytes: VecDeque::new(),
        }
    }

    pub fn unlimited() -> Self {
        Self::new(0, 0)
    }

    fn prune(&mut self, now: Instant) {
        let window = Duration::from_secs(1);
        while self
            .cmds
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            self.cmds.pop_front();
        }
        while self
            .bytes
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > window)
        {
            self.bytes.pop_front();
        }
    }

    /// Record one command of `bytes` bytes. A refusal leaks nothing: the
    /// command is not counted when it is rejected.
    pub fn allow(&mut self, bytes: usize) -> Result<(), AippError> {
        let now = Instant::now();
        self.prune(now);
        if self.max_cmds_per_sec > 0 && self.cmds.len() >= self.max_cmds_per_sec as usize {
            return Err(AippError::new(
                ErrorKind::RateLimited,
                format!("over {} commands/s", self.max_cmds_per_sec),
            ));
        }
        if self.max_bytes_per_sec > 0 {
            let used: usize = self.bytes.iter().map(|(_, b)| b).sum();
            if used + bytes > self.max_bytes_per_sec as usize {
                return Err(AippError::new(
                    ErrorKind::RateLimited,
                    format!("over {} bytes/s", self.max_bytes_per_sec),
                ));
            }
        }
        self.cmds.push_back(now);
        if bytes > 0 {
            self.bytes.push_back((now, bytes));
        }
        Ok(())
    }
}

/// Append-only audit log with a hash chain: each entry commits to the
/// previous one, so deleting or editing a line breaks verification.
#[derive(Debug, Default)]
pub struct AuditChain {
    last: String,
    entries: u64,
}

fn digest(event: &str, detail: &str, prev: &str) -> String {
    let body = format!("{prev}|{event}|{detail}");
    let mut m = HmacSha256::new_from_slice(b"aipp-audit-chain").expect("hmac");
    m.update(body.as_bytes());
    hex(&m.finalize().into_bytes()[..8])
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            last: "genesis".to_string(),
            entries: 0,
        }
    }

    /// Returns the line to append (with its `prev` and `h` fields).
    pub fn append(&mut self, event: &str, detail: &str) -> String {
        let prev = self.last.clone();
        let h = digest(event, detail, &prev);
        self.last = h.clone();
        self.entries += 1;
        format!(r#"{{"ev":"{event}","detail":{detail},"prev":"{prev}","h":"{h}"}}"#)
    }

    pub fn head(&self) -> &str {
        &self.last
    }

    pub fn entries(&self) -> u64 {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Authority {
        Authority::new(b"mesh-secret".to_vec())
    }

    #[test]
    fn a_token_carries_the_identity_and_the_rights() {
        let a = auth();
        let token = a.issue("supervisor_agent", cap::ALL, 60_000);
        let id = a.verify(&token).unwrap();
        assert_eq!(id.ag_id, "supervisor_agent");
        assert_eq!(id.caps, cap::ALL);
        assert!(id.can(cap::KICK) && id.can(cap::MODERATE));
        assert!(!Identity {
            caps: cap::SPEAK,
            ..id.clone()
        }
        .can(cap::KICK));
    }

    #[test]
    fn a_renamed_identity_breaks_the_signature() {
        let a = auth();
        let token = a.issue("worker_1", cap::SPEAK, 60_000);
        let forged = token.replacen("worker_1", "supervisor_agent", 1);
        let err = a.verify(&forged).unwrap_err().to_string();
        assert!(err.contains("signature"), "{err}");
    }

    #[test]
    fn an_escalated_capability_breaks_the_signature() {
        let a = auth();
        let token = a.issue("worker_1", cap::SPEAK, 60_000);
        let forged = token.replacen(
            &format!(".{:x}.", cap::SPEAK),
            &format!(".{:x}.", cap::ALL),
            1,
        );
        assert!(a.verify(&forged).is_err(), "caps are inside the MAC");
    }

    #[test]
    fn another_key_cannot_verify_and_expiry_is_enforced() {
        let token = auth().issue("worker_1", cap::SPEAK, 60_000);
        assert!(Authority::new(b"other".to_vec()).verify(&token).is_err());
        let expired = auth().issue("worker_1", cap::SPEAK, 0);
        std::thread::sleep(Duration::from_millis(5));
        let err = auth().verify(&expired).unwrap_err().to_string();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn malformed_tokens_are_named_not_guessed() {
        let a = auth();
        for (bad, needle) in [
            ("", "<ag_id>"),
            ("only.two", "<ag_id>"),
            ("bad id.123.1.ff", "invalid AG-ID"),
            ("ok.abc.1.ff", "expiry"),
            ("ok.123.zz.ff", "hex"),
        ] {
            let err = a.verify(bad).unwrap_err().to_string();
            assert!(err.contains(needle), "{bad:?} -> {err}");
        }
    }

    #[test]
    fn rate_limiter_counts_commands_and_bytes_per_second() {
        let mut r = RateLimiter::new(3, 100);
        assert!(r.allow(10).is_ok());
        assert!(r.allow(10).is_ok());
        assert!(r.allow(10).is_ok());
        let err = r.allow(10).unwrap_err().to_string();
        assert!(err.contains("commands/s"), "{err}");

        let mut b = RateLimiter::new(0, 50);
        assert!(b.allow(40).is_ok());
        let err = b.allow(20).unwrap_err().to_string();
        assert!(err.contains("bytes/s"), "{err}");
        // a refusal must not consume the budget
        assert!(b.allow(5).is_ok());
    }

    #[test]
    fn unlimited_never_refuses() {
        let mut r = RateLimiter::unlimited();
        for _ in 0..1000 {
            assert!(r.allow(1024).is_ok());
        }
    }

    #[test]
    fn the_audit_chain_links_every_entry() {
        let mut c = AuditChain::new();
        let first = c.append("join", r#"{"ag":"a"}"#);
        let second = c.append("kick", r#"{"ag":"b"}"#);
        assert!(first.contains("\"h\":"));
        assert!(second.contains(&format!("\"prev\":\"{}\"", extract_h(&first))));
        assert_eq!(c.entries(), 2);
        assert_eq!(c.head(), extract_h(&second));
    }

    fn extract_h(line: &str) -> String {
        let idx = line.rfind("\"h\":\"").expect("h field");
        line[idx + 5..].trim_end_matches("\"}").to_string()
    }

    #[test]
    fn a_tampered_entry_no_longer_links() {
        let mut c = AuditChain::new();
        let first = c.append("join", r#"{"ag":"a"}"#);
        // recomputing the hash over edited content must not match the line
        assert_ne!(
            extract_h(&first),
            digest("join", r#"{"ag":"b"}"#, "genesis"),
            "an edited entry cannot keep its hash"
        );
        let second = c.append("part", r#"{}"#);
        assert!(
            second.contains(&extract_h(&first)),
            "the chain commits to the real prev"
        );
    }
}
