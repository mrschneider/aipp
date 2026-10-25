//! Presence: the ICQ/OSCAR half of AIPP.
//!
//! An agent is not a stateless RPC endpoint — it is a node with a state
//! vector, and that vector is what lets an orchestrator make a sane
//! decision under load. The five states are deliberately small and
//! explicit: every additional state is one more thing a scheduler gets
//! wrong.
//!
//! ```text
//! 0x00 ONLINE      ready for task dispatch
//! 0x01 BUSY        executing a tool call / inference loop; queues tasks
//! 0x02 HIGH_LOAD   CPU/VRAM threshold exceeded; shed non-critical load
//! 0x03 AWAY        maintenance, GC, model swapping
//! 0x04 OFFLINE     graceful disconnect or heartbeat timeout
//! ```
//!
//! The TTL is enforced by the broker, not by the agent: a node that is
//! wedged in a GC pause must not be able to lie about being alive.

use std::time::{Duration, Instant};

/// The presence vector of one agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PresenceState {
    Online = 0x00,
    Busy = 0x01,
    HighLoad = 0x02,
    Away = 0x03,
    Offline = 0x04,
}

impl PresenceState {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Online),
            0x01 => Some(Self::Busy),
            0x02 => Some(Self::HighLoad),
            0x03 => Some(Self::Away),
            0x04 => Some(Self::Offline),
            _ => None,
        }
    }

    /// Accepts `0x00`..`0x04`, `00`, and bare `0`..`4` — operators type
    /// all three forms into a telnet session.
    pub fn from_hex(s: &str) -> Option<Self> {
        let t = s.trim();
        let t = t
            .strip_prefix("0x")
            .or_else(|| t.strip_prefix("0X"))
            .unwrap_or(t);
        let code = u8::from_str_radix(t, 16).ok()?;
        Self::from_code(code)
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    /// The canonical wire form (`0x01`), used by STATUS broadcasts.
    pub fn hex(self) -> &'static str {
        match self {
            Self::Online => "0x00",
            Self::Busy => "0x01",
            Self::HighLoad => "0x02",
            Self::Away => "0x03",
            Self::Offline => "0x04",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Online => "ONLINE",
            Self::Busy => "BUSY",
            Self::HighLoad => "HIGH_LOAD",
            Self::Away => "AWAY",
            Self::Offline => "OFFLINE",
        }
    }

    /// Only ONLINE takes new work without the caller having to think
    /// about queueing; BUSY accepts work but the dispatcher should know
    /// it is queueing.
    pub fn accepts_tasks(self) -> bool {
        matches!(self, Self::Online | Self::Busy)
    }

    /// Should an orchestrator stop sending non-critical work?
    pub fn should_shed_load(self) -> bool {
        matches!(self, Self::HighLoad | Self::Away | Self::Offline)
    }
}

/// One agent as the broker knows it: identity, class, capabilities, and
/// the presence vector with its last-seen timestamp.
#[derive(Debug, Clone)]
pub struct AgentRecord {
    /// Immutable AG-ID: the nick, fixed for the session lifetime.
    pub ag_id: String,
    /// `USER`'s first argument — `coder-specialist`, `qa`, `supervisor`.
    pub class: String,
    /// `USER`'s capability bitmask.
    pub caps: u32,
    pub state: PresenceState,
    /// Free VRAM reported by the agent's own probe (MiB).
    pub vram_free_mb: u32,
    /// Tasks this agent says are in flight.
    pub active_tasks: u32,
    /// Last control-plane evidence of life (any command refreshes it).
    pub last_seen: Instant,
}

impl AgentRecord {
    pub fn new(ag_id: impl Into<String>, class: impl Into<String>, caps: u32) -> Self {
        Self {
            ag_id: ag_id.into(),
            class: class.into(),
            caps,
            state: PresenceState::Online,
            vram_free_mb: 0,
            active_tasks: 0,
            last_seen: Instant::now(),
        }
    }

    /// Any inbound traffic keeps the session alive.
    pub fn touch(&mut self, now: Instant) {
        self.last_seen = now;
    }

    /// Apply a `STATUS` line.
    pub fn set_status(&mut self, state: PresenceState, vram_free_mb: u32, active_tasks: u32) {
        self.state = state;
        self.vram_free_mb = vram_free_mb;
        self.active_tasks = active_tasks;
    }

    /// The heartbeat TTL expired: the broker must evict it. A stuck
    /// agent cannot extend its own life if it cannot send.
    pub fn expired(&self, ttl: Duration, now: Instant) -> bool {
        now.duration_since(self.last_seen) > ttl
    }

    /// The presence vector as it goes on the wire.
    pub fn status_line(&self) -> String {
        format!(
            "STATUS {} {} {} {}",
            self.ag_id,
            self.state.hex(),
            self.vram_free_mb,
            self.active_tasks
        )
    }

    /// Human-readable form for `NAMES`/diagnostics.
    pub fn describe(&self) -> String {
        format!(
            "{}({}/{})",
            self.ag_id,
            self.state.label(),
            self.active_tasks
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_accepts_all_three_operator_forms() {
        for (s, expect) in [
            ("0x00", PresenceState::Online),
            ("0x01", PresenceState::Busy),
            ("0x02", PresenceState::HighLoad),
            ("0x03", PresenceState::Away),
            ("0x04", PresenceState::Offline),
            ("1", PresenceState::Busy),
            ("01", PresenceState::Busy),
        ] {
            assert_eq!(PresenceState::from_hex(s), Some(expect), "input {s}");
        }
        assert_eq!(PresenceState::from_hex("0x09"), None, "unknown code");
        assert_eq!(PresenceState::from_hex("busy"), None, "not hex");
    }

    #[test]
    fn status_line_is_exactly_the_wire_format() {
        let mut a = AgentRecord::new("ag_alpha_09", "coder-specialist", 0x0F);
        a.set_status(PresenceState::Busy, 32768, 2);
        assert_eq!(a.status_line(), "STATUS ag_alpha_09 0x01 32768 2");
    }

    #[test]
    fn ttl_expiry_is_strictly_greater_than_the_ttl() {
        let ttl = Duration::from_secs(15);
        let start = Instant::now();
        let mut a = AgentRecord::new("ag_1", "qa", 0);
        a.last_seen = start;
        assert!(
            !a.expired(ttl, start + Duration::from_secs(15)),
            "at TTL exactly: still alive"
        );
        assert!(
            a.expired(ttl, start + Duration::from_millis(15_001)),
            "past TTL: expired"
        );
        a.touch(start + Duration::from_secs(15));
        assert!(
            !a.expired(ttl, start + Duration::from_secs(20)),
            "a touch revives the session"
        );
    }

    #[test]
    fn capacity_flags_drive_dispatch_decisions() {
        assert!(PresenceState::Online.accepts_tasks());
        assert!(
            PresenceState::Busy.accepts_tasks(),
            "busy queues, it does not drop"
        );
        assert!(!PresenceState::HighLoad.accepts_tasks());
        assert!(PresenceState::HighLoad.should_shed_load());
        assert!(!PresenceState::Busy.should_shed_load());
        assert!(PresenceState::Offline.should_shed_load());
    }
}
