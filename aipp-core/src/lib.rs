//! # AIPP — Agentic Internet & Presence Protocol (core library)
//!
//! A dual-plane wire protocol for multi-agent systems. It synthesizes the
//! two ideas that actually survived thirty years of network programming:
//!
//! * **IRC's channel model** — agents bind to ephemeral `#channels` and
//!   broadcast, with no central service-discovery graph to keep in sync.
//! * **ICQ/OSCAR's presence model** — every agent is a *stateful* node
//!   with an explicit presence vector, so an orchestrator can see
//!   `BUSY`/`HIGH_LOAD` and shed load instead of firing tasks into a
//!   black hole.
//!
//! Both travel over ONE persistent connection:
//!
//! ```text
//! +------------------------------------------------------+
//! |                 AIPP connection                      |
//! +---------------------------+--------------------------+
//! |  Control plane (text)     |  Payload plane (binary)  |
//! |  CRLF-terminated ASCII    |  TLV frames, magic 0x41  |
//! |  JOIN / STATUS / PRIVMSG  |  JSON, embeddings, blobs |
//! +---------------------------+--------------------------+
//! ```
//!
//! The control plane stays human-readable on purpose: `telnet` and `nc`
//! are legitimate debugging tools for agent fleets, and so is `grep` on a
//! wire capture. The payload plane exists because 4096-dimension float
//! vectors and streamed token chunks do not belong in a text line.
//!
//! Modules:
//! * [`control`] — the command vocabulary and its parser/serializer.
//! * [`presence`] — the five-state presence vector and its lifecycle.
//! * [`channel`] — channel registry, membership and operator flags.
//! * [`tlv`] — the binary frame codec (magic, version, length, TLV type).

pub mod channel;
pub mod control;
pub mod presence;
pub mod tlv;

pub use channel::{Channel, Flags, Registry};
pub use control::Command;
pub use presence::{AgentRecord, PresenceState};
pub use tlv::{Frame, FrameError};

/// Protocol version advertised in the binary frame header.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// CRLF: the control plane is line-oriented and ends every line with it.
pub const CRLF: &str = "\r\n";
