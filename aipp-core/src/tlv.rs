//! The payload plane: OSCAR-derived binary TLV frames.
//!
//! Control-plane text is right for commands and presence. It is wrong for
//! a 4096-dimension embedding (16 KiB of float32 that would become 40 KiB
//! of decimal digits) or for streamed token chunks where every byte of
//! framing is multiplied by thousands of messages a second.
//!
//! So the same connection carries binary frames:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Magic (0x41)  | Version (0x01)|         Frame Type (u16)      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Payload Length (u32)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      TLV Type (u16)           |        Reserved (u16)         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Payload (N bytes)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Demultiplexing rule, and it is the only one that keeps telnet usable:
//! an item is a **binary frame iff its first two bytes are `0x41 0x01`**;
//! anything else is a CRLF-terminated control line. Printable control
//! text can never start with `0x41 0x01`, so the rule is unambiguous.

use std::fmt;

/// Frame magic. Deliberately the ASCII of `A` so a hex dump of a capture
/// reads `41 01 ...` for frames and legible text for commands.
pub const MAGIC: u8 = 0x41;
/// Wire version. Bumping it is a breaking change to the header.
pub const VERSION: u8 = 0x01;
/// magic(1) + version(1) + frame_type(2) + length(4) + tlv_type(2) + reserved(2)
pub const HEADER_LEN: usize = 12;
/// Refuse absurd lengths instead of allocating what a hostile peer asks.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// The TLV type registry (section 4 of the spec).
pub mod tlv_type {
    /// Raw UTF-8 text token chunk — streamed LLM output.
    pub const TEXT_CHUNK: u16 = 0x0001;
    /// Structured JSON tool-execution payload (MCP / function call).
    pub const JSON_TOOL: u16 = 0x0002;
    /// Vector embedding, little-endian f32 array.
    pub const EMBEDDING: u16 = 0x0003;
    /// State snapshot / memory checkpoint blob.
    pub const STATE_SNAPSHOT: u16 = 0x0004;
    /// Store-and-forward envelope for an offline agent's queue.
    pub const STORE_FORWARD: u16 = 0x0005;
}

/// Human label for a TLV type, for logs and `NOTICE`s.
pub fn tlv_label(t: u16) -> &'static str {
    match t {
        tlv_type::TEXT_CHUNK => "TEXT_CHUNK",
        tlv_type::JSON_TOOL => "JSON_TOOL",
        tlv_type::EMBEDDING => "EMBEDDING",
        tlv_type::STATE_SNAPSHOT => "STATE_SNAPSHOT",
        tlv_type::STORE_FORWARD => "STORE_FORWARD",
        _ => "UNKNOWN",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    BadMagic(u8),
    UnsupportedVersion(u8),
    TooLarge(usize),
    TruncatedHeader,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic(b) => write!(f, "bad frame magic 0x{b:02X} (expected 0x41)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported frame version 0x{v:02X}"),
            Self::TooLarge(n) => write!(f, "payload of {n} bytes exceeds the {MAX_PAYLOAD} cap"),
            Self::TruncatedHeader => write!(f, "truncated frame header"),
        }
    }
}

impl std::error::Error for FrameError {}

/// One binary frame: a TLV-typed payload multiplexed on the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Reserved for future framing modes; 0x0001 = TLV over one channel.
    pub frame_type: u16,
    /// One of [`tlv_type`].
    pub tlv_type: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(tlv_type: u16, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            frame_type: 0x0001,
            tlv_type,
            payload: payload.into(),
        }
    }

    /// A JSON tool payload. Validation is the caller's job: this crate
    /// does not depend on a JSON parser to move bytes.
    pub fn json_tool(payload: impl Into<Vec<u8>>) -> Self {
        Self::new(tlv_type::JSON_TOOL, payload)
    }

    /// A streamed text chunk.
    pub fn text_chunk(chunk: &str) -> Self {
        Self::new(tlv_type::TEXT_CHUNK, chunk.as_bytes().to_vec())
    }

    /// A float32 embedding, little-endian on the wire (network order is
    /// for headers, not for arrays the peer will hand to BLAS).
    pub fn embedding(values: &[f32]) -> Self {
        let mut payload = Vec::with_capacity(values.len() * 4);
        for v in values {
            payload.extend_from_slice(&v.to_le_bytes());
        }
        Self::new(tlv_type::EMBEDDING, payload)
    }

    /// Decode a float32 embedding payload back.
    pub fn embedding_values(&self) -> Option<Vec<f32>> {
        if self.tlv_type != tlv_type::EMBEDDING || !self.payload.len().is_multiple_of(4) {
            return None;
        }
        Some(
            self.payload
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
        )
    }

    /// Total wire size of this frame, header included.
    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.push(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.frame_type.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.tlv_type.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // reserved
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode one frame from the front of `buf`.
    ///
    /// * `Ok(Some((frame, consumed)))` — a whole frame.
    /// * `Ok(None)` — the buffer holds only part of a frame; read more.
    /// * `Err(_)` — the bytes are not a frame this version accepts.
    pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
        if buf.is_empty() {
            return Ok(None);
        }
        let magic = buf[0];
        if magic != MAGIC {
            return Err(FrameError::BadMagic(magic));
        }
        if buf.len() < 2 {
            return Ok(None);
        }
        if buf[1] != VERSION {
            return Err(FrameError::UnsupportedVersion(buf[1]));
        }
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let frame_type = u16::from_be_bytes([buf[2], buf[3]]);
        let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(FrameError::TooLarge(len));
        }
        let tlv_type = u16::from_be_bytes([buf[8], buf[9]]);
        let total = HEADER_LEN + len;
        if buf.len() < total {
            return Ok(None);
        }
        Ok(Some((
            Frame {
                frame_type,
                tlv_type,
                payload: buf[HEADER_LEN..total].to_vec(),
            },
            total,
        )))
    }

    /// Cheap demux check used by the connection reader before it decides
    /// between "frame" and "text line".
    pub fn looks_like_frame(buf: &[u8]) -> bool {
        buf.len() >= 2 && buf[0] == MAGIC && buf[1] == VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_matches_the_spec_diagram() {
        let f = Frame::new(tlv_type::JSON_TOOL, vec![1, 2, 3, 4]);
        let wire = f.encode();
        assert_eq!(wire[0], 0x41, "magic");
        assert_eq!(wire[1], 0x01, "version");
        assert_eq!(&wire[2..4], &[0x00, 0x01], "frame type big-endian");
        assert_eq!(&wire[4..8], &[0, 0, 0, 4], "payload length big-endian");
        assert_eq!(&wire[8..10], &[0x00, 0x02], "tlv type big-endian");
        assert_eq!(&wire[10..12], &[0x00, 0x00], "reserved");
        assert_eq!(&wire[12..], &[1, 2, 3, 4], "payload");
        assert_eq!(wire.len(), f.wire_len());
    }

    #[test]
    fn roundtrip_all_registry_types() {
        for t in [
            tlv_type::TEXT_CHUNK,
            tlv_type::JSON_TOOL,
            tlv_type::EMBEDDING,
            tlv_type::STATE_SNAPSHOT,
            tlv_type::STORE_FORWARD,
            0x00FF,
        ] {
            let f = Frame::new(t, b"payload".to_vec());
            let (back, used) = Frame::decode(&f.encode()).unwrap().unwrap();
            assert_eq!(back, f);
            assert_eq!(used, f.wire_len());
        }
    }

    #[test]
    fn partial_bytes_report_need_more_not_corruption() {
        let f = Frame::new(tlv_type::TEXT_CHUNK, b"hello world".to_vec());
        let wire = f.encode();
        for cut in 0..wire.len() {
            match Frame::decode(&wire[..cut]) {
                Ok(None) => {}
                other => panic!("cut at {cut} should be incomplete, got {other:?}"),
            }
        }
        assert!(
            Frame::decode(&wire).unwrap().is_some(),
            "full buffer decodes"
        );
    }

    #[test]
    fn demux_rule_distinguishes_frames_from_text() {
        assert!(Frame::looks_like_frame(&[0x41, 0x01]));
        assert!(
            !Frame::looks_like_frame(b"ACK 001 :welcome"),
            "text is not a frame"
        );
        assert!(!Frame::looks_like_frame(&[0x41]), "one byte is not enough");
        // 'A' then CR would be text, not a frame
        assert!(!Frame::looks_like_frame(&[0x41, 0x0D]));
    }

    #[test]
    fn embedding_roundtrips_little_endian_float32() {
        let values = vec![0.5f32, -1.25, 3.75, 0.0];
        let f = Frame::embedding(&values);
        assert_eq!(f.tlv_type, tlv_type::EMBEDDING);
        assert_eq!(f.payload.len(), 16, "4 floats x 4 bytes");
        assert_eq!(f.embedding_values().unwrap(), values);
        // 0.5f32 LE = 00 00 00 3F
        assert_eq!(&f.payload[0..4], &[0x00, 0x00, 0x00, 0x3F]);
        assert!(
            Frame::text_chunk("x").embedding_values().is_none(),
            "wrong type"
        );
    }

    #[test]
    fn rejects_bad_magic_version_and_oversize() {
        assert_eq!(
            Frame::decode(&[0x42, 0x01]).unwrap_err(),
            FrameError::BadMagic(0x42)
        );
        assert_eq!(
            Frame::decode(&[0x41, 0x09]).unwrap_err(),
            FrameError::UnsupportedVersion(0x09)
        );
        let mut hostile = vec![0x41, 0x01, 0x00, 0x01];
        hostile.extend_from_slice(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
        hostile.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(
            Frame::decode(&hostile).unwrap_err(),
            FrameError::TooLarge(_)
        ));
    }

    #[test]
    fn two_frames_back_to_back_decode_in_order() {
        let a = Frame::text_chunk("first").encode();
        let b = Frame::json_tool(br#"{"tool":"grep"}"#.to_vec()).encode();
        let mut wire = a.clone();
        wire.extend_from_slice(&b);

        let (f1, n1) = Frame::decode(&wire).unwrap().unwrap();
        let (f2, n2) = Frame::decode(&wire[n1..]).unwrap().unwrap();
        assert_eq!(n1, a.len());
        assert_eq!(n1 + n2, wire.len());
        assert_eq!(f1.payload, b"first");
        assert_eq!(f2.payload, br#"{"tool":"grep"}"#);
    }
}
