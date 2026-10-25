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

/// Frames larger than this are fragmented, keeping one frame's work
/// bounded and a hostile header from asking for a huge allocation.
pub const MAX_FRAGMENT: usize = 64 * 1024;

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
    /// Continuation of a fragmented TLV payload (AIPP's own extension).
    pub const FRAGMENT: u16 = 0x0007;
}

/// Human label for a TLV type, for logs and `NOTICE`s.
pub fn tlv_label(t: u16) -> &'static str {
    match t {
        tlv_type::TEXT_CHUNK => "TEXT_CHUNK",
        tlv_type::JSON_TOOL => "JSON_TOOL",
        tlv_type::EMBEDDING => "EMBEDDING",
        tlv_type::STATE_SNAPSHOT => "STATE_SNAPSHOT",
        tlv_type::STORE_FORWARD => "STORE_FORWARD",
        tlv_type::FRAGMENT => "FRAGMENT",
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

/// Split a payload into `FRAGMENT` frames: a 6-byte header (bundle id,
/// index, total) then the chunk. Reassembly is by bundle id, and an
/// incomplete set is never delivered — the same rule as GAIP's GIOP
/// fragments, because a half message is worse than none.
pub fn fragment_payload(bundle_id: u32, inner: u16, payload: &[u8], max: usize) -> Vec<Frame> {
    let max = max.clamp(64, MAX_FRAGMENT);
    let chunks: Vec<&[u8]> = payload.chunks(max).collect();
    let total = chunks.len().max(1) as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut body = Vec::with_capacity(10 + chunk.len());
            body.extend_from_slice(&bundle_id.to_be_bytes());
            // the original TLV type rides in the bundle, so reassembly can
            // hand back the frame the sender meant, not a FRAGMENT
            body.extend_from_slice(&inner.to_be_bytes());
            body.extend_from_slice(&(i as u16).to_be_bytes());
            body.extend_from_slice(&total.to_be_bytes());
            body.extend_from_slice(chunk);
            Frame::new(tlv_type::FRAGMENT, body)
        })
        .collect()
}

/// Collects fragments until a set is complete.
/// bundle id -> (total fragments, received chunks)
type Partial = std::collections::HashMap<u32, (u16, Vec<Option<Vec<u8>>>)>;

#[derive(Debug, Default)]
pub struct Reassembler {
    partial: Partial,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one fragment. Returns the whole payload once every fragment
    /// of that bundle has arrived.
    pub fn push(&mut self, frame: &Frame) -> Option<(u32, u16, Vec<u8>)> {
        if frame.tlv_type != tlv_type::FRAGMENT || frame.payload.len() < 10 {
            return None;
        }
        let id = u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]);
        let inner = u16::from_be_bytes([frame.payload[4], frame.payload[5]]);
        let index = u16::from_be_bytes([frame.payload[6], frame.payload[7]]) as usize;
        // total lives in the chunk header for the first fragment only in
        // some encodings; here every fragment carries it in bytes 4..6 of
        // the body prefix, so parse it from the third field
        let total = u16::from_be_bytes([
            frame.payload.get(8).copied().unwrap_or(0),
            frame.payload.get(9).copied().unwrap_or(0),
        ]) as usize;
        let chunk = frame.payload.get(10..)?.to_vec();
        if total == 0 || index >= total {
            return None;
        }
        let entry = self
            .partial
            .entry(id)
            .or_insert_with(|| (total as u16, vec![None; total]));
        entry.1[index] = Some(chunk);
        if entry.1.iter().all(|p| p.is_some()) {
            let (_, parts) = self.partial.remove(&id)?;
            let joined: Vec<u8> = parts.into_iter().flatten().flatten().collect();
            return Some((id, inner, joined));
        }
        None
    }

    pub fn pending(&self) -> usize {
        self.partial.len()
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
    fn a_large_payload_fragments_and_reassembles() {
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let frames = fragment_payload(7, tlv_type::JSON_TOOL, &payload, 512);
        assert!(frames.len() > 8, "5000 B at 512/frag -> {}", frames.len());
        let mut r = Reassembler::new();
        let mut out = None;
        for f in &frames {
            if let Some(done) = r.push(f) {
                out = Some(done);
            }
        }
        let (id, inner, joined) = out.expect("a complete set must reassemble");
        assert_eq!(id, 7);
        assert_eq!(
            inner,
            tlv_type::JSON_TOOL,
            "the original type survives the split"
        );
        assert_eq!(joined, payload);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn an_incomplete_set_is_never_delivered() {
        let payload: Vec<u8> = vec![9u8; 2000];
        let mut frames = fragment_payload(1, tlv_type::JSON_TOOL, &payload, 256);
        frames.pop();
        let mut r = Reassembler::new();
        for f in &frames {
            assert!(r.push(f).is_none(), "half a message must not be delivered");
        }
        assert_eq!(r.pending(), 1);
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
