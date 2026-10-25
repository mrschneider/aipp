//! Conformance suite: replay `conformance/vectors.json`.
//!
//! This is the file another implementation can run against. It asserts the
//! two things a wire protocol actually promises: what a canonical line
//! looks like, and how a refusal is explained. Nothing here is
//! implementation-specific — no sockets, no broker.

use aipp_core::control::Command;
use aipp_core::tlv::{Frame, HEADER_LEN, MAGIC, VERSION};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../conformance/vectors.json");
    let text = std::fs::read_to_string(path).expect("conformance vectors are readable");
    serde_json::from_str(&text).expect("conformance vectors are valid JSON")
}

#[test]
fn every_canonical_line_parses_to_itself() {
    let v = vectors();
    let mut checked = 0;
    for case in v["lines_ok"].as_array().expect("lines_ok") {
        let input = case["in"].as_str().expect("in");
        let canonical = case["canonical"].as_str().expect("canonical");
        let parsed =
            Command::parse(input).unwrap_or_else(|e| panic!("{input:?} must parse, got error {e}"));
        assert_eq!(
            parsed.to_line(),
            canonical,
            "{input:?} must round-trip to {canonical:?}"
        );
        // the canonical form must itself round-trip: a spec that is not
        // idempotent is not a spec
        let again = Command::parse(canonical).expect("canonical form parses");
        assert_eq!(
            again.to_line(),
            canonical,
            "{canonical:?} is not idempotent"
        );
        checked += 1;
    }
    assert!(checked >= 20, "expected the full vector set, got {checked}");
}

#[test]
fn every_invalid_line_is_refused_with_a_reason() {
    let v = vectors();
    let mut checked = 0;
    for case in v["lines_bad"].as_array().expect("lines_bad") {
        let input = case["in"].as_str().expect("in");
        let needle = case["error_contains"].as_str().expect("error_contains");
        let err = match Command::parse(input) {
            Ok(cmd) => panic!("{input:?} must be refused, but parsed as {cmd:?}"),
            Err(e) => e,
        };
        assert!(
            err.contains(needle),
            "{input:?} -> {err:?} must mention {needle:?}"
        );
        checked += 1;
    }
    assert!(checked >= 12, "expected the full refuse set, got {checked}");
}

#[test]
fn every_frame_vector_decodes_to_the_same_bytes() {
    let v = vectors();
    let mut checked = 0;
    for case in v["frames"].as_array().expect("frames") {
        let tlv_type = case["tlv_type"].as_u64().expect("tlv_type") as u16;
        let hex = case["payload_hex"].as_str().expect("payload_hex");
        let payload: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();

        let frame = Frame::new(tlv_type, payload.clone());
        let wire = frame.encode();

        // the header is normative: magic, version, and a length that agrees
        // with the payload it carries
        assert_eq!(wire[0], MAGIC, "byte 0 is the magic");
        assert_eq!(wire[1], VERSION, "byte 1 is the version");
        assert_eq!(wire.len(), HEADER_LEN + payload.len());

        let (decoded, used) = Frame::decode(&wire)
            .expect("decode")
            .expect("one frame is enough");
        assert_eq!(decoded.tlv_type, tlv_type);
        assert_eq!(decoded.payload, payload);
        assert_eq!(used, wire.len(), "decode must consume exactly one frame");
        checked += 1;
    }
    assert_eq!(checked, 3, "expected three frame vectors");
}

#[test]
fn a_truncated_frame_is_incomplete_not_corrupt() {
    let frame = Frame::new(2, vec![1, 2, 3, 4]);
    let wire = frame.encode();
    for cut in 1..wire.len() {
        match Frame::decode(&wire[..cut]) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("a truncated frame must not decode as complete (cut {cut})"),
            Err(e) => panic!("a truncated frame must be incomplete, not invalid (cut {cut}): {e}"),
        }
    }
}
