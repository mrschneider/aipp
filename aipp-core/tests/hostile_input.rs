//! Hostile input: the parsers are the two places where an attacker
//! writes first. This is a deterministic stress test (xorshift, no
//! libFuzzer toolchain) over 40k inputs: garbage, long tokens, embedded
//! NULs, CRLF soup, truncated frames.
//!
//! The contract asserted here is narrow and honest: **the parser returns,
//! it never panics and never allocates unbounded memory.**

use aipp_core::control::Command;
use aipp_core::tlv::{Frame, MAX_PAYLOAD};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }

    fn range(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz0123456789#@:.-_\\x00\\r\\n\\t";

fn mutate(rng: &mut Rng, seeds: &[&[u8]]) -> Vec<u8> {
    let mut out = seeds[rng.range(seeds.len())].to_vec();
    match rng.range(4) {
        0 => {
            let n = rng.range(64);
            for _ in 0..n {
                out.push(ALPHABET[rng.range(ALPHABET.len())]);
            }
        }
        1 => {
            let n = rng.range(out.len().max(1));
            for _ in 0..n {
                if out.is_empty() {
                    break;
                }
                let i = rng.range(out.len());
                out[i] = ALPHABET[rng.range(ALPHABET.len())];
            }
        }
        2 => {
            let n = rng.range(8);
            for _ in 0..n {
                if !out.is_empty() {
                    out.remove(rng.range(out.len()));
                }
            }
        }
        _ => {
            let n = rng.range(200);
            out.extend(std::iter::repeat_n(0u8, n));
        }
    }
    out
}

#[test]
fn the_line_parser_always_answers() {
    let seeds: Vec<&[u8]> = vec![
        b"NICK a",
        b"STATUS ag 0x01 1024 3",
        b"JOIN #c",
        b"MODE #c +v a",
        b"PRIVMSG #c :hello",
        b"BIN_FRAME #c 0x0002 10",
        b"AUTH a.1.1.ff",
        b"TOPIC #c :t",
        b"WHO @pool:q",
    ];
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for _ in 0..20_000 {
        let raw = mutate(&mut rng, &seeds);
        let line = String::from_utf8_lossy(&raw);
        // no panic is the assertion; a parsed command must also serialize
        // back into something that parses again
        if let Ok(cmd) = Command::parse(&line) {
            let canonical = cmd.to_line();
            let again = Command::parse(&canonical).unwrap_or_else(|e| {
                panic!("canonical form of {line:?} does not re-parse: {canonical:?} -> {e}")
            });
            assert_eq!(again.to_line(), canonical, "not idempotent: {canonical:?}");
        }
    }
}

#[test]
fn the_frame_decoder_never_panics_and_never_over_allocates() {
    let seed = Frame::new(2, b"{\"intent\":\"X\"}".to_vec()).encode();
    let mut rng = Rng(0x2545F4914F6CDD1D);
    for _ in 0..20_000 {
        let mut data = seed.clone();
        match rng.range(3) {
            0 => {
                for _ in 0..rng.range(16) {
                    if !data.is_empty() {
                        let i = rng.range(data.len());
                        data[i] = rng.byte();
                    }
                }
            }
            1 => data.truncate(rng.range(data.len().max(1))),
            _ => {
                let n = rng.range(64);
                for _ in 0..n {
                    data.push(rng.byte());
                }
            }
        }
        if let Ok(Some((f, used))) = Frame::decode(&data) {
            assert!(used <= data.len(), "decode consumed more than it was given");
            assert!(f.payload.len() <= MAX_PAYLOAD);
        }
    }
}

#[test]
fn an_announced_length_above_the_cap_is_refused() {
    // craft a header claiming 4 GiB: the decoder must refuse before it
    // allocates anything of the sort
    let mut bytes = Frame::new(2, b"x".to_vec()).encode();
    let len = (u32::MAX - 1).to_be_bytes();
    bytes[4..8].copy_from_slice(&len);
    match Frame::decode(&bytes) {
        Err(_) => {}
        Ok(None) => panic!("an over-cap header must be refused, not awaited"),
        Ok(Some(_)) => panic!("an over-cap header must not decode"),
    }
}
