//! The control plane: IRC-derived, line-oriented, CRLF-terminated ASCII.
//!
//! Every line is `COMMAND [args...] [ :trailing text]`. The trailing
//! form (IRC's `:text`) exists for exactly one reason: message bodies
//! contain spaces, and quoting them would make the protocol
//! un-`grep`-able.
//!
//! Parsing is deliberately strict and gives a precise error: a broker
//! that silently ignores a malformed command is a broker whose agents
//! think a task was dispatched when it was not.

use crate::presence::PresenceState;

/// One control-plane command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `NICK <agent_name>` — bind the session to an immutable AG-ID.
    Nick(String),
    /// `USER <agent_class> <capabilities_bitmask>`
    User { class: String, caps: u32 },
    /// `STATUS <agent_id> <state_hex> <vram_free_mb> <active_tasks>`
    Status {
        agent: String,
        state: PresenceState,
        vram_free_mb: u32,
        active_tasks: u32,
    },
    /// `JOIN #channel`
    Join(String),
    /// `PART #channel [:reason]`
    Part {
        channel: String,
        reason: Option<String>,
    },
    /// `PRIVMSG <#channel|nick> :text`
    Privmsg { target: String, text: String },
    /// `NOTICE <#channel|nick> :text` — system voice, never a reply.
    Notice { target: String, text: String },
    /// `MODE #channel +o|-o|+v|-v <nick>`
    Mode {
        channel: String,
        flag: char,
        on: bool,
        target: String,
    },
    /// `KICK #channel <nick> [:reason]`
    Kick {
        channel: String,
        target: String,
        reason: String,
    },
    /// `QUIT [:reason]`
    Quit { reason: String },
    /// `PING [:token]` — also the heartbeat.
    Ping(Option<String>),
    /// `PONG [:token]`
    Pong(Option<String>),
    /// `NAMES #channel` — ask who is present right now.
    Names(String),
    /// `BIN_FRAME <#channel|nick> <tlv_type_hex> <length>` — announces
    /// that the next item on the wire is a binary frame of that size.
    BinFrame {
        target: String,
        tlv_type: u16,
        length: u32,
    },
}

/// Split a line into the head tokens and the IRC trailing part.
fn split_trailing(line: &str) -> (Vec<&str>, Option<&str>) {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    match trimmed.find(" :") {
        Some(pos) => {
            let head: Vec<&str> = trimmed[..pos].split_whitespace().collect();
            (head, Some(&trimmed[pos + 2..]))
        }
        None => (trimmed.split_whitespace().collect(), None),
    }
}

fn parse_channel(name: &str) -> Result<String, String> {
    if !name.starts_with('#') || name.len() < 2 {
        return Err(format!("channel names start with '#': got '{name}'"));
    }
    if name.chars().any(|c| c.is_whitespace() || c == ',') {
        return Err(format!("channel name has invalid characters: '{name}'"));
    }
    Ok(name.to_string())
}

impl Command {
    /// Parse one CRLF-stripped control line.
    pub fn parse(line: &str) -> Result<Command, String> {
        let (head, trailing) = split_trailing(line);
        let Some(cmd) = head.first().map(|c| c.to_ascii_uppercase()) else {
            return Err("empty command".to_string());
        };
        let args = &head[1..];
        let arg = |i: usize, what: &str| -> Result<&str, String> {
            args.get(i)
                .copied()
                .ok_or_else(|| format!("{cmd}: missing {what}"))
        };
        match cmd.as_str() {
            "NICK" => {
                let name = arg(0, "agent name")?;
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_alphanumeric() || "_-.|".contains(c))
                {
                    return Err(format!("NICK: invalid agent id '{name}'"));
                }
                Ok(Command::Nick(name.to_string()))
            }
            "USER" => {
                let class = arg(0, "agent class")?;
                let caps_raw = arg(1, "capabilities bitmask")?;
                let caps = parse_u32(caps_raw)
                    .ok_or_else(|| format!("USER: invalid capability bitmask '{caps_raw}'"))?;
                Ok(Command::User {
                    class: class.to_string(),
                    caps,
                })
            }
            "STATUS" => {
                let agent = arg(0, "agent id")?;
                let state_raw = arg(1, "presence state (0x00..0x04)")?;
                let state = PresenceState::from_hex(state_raw)
                    .ok_or_else(|| format!("STATUS: unknown presence state '{state_raw}'"))?;
                let vram = arg(2, "vram_free_mb")?
                    .parse::<u32>()
                    .map_err(|_| "STATUS: vram_free_mb must be a number".to_string())?;
                let tasks = arg(3, "active_tasks")?
                    .parse::<u32>()
                    .map_err(|_| "STATUS: active_tasks must be a number".to_string())?;
                Ok(Command::Status {
                    agent: agent.to_string(),
                    state,
                    vram_free_mb: vram,
                    active_tasks: tasks,
                })
            }
            "JOIN" => Ok(Command::Join(parse_channel(arg(0, "channel")?)?)),
            "NAMES" => Ok(Command::Names(parse_channel(arg(0, "channel")?)?)),
            "PART" => Ok(Command::Part {
                channel: parse_channel(arg(0, "channel")?)?,
                reason: trailing.map(str::to_string),
            }),
            "PRIVMSG" => {
                let target = arg(0, "target")?;
                let text = trailing.ok_or_else(|| "PRIVMSG: missing ':text'".to_string())?;
                Ok(Command::Privmsg {
                    target: target.to_string(),
                    text: text.to_string(),
                })
            }
            "NOTICE" => {
                let target = arg(0, "target")?;
                let text = trailing.ok_or_else(|| "NOTICE: missing ':text'".to_string())?;
                Ok(Command::Notice {
                    target: target.to_string(),
                    text: text.to_string(),
                })
            }
            "MODE" => {
                let channel = parse_channel(arg(0, "channel")?)?;
                let mode = arg(1, "mode (+o|-o|+v|-v)")?;
                let mut chars = mode.chars();
                let sign = chars.next().ok_or("MODE: empty mode")?;
                if sign != '+' && sign != '-' {
                    return Err(format!(
                        "MODE: mode must start with '+' or '-', got '{mode}'"
                    ));
                }
                let flag = chars.next().ok_or("MODE: missing flag")?;
                if chars.next().is_some() {
                    return Err(format!("MODE: one flag per command, got '{mode}'"));
                }
                let on = match sign {
                    '+' => true,
                    '-' => false,
                    _ => unreachable!("sign was validated above"),
                };
                if flag != 'o' && flag != 'v' {
                    return Err(format!(
                        "MODE: unsupported channel flag '{flag}' (use o or v)"
                    ));
                }
                Ok(Command::Mode {
                    channel,
                    flag,
                    on,
                    target: arg(2, "target nick")?.to_string(),
                })
            }
            "KICK" => Ok(Command::Kick {
                channel: parse_channel(arg(0, "channel")?)?,
                target: arg(1, "target nick")?.to_string(),
                reason: trailing.unwrap_or("no reason given").to_string(),
            }),
            "QUIT" => Ok(Command::Quit {
                reason: trailing.unwrap_or("leaving").to_string(),
            }),
            "PING" => Ok(Command::Ping(trailing.map(str::to_string))),
            "PONG" => Ok(Command::Pong(trailing.map(str::to_string))),
            "BIN_FRAME" => {
                let target = arg(0, "target")?;
                let tlv_raw = arg(1, "tlv type")?;
                let tlv_type = parse_hex16(tlv_raw)
                    .ok_or_else(|| format!("BIN_FRAME: invalid tlv type '{tlv_raw}'"))?;
                let length = arg(2, "payload length")?
                    .parse::<u32>()
                    .map_err(|_| "BIN_FRAME: length must be a number".to_string())?;
                Ok(Command::BinFrame {
                    target: target.to_string(),
                    tlv_type,
                    length,
                })
            }
            other => Err(format!("unknown command '{other}'")),
        }
    }

    /// Serialize back to the canonical wire line (no CRLF).
    pub fn to_line(&self) -> String {
        match self {
            Command::Nick(n) => format!("NICK {n}"),
            Command::User { class, caps } => format!("USER {class} 0x{caps:02X}"),
            Command::Status {
                agent,
                state,
                vram_free_mb,
                active_tasks,
            } => format!(
                "STATUS {agent} {} {vram_free_mb} {active_tasks}",
                state.hex()
            ),
            Command::Join(c) => format!("JOIN {c}"),
            Command::Names(c) => format!("NAMES {c}"),
            Command::Part { channel, reason } => match reason {
                Some(r) => format!("PART {channel} :{r}"),
                None => format!("PART {channel}"),
            },
            Command::Privmsg { target, text } => format!("PRIVMSG {target} :{text}"),
            Command::Notice { target, text } => format!("NOTICE {target} :{text}"),
            Command::Mode {
                channel,
                flag,
                on,
                target,
            } => format!(
                "MODE {channel} {}{flag} {target}",
                if *on { '+' } else { '-' }
            ),
            Command::Kick {
                channel,
                target,
                reason,
            } => format!("KICK {channel} {target} :{reason}"),
            Command::Quit { reason } => format!("QUIT :{reason}"),
            Command::Ping(Some(t)) => format!("PING :{t}"),
            Command::Ping(None) => "PING".to_string(),
            Command::Pong(Some(t)) => format!("PONG :{t}"),
            Command::Pong(None) => "PONG".to_string(),
            Command::BinFrame {
                target,
                tlv_type,
                length,
            } => format!("BIN_FRAME {target} 0x{tlv_type:04X} {length}"),
        }
    }
}

fn parse_u32(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_hex16(s: &str) -> Option<u16> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).ok()
    } else {
        u16::from_str_radix(s, 16).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_reference_trace_lines() {
        // the exact lines from the protocol spec's example trace
        assert_eq!(
            Command::parse("NICK builder_agent").unwrap(),
            Command::Nick("builder_agent".into())
        );
        assert_eq!(
            Command::parse("USER coder-specialist 0x0F").unwrap(),
            Command::User {
                class: "coder-specialist".into(),
                caps: 0x0F
            }
        );
        assert_eq!(
            Command::parse("STATUS builder_agent 0x00 61440 0").unwrap(),
            Command::Status {
                agent: "builder_agent".into(),
                state: PresenceState::Online,
                vram_free_mb: 61440,
                active_tasks: 0
            }
        );
        assert_eq!(
            Command::parse("JOIN #swarm-backend").unwrap(),
            Command::Join("#swarm-backend".into())
        );
        assert_eq!(
            Command::parse(
                "PRIVMSG #swarm-backend :Generated migration script for PostgreSQL schema."
            )
            .unwrap(),
            Command::Privmsg {
                target: "#swarm-backend".into(),
                text: "Generated migration script for PostgreSQL schema.".into()
            }
        );
        assert_eq!(
            Command::parse("MODE #code-review +o supervisor_agent").unwrap(),
            Command::Mode {
                channel: "#code-review".into(),
                flag: 'o',
                on: true,
                target: "supervisor_agent".into()
            }
        );
        assert_eq!(
            Command::parse("KICK #code-review rogue_agent :Infinite loop detected").unwrap(),
            Command::Kick {
                channel: "#code-review".into(),
                target: "rogue_agent".into(),
                reason: "Infinite loop detected".into()
            }
        );
    }

    #[test]
    fn trailing_text_keeps_its_spaces_and_colons() {
        let c = Command::parse("PRIVMSG #ops :fix auth.rs:42 : the lifetime is wrong").unwrap();
        assert_eq!(
            c,
            Command::Privmsg {
                target: "#ops".into(),
                text: "fix auth.rs:42 : the lifetime is wrong".into()
            }
        );
    }

    #[test]
    fn roundtrip_every_variant() {
        let samples = [
            Command::Nick("ag_1".into()),
            Command::User {
                class: "qa".into(),
                caps: 0x0F,
            },
            Command::Status {
                agent: "ag_1".into(),
                state: PresenceState::Busy,
                vram_free_mb: 32768,
                active_tasks: 2,
            },
            Command::Join("#swarm".into()),
            Command::Part {
                channel: "#swarm".into(),
                reason: Some("done".into()),
            },
            Command::Privmsg {
                target: "#swarm".into(),
                text: "hello there".into(),
            },
            Command::Notice {
                target: "#system".into(),
                text: "[WARN] GPU temperature exceeds 85C".into(),
            },
            Command::Mode {
                channel: "#swarm".into(),
                flag: 'v',
                on: false,
                target: "ag_2".into(),
            },
            Command::Kick {
                channel: "#swarm".into(),
                target: "ag_3".into(),
                reason: "Infinite loop detected".into(),
            },
            Command::Quit {
                reason: "Heartbeat timeout - dropping session".into(),
            },
            Command::Names("#swarm".into()),
            Command::Ping(Some("tok".into())),
            Command::BinFrame {
                target: "#swarm".into(),
                tlv_type: 0x0002,
                length: 512,
            },
        ];
        for c in samples {
            let line = c.to_line();
            let back = Command::parse(&line).unwrap_or_else(|e| panic!("{line}: {e}"));
            assert_eq!(back, c, "roundtrip of {line}");
        }
    }

    #[test]
    fn rejects_with_a_reason_instead_of_guessing() {
        for (bad, needle) in [
            ("JOIN swarm", "start with '#'"),
            ("STATUS ag 0x09 1 0", "unknown presence state"),
            ("STATUS ag 0x00 many 0", "vram_free_mb"),
            ("PRIVMSG #c no-colon-text", "missing ':text'"),
            ("MODE #c +x ag", "unsupported channel flag"),
            ("MODE #c o ag", "must start with '+' or '-'"),
            ("BOGUS #c", "unknown command"),
            ("", "empty command"),
        ] {
            let err = Command::parse(bad).unwrap_err();
            assert!(
                err.contains(needle),
                "'{bad}' -> '{err}' should mention {needle}"
            );
        }
    }

    #[test]
    fn hex_and_decimal_capability_masks_both_parse() {
        assert_eq!(
            Command::parse("USER coder 15").unwrap(),
            Command::parse("USER coder 0x0F").unwrap()
        );
    }
}
