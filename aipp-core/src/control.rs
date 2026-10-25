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
        /// the away/status message: the *why* behind the state
        status_text: Option<String>,
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
    /// `AUTH <token>` — prove identity before NICK; the AG-ID comes from
    /// the token, never from the claim.
    Auth(String),
    /// `CAP LS` — advertise optional capabilities so extensions can be
    /// added without breaking old clients.
    Cap,
    /// `TOPIC #channel [:new topic]` — read or set the topic.
    Topic {
        channel: String,
        topic: Option<String>,
    },
    /// `LIST` — operator view of channels and occupancy.
    List,
    /// `WHO [#channel|@pool]` — operator view of participants.
    Who(Option<String>),
    /// `DRAIN` — stop accepting new work, finish what is in flight.
    Drain,
    /// server-side roster: `ROSTER ADD <target>` / `ROSTER DEL <target>` /
    /// `ROSTER` — the contact list the broker persists for this agent.
    Roster {
        op: RosterOp,
        target: Option<String>,
    },
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

/// `@pool:name` addresses a group of agents; the broker picks a live one
/// by presence. `#channel` addresses a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterOp {
    List,
    Add,
    Del,
}

pub fn parse_target(name: &str) -> Result<String, String> {
    if name.starts_with('@') {
        let pool = name.strip_prefix('@').unwrap_or(name);
        let (kind, rest) = pool
            .split_once(':')
            .ok_or_else(|| format!("a pool target is '@pool:<name>', got '{name}'"))?;
        if kind != "pool" || rest.is_empty() {
            return Err(format!("a pool target is '@pool:<name>', got '{name}'"));
        }
        if !rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!("invalid pool name '{rest}'"));
        }
        return Ok(name.to_string());
    }
    parse_channel(name)
}

pub fn is_pool(target: &str) -> bool {
    target.starts_with("@pool:")
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
                let state_raw = arg(1, "presence state (0x00..0x05)")?;
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
                    status_text: trailing.map(str::to_string),
                })
            }
            "JOIN" => Ok(Command::Join(parse_channel(arg(0, "channel")?)?)),
            "NAMES" => Ok(Command::Names(parse_channel(arg(0, "channel")?)?)),
            "AUTH" => Ok(Command::Auth(arg(0, "token")?.to_string())),
            "CAP" => {
                if let Some(sub) = args.first() {
                    if !sub.eq_ignore_ascii_case("LS") && !sub.eq_ignore_ascii_case("LIST") {
                        return Err(format!("CAP: unknown subcommand '{sub}' (use LS)"));
                    }
                }
                Ok(Command::Cap)
            }
            "TOPIC" => Ok(Command::Topic {
                channel: parse_channel(arg(0, "channel")?)?,
                topic: trailing.map(str::to_string),
            }),
            "LIST" => Ok(Command::List),
            "WHO" => {
                // a bare "@pool:" is a malformed target, not "everything"
                if let Some(t) = args.first() {
                    if t.starts_with('@') {
                        parse_target(t).map_err(|e| format!("WHO: {e}"))?;
                    }
                }
                Ok(Command::Who(args.first().map(|s| s.to_string())))
            }
            "DRAIN" => Ok(Command::Drain),
            "ROSTER" => {
                let op = match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
                    None | Some("LIST") => RosterOp::List,
                    Some("ADD") => RosterOp::Add,
                    Some("DEL") | Some("REMOVE") => RosterOp::Del,
                    Some(other) => {
                        return Err(format!("ROSTER: unknown op '{other}' (LIST, ADD, DEL)"))
                    }
                };
                let target = match op {
                    RosterOp::List => None,
                    _ => Some(arg(1, "target")?.to_string()),
                };
                Ok(Command::Roster { op, target })
            }
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
                // member flags (o, v) name a target; channel flags
                // (m, i, t) do not
                if !matches!(flag, 'o' | 'v' | 'm' | 'i' | 't') {
                    return Err(format!(
                        "MODE: unsupported flag '{flag}' (member: o, v; channel: m, i, t)"
                    ));
                }
                Ok(Command::Mode {
                    channel,
                    flag,
                    on,
                    target: if matches!(flag, 'm' | 'i' | 't') {
                        args.get(2).map(|s| s.to_string()).unwrap_or_default()
                    } else {
                        arg(2, "target nick")?.to_string()
                    },
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
            // the spec documents `PING <token>`; a token is accepted with
            // or without the colon, because a client that sends the bare
            // form must still be able to match its reply
            "PING" => Ok(Command::Ping(
                trailing
                    .map(str::to_string)
                    .or_else(|| args.first().map(|s| s.to_string())),
            )),
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
                status_text,
            } => match status_text {
                Some(t) => format!(
                    "STATUS {agent} {} {vram_free_mb} {active_tasks} :{t}",
                    state.hex()
                ),
                None => format!(
                    "STATUS {agent} {} {vram_free_mb} {active_tasks}",
                    state.hex()
                ),
            },
            Command::Join(c) => format!("JOIN {c}"),
            Command::Names(c) => format!("NAMES {c}"),
            Command::Auth(t) => format!("AUTH {t}"),
            Command::Cap => "CAP LS".to_string(),
            Command::Topic { channel, topic } => match topic {
                Some(t) => format!("TOPIC {channel} :{t}"),
                None => format!("TOPIC {channel}"),
            },
            Command::List => "LIST".to_string(),
            Command::Who(Some(t)) => format!("WHO {t}"),
            Command::Who(None) => "WHO".to_string(),
            Command::Drain => "DRAIN".to_string(),
            Command::Roster { op, target } => match (op, target) {
                (RosterOp::List, _) => "ROSTER LIST".to_string(),
                (RosterOp::Add, Some(t)) => format!("ROSTER ADD {t}"),
                (RosterOp::Del, Some(t)) => format!("ROSTER DEL {t}"),
                _ => "ROSTER".to_string(),
            },
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
                // a channel flag has no target: emitting a trailing space
                // would make the canonical form differ from itself
                "MODE {channel} {sign}{flag}{tail}",
                sign = if *on { '+' } else { '-' },
                tail = if target.is_empty() {
                    String::new()
                } else {
                    format!(" {target}")
                }
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
            Command::Auth("agent_1.123.1f.abcd".into()),
            Command::Cap,
            Command::Topic {
                channel: "#swarm".into(),
                topic: Some("migration in progress".into()),
            },
            Command::List,
            Command::Who(Some("@pool:coder".into())),
            Command::Drain,
            Command::Roster {
                op: RosterOp::Add,
                target: Some("#swarm".into()),
            },
            Command::Status {
                agent: "ag_1".into(),
                state: PresenceState::Away,
                vram_free_mb: 0,
                active_tasks: 0,
                status_text: Some("rebuilding index".into()),
            },
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
            ("MODE #c +x ag", "unsupported flag"),
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
