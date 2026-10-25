//! Channel routing: the IRC half of AIPP.
//!
//! Agents do not need a central HTTP router or a hand-maintained service
//! graph: they bind to ephemeral `#channels` and broadcast. A channel is
//! a collision space with a membership set and two flags — `+o` (operator:
//! may kick and re-mode) and `+v` (voice: may speak in a moderated
//! channel).
//!
//! The registry is pure data with no IO so the broker can hold it behind
//! one mutex and the tests can drive any scenario without sockets.

use std::collections::BTreeMap;

/// Membership flags for one agent inside one channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub op: bool,
    pub voice: bool,
}

impl Flags {
    /// IRC-style prefix for `NAMES`: `@` op, `+` voice, empty for a
    /// plain member.
    pub fn prefix(&self) -> &'static str {
        if self.op {
            "@"
        } else if self.voice {
            "+"
        } else {
            ""
        }
    }
}

/// One channel and its members, ordered deterministically so `NAMES`
/// output is stable (an agent fleet diffing two listings should see
/// identity, not hash order).
#[derive(Debug, Clone)]
pub struct Channel {
    pub name: String,
    pub members: BTreeMap<String, Flags>,
    /// `+m`: only operators and voiced members may speak
    pub moderated: bool,
    /// `+i`: only invited agents may join
    pub invite_only: bool,
    /// `+t`: only operators may change the topic
    pub topic_locked: bool,
    pub topic: Option<String>,
    pub invites: std::collections::BTreeSet<String>,
    pub bans: std::collections::BTreeSet<String>,
}

impl Channel {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            members: BTreeMap::new(),
            moderated: false,
            invite_only: false,
            topic_locked: true,
            topic: None,
            invites: Default::default(),
            bans: Default::default(),
        }
    }

    /// The `NAMES` payload: `@supervisor, builder, +qa`.
    ///
    /// IRC convention, and the useful one for an operator reading the
    /// line: operators first, then voiced members, then everyone else,
    /// alphabetical inside each group.
    pub fn names(&self) -> String {
        let mut members: Vec<(&String, &Flags)> = self.members.iter().collect();
        members.sort_by(|a, b| {
            let rank = |f: &Flags| {
                if f.op {
                    0
                } else if f.voice {
                    1
                } else {
                    2
                }
            };
            rank(a.1).cmp(&rank(b.1)).then(a.0.cmp(b.0))
        });
        members
            .iter()
            .map(|(n, f)| format!("{}{n}", f.prefix()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn is_op(&self, agent: &str) -> bool {
        self.members.get(agent).map(|f| f.op).unwrap_or(false)
    }

    /// May this agent speak here? `+m` is the rule that makes `+v` mean
    /// something; without it voice was a decoration.
    pub fn may_speak(&self, agent: &str) -> bool {
        if !self.moderated {
            return true;
        }
        self.members
            .get(agent)
            .map(|f| f.op || f.voice)
            .unwrap_or(false)
    }
}

/// All channels the broker knows about.
#[derive(Debug, Default)]
pub struct Registry {
    channels: BTreeMap<String, Channel>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Join a channel, creating it (and making the first joiner its
    /// operator) if it does not exist. Returns `true` when the agent was
    /// not already a member.
    ///
    /// First-joiner-is-operator is the ChanServ rule reduced to its
    /// useful core: somebody has to be able to moderate, and in an
    /// agent swarm the creator is the least surprising choice.
    pub fn join(&mut self, channel: &str, agent: &str) -> bool {
        let chan = self
            .channels
            .entry(channel.to_string())
            .or_insert_with(|| Channel::new(channel));
        if chan.members.contains_key(agent) {
            return false;
        }
        let first = chan.members.is_empty();
        // voice is GRANTED, not implied: in an unmoderated channel it
        // costs nothing, and in a moderated one (+v) it must be explicit
        chan.members.insert(
            agent.to_string(),
            Flags {
                op: first,
                voice: false,
            },
        );
        true
    }

    /// Remove an agent from one channel. Empty channels are dropped: an
    /// ephemeral collaboration space should not outlive its members.
    /// Returns `true` if the agent was a member.
    pub fn part(&mut self, channel: &str, agent: &str) -> bool {
        let Some(chan) = self.channels.get_mut(channel) else {
            return false;
        };
        let removed = chan.members.remove(agent).is_some();
        if chan.members.is_empty() {
            self.channels.remove(channel);
        }
        removed
    }

    /// Drop an agent from every channel (disconnect / TTL eviction).
    /// Returns the channels it was in, so the caller can broadcast PART.
    pub fn remove_agent(&mut self, agent: &str) -> Vec<String> {
        let mut left = Vec::new();
        for (name, chan) in self.channels.iter_mut() {
            if chan.members.remove(agent).is_some() {
                left.push(name.clone());
            }
        }
        self.channels.retain(|_, c| !c.members.is_empty());
        left
    }

    pub fn exists(&self, channel: &str) -> bool {
        self.channels.contains_key(channel)
    }

    /// Members of a channel, in stable order.
    /// Operator view: one line per channel, deterministic order.
    pub fn list(&self) -> Vec<String> {
        self.channels
            .values()
            .map(|c| {
                let flags = format!(
                    "{}{}{}",
                    if c.moderated { "m" } else { "-" },
                    if c.invite_only { "i" } else { "-" },
                    if c.topic_locked { "t" } else { "-" }
                );
                format!(
                    "CHAN {} members={} ops={} flags=+{} topic={}",
                    c.name,
                    c.members.len(),
                    c.members.values().filter(|f| f.op).count(),
                    flags,
                    c.topic.as_deref().unwrap_or("")
                )
            })
            .collect()
    }

    pub fn members(&self, channel: &str) -> Vec<String> {
        self.channels
            .get(channel)
            .map(|c| c.members.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn names(&self, channel: &str) -> Option<String> {
        self.channels.get(channel).map(|c| c.names())
    }

    pub fn is_op(&self, channel: &str, agent: &str) -> bool {
        self.channels
            .get(channel)
            .map(|c| c.is_op(agent))
            .unwrap_or(false)
    }

    /// Set a channel flag (`+m`, `+i`, `+t`). Only operators do this; the
    /// permission check lives in the broker.
    pub fn set_flag(&mut self, channel: &str, flag: char, on: bool) -> Result<(), String> {
        let Some(chan) = self.channels.get_mut(channel) else {
            return Err(format!("no such channel {channel}"));
        };
        match flag {
            'm' => chan.moderated = on,
            'i' => chan.invite_only = on,
            't' => chan.topic_locked = on,
            other => return Err(format!("unsupported channel flag '{other}' (use m, i, t)")),
        }
        Ok(())
    }

    pub fn set_topic(&mut self, channel: &str, topic: Option<String>) -> Result<(), String> {
        let Some(chan) = self.channels.get_mut(channel) else {
            return Err(format!("no such channel {channel}"));
        };
        chan.topic = topic;
        Ok(())
    }

    pub fn topic(&self, channel: &str) -> Option<String> {
        self.channels.get(channel).and_then(|c| c.topic.clone())
    }

    pub fn set_ban(&mut self, channel: &str, agent: &str, on: bool) -> Result<(), String> {
        let Some(chan) = self.channels.get_mut(channel) else {
            return Err(format!("no such channel {channel}"));
        };
        if on {
            chan.bans.insert(agent.to_string());
        } else {
            chan.bans.remove(agent);
        }
        Ok(())
    }

    pub fn is_banned(&self, channel: &str, agent: &str) -> bool {
        self.channels
            .get(channel)
            .map(|c| c.bans.contains(agent))
            .unwrap_or(false)
    }

    pub fn invite(&mut self, channel: &str, agent: &str) {
        if let Some(c) = self.channels.get_mut(channel) {
            c.invites.insert(agent.to_string());
        }
    }

    pub fn may_join(&self, channel: &str, agent: &str) -> Result<(), String> {
        let Some(chan) = self.channels.get(channel) else {
            return Ok(()); // a new channel has no rules yet
        };
        if chan.bans.contains(agent) {
            return Err(format!("{agent} is banned from {channel}"));
        }
        if chan.invite_only && !chan.invites.contains(agent) && !chan.members.contains_key(agent) {
            return Err(format!("{channel} is invite-only (+i)"));
        }
        Ok(())
    }

    pub fn may_speak(&self, channel: &str, agent: &str) -> bool {
        self.channels
            .get(channel)
            .map(|c| c.may_speak(agent))
            .unwrap_or(true)
    }

    pub fn is_moderated(&self, channel: &str) -> bool {
        self.channels
            .get(channel)
            .map(|c| c.moderated)
            .unwrap_or(false)
    }

    /// `MODE #chan +o nick`. Only existing members can be re-moded.
    pub fn set_mode(
        &mut self,
        channel: &str,
        agent: &str,
        flag: char,
        on: bool,
    ) -> Result<(), String> {
        let Some(chan) = self.channels.get_mut(channel) else {
            return Err(format!("no such channel {channel}"));
        };
        let Some(flags) = chan.members.get_mut(agent) else {
            return Err(format!("{agent} is not on {channel}"));
        };
        match flag {
            'o' => flags.op = on,
            'v' => flags.voice = on,
            other => return Err(format!("unsupported channel flag '{other}'")),
        }
        Ok(())
    }

    /// Remove an agent from a channel on someone else's authority. The
    /// permission check lives in the broker; this is the mechanism.
    pub fn kick(&mut self, channel: &str, agent: &str) -> Result<(), String> {
        if !self.part(channel, agent) {
            return Err(format!("{agent} is not on {channel}"));
        }
        Ok(())
    }

    /// Every channel name, sorted.
    pub fn channel_names(&self) -> Vec<String> {
        self.channels.keys().cloned().collect()
    }

    /// `LIST` payload: `#a(3) #b(1)`.
    pub fn listing(&self) -> String {
        self.channels
            .iter()
            .map(|(n, c)| format!("{n}({})", c.members.len()))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_joiner_becomes_operator() {
        let mut r = Registry::new();
        assert!(r.join("#swarm", "supervisor"));
        assert!(r.join("#swarm", "builder"));
        assert!(r.is_op("#swarm", "supervisor"), "creator moderates");
        assert!(!r.is_op("#swarm", "builder"));
        assert!(!r.join("#swarm", "builder"), "second join is a no-op");
    }

    #[test]
    fn names_render_irc_style_prefixes() {
        let mut r = Registry::new();
        r.join("#swarm", "supervisor");
        r.join("#swarm", "builder");
        r.join("#swarm", "qa");
        r.set_mode("#swarm", "qa", 'v', true).unwrap();
        // ops first, then voiced, then plain — each group alphabetical
        assert_eq!(r.names("#swarm").unwrap(), "@supervisor, +qa, builder");
    }

    #[test]
    fn mode_requires_membership_and_a_known_flag() {
        let mut r = Registry::new();
        r.join("#swarm", "supervisor");
        assert!(r.set_mode("#swarm", "ghost", 'o', true).is_err());
        assert!(r.set_mode("#swarm", "supervisor", 'x', true).is_err());
        assert!(r.set_mode("#nope", "supervisor", 'o', true).is_err());
        r.set_mode("#swarm", "supervisor", 'o', false).unwrap();
        assert!(!r.is_op("#swarm", "supervisor"));
    }

    #[test]
    fn part_drops_empty_channels() {
        let mut r = Registry::new();
        r.join("#ephemeral", "a");
        r.join("#persistent", "a");
        r.join("#persistent", "b");
        assert!(r.part("#ephemeral", "a"));
        assert!(!r.exists("#ephemeral"), "empty channels are ephemeral");
        assert!(r.part("#persistent", "a"));
        assert!(r.exists("#persistent"), "a member remains");
        assert!(!r.part("#persistent", "ghost"));
    }

    #[test]
    fn remove_agent_reports_every_channel_it_left() {
        let mut r = Registry::new();
        r.join("#a", "ag");
        r.join("#b", "ag");
        r.join("#b", "other");
        let left = r.remove_agent("ag");
        assert_eq!(left, vec!["#a".to_string(), "#b".to_string()]);
        assert!(!r.exists("#a"), "sole member left -> channel gone");
        assert_eq!(r.members("#b"), vec!["other".to_string()]);
        assert!(r.remove_agent("ghost").is_empty());
    }

    #[test]
    fn kick_removes_and_errors_for_a_non_member() {
        let mut r = Registry::new();
        r.join("#swarm", "op");
        r.join("#swarm", "rogue");
        r.kick("#swarm", "rogue").unwrap();
        assert_eq!(r.members("#swarm"), vec!["op".to_string()]);
        assert!(r.kick("#swarm", "rogue").is_err());
    }

    #[test]
    fn listing_is_stable_and_counted() {
        let mut r = Registry::new();
        r.join("#b", "x");
        r.join("#a", "x");
        r.join("#a", "y");
        assert_eq!(r.listing(), "#a(2) #b(1)");
    }
}
