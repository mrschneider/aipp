# AIPP — Agentic Internet & Presence Protocol

**IRC's channels for routing. ICQ's presence for scheduling. One socket for both.**

AIPP is a dual-plane wire protocol for multi-agent systems. It takes the
two ideas that actually survived thirty years of network programming and
puts them on one persistent connection:

| Plane | Model | Carries | Why |
|---|---|---|---|
| **Control** | IRC | `JOIN`, `PRIVMSG`, `STATUS`, `MODE`, `KICK` — CRLF ASCII | `telnet` and `grep` are real debugging tools for an agent fleet |
| **Payload** | ICQ / OSCAR | binary TLV frames: JSON tool calls, embeddings, checkpoints | 16 KiB of float32 must not become 40 KiB of decimal digits |

```
+------------------------------------------------------+
|                 AIPP connection                      |
+---------------------------+--------------------------+
|  Control plane (text)     |  Payload plane (binary)  |
|  JOIN #secops             |  TLV 0x0002 (JSON tool)  |
|  STATUS agent_7 0x01 ...  |  TLV 0x0003 (embedding)  |
+---------------------------+--------------------------+
```

## Why the two halves belong together

An orchestrator needs two different questions answered, and neither model
answers both:

* **Where does this task go?** IRC channels give ephemeral collaboration
  spaces with no service-discovery graph to keep in sync — an agent joins
  `#swarm-backend` and the swarm knows where it is.
* **Can this agent take it right now?** ICQ presence gives a state vector
  per node (`ONLINE`, `BUSY`, `HIGH_LOAD`, `AWAY`, `OFFLINE`) plus the VRAM
  and in-flight task counts, so a scheduler sheds load instead of firing
  work into a black hole.

Presence without routing is a status page. Routing without presence drops
tasks silently. Together they are a dispatch substrate.

## Quickstart

```bash
cargo build --release
./target/release/aipp-broker --host 0.0.0.0 --port 6669 --ttl-ms 15000

# in another terminal — the control plane is telnet-compatible on purpose
telnet 127.0.0.1 6669
NICK my_agent
USER coder-specialist 0x0F
STATUS my_agent 0x01 32768 2
JOIN #swarm
PRIVMSG #swarm :hello from telnet
```

Opening the port on a host with ufw:

```bash
sudo ufw allow 6669/tcp        # or: sudo ufw allow from 192.168.0.0/24 to any port 6669
```

## Control plane

Every line is `COMMAND [args] [ :trailing text]`, CRLF-terminated.

| Command | Meaning |
|---|---|
| `NICK <agent_id>` | bind the session to an immutable AG-ID |
| `USER <class> <caps>` | agent class + capability bitmask |
| `STATUS <id> <state_hex> <vram_mb> <tasks>` | publish the presence vector |
| `JOIN #chan` / `PART #chan [:reason]` | bind / leave a collaboration space |
| `NAMES #chan` | who is here right now |
| `PRIVMSG <#chan\|nick> :text` | message; members receive `:<sender> PRIVMSG ...` |
| `NOTICE <#chan\|nick> :text` | system voice, never a reply |
| `MODE #chan +o\|-o\|+v\|-v <nick>` | operator (`+o`) and voice (`+v`) flags |
| `KICK #chan <nick> [:reason]` | operator-only removal |
| `BIN_FRAME <target> <tlv_hex> <len>` | announce the next item is a binary frame |
| `PING [:token]` / `PONG` | heartbeat; any command refreshes the lease |
| `QUIT [:reason]` | graceful disconnect |

Presence states: `0x00 ONLINE`, `0x01 BUSY` (queues work), `0x02 HIGH_LOAD`
(shed non-critical), `0x03 AWAY`, `0x04 OFFLINE`.

The broker owns the clock: an agent that stops talking for `--ttl-ms` is
evicted and every peer receives

```text
QUIT ag_alpha_09 :Heartbeat timeout - dropping session
```

A node wedged in a GC pause cannot renew its own lease — that is the point.

## Payload plane

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Magic (0x41) | Version (0x01)|         Frame Type (u16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (u32)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      TLV Type (u16)           |        Reserved (u16)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload (N bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| TLV | Meaning |
|---|---|
| `0x0001` | UTF-8 text token chunk (streamed LLM output) |
| `0x0002` | structured JSON tool-execution payload (MCP / function call) |
| `0x0003` | vector embedding, little-endian `f32[]` |
| `0x0004` | state snapshot / memory checkpoint blob |
| `0x0005` | store-and-forward envelope for an offline agent |

**Demultiplexing rule:** an item is a binary frame **iff its first two
bytes are `0x41 0x01`**; anything else is a control line. Printable text
can never start with `0x41 0x01`, so the rule survives a frame split
across TCP segments — and `telnet` keeps working.

A frame must follow its `BIN_FRAME` announcement and match it; a
mismatched type or length is refused with `ERR 409` instead of being
routed. The sender gets `BIN_ACK <target> <bytes>`.

## Verified results

`python3 experiments/experiment_001_dual_plane.py` (real broker over TCP,
four real agent sockets, run end to end):

```
PASS: identification: NICK/USER answered with ACK 001
PASS: presence: STATUS is acknowledged with STATS_OK
PASS: channel: JOIN is confirmed with JOINED
PASS: channel: NAMES lists the whole membership
PASS: channel: the first joiner holds operator status (@)
PASS: presence: peers receive the STATUS broadcast
PASS: routing: PRIVMSG reaches every other member
PASS: routing: the sender does not receive their own PRIVMSG
PASS: payload plane: a TLV 0x0002 frame reaches peers byte-identical
PASS: payload plane: the sender gets BIN_ACK with the byte count
PASS: payload plane: a frame that disagrees with its announcement is refused
PASS: privileges: a non-operator MODE is refused with ERR 482
PASS: privileges: the operator grants +v and the channel sees it
PASS: privileges: KICK removes the member and notifies them
PASS: privileges: the kicked agent is gone from NAMES
PASS: lifecycle: a silent agent is evicted after the TTL and peers see QUIT
PASS: lifecycle: the evicted agent left every channel
PASS: observability: the JSONL log records the whole session

18 passed, 0 failed
EXPERIMENT_001: PASS
```

Unit tests: `cargo test --workspace` → **23 passed** (control-line parsing
incl. the spec's own trace, presence TTL semantics, channel/flag rules,
TLV header layout, partial-frame handling, hostile-length refusal).

## Layout

```
aipp-core/      library: control vocabulary, presence engine, channel
                registry, TLV codec — pure data, no IO
aipp-broker/    the edge broker: TCP listener, routing, TTL sweeper,
                JSONL audit log
experiments/    runnable end-to-end proof
```

## Deliberately not implemented (v0.1)

Honest scope, so nothing here is mistaken for "done":

* **Federation between brokers** — one broker is one island. Cross-broker
  channel linking is future work.
* **QUIC transport** — the framing is transport-agnostic, but only TCP is
  implemented and tested.
* **Authentication** — `NICK`/`USER` identify, they do not authenticate.
  Any agent can claim any id; run it behind mTLS or WireGuard.
* **Moderated channels (`+m`)** — `+v` exists and is reported, but a
  moderated mode that actually gates speech is not enforced yet.
* **Store-and-forward** — TLV `0x0005` is reserved and documented; the
  broker does not queue frames for offline agents.
* **Backpressure** — writes to a slow peer block that peer's sender
  thread; there is no per-connection output queue or flow control yet.

## License

Apache-2.0.
