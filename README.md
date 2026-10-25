# AIPP — Agentic Internet & Presence Protocol

**A high-performance, dual-plane wire protocol for multi-agent systems.**

AIPP synthesizes IRC's decentralized pub/sub channel routing with ICQ's
stateful, presence-driven framing: a human-readable control plane an
operator can inspect with `nc`, and a binary TLV payload plane for
embeddings and tool JSON on the same persistent connection.

> **The normative document is [SPEC.md](SPEC.md).** This README describes
> the reference implementation; where the two disagree, the spec wins and
> the code is wrong. A Rust crate is a reference implementation, not a
> definition.

**Why not REST or gRPC for everything?** Because agents are long-lived
stateful nodes, not request handlers. An agent has a presence vector, a
heartbeat TTL the *server* enforces, and membership in ephemeral
collaboration spaces. You cannot express "this agent is BUSY, shed
non-critical load" in a request/response API without inventing a second
protocol — which is exactly what AIPP is.

---

## What is implemented

Every claim below is proved by a runnable experiment or a byte-level
vector in this repository. Nothing is claimed without its test.

### Dual-plane framing
* Control plane: UTF-8 lines, CRLF-terminated, telnet-able by design.
* Payload plane: 12-byte TLV frames (magic `0x41`, version `0x01`,
  frame type, length, TLV type, reserved) multiplexed on the same socket.
* Demultiplexing is by magic bytes; frames MUST be announced with
  `BIN_FRAME <target> <tlv> <len>` and a mismatch is refused (`ERR 409`),
  an unannounced frame refused (`ERR 412`).

### Presence engine (the ICQ half)
* Six states — `ONLINE 0x00`, `BUSY 0x01`, `HIGH_LOAD 0x02`,
  `AWAY 0x03`, `OFFLINE 0x04`, `DND 0x05` — carried with `vram_free_mb`
  and `active_tasks`.
* **`DND` is its own state**: not even critical work — stronger than
  `HIGH_LOAD`, which still accepts what matters. A `DND` agent is
  skipped by pool dispatch.
* **The away message rides the state**: `STATUS ag_1 0x05 0 0 :rebuilding
  the index` — the *why* behind the state, broadcast with the vector, so
  an orchestrator reads the reason instead of guessing.
* **Presence TTL is enforced by the broker**: an agent that stops
  responding is announced gone — `QUIT <ag-id> :Heartbeat timeout` — a
  wedged agent cannot lie by staying quiet.
* **Presence-aware dispatch**: `PRIVMSG @pool:<class>` picks a member of
  that class that accepts tasks and is not draining, lowest
  `active_tasks` first.
* **`DRAIN`**: an agent leaves dispatch, moves to `AWAY`, finishes what
  it has. A draining agent receives no new pool work.
* **Backpressure as protocol**: a peer that is not reading gets
  `ERR 509` instead of parking the broker. The broker never blocks on a
  slow peer: every connection has a bounded `Outbox` with its own writer
  thread.

### The social layer (ICQ's other lesson)
* **Server-side roster** — `ROSTER ADD/DEL/LIST`, persisted in the state
  file, inherited at registration: an agent that comes back online gets
  its social context back instead of rebuilding it by naming convention.
  A roster subscriber receives the watched agent's presence *without
  sharing a channel* — that is what "following" means — and a
  subscription to an agent on another broker is registered on the broker
  that hosts it.
* **Privacy lists** — `IGNORE` always wins: an ignored sender is refused
  with `ERR 486`, named, and stops receiving the agent's presence
  broadcasts. A non-empty `PERMIT` list is allow-list mode: a sender not
  on it is refused with `ERR 487`. Both persist.
* **Typing events** — `TYPING <target>` is relayed like a message, so a
  producer announces the stream before the tokens arrive.
* **Directory search** — `FIND <query>` matches agents by ag-id, class
  and status text (case-insensitive substring), floods across the
  federation like a relay, and the matches come back along the reverse
  path as `FOUND <ag-id> <class> <state> :<status text>`. The whitepages,
  for agents.

### Channels (the IRC half)
* `JOIN`/`PART`/`NAMES`/`PRIVMSG`/`NOTICE`, first joiner is `+o`.
* Modes that mean something: `+m` (only ops and voiced may speak — this
  is what gives `+v` its meaning), `+i` (invite-only), `+t`
  (topic-locked), bans, invites.
* `TOPIC`, `LIST`, `WHO` (per channel, per pool, or the whole mesh) as
  operator views, gated by the `INSPECT` capability.
* `CAP LS` advertises extensions so old clients keep working.

### Payload plane
* TLV registry: `TEXT_CHUNK`, `JSON_TOOL`, `EMBEDDING`,
  `STATE_SNAPSHOT`, `STORE_FORWARD`, `CREDIT`, `FRAGMENT`. Unknown types
  are relayed unchanged.
* **Fragmentation both ways**: an oversized frame is split, with the
  original TLV type carried inside the bundle; a receiver never delivers
  half a message (`FRAG_ACK :partial` / `:complete`).
* `CreditWindow` for producers of token streams.
* **Store-and-forward**: a direct message to an unreachable agent is
  held (256 per agent, 15 min TTL, expiry journaled) and delivered at
  registration behind `STORED_INBOX <n>`. The sender was told `STORED`,
  never "delivered".

### Identity and abuse resistance
* `AUTH <token>` before `NICK`: `<ag-id>.<expires-ms>.<caps-hex>.<hmac>`.
  The **AG-ID comes from the token, not from the claim** — a renamed or
  re-checked token fails, expiry is mandatory, comparison is
  constant-time.
* The `USER` capability mask is **intersected** with the token's:
  announcing a capability is not being granted one.
  `SPEAK 0x01 MODERATE 0x02 KICK 0x04 INSPECT 0x08 PAYLOAD 0x10`.
* Rate limiting per connection (commands/s and bytes/s, sliding window);
  a refusal does not consume budget.
* An append-only audit log with a **hash chain**: an edited line cannot
  keep its hash.

### Federation
Brokers link and agents reach each other across links (`--peer`,
`--id`):

* The link speaks AIPP itself with link-only commands
  (`FEDERATE`/`FEDERATED`, `RELAY`, `RELAY_ACK`, `FIND_RELAY`,
  `FOUND_RELAY`, `ROSTER_SUB`, `PRESENCE_RELAY`) intercepted **before**
  the agent grammar, so an agent cannot forge them.
* **Delivery acknowledgement**: a broker that accepts a relay — delivers
  it or holds it — answers `RELAY_ACK <msg-id>` along the reverse path
  it was received on; intermediates forward the ack the same way; when
  it reaches the origin the local sender is told `DELIVERED <msg-id>`.
  Relayed messages are therefore **at-least-once** (dedup by `msg-id`
  makes replays safe). A relay that dies at a dead end is never
  acknowledged — the honest signal of loss, not a fake delivery.
* Flooding deduped by message id and bounded by 8 hops; a relay that
  arrives at its origin is dropped — A↔B↔C cannot loop.
* The origin is first told `RELAYED <msg-id> <target> <links>` —
  "entered the mesh", not "delivered".
* A target known-but-unreachable on the receiving broker is held by that
  broker's store-and-forward — federation and the backlog compose.
* Channel fan-out stays local in v1.0: a relayed channel message is
  dropped rather than half-delivered.
* Link peers are trusted by address; there is no broker authentication.

### Security: TLS on both planes
* `--tls-cert/--tls-key`: TLS 1.3 carrying **text lines and binary
  frames** on the same encrypted socket.
* A plaintext client gets no service — no downgrade.
* Because a TLS session is stateful and cannot be cloned for a separate
  writer thread, the reader and the `Outbox` writer share one connection
  behind a mutex and the reader uses a 100 ms read timeout to release
  it — which is also what bounds a slowloris.

### Operations
* `--state <path>`: channel snapshot **and per-agent rosters and privacy
  lists** written atomically on every mutation and reloaded at boot.
  **Members are deliberately not persisted** — a restart must not
  resurrect agents that are not connected.
* JSONL journal of every decision, hash-chained.
* GitHub Actions: CI runs fmt, clippy `-D warnings`, all 44 tests and
  the five end-to-end experiments on real sockets; the release workflow
  re-runs the whole gate before packaging `aipp-broker` for
  x86_64 (gnu and musl) with sha256 sums. Dependabot keeps actions and
  Rust deps current (coordinated bumps when two crates must move
  together).

## Conformance

`conformance/vectors.json` is the byte-level test set any implementation
can replay, and `aipp-core/tests/conformance.rs` replays it:

1. 21 canonical lines, each idempotent (the canonical form re-parses to
   itself);
2. 13 refusals, each with the reason text it must carry;
3. 3 frame encodings, lengths normative;
4. a truncated frame is reported incomplete, never corrupt.

Plus a 40k-case hostile-input stress test: the line parser and frame
decoder always return, never panic, never over-allocate, and an
announced 4 GiB payload is refused without allocation.

## Verified results

**`cargo test --workspace` → 44 tests** (unit + conformance + hostile
input), `clippy -D warnings` and `cargo fmt --check` clean. CI is green
on `main`.

**`experiments/experiment_001_dual_plane.py` → 18/18 PASS** — four real
agents on a real broker: identification, presence broadcast, channel
routing, binary multiplexing with the payload intact, operator
privileges (`ERR 482` for a non-op), TTL eviction, and the hash-chained
journal recording the session.

**`experiments/experiment_002_hardening.py` → 18/18 PASS** — AUTH
enforced, a token for `worker_1` cannot claim `supervisor_agent`, a
renamed token fails the signature, `@pool:coder` dispatches by presence,
`DRAIN` removes an agent from dispatch, `+m` refuses an unvoiced member
and `+v` lets it speak, TOPIC/LIST/WHO work and `LIST` without
`INSPECT` is refused, a burst is rate-limited (`ERR 439`), and ~1 MB
pushed at a peer that never reads a byte does not freeze the broker.

**`experiments/experiment_003_tls.py` → 6/6 PASS** — TLS 1.3
(`TLS_AES_256_GCM_SHA384`), the control plane over TLS, a TLV frame
accepted with the right length over the encrypted connection, the text
stream undisturbed after binary traffic, and no downgrade for a
plaintext client.

**`experiments/experiment_004_federation.py` → 8/8 PASS** — three
brokers in a chain (C → A → B, no direct C–B link): a message crosses
the link with the sender attributed, the reply crosses back with no
route table, a two-hop message reaches the far broker, flooding neither
duplicates nor loops, the origin is told the message entered the mesh
(with the id it is later acknowledged against), an unknown target
everywhere is relayed — and its loss is asserted, not hidden — and a
dropped relay is not resurrected at registration.

**`experiments/experiment_005_icq.py` → 11/11 PASS** — the away message
rides the presence broadcast, DND is its own state and is skipped by
pool dispatch, the roster survives a broker restart, an ignored sender
is refused and named, a sender outside the permit list is refused, a
permitted sender is delivered, the typing event is relayed, the origin
learns the delivery id and the `DELIVERED` ack across two hops, a
directory search crosses brokers, and the link handshake answers once
(no echo loop).

## Layout

```
aipp-core/      the contract, no IO: control grammar (canonical forms),
                presence, channels, TLV codec + fragmentation, flow
                control (Outbox, CreditWindow), identity (AUTH, caps,
                rate limit, audit chain)
aipp-broker/    the edge broker: registration, presence TTL, channels,
                dual-plane multiplexing, pools, drain, roster, privacy
                lists, store-and-forward, persistence, TLS, federation
                (relay, acks, directory)
conformance/    byte-level vectors (normative)
experiments/    5 end-to-end proofs, Python peers on purpose: the point
                is cross-runtime interop
SPEC.md         the normative document
```

## Quickstart

```bash
cargo build --release

# broker, open mode (debugging)
./target/release/aipp-broker --port 7911 --ttl-ms 15000

# broker, authenticated, with persistent channels/rosters/privacy lists
./target/release/aipp-broker --port 7912 --auth-key <shared-secret> --state aipp.json

# broker with TLS
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
        -days 1 -subj /CN=localhost
./target/release/aipp-broker --port 7913 --tls-cert cert.pem --tls-key key.pem

# a federation hub with two spokes
./target/release/aipp-broker --port 7914 --id hub
./target/release/aipp-broker --port 7915 --id spoke-1 --peer 127.0.0.1:7914

# then, from a shell, an agent is just:
#   printf 'NICK ag_1\r\nUSER coder 0x1f\r\nSTATUS ag_1 0x00 0 0 :ready\r\n' | nc localhost 7911
```

## Deliberately not implemented

Stated, not implied:

* **Delivery guarantees across the whole mesh** — the ack upgrade makes
  relayed messages at-least-once, but a dead end still loses the message
  silently at the origin's edge; end-to-end acks from the *agent* (not
  the broker) are the next step and are not written.
* **Channel fan-out across brokers** — `#channels` are local in v1.0.
* **Broker authentication** — link peers are trusted by address.
* **Transfer of large artifacts (P2P/file transfer)** — the ICQ direct
  connection with chunked, resumable transfer is designed, not written;
  `FIND` and the relay are its prerequisites and both exist.
* **Configurable per-frame read deadlines** — the reader uses a fixed
  100 ms timeout today.
* **Outbound compression** — the TLV space has room for it; nothing is
  claimed until it is measured.
* **cargo-fuzz targets** — the hostile-input stress test is a
  deterministic generator, not libFuzzer.

## Version history

| Version | What landed |
|---|---|
| **v0.5.0** | the ICQ feature set: delivery acks across the mesh (at-least-once), DND + away message, server-side roster, privacy lists (permit/ignore), typing events, federated directory search |
| v0.4.0 | store-and-forward, channel persistence, TLS on both planes, federation |
| v0.3.0 | identity (AUTH + capabilities), backpressure (Outbox), presence-aware dispatch (`@pool`, `DRAIN`), full channel modes, TLV fragmentation, rate limiting, audit chain |
| v0.2.0 | dual-plane E2E proof, broker, presence TTL, JSONL journal |
| v0.1.0 | core: control grammar, presence, channels, TLV codec |

## License

Apache-2.0.
