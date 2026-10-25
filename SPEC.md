# AIPP — Agentic Internet & Presence Protocol

**Version 1.0 · normative.** This document is the contract. The Rust crate
in this repository is a reference implementation of it, not its
definition; where the two disagree, the disagreement is a bug in the
implementation.

The key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

---

## 1. Scope

AIPP is a **dual-plane** wire protocol for multi-agent systems: a
human-readable control plane for identity, presence, channels and
moderation, and a binary payload plane for structured data, multiplexed
on the same persistent connection.

It is designed to be **telnet-able**: an operator with `nc` MUST be able
to inspect a live session. It is also designed to move embeddings and
tool JSON without base64.

## 2. Transport

* AIPP runs over a reliable, ordered, byte-stream transport (TCP).
* The server listens on a configured address; it MUST accept TLS 1.3 when
  configured with a certificate and key.
* Default port: none is assigned. Deployments choose one and advertise it
  out of band.
* A peer MAY be disconnected after an idle period; the presence TTL (§7)
  is the normative mechanism, not TCP keepalive.

## 3. Framing and demultiplexing

The connection carries two kinds of item, distinguished by their first
bytes:

```
item := control-line | binary-frame
```

**Control line.** UTF-8 text terminated by `CRLF` (`0x0D 0x0A`). A bare
`LF` MUST be accepted on input (be liberal in what you accept) but MUST
NOT be emitted. A line MUST NOT exceed 8192 bytes; a longer line is a
protocol error and the connection MAY be closed.

**Binary frame.** A 12-byte header followed by a payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Magic 0x41  | Version 0x01  |        Frame Type (16)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload Length (32, big-endian)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          TLV Type (16)        |          Reserved (16)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload (Length bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* `Payload Length` is the length of the payload **only**, excluding the
  12-byte header.
* Payload length MUST NOT exceed 16 MiB (16777216). A peer that announces
  more MUST be refused without allocating.
* `Reserved` MUST be sent as zero and MUST be ignored on receipt.

**Demultiplexing rule.** A frame is present if and only if the next two
bytes are `0x41 0x01`. Otherwise the item is a control line. This rule is
normative and is why the magic cannot be a printable character.

**Announcement.** Before a binary frame, the sender MUST announce it:

```
BIN_FRAME <target> <tlv-type-hex> <payload-length>
```

The receiving broker MUST verify that the frame's TLV type and payload
length match the announcement, and MUST refuse a mismatch with `ERR 409`.
A frame with no open announcement MUST be refused with `ERR 412`.

## 4. Control-plane grammar

```
line      := command *( SP param ) *( SP ":" trailing )
command   := 1*ALPHA
```

* The command verb is case-insensitive; it MUST be transmitted uppercase.
* Parameters are separated by single spaces.
* The **trailing** parameter starts with `:` and may contain spaces and
  further colons; the leading `:` is not part of the value.
* Text that contains spaces MUST be sent as trailing.

### 4.1 Commands

| Command | Form | Meaning |
|---|---|---|
| `AUTH` | `AUTH <token>` | prove identity (§9) |
| `NICK` | `NICK <ag-id>` | claim an AG-ID (MUST match the token) |
| `USER` | `USER <class> <caps-hex>` | announce class and capabilities |
| `STATUS` | `STATUS <ag-id> <state-hex> <vram_free_mb> <active_tasks>` | publish a presence vector |
| `JOIN` / `PART` | `JOIN #chan` / `PART #chan [:reason]` | channel membership |
| `PRIVMSG` / `NOTICE` | `<VERB> <target> :<text>` | deliver text |
| `NAMES` | `NAMES #chan` | roster |
| `MODE` | `MODE #chan <+|-><flag> [target]` | channel/member mode |
| `KICK` | `KICK #chan <ag-id> [:reason]` | remove a member |
| `TOPIC` | `TOPIC #chan [:<text>]` | read or set the topic |
| `LIST` / `WHO` | `LIST` / `WHO [#chan|@pool:<class>]` | operator views |
| `CAP` | `CAP LS` | capability advertisement |
| `DRAIN` | `DRAIN` | stop accepting new work |
| `BIN_FRAME` | §3 | announce a binary frame |
| `PING` / `PONG` | `PING [:<token>]` | liveness, token echoed |
| `QUIT` | `QUIT [:<reason>]` | leave |

A target is either `#channel`, an AG-ID, or `@pool:<class>`.

### 4.2 Canonical form

Every command has exactly one canonical serialization, and parsing the
canonical form MUST yield the canonical form again (idempotence). Examples:

```
USER coder-specialist 0x0F          (capabilities always hex, 0x-prefixed)
PING keepalive        ->  PING :keepalive
MODE #c +m            ->  MODE #c +m        (no trailing space)
```

`conformance/vectors.json` is the normative test set for this.

## 5. Presence

```
state := 0x00 ONLINE | 0x01 BUSY | 0x02 HIGH_LOAD | 0x03 AWAY | 0x04 OFFLINE
```

* `ONLINE` and `BUSY` accept new work; `BUSY` signals queueing.
* `HIGH_LOAD` means an orchestrator SHOULD shed non-critical work.
* Presence is enforced **by the server**, not asserted by the agent: an
  agent that stops sending anything for the TTL is announced as gone:

```
QUIT <ag-id> :Heartbeat timeout - dropping session
```

* A `STATUS` broadcast is sent only to agents sharing a channel with the
  subject. Presence is not global by default.

## 6. Channels

* Names begin with `#`. Membership grants read and (subject to modes)
  write.
* The first joiner of a new channel is granted `+o`.
* Modes:

| Flag | Applies to | Effect |
|---|---|---|
| `+o` | member | operator: may `MODE`, `KICK`, set `TOPIC` |
| `+v` | member | may speak in a `+m` channel |
| `+m` | channel | only operators and voiced members may `PRIVMSG` |
| `+i` | channel | only invited agents may `JOIN` |
| `+t` | channel | only operators may change the topic |

* `+v` is **granted, never implied** by joining.
* `NAMES` order is normative: operators, then voiced, then plain, each
  group alphabetical; prefixes `@` and `+`.

## 7. Payload plane

TLV types are registered centrally:

| Type | Name | Payload |
|---|---|---|
| `0x0001` | TEXT_CHUNK | UTF-8 text |
| `0x0002` | JSON_TOOL | JSON object |
| `0x0003` | EMBEDDING | opaque binary (implementation-defined encoding) |
| `0x0004` | STATE_SNAPSHOT | opaque |
| `0x0005` | STORE_FORWARD | envelope for a held message |
| `0x0006` | CREDIT | flow-control grant |
| `0x0007` | FRAGMENT | continuation of a fragmented payload |

Unknown types MUST be relayed unchanged, never dropped and never guessed
at.

### 7.1 Fragmentation

A payload larger than 64 KiB SHOULD be fragmented. A fragment's payload
is:

```
bundle-id (32) | inner-type (16) | index (16) | total (16) | chunk
```

* `total` is the number of fragments; `index` is 0-based and MUST be
  `< total`.
* A receiver MUST NOT deliver a bundle until every index is present.
* Out-of-range index, `total == 0`, or a fragment shorter than the header
  is a protocol error for that bundle; the bundle is discarded.

### 7.2 Store-and-forward

A direct message addressed to an agent that is not connected SHOULD be
held (implementation-defined limits and TTL) and delivered at
registration, preceded by:

```
STORED_INBOX <ag-id> <count>
```

The sender is told the message was held, not delivered:

```
STORED <target> <queued>
```

## 8. Numerics

Errors are `<numeric> <human text>`. The numeric set is normative in
kind, not in numbering:

| Numeric | Meaning |
|---|---|
| 401 | no such agent / no live agent in pool |
| 403 | no such channel |
| 404 | not voiced in a `+m` channel |
| 409 | frame does not match its announcement |
| 412 | binary frame without an announcement |
| 421 | unknown command, or syntax error naming the problem |
| 439 | rate limited |
| 451 | not registered (NICK first) |
| 464 | authentication required / token invalid / expired |
| 482 | not an operator / capability missing |
| 509 | peer is not draining (backpressure) |

A refusal MUST name what was wrong with the input. `ERR 421 :unknown
command 'AGENT_STEP'` is conformant; `ERR 421 :bad command` is not.

## 9. Identity

* `AUTH <token>` MUST precede `NICK` when the server requires
  authentication.
* Token form: `<ag-id>.<expires-ms>.<caps-hex>.<signature>`, where the
  signature is HMAC-SHA256 over `aipp1|<ag-id>|<caps>|<expires-ms>` with
  a key shared out of band.
* The AG-ID used in `NICK` MUST equal the token's; a mismatch MUST be
  refused with `464`.
* The capability mask announced in `USER` MUST be intersected with the
  token's. Announcing a capability is not being granted one.
* Expiry is mandatory: a token without a usable expiry MUST be refused.

Capability bits: `SPEAK 0x01`, `MODERATE 0x02`, `KICK 0x04`,
`INSPECT 0x08`, `PAYLOAD 0x10`.

## 10. Flow control

* A server MUST NOT block on a peer that is not reading. A bounded
  outbound queue per connection plus a refusal (`509`) is the required
  behaviour.
* A sender MUST honour `509` as "retry later", not as "message accepted".

## 11. Extensibility

`CAP LS` advertises the extensions in use, one line:

```
CAP LS :aipp=1.0 AUTH FRAGMENT CREDIT POOL TOPIC MODES=mitb DRAIN TLVS=... CAPS=...
```

A client that does not understand an advertised token MUST ignore it.
New commands MUST NOT break an existing client: an unknown command is
answered with `421` and the session continues.

## 12. Conformance

An implementation is AIPP 1.0 conformant if it passes
`conformance/vectors.json` as replayed by
`aipp-core/tests/conformance.rs`:

1. every canonical line parses to itself, and is idempotent;
2. every invalid line is refused with a reason containing the stated text;
3. every frame vector decodes to the same payload with the stated length;
4. a truncated frame is reported incomplete, never corrupt.

The reference implementation additionally passes 40k hostile-input
mutations (no panic, no over-allocation) and three end-to-end
experiments (dual plane, hardening, TLS).

## 13. Deliberately out of scope

* Federation between brokers (design sketched, not specified here).
* Broker authentication (peer brokers are trusted by address today).
* Payload schema registry beyond the TLV type table.
* Compression.
