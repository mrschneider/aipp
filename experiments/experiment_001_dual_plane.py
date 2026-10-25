#!/usr/bin/env python3
"""AIPP experiment 001 — the dual plane, end to end.

Drives a real broker over TCP with four real agent sockets and asserts
every guarantee the spec makes:

  1. identification        NICK/USER -> ACK 001
  2. presence broadcast    STATUS 0x00/0x01 ... -> STATS_OK + peer view
  3. channel routing       JOIN -> JOINED + NAMES, PRIVMSG fans out
  4. binary multiplexing   BIN_FRAME announce + TLV frame reaches peers
                           with the payload intact, sender gets BIN_ACK
  5. operator privileges   non-op MODE -> ERR 482; op MODE/KICK work
  6. presence lifecycle    a silent agent is evicted after the TTL and
                           every peer sees QUIT ... :Heartbeat timeout

Prints PASS/FAIL per assertion and exits non-zero on any failure.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HOST = "127.0.0.1"
PORT = int(os.environ.get("AIPP_PORT", "6670"))
TTL_MS = 2000
MAGIC = b"\x41\x01"

PASSED = []
FAILED = []


def check(label, cond, detail=""):
    if cond:
        PASSED.append(label)
        print(f"PASS: {label}")
    else:
        FAILED.append(label)
        print(f"FAIL: {label}" + (f" | {detail}" if detail else ""))


class Client:
    """Minimal AIPP client: control lines + binary TLV frames."""

    def __init__(self, name, cls="coder-specialist", caps="0x0F"):
        self.name = name
        self.sock = socket.create_connection((HOST, PORT), timeout=5)
        self.buf = bytearray()
        self.lines = []
        self.frames = []
        self.lock = threading.Lock()
        self.alive = True
        self.heartbeat = True
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._pinger, daemon=True).start()
        self.send(f"NICK {name}")
        self.send(f"USER {cls} {caps}")

    def _pinger(self):
        while self.alive:
            if self.heartbeat:
                try:
                    self.sock.sendall(b"PING :hb\r\n")
                except OSError:
                    return
            time.sleep(0.4)

    def _reader(self):
        while self.alive:
            try:
                data = self.sock.recv(65536)
            except OSError:
                return
            if not data:
                return
            with self.lock:
                self.buf.extend(data)
                self._drain()

    def _drain(self):
        while True:
            if self.buf[:2] == MAGIC:
                if len(self.buf) < 12:
                    return
                length = int.from_bytes(self.buf[4:8], "big")
                if len(self.buf) < 12 + length:
                    return
                tlv = int.from_bytes(self.buf[8:10], "big")
                payload = bytes(self.buf[12:12 + length])
                self.frames.append((tlv, payload))
                del self.buf[:12 + length]
            else:
                idx = self.buf.find(b"\r\n")
                if idx < 0:
                    return
                line = bytes(self.buf[:idx]).decode("utf-8", "replace")
                del self.buf[:idx + 2]
                self.lines.append(line)

    def send(self, line):
        self.sock.sendall(line.encode() + b"\r\n")

    def send_frame(self, tlv, payload):
        header = struct.pack(">HIHH", 0x0001, len(payload), tlv, 0)
        self.sock.sendall(MAGIC + header + payload)

    def wait_line(self, pred, timeout=4.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                for ln in self.lines:
                    if pred(ln):
                        return ln
            time.sleep(0.02)
        return None

    def wait_frame(self, timeout=4.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if self.frames:
                    return self.frames[0]
            time.sleep(0.02)
        return None

    def has_line(self, needle, timeout=2.0):
        return self.wait_line(lambda ln: needle in ln, timeout) is not None

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    log_path = os.path.join(tempfile.mkdtemp(prefix="aipp_exp_"), "broker.jsonl")
    broker = subprocess.Popen(
        [
            "./target/debug/aipp-broker",
            "--host", HOST,
            "--port", str(PORT),
            "--ttl-ms", str(TTL_MS),
            "--log", log_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.6)
    if broker.poll() is not None:
        err = broker.stderr.read().decode()
        print("FAIL: broker did not start |", err)
        return 1

    clients = []
    try:
        # ---- 1. identification -------------------------------------------
        supervisor = Client("supervisor_agent", "supervisor", "0x0F")
        builder = Client("builder_agent", "coder-specialist", "0x0F")
        qa = Client("qa_agent", "qa", "0x03")
        rogue = Client("rogue_agent", "coder-specialist", "0x00")
        clients = [supervisor, builder, qa, rogue]

        check(
            "identification: NICK/USER answered with ACK 001",
            supervisor.wait_line(lambda l: l.startswith("ACK 001")) is not None,
        )

        # ---- 2. presence --------------------------------------------------
        builder.send(f"STATUS {builder.name} 0x01 32768 2")
        check(
            "presence: STATUS is acknowledged with STATS_OK",
            builder.wait_line(lambda l: l.startswith("STATS_OK builder_agent")) is not None,
        )

        # ---- 3. channels ---------------------------------------------------
        # Join one at a time and wait for each JOINED: "the first joiner
        # holds operator status" is only a meaningful claim when the order
        # is actually defined (writes are queued by the broker's Outbox).
        for c in (supervisor, builder, qa, rogue):
            c.send("JOIN #swarm-backend")
            c.wait_line(lambda l: l.startswith("JOINED #swarm-backend"))
        joined = supervisor.wait_line(lambda l: l.startswith("JOINED #swarm-backend"))
        # The JOIN reply lists the roster at THAT instant, so poll NAMES
        # until every agent is in: this is also the operator's own tool
        # for "who is here right now".
        want = ("supervisor_agent", "builder_agent", "qa_agent", "rogue_agent")
        names = None
        deadline = time.time() + 5
        while time.time() < deadline and names is None:
            supervisor.send("NAMES #swarm-backend")
            names = supervisor.wait_line(
                lambda l: l.startswith("NAMES #swarm-backend") and all(n in l for n in want), 0.7
            )
        check("channel: JOIN is confirmed with JOINED", joined is not None, str(joined))
        check(
            "channel: NAMES lists the whole membership",
            names is not None
            and all(n in names for n in ("supervisor_agent", "builder_agent", "qa_agent", "rogue_agent")),
            str(names),
        )
        check(
            "channel: the first joiner holds operator status (@)",
            names is not None and "@supervisor_agent" in names,
            str(names),
        )

        # presence is visible to peers once they share a channel
        builder.send(f"STATUS {builder.name} 0x01 32768 2")
        seen = supervisor.wait_line(lambda l: l.startswith("STATUS builder_agent 0x01"), 3.0)
        check("presence: peers receive the STATUS broadcast", seen is not None, str(seen))

        # ---- 4. text broadcast --------------------------------------------
        msg = "Generated migration script for PostgreSQL schema."
        builder.send(f"PRIVMSG #swarm-backend :{msg}")
        got_sup = supervisor.has_line(f":builder_agent PRIVMSG #swarm-backend :{msg}")
        got_qa = qa.has_line(f":builder_agent PRIVMSG #swarm-backend :{msg}")
        check("routing: PRIVMSG reaches every other member", got_sup and got_qa,
              f"supervisor={got_sup} qa={got_qa}")
        check(
            "routing: the sender does not receive their own PRIVMSG",
            not builder.has_line("PRIVMSG #swarm-backend :" + msg, 0.6),
        )

        # ---- 5. binary TLV multiplexing ------------------------------------
        tool_json = json.dumps(
            {"tool": "apply_migration", "args": {"schema": "public", "rev": 42}}
        ).encode()
        builder.send(f"BIN_FRAME #swarm-backend 0x0002 {len(tool_json)}")
        builder.send_frame(0x0002, tool_json)
        frame = supervisor.wait_frame(4.0)
        check(
            "payload plane: a TLV 0x0002 frame reaches peers byte-identical",
            frame is not None and frame[0] == 0x0002 and frame[1] == tool_json,
            str(frame)[:120] if frame else "no frame",
        )
        check(
            "payload plane: the sender gets BIN_ACK with the byte count",
            builder.wait_line(lambda l: l.startswith(f"BIN_ACK #swarm-backend {len(tool_json)}"))
            is not None,
        )

        # a frame that does not match its announcement must be refused,
        # never routed: announce 32 bytes, send 16
        rogue.send("BIN_FRAME #swarm-backend 0x0003 32")
        rogue.send_frame(0x0003, b"\x00" * 16)
        check(
            "payload plane: a frame that disagrees with its announcement is refused",
            rogue.wait_line(lambda l: l.startswith("ERR 409")) is not None,
        )

        # ---- 6. operator privileges ----------------------------------------
        rogue.send("MODE #swarm-backend +o rogue_agent")
        check(
            "privileges: a non-operator MODE is refused with ERR 482",
            rogue.wait_line(lambda l: l.startswith("ERR 482")) is not None,
        )
        supervisor.send("MODE #swarm-backend +v qa_agent")
        check(
            "privileges: the operator grants +v and the channel sees it",
            qa.has_line(":supervisor_agent MODE #swarm-backend +v qa_agent"),
        )
        supervisor.send("KICK #swarm-backend rogue_agent :Infinite loop detected")
        check(
            "privileges: KICK removes the member and notifies them",
            rogue.has_line(":supervisor_agent KICK #swarm-backend rogue_agent :Infinite loop detected"),
        )
        supervisor.send("NAMES #swarm-backend")
        listing = supervisor.wait_line(lambda l: l.startswith("NAMES #swarm-backend"), 2.0)
        check(
            "privileges: the kicked agent is gone from NAMES",
            listing is not None and "rogue_agent" not in listing,
            str(listing),
        )

        # ---- 7. presence lifecycle (TTL) ------------------------------------
        qa.heartbeat = False  # stop renewing the lease
        evicted = supervisor.wait_line(
            lambda l: l.startswith("QUIT qa_agent :Heartbeat timeout"), TTL_MS / 1000 + 3
        )
        check(
            "lifecycle: a silent agent is evicted after the TTL and peers see QUIT",
            evicted is not None,
            str(evicted),
        )
        supervisor.send("NAMES #swarm-backend")
        listing = supervisor.wait_line(lambda l: l.startswith("NAMES #swarm-backend"), 2.0)
        check(
            "lifecycle: the evicted agent left every channel",
            listing is not None and "qa_agent" not in listing,
            str(listing),
        )

        # ---- 8. the log is auditable ----------------------------------------
        time.sleep(0.4)
        events = []
        with open(log_path) as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    events.append(json.loads(ln)["ev"])
        check(
            "observability: the JSONL log records the whole session",
            all(e in events for e in ("connect", "nick", "join", "bin_frame", "presence_expired")),
            str(sorted(set(events))),
        )

    finally:
        for c in clients:
            c.close()
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.kill()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        print("EXPERIMENT_001: FAIL")
        return 1
    print("EXPERIMENT_001: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
