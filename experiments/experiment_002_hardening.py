#!/usr/bin/env python3
"""AIPP experiment 002 — identity, presence-aware dispatch, modes, ops views.

Proves the hardening pass against a real broker over real sockets:

  A. AUTH is enforced and the AG-ID comes from the token, not the claim
  B. `@pool:<class>` dispatches by presence, and DRAIN takes an agent out
  C. `+m` makes `+v` mean something; TOPIC/LIST/WHO are operator tools
  D. a flood is rate limited, and a stalled peer does not freeze anyone
"""

import hashlib, hmac, os, socket, subprocess, sys, time

PORT = int(os.environ.get("AIPP_PORT", "7912"))
KEY = b"mesh-secret"
PASSED, FAILED = [], []


def check(label, cond, detail=""):
    (PASSED if cond else FAILED).append(label)
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + detail) if detail and not cond else ""))


def token(ag_id, caps, ttl_ms=120_000):
    exp = int(time.time() * 1000) + ttl_ms
    msg = f"aipp1|{ag_id}|{caps}|{exp}".encode()
    sig = hmac.new(KEY, msg, hashlib.sha256).hexdigest()
    return f"{ag_id}.{exp}.{caps:x}.{sig}"


class Client:
    def __init__(self, name, cls="worker", caps="0x0F", connect=True):
        self.name = name
        self.cls = cls
        self.sock = None
        self.buf = b""
        if connect:
            self.connect()

    def connect(self):
        self.sock = socket.create_connection(("127.0.0.1", PORT), timeout=8)
        self.buf = b""

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())

    def lines(self, timeout=2.0):
        out = []
        end = time.time() + timeout
        self.sock.settimeout(0.2)
        while time.time() < end:
            try:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                self.buf += chunk
                while b"\r\n" in self.buf:
                    ln, self.buf = self.buf.split(b"\r\n", 1)
                    out.append(ln.decode(errors="replace"))
            except (socket.timeout, TimeoutError):
                if out:
                    break
        return out

    def wait(self, pred, timeout=3.0):
        end = time.time() + timeout
        seen = []
        while time.time() < end:
            for ln in self.lines(0.3):
                seen.append(ln)
                if pred(ln):
                    return ln
        return None

    def register(self, auth=True, nick=None, caps=0x1F):
        nick = nick or self.name
        self.caps = caps
        if auth:
            self.send(f"AUTH {token(nick, caps)}")
            ok = self.wait(lambda l: l.startswith("AUTH_OK") or l.startswith("ERR"))
            if ok is None or ok.startswith("ERR"):
                return ok
        self.send(f"NICK {nick}")
        self.send(f"USER {self.cls} 0x{self.caps:x}")
        return self.wait(lambda l: l.startswith("ACK 001") or l.startswith("ERR"), 4.0)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    global PORT
    log = "/tmp/aipp_exp002.jsonl"
    if os.path.exists(log):
        os.remove(log)
    broker = subprocess.Popen(
        ["./target/debug/aipp-broker", "--port", str(PORT), "--ttl-ms", "60000",
         "--auth-key", KEY.decode(), "--max-cmds-per-sec", "40", "--log", log],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    time.sleep(0.7)
    if broker.poll() is not None:
        print("FAIL: broker did not start |", broker.stderr.read().decode()[-300:])
        return 1

    try:
        # ---- A. identity ------------------------------------------------
        anon = Client("anon")
        anon.send("NICK sneaky_agent")
        r = anon.wait(lambda l: l.startswith("ERR") and "464" in l)
        check("auth: NICK without AUTH is refused (464)", r is not None, str(r))
        anon.close()

        sup = Client("supervisor_agent", "supervisor")
        r = sup.register()
        check("auth: a signed token authenticates and registration completes",
              r is not None and r.startswith("ACK 001"), str(r))

        claimed = Client("worker_1")
        claimed.send(f"AUTH {token('worker_1', 0x01)}")
        claimed.wait(lambda l: l.startswith("AUTH_OK"))
        claimed.send("NICK supervisor_agent")
        r = claimed.wait(lambda l: l.startswith("ERR") and "464" in l)
        check("auth: a token for worker_1 cannot claim supervisor_agent (464)",
              r is not None and "worker_1" in r, str(r))
        claimed.close()

        forged = Client("forger", connect=False)
        forged.connect()
        forged.send(f"AUTH {token('forger', 0x01).replace('forger', 'root_agent', 1)}")
        r = forged.wait(lambda l: l.startswith("ERR") and "464" in l)
        check("auth: a renamed token fails the signature (464)", r is not None, str(r))
        forged.close()

        # ---- B. presence-aware dispatch ---------------------------------
        c1 = Client("coder_1", "coder")
        # a worker token without INSPECT: operator views must be refused
        c1.register(caps=0x03)
        c2 = Client("coder_2", "coder")
        c2.register()
        sup.send("PRIVMSG @pool:coder :pick me a coder")
        got = c1.wait(lambda l: "pick me a coder" in l, 2.0) or c2.wait(
            lambda l: "pick me a coder" in l, 2.0)
        check("pool: @pool:coder reached a member of that class", got is not None, str(got))

        c2.send("DRAIN")
        d = c2.wait(lambda l: l.startswith("DRAINING"))
        check("drain: DRAIN is acknowledged", d is not None, str(d))
        picks = []
        for i in range(3):
            sup.send(f"PRIVMSG @pool:coder :drain-check-{i}")
            got = c1.wait(lambda l: f"drain-check-{i}" in l, 2.0)
            picks.append(got is not None)
        check("drain: a draining agent receives no new pool work", all(picks),
              f"coder_1 got {sum(picks)}/3")

        # ---- C. modes, topic, operator views ----------------------------
        for c in (sup, c1):
            c.send("JOIN #ops")
            c.wait(lambda l: l.startswith("JOINED #ops"))
        sup.send("MODE #ops +m")
        check("modes: the operator sets +m", sup.wait(lambda l: "MODE" in l, 2.0) is not None)
        c1.send("PRIVMSG #ops :unvoiced comment")
        r = c1.wait(lambda l: l.startswith("ERR") and ("404" in l or "482" in l), 2.0)
        check("modes: +m refuses an unvoiced member", r is not None, str(r))
        sup.send("MODE #ops +v coder_1")
        sup.wait(lambda l: "MODE" in l, 2.0)
        c1.send("PRIVMSG #ops :voiced now")
        check("modes: +v lets the member speak", sup.wait(lambda l: "voiced now" in l, 2.0) is not None)

        sup.send("TOPIC #ops :migration window at 22:00")
        t = sup.wait(lambda l: l.startswith("TOPIC_SET") or "TOPIC #ops" in l, 2.0)
        check("topic: the operator sets a topic", t is not None, str(t))
        c1.send("TOPIC #ops")
        t2 = c1.wait(lambda l: "migration window" in l, 2.0)
        check("topic: a member reads it back", t2 is not None, str(t2))

        sup.send("LIST")
        lst = sup.wait(lambda l: l.startswith("CHAN #ops"), 2.0)
        check("ops: LIST shows the channel with its flags", lst is not None and "m" in lst, str(lst))
        sup.send("WHO")
        who = sup.wait(lambda l: l.startswith("WHO coder_1"), 2.0)
        check("ops: WHO shows an agent with class and presence", who is not None, str(who))
        c1.send("LIST")
        r = c1.wait(lambda l: l.startswith("ERR") and "482" in l, 2.0)
        check("ops: LIST without INSPECT is refused (482)", r is not None, str(r))

        sup.send("CAP LS")
        caps = sup.wait(lambda l: l.startswith("CAP LS"), 2.0)
        check("cap: CAP LS advertises the extensions in use",
              caps is not None and all(x in caps for x in ("AUTH", "FRAGMENT", "POOL", "DRAIN")), str(caps))

        # ---- D. flood and a stalled peer --------------------------------
        flood = Client("flooder", connect=False)
        flood.connect()
        for i in range(80):
            flood.send("PING flood")
        refused = [l for l in flood.lines(2.0) if "439" in l]
        check("rate limit: a burst is refused with ERR 439", len(refused) > 0, f"{len(refused)} refusals")
        flood.close()

        # A second broker without rate limits: the point of this phase is
        # the output queue, not the limiter.
        port2 = PORT + 1
        broker2 = subprocess.Popen(
            ["./target/debug/aipp-broker", "--port", str(port2), "--ttl-ms", "60000",
             "--auth-key", KEY.decode()],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(0.6)
        old_port = PORT
        PORT = port2
        try:
            sup2 = Client("supervisor_agent", "supervisor")
            sup2.register()
            sup2.send("JOIN #quiet")
            sup2.wait(lambda l: l.startswith("JOINED #quiet"))

            # a peer that never reads a byte
            stalled = socket.create_connection(("127.0.0.1", PORT), timeout=5)
            stalled.sendall(b"AUTH " + token("stalled_agent", 0x1F).encode() + b"\r\n")
            stalled.sendall(b"NICK stalled_agent\r\nUSER worker 0x1F\r\nJOIN #quiet\r\n")
            time.sleep(0.3)

            # ~1 MB aimed at the peer that never reads: with a blocking write
            # this parks the broker, with the Outbox it does not
            big = "x" * 200
            for i in range(3000):
                # the sender is not a member of #quiet, so its own queue
                # stays free: only the stalled peer is loaded
                sup2.send(f"PRIVMSG #quiet :{i}-{big}")
            t0 = time.time()
            sup2.send("PING alive")
            pong = sup2.wait(lambda l: "alive" in l, 8.0)
            elapsed = time.time() - t0
            check("backpressure: a stalled peer does not freeze the broker",
                  pong is not None and elapsed < 8.0, f"{elapsed:.2f}s pong={pong}")
            stalled.close()
            sup2.close()
        finally:
            broker2.terminate()
            try:
                broker2.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker2.kill()
            PORT = old_port

    finally:
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.kill()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    print("EXPERIMENT_002:", "PASS" if not FAILED else "FAIL")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
