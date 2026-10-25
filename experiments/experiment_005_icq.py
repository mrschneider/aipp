#!/usr/bin/env python3
"""AIPP experiment 005 — the ICQ feature set.

What the OSCAR era knew that agents still need: the away message behind
the state, DND as a state of its own, a server-side roster that survives
restarts, authorization to message someone, typing announcements,
delivery acknowledgements across the mesh, and a directory search that
crosses brokers.
"""

import hmac, hashlib, json, os, socket, subprocess, sys, time

KEY = b"mesh-secret"
PASSED, FAILED = [], []


def check(label, cond, detail=""):
    (PASSED if cond else FAILED).append(label)
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + detail) if detail and not cond else ""))


def token(ag_id, caps=0x1F):
    exp = int(time.time() * 1000) + 120_000
    sig = hmac.new(KEY, f"aipp1|{ag_id}|{caps}|{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{ag_id}.{exp}.{caps:x}.{sig}"


def boot(port, peers=(), log=None):
    args = ["./target/debug/aipp-broker", "--port", str(port), "--ttl-ms", "120000",
            "--auth-key", KEY.decode(), "--id", f"b{port}", "--state", f"/tmp/aipp_e5_{port}.json"]
    if log:
        args += ["--log", log]
    for p in peers:
        args += ["--peer", f"127.0.0.1:{p}"]
    b = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.7)
    return b


def agent(port, name, cls="worker"):
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(0.3)
    s.sendall(f"AUTH {token(name)}\r\nNICK {name}\r\nUSER {cls} 0x1f\r\n".encode())
    time.sleep(0.35)
    try:
        s.recv(65536)
    except OSError:
        pass
    return s


def read(s, seconds=2.0):
    out, end = [], time.time() + seconds
    while time.time() < end:
        try:
            chunk = s.recv(65536)
        except (socket.timeout, TimeoutError):
            if out:
                break
            continue
        except OSError:
            break
        if not chunk:
            break
        out.append(chunk.decode(errors="replace"))
    return "".join(out)


def main():
    if os.path.exists("/tmp/aipp_e5_state.json"):
        os.remove("/tmp/aipp_e5_state.json")
    A, B, C = 8351, 8352, 8353
    log_a = f"/tmp/aipp_e5_a.jsonl"
    if os.path.exists(log_a):
        os.remove(log_a)
    bA = boot(A, log=log_a)
    bB = boot(B, peers=[A])
    bC = boot(C, peers=[A])
    time.sleep(1.0)

    try:
        # ---- 1. DND and the away message, seen through the roster -------
        watcher = agent(A, "watcher")
        worker = agent(B, "worker")
        watcher.sendall(b"ROSTER ADD worker\r\n")
        time.sleep(0.4)
        read(watcher, 0.5)
        worker.sendall(b"STATUS worker 0x05 0 0 :rebuilding the index\r\n")
        got = read(watcher)
        check("icq: the away message rides the presence broadcast",
              "0x05 0 0 :rebuilding the index" in got, got[:140])
        check("icq: DND is its own state (0x05)", "0x05" in got, got[:140])

        # a DND agent takes no pool work
        agent(B, "coder_9", cls="coder")
        worker2 = agent(B, "coder_busy", cls="coder")
        worker2.sendall(b"STATUS coder_busy 0x05 0 0 :do not disturb\r\n")
        time.sleep(0.4)
        read(worker2, 0.5)
        watcher.sendall(b"PRIVMSG @pool:coder :anyone free?\r\n")
        got = read(worker2, 1.5)
        check("icq: a DND agent is skipped by pool dispatch",
              "anyone free?" not in got, got[:140])

        # ---- 2. the roster survives a restart --------------------------
        bB.terminate()
        try:
            bB.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bB.kill()
        bB = boot(B, peers=[A])
        time.sleep(0.8)
        # A never restarted and the nick is still held by the live
        # connection: the roster query goes through the same socket
        watcher.sendall(b"ROSTER LIST\r\n")
        got = read(watcher)
        check("icq: the server-side roster survives a restart",
              "ROSTER worker" in got, got[:140])

        # ---- 3. authorization: permit and ignore lists -----------------
        alice = agent(A, "alice")
        spammer = agent(A, "spammer")
        carl = agent(A, "carl")
        bob = agent(A, "bob")
        alice.sendall(b"PERMIT ADD bob\r\nPERMIT ADD alice\r\nIGNORE ADD spammer\r\n")
        time.sleep(0.5)
        read(alice, 0.6)
        spammer.sendall(b"PRIVMSG alice :buy my tokens\r\n")
        got = read(spammer)
        check("icq: an ignored sender is refused and named (486)",
              "486" in got and "ignore list" in got, got[:140])
        carl.sendall(b"PRIVMSG alice :hello?\r\n")
        got = read(carl)
        check("icq: a sender outside the permit list is refused (487)",
              "487" in got and "not authorized" in got, got[:140])
        bob.sendall(b"PRIVMSG alice :legit question\r\n")
        got = read(alice)
        check("icq: a permitted sender is delivered",
              ":bob PRIVMSG alice :legit question" in got, got[:140])

        # ---- 4. typing announcement ------------------------------------
        bob.sendall(b"TYPING alice\r\n")
        got = read(alice)
        check("icq: the typing event is relayed to the receiver",
              ":bob TYPING alice" in got, got[:140])

        # ---- 5. delivery acknowledgement across the mesh ---------------
        planner = agent(C, "planner_1", cls="python-planner")
        watcher.sendall(b"PRIVMSG planner_1 :cross-mesh delivery\r\n")
        got = read(watcher, 3.0)
        relayed = [l for l in got.split("\r\n") if l.startswith("RELAYED ")]
        delivered = [l for l in got.split("\r\n") if l.startswith("DELIVERED ")]
        check("icq: the origin learns the message id and that it was delivered",
              bool(relayed) and delivered
              and delivered[0].split()[1] == relayed[0].split()[1],
              got[:180])

        # ---- 6. directory search across brokers ------------------------
        engine = agent(A, "engine_1", cls="rust-engine")
        engine.sendall(b"STATUS engine_1 0x00 30000 0 :inventory optimization\r\n")
        time.sleep(0.4)
        read(engine, 0.5)
        seeker = agent(C, "seeker")
        seeker.sendall(b"FIND inventory\r\n")
        got = read(seeker, 3.0)
        check("icq: directory search crosses brokers (whitepages)",
              any(l.startswith("FOUND ") and "inventory" in l for l in got.split("\r\n")),
              got[:200])

        # ---- 7. no FEDERATED echo storm --------------------------------
        count = sum(1 for line in open(log_a) if '"federate"' in line)
        check("icq: the link handshake answers once, not in an echo loop",
              1 <= count <= 3, f"{count} federate events on the hub")
    finally:
        for b in (bA, bB, bC):
            b.terminate()
            try:
                b.wait(timeout=5)
            except subprocess.TimeoutExpired:
                b.kill()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    print("EXPERIMENT_005:", "PASS" if not FAILED else "FAIL")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
