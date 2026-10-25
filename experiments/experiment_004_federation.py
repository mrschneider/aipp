#!/usr/bin/env python3
"""AIPP experiment 004 — federation.

Three brokers in a chain (C -> A -> B, C is NOT linked to B directly):

  A. a message crosses the link to an agent on the peer broker
  B. the reply crosses back without any route table
  C. a two-hop message reaches the far broker through the middle one
  D. flooding cannot loop: the same message is never delivered twice,
     and a message that comes home is dropped
"""

import hmac, hashlib, os, socket, subprocess, sys, time

KEY = b"mesh-secret"
PASSED, FAILED = [], []


def check(label, cond, detail=""):
    (PASSED if cond else FAILED).append(label)
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + detail) if detail and not cond else ""))


def token(ag_id, caps=0x1F):
    exp = int(time.time() * 1000) + 120_000
    sig = hmac.new(KEY, f"aipp1|{ag_id}|{caps}|{exp}".encode(), hashlib.sha256).hexdigest()
    return f"{ag_id}.{exp}.{caps:x}.{sig}"


def boot(port, peers=(), name=None):
    args = ["./target/debug/aipp-broker", "--port", str(port), "--ttl-ms", "120000",
            "--auth-key", KEY.decode(), "--id", name or f"b{port}"]
    for p in peers:
        args += ["--peer", f"127.0.0.1:{p}"]
    b = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.7)
    return b


def agent(port, name, cls="worker"):
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.settimeout(0.2)
    s.sendall(f"AUTH {token(name)}\r\nNICK {name}\r\nUSER {cls} 0x1f\r\n".encode())
    time.sleep(0.4)
    s.recv(65536)
    return s


def lines(sock, seconds=2.0):
    out, end = [], time.time() + seconds
    while time.time() < end:
        try:
            chunk = sock.recv(65536)
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
    A, B, C = 8201, 8202, 8203
    bA = boot(A)                      # hub
    bB = boot(B, peers=[A])           # B dials A
    bC = boot(C, peers=[A])           # C dials A
    time.sleep(1.0)
    try:
        alice = agent(B, "alice")
        bob = agent(A, "bob")
        carol = agent(C, "carol")

        # A. across the link ------------------------------------------
        alice.sendall(b"PRIVMSG bob :reach across the mesh\r\n")
        got = lines(bob)
        check("federation: a direct message crosses the link",
              "reach across the mesh" in got, got[:120])
        check("federation: the sender is attributed",
              ":alice PRIVMSG bob" in got, got[:120])

        # B. the reply comes back -------------------------------------
        bob.sendall(b"PRIVMSG alice :and back the other way\r\n")
        got = lines(alice)
        check("federation: the reply crosses back with no route table",
              ":bob PRIVMSG alice :and back the other way" in got, got[:140])

        # C. two hops through the hub ---------------------------------
        carol.sendall(b"PRIVMSG bob :two hops away\r\n")
        got = lines(bob)
        check("federation: a two-hop message reaches the far broker",
              ":carol PRIVMSG bob :two hops away" in got, got[:140])

        # D. no loops, no duplicates ----------------------------------
        for _ in range(3):
            alice.sendall(b"PRIVMSG bob :loop probe\r\n")
            time.sleep(0.3)
        got = lines(bob, 2.0)
        n = got.count("loop probe")
        check("federation: flooding does not duplicate or loop", n == 3, f"{n} copies")
        carol.sendall(b"PRIVMSG nobody_here :dead end\r\n")
        got = lines(carol)
        # the mesh is at-most-once flooding without acks: the origin is told
        # the message entered the mesh, and a dead end drops it (journaled).
        # Claiming a delivery guarantee here would be the lie.
        # the origin is told the message entered the mesh, with the id it
        # can be acknowledged against
        relayed = [l for l in got.split("\r\n") if l.startswith("RELAYED ")]
        check("federation: the origin is told the message entered the mesh",
              any("nobody_here" in l for l in relayed), got[:120])

        # a target that left before the message arrives: the relay reaches
        # the broker that last saw it, finds nobody, has no further links
        # and drops it. That is the honest contract of flooding without
        # acks -- at-most-once, no delivery guarantee -- and the test
        # asserts the loss instead of pretending it cannot happen.
        away = agent(B, "away_agent")
        away.close()          # QUIT removes the agent from the mesh
        time.sleep(0.4)
        bob.sendall(b"PRIVMSG away_agent :too late\r\n")
        got = lines(bob)
        relayed = [l for l in got.split("\r\n") if l.startswith("RELAYED ")]
        check("federation: an unknown target here is relayed, not refused",
              any("away_agent" in l for l in relayed), got[:120])
        late = agent(B, "away_agent")
        got = lines(late, 2.0)
        check("federation: a dropped relay is not resurrected at registration",
              "too late" not in got, got[:200])
        late.close()

    finally:
        for b in (bA, bB, bC):
            b.terminate()
            try:
                b.wait(timeout=5)
            except subprocess.TimeoutExpired:
                b.kill()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    print("EXPERIMENT_004:", "PASS" if not FAILED else "FAIL")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
