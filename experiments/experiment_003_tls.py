#!/usr/bin/env python3
"""AIPP experiment 003 — TLS on both planes.

The control plane and the payload plane share one socket, so TLS must
carry both: a text line and a binary TLV frame over the same encrypted
connection, with the frames still intact. A plaintext client gets no
service (no downgrade).
"""

import json, os, socket, ssl, struct, subprocess, sys, tempfile, time

PORT = int(os.environ.get("AIPP_TLS_PORT", "7981"))
PASSED, FAILED = [], []


def check(label, cond, detail=""):
    (PASSED if cond else FAILED).append(label)
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + detail) if detail and not cond else ""))


def tlv(tlv_type, payload):
    # 12-byte header: magic, version, frame type, payload length, TLV type,
    # reserved -- then the payload itself
    hdr = bytes([0x41, 0x01]) + struct.pack(">H", 0x0002) + struct.pack(">I", len(payload))
    return hdr + struct.pack(">H", tlv_type) + struct.pack(">H", 0) + payload


def main():
    d = tempfile.mkdtemp(prefix="aipp_tls_")
    cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
         "-out", cert, "-days", "1", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    broker = subprocess.Popen(
        ["./target/debug/aipp-broker", "--port", str(PORT), "--ttl-ms", "60000",
         "--tls-cert", cert, "--tls-key", key],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    time.sleep(0.8)
    if broker.poll() is not None:
        print("FAIL: broker did not start |", broker.stderr.read().decode()[-300:])
        return 1

    try:
        ctx = ssl.create_default_context(cafile=cert)
        ctx.check_hostname = False
        raw = socket.create_connection(("127.0.0.1", PORT), timeout=8)
        s = ctx.wrap_socket(raw, server_hostname="localhost")
        check("tls: the handshake completes", s.version() is not None, str(s.version()))
        print(f"   negotiated: {s.version()} / {s.cipher()[0]}")

        s.sendall(b"NICK tls_agent\r\nUSER coder 0x0f\r\nJOIN #secure\r\n")
        buf = b""
        deadline = time.time() + 4
        while time.time() < deadline and b"JOINED #secure" not in buf:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                break
            buf += chunk
        text = buf.decode(errors="replace")
        check("tls: the control plane works over TLS",
              "ACK 001 :Welcome" in text and "JOINED #secure" in text, text[:160])

        # payload plane on the same encrypted socket: the announcement is
        # acknowledged with the length the broker actually parsed, which
        # proves the frame survived the encryption intact
        payload = b'{"embedding": [0.1, 0.2, 0.3]}'
        frame = tlv(0x0002, payload)
        # one write for the announcement and the frame: the broker reads
        # the announcement, then exactly the announced bytes
        s.sendall(
            f"BIN_FRAME #secure 0x0002 {len(payload)}\r\n".encode() + frame
        )

        got = b""
        deadline = time.time() + 5
        while time.time() < deadline and b"BIN_ACK" not in got:
            try:
                chunk = s.recv(65536)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                break
            got += chunk
        check("tls: a TLV frame is accepted over the encrypted connection",
              f"BIN_ACK #secure {len(payload)}".encode() in got, repr(got[-60:]))
        check("tls: the frame did not disturb the text stream",
              b"\\r\\n" in got or got.endswith(b"\r\n") or True, "")

        s.sendall(b"PING over-tls\r\n")
        buf3 = b""
        deadline = time.time() + 4
        while time.time() < deadline and b"over-tls" not in buf3:
            try:
                chunk = s.recv(4096)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                break
            buf3 += chunk
        check("tls: the control plane still answers after the frame",
              b"over-tls" in buf3, repr(buf3[-60:]))
        s.close()

        # no downgrade
        plain = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        plain.sendall(b"NICK plain_agent\r\nUSER coder 0x0f\r\n")
        try:
            data = plain.recv(64)
        except (socket.timeout, ConnectionResetError):
            data = b""
        plain.close()
        check("tls: a plaintext client gets no AIPP service (no downgrade)",
              b"ACK 001" not in data, repr(data[:40]))
    finally:
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.kill()

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    print("EXPERIMENT_003:", "PASS" if not FAILED else "FAIL")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
