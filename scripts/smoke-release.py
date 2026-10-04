#!/usr/bin/env python3
"""Smoke-test a release binary on the platform it was built for.

Usage: smoke-release.py <path-to-rust-dns-binary>

Starts the binary with a throwaway config on free loopback ports, signs in,
creates a zone and an A record through the API, then resolves the record over
UDP and TCP. Python standard library only, so it runs unchanged on Linux,
Windows and FreeBSD (release workflow) and needs nothing installed.
"""

import http.cookiejar
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

ZONE = "smoke.test"
ADDR = "192.0.2.53"
PASSWORD = "smoke-test-password-1"


def free_port(kind):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def free_dns_port():
    # The same number must be free for both UDP and TCP.
    for _ in range(50):
        p = free_port(socket.SOCK_DGRAM)
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            t.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
        finally:
            t.close()
    raise SystemExit("no free port for DNS")


def query_bytes(qid, name):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)  # A, IN


def a_answers(msg, qid):
    rid, flags, qd, an = struct.unpack(">HHHH", msg[:8])
    assert rid == qid, f"reply id {rid} != {qid}"
    rcode = flags & 0xF
    assert rcode == 0, f"rcode {rcode}"
    assert flags & 0x0400, "reply is not authoritative"
    pos = 12
    for _ in range(qd):
        pos = skip_name(msg, pos) + 4
    out = []
    for _ in range(an):
        pos = skip_name(msg, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        if rtype == 1:
            out.append(socket.inet_ntoa(msg[pos:pos + rdlen]))
        pos += rdlen
    return out


def skip_name(msg, pos):
    while True:
        n = msg[pos]
        if n == 0:
            return pos + 1
        if n & 0xC0 == 0xC0:
            return pos + 2
        pos += n + 1


def dns_udp(port, name):
    qid = random.randrange(1, 0xFFFF)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(query_bytes(qid, name), ("127.0.0.1", port))
    msg, _ = s.recvfrom(4096)
    s.close()
    return a_answers(msg, qid)


def dns_tcp(port, name):
    qid = random.randrange(1, 0xFFFF)
    q = query_bytes(qid, name)
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(struct.pack(">H", len(q)) + q)
    buf = b""
    while len(buf) < 2 or len(buf) < 2 + struct.unpack(">H", buf[:2])[0]:
        chunk = s.recv(4096)
        if not chunk:
            raise AssertionError("TCP connection closed early")
        buf += chunk
    s.close()
    return a_answers(buf[2:], qid)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    binary = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="rust-dns-smoke-")
    dns, web = free_dns_port(), free_port(socket.SOCK_STREAM)
    cfg = os.path.join(work, "rust-dns.toml")
    db = os.path.join(work, "smoke.db").replace("\\", "/")
    with open(cfg, "w") as f:
        f.write(f"""[server]
bind = ["127.0.0.1"]
port = {dns}
[forwarding]
upstreams = []
[database]
path = "{db}"
[backup]
dir = ""
[web_console]
bind = "127.0.0.1:{web}"
[root]
username = "root"
password = "{PASSWORD}"
[logging]
level = "warn"
""")

    version = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    print(f"version: {version}")
    subprocess.run([binary, "--check", "--config", cfg], check=True)
    print("config check: ok")

    proc = subprocess.Popen([binary, "--config", cfg], cwd=work)
    try:
        base = f"http://127.0.0.1:{web}/api"
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

        def call(method, path, body=None):
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(base + path, data=data, method=method)
            req.add_header("X-Requested-With", "rust-dns")
            for c in jar:
                if c.name in ("rdns_csrf", "__Host-rdns_csrf"):
                    req.add_header("X-CSRF-Token", c.value)
            if data is not None:
                req.add_header("Content-Type", "application/json")
            with opener.open(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"null")

        deadline = time.time() + 30
        while True:
            if proc.poll() is not None:
                raise AssertionError(f"server exited with {proc.returncode}")
            try:
                call("GET", "/health")
                break
            except OSError:
                if time.time() > deadline:
                    raise AssertionError("server did not become healthy within 30s")
                time.sleep(0.2)
        print("health: ok")

        call("POST", "/auth/login", {"username": "root", "password": PASSWORD})
        status, _ = call("POST", "/zones", {"name": ZONE})
        assert status == 201, f"create zone: {status}"
        status, _ = call("POST", f"/zones/{ZONE}/records", {"name": "www", "type": "A", "value": ADDR})
        assert status == 201, f"create record: {status}"
        print("api: zone and record created")

        name = f"www.{ZONE}"
        for proto, fn in (("udp", dns_udp), ("tcp", dns_tcp)):
            got = fn(dns, name)
            assert got == [ADDR], f"{proto}: {name} A -> {got}"
            print(f"dns {proto}: {name} A {ADDR}")
        print("smoke test passed")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
