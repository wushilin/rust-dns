#!/usr/bin/env python3
"""End-to-end pass over every Phase O feature on a local primary + standby.

    scripts/e2e-phase-o.py BIN [--workdir DIR] [--keep]

Starts four servers of BIN on free ports under DIR (default: a temp dir):
U (an independent server, the external primary of a secondary zone), P
(the primary, with response rate limiting, DoT and DoH), S (a standby of
P) and C (a standby of S, O21). Then exercises each Phase O feature through
the API and DNS, checking its effect on P and, where it replicates, on S
and C. Prints PASS / FAIL per check; exit status 0 only when all pass.

Needs Python 3 with dnspython, and BIND's `dig` and `delv` (DoT / DoH and
DNSSEC validation). Never uses port 5353. Covered elsewhere and not here:
console flows (tests/ui/browser.test.js), packaging (O18-O20, CI), the
reverse proxy (O14, CI), the soak (O13), the private CA of [follow]
(O23, tests/follow.rs).
"""
import base64, http.cookiejar, json, os, re, shutil, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request

import dns.message, dns.query, dns.rdatatype, dns.flags, dns.rcode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TLS = os.path.join(ROOT, "tests", "fixtures", "tls")
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'} {name}" + ("" if cond or not detail else f"  -- {str(detail)[:300]}"), flush=True)


def free_port():
    while True:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            p = s.getsockname()[1]
        if p == 5353:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue


def tool(name):
    for d in ["/opt/homebrew/opt/bind/bin", "/opt/homebrew/opt/bind/sbin", "/usr/bin", "/usr/sbin"] + os.environ.get("PATH", "").split(":"):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    sys.exit(f"{name} not found")


DIG, DELV = tool("dig"), tool("delv")


class Node:
    def __init__(self, base, name, extra=""):
        self.name, self.dir = name, os.path.join(base, name)
        os.makedirs(self.dir, exist_ok=True)
        self.dns, self.web = free_port(), free_port()
        self.pw = f"pw-{name}-123456"
        self.extra = extra
        self.proc = None

    def write(self, extra=None):
        if extra is not None:
            self.extra = extra
        with open(os.path.join(self.dir, "c.toml"), "w") as f:
            f.write(f"""
[server]
bind = ["127.0.0.1"]
port = {self.dns}
cookies = true
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "{self.dir}/d.db"
[backup]
dir = ""
[web_console]
bind = "127.0.0.1:{self.web}"
login_attempts_per_minute = 10000
login_backoff_after = 100000
[root]
username = "root"
password = "{self.pw}"
[logging]
level = "info"
file = "{self.dir}/server.log"
[transfer]
allow = ["127.0.0.0/8"]
{self.extra}
""")

    def start(self, binary):
        self.write()
        self.proc = subprocess.Popen([binary, "--config", os.path.join(self.dir, "c.toml")], stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={**os.environ, "RUST_DNS_EXIT_WITH_STDIN": "1"})
        wait(f"{self.name} up", 30, lambda: http_ok(f"http://127.0.0.1:{self.web}/rust-dns/api/health"))

    def stop(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait()

    def log(self):
        try:
            return open(os.path.join(self.dir, "server.log")).read()
        except OSError:
            return ""


def http_ok(url):
    try:
        urllib.request.urlopen(url, timeout=1).read()
        return True
    except Exception:
        return False


def wait(what, secs, f):
    end = time.time() + secs
    while time.time() < end:
        try:
            if f():
                return True
        except Exception:
            pass
        time.sleep(0.3)
    check(f"timed out: {what}", False)
    return False


class Api:
    """A browser-like session (cookie + CSRF header) or a bearer token."""

    def __init__(self, node, user="root", pw=None, token=None):
        self.base = f"http://127.0.0.1:{node.web}/rust-dns/api"
        self.jar = http.cookiejar.CookieJar()
        self.o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf, self.token = "", token
        if token is None:
            st, v = self.call("POST", "/auth/login", {"username": user, "password": pw or node.pw})
            if st != 200:
                raise SystemExit(f"login {user}@{node.name}: {st} {v}")
            self.csrf = v.get("csrf_token", "")

    def call(self, method, path, body=None, csrf=True):
        h = {"X-Requested-With": "rust-dns"}
        if body is not None:
            h["Content-Type"] = "application/json"
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        elif csrf and self.csrf:
            h["X-CSRF-Token"] = self.csrf
        r = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(), method=method, headers=h)
        try:
            with self.o.open(r, timeout=20) as resp:
                t = resp.read()
                return resp.status, (json.loads(t) if t and t[:1] in b"[{" else t.decode())
        except urllib.error.HTTPError as e:
            t = e.read()
            try:
                return e.code, json.loads(t)
            except Exception:
                return e.code, t.decode(errors="replace")

    def ok(self, method, path, body=None):
        st, v = self.call(method, path, body)
        if st >= 300:
            check(f"{method} {path}", False, f"{st} {v}")
        return v


def q(node, name, t="A", do=False, tcp=False):
    m = dns.message.make_query(name, t, want_dnssec=do)
    return (dns.query.tcp if tcp else dns.query.udp)(m, "127.0.0.1", port=node.dns, timeout=3)


def addrs(node, name, t="A"):
    try:
        r = q(node, name, t)
        return sorted(rr.to_text() for s in r.answer for rr in s if s.rdtype == dns.rdatatype.from_text(t))
    except Exception:
        return []


def dig(*args):
    return subprocess.run([DIG, "@127.0.0.1", "+tries=1", "+time=3", *args], capture_output=True, text=True).stdout


def delv_ok(node, zone, dnskey_text, name, t, want):
    f = dnskey_text.split()
    anchor = os.path.join(node.dir, f"{zone}.anchor")
    with open(anchor, "w") as fh:
        fh.write(f'trust-anchors {{ "{zone}." static-key {f[4]} {f[5]} {f[6]} "{f[7]}"; }};\n')
    out = subprocess.run([DELV, "@127.0.0.1", "-p", str(node.dns), "-a", anchor, f"+root={zone}", name, t], capture_output=True, text=True)
    text = out.stdout + out.stderr
    return any(l.startswith(want) for l in text.splitlines()), text


def reconciled(api_primary, standby_api, standby):
    st = standby_api.ok("GET", "/replication/status")
    f = st.get("follow") or {}
    head = api_primary.ok("GET", "/replication/status").get("head")
    return f.get("halted") is None and f.get("last_applied_offset") == head and str(f.get("last_reconcile_result", "")).startswith("ok")


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    binary = os.path.abspath(args[0])
    keep = "--keep" in args
    work = args[args.index("--workdir") + 1] if "--workdir" in args else tempfile.mkdtemp(prefix="rust-dns-e2e-o-")
    os.makedirs(work, exist_ok=True)
    nodes = []
    try:
        run(binary, work, nodes)
    finally:
        for n in nodes:
            n.stop()
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" + (f"; failed: {failed}" if failed else ""))
    sys.exit(1 if failed else 0)


def run(binary, work, nodes):
    u, p, s, c = Node(work, "upstream"), Node(work, "primary"), Node(work, "standby"), Node(work, "cascade")
    nodes += [u, p, s, c]
    dot, doh = free_port(), free_port()
    p.extra = f"""
[rate_limit.rrl]
responses_per_second = 5
exempt = []
[encrypted_dns]
cert_file = "{TLS}/server.pem"
key_file = "{TLS}/server.key"
dot_listen = ["127.0.0.1:{dot}"]
doh_listen = ["127.0.0.1:{doh}"]
"""
    u.extra = f'notify = ["127.0.0.1:{p.dns}", "127.0.0.1:{s.dns}"]\n'
    # (U's extra lands in its [transfer] table.)
    for n in (u, p):
        n.start(binary)
    ua, pa = Api(u), Api(p)
    ua.ok("POST", "/zones", {"name": "far.test"})
    ua.ok("POST", "/zones/far.test/records", {"name": "www", "type": "A", "value": "192.0.2.10"})

    # --- group 1: security and accounts ---
    st, v = pa.call("POST", "/zones", {"name": "csrf.test"}, csrf=False)
    check("O7: a cookie write without the CSRF token is refused", st == 403, f"{st} {v}")
    pa.ok("PUT", "/settings/security", {"password_min_length": 14, "password_history": 2})
    st, v = pa.call("POST", "/users", {"username": "bob", "password": "short-pass"})
    check("O6: the password policy refuses a short password", st == 400, f"{st} {v}")
    bob = pa.ok("POST", "/users", {"username": "bob", "password": "a-long-password-1"})
    ba = Api(p, "bob", "a-long-password-1")
    tok = ba.ok("POST", "/tokens", {"name": "t1"})["token"]
    check("O1: the token works", Api(p, token=tok).call("GET", "/me")[0] == 200)
    ba.ok("PUT", "/me/password", {"current_password": "a-long-password-1", "new_password": "another-long-pw-2", "revoke_tokens": True})
    check("O1: a password change revoked the user's tokens", Api(p, token=tok).call("GET", "/me")[0] == 401)
    st, v = ba.call("PUT", "/me/password", {"current_password": "another-long-pw-2", "new_password": "a-long-password-1"})
    check("O6: the password history refuses a reuse", st == 400, f"{st} {v}")
    try:
        Api(p, "bob", "wrong-password-xx")
    except SystemExit:
        pass
    signins = pa.ok("GET", "/audit/sign-ins?user=bob")
    check("O4: the sign-in audit lists bob's failure", "fail" in json.dumps(signins).lower(), signins)
    st, v = pa.call("POST", f"/users/{bob['id']}/mfa/enroll", {})
    check("O5: an administrator generates an MFA enrollment for a user", st == 200 and ("otpauth" in json.dumps(v) or "qr" in json.dumps(v).lower()), f"{st} {str(v)[:200]}")

    # --- replication: S follows P (gzip snapshot, O22), C follows S (O21) ---
    repl = pa.ok("POST", "/tokens", {"name": "repl"})["token"]
    s.extra = f'[follow]\nprimary = "http://127.0.0.1:{p.web}"\ninstance_id = "dns2"\ntoken = "{repl}"\nreconcile_interval_secs = 2\n'
    s.start(binary)
    sa = Api(s)
    srepl = repl  # the root's tokens replicate: the same token is valid on S
    c.extra = f'[follow]\nprimary = "http://127.0.0.1:{s.web}"\ninstance_id = "dns3"\ntoken = "{srepl}"\nreconcile_interval_secs = 2\n'
    # C must use the same [root] username (O21), which every node does.
    c.start(binary)
    ca = Api(c)

    # --- group 2: console productivity (API side) ---
    for z in ("a.test", "b.test"):
        pa.ok("POST", "/zones", {"name": z})
        pa.ok("POST", f"/zones/{z}/records", {"name": "@", "type": "NS", "value": "ns1.a.test."})
        pa.ok("POST", f"/zones/{z}/records", {"name": "www", "type": "A", "value": "192.0.2.80"})
    pa.ok("POST", "/zones/a.test/records", {"name": "ns1", "type": "A", "value": "192.0.2.53"})
    hits = pa.ok("GET", "/search?q=www")
    check("O9: search finds records across zones", {h["zone"] for h in hits["hits"]} >= {"a.test", "b.test"}, hits)
    r = pa.ok("POST", "/zones/b.test/records/bulk", {"add": "x1 300 A 192.0.2.1\nx2 300 A 192.0.2.2\nx3 300 TXT hello"})
    check("O10: bulk paste applies in one transaction", r.get("applied") is True, r)
    pa.ok("POST", "/zones/b.test/clone", {"name": "c.test", "records": True})
    pa.ok("POST", "/zones/c.test/rename", {"name": "d.test"})
    check("O11: clone then rename", addrs(p, "x1.d.test.") == ["192.0.2.1"])

    # --- group 3: operations ---
    pa.ok("PUT", "/settings/rate-limit", {"exempt_valid_cookies": True})
    rl = pa.ok("GET", "/settings/rate-limit")
    check("O15: cookie exemption set from the API is in effect", rl["in_effect"]["exempt_valid_cookies"] is True, rl)
    pa.ok("PUT", "/zones/a.test/settings", {"auto_ptr": False, "transfer_allow": ["127.0.0.1/32"]})

    # --- group 6 ---
    on = pa.ok("PUT", "/zones/a.test/dnssec", {"enabled": True, "denial": "nsec3"})
    pa.ok("POST", "/zones", {"name": "e.test"})
    pa.ok("POST", "/zones/e.test/records", {"name": "@", "type": "NS", "value": "ns1.a.test."})
    pa.ok("POST", "/zones/e.test/records", {"name": "www", "type": "A", "value": "192.0.2.81"})
    ed = pa.ok("PUT", "/zones/e.test/dnssec", {"enabled": True, "algorithm": 15})
    pa.ok("POST", "/zones/b.test/records", {"name": "loc", "type": "LOC", "value": "52 22 23 N 4 53 32 E -2m"})
    pa.ok("POST", "/zones", {"name": "far.test", "secondary": {"primaries": [f"127.0.0.1:{u.dns}"]}})

    wait("S reconciled", 60, lambda: reconciled(pa, sa, s))
    wait("C reconciled against S", 60, lambda: reconciled(sa, ca, c))
    check("O22: the standby's snapshot came gzip-compressed", any("snapshot received" in l and re.search(r"gzip\W*(=|:)?\W*true", l) for l in s.log().splitlines()), [l for l in s.log().splitlines() if "snapshot received" in l][:1])
    check("O21: C (a standby of the standby) serves P's data", addrs(c, "www.a.test.") == ["192.0.2.80"])
    sst = pa.ok("GET", "/replication/replicas")
    check("O21: P lists S; S lists C", "dns2" in json.dumps(sst) and "dns3" in json.dumps(sa.ok("GET", "/replication/replicas")))

    for n in (p, s):
        r = q(n, "nope.a.test.", "A", do=True, tcp=True)
        check(f"O24: NSEC3 denial on {n.name}", any(x.rdtype == dns.rdatatype.NSEC3 for x in r.authority) and r.rcode() == dns.rcode.NXDOMAIN)
        good, text = delv_ok(n, "a.test", on["key"]["dnskey"], "nope.a.test", "A", "; negative response, fully validated")
        check(f"O24: delv validates the NSEC3 NXDOMAIN on {n.name}", good, text)
        good, text = delv_ok(n, "e.test", ed["key"]["dnskey"], "www.e.test", "A", "; fully validated")
        check(f"O25: delv validates the Ed25519 zone on {n.name}", good, text)
        r = q(n, "loc.b.test.", "LOC")
        check(f"O28: LOC answered on {n.name}", r.answer and "52 22 23" in r.answer[0].to_text(), r)

    # O27: every server transfers the secondary zone itself.
    for n, a in ((p, pa), (s, sa)):
        wait(f"{n.name} transfers far.test", 30, lambda: addrs(n, "www.far.test.") == ["192.0.2.10"])
        st = a.ok("GET", "/zones/far.test/secondary")
        check(f"O27: {n.name} serves the secondary zone from its own transfer", st["state"] == "ok" and st["source"] == f"127.0.0.1:{u.dns}", st)
    st, v = pa.call("POST", "/zones/far.test/records", {"name": "x", "type": "A", "value": "192.0.2.1"})
    check("O27: a secondary zone is read-only", st == 409, f"{st} {v}")
    ua.ok("POST", "/zones/far.test/records", {"name": "new", "type": "A", "value": "192.0.2.11"})
    for n in (p, s):
        wait(f"NOTIFY refreshes far.test on {n.name}", 20, lambda: addrs(n, "new.far.test.") == ["192.0.2.11"])
        check(f"O27: NOTIFY from the zone's primary refreshed {n.name}", addrs(n, "new.far.test.") == ["192.0.2.11"])

    # O29: DoT and DoH on P.
    ca_file = f"+tls-ca={TLS}/ca.pem"
    out = dig("-p", str(dot), "+tls", ca_file, "+tls-hostname=localhost", "+short", "www.a.test", "A")
    check("O29: DNS over TLS answers", out.strip() == "192.0.2.80", out)
    out = dig("-p", str(doh), "+https", ca_file, "+tls-hostname=localhost", "+short", "www.a.test", "A")
    check("O29: DNS over HTTPS (POST) answers", out.strip() == "192.0.2.80", out)
    out = dig("-p", str(doh), "+https-get", ca_file, "+tls-hostname=localhost", "+short", "www.a.test", "A")
    check("O29: DNS over HTTPS (GET) answers", out.strip() == "192.0.2.80", out)

    # O26: RRL on P: 40 identical UDP queries at once.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(40):
        m = dns.message.make_query("www.b.test.", "A", use_edns=False)
        m.id = 2000 + i
        sock.sendto(m.to_wire(), ("127.0.0.1", p.dns))
    sock.settimeout(0.5)
    full = tc = 0
    try:
        while True:
            data, _ = sock.recvfrom(4096)
            r = dns.message.from_wire(data)
            if r.flags & dns.flags.TC and not r.answer:
                tc += 1
            else:
                full += 1
    except socket.timeout:
        pass
    check("O26: RRL answers about 5 a second, slips some and drops the rest", 5 <= full <= 10 and tc >= 5 and full + tc < 40, f"full {full} tc {tc}")
    check("O26: legitimate traffic (another name) is unaffected", addrs(p, "x2.b.test.") == ["192.0.2.2"])

    # Final state: nothing halted, all reconciled.
    wait("S reconciled at the end", 60, lambda: reconciled(pa, sa, s))
    wait("C reconciled at the end", 60, lambda: reconciled(sa, ca, c))
    for n, a in ((s, sa), (c, ca)):
        f = a.ok("GET", "/replication/status").get("follow") or {}
        check(f"{n.name}: following, not halted, reconcile ok", f.get("halted") is None and str(f.get("last_reconcile_result", "")).startswith("ok"), f)


if __name__ == "__main__":
    main()
