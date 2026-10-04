#!/usr/bin/env python3
"""Soak / load test of a rust-dns build with a standby (M5).

Starts a PRIMARY and a STANDBY of the given binary on free loopback ports
(throwaway configs and databases under --workdir; nothing else on the host
is touched, port 53 is never used), seeds a DNSSEC-signed zone, then for
--duration sends a mixed DNS query load at --qps (both servers) while the
primary's records change --change-rate times a minute through the API.
Every --interval seconds it records, per server: memory (RSS), CPU time,
open file descriptors (Linux), query latency p50/p95/p99/max, timeouts and
unexpected answers, API errors, the standby's lag and halted state.

Standard library only (no dnspython), so it runs on a bare host.

    scripts/soak.py --bin target/release/rust-dns --duration 4h --qps 500 --change-rate 6

Outputs (in --workdir): samples.jsonl (one JSON object per interval),
summary.json, and the servers' own logs. Exit 0 when the run was clean
(error rate under --max-error-rate, standby never halted and caught up at
the end, memory growth under --max-rss-growth), else 1.
"""
import argparse
import json
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

ZONE = "soak.test"


def parse_duration(s):
    s = str(s).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s and s[-1] in units:
        return float(s[:-1]) * units[s[-1]]
    return float(s)


def free_port():
    while True:
        t = socket.socket()
        t.bind(("127.0.0.1", 0))
        p = t.getsockname()[1]
        t.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.bind(("127.0.0.1", p))
            u.close()
            if p != 5353:
                return p
        except OSError:
            u.close()


# ---- servers -------------------------------------------------------------------


def csrf_of(opener):
    """O7: the session's CSRF token (rdns_csrf cookie), sent with cookie writes."""
    for h in opener.handlers:
        for c in getattr(h, "cookiejar", None) or []:
            if c.name in ("rdns_csrf", "__Host-rdns_csrf"):
                return c.value
    return ""


class Server:
    def __init__(self, binary, workdir, name, password, extra=""):
        self.name, self.password = name, password
        self.dir = os.path.join(workdir, name)
        os.makedirs(self.dir, exist_ok=True)
        self.dns, self.web = free_port(), free_port()
        self.url = f"http://127.0.0.1:{self.web}"
        self.log = os.path.join(self.dir, "server.log")
        cfg = os.path.join(self.dir, "rust-dns.toml")
        with open(cfg, "w") as f:
            f.write(f"""
[server]
bind = ["127.0.0.1"]
port = {self.dns}
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "{os.path.join(self.dir, 'data.db')}"
[web_console]
bind = "127.0.0.1:{self.web}"
login_attempts_per_minute = 10000
login_backoff_after = 100000
[root]
username = "root"
password = "{password}"
[logging]
level = "info"
file = "{self.log}"
[backup]
dir = ""
{extra}
""")
        self.proc = subprocess.Popen([binary, "--config", cfg],
                                     stdout=subprocess.DEVNULL, stderr=open(os.path.join(self.dir, "stderr.log"), "w"))
        deadline = time.time() + 60
        while True:
            try:
                urllib.request.urlopen(f"{self.url}/api/health", timeout=1).read()
                break
            except Exception:
                if self.proc.poll() is not None or time.time() > deadline:
                    raise SystemExit(f"{name} did not start; see {self.log}")
                time.sleep(0.2)
        self.api = Api(self.url, "root", password)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def proc_stats(self):
        """RSS (KiB), CPU seconds, open fds (Linux only; None elsewhere)."""
        pid = self.proc.pid
        rss = cpu = fds = None
        try:
            out = subprocess.run(["ps", "-o", "rss=,time=", "-p", str(pid)], capture_output=True, text=True).stdout.split()
            rss = int(out[0])
            t = out[1].replace("-", ":").split(":")  # [[dd-]hh:]mm:ss
            cpu = 0.0
            for part in t:
                cpu = cpu * 60 + float(part)
        except Exception:
            pass
        if os.path.isdir(f"/proc/{pid}/fd"):
            try:
                fds = len(os.listdir(f"/proc/{pid}/fd"))
            except OSError:
                pass
        return rss, cpu, fds


class Api:
    def __init__(self, base, user, password):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
        self.call("POST", "/auth/login", {"username": user, "password": password})

    def call(self, method, path, body=None, timeout=15):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.base}/api{path}", data=data, method=method,
                                     headers={"x-requested-with": "rust-dns", "content-type": "application/json",
                                              "x-csrf-token": csrf_of(self.opener)})
        try:
            with self.opener.open(req, timeout=timeout) as r:
                txt = r.read()
                return r.status, (json.loads(txt) if txt else None)
        except urllib.error.HTTPError as e:
            txt = e.read()
            try:
                return e.code, json.loads(txt)
            except Exception:
                return e.code, None


# ---- DNS load -----------------------------------------------------------------------


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


QTYPES = {"A": 1, "NS": 2, "SOA": 6, "TXT": 16, "AAAA": 28, "DNSKEY": 48}


def query(qid, name, qtype, dnssec):
    flags = 0x0100  # RD
    arcount = 1 if dnssec else 0
    msg = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, arcount) + encode_name(name) + struct.pack(">HH", QTYPES[qtype], 1)
    if dnssec:
        msg += b"\x00" + struct.pack(">HHIH", 41, 1232, 0x00008000, 0)  # OPT, DO
    return msg


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.lat = []
        self.sent = self.ok = self.timeouts = self.bad = 0
        self.bad_examples = []

    def take(self):
        with self.lock:
            snap = (self.lat, self.sent, self.ok, self.timeouts, self.bad, self.bad_examples)
            self.reset()
        return snap


def pct(v, p):
    if not v:
        return None
    v = sorted(v)
    return round(v[min(len(v) - 1, int(len(v) * p / 100))] * 1000, 3)


class Load(threading.Thread):
    """UDP load against one server: a paced sender and a receiver matching
    replies by id. Expected rcodes: NOERROR for names that exist, NXDOMAIN
    for names that do not; anything else (or a missing reply) is counted."""

    def __init__(self, server, qps, names, stop, timeout=2.0):
        super().__init__(daemon=True)
        self.server, self.qps, self.names, self.stop = server, qps, names, stop
        self.stats = Stats()
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.connect(("127.0.0.1", server.dns))
        self.sock.settimeout(0.2)
        self.inflight = {}
        self.lock = threading.Lock()
        self.rx = threading.Thread(target=self.receive, daemon=True)

    def pick(self):
        r = random.random()
        if r < 0.55:
            return f"{random.choice(self.names())}.{ZONE}", "A", 0
        if r < 0.65:
            return f"{random.choice(self.names())}.{ZONE}", "AAAA", 0  # NODATA
        if r < 0.80:
            return f"nx{random.randrange(10**9)}.{ZONE}", "A", 3
        if r < 0.90:
            return ZONE, random.choice(["SOA", "NS", "TXT"]), 0
        return ZONE, "DNSKEY", 0

    def receive(self):
        while not self.stop.is_set():
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                self.expire()
                continue
            except OSError:
                continue
            if len(data) < 12:
                continue
            qid = struct.unpack(">H", data[:2])[0]
            rcode = data[3] & 0x0F
            with self.lock:
                ent = self.inflight.pop(qid, None)
            if not ent:
                continue
            t0, want, what = ent
            with self.stats.lock:
                if rcode == want:
                    self.stats.ok += 1
                    self.stats.lat.append(time.monotonic() - t0)
                else:
                    self.stats.bad += 1
                    if len(self.stats.bad_examples) < 5:
                        self.stats.bad_examples.append(f"{what}: rcode {rcode}, want {want}")
            self.expire()

    def expire(self):
        now = time.monotonic()
        with self.lock:
            old = [k for k, (t0, _, _) in self.inflight.items() if now - t0 > self.timeout]
            for k in old:
                del self.inflight[k]
        if old:
            with self.stats.lock:
                self.stats.timeouts += len(old)

    def run(self):
        self.rx.start()
        interval = 1.0 / self.qps
        nxt = time.monotonic()
        qid = random.randrange(65536)
        while not self.stop.is_set():
            now = time.monotonic()
            if now < nxt:
                time.sleep(min(nxt - now, 0.05))
                continue
            nxt += interval
            if now - nxt > 1.0:  # fell behind: do not burst
                nxt = now
            qid = (qid + 1) & 0xFFFF
            name, qtype, want = self.pick()
            with self.lock:
                if qid in self.inflight:
                    continue
                self.inflight[qid] = (time.monotonic(), want, f"{name} {qtype}")
            try:
                self.sock.send(query(qid, name, qtype, random.random() < 0.3))
                with self.stats.lock:
                    self.stats.sent += 1
            except OSError:
                with self.stats.lock:
                    self.stats.bad += 1


# ---- changes ----------------------------------------------------------------------------


class Changer(threading.Thread):
    """Creates, updates and deletes records on the primary (a pool of
    churning names; a few with short expiries so expiry runs too)."""

    def __init__(self, primary, per_minute, stop):
        super().__init__(daemon=True)
        self.p, self.per_minute, self.stop = primary, per_minute, stop
        self.live = {}  # name -> record id
        self.lock = threading.Lock()
        self.done = self.errors = 0
        self.error_examples = []

    def names(self):
        with self.lock:
            return list(self.live) or ["www"]

    def run(self):
        if self.per_minute <= 0:
            return
        n = 0
        while not self.stop.wait(60.0 / self.per_minute):
            n += 1
            try:
                self.step(n)
                self.done += 1
            except Exception as e:  # noqa: BLE001
                self.errors += 1
                if len(self.error_examples) < 5:
                    self.error_examples.append(str(e))

    def step(self, n):
        with self.lock:
            live = dict(self.live)
        kind = random.random()
        if len(live) < 20 or kind < 0.4:
            name = f"h{n}"
            body = {"name": name, "type": "A", "value": f"10.{n % 250}.{(n // 250) % 250}.{n % 200 + 1}"}
            if random.random() < 0.2:
                body["expires_in"] = random.randrange(60, 600)
            s, v = self.p.api.call("POST", f"/zones/{ZONE}/records", body)
            if s != 201:
                raise RuntimeError(f"create {s} {v}")
            if "expires_in" not in body:
                with self.lock:
                    self.live[name] = v["id"]
        elif kind < 0.75:
            name, rid = random.choice(list(live.items()))
            s, v = self.p.api.call("PUT", f"/zones/{ZONE}/records/{rid}", {"value": f"10.200.{n % 250}.{n % 200 + 1}"})
            if s != 200:
                raise RuntimeError(f"update {s} {v}")
        else:
            name, rid = random.choice(list(live.items()))
            with self.lock:
                self.live.pop(name, None)
            s, v = self.p.api.call("DELETE", f"/zones/{ZONE}/records/{rid}")
            if s not in (200, 204):
                raise RuntimeError(f"delete {s} {v}")


# ---- main ------------------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True, help="rust-dns binary (a release build)")
    ap.add_argument("--duration", default="1h", help="e.g. 600, 30m, 6h (default 1h)")
    ap.add_argument("--qps", type=float, default=200, help="queries per second per server (default 200)")
    ap.add_argument("--change-rate", type=float, default=6, help="record changes per minute on the primary (default 6)")
    ap.add_argument("--interval", type=float, default=60, help="seconds between samples (default 60)")
    ap.add_argument("--no-standby", action="store_true", help="primary only")
    ap.add_argument("--workdir", default=None, help="default: a new temporary directory (kept)")
    ap.add_argument("--max-error-rate", type=float, default=0.001, help="fail above this share of timeouts + wrong answers")
    ap.add_argument("--max-rss-growth", type=float, default=0.5,
                    help="fail when the last sample's RSS exceeds the one after warm-up by this share (default 0.5)")
    a = ap.parse_args()
    duration = parse_duration(a.duration)
    workdir = a.workdir or tempfile.mkdtemp(prefix="rust-dns-soak-")
    os.makedirs(workdir, exist_ok=True)
    print(f"workdir {workdir}", flush=True)

    servers = []
    try:
        p = Server(a.bin, workdir, "primary", "soak-primary-pass")
        servers.append(p)
        s, v = p.api.call("POST", "/zones", {"name": ZONE})
        assert s == 201, v
        for name, t, val in [("@", "NS", f"ns1.{ZONE}."), ("ns1", "A", "192.0.2.53"), ("www", "A", "192.0.2.80"),
                             ("@", "TXT", "soak")]:
            s, v = p.api.call("POST", f"/zones/{ZONE}/records", {"name": name, "type": t, "value": val})
            assert s == 201, v
        s, v = p.api.call("PUT", f"/zones/{ZONE}/dnssec", {"enabled": True})
        assert s == 200, v
        standby = None
        if not a.no_standby:
            s, v = p.api.call("POST", "/tokens", {"name": "soak-repl"})
            assert s == 201, v
            standby = Server(a.bin, workdir, "standby", "soak-standby-pass",
                             f'[follow]\nprimary = "{p.url}"\ninstance_id = "soak"\ntoken = "{v["token"]}"\n')
            servers.append(standby)

        stop = threading.Event()
        changer = Changer(p, a.change_rate, stop)
        names = lambda: ["www", "ns1"] + changer.names()  # noqa: E731
        loads = [Load(srv, a.qps, names, stop) for srv in servers]
        for t in [changer] + loads:
            t.start()

        samples_path = os.path.join(workdir, "samples.jsonl")
        samples = []
        t_start = time.time()
        halted = False
        last_cpu = {srv.name: srv.proc_stats()[1] for srv in servers}
        with open(samples_path, "w") as out:
            while time.time() - t_start < duration:
                time.sleep(min(a.interval, max(0.0, duration - (time.time() - t_start))))
                sample = {"t": round(time.time() - t_start, 1), "changes": changer.done, "change_errors": changer.errors}
                for srv, load in zip(servers, loads):
                    lat, sent, ok, timeouts, bad, ex = load.stats.take()
                    rss, cpu, fds = srv.proc_stats()
                    alive = srv.proc.poll() is None
                    sample[srv.name] = {
                        "alive": alive, "rss_kib": rss, "fds": fds,
                        "cpu_s": None if cpu is None or last_cpu[srv.name] is None else round(cpu - last_cpu[srv.name], 2),
                        "sent": sent, "ok": ok, "timeouts": timeouts, "bad": bad, "bad_examples": ex,
                        "p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99),
                        "max_ms": round(max(lat) * 1000, 3) if lat else None,
                    }
                    last_cpu[srv.name] = cpu
                if standby:
                    s1, ps = p.api.call("GET", "/replication/status")
                    s2, ss = standby.api.call("GET", "/replication/status")
                    if s1 == 200 and s2 == 200:
                        sample["replication"] = {"lag": (ps.get("head") or 0) - (ss.get("head") or 0),
                                             "state": (ss.get("follow") or {}).get("state"),
                                             "halted": (ss.get("follow") or {}).get("halted"),
                                             "reconcile": (ss.get("follow") or {}).get("last_reconcile_result")}
                        halted = halted or bool(sample["replication"]["halted"])
                samples.append(sample)
                out.write(json.dumps(sample) + "\n")
                out.flush()
                brief = " | ".join(f"{srv.name} rss {sample[srv.name]['rss_kib']} KiB p99 {sample[srv.name]['p99_ms']} ms "
                                   f"ok {sample[srv.name]['ok']} to {sample[srv.name]['timeouts']} bad {sample[srv.name]['bad']}"
                                   for srv in servers)
                lag = sample.get("replication", {}).get("lag")
                print(f"[{sample['t']:>8.0f}s] {brief} | changes {changer.done} (err {changer.errors}) | lag {lag}", flush=True)
                if any(not sample[srv.name]["alive"] for srv in servers):
                    print("a server exited", flush=True)
                    break
        stop.set()
        time.sleep(1)

        # Let the standby catch up, then summarize.
        caught_up = None
        if standby:
            deadline = time.time() + 60
            while time.time() < deadline:
                _, ps = p.api.call("GET", "/replication/status")
                _, ss = standby.api.call("GET", "/replication/status")
                if ps and ss and ps.get("head") == ss.get("head"):
                    caught_up = True
                    break
                time.sleep(1)
            caught_up = bool(caught_up)

        summary = {"workdir": workdir, "duration_s": round(time.time() - t_start), "qps_per_server": a.qps,
                   "change_rate_per_min": a.change_rate, "changes": changer.done, "change_errors": changer.errors,
                   "change_error_examples": changer.error_examples, "standby_halted": halted,
                   "standby_caught_up": caught_up, "servers": {}}
        failed = changer.errors > 0 or halted or caught_up is False
        for srv in servers:
            rows = [smp[srv.name] for smp in samples]
            sent = sum(r["sent"] for r in rows)
            errs = sum(r["timeouts"] + r["bad"] for r in rows)
            rss = [r["rss_kib"] for r in rows if r["rss_kib"]]
            warm = rss[min(len(rss) - 1, max(1, len(rss) // 10))] if rss else None
            growth = (rss[-1] - warm) / warm if rss and warm else None
            p99s = [r["p99_ms"] for r in rows if r["p99_ms"] is not None]
            summary["servers"][srv.name] = {
                "queries": sent, "errors": errs, "error_rate": (errs / sent) if sent else None,
                "rss_kib_first": rss[0] if rss else None, "rss_kib_after_warmup": warm,
                "rss_kib_last": rss[-1] if rss else None, "rss_kib_max": max(rss) if rss else None,
                "rss_growth_after_warmup": round(growth, 3) if growth is not None else None,
                "p99_ms_median_of_samples": sorted(p99s)[len(p99s) // 2] if p99s else None,
                "p99_ms_worst_sample": max(p99s) if p99s else None,
                "alive_at_end": srv.proc.poll() is None,
            }
            if not sent or errs / sent > a.max_error_rate or (growth or 0) > a.max_rss_growth or srv.proc.poll() is not None:
                failed = True
        summary["result"] = "FAIL" if failed else "ok"
        with open(os.path.join(workdir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)
        print(json.dumps(summary, indent=2), flush=True)
        return 1 if failed else 0
    finally:
        for srv in servers:
            srv.stop()


if __name__ == "__main__":
    sys.exit(main())
