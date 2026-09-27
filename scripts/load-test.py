#!/usr/bin/env python3
"""Small UDP throughput probe for a running rust-dns instance.

Usage: scripts/load-test.py [zone] [server-ip] [port] [seconds] [clients] [timeout]

Each client keeps up to 256 queries in flight. A query that gets no reply
within `timeout` seconds (default 1.0) is counted as lost and its window slot
is freed, so packet loss does not stall sending. Query IDs still in flight (or
expired within the last `timeout`) are never reused, so a stale reply cannot be
mistaken for a fresh one.

The report shows queries sent, answered, timed out (lost), late replies (for a
query that had already timed out) and unmatched replies (unknown ID). Rates
are computed over the sending phase only. The tool does not enforce a machine-
dependent performance threshold; it exits non-zero only if no replies arrive.
"""
import collections
import select
import socket
import struct
import sys
import threading
import time

ZONE = sys.argv[1] if len(sys.argv) > 1 else "example.test"
IP = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 53
DURATION = max(1.0, float(sys.argv[4]) if len(sys.argv) > 4 else 5.0)
CLIENTS = max(1, int(sys.argv[5]) if len(sys.argv) > 5 else 8)
TIMEOUT = max(0.01, float(sys.argv[6]) if len(sys.argv) > 6 else 1.0)
WINDOW = 256


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\0"


QUESTION = encode_name("www." + ZONE) + struct.pack("!HH", 1, 1)
DEADLINE = time.monotonic() + DURATION
# sent, answered, timed_out, late, unmatched
counts = [[0, 0, 0, 0, 0] for _ in range(CLIENTS)]


def worker(index):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.connect((IP, PORT))
    pending = {}  # id -> send time (monotonic)
    order = collections.deque()  # (id, send time) in send order, for expiry
    expired = {}  # id -> time it may be reused again
    expired_order = collections.deque()
    next_id = index * 4096
    sent = answered = timed_out = late = unmatched = 0

    def expire(now):
        nonlocal timed_out
        cutoff = now - TIMEOUT
        while order and order[0][1] <= cutoff:
            ident, sent_at = order.popleft()
            if pending.get(ident) == sent_at:
                del pending[ident]
                timed_out += 1
                expired[ident] = now + TIMEOUT
                expired_order.append((ident, now + TIMEOUT))
        while expired_order and expired_order[0][1] <= now:
            ident, until = expired_order.popleft()
            if expired.get(ident) == until:
                del expired[ident]

    def receive():
        nonlocal answered, late, unmatched
        while True:
            try:
                response = sock.recv(4096)
            except (BlockingIOError, ConnectionRefusedError):
                return
            if len(response) < 2:
                unmatched += 1
                continue
            ident = struct.unpack("!H", response[:2])[0]
            if pending.pop(ident, None) is not None:
                answered += 1
            elif ident in expired:
                late += 1
            else:
                unmatched += 1

    while True:
        now = time.monotonic()
        if now >= DEADLINE:
            break
        expire(now)
        while len(pending) < WINDOW and time.monotonic() < DEADLINE:
            ident = next_id & 0xFFFF
            next_id += 1
            if ident in pending or ident in expired:
                continue  # still in flight / recently lost: never reuse
            packet = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + QUESTION
            try:
                sock.send(packet)
            except (BlockingIOError, ConnectionRefusedError):
                break
            sent_at = time.monotonic()
            pending[ident] = sent_at
            order.append((ident, sent_at))
            sent += 1
        readable, _, _ = select.select([sock], [], [], 0.001)
        if readable:
            receive()

    # Drain: give outstanding queries their full timeout to be answered.
    while pending:
        now = time.monotonic()
        expire(now)
        if not pending:
            break
        wait = max(0.0, min(0.01, order[0][1] + TIMEOUT - now)) if order else 0.01
        readable, _, _ = select.select([sock], [], [], wait)
        if readable:
            receive()
    sock.close()
    counts[index] = [sent, answered, timed_out, late, unmatched]


threads = [threading.Thread(target=worker, args=(i,)) for i in range(CLIENTS)]
started = time.monotonic()
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
elapsed = max(DEADLINE - started, 1e-9)  # sending phase; drain time excluded
sent, answered, timed_out, late, unmatched = (sum(v[i] for v in counts) for i in range(5))
print(
    f"zone={ZONE} clients={CLIENTS} duration={elapsed:.2f}s timeout={TIMEOUT:g}s "
    f"sent={sent} answered={answered} timed_out={timed_out} late={late} unmatched={unmatched}"
)
print(f"offered={sent / elapsed:.0f} q/s answered={answered / elapsed:.0f} q/s loss={(sent - answered) / max(sent, 1):.1%}")
if answered == 0:
    raise SystemExit("no DNS replies received")
