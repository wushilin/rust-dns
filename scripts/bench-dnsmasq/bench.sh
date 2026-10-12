#!/usr/bin/env bash
# Runs inside the container (see run.sh). Usage: bench.sh N DURATION ROUNDS
# dnsmasq is measured over UDP only: it serves TCP from a forked process per
# connection, and dnsperf over TCP got almost no answers from it.
set -euo pipefail
N=${1:-1000}; DUR=${2:-15}; ROUNDS=${3:-3}
W=/tmp/w; rm -rf $W; mkdir -p $W
# Same data for both servers: N A records in bench.test.
python3 - "$N" > $W/hosts <<'PY'
import sys; n=int(sys.argv[1])
print("10.0.0.53 ns1.bench.test")
for i in range(n): print(f"10.{i//65536%256}.{i//256%256}.{i%256} h{i}.bench.test")
PY
# Query mix: 80% existing A, 10% AAAA of existing name (NODATA), 10% NXDOMAIN.
python3 - "$N" > $W/queries <<'PY'
import sys, random; n=int(sys.argv[1]); random.seed(1)
for _ in range(100000):
    r = random.random(); i = random.randrange(n)
    if r < 0.8: print(f"h{i}.bench.test A")
    elif r < 0.9: print(f"h{i}.bench.test AAAA")
    else: print(f"missing{i}.bench.test A")
PY
SRV_CPUS=${SRV_CPUS:-0-3}; CLI_CPUS=${CLI_CPUS:-4-7}
perf() { # server-label mode
  for r in $(seq 1 $ROUNDS); do
    out=$(taskset -c $CLI_CPUS dnsperf -m $2 -s 127.0.0.1 -p 5300 -d $W/queries -c 16 -T 4 -q 500 -l $DUR 2>&1)
    q=$(echo "$out" | awk '/Queries per second/ {print $4}')
    lost=$(echo "$out" | awk '/Queries lost/ {print $3}')
    lat=$(echo "$out" | awk '/Average Latency/ {print $4; exit}')
    echo "RESULT server=$1 mode=$2 cpus=$SRV_CPUS round=$r qps=$q lost=$lost avg_latency_s=$lat"
  done
}
rss() { echo "RSS server=$1 kb=$(ps -o rss= -p $2 | tr -d ' ')"; }

# --- dnsmasq: local hosts data, no upstream, unknown names in bench.test answered locally.
taskset -c $SRV_CPUS dnsmasq --keep-in-foreground --no-daemon --port=5300 --listen-address=127.0.0.1 --bind-interfaces \
  --no-resolv --no-hosts --addn-hosts=$W/hosts --local=/bench.test/ --cache-size=10000 \
  --dns-forward-max=10000 --user=root --log-facility=/dev/null >$W/dnsmasq.log 2>&1 &
DM=$!; sleep 1
dig +short @127.0.0.1 -p 5300 h1.bench.test A; dig @127.0.0.1 -p 5300 missing1.bench.test A | grep -o 'status: [A-Z]*'
perf dnsmasq udp; rss dnsmasq $DM
kill $DM; wait $DM 2>/dev/null || true

# --- rust-dns: same records as an authoritative zone.
cat > $W/config.toml <<EOC
[server]
bind = ["127.0.0.1"]
port = 5300
auto_ptr = false
max_tcp_connections = 4096
max_tcp_connections_per_client = 0
tcp_max_queries_per_connection = 100000000
tcp_max_connection_secs = 100000
[rate_limit]
max_resolutions_per_second_per_address = 0
[database]
path = "$W/rust-dns.db"
[backup]
dir = ""
[web_console]
bind = "127.0.0.1:5380"
[root]
username = "root"
password = "bench-root-password"
[logging]
level = "warn"
EOC
taskset -c $SRV_CPUS /bench/rust-dns --config $W/config.toml >$W/rust-dns.log 2>&1 &
RD=$!
python3 /bench/seed.py http://127.0.0.1:5380 $N || { cat $W/rust-dns.log; exit 1; }
sleep 1
dig +short @127.0.0.1 -p 5300 h1.bench.test A; dig @127.0.0.1 -p 5300 missing1.bench.test A | grep -o 'status: [A-Z]*'
perf rust-dns udp; perf rust-dns tcp; rss rust-dns $RD
kill $RD; wait $RD 2>/dev/null || true
