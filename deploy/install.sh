#!/usr/bin/env bash
# Install or upgrade rust-dns as a systemd service under a prefix (default /opt/rust-dns).
#
#   sudo deploy/install.sh <rust-dns-binary> [config-to-install-if-none-exists]
#
# Layout:
#   /opt/rust-dns/bin/rust-dns        binary (root-owned)
#   /opt/rust-dns/etc/rust-dns.toml   config (rust-dns-owned: the plaintext root password is hashed in place)
#   /opt/rust-dns/data/               database and backups
#   /opt/rust-dns/logs/               log files (rotated by rust-dns itself)
# An existing config is never overwritten. Upgrades replace only the binary and unit.
set -euo pipefail
BIN="${1:?usage: install.sh <rust-dns-binary> [initial-config.toml]}"
INIT_CFG="${2:-}"
PREFIX="${PREFIX:-/opt/rust-dns}"
UNIT=/etc/systemd/system/rust-dns.service

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "$BIN" ] || chmod +x "$BIN"

if ! id rust-dns >/dev/null 2>&1; then
  useradd --system --home-dir "$PREFIX" --no-create-home --shell /usr/sbin/nologin rust-dns
  echo "created system user rust-dns"
fi

install -d -o root -g root -m 0755 "$PREFIX" "$PREFIX/bin"
install -d -o rust-dns -g rust-dns -m 0750 "$PREFIX/etc" "$PREFIX/data" "$PREFIX/data/backups" "$PREFIX/logs"

# Replace the binary atomically.
install -o root -g root -m 0755 "$BIN" "$PREFIX/bin/rust-dns.new"
mv -f "$PREFIX/bin/rust-dns.new" "$PREFIX/bin/rust-dns"

CFG="$PREFIX/etc/rust-dns.toml"
if [ ! -e "$CFG" ]; then
  if [ -n "$INIT_CFG" ]; then
    install -o rust-dns -g rust-dns -m 0640 "$INIT_CFG" "$CFG"
    echo "installed config $CFG"
  else
    "$PREFIX/bin/rust-dns" --print-sample-config > "$CFG"
    chown rust-dns:rust-dns "$CFG"; chmod 0640 "$CFG"
    echo "wrote sample config $CFG (set [root].password before starting)"
  fi
else
  echo "keeping existing config $CFG"
fi
"$PREFIX/bin/rust-dns" --check --config "$CFG"

cat > "$UNIT" <<UNITEOF
[Unit]
Description=rust-dns authoritative DNS server
Documentation=https://github.com/wushilin/rust-dns
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rust-dns
Group=rust-dns
WorkingDirectory=$PREFIX/data
ExecStartPre=$PREFIX/bin/rust-dns --check --config $CFG
ExecStart=$PREFIX/bin/rust-dns --config $CFG
# Re-read the config file (log level, forwarding, rate limits, expiry, ...).
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=2
# Port 53 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=$PREFIX/etc $PREFIX/data $PREFIX/logs
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable rust-dns >/dev/null 2>&1
if systemctl is-active --quiet rust-dns; then
  systemctl restart rust-dns
  echo "restarted rust-dns"
else
  systemctl start rust-dns
  echo "started rust-dns"
fi
sleep 1
systemctl --no-pager --lines=0 status rust-dns | head -5
