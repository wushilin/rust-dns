#!/usr/bin/env bash
# Install or upgrade rust-dns as a systemd service under a prefix (default /opt/rust-dns).
#
#   sudo deploy/install.sh <rust-dns-binary> [config-to-install-if-none-exists]
#
# Layout:
#   /opt/rust-dns/bin/rust-dns        binary (root-owned)
#   /opt/rust-dns/etc/rust-dns.toml   config (rust-dns-owned, 0600; a new one gets a random root password,
#                                     shown once by this script; a plaintext password is hashed in place)
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
install -d -o rust-dns -g rust-dns -m 0700 "$PREFIX/etc" "$PREFIX/data" "$PREFIX/data/backups" "$PREFIX/logs"

# Replace the binary atomically.
install -o root -g root -m 0755 "$BIN" "$PREFIX/bin/rust-dns.new"
mv -f "$PREFIX/bin/rust-dns.new" "$PREFIX/bin/rust-dns"

CFG="$PREFIX/etc/rust-dns.toml"
CREDS=""
if [ ! -e "$CFG" ]; then
  if [ -n "$INIT_CFG" ]; then
    install -o rust-dns -g rust-dns -m 0600 "$INIT_CFG" "$CFG"
    echo "installed config $CFG"
  else
    # A new config with a random root password (stored hashed, file mode 0600).
    # The plaintext is printed once, here, and nowhere else.
    CREDS="$("$PREFIX/bin/rust-dns" --init-config "$CFG")"
    chown rust-dns:rust-dns "$CFG"; chmod 0600 "$CFG"
    echo "wrote new config $CFG"
  fi
else
  echo "keeping existing config $CFG"
fi
# Files written by older versions may be group/world readable: make every
# file under etc, data and logs owner-only (the process now uses umask 0077).
find "$PREFIX/etc" "$PREFIX/data" "$PREFIX/logs" -type f -perm /077 -exec chmod go-rwx {} +
# Refuses the "change-me" placeholder and an empty root password.
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
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
# AF_NETLINK: reading and following interface addresses ([server] interfaces).
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077
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
if [ -n "$CREDS" ]; then
  echo
  echo "=================================================================="
  echo " New rust-dns root login (shown once; the config stores a hash):"
  echo "$CREDS" | sed -n 's/^root \(username\|password\): /   \1: /p'
  echo "=================================================================="
fi
