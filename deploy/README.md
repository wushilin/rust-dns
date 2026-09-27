# Deployment notes

## systemd

```
sudo useradd -r -s /usr/sbin/nologin rust-dns
sudo mkdir -p /etc/rust-dns /var/lib/rust-dns
sudo cp target/release/rust-dns /usr/local/bin/
sudo rust-dns --init-config /etc/rust-dns/rust-dns.toml   # mode 0600; prints the random root password once
sudo chown -R rust-dns:rust-dns /etc/rust-dns /var/lib/rust-dns
sudo chmod 0700 /etc/rust-dns /var/lib/rust-dns
sudo cp deploy/rust-dns.service /etc/systemd/system/
sudo systemctl enable --now rust-dns
```

Set `[database].path = "/var/lib/rust-dns/rust-dns.db"` and put the web
console behind a TLS reverse proxy; list that proxy's own address in
`[web_console].proxy_trust` (nothing is trusted by default) and send HSTS
from the proxy. `deploy/install.sh` does all of this under /opt/rust-dns and
shows the generated root password at the end. The units use `UMask=0077` and
systemd sandboxing (`ProtectKernel*`, `RestrictAddressFamilies`,
`SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, ...) while
keeping `CAP_NET_BIND_SERVICE` for port 53.

## Docker

```
docker build -f deploy/Dockerfile -t rust-dns .
docker run -d --name rust-dns -p 53:53/udp -p 53:53/tcp -p 127.0.0.1:8053:8053 -v rust-dns-data:/data rust-dns
docker logs rust-dns   # the generated root password is printed once (stderr) on first start
```

Inside the container the default config binds the console to 127.0.0.1;
set `[web_console].bind = "0.0.0.0:8053"` in `/data/rust-dns.toml` to
publish it, and front it with TLS.
