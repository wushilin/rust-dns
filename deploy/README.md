# Deployment notes

## systemd

```
sudo useradd -r -s /usr/sbin/nologin rust-dns
sudo mkdir -p /etc/rust-dns /var/lib/rust-dns
sudo cp target/release/rust-dns /usr/local/bin/
rust-dns --print-sample-config | sudo tee /etc/rust-dns/rust-dns.toml
sudo chown -R rust-dns:rust-dns /etc/rust-dns /var/lib/rust-dns   # the config is rewritten once to hash the root password
sudo cp deploy/rust-dns.service /etc/systemd/system/
sudo systemctl enable --now rust-dns
```

Set `[database].path = "/var/lib/rust-dns/rust-dns.db"` and put the web
console behind a TLS reverse proxy (see the PROXY protocol / trusted proxy
settings in the config).

## Docker

```
docker build -f deploy/Dockerfile -t rust-dns .
docker run -d --name rust-dns -p 53:53/udp -p 53:53/tcp -p 127.0.0.1:8053:8053 -v rust-dns-data:/data rust-dns
docker logs rust-dns   # shows the generated root password on first start
```

Inside the container the default config binds the console to 127.0.0.1;
set `[web_console].bind = "0.0.0.0:8053"` in `/data/rust-dns.toml` to
publish it, and front it with TLS.
