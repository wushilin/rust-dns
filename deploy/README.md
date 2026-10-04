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

Release image (O18): every release tag pushes a multi-arch image
(linux/amd64, linux/arm64) built from the release's static binaries
(`deploy/Dockerfile.release`) to `ghcr.io/wushilin/rust-dns:<version>`
(and `:latest` for a non-pre-release). The repository is private, so is
the package: `docker login ghcr.io` with a token that has `read:packages`
first.

```
docker run -d --name rust-dns -p 53:53/udp -p 53:53/tcp -p 127.0.0.1:8053:8053 \
  -v rust-dns-data:/data ghcr.io/wushilin/rust-dns:<version>
```

## Debian / Ubuntu package

Each release has `rust-dns_<version>_amd64.deb` and `_arm64.deb`
(`scripts/build-deb.py`): `/usr/bin/rust-dns`, the systemd unit above
(`rust-dns.service`, enabled and started), config in `/etc/rust-dns`,
data in `/var/lib/rust-dns`, user `rust-dns`.

```
sudo apt install ./rust-dns_<version>_amd64.deb   # prints the root password once
```

A config already at `/etc/rust-dns/rust-dns.toml` is kept (write it before
installing to choose ports: on Ubuntu, systemd-resolved holds
127.0.0.53:53, so the default `[server]` bind on port 53 may not start).
`apt remove` stops the service; config and data stay even on purge.

## Homebrew

Each release has `rust-dns.rb`, a formula that builds the tagged source
with cargo. Homebrew installs formulae only from a tap; a local one does:

```
brew tap-new --no-git $USER/local
cp rust-dns.rb "$(brew --repository)/Library/Taps/$USER/homebrew-local/Formula/"
HOMEBREW_GITHUB_API_TOKEN=$(gh auth token) brew install $USER/local/rust-dns
rust-dns --init-config "$(brew --prefix)/etc/rust-dns/rust-dns.toml"
brew services start rust-dns
```

The token is needed while the repository is private (the formula sends
it with the source download).

## Windows service

```
rust-dns.exe --init-config C:\rust-dns\rust-dns.toml
rust-dns.exe --install-service --config C:\rust-dns\rust-dns.toml   (elevated prompt)
sc start rust-dns
sc stop rust-dns
rust-dns.exe --uninstall-service
```

The service `rust-dns` starts automatically at boot as LocalSystem, in the
config file's directory (relative paths in the config resolve there). It
has no console: set `[logging] file` to keep a log. `[server].interfaces`
(following interface addresses) is not available on Windows; use
`[server].bind`.
