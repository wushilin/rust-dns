#!/usr/bin/env python3
"""Build a Debian package of a rust-dns binary (O19).

Usage: build-deb.py <rust-dns-binary> <version> <amd64|arm64> <out-dir>

Python standard library only (no dpkg-deb needed), so it runs on any
build host; the release workflow checks the result with dpkg-deb and
installs it. Layout:

  /usr/bin/rust-dns
  /lib/systemd/system/rust-dns.service   (deploy/rust-dns.service, /usr/bin)
  /etc/rust-dns/                         config (0700, user rust-dns)
  /var/lib/rust-dns/                     database, backups (0700)
  /usr/share/doc/rust-dns/               README.md, copyright, examples/

postinst creates the system user `rust-dns`, writes a new config with a
random root password (printed once) unless /etc/rust-dns/rust-dns.toml
already exists, checks it, and enables and starts the service where
systemd runs. A config written before installing (e.g. other ports) is
kept as it is. Removal stops the service; purge keeps config and data
(remove /etc/rust-dns and /var/lib/rust-dns yourself).

The package version is the release version with '-' turned into '~'
(0.2.0-rc.1 -> 0.2.0~rc.1, sorting before 0.2.0 as Debian expects).
"""
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

POSTINST = """#!/bin/sh
set -e
if [ "$1" = configure ]; then
  if ! getent passwd rust-dns >/dev/null; then
    useradd --system --home-dir /var/lib/rust-dns --no-create-home \\
      --shell /usr/sbin/nologin rust-dns
  fi
  install -d -o rust-dns -g rust-dns -m 0700 /etc/rust-dns /var/lib/rust-dns /var/lib/rust-dns/backups
  CFG=/etc/rust-dns/rust-dns.toml
  if [ ! -e "$CFG" ]; then
    echo "rust-dns: writing $CFG with a random root password (shown once):"
    /usr/bin/rust-dns --init-config "$CFG"
  fi
  chown rust-dns:rust-dns "$CFG"
  chmod 0600 "$CFG"
  if ! /usr/bin/rust-dns --check --config "$CFG" >/dev/null 2>&1; then
    echo "rust-dns: $CFG does not pass 'rust-dns --check'; the service is not started" >&2
    exit 0
  fi
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable rust-dns.service >/dev/null 2>&1 || true
    if ! systemctl restart rust-dns.service; then
      echo "rust-dns: the service did not start (port 53 taken, e.g. by systemd-resolved?)." >&2
      echo "rust-dns: see 'journalctl -u rust-dns', adjust $CFG, then 'systemctl restart rust-dns'." >&2
    fi
  fi
fi
exit 0
"""

PRERM = """#!/bin/sh
set -e
if [ -d /run/systemd/system ] && [ "$1" = remove ]; then
  systemctl stop rust-dns.service >/dev/null 2>&1 || true
  systemctl disable rust-dns.service >/dev/null 2>&1 || true
fi
exit 0
"""

POSTRM = """#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = purge ]; then
  echo "rust-dns: configuration and data are kept: /etc/rust-dns, /var/lib/rust-dns" >&2
fi
exit 0
"""


def deb_version(v):
    v = v.lstrip("v").replace("-", "~")
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+~]*", v):
        raise SystemExit(f"not a usable package version: {v}")
    return v


def unit_text():
    text = open(os.path.join(ROOT, "deploy", "rust-dns.service")).read()
    text = text.replace("/usr/local/bin/rust-dns", "/usr/bin/rust-dns")
    if "/usr/bin/rust-dns --config /etc/rust-dns/rust-dns.toml" not in text:
        raise SystemExit("deploy/rust-dns.service no longer has the expected ExecStart")
    return text


def tar_bytes(entries, mtime):
    """entries: (path, mode, data or None for a directory)."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=mtime) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for path, mode, data in entries:
                name = path.strip("/")
                info = tarfile.TarInfo("./" if not name else "./" + name + ("/" if data is None else ""))
                info.mode = mode
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = mtime
                if data is None:
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                else:
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def ar_member(name, data, mtime):
    head = f"{name:<16}{mtime:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
    assert len(head) == 60
    return head + data + (b"\n" if len(data) % 2 else b"")


def build(binary, version, arch, out_dir):
    if arch not in ("amd64", "arm64"):
        raise SystemExit("arch must be amd64 or arm64")
    version = deb_version(version)
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    files = {
        "usr/bin/rust-dns": (0o755, open(binary, "rb").read()),
        "lib/systemd/system/rust-dns.service": (0o644, unit_text().encode()),
        "usr/share/doc/rust-dns/README.md": (0o644, open(os.path.join(ROOT, "README.md"), "rb").read()),
        "usr/share/doc/rust-dns/copyright": (
            0o644,
            b"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
            b"Upstream-Name: rust-dns\nFiles: *\nLicense: Apache-2.0\n",
        ),
    }
    ex = os.path.join(ROOT, "examples")
    for d, _, names in os.walk(ex):
        for n in sorted(names):
            p = os.path.join(d, n)
            rel = os.path.relpath(p, ex).replace(os.sep, "/")
            files[f"usr/share/doc/rust-dns/examples/{rel}"] = (0o644, open(p, "rb").read())
    dirs = set()
    for path in files:
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    entries = [("", 0o755, None)] + [(d, 0o755, None) for d in sorted(dirs)]
    entries += [(p, m, data) for p, (m, data) in sorted(files.items())]
    data_tar = tar_bytes(entries, mtime)
    size_kb = (sum(len(d) for _, d in files.values()) + 1023) // 1024
    control = f"""Package: rust-dns
Version: {version}
Architecture: {arch}
Maintainer: rust-dns maintainers <noreply@users.noreply.github.com>
Installed-Size: {size_kb}
Depends: passwd, ca-certificates
Section: net
Priority: optional
Homepage: https://github.com/wushilin/rust-dns
Description: SQLite-backed authoritative DNS server with a web console
 rust-dns serves DNS zones (with DNSSEC signing) from SQLite, with a
 realtime web console and API, primary/standby replication, forwarding
 and resolver features. Static binary, systemd service rust-dns.
"""
    md5sums = "".join(
        f"{hashlib.md5(data).hexdigest()}  {path}\n" for path, (_, data) in sorted(files.items())
    )
    control_tar = tar_bytes(
        [
            ("", 0o755, None),
            ("control", 0o644, control.encode()),
            ("md5sums", 0o644, md5sums.encode()),
            ("postinst", 0o755, POSTINST.encode()),
            ("prerm", 0o755, PRERM.encode()),
            ("postrm", 0o755, POSTRM.encode()),
        ],
        mtime,
    )
    deb = b"!<arch>\n"
    deb += ar_member("debian-binary", b"2.0\n", mtime)
    deb += ar_member("control.tar.gz", control_tar, mtime)
    deb += ar_member("data.tar.gz", data_tar, mtime)
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"rust-dns_{version}_{arch}.deb")
    with open(out, "wb") as f:
        f.write(deb)
    return out


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    print(build(*sys.argv[1:]))


if __name__ == "__main__":
    main()
