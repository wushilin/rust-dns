#!/usr/bin/env python3
"""Check a rust-dns .deb built by build-deb.py (O19), without dpkg.

Usage: check-deb.py <file.deb> [expected-arch]

Reads the ar archive and its tarballs and checks: member order and
format, the control fields, md5sums against the payload, the maintainer
scripts are executable shell scripts, the binary is executable and is an
ELF of the expected architecture, the unit runs /usr/bin/rust-dns with
/etc/rust-dns/rust-dns.toml, and every payload file is owned by root.
Exit 0 when everything holds.
"""
import hashlib
import io
import sys
import tarfile


def ar_members(data):
    assert data[:8] == b"!<arch>\n", "not an ar archive"
    pos, out = 8, []
    while pos < len(data):
        head = data[pos:pos + 60]
        assert head[58:60] == b"`\n", f"bad ar header at {pos}"
        name = head[:16].decode().strip().rstrip("/")
        size = int(head[48:58].decode().strip())
        out.append((name, data[pos + 60:pos + 60 + size]))
        pos += 60 + size + (size % 2)
    return out


def tar_files(blob):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        for m in t.getmembers():
            files[m.name] = (m, t.extractfile(m).read() if m.isfile() else None)
    return files


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__)
    want_arch = sys.argv[2] if len(sys.argv) == 3 else None
    members = ar_members(open(sys.argv[1], "rb").read())
    names = [n for n, _ in members]
    assert names == ["debian-binary", "control.tar.gz", "data.tar.gz"], names
    assert members[0][1] == b"2.0\n"
    control = tar_files(members[1][1])
    data = tar_files(members[2][1])
    fields = {}
    for line in control["./control"][1].decode().splitlines():
        if line and not line.startswith(" "):
            k, v = line.split(":", 1)
            fields[k] = v.strip()
    for k in ("Package", "Version", "Architecture", "Maintainer", "Description"):
        assert fields.get(k), f"control: {k} missing"
    assert fields["Package"] == "rust-dns"
    if want_arch:
        assert fields["Architecture"] == want_arch, fields["Architecture"]
    for script in ("postinst", "prerm", "postrm"):
        m, body = control[f"./{script}"]
        assert m.mode & 0o111, f"{script} not executable"
        assert body.startswith(b"#!/bin/sh"), f"{script} has no shell line"
    for line in control["./md5sums"][1].decode().splitlines():
        digest, path = line.split("  ", 1)
        got = hashlib.md5(data["./" + path][1]).hexdigest()
        assert got == digest, f"md5sums: {path}"
    for name, (m, _) in data.items():
        assert m.uid == 0 and m.gid == 0, f"{name} not owned by root"
    m, binary = data["./usr/bin/rust-dns"]
    assert m.mode & 0o111, "binary not executable"
    assert binary[:4] == b"\x7fELF", "binary is not ELF"
    machine = int.from_bytes(binary[18:20], "little")
    arch = {62: "amd64", 183: "arm64"}.get(machine, f"machine {machine}")
    assert arch == fields["Architecture"], f"binary is {arch}, control says {fields['Architecture']}"
    unit = data["./lib/systemd/system/rust-dns.service"][1].decode()
    assert "ExecStart=/usr/bin/rust-dns --config /etc/rust-dns/rust-dns.toml" in unit, unit
    assert "/usr/local/bin" not in unit
    print(f"{sys.argv[1]}: rust-dns {fields['Version']} {fields['Architecture']}, "
          f"{len(data)} entries, ok")


if __name__ == "__main__":
    main()
