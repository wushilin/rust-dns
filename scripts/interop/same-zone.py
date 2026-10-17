#!/usr/bin/env python3
"""Compare two zone transfers semantically (run.sh).

  same-zone.py <zone> <file-a> <file-b>

Both files are AXFR output in presentation format (dig, kdig), which the
clients print differently (base64 line breaks, the closing SOA). dnspython
parses both, so this also checks that a third implementation reads every
record; exit 1 lists the RRsets that differ.
"""
import sys

import dns.zone

origin = sys.argv[1]


def load(path):
    return dns.zone.from_file(path, origin=origin, relativize=False, check_origin=True)


a, b = load(sys.argv[2]), load(sys.argv[3])
diff = []
for name in sorted(set(a.nodes) | set(b.nodes)):
    na, nb = a.nodes.get(name), b.nodes.get(name)
    sa = {(r.rdtype, r.covers): r for r in (na.rdatasets if na else [])}
    sb = {(r.rdtype, r.covers): r for r in (nb.rdatasets if nb else [])}
    for k in sorted(set(sa) | set(sb)):
        if sa.get(k) != sb.get(k):
            diff.append(f"{name} {dns.rdatatype.to_text(k[0])}: {sys.argv[2]} {sa.get(k)} / {sys.argv[3]} {sb.get(k)}")
for d in diff:
    print(d)
records = sum(len(r) for n in a.nodes.values() for r in n.rdatasets)
print(f"{records} records, {len(diff)} RRsets differ")
sys.exit(1 if diff else 0)
