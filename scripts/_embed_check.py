#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`EMBEDDED == DIST` gate (helper of `scripts/make_packages_221r2.sh`).

Proves that every file rust-embed baked into the binary is byte-identical to the file in
`web/dist` — i.e. the shipped binary serves exactly the reviewed frontend.
"""
import hashlib
import os
import sys

bin_path, dist = sys.argv[1], sys.argv[2]
b = open(bin_path, "rb").read()
bad = []
for name in sorted(os.listdir(dist)):
    p = os.path.join(dist, name)
    if not os.path.isfile(p):
        continue
    blob = open(p, "rb").read()
    ok = blob in b
    print("  %-18s %9d embedded=%s  md5=%s" % (name, len(blob), ok, hashlib.md5(blob).hexdigest()))
    if not ok:
        bad.append(name)
if bad:
    print("EMBEDDED_EQ_DIST=NO -> %s" % bad, file=sys.stderr)
    sys.exit(1)
print("EMBEDDED_EQ_DIST=YES")
print("BIN_MD5=%s BIN_BYTES=%d" % (hashlib.md5(b).hexdigest(), len(b)))
