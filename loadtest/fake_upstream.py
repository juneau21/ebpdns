#!/usr/bin/env python3
"""本地假 DNS 上游：UDP 高端口，对任意查询名快速回真实 A/AAAA 应答。
A -> 9.9.9.9 ; AAAA -> 2606:4700:4700::1111。其余 NXDOMAIN 也回 RCODE=0 空答。
仅用于压测，保证 miss 能成功回填缓存。
"""
import socket, struct, sys, threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 15353
COUNT = [0]

def decode_name(data, off):
    labels = []
    while True:
        l = data[off]
        if l == 0:
            off += 1
            break
        labels.append(data[off+1:off+1+l].decode())
        off += 1 + l
    return ".".join(labels), off

def build_resp(req):
    if len(req) < 12:
        return None
    mid = req[:2]
    flags = 0x8180  # standard response, no error
    qd = 1
    try:
        name, off = decode_name(req, 12)
    except Exception:
        return None
    qtype, qclass = struct.unpack(">HH", req[off:off+4])
    qend = off + 4
    question = req[12:qend]
    an = b""
    ancount = 0
    if qtype in (1, 28):
        ancount = 1
        # name pointer 0xC00C
        if qtype == 1:
            rdata = socket.inet_aton("9.9.9.9")
            rtype = 1
        else:
            rdata = socket.inet_pton(socket.AF_INET6, "2606:4700:4700::1111")
            rtype = 28
        # answer: ptr, type, class, ttl, rdlen, rdata
        an = struct.pack(">HHHIH", 0xC00C, rtype, 1, 300, len(rdata)) + rdata
    hdr = struct.pack(">HHHHHH", int.from_bytes(mid,"big"), flags, qd, ancount, 0, 0)
    return hdr + question + an

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    print(f"fake upstream on 127.0.0.1:{PORT}", flush=True)
    while True:
        try:
            data, addr = s.recvfrom(4096)
            resp = build_resp(data)
            if resp:
                s.sendto(resp, addr)
                COUNT[0] += 1
        except Exception:
            pass

if __name__ == "__main__":
    main()
