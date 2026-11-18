#!/usr/bin/env python3
"""极简假上游：任何 A 查询都返回 1.2.3.4/300s，用于隔离上游延迟对缓存基准的影响。"""
import socket, struct, sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15453
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
print("fake upstream on 127.0.0.1:%d" % port, flush=True)

while True:
    data, addr = s.recvfrom(4096)
    if len(data) < 12:
        continue
    qid = data[:2]
    # 找到问题区结尾
    i = 12
    while i < len(data) and data[i] != 0:
        i += 1 + data[i]
    qend = i + 1 + 4
    if qend > len(data):
        continue
    question = data[12:qend]
    header = qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([1, 2, 3, 4])
    s.sendto(header + question + ans, addr)
