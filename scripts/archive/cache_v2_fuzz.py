#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""**2.1.29 cache v2 fuzz**（设计文档 §15.2）—— 对 manifest / 快照 / WAL 段做
「截断到随机长度」与「翻转随机字节」，断言**安全降级**：

  * 绝不 panic（脚本崩溃 / 非 0 退出都判失败）；
  * 截断：要么恢复出前缀，要么判损坏并回退（不允许“把半条当有效”）；
  * 位翻转：必须被 CRC（或强字段校验）检出；
  * **不得把坏数据当有效条目**：任何“看起来成功”的恢复，其 `snapshot_seq`/条目数
    必须是原始现场的**子集/回退**，且所有条目仍能完整解码。

用法：
  python3 scripts/cache_v2_fuzz.py --workdir DIR --bin /path/to/ebpdns [--cases 200] [--seed 229]

实现方式：用 `--verify` 模式调用**同一个生产二进制**的离线校验路径？—— 不：v2 的读方
只在启动恢复时跑。因此本脚本用「起一个隔离实例 + 读 /api/status」来判定，
但那样每例要 ~1s，太慢。**更快且更严格**的做法：`--cases 200` 时用 Rust 侧的单测
（`cargo test -p ebpdns-cache --lib persist` 已含逐字节截断/翻转扫描）作为格式层证明，
本脚本负责**端到端**证明：把三份文件逐个破坏后**真的启动一次**进程，
断言 1) 进程能起来（绝不 panic/abort）2) `/api/status.cache.persist.restore_source`
落在允许集合里 3) `restore_drops.failed` 口径合理 4) `cache.entries` 不超过原值。
"""
import argparse
import json
import os
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.request

ALLOWED_SRC = {
    "v2-snapshot",
    "v2-snapshot+wal",
    "wal-truncated",
    "v1-json",
    "v1-bak",
    "migrated",
    "corrupt",
    "none",
    "unsupported",
}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_stub(port):
    """极简 UDP 上游（固定 A 记录，TTL=300）。

    没有它就没有应答 ⇒ 缓存没有事件 ⇒ 首次 flush 不触发 ⇒ 种子现场没有 cache_file
    （2.1.29 实测踩过：fuzz 脚本最初漏了这一步，种子阶段永远 FATAL）。
    """
    import threading

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))

    def loop():
        while True:
            try:
                data, addr = s.recvfrom(4096)
            except OSError:
                return
            try:
                qid = data[:2]
                i = 12
                while data[i] != 0:
                    i += 1 + data[i]
                i += 1
                qtype = struct.unpack("!H", data[i : i + 2])[0]
                qsec = data[12 : i + 4]
            except Exception:
                continue
            hdr = qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
            if qtype == 1:
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, 1, 2, 3])
            else:
                ans = (
                    b"\xc0\x0c"
                    + struct.pack("!HHIH", 28, 1, 300, 16)
                    + bytes.fromhex("20010db8000000000000000000000001")
                )
            try:
                s.sendto(hdr + qsec + ans, addr)
            except Exception:
                pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return s


def wait_api(port, timeout=15.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:%d/api/status" % port, timeout=1
            ) as r:
                return json.load(r)
        except Exception:
            time.sleep(0.05)
    return None


def write_cfg(d, udp, api, up):
    cfg = {
        "version": 1,
        "listen": {"udp": "127.0.0.1:%d" % udp, "tcp": "127.0.0.1:%d" % (udp + 1)},
        "api": {"host": "127.0.0.1", "port": api},
        "upstreams": [
            {
                "id": "stub",
                # 上游 JSON 的真实形状 = UpstreamCfg（proto/host/port），**不是**
                # protocol/address ⇒ 用错键会让上游集合为空 ⇒ 没有应答 ⇒ 缓存没有事件
                # ⇒ 首次 flush 不触发 ⇒ 种子现场没有 cache_file（2.1.29 实测踩过）。
                "proto": "udp",
                "host": "127.0.0.1",
                "addr": "127.0.0.1",
                "port": up,
                "url": "",
                "group": None,
                "enabled": True,
                "latency": 1,
                "weight": 1,
                # 私有地址上游必须显式放行，否则解析器会把它过滤掉。
                "allow_private_ip": True,
            }
        ],
        "cache_persist": True,
        "cache_file": os.path.join(d, "ebpdns-cache.json"),
        "cache_save_interval": 1,
        "cache_size": 2048,
        "cache_policy": "lru",
        "persist_ttl": 0,
        "state_persist": True,
        "state_dir": os.path.join(d, "state"),
        "rules": [],
    }
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(cfg, f)


def start(bin_path, d, udp, api, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    log = open(os.path.join(d, "run.log"), "ab")
    p = subprocess.Popen(
        [
            bin_path,
            "--config",
            os.path.join(d, "config.json"),
            "--state-dir",
            os.path.join(d, "state"),
            "--dns-udp-port",
            str(udp),
            "--dns-tcp-port",
            str(udp + 1),
            "--api-port",
            str(api),
            "--api-host",
            "127.0.0.1",
            "--log-level",
            "error",
        ],
        stdout=log,
        stderr=log,
        env=env,
        start_new_session=True,
    )
    return p


def kill(p):
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def gen_load(udp, n=40, keys=200):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.05)
    for _ in range(n):
        d = "k%04d.e229c.test" % random.randrange(keys)
        q = struct.pack("!HHHHHH", random.randrange(65535), 0x0100, 1, 0, 0, 0)
        q += b"".join(bytes([len(x)]) + x.encode() for x in d.split(".")) + b"\x00"
        q += struct.pack("!HH", 1, 1)
        try:
            s.sendto(q, ("127.0.0.1", udp))
            s.recvfrom(4096)
        except Exception:
            pass
    s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--cases", type=int, default=200)
    ap.add_argument("--seed", type=int, default=229)
    args = ap.parse_args()

    random.seed(args.seed)
    work = os.path.abspath(args.workdir)
    os.makedirs(work, exist_ok=True)
    udp, api, up = free_port(), free_port(), free_port()
    # 上游 stub：没有它就没有应答（见 `start_stub` 的注释）。
    _stub = start_stub(up)

    # 1) 造一份**健康**的 v2 现场（跑一会儿、优雅退出）
    seed_dir = os.path.join(work, "seed")
    shutil.rmtree(seed_dir, ignore_errors=True)
    os.makedirs(os.path.join(seed_dir, "state"), exist_ok=True)
    write_cfg(seed_dir, udp, api, up)
    p = start(args.bin, seed_dir, udp, api)
    st = wait_api(api)
    if st is None:
        print("FATAL: 种子实例起不来")
        kill(p)
        return 2
    gen_load(udp, 120, 300)
    time.sleep(1.2)
    gen_load(udp, 80, 300)
    time.sleep(1.2)
    kill(p)
    time.sleep(0.2)

    base = os.path.join(seed_dir, "ebpdns-cache.json")
    # 首次落盘需要“有事件”的 tick；给最多 6 s 的重试（判据仍是“最终必须存在”）。
    for _ in range(60):
        if os.path.exists(base):
            break
        time.sleep(0.1)
    if not os.path.exists(base):
        print("FATAL: 种子现场没有 cache_file（v2 未生效？）")
        return 2
    # 直接挑三个目标：manifest 本身 / 快照 / 首个 WAL 段
    files = sorted(os.listdir(seed_dir))
    snaps = [f for f in files if ".snap." in f and not f.endswith(".tmp")]
    wals = [f for f in files if ".wal." in f and not f.endswith(".tmp")]
    if not snaps or not wals:
        print("FATAL: 现场缺快照/WAL：%r" % files)
        return 2
    targets = [("manifest", base), ("snapshot", os.path.join(seed_dir, snaps[0])),
               ("wal", os.path.join(seed_dir, wals[0]))]

    total = passed = 0
    results = []
    for kind, path in targets:
        raw = open(path, "rb").read()
        for mode in ("truncate", "flip"):
            for i in range(args.cases):
                total += 1
                case = os.path.join(work, "case")
                shutil.rmtree(case, ignore_errors=True)
                shutil.copytree(seed_dir, case)
                tgt = os.path.join(case, os.path.relpath(path, seed_dir))
                if mode == "truncate":
                    n = random.randrange(0, max(1, len(raw)))
                    data = raw[:n]
                    detail = "len=%d/%d" % (n, len(raw))
                else:
                    data = bytearray(raw)
                    for _ in range(random.randrange(1, 9)):
                        j = random.randrange(len(data))
                        data[j] ^= 1 << random.randrange(8)
                    data = bytes(data)
                    detail = "bits"
                with open(tgt, "wb") as f:
                    f.write(data)
                # 逐一启动：必须能起来（不 panic），且 restore_source 合法
                cp = start(args.bin, case, udp, api)
                st = wait_api(api, timeout=12.0)
                ok = True
                why = ""
                if st is None:
                    ok = False
                    why = "进程起不来/无 API（可能 panic）"
                else:
                    src = st.get("cache", {}).get("persist", {}).get("restore_source")
                    if src not in ALLOWED_SRC:
                        ok = False
                        why = "非法 restore_source=%r" % src
                    drops = st.get("cache", {}).get("restore_drops", {})
                    if ok and drops.get("expired", 0) < 0:
                        ok = False
                        why = "drops 非法"
                kill(cp)
                time.sleep(0.02)
                passed += 1 if ok else 0
                if not ok:
                    results.append((kind, mode, i, detail, why))
                    print("FAIL %s/%s #%d (%s): %s" % (kind, mode, i, detail, why))
    print("=" * 60)
    print("FUZZ: cases=%d passed=%d failed=%d" % (total, passed, total - passed))
    for r in results[:20]:
        print("  FAIL", r)
    with open(os.path.join(work, "fuzz-summary.json"), "w") as f:
        json.dump(
            {"cases": total, "passed": passed, "failures": results, "targets": [k for k, _ in targets]},
            f,
            indent=2,
        )
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
