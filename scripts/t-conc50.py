#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""包布局并发 50 轮验收探针（**2.1.30**；可指定 state_dir / API / DNS 端口）。

两个写者读**同一个** `revision`，再并发 `PUT /api/config` 带 `if-revision: <rev>`：
每轮必须**恰好 1 个 200 + 1 个 409**；409 一方**零写入**；全部轮次结束后磁盘值必须
属于**真实写入过**的集合（`LOST_UPDATE=0`）；`state_dir/commit.json` 的 parts 摘要
在每个采样点自洽（`TEAR=0`）。

用法（只对隔离实例；**绝不**默认生产路径）：

    python3 scripts/t-conc50.py \
      --api http://127.0.0.1:18453 --token "$TOKEN" \
      --state-dir /root/m230/work/iso230/state \
      --cfg /root/m230/work/iso230/etc/config.json \
      --dns-port 19053 --rounds 50 --duration 300 --out /tmp/conc50.json

退出码：0 = `LOST_UPDATE=0` 且 `TEAR=0` 且每轮 200/409 恰各一；1 = 任一判据失败。
"""
import hashlib
import io
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

A = sys.argv[1:]


def opt(name, default=None):
    return A[A.index(name) + 1] if name in A else default


API = opt("--api", "http://127.0.0.1:18453").rstrip("/")
TOKEN = opt("--token", "")
STATE = opt("--state-dir", "")
CFG = opt("--cfg", os.path.join(os.path.dirname(STATE.rstrip("/")), "etc", "config.json") if STATE else "")
DNS_PORT = int(opt("--dns-port", "0"))
ROUNDS = int(opt("--rounds", "50"))
DURATION = float(opt("--duration", "0"))
SLEEP = float(opt("--sleep", "0.5"))
OUT = opt("--out", "")
if not STATE:
    raise SystemExit("必须显式给 --state-dir（探针拒绝猜生产路径）")


def http(method, path, body=None, headers=None, timeout=15):
    h = {"Content-Type": "application/json"}
    if TOKEN:
        h["Authorization"] = "Bearer " + TOKEN
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, str(e).encode()


def api_origin():
    # 写端点要过 CSRF/同源：Origin 必须与 api.host 一致。
    return API


def revision():
    c, b = http("GET", "/api/status")
    try:
        return (json.loads(b).get("state_persist") or {}).get("revision")
    except Exception:
        return None


def disk_value():
    try:
        return json.load(io.open(CFG, encoding="utf-8")).get("cache_size")
    except Exception:
        return None


def tear_check():
    """state_dir/commit.json 的 parts 摘要自洽性。返回 (ok, detail)。"""
    p = os.path.join(STATE, "commit.json")
    if not os.path.isfile(p):
        return True, "no-commit-yet"
    try:
        c = json.load(io.open(p, encoding="utf-8"))
    except Exception as e:
        return False, "commit-unparseable:%s" % e
    parts = c.get("parts") or []
    for part in parts:
        rel = part.get("path") or ""
        want = (part.get("sha256") or "").lower()
        if not rel:
            continue
        full = rel if os.path.isabs(rel) else os.path.join(STATE, rel)
        if not os.path.isfile(full):
            return False, "missing-part:%s" % rel
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if want and h.hexdigest() != want:
            return False, "sha-mismatch:%s" % rel
    return True, "ok(%d parts)" % len(parts)


R = {
    "api": API,
    "state_dir": STATE,
    "cfg": CFG,
    "dns_port": DNS_PORT,
    "rounds_target": ROUNDS,
    "duration_target_s": DURATION,
    "per_round": [],
    "anomalies": [],
    "tear_events": [],
    "written": [],
}

# 先建立 revision（首次 PUT 会创建 commit.json）。
cur = disk_value()
if cur is None:
    raise SystemExit("读不到 --cfg 的 cache_size：%s" % CFG)
code, body = http("PUT", "/api/config", {"cache_size": cur}, {"Origin": api_origin()})
if code != 200:
    raise SystemExit("初始化 PUT 失败：%s %s" % (code, body[:200]))

ok = conflict = other = 0
t0 = time.time()
i = 0
while True:
    done_enough = i >= ROUNDS and (time.time() - t0) >= DURATION
    if done_enough:
        break
    rev = revision()
    base = 100000 + i * 2
    res = {}
    barrier = threading.Barrier(2)

    def writer(tag, v):
        barrier.wait()
        res[tag] = http(
            "PUT",
            "/api/config",
            {"cache_size": v},
            {"Origin": api_origin(), "if-revision": str(rev)},
        )

    ts = [
        threading.Thread(target=writer, args=("a", base)),
        threading.Thread(target=writer, args=("b", base + 1)),
    ]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    codes = {k: v[0] for k, v in res.items()}
    wins = [k for k, c in codes.items() if c == 200]
    loses = [k for k, c in codes.items() if c == 409]
    rec = {"round": i, "rev_in": rev, "codes": codes, "winner": wins[0] if len(wins) == 1 else None}
    if len(wins) == 1 and len(loses) == 1:
        ok += 1
        conflict += 1
        R["written"].append(base if wins[0] == "a" else base + 1)
    else:
        other += 1
        R["anomalies"].append(rec)
        print("  round %d ANOMALY codes=%s" % (i, codes))
    if i % 5 == 0:
        tok, detail = tear_check()
        if not tok:
            R["tear_events"].append({"round": i, "detail": detail})
            print("  round %d TEAR: %s" % (i, detail))
    R["per_round"].append(rec)
    i += 1
    if i % 50 == 0:
        print("  ... %d rounds  ok=%d conflict=%d other=%d elapsed=%.1fs" % (i, ok, conflict, other, time.time() - t0))
    if SLEEP > 0:
        time.sleep(SLEEP)

final_rev = revision()
tok, detail = tear_check()
if not tok:
    R["tear_events"].append({"round": i, "detail": detail})
dv = disk_value()
R.update(
    {
        "rounds_done": i,
        "ok": ok,
        "conflict": conflict,
        "other": other,
        "final_revision": final_rev,
        "disk_cache_size": dv,
        "lost_update": dv not in R["written"],
        "tear": len(R["tear_events"]),
        "elapsed_s": round(time.time() - t0, 3),
    }
)
R["all_pass"] = (
    ok == i and conflict == i and other == 0 and not R["lost_update"] and R["tear"] == 0
)
print()
print("rounds done               = %d" % i)
print("ok(=200 winners)          = %d" % ok)
print("conflict(=409 losers)     = %d" % conflict)
print("other(500/-1/2xx!=1)      = %d" % other)
print("disk cache_size           = %r (written set?)" % dv)
print("LOST_UPDATE               = %d" % (1 if R["lost_update"] else 0))
print("TEAR                      = %d" % R["tear"])
print("final revision            = %r" % final_rev)
print("elapsed                   = %.1fs" % R["elapsed_s"])
print("CONC50_VERDICT=%s" % ("ALL_PASS" if R["all_pass"] else "HAS_FAIL"))
if OUT:
    with io.open(OUT, "w", encoding="utf-8") as fh:
        json.dump(R, fh, ensure_ascii=False, indent=1)
sys.exit(0 if R["all_pass"] else 1)
