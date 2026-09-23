#!/usr/bin/env python3
"""
续测脚本: 完成 test_boundary_v1953.py 因 ReDoS 崩溃而未执行的测试项。
跳过 ReDoS 测试(已确认崩溃 bug), 完成规则测试和热重载测试。
"""
import json, os, socket, struct, sys, time, copy, urllib.request, urllib.error

UDP_HOST, UDP_PORT, TCP_PORT = "127.0.0.1", 15365, 15366
API = "http://127.0.0.1:18096"
CFG = "/tmp/v1931.json"
LOG = "/tmp/ebpdns_v1931.log"
RESULTS = []

def rec(cat, name, ok, detail=""):
    RESULTS.append((cat, name, ok, detail))
    print("  [%s] %s — %s" % ("PASS" if ok else "FAIL", name, detail))

def api_get(p):
    try:
        with urllib.request.urlopen(API+p, timeout=5) as r: return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try: return json.loads(e.read()), e.code
        except: return {}, e.code
    except Exception as e: return {"error": str(e)}, 0

def api_post(p, b=None):
    data = json.dumps(b or {}).encode()
    req = urllib.request.Request(API+p, data=data, headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try: return json.loads(e.read()), e.code
        except: return {}, e.code
    except Exception as e: return {"error": str(e)}, 0

def api_put(p, b=None):
    data = json.dumps(b or {}).encode()
    req = urllib.request.Request(API+p, data=data, headers={"Content-Type":"application/json"}, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        try: return json.loads(e.read()), e.code
        except: return {}, e.code
    except Exception as e: return {"error": str(e)}, 0

def alive():
    try:
        _, c = api_get("/api/status")
        return c == 200
    except: return False

def encode_name(n):
    n = n.rstrip(".")
    if not n: return b"\x00"
    out = bytearray()
    for lab in n.split("."):
        b = lab.encode("ascii", errors="replace")[:63]
        out.append(len(b)); out += b
    out.append(0)
    return bytes(out)

def q(domain="www.baidu.com", qtype=1, qid=0xABCD):
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return hdr + encode_name(domain) + struct.pack(">HH", qtype, 1)

def send_udp(data, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout); t0=time.monotonic()
    try:
        s.sendto(data, (UDP_HOST, UDP_PORT))
        r,_ = s.recvfrom(4096)
        return r, (time.monotonic()-t0)*1000
    except: return None, (time.monotonic()-t0)*1000
    finally: s.close()

def load_cfg():
    with open(CFG) as f: return json.load(f)

def save_cfg(c):
    with open(CFG, "w") as f: json.dump(c, f, ensure_ascii=False, indent=2)


print("=" * 60)
print("续测: 规则极端值(续) + 配置热重载")
print("=" * 60)

orig = load_cfg()
print("服务存活:", alive())

# ─── 规则测试续 ───
print("\n=== 4. 规则极端值(续) ===")

# 清空规则
api_put("/api/config", {"rules": []})
time.sleep(0.5)

# 4e. 非法 action
r, c = api_post("/api/rules", {"match": "bad-act-test.com", "action": "explode"})
time.sleep(0.3)
d, ms = send_udp(q("bad-act-test.com"), timeout=3.0)
rec("规则", "非法action值", alive() and c in (200,201), "HTTP=%d, 存活=%s" % (c, alive()))

# 4f. forceIp
api_post("/api/rules", {"match": "forceip-t.com", "action": "forceIp", "ip": "5.6.7.8"})
time.sleep(0.5)
d, ms = send_udp(q("forceip-t.com"), timeout=3.0)
hit = False
if d and len(d) >= 12:
    # 简单检查 answer 区是否包含 5.6.7.8
    if b"\x05\x06\x07\x08" in d:
        hit = True
rec("规则", "forceIp规则(5.6.7.8)", hit and alive(), "命中=%s, 存活=%s" % (hit, alive()))

# 4g. block
api_post("/api/rules", {"match": "block-t.com", "action": "block"})
time.sleep(0.5)
d, ms = send_udp(q("block-t.com"), timeout=3.0)
rcode = d[3] & 0x0F if d and len(d) >= 12 else None
rec("规则", "block action(SERVFAIL)", rcode == 2 and alive(), "rcode=%s(预期2)" % rcode)

# 4h. allow
api_post("/api/rules", {"match": "allow-t.com", "action": "allow"})
time.sleep(0.5)
d, ms = send_udp(q("allow-t.com"), timeout=5.0)
rec("规则", "allow action", alive(), "响应=%s, 存活=%s" % ("有" if d else "无", alive()))

# 4i. group
api_post("/api/rules", {"match": "group-t.com", "action": "group", "group": "domestic"})
time.sleep(0.5)
d, ms = send_udp(q("group-t.com"), timeout=5.0)
rec("规则", "group action", alive(), "响应=%s, 存活=%s" % ("有" if d else "无", alive()))

# 4d. 重复规则
api_post("/api/rules", {"match": "dup-t.com", "action": "block"})
api_post("/api/rules", {"match": "dup-t.com", "action": "allow"})
time.sleep(0.5)
d, ms = send_udp(q("dup-t.com"), timeout=5.0)
rec("规则", "重复规则(block后allow)", alive(), "响应=%s, 存活=%s" % ("有" if d else "无", alive()))

# 清理规则
api_put("/api/config", {"rules": []})
time.sleep(0.3)

# ─── 热重载测试 ───
print("\n=== 5. 配置热重载极端 ===")

# 5a. 空配置 {}
try:
    save_cfg({})
    r, c = api_post("/api/reload")
    time.sleep(0.5)
    a = alive()
    rec("热重载", "空配置{}", a, "reload=%s, 存活=%s" % (str(r)[:80], a))
except Exception as e:
    rec("热重载", "空配置{}", False, "异常: %r" % e)
finally:
    save_cfg(orig); api_post("/api/reload"); time.sleep(1.0)

# 5b. 缺失 upstreams
try:
    bad = copy.deepcopy(orig); del bad["upstreams"]
    save_cfg(bad)
    r, c = api_post("/api/reload")
    time.sleep(0.5)
    a = alive()
    d, _ = send_udp(q("nostream.com"), timeout=3.0)
    rec("热重载", "缺失upstreams", a and alive(), "存活=%s" % alive())
except Exception as e:
    rec("热重载", "缺失upstreams", False, "异常: %r" % e)
finally:
    save_cfg(orig); api_post("/api/reload"); time.sleep(1.0)

# 5c. 端口为字符串
try:
    bad = copy.deepcopy(orig)
    bad["listen"]["udp"] = "127.0.0.1:notaport"
    save_cfg(bad)
    r, c = api_post("/api/reload")
    time.sleep(0.5)
    rec("热重载", "端口字符串", alive(), "存活=%s" % alive())
except Exception as e:
    rec("热重载", "端口字符串", False, "异常: %r" % e)
finally:
    save_cfg(orig); api_post("/api/reload"); time.sleep(1.0)

# 5d. 上游地址非法
try:
    bad = copy.deepcopy(orig)
    bad["upstreams"] = [{"id":"x1","name":"Bad","proto":"udp","addr":"not.an.ip","port":53,"group":"domestic","enabled":True}]
    save_cfg(bad)
    r, c = api_post("/api/reload")
    time.sleep(0.5)
    d, _ = send_udp(q("badup.com"), timeout=5.0)
    rec("热重载", "上游地址非法", alive(), "存活=%s, 响应=%s" % (alive(), "有" if d else "无"))
except Exception as e:
    rec("热重载", "上游地址非法", False, "异常: %r" % e)
finally:
    save_cfg(orig); api_post("/api/reload"); time.sleep(1.0)

# 5e. 重复上游 ID
try:
    bad = copy.deepcopy(orig)
    bad["upstreams"] = [
        {"id":"dup","name":"A","proto":"udp","addr":"223.5.5.5","port":53,"group":"domestic","enabled":True},
        {"id":"dup","name":"B","proto":"udp","addr":"119.29.29.29","port":53,"group":"domestic","enabled":True},
    ]
    save_cfg(bad)
    r, c = api_post("/api/reload")
    time.sleep(0.5)
    d, _ = send_udp(q("dupid.com"), timeout=5.0)
    rec("热重载", "重复上游ID", alive(), "存活=%s" % alive())
except Exception as e:
    rec("热重载", "重复上游ID", False, "异常: %r" % e)
finally:
    save_cfg(orig); api_post("/api/reload"); time.sleep(1.0)

# 5f. cache_size 字符串(文件reload)
try:
    bad = copy.deepcopy(orig); bad["cache_size"] = "50000"
    save_cfg(bad)
    r, c = api_post("/api/reload")
    time.sleep(0.5)
    rec("热重载", "cache_size字符串", alive(), "存活=%s" % alive())
except Exception as e:
    rec("热重载", "cache_size字符串", False, "异常: %r" % e)
finally:
    save_cfg(orig); api_post("/api/reload"); time.sleep(1.0)

# ─── 日志检查 ───
print("\n=== 日志检查 ===")
try:
    with open(LOG, errors="replace") as f:
        lines = f.readlines()
    errs = [(i+1, l.rstrip()) for i,l in enumerate(lines)
            if any(k in l.upper() for k in ("ERROR","EXCEPTION","TRACEBACK"))]
    if errs:
        rec("日志", "错误扫描", False, "发现 %d 条" % len(errs))
        for ln, t in errs[-10:]:
            print("    L%d: %s" % (ln, t[:200]))
    else:
        rec("日志", "错误扫描", True, "无 ERROR/Exception/Traceback")
except Exception as e:
    rec("日志", "错误扫描", False, "无法读取: %r" % e)

# ─── 汇总 ───
print("\n" + "=" * 60)
total = len(RESULTS)
p = sum(1 for r in RESULTS if r[2])
print("续测: %d项 | 通过:%d | 失败:%d" % (total, p, total-p))
for cat, name, ok, detail in RESULTS:
    print("  [%s] [%s] %s" % ("PASS" if ok else "FAIL", cat, name))
print("服务存活:", alive())
