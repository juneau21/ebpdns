#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""接口键集门禁（**2.1.30 / 第 10 道门**）。

从 `web/INTERFACE.md` 的**标记块**解析交付契约，再与**隔离实例的实际响应**逐键比对：

  * `<!-- STATUS_KEYS_BEGIN --> … <!-- STATUS_KEYS_END -->`   ↔ `/api/status` 顶层键
  * `<!-- COUNTERS_KEYS_BEGIN --> … <!-- COUNTERS_KEYS_END -->` ↔ `/api/status.counters`
  * `<!-- METRICS_BEGIN --> … <!-- METRICS_END -->`            ↔ `/metrics` 的 `# HELP` family
  * `cache.persist` 字段字典的表格行                            ↔ `/api/status.cache.persist`
  * `Pipeline{…}` 的 8 个字段                                   ↔ `/api/pipeline`
  * qtype 表格的 20 型 / 12 类                                  ↔ `ebpdns_proto::constants`

判定：
  * 集合不一致（多/少一个键、改名）⇒ rc=1；
  * 文档声明的数字（35 / 34 / 14 / 8 / 45 / 20 / 12）与实际不符 ⇒ rc=1。

实例来源（按顺序）：
  1. `--api URL --token T` 或环境变量 `EBP_INTERFACE_API` / `EBP_INTERFACE_TOKEN`；
  2. `--bin PATH` / `EBP_BIN` / `<tree>/target/{release,debug}/ebpdns`：
     自动拉起**临时实例**（私有 `--state-dir` + 临时端口 + 本地假上游用于暖机）；
  3. 都没有 ⇒ 打印 `INTERFACE_KEYS=SKIP`，rc=0（缺夹具时不冒充绿，也不假红）。

用法：
    python3 scripts/_interface_keys.py <tree-root>
    python3 scripts/_interface_keys.py <tree-root> --api http://127.0.0.1:18453 --token TOKEN
    python3 scripts/_interface_keys.py <tree-root> --selftest
"""
import io
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

TWO_LAZY = ("ebpdns_upstream_latency_ms", "ebpdns_upstream_latency_ms_quantile")


def read(root, rel):
    with io.open(os.path.join(root, rel.replace("/", os.sep)), encoding="utf-8") as fh:
        return fh.read()


def marker(text, name):
    m = re.search(
        r"<!--\s*%s_BEGIN\s*-->(.*?)<!--\s*%s_END\s*-->" % (name, name),
        text,
        re.S,
    )
    if not m:
        return None
    return [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]


def count_claim(text, pat, label):
    m = re.search(pat, text, re.S)
    if not m:
        raise SystemExit("  FAIL  文档里找不到计数声明：%s（正则 %s）" % (label, pat))
    return int(m.group(1))


def persist_keys(text):
    """从 `cache.persist` 字段字典的两张表里取第一列键名。"""
    start = text.index("### `/api/status.cache.persist`")
    end = text.index("**配置页两种空态文案", start)
    body = text[start:end]
    keys = re.findall(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|", body, re.M)
    # 表格行里只有字段名在第一列；去重保序
    seen = []
    for k in keys:
        if k not in seen:
            seen.append(k)
    return seen


def pipeline_fields(text):
    """解析 `Pipeline{...}`（去掉嵌套 `PipeUpstream{...}`）的顶层字段名。"""
    m = re.search(r"`Pipeline\{([^`]+)\}`", text)
    if not m:
        return None
    s = m.group(1)
    out, buf, depth = [], [], 0
    for ch in s:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if "".join(buf).strip():
        out.append("".join(buf))
    fields = []
    for f in out:
        name = f.split(":", 1)[0].strip()
        if name:
            fields.append(name)
    return fields


def constants_qtypes(root):
    """从 `crates/ebpdns-proto/src/constants.rs` 取受理/拒绝名单。"""
    src = read(root, "crates/ebpdns-proto/src/constants.rs")
    m = re.search(r"pub const SUPPORTED_QTYPES[^=]*=\s*&\[(.*?)\];", src, re.S)
    supported = re.findall(r'\(TYPE_[A-Z0-9_]+,\s*"([A-Z0-9]+)"\)', m.group(1)) if m else []
    m2 = re.search(r"pub fn qtype_must_reject\(t: u16\) -> bool \{(.*?)\n\}", src, re.S)
    reject = []
    if m2:
        body = m2.group(1)
        if re.search(r"t\s*==\s*0", body):
            reject.append("TYPE0")
        mm = re.search(r"matches!\(\s*t,(.*?)\)", body, re.S)
        if mm:
            for tok in re.findall(r"TYPE_[A-Z0-9_]+", mm.group(1)):
                name = tok[len("TYPE_"):]
                if name not in reject:
                    reject.append(name)
    return supported, reject


# ---------------------------------------------------------------------------------------------
# 取实际响应
# ---------------------------------------------------------------------------------------------
def http_json(api, token, path):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(api.rstrip("/") + path, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def http_text(api, token, path):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(api.rstrip("/") + path, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakeUpstream(threading.Thread):
    """最小 UDP DNS 上游：给任意 A 查询回一条 A 记录，用于触发上游延迟 family。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.stop = False

    def run(self):
        self.sock.settimeout(0.5)
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 12:
                continue
            qend = 12
            while qend < len(data) and data[qend] != 0:
                qend += data[qend] + 1
            qend += 5
            qtype = struct.unpack(">H", data[qend - 4:qend - 2])[0] if qend >= 14 else 1
            question = data[12:qend]
            an = b""
            ancount = 0
            if qtype == 1:
                rdata = socket.inet_aton("9.9.9.9")
                an = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + rdata
                ancount = 1
            resp = struct.pack(
                ">HHHHHH", int.from_bytes(data[:2], "big"), 0x8180, 1, ancount, 0, 0
            ) + question + an
            try:
                self.sock.sendto(resp, addr)
            except OSError:
                pass

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def dns_query(port, qtype=1):
    name = b"\x08iface-p\x04test\x00"
    pkt = struct.pack(">HHHHHH", 0x2301, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        s.recvfrom(4096)
    except OSError:
        pass
    finally:
        s.close()


class Spawned(object):
    def __init__(self, bin_path):
        self.dir = tempfile.mkdtemp(prefix="ifacekeys-")
        self.bin = bin_path
        self.proc = None
        self.up = None
        self.api_port = free_port()
        self.dns_port = free_port(socket.SOCK_DGRAM)
        self.up_port = free_port(socket.SOCK_DGRAM)
        self.token = "m230iface"
        self.api = "http://127.0.0.1:%d" % self.api_port

    def start(self):
        self.up = FakeUpstream(self.up_port)
        self.up.start()
        cfg = {
            "api": {"host": "127.0.0.1", "port": self.api_port, "token": self.token},
            "listen": {
                "udp": "127.0.0.1:%d" % self.dns_port,
                "tcp": "127.0.0.1:%d" % self.dns_port,
                "udp6": "",
                "tcp6": "",
            },
            "dns_port": self.dns_port,
            "web_root": "",
            "cache_size": 256,
            "cache_policy": "tinylfu",
            "cache_persist": False,
            "cache_file": os.path.join(self.dir, "cache.json"),
            "state_dir": os.path.join(self.dir, "state"),
            "state_persist": True,
            "prefetch": False,
            "speed_test": False,
            "warmup": {"enabled": False, "queries": 0, "timeout_ms": 500},
            "serve_stale": False,
            "health_check_interval": 3600,
            "rule_subscriptions": [],
            "rules": [],
            "upstreams": [
                {
                    "id": "iface-fake",
                    "name": "iface-fake",
                    "proto": "udp",
                    "host": "127.0.0.1",
                    "addr": "127.0.0.1",
                    "port": self.up_port,
                    "url": "",
                    "group": "domestic",
                    "enabled": True,
                }
            ],
            "log_level": "warn",
            "log_format": "plain",
        }
        os.makedirs(os.path.join(self.dir, "state"))
        cfg_path = os.path.join(self.dir, "config.json")
        with io.open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False)
        log = open(os.path.join(self.dir, "ebpdns.log"), "wb")
        self.proc = subprocess.Popen(
            [self.bin, "--config", cfg_path, "--state-dir", cfg["state_dir"], "--foreground"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                h = http_json(self.api, self.token, "/api/health")
                if h.get("running"):
                    break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("临时实例未在 15s 内就绪（日志 %s/ebpdns.log）" % self.dir)
        # 暖机：一条 A 查询，触发上游 RTT 样本
        dns_query(self.dns_port, 1)
        time.sleep(0.5)
        return self.api, self.token

    def stop(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        if self.up is not None:
            self.up.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def find_bin(root, explicit):
    for p in (
        explicit,
        os.environ.get("EBP_BIN"),
        os.path.join(root, "target", "release", "ebpdns"),
        os.path.join(root, "target", "debug", "ebpdns"),
    ):
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    for base in ("dist-packages",):
        d = os.path.join(root, base)
        if os.path.isdir(d):
            for n in sorted(os.listdir(d)):
                cand = os.path.join(d, n, "bin", "ebpdns")
                if os.path.isfile(cand):
                    return cand
    return None


# ---------------------------------------------------------------------------------------------
# 断言
# ---------------------------------------------------------------------------------------------
def diff_set(label, doc, live):
    doc, live = set(doc), set(live)
    return [
        "%s: 文档多 %s" % (label, sorted(doc - live)),
        "%s: 文档少 %s" % (label, sorted(live - doc)),
    ] if doc != live else []


def main():
    args = sys.argv[1:]
    tree = None
    api = os.environ.get("EBP_INTERFACE_API")
    token = os.environ.get("EBP_INTERFACE_TOKEN", "")
    bin_path = None
    selftest = "--selftest" in args
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--api" and i + 1 < len(args):
            api = args[i + 1]
            i += 2
            continue
        if a == "--token" and i + 1 < len(args):
            token = args[i + 1]
            i += 2
            continue
        if a == "--bin" and i + 1 < len(args):
            bin_path = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if tree is None:
            tree = a
        i += 1
    tree = os.path.abspath(tree or ".")
    doc = read(tree, "web/INTERFACE.md")

    status_keys = marker(doc, "STATUS_KEYS")
    counter_keys = marker(doc, "COUNTERS_KEYS")
    rules_keys = marker(doc, "RULES_KEYS")
    metric_names = marker(doc, "METRICS")
    persist = persist_keys(doc)
    pipeline = pipeline_fields(doc)
    supported, reject = constants_qtypes(tree)
    if (
        status_keys is None
        or counter_keys is None
        or rules_keys is None
        or metric_names is None
        or not persist
        or not pipeline
    ):
        print("  FAIL  INTERFACE.md 缺少键集标记块或字段表")
        print("INTERFACE_KEYS=FAIL")
        return 1

    c_status = count_claim(doc, r"顶层字段（\*\*2\.1\.30 实测：(\d+) 个键\*\*）", "status 35")
    c_counters = count_claim(doc, r"\| `counters` \| object \| 同代计数器表，\*\*(\d+) 个键\*\*", "counters 34")
    c_rules = count_claim(doc, r"三本账（\*\*2\.1\.30：(\d+) 个顶层键", "rules 6")
    c_persist = count_claim(doc, r"2\.1\.30 共 (\d+) 键", "persist 14")
        # **2.1.43-A**：版本号改为**不锁死小版本**（`2\.1\.\d+`）。2.1.42 及以前这里写死
    # `2\.1\.42`，于是"只改指标数/推进版本"时，文档已同步、脚本没同步 ⇒ 门禁报
    # "找不到计数声明"（假红）。判据本身（块行数 == 声明数）不变。
    c_metrics = count_claim(
        doc, r"指标名全表（\*\*2\.1\.\d+：(\d+) 个 HELP family\*\*）", "metrics 47"
    )
    c_pipeline = count_claim(doc, r"（\*\*(\d+) 个字段\*\*", "pipeline 8")
    c_supported = count_claim(doc, r"\*\*受理并缓存 (\d+) 型\*\*", "qtype 20")
    c_reject = count_claim(doc, r"\*\*(\d+) 类一律 `NOTIMP`\*\*", "qtype 12")

    fails = []
    if len(status_keys) != c_status:
        fails.append("status 标记块 %d 行 != 声明 %d" % (len(status_keys), c_status))
    if len(counter_keys) != c_counters:
        fails.append("counters 标记块 %d 行 != 声明 %d" % (len(counter_keys), c_counters))
    if len(rules_keys) != c_rules:
        fails.append("rules 标记块 %d 行 != 声明 %d" % (len(rules_keys), c_rules))
    if len(metric_names) != c_metrics:
        fails.append("metrics 标记块 %d 行 != 声明 %d" % (len(metric_names), c_metrics))
    if len(persist) != c_persist:
        fails.append("persist 表 %d 行 != 声明 %d" % (len(persist), c_persist))
    if len(pipeline) != c_pipeline:
        fails.append("pipeline 字段 %d 个 != 声明 %d" % (len(pipeline), c_pipeline))
    if len(supported) != c_supported:
        fails.append("constants 受理名单 %d 型 != 声明 %d" % (len(supported), c_supported))
    if len(reject) != c_reject:
        fails.append("constants 拒绝名单 %d 类 != 声明 %d" % (len(reject), c_reject))

    # 文档的 qtype 名单还必须与单一来源逐名一致（防止"数字对了、名字错了"）。
    m_sup = re.search(r"\| \*\*受理并缓存（\d+ 型）\*\* \|(.*?)\|", doc, re.S)
    if m_sup:
        cell = m_sup.group(1)
        doc_sup = []
        # 既有 9 型写成一段空格分隔的代码：`A NS CNAME …`
        for span in re.findall(r"`([A-Z][A-Z0-9 ]*)`", cell):
            doc_sup.extend(span.split())
        # 新增 11 型写成 `NAME(code)`
        doc_sup.extend(re.findall(r"`([A-Z][A-Z0-9]*)\(\d+\)`", cell))
        doc_sup = [x for x in doc_sup if x in supported]
        if sorted(set(doc_sup)) != sorted(set(supported)):
            fails.append("qtype 受理名单与 constants 不一致：doc=%s const=%s" % (sorted(set(doc_sup)), sorted(set(supported))))
    m_rej = re.search(r"\| \*\*一律拒绝（NOTIMP，\d+ 类）\*\* \|(.*?)\|", doc, re.S)
    if m_rej:
        cell = m_rej.group(1)
        doc_rej = re.findall(r"`([A-Z][A-Z0-9]*)\(\d+\)`", cell)
        doc_rej += re.findall(r"`(TYPE\d+)`", cell)
        doc_rej = [x for x in doc_rej if x in reject]
        if sorted(set(doc_rej)) != sorted(set(reject)):
            fails.append("qtype 拒绝名单与 constants 不一致：doc=%s const=%s" % (sorted(set(doc_rej)), sorted(set(reject))))

    # ---- 实际响应 ----
    spawned = None
    try:
        if not api:
            bin_path = find_bin(tree, bin_path)
            if not bin_path:
                print("  SKIP  未发现可执行二进制（target/{release,debug}/ebpdns / EBP_BIN / --bin）")
                print("  SKIP  （源码包树按设计没有构建产物；有二进制时本门禁严格执行）")
                print("INTERFACE_KEYS=SKIP")
                return 0
            print("  启动临时隔离实例：%s" % bin_path)
            spawned = Spawned(bin_path)
            api, token = spawned.start()
        status = http_json(api, token, "/api/status")
        pipeline_live = http_json(api, token, "/api/pipeline")
        rules_live = http_json(api, token, "/api/rules")
        metrics_text = http_text(api, token, "/metrics")
    finally:
        if spawned is not None:
            spawned.stop()

    live_status = set(status.keys())
    live_counters = set(status.get("counters", {}).keys())
    live_persist = set(status.get("cache", {}).get("persist", {}).keys())
    live_pipeline = set(pipeline_live.keys())
    live_rules = set(rules_live.keys())
    live_metrics = set(
        ln.split()[2] for ln in metrics_text.splitlines() if ln.startswith("# HELP ")
    )

    fails += diff_set("status", status_keys, live_status)
    fails += diff_set("counters", counter_keys, live_counters)
    fails += diff_set("rules", rules_keys, live_rules)
    fails += diff_set("persist", persist, live_persist)
    fails += diff_set("pipeline", pipeline, live_pipeline)

    if len(live_metrics) == c_metrics:
        fails += diff_set("metrics", metric_names, live_metrics)
        metric_state = "warm=%d" % len(live_metrics)
    elif len(live_metrics) == c_metrics - len(TWO_LAZY) and all(m not in live_metrics for m in TWO_LAZY):
        expected_cold = set(metric_names) - set(TWO_LAZY)
        fails += diff_set("metrics(cold)", expected_cold, live_metrics)
        metric_state = "cold=%d (lazy: %s)" % (len(live_metrics), ",".join(TWO_LAZY))
    else:
        fails.append("metrics 实际 %d 个（期望 %d 热态 / %d 冷态）" % (len(live_metrics), c_metrics, c_metrics - len(TWO_LAZY)))
        metric_state = "actual=%d" % len(live_metrics)

    print("  文档声明：status=%d counters=%d rules=%d persist=%d pipeline=%d metrics=%d qtype=%d/%d"
          % (c_status, c_counters, c_rules, c_persist, c_pipeline, c_metrics, c_supported, c_reject))
    print("  实际实测：status=%d counters=%d rules=%d persist=%d pipeline=%d metrics=%s"
          % (len(live_status), len(live_counters), len(live_rules), len(live_persist), len(live_pipeline), metric_state))
    if fails:
        for f in fails:
            print("  FAIL  " + f)
        print("INTERFACE_KEYS=FAIL (%d)" % len(fails))
        return 1
    print("INTERFACE_KEYS=PASS（status/counters/rules/persist/pipeline/metrics/qtype 全部逐键一致）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
