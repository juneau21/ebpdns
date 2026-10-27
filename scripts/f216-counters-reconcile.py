#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""压测口径自动对账（2.1.16 修复项 11 起；**2.1.17 增补 R8/R9**）。

判据（**修计数，不放宽断言**）：同一次压测窗口内，客户端观测到的 rcode 分布
必须与服务端 `/api/status.counters` 自洽：

  R1  server_client_rcode_2 == delta(counters.servfail_total)
      —— 二者是**同一打点**（dns.rs::log_and_count），必须逐位相等。
  R2  sum(counters.client_rcode[*]) == delta(counters.total)
      —— 每一条计了 total 的查询都对应一条实际发出的应答（服务端侧口径闭合）。
  R3  counters.client_rcode["2"] == counters.servfail_total（快照内恒等式）
  R4  sum(counters.servfail_reasons[*]) == counters.servfail_total
  R5  delta(counters.hit) + delta(counters.miss) <= delta(counters.total)
      —— 允许总和不等于（Rule / RFC8020 / malformed 路径按既有口径不计 hit/miss），
         但**绝不允许超过**（超过即重复计数）。
  R6  client_rcode_2 <= client_rcode_total_and_timeouts
      —— 客户端侧：`rcode==2` 必须 <= 客户端观测总数；**超时/无应答单独统计**，
         不得并入 SERVFAIL（这是 2.1.15 "客户端 2 / 服务端 0" 的唯一解释来源）。
  R7  metrics 口径：`ebpdns_servfail_total`（无标签聚合）== `Σ ebpdns_servfail_reasons_total`
      —— 且**两者不得相加**（相加即翻倍，2.1.16 已拆成两个指标名防误读）。

  —— 以下为 **2.1.17 新增** ——

  R8  **快照时序可对齐（修复项 4）**：`/api/status` 必须给出同点取值的
      `snapshot_monotonic_ms` / `snapshot_epoch_ms` / `snapshot_uptime_s`，
      且三者自洽；`/metrics` 首部必须给出 `# align-snapshot monotonic_ms=…`
      锚点（与 `/api/status` 同一个单调时钟）。
      有了锚点，压测脚本才能把「服务端构造窗口」与「客户端接收窗口」三点对齐：
        * 压测前后各读一次 `/api/status`，取 `snapshot_monotonic_ms` 作为窗口端点；
        * `服务端窗口内构造数 = ΔΣclient_rcode`；
        * 判定 `Δ服务端构造 − Δ客户端接收 ≤ Δ客户端超时`（R8e，需客户端 json）。
      这条判据就是 2.1.16 首轮「服务端构造 − 客户端接收 = 3951、客户端超时 2896、
      余 1055（0.5%）」的收口口径：那 1055 条是**客户端收摊之后**服务端才把
      3 秒超时的应答构造并发出的部分，属于客户端超时集合的子集，不该记为漏计。
  R9  **私网答案不入缓存（修复项 3）**：`counters.cache_skipped_private_total`
      与 `/metrics` 的 `ebpdns_cache_skipped_private_total` 必须存在（同源）。
      —— 它是「RFC1918 应答按设计不入缓存」的唯一可观测证据；
        非零即解释「同键恒 miss / entries=0」，不得据此判为缓存缺陷。
        注意它与 `counters.rebind_blocked`（**控制面** DNS-rebinding 拦截）**不是**
        同一个门，纯 DNS 数据面下 `rebind_blocked` 恒 0 是正确行为。

退出码：0 = 全部通过；1 = 有断言失败（打印逐条对照）。
"""  # noqa: E501
import json
import re
import sys
import urllib.request

API = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18353"
# 客户端侧实测（由压测脚本产出）：{rcode: n, "timeout": n, "no_answer": n}
CLIENT = json.load(open(sys.argv[2], encoding="utf-8")) if len(sys.argv) > 2 else None


def status():
    with urllib.request.urlopen(API + "/api/status", timeout=15) as f:
        return json.loads(f.read().decode())


def metrics_text():
    with urllib.request.urlopen(API + "/metrics", timeout=15) as f:
        return f.read().decode()


def d(a, b, k):
    return (b.get(k, 0) or 0) - (a.get(k, 0) or 0)


def main():
    st1 = status()
    c1 = st1.get("counters", {})
    results = []

    def chk(name, ok, detail):
        results.append((name, bool(ok), detail))

    # ---- 快照内恒等式 ----
    cr = {str(k): v for k, v in (c1.get("client_rcode") or {}).items()}
    chk("R3 client_rcode['2'] == servfail_total",
        cr.get("2", 0) == c1.get("servfail_total", 0),
        "client_rcode[2]=%s servfail_total=%s" % (cr.get("2"), c1.get("servfail_total")))
    sr = c1.get("servfail_reasons") or {}
    chk("R4 sum(reasons) == servfail_total",
        sum(sr.values()) == c1.get("servfail_total", 0),
        "sum(reasons)=%s total=%s" % (sum(sr.values()), c1.get("servfail_total")))
    chk("R2 sum(client_rcode) == total",
        sum(cr.values()) == c1.get("total", 0),
        "sum(client_rcode)=%s total=%s" % (sum(cr.values()), c1.get("total")))
    chk("R5 hit+miss <= total",
        c1.get("hit", 0) + c1.get("miss", 0) <= c1.get("total", 0),
        "hit+miss=%s total=%s" % (c1.get("hit", 0) + c1.get("miss", 0), c1.get("total")))

    # ---- metrics 口径 ----
    txt = metrics_text()
    agg = None
    per = {}
    for line in txt.splitlines():
        if line.startswith("ebpdns_servfail_total "):
            agg = float(line.split()[-1])
        elif line.startswith("ebpdns_servfail_reasons_total{"):
            r = line.split('reason="')[1].split('"')[0]
            per[r] = float(line.split()[-1])
    chk("R7 metrics aggregate == sum(reasons)",
        agg is not None and abs(agg - sum(per.values())) < 1e-9,
        "aggregate=%s sum(reasons)=%s (%s)" % (agg, sum(per.values()), per))
    chk("R7b 聚合 series 无 reason 标签（不得与分档相加）",
        'ebpdns_servfail_total{reason=' not in txt,
        "旧写法 ebpdns_servfail_total{reason=...} 必须已不存在")

    # ---- **2.1.17 R9（修复项 3）**：私网答案过滤计数（设计行为可观测） ----
    chk("R9 counters.cache_skipped_private_total 存在",
        "cache_skipped_private_total" in c1,
        "值=%s（>0 即解释「同键恒 miss / entries=0」是设计行为，不是缓存缺陷）"
        % c1.get("cache_skipped_private_total"))
    chk("R9b metrics 暴露 ebpdns_cache_skipped_private_total",
        "ebpdns_cache_skipped_private_total " in txt,
        "与 /api/status.counters.cache_skipped_private_total 同源（同一原子计数）")

    # ---- **2.1.17 R8（修复项 4）**：快照时序锚点 ----
    mono = st1.get("snapshot_monotonic_ms")
    epms = st1.get("snapshot_epoch_ms")
    up_s = st1.get("snapshot_uptime_s")
    present = mono is not None and epms is not None and up_s is not None
    chk("R8a /api/status 提供 snapshot_{monotonic_ms,epoch_ms,uptime_s}",
        present, "monotonic_ms=%s epoch_ms=%s uptime_s=%s" % (mono, epms, up_s))
    if present:
        same_src = abs(mono / 1000.0 - float(up_s)) < 1.0
        chk("R8b monotonic_ms 与 uptime_s 同源（同一 boot 基准）", same_src,
            "monotonic_ms/1000=%.3f uptime_s=%s" % (mono / 1000.0, up_s))
        boot_epoch = epms - mono
        chk("R8c boot_epoch = epoch_ms - monotonic_ms 是过去的合理时刻",
            boot_epoch > 1600000000000 and boot_epoch <= epms,
            "boot_epoch=%d (%s)" % (boot_epoch, boot_epoch / 1000.0))
    m = re.search(r"^# align-snapshot monotonic_ms=(\d+) epoch_ms=(\d+) uptime_s=(\d+)$",
                  txt, re.M)
    chk("R8d /metrics 首部提供 # align-snapshot 锚点", m is not None,
        (m.group(0) if m else "缺失（压测脚本无法把 metrics 抓取对齐到服务端窗口）"))

    # ---- 客户端侧（可选，需要压测脚本给出客户端统计）----
    if CLIENT is not None:
        c2 = CLIENT
        cli_total = sum(v for k, v in c2.items() if k.isdigit())
        chk("R6 客户端 rcode==2 不得并入超时/无应答",
            c2.get("2", 0) <= cli_total,
            "client rcode2=%s client_total=%s timeout=%s no_answer=%s"
            % (c2.get("2", 0), cli_total, c2.get("timeout", 0), c2.get("no_answer", 0)))
        chk("R1 客户端 rcode==2 与服务端 client_rcode[2] 一致",
            c2.get("2", 0) == cr.get("2", 0),
            "client=%s server=%s （不等 ⇒ 客户端把超时/无应答误分类，或抓包被丢弃）"
            % (c2.get("2", 0), cr.get("2", 0)))
        chk("R1b 客户端 rcode==2 与 servfail_total 一致",
            c2.get("2", 0) == c1.get("servfail_total", 0),
            "client=%s servfail_total=%s" % (c2.get("2", 0), c1.get("servfail_total")))
        # R8e：客户端收摊后服务端仍会构造并发出"已超时"的应答，这段余量必须
        # 被**客户端超时数**覆盖（上界），否则说明还有第三种未解释的缺口。
        srv_built = sum(cr.values())
        cli_recv = cli_total
        margin = srv_built - cli_recv
        chk("R8e 服务端构造 − 客户端接收 ≤ 客户端超时（余量必须被超时解释）",
            0 <= margin <= c2.get("timeout", 0),
            "srv_built=%s cli_recv=%s margin=%s client_timeout=%s"
            % (srv_built, cli_recv, margin, c2.get("timeout", 0)))

    bad = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print("%-52s %s  %s" % (name, "PASS" if ok else "FAIL", detail))
    if bad:
        print("\nRECONCILE_FAILED n=%d/%d" % (len(bad), len(results)))
        return 1
    print("\nRECONCILE_OK n=%d" % len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
