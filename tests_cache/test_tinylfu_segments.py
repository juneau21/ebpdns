"""W-TinyLFU 三段式逻辑校验。

覆盖:
- _repartition_locked 容量比例(window 1% / probation 40% main / protected 60% main)
- 满容量下条目总数不缩水、各段不超容
- admit 准入: candidate freq >= victim freq 才替换
- promote: probation 命中晋升 protected
- demote: protected 超容队首回 probation
- 高频条目最终留在 protected
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ebpdns.cache import TinyLFUCache  # noqa: E402

NOW = 1_000_000.0


def _val(ttl=3600):
    return {"answers": [{"value": "1.2.3.4"}], "rcode": 0, "expires_at": NOW + ttl}


def check(cond, msg):
    if not cond:
        raise AssertionError("FAIL: " + msg)
    print("  ok - " + msg)


def test_repartition():
    print("[test_repartition]")
    c = TinyLFUCache(1024)
    s = c.summary()
    win, prob, prot = c._win_cap, c._prob_cap, c._prot_cap
    # window 1% = max(16, 10) = 16
    check(win == 16, "win_cap=%d == 16" % win)
    main = 1024 - win
    # probation 40% of main = 403, protected 60% = 605
    check(prob == main * 2 // 5, "prob_cap=%d == %d (40%% main)" % (prob, main * 2 // 5))
    check(prot == main - prob, "prot_cap=%d == %d (60%% main)" % (prot, main - prob))
    check(win + prob + prot == 1024, "win+prob+prot=%d == cap 1024" % (win + prob + prot))
    check(s["window"] <= win and s["probation"] <= prob and s["protected"] <= prot,
          "empty summary within caps: %s" % s)
    print("  repartition OK\n")


def test_full_no_shrink():
    print("[test_full_no_shrink]")
    cap = 1024
    c = TinyLFUCache(cap)
    for i in range(cap):
        c.put(("d%05d.com" % i, "A"), _val(), now=NOW)
    check(len(c) == cap, "after fill len=%d == %d" % (len(c), cap))
    s = c.summary()
    check(s["window"] <= c._win_cap, "window %d <= %d" % (s["window"], c._win_cap))
    check(s["probation"] <= c._prob_cap, "probation %d <= %d" % (s["probation"], c._prob_cap))
    check(s["protected"] <= c._prot_cap, "protected %d <= %d" % (s["protected"], c._prot_cap))
    # 稳态继续写 2000 个新 key, 总数不应缩水超过极少, 各段不超容
    for i in range(cap, cap + 2000):
        c.put(("d%05d.com" % i, "A"), _val(), now=NOW)
    check(len(c) == cap, "steady-state len=%d == %d (no shrink)" % (len(c), cap))
    s = c.summary()
    check(s["window"] <= c._win_cap + 1, "window steady %d" % s["window"])
    check(s["probation"] <= c._prob_cap + 1, "probation steady %d" % s["probation"])
    check(s["protected"] <= c._prot_cap + 1, "protected steady %d" % s["protected"])
    print("  no-shrink OK\n")


def test_promote_demote():
    """确定性验证: probation 命中晋升 protected; protected 满则队首挤回 probation。"""
    print("[test_promote_demote]")
    c = TinyLFUCache(256)
    # 直接把一条目标 key 注入 probation
    target = ("promote.com", "A")
    c._probation[target] = _val()
    # 把 protected 填满到容量
    for i in range(c._prot_cap):
        c._protected[("prot%03d.com" % i, "A")] = _val()
    head_before = next(iter(c._protected))  # protected 队首(最久未用)
    check(target not in c._protected, "target initially not protected")
    # 命中 target: 应从 probation 晋升 protected, 同时把 protected 队首挤回 probation
    e = c.get(target, now=NOW)
    check(e is not None, "probation hit returns entry")
    check(target in c._protected, "target promoted to protected")
    check(target not in c._probation, "target removed from probation")
    check(head_before not in c._protected, "protected head evicted by promotion")
    check(head_before in c._probation, "evicted head lands back in probation")
    check(len(c._protected) <= c._prot_cap, "protected not over cap after promotion (%d)"
          % len(c._protected))
    print("  protected=%d/%d, demoted head=%s OK" % (len(c._protected), c._prot_cap, head_before))
    print("  promote/demote OK\n")


def test_admission_decision():
    """candidate freq >= victim freq 才替换; 低频 candidate 被拒。"""
    print("[test_admission_decision]")
    cap = 128
    c = TinyLFUCache(cap)
    # 用一条高频 victim 占位 probation
    victim = ("victim.com", "A")
    # 先填满足量
    for i in range(cap):
        c.put(("cold%04d.com" % i, "A"), _val(), now=NOW)
    # 反复访问 victim 使其 freq 很高, 并确保它停在 probation 队首附近
    for _ in range(30):
        c.put(victim, _val(), now=NOW)
        c.get(victim, now=NOW)
    # 此时 victim freq 很高。灌入一个全新低频 candidate: 它 freq=1, 应被拒绝准入
    victim_freq_before = c._sketch.freq(victim)
    candidate = ("brandnew-lowfreq.com", "A")
    c.put(candidate, _val(), now=NOW)
    c.put(("brandnew-lowfreq2.com", "A"), _val(), now=NOW)
    c.put(("brandnew-lowfreq3.com", "A"), _val(), now=NOW)
    # candidate 是低频新条目, 不会把高频 victim 淘汰出去
    check(c.get(victim, now=NOW) is not None,
          "high-freq victim survives low-freq candidate (freq=%d before, victim still alive)"
          % victim_freq_before)
    check(victim in c._window or victim in c._probation or victim in c._protected,
          "victim retained in some segment")
    check(c._sketch.freq(victim) >= victim_freq_before, "victim freq preserved")
    print("  admission OK\n")


def test_high_freq_stays_protected():
    """交替: 热键访问 + 冷数据冲刷, 热键被挤出 window 到 probation 后再次命中晋升 protected,
    最终冷洪峰下仍留存。"""
    print("[test_high_freq_stays_protected]")
    cap = 512
    c = TinyLFUCache(cap)
    hot = [("hot%02d.com" % i, "A") for i in range(10)]
    cold_i = 0
    for _ in range(30):
        for k in hot:
            c.put(k, _val(), now=NOW)
            c.get(k, now=NOW)
        # 冷数据冲刷, 把热键从 window 挤到 probation
        for _ in range(40):
            c.put(("cold%06d.com" % cold_i, "A"), _val(), now=NOW)
            cold_i += 1
    # 再来一波冷洪峰
    for i in range(cap * 2):
        c.put(("flood%05d.com" % i, "A"), _val(), now=NOW)
    alive = sum(1 for k in hot if c.get(k, now=NOW) is not None)
    check(alive >= 9, "hot keys survived cold flood: %d/10" % alive)
    in_prot = sum(1 for k in hot if k in c._protected)
    check(in_prot >= 7, "hot keys in protected after flood: %d/10" % in_prot)
    print("  high-freq retention OK\n")


def test_expired_lazy():
    print("[test_expired_lazy]")
    c = TinyLFUCache(64)
    c.put(("short.com", "A"), {"answers": [], "rcode": 0, "expires_at": NOW + 10}, now=NOW)
    check(c.get(("short.com", "A"), now=NOW) is not None, "fresh hit")
    check(c.get(("short.com", "A"), now=NOW + 100) is None, "expired returns None")
    check(("short.com", "A") not in c._protected and ("short.com", "A") not in c._window
          and ("short.com", "A") not in c._probation, "expired lazily removed")
    print("  expired lazy OK\n")


if __name__ == "__main__":
    test_repartition()
    test_full_no_shrink()
    test_promote_demote()
    test_admission_decision()
    test_high_freq_stays_protected()
    test_expired_lazy()
    print("ALL SEGMENT TESTS PASSED")
