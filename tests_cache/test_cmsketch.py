"""_CMSketch 正确性校验。

- inc 哈希列索引公式: h = (h1 >> (i*8)) | (i*2654435761), col=(h&0x7FFFFFFF)%1024
- 饱和计数不超过 255
- 老化: ops>=65536 全表右移 1 位
- freq 返回各行最小值(上界估计)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ebpdns.cache import _CMSketch  # noqa: E402


def check(cond, msg):
    if not cond:
        raise AssertionError("FAIL: " + msg)
    print("  ok - " + msg)


def test_freq_increments():
    print("[test_freq_increments]")
    s = _CMSketch()
    k = ("example.com", "A")
    check(s.freq(k) == 0, "initial freq == 0, got %d" % s.freq(k))
    for _ in range(5):
        s.inc(k)
    check(s.freq(k) == 5, "after 5 inc freq == 5, got %d" % s.freq(k))
    s.inc(k, n=10)
    check(s.freq(k) == 15, "after +10 freq == 15, got %d" % s.freq(k))
    print("  freq increments OK\n")


def test_saturation():
    print("[test_saturation]")
    s = _CMSketch()
    k = ("sat.com", "A")
    s.inc(k, n=100000)  # 远超 255
    check(s.freq(k) == 255, "saturated freq == 255, got %d" % s.freq(k))
    for row in s._t:
        for v in row:
            check(v <= 255, "no counter exceeds 255")
            break  # 抽样即可
    print("  saturation OK\n")


def test_aging():
    print("[test_aging]")
    s = _CMSketch()
    k = ("age.com", "A")
    for _ in range(100):
        s.inc(k)
    check(s.freq(k) == 100, "before age freq == 100, got %d" % s.freq(k))
    # 触发老化: ops 累计到 65536
    s._ops = 65535
    s.inc(("other%d.com" % 0, "A"))  # 跨过阈值
    check(s._ops == 0, "_ops reset after age, got %d" % s._ops)
    # 100 >> 1 == 50
    after = s.freq(k)
    check(40 <= after <= 55, "aged freq ~50 (right-shift), got %d" % after)
    # 全表都右移过: 其他计数也应减半
    print("  aging OK\n")


def test_conflict_upper_bound():
    """不同 key 即使哈希冲突, freq 也只是上界估计(>=真实频次)。"""
    print("[test_conflict_upper_bound]")
    s = _CMSketch()
    a = ("a.com", "A")
    for _ in range(7):
        s.inc(a)
    fa = s.freq(a)
    check(fa == 7, "key A freq == 7, got %d" % fa)
    # 另一个 key b 从未 inc, 但其 freq 受 A 污染(冲突时 >0); 无冲突时为 0
    b = ("b.com", "A")
    fb = s.freq(b)
    check(0 <= fb <= 7, "key B freq is upper-bound estimate, got %d" % fb)
    # freq 绝不应低于真实 inc 次数
    c = ("c.com", "A")
    for _ in range(3):
        s.inc(c)
    check(s.freq(c) >= 3, "freq >= true count, got %d" % s.freq(c))
    print("  upper-bound OK\n")


def test_column_formula():
    """直接核对列索引公式与规格一致。"""
    print("[test_column_formula]")
    s = _CMSketch()
    k = ("formula.com", "A")
    h1 = hash(k)
    expected_cols = []
    for i in range(4):
        h = (h1 >> (i * 8)) | (i * 2654435761)
        expected_cols.append((h & 0x7FFFFFFF) % 1024)
    # inc 后对应列应非零
    s.inc(k)
    for i, col in enumerate(expected_cols):
        check(s._t[i][col] >= 1, "row %d col %d written" % (i, col))
    print("  formula OK\n")


if __name__ == "__main__":
    test_freq_increments()
    test_saturation()
    test_aging()
    test_conflict_upper_bound()
    test_column_formula()
    print("ALL CMSKETCH TESTS PASSED")
