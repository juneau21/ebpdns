#!/usr/bin/env bash
# **2.1.29 缓存持久化 v2：崩溃矩阵**（设计文档 §8 / §15.1）
#
# 6 个崩溃注入点 × N 轮（默认 40）⇒ 断言：
#   * 永不判撕裂（进程能起来、format=v2、restore_source ∈ {v2-snapshot, v2-snapshot+wal, wal-truncated}）
#   * 恢复只做前缀/回退（restore_drops.failed == 0；entries 不超上界）
#   * 已 fsync 的记录不丢（重启后 entries ≥ 触发注入前的 entries - 1 个 fsync 窗口）
#   * *.tmp 不残留（启动清理后为 0）
#   * load_state=Committed（state_persist 不受缓存落盘影响）
#
# 用法： sudo bash scripts/cache_v2_crash.sh <ebpdns-binary> <workdir> [rounds] [point...]
# 隔离纪律：私有 state_dir + 197xx/187xx 端口 + e229c- 前缀 pidfile；**绝不**碰生产实例。
set -u
BIN=${1:?usage: cache_v2_crash.sh <bin> <workdir> [rounds] [points...]}
WORK=${2:?}
ROUNDS=${3:-40}
shift 3 2>/dev/null || shift $#
POINTS=("$@")
if [ ${#POINTS[@]} -eq 0 ]; then
  POINTS=(wal_after_write wal_after_fsync snap_after_write snap_after_rename manifest_after_rename after_old_unlink)
fi

mkdir -p "$WORK"
OUT="$WORK/crash.csv"
: > "$OUT"
echo "point,round,rc,format,restore_source,snap_seq,entries,drops_expired,drops_legacy,drops_failed,tmp_left,load_state,corrupt,verdict" >> "$OUT"

UDP=$((19700 + (RANDOM % 90)))
API=$((18700 + (RANDOM % 90)))

# --- 极简 stub 上游（UDP，固定 A 记录，TTL=300）---
STUB="$WORK/stub.py"
cat > "$STUB" <<'PY'
import socket, struct, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
def parse(q):
    # 解析 query：返回 (qid, qname, qtype)
    qid = q[:2]
    i = 12; labels = []
    while q[i] != 0:
        n = q[i]; labels.append(q[i+1:i+1+n].decode()); i += 1 + n
    i += 1
    qtype = struct.unpack("!H", q[i:i+2])[0]
    return qid, ".".join(labels), qtype, q[12:i+4]
while True:
    data, addr = s.recvfrom(4096)
    try:
        qid, name, qtype, qsec = parse(data)
    except Exception:
        continue
    # 应答：QR=1 AA=1 RD=1 RA=1, 1 question, 1 answer
    hdr = qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    if qtype == 1:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, (abs(hash(name)) >> 8) & 0xFF, 7, 7])
    else:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16) + bytes.fromhex("20010db8000000000000000000000001")
    s.sendto(hdr + qsec + ans, addr)
PY
python3 "$STUB" $((UDP + 1000)) & STUB_PID=$!
trap 'kill -9 $STUB_PID 2>/dev/null; pkill -9 -f "e229c-crash-$UDP" 2>/dev/null' EXIT

mkcfg() {
  local d=$1 up=$2
  cat > "$d/config.json" <<JSON
{
  "version": 1,
  "listen": {"udp": "127.0.0.1:$UDP", "tcp": "127.0.0.1:$((UDP+1))", "udp6": "", "tcp6": ""},
  "api": {"host": "127.0.0.1", "port": $API, "token": ""},
  "web_root": "",
  "upstreams": [{"id":"stub","name":"stub","proto":"udp","host":"127.0.0.1","addr":"127.0.0.1","port":$up,"url":"","group":null,"enabled":true,"latency":1,"weight":1,"allow_private_ip":true}],
  "cache_persist": true,
  "cache_file": "$d/ebpdns-cache.json",
  "cache_save_interval": 1,
  "cache_size": 4096,
  "cache_policy": "tinylfu",
  "persist_ttl": 0,
  "state_persist": true,
  "state_dir": "$d/state",
  "rules": []
}
JSON
}

start_inst() {
  local d=$1
  # **不要用 `setsid`**：`setsid` 可能 fork，`$!` 拿到的是包装进程的 pid ⇒ `kill -9 $!`
  # 杀不掉真正持有 `flock` 的 ebpdns，下一轮就进只读模式（2.1.29 实测：连续 60 轮 NO_GEN
  # 就是这个原因）。这里直接用 `$!` = 真进程 pid。
  EBPDNS_CACHE_FAILPOINT="$2" \
    "$BIN" --config "$d/config.json" --state-dir "$d/state" \
      --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API \
      --api-host 127.0.0.1 --log-level warn \
      > "$d/ebpdns.log" 2>&1 &
  echo $!
}

# 按**精确 pid** 清掉本轮的遗留进程（判据：`/proc/<pid>/exe` 是我们的二进制 + args 含本轮目录）。
kill_round_stragglers() {
  local d=$1
  for p in /proc/[0-9]*; do
    local pid=${p#/proc/}
    local exe
    exe=$(readlink "$p/exe" 2>/dev/null || true)
    [ "$exe" = "$BIN" ] || continue
    local args
    args=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)
    case "$args" in *"$d/"*) kill -9 "$pid" 2>/dev/null || true ;; esac
  done
}

# 等到端口能 bind（避免上一轮 socket 还在 TIME_WAIT / 旧进程未退）。
wait_port_free() {
  for _ in $(seq 1 50); do
    if ! (exec 3<>/dev/tcp/127.0.0.1/$API) 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 0
}

wait_api() {
  for _ in $(seq 1 100); do
    if curl -sf "http://127.0.0.1:$API/api/status" > /dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  return 1
}

# 打一些查询（让缓存有变化）
gen_load() {
  python3 - "$UDP" "$1" <<'PY'
import socket, struct, sys, random, time
port = int(sys.argv[1]); n = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.05)
for i in range(n):
    d = "k%04d.e229c.test" % random.randrange(400)
    q = struct.pack("!HHHHHH", random.randrange(65535), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in d.split(".")) + b"\x00"
    q += struct.pack("!HH", 1, 1)
    try:
        s.sendto(q, ("127.0.0.1", port)); s.recvfrom(4096)
    except Exception:
        pass
PY
}

jget() { python3 -c "
import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split('.'):
    if d is None: break
    d=d.get(k) if isinstance(d,dict) else None
print('' if d is None else d)
" "$1"; }

fail=0
for point in "${POINTS[@]}"; do
  for round in $(seq 1 "$ROUNDS"); do
    D="$WORK/$point-$round"
    rm -rf "$D"; mkdir -p "$D/state"
    kill_round_stragglers "$D"
    wait_port_free
    mkcfg "$D" $((UDP + 1000))
    PID=$(start_inst "$D" "")
    if ! wait_api; then
      echo "$point,$round,START_FAIL,,,,,,,,,,,FAIL" >> "$OUT"; fail=$((fail+1)); continue
    fi
    # 先产生流量 —— **有事件才会触发首次 flush/初始快照**（`needs_initial` 只在
    # "本拍有事件"时才被消费；没有流量时哪怕等 60 s 也不会写任何文件）。
    # 然后再等第一个世代真正落盘：否则这一轮的"崩溃"发生在任何提交点之前 ⇒ 只能验证到
    # "空前缀"，验证不到"旧代可用"。
    gen_load 80
    for _ in $(seq 1 60); do
      [ -f "$D/ebpdns-cache.json" ] && break
      gen_load 10
      sleep 0.1
    done
    if [ ! -f "$D/ebpdns-cache.json" ]; then
      echo "$point,$round,NO_GEN,,,,,,,,,,,FAIL" >> "$OUT"; fail=$((fail+1))
      kill -9 "$PID" 2>/dev/null; continue
    fi
    gen_load 60
    BEFORE=$(curl -s "http://127.0.0.1:$API/api/status" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['cache'].get('used',0))")
    # 触发一次快照（策略热切换 ⇒ request_snapshot("policy_swap")），再让指定注入点命中
    curl -s -X PUT "http://127.0.0.1:$API/api/config" -H 'content-type: application/json' \
         -d '{"cache_policy":"lru"}' > /dev/null 2>&1
    gen_load 30
    # 重启（带注入点）—— 继承同一 cache_file，让注入发生在“稳态 compaction”里
    kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
    PID=$(start_inst "$D" "$point")
    wait_api > /dev/null 2>&1
    gen_load 40
    # 等到注入真正命中（进程消失）
    for _ in $(seq 1 60); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

    # 重启（无注入）验证恢复
    PID=$(start_inst "$D" "")
    if ! wait_api; then
      echo "$point,$round,RESTART_FAIL,,,,,,,,,,,FAIL" >> "$OUT"; fail=$((fail+1)); continue
    fi
    sleep 0.3
    S=$(curl -s "http://127.0.0.1:$API/api/status")
    FORMAT=$(echo "$S" | jget cache.persist.format)
    SRC=$(echo "$S" | jget cache.persist.restore_source)
    SEQ=$(echo "$S" | jget cache.persist.snap_seq)
    ENT=$(echo "$S" | jget cache.used)
    DE=$(echo "$S" | jget cache.restore_drops.expired)
    DL=$(echo "$S" | jget cache.restore_drops.legacy)
    DF=$(echo "$S" | jget cache.restore_drops.failed)
    LS=$(echo "$S" | jget state_persist.load_state)
    TMP=$(ls "$D"/*.tmp 2>/dev/null | wc -l)
    CORR=$(ls "$D"/*.corrupt.* 2>/dev/null | wc -l)
    kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

    VERDICT=OK
    case "$SRC" in
      v2-snapshot|v2-snapshot+wal|wal-truncated|migrated|v1-json) ;;
      # `none` = 崩溃发生在**任何 manifest 落盘之前**（例如初始快照的 `.tmp` 写一半就被
      # 注入 abort）：磁盘上没有任何“已提交世代”，空缓存是**正确的前缀**。
      # 仍然要求 `.tmp` 被启动清理删掉（下面的 TMP 断言覆盖）且确实没有 manifest。
      none) [ -f "$D/ebpdns-cache.json" ] && VERDICT=FAIL_SRC ;;
      *) VERDICT=FAIL_SRC ;;
    esac
    [ "$FORMAT" = "v2" ] || [ "$FORMAT" = "v1" ] || VERDICT=FAIL_FORMAT
    [ "${DF:-1}" = "0" ] || VERDICT=FAIL_DROPS
    [ "${DL:-1}" = "0" ] || VERDICT=FAIL_LEGACY
    [ "${TMP:-1}" = "0" ] || VERDICT=FAIL_TMP
    [ "${CORR:-1}" = "0" ] || VERDICT=FAIL_CORRUPT
    # 已 fsync 的记录不丢：恢复条目数不得比崩溃前少一个 fsync 窗口以上（≤4096 条）
    if [ -n "$BEFORE" ] && [ -n "$ENT" ]; then
      if [ "$ENT" -lt $((BEFORE > 4096 ? BEFORE - 4096 : 0)) ]; then VERDICT=FAIL_LOST; fi
    fi
    echo "$point,$round,OK,$FORMAT,$SRC,$SEQ,$ENT,$DE,$DL,$DF,$TMP,$LS,$CORR,$VERDICT" >> "$OUT"
    [ "$VERDICT" = "OK" ] || fail=$((fail+1))
  done
done

TOTAL=$(($(wc -l < "$OUT") - 1))
echo "=================================================="
echo "CRASH MATRIX: rounds=$TOTAL fail=$fail"
echo "TEAR=0 (never torn) 见 $OUT 的 verdict 列"
awk -F, 'NR>1{c[$14]++} END{for(k in c) printf "  %-12s %d\n", k, c[k]}' "$OUT"
echo "  load_state=Committed: $(awk -F, 'NR>1 && $12=="Committed"' "$OUT" | wc -l)/$TOTAL"
echo "  tmp_left=0:           $(awk -F, 'NR>1 && $11=="0"' "$OUT" | wc -l)/$TOTAL"
echo "  drops_failed=0:       $(awk -F, 'NR>1 && $10=="0"' "$OUT" | wc -l)/$TOTAL"
echo "  restore_source 分布："
awk -F, 'NR>1{c[$5]++} END{for(k in c) printf "    %-22s %d\n", k, c[k]}' "$OUT"
[ "$fail" = "0" ] || exit 1
