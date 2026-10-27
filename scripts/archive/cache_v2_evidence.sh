#!/usr/bin/env bash
# **2.1.29 缓存持久化 v2：环境故障与 A/B 证据**（§15.3 / §15.5 / §11 / §15.7）
#
# 子命令：
#   enospc   <bin> <work>   真 64 KiB tmpfs 填到剩 4 KiB ⇒ 落盘失败**只影响缓存**
#   exdev    <bin> <work>   cache_file 在 tmpfs、state_dir 在 ext4 ⇒ 无 EXDEV
#   ab       <bin> <work>   v1(EBPDNS_CACHE_FORMAT=v1) vs v2 命中率 A/B + 迁移专项
#   perf     <bin> <work>   v1 vs v2：落盘字节/次、恢复 p50/p99、峰值 RSS
#
# 纪律：私有 state_dir + 197xx/187xx 端口 + `e229c-` 前缀；**绝不**碰生产实例。
set -u
CMD=${1:?usage: cache_v2_evidence.sh <enospc|exdev|ab|perf> <bin> <workdir>}
BIN=${2:?}
WORK=${3:?}
mkdir -p "$WORK"
PREFIX="e229c-evid"

UDP=$((19700 + (RANDOM % 90)))
API=$((18700 + (RANDOM % 90)))
UP=$((15800 + (RANDOM % 90)))

stub_start() {
  cat > "$WORK/stub.py" <<'PY'
import socket, struct, sys, random
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
while True:
    data, addr = s.recvfrom(4096)
    try:
        qid = data[:2]; i = 12
        while data[i] != 0: i += 1 + data[i]
        i += 1; qtype = struct.unpack("!H", data[i:i+2])[0]; qsec = data[12:i+4]
    except Exception: continue
    hdr = qid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    if qtype == 1:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, random.randrange(256), 7, 7])
    else:
        ans = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 300, 16) + bytes.fromhex("20010db8000000000000000000000001")
    s.sendto(hdr + qsec + ans, addr)
PY
  python3 "$WORK/stub.py" "$UP" & STUB=$!
  trap 'kill -9 $STUB 2>/dev/null' EXIT
}

mkcfg() { # dir extra_json
  local d=$1 extra=${2:-}
  cat > "$d/config.json" <<JSON
{
  "version": 1,
  "listen": {"udp": "127.0.0.1:$UDP", "tcp": "127.0.0.1:$((UDP+1))", "udp6": "", "tcp6": ""},
  "api": {"host": "127.0.0.1", "port": $API, "token": ""},
  "web_root": "",
  "upstreams": [{"id":"stub","name":"stub","proto":"udp","host":"127.0.0.1","addr":"127.0.0.1","port":$UP,"url":"","group":null,"enabled":true,"latency":1,"weight":1,"allow_private_ip":true}],
  "cache_persist": true,
  "cache_file": "$d/ebpdns-cache.json",
  "cache_save_interval": 1,
  "cache_size": 8192,
  "cache_policy": "tinylfu",
  "persist_ttl": 0,
  "state_persist": true,
  "state_dir": "$d/state",
  "rules": []
}
JSON
  [ -n "$extra" ] && echo "$extra"
}

start() { # dir failpoint
  local d=$1 fp=${2:-}
  EBPDNS_CACHE_FAILPOINT="$fp" setsid "$BIN" --config "$d/config.json" --state-dir "$d/state" \
    --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API --api-host 127.0.0.1 \
    --log-level info >> "$d/ebpdns.log" 2>&1 &
  echo $!
}
wait_api() { for _ in $(seq 1 150); do curl -sf "http://127.0.0.1:$API/api/status" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }
load() { python3 - "$UDP" "$1" "${2:-400}" <<'PY'
import socket, struct, sys, random
port=int(sys.argv[1]); n=int(sys.argv[2]); keys=int(sys.argv[3])
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.05)
for _ in range(n):
    d="k%04d.e229c.test"%random.randrange(keys)
    q=struct.pack("!HHHHHH", random.randrange(65535),0x0100,1,0,0,0)
    q+=b"".join(bytes([len(x)])+x.encode() for x in d.split("."))+b"\x00"+struct.pack("!HH",1,1)
    try:
        s.sendto(q,("127.0.0.1",port)); s.recvfrom(4096)
    except Exception: pass
PY
}
jq_() { python3 -c "import json,sys;d=json.load(sys.stdin);
for k in sys.argv[1].split('.'):
    d = d.get(k) if isinstance(d,dict) else None
print('' if d is None else d)" "$1"; }

stub_start

case "$CMD" in
# ---------------- ENOSPC ----------------
enospc)
  D="$WORK/enospc"; rm -rf "$D"; mkdir -p "$D/state" "$D/mnt"
  mount -t tmpfs -o size=64k tmpfs "$D/mnt" || { echo "MOUNT_FAIL"; exit 1; }
  # 把 cache_file 放 tmpfs；state_dir 放**另一个** FS（ext4 的 $D/state）
  sed -i "s#\"cache_file\": \"[^\"]*\"#\"cache_file\": \"$D/mnt/ebpdns-cache.json\"#" /dev/null 2>/dev/null
  mkcfg "$D"
  python3 - "$D/config.json" "$D/mnt/ebpdns-cache.json" <<'PY'
import json,sys
p,cf=sys.argv[1],sys.argv[2]
d=json.load(open(p)); d["cache_file"]=cf; json.dump(d,open(p,"w"))
PY
  PID=$(start "$D"); wait_api || { echo "START_FAIL"; exit 1; }
  load 300 400; sleep 1.5
  S1=$(curl -s "http://127.0.0.1:$API/api/status")
  REV1=$(echo "$S1" | jq_ state_persist.revision)
  MAN1=$(md5sum "$D/mnt/ebpdns-cache.json" 2>/dev/null | cut -d' ' -f1)
  # 填到剩 4 KiB
  dd if=/dev/zero of="$D/mnt/fill.bin" bs=1k count=64 2>/dev/null
  AVAIL=$(df -k "$D/mnt" | awk 'NR==2{print $4}')
  dd if=/dev/zero of="$D/mnt/fill2.bin" bs=1k count=$((AVAIL > 4 ? AVAIL - 4 : 0)) 2>/dev/null
  echo "ENOSPC: avail_kb_after_fill=$(df -k "$D/mnt" | awk 'NR==2{print $4}')"
  # 制造更多变更，逼迫 WAL/快照失败
  load 800 400; sleep 2.5
  S2=$(curl -s "http://127.0.0.1:$API/api/status")
  DNS_OK=0
  for _ in $(seq 1 20); do
    python3 - "$UDP" <<'PY' && { DNS_OK=1; break; }
import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1)
q=struct.pack("!HHHHHH",1,0x0100,1,0,0,0)+b"\x04k005\x04e229c\x04test\x00"+struct.pack("!HH",1,1)
try:
    s.sendto(q,("127.0.0.1",int(sys.argv[1]))); s.recvfrom(4096); sys.exit(0)
except Exception: sys.exit(1)
PY
    sleep 0.2
  done
  MAN2=$(md5sum "$D/mnt/ebpdns-cache.json" 2>/dev/null | cut -d' ' -f1)
  REV2=$(echo "$S2" | jq_ state_persist.revision)
  TMP=$(ls "$D"/mnt/*.tmp 2>/dev/null | wc -l)
  kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  # 恢复磁盘空间后重启：旧代仍可读
  rm -f "$D"/mnt/fill*.bin
  PID=$(start "$D"); wait_api || { echo "RESTART_FAIL"; exit 1; }
  S3=$(curl -s "http://127.0.0.1:$API/api/status")
  kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  umount "$D/mnt" 2>/dev/null
  echo "ENOSPC_RESULT old_manifest_unchanged=$([ "$MAN1" = "$MAN2" ] && echo YES || echo NO) revision_unchanged=$([ "$REV1" = "$REV2" ] && echo YES || echo NO) dns_ok=$DNS_OK tmp_left=$TMP restart_ok=YES restore_source=$(echo "$S3"|jq_ cache.persist.restore_source) format=$(echo "$S3"|jq_ cache.persist.format)"
  ;;

# ---------------- EXDEV ----------------
exdev)
  D="$WORK/exdev"; rm -rf "$D"; mkdir -p "$D/state" "$D/cachefs"
  mount -t tmpfs -o size=8m tmpfs "$D/cachefs" || { echo "MOUNT_FAIL"; exit 1; }
  mkcfg "$D"
  python3 - "$D/config.json" "$D/cachefs/ebpdns-cache.json" <<'PY'
import json,sys
p,cf=sys.argv[1],sys.argv[2]
d=json.load(open(p)); d["cache_file"]=cf; json.dump(d,open(p,"w"))
PY
  PID=$(start "$D"); wait_api || { echo "START_FAIL"; exit 1; }
  load 400 400; sleep 1.2; load 400 400; sleep 1.5
  kill -TERM "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  PID=$(start "$D"); wait_api || { echo "RESTART_FAIL"; exit 1; }
  S=$(curl -s "http://127.0.0.1:$API/api/status")
  kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  EXDEV=$(grep -c "EXDEV\|Invalid cross-device" "$D/ebpdns.log" 2>/dev/null || true)
  # 回滚演练：把 .v1.bak 放回 cache_file，v1 模式能读到
  RB=NA
  if [ -f "$D/cachefs/ebpdns-cache.json.v1.bak" ]; then
    cp -p "$D/cachefs/ebpdns-cache.json.v1.bak" "$D/cachefs/ebpdns-cache.json"
    EBPDNS_CACHE_FORMAT=v1 setsid "$BIN" --config "$D/config.json" --state-dir "$D/state" \
      --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API --api-host 127.0.0.1 \
      --log-level error >> "$D/ebpdns.log" 2>&1 &
    PID=$!
    if wait_api; then
      RB=$(curl -s "http://127.0.0.1:$API/api/status" | jq_ cache.used)
      kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
      RB="ok(entries=$RB)"
    else RB=FAIL; kill -9 "$PID" 2>/dev/null; fi
  fi
  # `EBPDNS_CACHE_FORMAT=v1` + **v2 数据目录**：必须安全降级（不报错、走 v1 读、空缓存可接受）
  DEG=NA
  D2="$WORK/exdev-degrade"; rm -rf "$D2"; mkdir -p "$D2/state"
  cp -a "$D/cachefs/." "$D2/" 2>/dev/null
  mkcfg "$D2"
  python3 - "$D2/config.json" "$D2/ebpdns-cache.json" <<'PY'
import json,sys
p,cf=sys.argv[1],sys.argv[2]
d=json.load(open(p)); d["cache_file"]=cf; json.dump(d,open(p,"w"))
PY
  EBPDNS_CACHE_FORMAT=v1 setsid "$BIN" --config "$D2/config.json" --state-dir "$D2/state" \
    --dns-udp-port $((UDP+2)) --dns-tcp-port $((UDP+3)) --api-port $((API+2)) --api-host 127.0.0.1 \
    --log-level info > "$D2/ebpdns.log" 2>&1 &
  PID=$!
  ok=0
  for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$((API+2))/api/status" >/dev/null 2>&1 && { ok=1; break; }; sleep 0.1; done
  if [ "$ok" = "1" ]; then
    S2=$(curl -s "http://127.0.0.1:$((API+2))/api/status")
    DEG="ok(format=$(echo "$S2"|jq_ cache.persist.format),source=$(echo "$S2"|jq_ cache.persist.restore_source))"
    kill -9 "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
  else DEG=FAIL; kill -9 "$PID" 2>/dev/null; fi
  umount "$D/cachefs" 2>/dev/null
  echo "EXDEV_RESULT exdev_errors=$EXDEV format=$(echo "$S"|jq_ cache.persist.format) source=$(echo "$S"|jq_ cache.persist.restore_source) rollback=$RB degrade_v1_env=$DEG"
  ;;

# ---------------- A/B（v1 vs v2 + 迁移专项）----------------
ab)
  D="$WORK/ab"; rm -rf "$D"; mkdir -p "$D"
  run_phase() { # dir seconds env...
    local d=$1 secs=$2; shift 2
    mkdir -p "$d/state"
    mkcfg "$d"
    env "$@" setsid "$BIN" --config "$d/config.json" --state-dir "$d/state" \
      --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API --api-host 127.0.0.1 \
      --log-level warn >> "$d/ebpdns.log" 2>&1 &
    local pid=$!
    wait_api || { echo "START_FAIL"; return 1; }
    load $((secs * 40)) 2000 &
    local lp=$!
    sleep "$secs"
    kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null; wait $lp 2>/dev/null
    return 0
  }
  measure_after_restart() { # dir env...
    local d=$1; shift
    env "$@" setsid "$BIN" --config "$d/config.json" --state-dir "$d/state" \
      --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API --api-host 127.0.0.1 \
      --log-level warn >> "$d/ebpdns.log" 2>&1 &
    local pid=$!
    local t0=$(date +%s%N)
    wait_api || { echo "RESTART_FAIL"; return 1; }
    local t1=$(date +%s%N)
    local recover_ms=$(( (t1 - t0) / 1000000 ))
    sleep 0.3
    local s0=$(curl -s "http://127.0.0.1:$API/api/status")
    local h0=$(echo "$s0" | jq_ counters.hit); local m0=$(echo "$s0" | jq_ counters.miss)
    load $((60 * 40)) 2000
    local s1=$(curl -s "http://127.0.0.1:$API/api/status")
    local h1=$(echo "$s1" | jq_ counters.hit); local m1=$(echo "$s1" | jq_ counters.miss)
    local used=$(echo "$s1" | jq_ cache.used)
    local de=$(echo "$s1" | jq_ cache.restore_drops.expired)
    local dl=$(echo "$s1" | jq_ cache.restore_drops.legacy)
    local df=$(echo "$s1" | jq_ cache.restore_drops.failed)
    local fmt=$(echo "$s1" | jq_ cache.persist.format)
    local src=$(echo "$s1" | jq_ cache.persist.restore_source)
    kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null
    python3 -c "
h1,m1,h0,m0=$h1,$m1,$h0,$m0
dh=h1-h0; dm=m1-m0
rate=dh/(dh+dm) if (dh+dm)>0 else 0
print('hit_rate=%.4f used=$used drops=$de/$dl/$df fmt=$fmt src=$src recover_ms=$recover_ms' % rate)
"
  }
  rm -rf "$D/v1" "$D/v2"; mkdir -p "$D/v1" "$D/v2"
  # A：v1 JSON（EBPDNS_CACHE_FORMAT=v1）
  A1=$(run_phase "$D/v1" 40 EBPDNS_CACHE_FORMAT=v1 && measure_after_restart "$D/v1" EBPDNS_CACHE_FORMAT=v1)
  # B：v2（默认）
  B1=$(run_phase "$D/v2" 40 && measure_after_restart "$D/v2")
  # 迁移专项：v1 跑一段 → SIGTERM（写 v1 JSON）→ B（默认）启动 ⇒ 触发迁移
  M="$D/mig"; mkdir -p "$M/state"; mkcfg "$M"
  EBPDNS_CACHE_FORMAT=v1 setsid "$BIN" --config "$M/config.json" --state-dir "$M/state" \
    --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API --api-host 127.0.0.1 \
    --log-level warn >> "$M/ebpdns.log" 2>&1 &
  PID=$!; wait_api && { load 1600 2000; sleep 1; }
  kill -TERM $PID 2>/dev/null; wait $PID 2>/dev/null
  V1SIZE=$(stat -c %s "$M/ebpdns-cache.json" 2>/dev/null || echo 0)
  MIG=$(measure_after_restart "$M")
  BAK=$(ls -l "$M/ebpdns-cache.json.v1.bak" 2>/dev/null | awk '{print $5}')
  echo "AB_RESULT A_v1=[$A1]"
  echo "AB_RESULT B_v2=[$B1]"
  echo "AB_RESULT migrate=[$MIG] v1_json_bytes=$V1SIZE bak_bytes=${BAK:-MISSING}"
  ;;

# ---------------- PERF ----------------
perf)
  D="$WORK/perf"; rm -rf "$D"; mkdir -p "$D"
  measure() { # dir label env...
    local d=$1 label=$2; shift 2
    mkdir -p "$d/state"; mkcfg "$d"
    env "$@" setsid "$BIN" --config "$d/config.json" --state-dir "$d/state" \
      --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API --api-host 127.0.0.1 \
      --log-level warn >> "$d/ebpdns.log" 2>&1 &
    local pid=$!
    wait_api || { echo "$label START_FAIL"; return 1; }
    load 4000 20000
    sleep 0.5
    local w0=$(awk '/^write_bytes/{print $2}' /proc/$pid/io)
    local t0=$(date +%s%N)
    sleep 20   # cache_save_interval=1 ⇒ 约 20 次落盘
    local t1=$(date +%s%N)
    local w1=$(awk '/^write_bytes/{print $2}' /proc/$pid/io)
    local hwm=$(awk '/^VmHWM/{print $2}' /proc/$pid/status)
    local entries=$(curl -s "http://127.0.0.1:$API/api/status" | jq_ cache.used)
    local bytes=$(curl -s "http://127.0.0.1:$API/api/status" | jq_ cache.persist.bytes)
    local walb=$(curl -s "http://127.0.0.1:$API/api/status" | jq_ cache.persist.wal_bytes)
    kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null
    # 恢复耗时：起 3 次取中位数
    local ms=""
    for i in 1 2 3; do
      local a=$(date +%s%N)
      env "$@" setsid "$BIN" --config "$d/config.json" --state-dir "$d/state" \
        --dns-udp-port $UDP --dns-tcp-port $((UDP+1)) --api-port $API --api-host 127.0.0.1 \
        --log-level warn >> "$d/ebpdns.log" 2>&1 &
      local p2=$!
      if wait_api; then :; fi
      local b=$(date +%s%N)
      ms="$ms $(( (b-a)/1000000 ))"
      kill -9 $p2 2>/dev/null; wait $p2 2>/dev/null
    done
    local med=$(echo $ms | tr ' ' '\n' | sort -n | sed -n 2p)
    local rss_after=$(awk '/^VmHWM/{print $2}' /proc/$$/status 2>/dev/null || echo 0)
    echo "$label entries=$entries write_bytes_20s=$((w1-w0)) per_save_bytes=$(( bytes )) saved_bytes_api=$bytes wal_bytes=$walb vmhwm_kb=$hwm recover_ms=$ms median_recover_ms=$med"
  }
  rm -rf "$D/v1" "$D/v2"; mkdir -p "$D/v1" "$D/v2"
  echo "PERF_RESULT $(measure "$D/v1" v1 EBPDNS_CACHE_FORMAT=v1)"
  echo "PERF_RESULT $(measure "$D/v2" v2)"
  ;;
*)
  echo "unknown subcommand $CMD"; exit 2;;
esac
