#!/usr/bin/env bash
# ============================================================================
# ebpdns **2.1.31**：`install.sh --adopt-new-defaults` 的**临时前缀**验收
#
#   sudo bash scripts/t-install-adopt.sh
#
# 2.1.31 起安装器支持 `EBP_INSTALL_ROOT`（系统路径整体前缀）与测试钩子
# `EBP_PASSWD_FILE` / `EBP_GROUP_FILE`，因此本用例不再改写 install.sh 的路径，
# 也不要求真机存在 `ebpdns` 用户：全部动作在 mktemp 前缀内，getent/id/systemctl/
# chown/setcap 均为 PATH stub，**绝不触碰**真机 /etc、/usr/local、systemd。
#
# 判据：
#   A1 keep（不带旗标）：已有配置**逐字节保留**（md5 不变）、**不产生 `.bak`**、rc=0；
#   A2 adopt：先备份（`.bak.<ts>` 内容 == 覆盖前的本地配置）→ 再用包内模板覆盖
#             （结果逐字节 == 模板）、rc=0；
#   A3 缺模板：`apply_adopt_new_defaults` 返回非 0，且**不产生备份、不改配置**；
#   A4 静态：`apply_adopt_new_defaults` 里 `cp -p` 必须出现在覆盖模板的 `install` 之前。
#
# 退出码：0 = 全部 PASS/SKIP；1 = 至少一条红。
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="$HERE/packaging/install.sh"
UNIT="$HERE/packaging/systemd/ebpdns.service"
FAILED=()
N=0
say() { N=$((N + 1)); printf '\n=== [%d] %s\n' "$N" "$*"; }
ok() { printf '  RESULT: PASS  (%s)\n' "$1"; }
bad() { printf '  RESULT: FAIL  (%s)\n' "$1"; FAILED+=("$1"); }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ebpdns-t-adopt-XXXXXX")" || exit 1
trap 'rm -rf "$TMP"' EXIT
if [ "$(id -u)" -ne 0 ]; then
  echo "T_INSTALL_ADOPT=SKIP（需要 root 跑 install.sh 的 require_root）"
  exit 0
fi

PREFIX="$TMP/root"
PKG="$TMP/pkg"
SHIM="$TMP/shim"
PASSWD_DB="$TMP/passwd"
GROUP_DB="$TMP/group"
mkdir -p "$PREFIX/etc/systemd/system" "$PREFIX/usr/local/bin" "$PREFIX/var/lib/ebpdns" \
  "$PKG/bin" "$PKG/etc/ebpdns" "$PKG/systemd" "$PKG/web" "$SHIM"
printf 'root:x:0:0:root:/root:/bin/sh\nebpdns:x:998:999::/var/lib/ebpdns:/usr/sbin/nologin\n' >"$PASSWD_DB"
printf 'root:x:0:\nebpdns:x:999:\n' >"$GROUP_DB"

cat >"$SHIM/getent" <<EOS
#!/bin/sh
case "\$1" in
  passwd) file="$PASSWD_DB" ;;
  group) file="$GROUP_DB" ;;
  *) exit 2 ;;
esac
awk -F: -v k="\$2" '\$1==k{print; found=1} END{exit !found}' "\$file"
EOS
cat >"$SHIM/id" <<'EOS'
#!/bin/sh
[ "${1:-}" = "-u" ] && { echo 0; exit 0; }
exit 0
EOS
for c in systemctl chown setcap; do
  cat >"$SHIM/$c" <<EOS
#!/bin/sh
echo "stub:$c \$*" >>"$TMP/stub.log"
exit 0
EOS
done
chmod +x "$SHIM"/*

cp -a "$INSTALL" "$PKG/install.sh"
cp -a "$UNIT" "$PKG/systemd/ebpdns.service"
cat >"$PKG/bin/ebpdns" <<'EOS'
#!/bin/sh
case "$1" in
  --version) echo "ebpdns 2.1.31"; exit 0 ;;
  check-config) echo "CONFIG-OK（stub）"; exit 0 ;;
  migrate-config) echo "MIGRATE-SUMMARY missing_keys: 0"; exit 0 ;;
  *) exit 0 ;;
esac
EOS
chmod 0755 "$PKG/bin/ebpdns" "$PKG/install.sh"
printf '{"api":{"host":"127.0.0.1","port":19861,"token":""},"listen":{"udp":"127.0.0.1:19862","tcp":"127.0.0.1:19862","udp6":"","tcp6":""},"dns_port":19862,"config_version":3,"cache_size":999,"state_dir":"/var/lib/ebpdns/state","upstreams":[],"rules":[],"rule_subscriptions":[]}\n' >"$PKG/etc/ebpdns/config.json"
echo '<html>stub</html>' >"$PKG/web/index.html"

run_install() {
  ( cd "$PKG" && EBP_INSTALL_ROOT="$PREFIX" EBP_PASSWD_FILE="$PASSWD_DB" \
    EBP_GROUP_FILE="$GROUP_DB" EBP_PWD_LOCK="$TMP/pwd.lock" EBP_INSTALL_PORTS="19861 19862" \
    PATH="$SHIM:$PATH" bash ./install.sh "$@" ) >"$TMP/install.out" 2>&1
  echo $?
}

# A4 静态：备份必须先于覆盖
say "A4 静态：apply_adopt_new_defaults 里 cp -p 必须先于 install 覆盖模板"
BAK_LINE="$(grep -n 'cp -p "\$conf" "\$bak"' "$INSTALL" | head -1 | cut -d: -f1)"
INST_LINE="$(grep -n 'install -m 0640 "\$tpl" "\$conf"' "$INSTALL" | head -1 | cut -d: -f1)"
if [ -n "$BAK_LINE" ] && [ -n "$INST_LINE" ] && [ "$BAK_LINE" -lt "$INST_LINE" ]; then
  ok "static-backup-before-overwrite"
else
  bad "static-backup-before-overwrite"
  printf '  cp 行=%s install 行=%s（必须 cp 在前）\n' "$BAK_LINE" "$INST_LINE"
fi

CONF="$PREFIX/etc/ebpdns/config.json"
TPL="$PKG/etc/ebpdns/config.json"
mkdir -p "$PREFIX/etc/ebpdns"
printf '{"config_version":3,"cache_size":4242,"state_dir":"%s/var/lib/ebpdns/state","local":"KEEP-ME"}\n' "$PREFIX" >"$CONF"

# A1 keep
say "A1 keep：不带旗标 ⇒ 配置逐字节保留、无 .bak、rc=0"
md1="$(md5sum "$CONF" | awk '{print $1}')"
rc="$(run_install)"
md2="$(md5sum "$CONF" | awk '{print $1}')"
if [ "$rc" = "0" ] && [ "$md1" = "$md2" ] && ! ls "$CONF".bak.* >/dev/null 2>&1; then
  ok "keep-preserved($rc)"
else
  bad "keep-preserved(rc=$rc md=$md1/$md2)"
  tail -20 "$TMP/install.out"
fi

# A2 adopt
say "A2 adopt：先备份（内容 == 覆盖前）→ 模板覆盖（结果 == 模板）、rc=0"
rc="$(run_install --adopt-new-defaults)"
baks=("$CONF".bak.*)
if [ "$rc" = "0" ] && [ -f "${baks[0]}" ] && [ "$(md5sum "${baks[0]}" | awk '{print $1}')" = "$md1" ] \
  && [ "$(md5sum "$CONF" | awk '{print $1}')" = "$(md5sum "$TPL" | awk '{print $1}')" ]; then
  ok "adopt-backup-and-overwrite($rc)"
else
  bad "adopt-backup-and-overwrite(rc=$rc bak=${baks[0]:-none})"
  tail -30 "$TMP/install.out"
fi

# A3 缺模板
say "A3 缺模板：apply_adopt_new_defaults 必须非 0，且不备份/不改配置"
md_before="$(md5sum "$CONF" | awk '{print $1}')"
n_before="$(ls "$CONF".bak.* 2>/dev/null | wc -l)"
mv "$TPL" "$TPL.hidden"
rc="$(run_install --adopt-new-defaults)"
mv "$TPL.hidden" "$TPL"
md_after="$(md5sum "$CONF" | awk '{print $1}')"
n_after="$(ls "$CONF".bak.* 2>/dev/null | wc -l)"
if [ "$rc" != "0" ] && [ "$md_before" = "$md_after" ] && [ "$n_before" = "$n_after" ]; then
  ok "missing-template-nonzero($rc)"
else
  bad "missing-template-nonzero(rc=$rc md=$md_before/$md_after bak=$n_before/$n_after)"
  tail -20 "$TMP/install.out"
fi

echo
if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "T_INSTALL_ADOPT=PASS（$N 项）"
  exit 0
fi
echo "T_INSTALL_ADOPT=FAIL（${#FAILED[@]} 项红：${FAILED[*]}）"
exit 1
