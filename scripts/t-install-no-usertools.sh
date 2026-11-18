#!/usr/bin/env bash
# ============================================================================
# ebpdns 2.1.31：**无 passwd 工具**专项（矩阵第 2 行的独立入口）
#
#   sudo bash scripts/t-install-no-usertools.sh
#
# 判据（由 t-install-matrix.sh --only 2 实现）：
#   * PATH 遮蔽 groupadd/useradd/addgroup/adduser（全部 exit 127）；
#   * `./install.sh start` 必须 **rc=0**（绝不中止）；
#   * 直接追加 /etc/group、/etc/passwd 的回退必须被触发，且 getent 复验存在；
#   * 服务可启动（测试里用 systemctl shim 记录 restart）；
#   * 全过程在临时前缀内，不碰真机账号库/systemd。
#
# 极端情形"全部遮蔽且禁止写 /etc"（只 WARN、继续）由矩阵脚本的只读
# EBP_GROUP_FILE/EBP_PASSWD_FILE 变体覆盖；本脚本聚焦"可写回退成功"这一条。
# ============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
exec bash "$HERE/scripts/t-install-matrix.sh" --only 2
