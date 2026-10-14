#!/usr/bin/env bash
# ============================================================
# ebpdns v1.9.163 安装脚本 (Debian 13 / 兼容 Debian 系)
#   用法: sudo ./install.sh
#         自动检测**并自动安装**全部所需依赖与软件, 一条命令完成部署:
#           * 必需: python3(>=3.10)
#           * 可选: aioquic(DoQ/DoH3)、完整 eBPF 工具链
#                   (clang/llvm/libbpf-dev/linux-libc-dev/bpftool)
#           * 运行时工具: iproute2(ip)、libcap2-bin(setcap)
#         可选依赖安装失败**不阻断部署**(DNS 服务照常, 仅对应增强功能不可用)。
#         离线/受限环境可用 EBPDNS_SKIP_DEPS=1 跳过自动安装(仅检测并提示)。
#   支持两种场景:
#     A) 就地安装: 包已解压到 /opt/ebpdns, 直接在 /opt/ebpdns 下运行本脚本
#     B) 异地安装: 包在任意目录, 运行后拷贝到 /opt/ebpdns
#   安装结果: /opt/ebpdns (代码) + /etc/ebpdns (配置) + systemd 服务
# ============================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ebpdns"
CONF_DIR="/etc/ebpdns"
UNIT_FILE="/etc/systemd/system/ebpdns.service"
SERVICE_NAME="ebpdns"

# ---------- 检查权限 ----------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "错误: 需要 root 权限, 请使用 sudo ./install.sh" >&2
  exit 1
fi

# ---------- 依赖检测与自动安装 ----------
# 自动安装开关: 默认开启; EBPDNS_SKIP_DEPS=1 仅检测并提示, 不自动安装
if [[ "${EBPDNS_SKIP_DEPS:-0}" == "1" ]]; then
  AUTO_DEPS=0
  echo "==> 0/4 依赖检测 (EBPDNS_SKIP_DEPS=1 已跳过自动安装)"
else
  AUTO_DEPS=1
  echo "==> 0/4 依赖检测与自动安装"
fi

# ---------- 统一依赖安装助手 (v1.9.161) ----------
# 设计要点:
#   * apt-get update 只做一次并记住结果(原脚本在 python3 与 aioquic 两处各更新一次,
#     联网慢时白白多花几十秒);
#   * `if ! cmd; then` 形式规避 set -e —— 旧脚本用 `! command -v python3` 作条件,
#     在 `set -e` 下一旦为真会直接终止脚本(退出码被 `!` 反转, 与 set -e 语义冲突),
#     这也是"自动安装依赖"长期不可靠的原因之一;
#   * 缺失即装、装完复验, 失败只提示不中断(可选项失败不应阻断部署)。
_APT_UPDATED=0
_apt_update_once() {
  [[ "$_APT_UPDATED" == "1" ]] && return 0
  _APT_UPDATED=1
  if command -v apt-get >/dev/null 2>&1; then
    echo "    → apt-get update (仅执行一次)"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null \
      || echo "[WARN] apt-get update 失败，继续尝试安装（可能安装到过期包）"
  fi
}

# _ensure_pkg <用于判定的命令> <apt 包名> <说明>
#   判定命令已存在 → 跳过; 否则自动 apt 安装并复验。
#   返回 0=就绪, 1=未能就绪。
_ensure_pkg() {
  local probe="$1" pkg="$2" desc="$3"
  if command -v "$probe" >/dev/null 2>&1; then
    return 0
  fi
  if [[ "$AUTO_DEPS" != "1" ]]; then
    echo "    (已跳过自动安装) 缺少 ${desc}（apt 包 ${pkg}）"
    return 1
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "    [WARN] 缺少 ${desc}（apt 包 ${pkg}），且本机无 apt-get，请手动安装"
    return 1
  fi
  _apt_update_once
  echo "    → 自动安装 ${desc}（${pkg}）"
  if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1 \
     && command -v "$probe" >/dev/null 2>&1; then
    echo "    ✓ ${desc} 已安装"
    return 0
  fi
  echo "    [WARN] ${desc} 自动安装失败，请手动:  apt install -y ${pkg}"
  return 1
}

# _ensure_path <绝对路径> <apt 包名> <说明>  —— 用于无同名命令的依赖(头文件/库)
_ensure_path() {
  local path="$1" pkg="$2" desc="$3"
  if [[ -e "$path" ]]; then
    return 0
  fi
  if [[ "$AUTO_DEPS" != "1" ]] || ! command -v apt-get >/dev/null 2>&1; then
    echo "    (未安装) 缺少 ${desc}（apt 包 ${pkg}）"
    return 1
  fi
  _apt_update_once
  echo "    → 自动安装 ${desc}（${pkg}）"
  if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1 \
     && [[ -e "$path" ]]; then
    echo "    ✓ ${desc} 已安装"
    return 0
  fi
  echo "    [WARN] ${desc} 自动安装失败，请手动:  apt install -y ${pkg}"
  return 1
}

# --- python3 (必需) ---
if ! command -v python3 >/dev/null 2>&1; then
  if [[ "$AUTO_DEPS" == "1" ]] && command -v apt-get >/dev/null 2>&1; then
    echo "    (未检测到 python3 → 自动安装 python3)"
    _apt_update_once
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 >/dev/null 2>&1 \
      || { echo "错误: 自动安装 python3 失败, 请手动执行:  apt install -y python3" >&2; exit 1; }
  else
    echo "错误: 未检测到 python3, 请先安装:  apt install -y python3" >&2
    exit 1
  fi
fi

# --- Python 版本 ---
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
  echo "错误: ebpdns 需要 Python 3.10+, 当前为 $(python3 --version 2>&1)" >&2
  echo "   Debian 13 自带 3.13; 其他系统请升级 Python 或改用 Python3.11+/3.12+" >&2
  exit 1
fi

# --- aioquic (DoQ/DoH3 上游需要; UDP/TCP/DoH/DoT 不依赖) ---
if ! python3 -c 'import aioquic' 2>/dev/null; then
  echo "    (未检测到 aioquic, DoQ/DoH3 上游需要它)"
  if [[ "$AUTO_DEPS" == "1" ]]; then
    _aq_ok=0
    # 优先 apt 系统包(与系统 python3 版本一致); 复用上面的"仅一次" update
    _apt_update_once
    if command -v apt-get >/dev/null 2>&1 && apt-get install -y python3-aioquic >/dev/null 2>&1; then
      echo "    aioquic 已通过 apt 安装 (python3-aioquic)"
      _aq_ok=1
    elif command -v python3 >/dev/null 2>&1 && python3 -m pip --version >/dev/null 2>&1; then
      # 回退 python3 -m pip(保证装到与 python3 同版本的解释器);
      # PEP 668 系统 Python 需 --break-system-packages, 否则 pip 拒绝安装
      echo "    (apt 无 python3-aioquic, 改用 python3 -m pip 安装)"
      # R31 P3-3: 去掉 `2>/dev/null`, 让 pip 的错误诊断(网络错误/依赖冲突)透传到 stderr。
      # --quiet 仍抑制正常安装进度与"Successfully installed"提示, 不会刷屏; 失败时用户能看到具体原因。
      python3 -m pip install --quiet --break-system-packages aioquic && _aq_ok=1 \
        || echo "    (python3 -m pip 安装失败, 详见上方 pip 错误输出)" >&2
    fi
    # v1.9.161: pip 自身可能缺失(Debian 最小安装无 pip)—— 先自动补齐 python3-pip 再重试
    if [[ "$_aq_ok" == "0" ]] && command -v apt-get >/dev/null 2>&1; then
      if ! python3 -m pip --version >/dev/null 2>&1; then
        echo "    (未检测到 pip → 自动安装 python3-pip)"
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip >/dev/null 2>&1 || true
      fi
      if python3 -m pip --version >/dev/null 2>&1; then
        echo "    (重试: python3 -m pip 安装 aioquic)"
        python3 -m pip install --quiet --break-system-packages aioquic && _aq_ok=1 \
          || echo "    (python3 -m pip 安装失败, 详见上方 pip 错误输出)" >&2
      fi
    fi
    if [[ "$_aq_ok" == "0" ]] && command -v pip3 >/dev/null 2>&1; then
      echo "    (最后尝试 pip3 安装)"
      # R31 P3-3: 同上, 不丢弃 pip3 stderr, 失败原因可见; 失败后下方已有友好兜底提示。
      pip3 install --quiet --break-system-packages aioquic && _aq_ok=1
    fi
    if [[ "$_aq_ok" == "1" ]] && python3 -c 'import aioquic' 2>/dev/null; then
      echo "    aioquic 安装成功 → DoQ/DoH3 上游可用"
    else
      echo "    警告: aioquic 自动安装失败, DoQ/DoH3 上游暂不可用" >&2
      echo "          (可稍后手动:  sudo python3 -m pip install aioquic)" >&2
      echo "          UDP/TCP/DoH/DoT 上游不受影响, 可继续安装" >&2
    fi
  else
    echo "    (已跳过自动安装) 未检测到 aioquic, DoQ/DoH3 上游暂不可用"
    echo "    (可稍后手动:  sudo python3 -m pip install aioquic; UDP/TCP/DoH/DoT 不受影响)"
  fi
else
  echo "    aioquic 已就绪 → DoQ/DoH3 上游可用"
fi


# ---------- 创建运行用户 ebpdns ----------
# systemd 以专用系统用户 ebpdns 运行服务(配合 User=ebpdns/Group=ebpdns)。
# 该用户无需登录 shell(nologin), 仅用于降权运行; home 指向代码目录 /opt/ebpdns。
# 不创建会导致 systemd 启动报 "Failed to determine user credentials"。
if ! getent group ebpdns >/dev/null 2>&1; then
  groupadd --system ebpdns
fi
if ! id -u ebpdns >/dev/null 2>&1; then
  useradd --system --gid ebpdns --home-dir /opt/ebpdns --shell /usr/sbin/nologin ebpdns
  echo "==> 已创建系统用户 ebpdns (运行服务, 无登录 shell)"
fi

# ---------- 1/4 代码就位 ----------
IN_PLACE=0
if [[ "$SRC_DIR" == "$INSTALL_DIR" ]]; then
  IN_PLACE=1
  echo "==> 检测到源码已位于 ${INSTALL_DIR} (就地安装), 跳过代码拷贝"
  # 完整性校验: 就地安装时关键文件必须齐全, 否则后续 systemd 启动必然失败
  # (历史问题: 早期版本就地安装缺文件时 cp 报错, 用户 VM 上 systemd 启动失败)
  # v1.9.80: 关键文件清单补全到运行时实际依赖(入口/包核心模块/前端页面与图表/unit)
  for _req in bin/ebpdns ebpdns/__init__.py ebpdns/__main__.py ebpdns/cli.py ebpdns/api.py \
              ebpdns/bpf_loader.py ebpdns/resolver.py ebpdns/server.py ebpdns/cache.py ebpdns/config.py \
              ebpdns/telemetry.py ebpdns/upstream.py ebpdns/dnsmsg.py ebpdns/probe.py \
              ebpdns/quic_upstream.py web/index.html web/echarts.min.js web/favicon.svg systemd/ebpdns.service; do
    if [[ ! -e "${INSTALL_DIR}/${_req}" ]]; then
      echo "错误: 就地安装缺少关键文件 ${INSTALL_DIR}/${_req}, 请确认完整解压部署包后再运行" >&2
      exit 1
    fi
  done
  # 就地安装: 包就在 /opt/ebpdns, 仍清理构建缓存(__pycache__/*.pyc),
  # 与异地 rsync/cp 分支行为对齐, 避免陈旧字节码随升级残留。
  find "${INSTALL_DIR}" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
  find "${INSTALL_DIR}" -name '*.pyc' -delete 2>/dev/null || true
  # P2-1(R4 审查): 就地升级(SRC_DIR==INSTALL_DIR)无法像异地 rsync --delete 那样
  # 清理上版本已删除的陈旧 .py。用户把 v1.9.146 解压覆盖到 /opt/ebpdns/ 后, 若新版
  # 删了 ebpdns/old_module.py, 该文件仍残留——Python 包目录导入虽不主动加载死模块,
  # 但若代码用 importlib.import_module("ebpdns." + name) 动态枚举会误加载, 且与异地
  # 升级行为漂移。这里用白名单对齐当前发布包的模块清单, 删除 ebpdns/ 下多余的 .py。
  # 维护提醒: 新增/删除模块时同步更新此白名单。
  _whitelist_py="__init__.py __main__.py cli.py api.py bpf_loader.py resolver.py server.py cache.py config.py telemetry.py upstream.py dnsmsg.py probe.py quic_upstream.py"
  if [[ -d "${INSTALL_DIR}/ebpdns" ]]; then
    ( cd "${INSTALL_DIR}/ebpdns" && \
      for _f in *.py; do
        [[ -e "$_f" ]] || continue
        case " $_whitelist_py " in
          *" $_f "*) : ;;
          *) echo "[INFO] 就地升级清理上版本残留模块: ebpdns/$_f"; rm -f -- "$_f" ;;
        esac
      done )
  fi
  # bin/ 下仅保留 ebpdns 入口, 清理任何陈旧可执行文件(与异地 rsync --delete 对齐)。
  if [[ -d "${INSTALL_DIR}/bin" ]]; then
    ( cd "${INSTALL_DIR}/bin" && \
      for _f in *; do
        [[ -e "$_f" ]] || continue
        [[ "$_f" == "ebpdns" ]] || { echo "[INFO] 就地升级清理 bin/$_f"; rm -f -- "$_f"; }
      done )
  fi
  # P3-8(R12): 就地分支此前清了 __pycache__/*.pyc/白名单 .py/bin/, 但未像异地 cp 回退路径
  # (:214 tests/、:218 artifacts/)那样后置清理 tests/ 与 artifacts/ 目录。裸源码就地升级覆盖
  # 到 /opt/ebpdns 时这两类目录会残留(daemon 不 import, 仅目录残留, 与异地升级口径对齐清除)。
  find "${INSTALL_DIR}" -type d -name 'tests' -prune -exec rm -rf {} + 2>/dev/null || true
  find "${INSTALL_DIR}" -type d -name 'artifacts' -prune -exec rm -rf {} + 2>/dev/null || true
else
  echo "==> 1/4 复制代码到 ${INSTALL_DIR}"
  # P2-26(第九轮审查): 异地安装前, 若发布包附带 SHA256SUMS, 先校验文件完整性。
  # 防止传输中断/磁盘损坏导致半拷贝包直接进 /opt, 后续 systemd 启动才报 ModuleNotFoundError。
  # 就地安装分支上方已做关键文件存在性检查, 此处只对异地拷贝包做 sha256 校验。
  if [ -f "$SRC_DIR/SHA256SUMS" ]; then
    echo "[INFO] 校验文件完整性..."
    # P3-5(R2 审查): sha256sum -c 失败时它本身已把 "FAILED" 行打到 stdout/stderr;
    # 原脚本只笼统打一句"文件完整性校验失败", 用户看不到哪个文件不通过。
    # 这里保留 sha256sum 的输出(不重定向), 失败后再补一句指向 FAILED 行的提示。
    (cd "$SRC_DIR" && sha256sum -c SHA256SUMS) || { echo "[ERROR] 文件完整性校验失败(详见上方 FAILED 行, 重新下载/拷贝发布包后再安装)" >&2; exit 1; }
  fi
  mkdir -p "${INSTALL_DIR}"
  if command -v rsync >/dev/null 2>&1; then
    # v1.9.90: --delete 重新引入, 但仅按纯代码子目录逐项加 --delete(尾斜杠语义),
    # 清理上一版本已删除的陈旧 .py/入口文件, 避免升级后残留死模块被误导入。
    # 不做整目录 --delete: 用户数据目录是独立的 /etc/ebpdns(rules_local.json/cache.json),
    # 不在 ${INSTALL_DIR} 内, 天然不受影响。
    # R5 P3-1: bpf/ 不加 --delete——bpf/ 是真实 XDP 内核旁路 C 源码, 进阶用户会就地
    # make 出 ebpdns_xdp.o(构建产物)甚至自定义改 .c; 带 --delete 升级会静默清除这些
    # 不在发布包清单里的文件(与下方 cp 回退路径行为对齐)。etc/(配置模板)保留 --delete,
    # 清陈旧模板。
    # v1.9.80: rsync 失败必须立即中止(磁盘满/权限不足), 不带 || true。
    # R6 P3-1: --exclude='artifacts' 与 package.sh 的 ebpdns/artifacts prune 口径对齐,
    # 防止裸 clone 时审查调试脚本(_r48_test.py 等)被拷入 /opt/ebpdns。
    for _d in bin ebpdns web systemd; do
      rsync -a --delete --ignore-missing-args \
        --exclude='*.pyc' --exclude='__pycache__' --exclude='artifacts' \
        "${SRC_DIR}/${_d}/" "${INSTALL_DIR}/${_d}/"
    done
    # bpf/: 纯覆盖拷贝, 不加 --delete(见上方 R5 P3-1 注释)
    rsync -a --ignore-missing-args \
      --exclude='*.pyc' --exclude='__pycache__' \
      "${SRC_DIR}/bpf/" "${INSTALL_DIR}/bpf/"
    # etc/(配置模板) + 顶层 README/LICENSE/NOTICE: --delete 仅镜像 etc/ 内部陈旧模板
    rsync -a --delete --ignore-missing-args \
      --exclude='*.pyc' --exclude='__pycache__' --exclude='tools' \
      --exclude='deploy-test' --exclude='tests' \
      "${SRC_DIR}/etc/" "${INSTALL_DIR}/etc/"
    # P3-11(R12): 原 `2>/dev/null || true` 静默吞掉 README/LICENSE/NOTICE 拷贝失败(磁盘满/只读挂载)。
    # 文档非运行时依赖, 缺失不影响 daemon, 故为非致命——改为显式 WARN(与同脚本 chown/chmod
    # 显式 WARN 风格对齐), 用户不再对文档缺失无感知。
    # R17 P3-1: NOTICE(第三方组件归属声明, Apache-2.0/GPL-2.0 随附声明)与 LICENSE/README 同等
    # 拷贝——异地部署后若将 /opt/ebpdns 整体再分发(Docker/VM 模板), 归属声明必须随附, 否则
    # 构成 Apache-2.0 合规缺失。
    cp -f "${SRC_DIR}/README.md" "${SRC_DIR}/LICENSE" "${SRC_DIR}/NOTICE" "${INSTALL_DIR}/" \
      || echo "[WARN] README/LICENSE/NOTICE 拷贝失败(不影响运行, 仅文档/归属声明缺失)"
  else
    # rsync 不可用 → 退回 cp。纯代码子目录(bin/ebpdns/web/systemd)先删旧再拷,
    # 对齐 rsync --delete: 清除上版本已删除的陈旧 .py/入口文件。bpf(用户就地 make 产物)按覆盖拷贝。
    # 用户数据目录 /etc/ebpdns 独立于 ${INSTALL_DIR}, 不受影响。
    for _d in bin ebpdns web systemd; do
      rm -rf -- "${INSTALL_DIR:?}/${_d}"
    done
    # R18 P3-1: etc/(纯配置模板)与上方 rsync 分支 --delete(install.sh:197-200)口径对齐——
    # 先清空目标 etc 再覆盖拷贝, 清除上版本已删除/改名的陈旧模板。原 cp 分支仅 mkdir+cp 覆盖,
    # 与 rsync --delete 漂移(陈旧模板残留)。bpf/ 不删: rsync 分支 bpf 无 --delete(install.sh:193-195),
    # 保留用户就地 make 出的 ebpdns_xdp.o / 自定义 .c; 用户真实数据在独立的 /etc/ebpdns, 不在
    # ${INSTALL_DIR}/etc, 此处清空安全。
    rm -rf -- "${INSTALL_DIR:?}/etc"
    mkdir -p "${INSTALL_DIR}"/bin "${INSTALL_DIR}"/ebpdns "${INSTALL_DIR}"/web \
             "${INSTALL_DIR}"/bpf "${INSTALL_DIR}"/etc "${INSTALL_DIR}"/systemd
    cp -r "${SRC_DIR}"/bin "${SRC_DIR}"/ebpdns "${SRC_DIR}"/web \
          "${SRC_DIR}"/bpf "${SRC_DIR}"/etc "${SRC_DIR}"/systemd "${INSTALL_DIR}/"
    # P3-11(R12): 同上方 rsync 分支, 移除 `2>/dev/null || true` 静默吞, 拷贝失败显式 WARN(非致命)。
    # R17 P3-1: NOTICE 与 LICENSE/README 同等拷贝(见上方 rsync 分支注释), 保证 cp 回退路径
    # 异地部署后归属声明不缺失。
    cp -f "${SRC_DIR}"/README.md "${SRC_DIR}"/LICENSE "${SRC_DIR}"/NOTICE "${INSTALL_DIR}/" \
      || echo "[WARN] README/LICENSE/NOTICE 拷贝失败(不影响运行, 仅文档/归属声明缺失)"
    # R31 P3-4: rsync 路径有 --exclude(*.pyc / __pycache__ / tests), cp 回退路径无 exclude 能力。
    # 拷贝后置清理构建缓存与测试目录, 避免陈旧 .pyc/__pycache__/tests 进入 /opt/ebpdns,
    # 与 rsync 路径排除项行为对齐。失败(目录不存在等)静默忽略, 不影响主安装流程。
    find "${INSTALL_DIR}" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
    find "${INSTALL_DIR}" -name '*.pyc' -delete 2>/dev/null || true
    find "${INSTALL_DIR}" -type d -name 'tests' -exec rm -rf {} + 2>/dev/null || true
    # R7 P3-4: rsync 路径带 --exclude='artifacts'(install.sh:184), cp 回退路径无 exclude 能力,
    # 后置清理清单补 artifacts/ 目录, 与 rsync exclude 口径对齐——防裸 clone + 无 rsync 极端精简
    # 环境下把调试/审查脚本(ebpdns/artifacts/*.py)拷入 /opt/ebpdns。-prune 防止递归进已删目录。
    find "${INSTALL_DIR}" -type d -name 'artifacts' -prune -exec rm -rf {} + 2>/dev/null || true
  fi
fi

chmod +x "${INSTALL_DIR}/bin/ebpdns"
# P3-5(R3 修复): 原 `|| true` 静默吞掉 chown 失败。/opt/ebpdns 若在只读挂载/NFS root-squash
# 上, chown 失败会被掩盖, 后续 systemd 以 root 启动可能因属主不对触发权限问题而脚本仍报"完成"。
# 改为显式 WARN(非致命, root 仍可读既有 root 文件), 不再静默。
chown -R root:root "${INSTALL_DIR}" 2>/dev/null \
  || echo "[WARN] chown ${INSTALL_DIR} 失败(只读挂载/NFS root-squash?), 请人工确认文件属主为 root"
# v1.9.150 R-fix(Debian 13 实测确认): 收敛**整个**安装目录的可读/可进入权限。
# 原实现只放宽了 web/(目录 755 + 静态文件 644), 未处理 ebpdns/*.py 与 bin/ebpdns。
# 若发布包在 umask 077 下解包、或用户从受限介质拷贝(文件 600 root:root), 上面
# `chown -R root:root` 之后服务用户 ebpdns 既读不到模块、也无法执行入口:
#   systemd 报 "Failed to execute /opt/ebpdns/bin/ebpdns: Permission denied",
#   status=203/EXEC, Restart=on-failure 反复重启直到 StartLimitBurst 进入 failed。
# Debian 13 实测复现: 源码树 go-rwx 后跑 install.sh → 服务起不来, 且**首次安装路径
# 不做 is-active 复核**, 脚本仍打印"4/4 完成", 运维看到的是"装好了但 53 没有服务"。
# a+rX 语义: 所有文件可读, 目录可进入, 已带执行位的文件保留可执行 —— 正好覆盖需求。
chmod -R a+rX "${INSTALL_DIR}" 2>/dev/null \
  || echo "[WARN] chmod -R a+rX ${INSTALL_DIR} 失败, 请人工确认 ebpdns 用户可读代码与执行入口"
# M2 修复: 降权后服务以 ebpdns 用户运行, 需读 /opt/ebpdns/web/ 下的静态控制台资源。
# (a+rX 已覆盖, 以下保留为显式声明与历史意图说明。)
chmod 755 "${INSTALL_DIR}/web" 2>/dev/null || true
# P3-9(R12): 收窄通配到 web/ 实际存在的文件类型。web/ 发布包仅含 index.html / echarts.min.js /
# favicon.svg(P3-1 新增), 原大括号里的 .css/.png/.ico 永不命中(空 glob 被 || true 静默吞, 死 glob)。
# 现仅 chmod 真实存在的三类扩展名; favicon.svg 纳入 644 保证 ebpdns 用户可读。
chmod 644 "${INSTALL_DIR}/web/"*.{html,js,svg} 2>/dev/null || true

# ---------- 1.5/4 eBPF 内核态缓存: 编译 XDP .o +  capabilities (v1.9.158 §8) ----------
# 检测 clang/llvm/libbpf-dev。工具链齐全则编译 ebpdns_xdp.o; 缺失则跳过,
# 服务以纯用户态运行(kernel_cache 默认 False, 不影响功能)。
echo "==> 1.5/4 eBPF 内核态缓存检测与工具链自动安装"

# ---------- 运行时必备工具(自动安装) ----------
# iproute2(`ip`)  : bpf_loader 的 bpftool 降级路径需要它 attach XDP
# libcap2-bin(setcap): 打印非 systemd 手动运行的能力授予指引
_ensure_pkg ip      iproute2  "iproute2(网卡操作)"  || true
_ensure_pkg setcap  libcap2-bin "libcap2-bin(setcap)" || true
# rsync: 异地安装/升级用它做 --delete 同步(清除上版本已删除的陈旧 .py)。
# 缺失时有 cp 回退可用, 不阻断安装; 但装上可保证升级语义与 rsync 分支一致。
_ensure_pkg rsync   rsync     "rsync(增量同步)"   || true

# ---------- eBPF 编译工具链(可选功能, 自动安装) ----------
# bpf/Makefile 依赖: make clang llvm libbpf-dev linux-libc-dev bpftool
#   * make         —— Makefile 的执行器(编译/clean/install 目标都靠它)
#   * clang        —— 编译 .bpf.c 为 BPF 目标文件
#   * llvm-strip   —— Makefile 校验/裁剪(BPF_TARGET=bpfel 需要 llvm 工具集)
#   * libbpf-dev   —— <bpf/bpf_helpers.h> 等头文件
#   * linux-libc-dev —— <linux/bpf.h> 等内核 UAPI 头(部分系统由 libc6-dev 提供)
#   * bpftool      —— `gen skeleton` 目标(缺它只影响 .skel.h, 不阻塞 .o)
# 说明: 这些是**可选加速层**的工具链。装不上不影响 DNS 服务(纯用户态 LRU 照常工作),
# 故失败只提示不中断部署。
_BPF_TOOLCHAIN_OK=1
# v1.9.161 R-fix(用户实测): make 是 Makefile 执行器, 缺它则 `make: command not found`
# —— 之前漏装了 make(仅装了 clang/llvm/头文件/bpftool)。干净机器上编译必然失败。
_ensure_pkg make make "make(BPF 构建工具)" || _BPF_TOOLCHAIN_OK=0
if ! command -v clang >/dev/null 2>&1; then
  _ensure_pkg clang clang "clang(BPF 编译器)" || _BPF_TOOLCHAIN_OK=0
fi
if [[ "$_BPF_TOOLCHAIN_OK" == "1" ]] \
   && ! { command -v llvm-strip >/dev/null 2>&1 || command -v llvm-objdump >/dev/null 2>&1; }; then
  _ensure_pkg llvm-strip llvm "llvm(工具集)" || _BPF_TOOLCHAIN_OK=0
fi
if [[ "$_BPF_TOOLCHAIN_OK" == "1" ]]; then
  _ensure_path /usr/include/bpf/bpf_helpers.h libbpf-dev "libbpf-dev(BPF 头文件)" \
    || _BPF_TOOLCHAIN_OK=0
fi
if [[ "$_BPF_TOOLCHAIN_OK" == "1" ]]; then
  _ensure_path /usr/include/linux/bpf.h linux-libc-dev "linux-libc-dev(内核 UAPI 头)" \
    || _BPF_TOOLCHAIN_OK=0
fi
# bpftool: 只在需要 .skel.h 时必需; 但 loader 的降级路径也用它, 故一并装。
_ensure_pkg bpftool bpftool "bpftool(BPF 工具)" || true

if [[ "$_BPF_TOOLCHAIN_OK" == "1" ]]; then
  echo "    工具链就绪, 编译 ebpdns_xdp.o ..."
  # 只编 .o (loader 实际加载物); skel.h 需 bpftool, 缺失不阻塞 .o。
  # v1.9.161 R-fix: 编译失败时**回显具体错误**。原实现 `>/dev/null 2>&1` 把
  # clang 的错误输出彻底吞掉, 用户只看到一句"编译失败", 却不知是缺头文件、
  # 语法错误还是架构不匹配 —— 必须手动跑 make 才能看, 徒增排查成本。
  # 现在失败时把 make 日志打到 stderr, 一眼可见根因。
  if make -C "${INSTALL_DIR}/bpf" ebpdns_xdp.o >/tmp/ebpdns_make.log 2>&1 \
     || make -C "${SRC_DIR}/bpf" ebpdns_xdp.o >>/tmp/ebpdns_make.log 2>&1; then
    rm -f /tmp/ebpdns_make.log
    # SRC_DIR 构建时拷到 INSTALL_DIR (上面 cp 已发生, 这里补拷一次 .o)
    if [[ -f "${SRC_DIR}/bpf/ebpdns_xdp.o" && ! -f "${INSTALL_DIR}/bpf/ebpdns_xdp.o" ]]; then
      cp -f "${SRC_DIR}/bpf/ebpdns_xdp.o" "${INSTALL_DIR}/bpf/" 2>/dev/null || true
    fi
    if [[ -f "${INSTALL_DIR}/bpf/ebpdns_xdp.o" ]]; then
      echo "    eBPF XDP 程序已编译: ${INSTALL_DIR}/bpf/ebpdns_xdp.o"
    else
      echo "    [WARN] eBPF 编译未见 .o 产物, 将以纯用户态运行"
    fi
  else
    echo "    [WARN] eBPF 编译失败, 将以纯用户态运行（不影响 DNS）"
    echo "    --- 编译错误详情 ---"
    sed 's/^/    | /' /tmp/ebpdns_make.log 2>/dev/null | tail -20
    rm -f /tmp/ebpdns_make.log
    echo "    --- 排查提示 ---"
    echo "    | 缺头文件: apt install -y libbpf-dev linux-libc-dev"
    echo "    | 架构不匹配: 检查 uname -m 与 Makefile 的 -D__TARGET_ARCH_ / include 路径"
  fi
else
  echo "    [提示] eBPF 工具链未齐全, 本机将以纯用户态运行（DNS 功能不受影响）"
  echo "           如需内核态加速, 可手动补装后重跑本脚本:"
  echo "             apt install -y clang llvm libbpf-dev linux-libc-dev bpftool"
fi
# eBPF 内核态缓存免 root 获取 BPF/NET_ADMIN/SYS_ADMIN/IPC_LOCK 能力(供 XDP attach)。
# v1.9.158 修正: bin/ebpdns 是带 shebang 的 Python 脚本(文本文件, 非 ELF), 对它 setcap
# 无效(能力只对 ELF 可执行文件生效)。推荐路径是 systemd 托管: ebpdns.service 已用
# AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN CAP_IPC_LOCK + LimitMEMLOCK=infinity
# 精确授予, 无需 setcap。下面仅打印手动(非 systemd)运行的可选做法, 不自动执行。
echo "    eBPF 能力授予: 推荐走 systemd(ebpdns.service 已配 AmbientCapabilities + LimitMEMLOCK)。"
if command -v setcap >/dev/null 2>&1; then
  _PYELF="$(readlink -f "$(command -v python3)" 2>/dev/null || true)"
  if [[ -n "${_PYELF}" && -f "${_PYELF}" ]]; then
    echo "    若坚持非 systemd 手动运行, 需把能力打在 Python 解释器 ELF 上(脚本本身打 setcap 无效):"
    echo "      sudo setcap cap_bpf,cap_net_admin,cap_sys_admin,cap_ipc_lock+ep '${_PYELF}'"
    echo "    [警告] 这会给整机所有 python3 程序赋予上述特权能力, 安全面大, 不推荐; 请优先用 systemd。"
  fi
else
  echo "    [提示] 未找到 setcap (libcap2-bin); systemd 托管方式无需 setcap。"
fi

# ---------- 兼容性检查（v1.9.163 新增）----------
# 已存在的 config.json 可能来自**另一实现**：Rust 版用 `upstreams[].host`，本版用 `addr`；
# 此时"保留不动"会让所有上游被 config.py 判为非法并**整体丢弃**（实测 22/22 被丢），
# api.port / web_root / bootstrap_dns 也可能不是本版形态 → 表现为"服务起来了但一个上游都不通、
# 控制台端口不对"。检测到即备份旧文件，改用本次发行模板。
if [[ -f "${CONF_DIR}/config.json" ]]; then
  if python3 - "${CONF_DIR}/config.json" <<'PYEOF' 2>/dev/null
import json, sys
try:
    c = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(0)                      # 解析失败/损坏 → 同样视为不兼容：备份并用发行模板重建
up = c.get("upstreams") or []
rust_schema = any(isinstance(u, dict) and ("host" in u) and ("addr" not in u) for u in up)
api = c.get("api") if isinstance(c.get("api"), dict) else {}
bad_api = api.get("port") not in (None, 8080)
sys.exit(0 if (rust_schema or bad_api) else 1)
PYEOF
  then
    _cfg_bak="${CONF_DIR}/config.json.incompat-$(date +%Y%m%d-%H%M%S).bak"
    cp -f "${CONF_DIR}/config.json" "${_cfg_bak}" 2>/dev/null || true
    echo "[WARN] 现有 ${CONF_DIR}/config.json 来自其它实现（Rust 版 schema 或非 8080 控制台端口）"
    echo "       已备份到 ${_cfg_bak}；将按本次发行模板重建（如需保留旧设置请手动合并）。"
    rm -f "${CONF_DIR}/config.json" 2>/dev/null || true
  fi
fi

# ---------- 2/4 生成配置 ----------
echo "==> 2/4 生成配置 ${CONF_DIR}/config.json"
# P3-5(R3 修复): 原 `|| true` 静默吞掉 mkdir 失败。无法创建配置目录属致命错误, 立即中止并提示。
mkdir -p "${CONF_DIR}" \
  || { echo "[ERROR] 无法创建配置目录 ${CONF_DIR}(权限不足?)" >&2; exit 1; }
if [[ ! -f "${CONF_DIR}/config.json" ]]; then
  # R5 P3-2: 原两处 `cp -f ... || true` 静默吞掉配置模板拷贝失败(磁盘满/只读挂载)。
  # 模板存在但拷贝失败时不再静默——先定位模板, 拷贝失败打印 [WARN] 并回退到下方 python 兜底。
  _cfg_tmpl=""
  if [[ -f "${INSTALL_DIR}/etc/ebpdns.conf.json" ]]; then _cfg_tmpl="${INSTALL_DIR}/etc/ebpdns.conf.json"
  elif [[ -f "${SRC_DIR}/etc/ebpdns.conf.json" ]]; then _cfg_tmpl="${SRC_DIR}/etc/ebpdns.conf.json"; fi
  if [[ -n "${_cfg_tmpl}" ]]; then
    if ! cp -f "${_cfg_tmpl}" "${CONF_DIR}/config.json"; then
      echo "[WARN] 配置模板拷贝失败(${_cfg_tmpl}), 将写入最小默认配置" >&2
      rm -f "${CONF_DIR}/config.json" 2>/dev/null || true
    fi
  fi
  if [[ ! -f "${CONF_DIR}/config.json" ]]; then
    # v1.9.76: 配置模板缺失(精简包未带 etc/), 用 python3 -c 落一份最小可用默认配置,
    # 避免 config.json 不存在导致后续 chmod/systemd 启动失败。
    # v1.9.80: 兜底 api.host 改 127.0.0.1(与 DEFAULTS 一致), 避免控制台意外暴露到局域网;
    # R5 P2-2: listen 与 api.host 一致用 127.0.0.1:53(旧注释误写 0.0.0.0, 与代码及下方"下一步"提示不符),
    #          DNS 默认仅本机; 需局域网 DNS/控制台访问时用户显式把 api.host/listen 改为 0.0.0.0。
    # R10 P2: Python 布尔字面量必须大写 True/False, 小写 true 会触发 NameError: name 'true' is not defined。
    echo "    (未找到配置模板, 写入最小默认配置)"
    python3 -c 'import json; json.dump({"listen":{"udp":"127.0.0.1:53","tcp":"127.0.0.1:53"},"api":{"host":"127.0.0.1","port":8080},"upstreams":[{"id":"ali","name":"AliDNS","proto":"udp","addr":"223.5.5.5","port":53,"url":"","group":"domestic","latency":5000,"enabled":True}]}, open("'"${CONF_DIR}/config.json"'","w"), ensure_ascii=False, indent=2)' || { echo "错误: 写入兜底配置失败" >&2; exit 1; }
  fi
  echo "    (新配置已创建, 请按需编辑上游/端口/规则)"
else
  echo "    (已存在配置, 保留不动)"
fi
# P3-5(R3 修复): chown 失败显式 WARN 而非静默 `|| true`。
# v1.9.90: 服务现以 ebpdns 用户运行(systemd User=ebpdns), 配置目录需读写(含
# cache.json/rules_sub.json/rules_local.json 落盘), 故属主改 ebpdns:ebpdns,
# 目录权限 750(仅 ebpdns 与 root 可读/进入), config.json 保持 640。
chown -R ebpdns:ebpdns "${CONF_DIR}" 2>/dev/null \
  || echo "[WARN] chown ${CONF_DIR} 失败(只读挂载/NFS root-squash?), 请人工确认配置属主为 ebpdns"
chmod 750 "${CONF_DIR}" \
  || echo "[WARN] chmod 750 ${CONF_DIR} 失败(只读挂载?), 请人工确认配置目录权限为 750"
# v1.9.76: chmod 前判存在, 防模板缺失且 python 落盘失败时 chmod 报错中断安装
# v7 P2-4: 644(全局可读)→640(仅 root 可读/组可读), 配置含上游地址/订阅链接, 不应全局可读
# R31 P3-1: 与上方 chown 显式 WARN 风格对齐。文件不存在时条件已判静默跳过;
# 文件存在但 chmod 失败(只读挂载/NFS root-squash)时打 WARN, 不再静默吞掉。
[[ -f "${CONF_DIR}/config.json" ]] && (chmod 640 "${CONF_DIR}/config.json" \
  || echo "[WARN] chmod 640 config.json 失败(只读挂载?), 请人工确认配置权限为 640") || true

# ---------- 3/4 安装 systemd 服务 ----------
echo "==> 3/4 安装 systemd 服务"
if [[ -f "${SRC_DIR}/systemd/ebpdns.service" ]]; then
  # R5 P3-3: 原 `cp -f ... || true` 静默吞掉 unit 拷贝失败。unit 文件是 systemd 启动的必需件,
  # 拷贝失败属致命错误(否则 daemon-reload 沿用旧 unit, R3/R4 新增硬化项缺失且无任何提示), 显式报错并中止。
  cp -f "${SRC_DIR}/systemd/ebpdns.service" "${UNIT_FILE}" \
    || { echo "[ERROR] systemd unit 拷贝失败: ${UNIT_FILE}" >&2; exit 1; }
elif [[ -f "${INSTALL_DIR}/systemd/ebpdns.service" ]]; then
  cp -f "${INSTALL_DIR}/systemd/ebpdns.service" "${UNIT_FILE}" \
    || { echo "[ERROR] systemd unit 拷贝失败: ${UNIT_FILE}" >&2; exit 1; }
fi
# 两个来源都不存在时, 若本机也无旧 unit 文件则服务无法启动, 属致命错误中止。
[[ -f "${UNIT_FILE}" ]] || { echo "[ERROR] 未找到 systemd unit 模板且 ${UNIT_FILE} 不存在" >&2; exit 1; }
chmod 644 "${UNIT_FILE}"
# v1.9.81: 检测 systemd 是否真正在运行(不只是有 systemctl 命令), 容器/WSL/chroot 中
# systemctl 存在但 PID 1 不是 systemd, daemon-reload 会报错中断安装
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || echo "    (daemon-reload 失败, 跳过)"
  # R31 P3-2: 与下方 timer enable 的显式 WARN 风格对齐, 不再静默 `|| true` 吞掉 enable 失败。
  # enable 失败(unit 损坏/systemd 异常)时用户无感知直到手动 start 才发现, 改为显式 WARN 并给出手动命令。
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 \
    || echo "    [WARN] enable 服务失败, 请手动执行: systemctl enable ${SERVICE_NAME}"
  # v1.9.83: 安装每日低峰重启 timer(内存卫生兜底, 每天 04:30 ± 5min)
  # P3-6(第七轮审查): 原两处 `cp ... || true` 静默吞掉 timer/service 拷贝失败。
  # 拷贝失败时主 ebpdns.service 仍在(上面已强制拷贝), 仅丢失每日内存卫生自动重启,
  # 故为非致命——改为显式 WARN(与 chown 风格对齐), 不再静默。
  if [[ -f "${SRC_DIR}/systemd/ebpdns-restart.timer" ]]; then
    cp -f "${SRC_DIR}/systemd/ebpdns-restart.service" /etc/systemd/system/ \
      || echo "[WARN] 重启 service 拷贝失败, 将无每日内存卫生自动重启(主服务不受影响)"
    cp -f "${SRC_DIR}/systemd/ebpdns-restart.timer" /etc/systemd/system/ \
      || echo "[WARN] 重启 timer 拷贝失败, 将无每日内存卫生自动重启(主服务不受影响)"
    # P3-N2(R4): restart.service/timer 拷入晚于上方唯一一次 daemon-reload(283),
    # 补一次 reload 使 disk 上的新 unit 立即被 systemd 识别, 兼容较老 systemd(隐式 reload 不保证)。
    systemctl daemon-reload || echo "    (daemon-reload 失败, 跳过)"
    # P3-3(第八轮审查): 原 `|| true` 静默吞掉 enable/start 失败。与上方 timer/service 拷贝
    # 的 WARN 风格对齐——启用/启动失败只丢失每日内存卫生自动重启, 主服务不受影响, 故为非致命,
    # 改为显式 WARN, 不再静默。
    systemctl enable ebpdns-restart.timer >/dev/null 2>&1 \
      || echo "[WARN] timer 启用失败, 将无每日内存卫生自动重启(主服务不受影响)"
    systemctl start ebpdns-restart.timer >/dev/null 2>&1 \
      || echo "[WARN] timer 启动失败, 将无每日内存卫生自动重启(主服务不受影响)"
  fi
  # R5 P3-2: 升级场景——新 .py 已落 ${INSTALL_DIR}, 但运行中的旧进程仍在内存跑旧字节码。
  # 检测服务当前 active: 是(升级)→显式 restart 使新代码立即生效, 否则用户照末尾提示
  # `systemctl start` 对 active 单元是空操作, 误以为升级完成实际跑旧代码;
  # 否(首次安装)→不擅自拉起服务, 保持由用户按末尾提示手动 start 的原有行为。
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "    检测到 ${SERVICE_NAME} 正在运行(升级场景), 重启以加载新代码(中断 DNS 约 5-10s)..."
    systemctl restart "${SERVICE_NAME}" \
      || echo "    [WARN] restart ${SERVICE_NAME} 失败, 请手动执行: sudo systemctl restart ${SERVICE_NAME}"
    # R6 P3-3: systemctl restart 返回 0 仅表示指令被 systemd 接受, 不代表新进程成功拉起。
    # 新代码若启动即崩(导入错误/配置不兼容), systemd 会崩溃循环后进入 failed, 此处必须
    # 复核 active, 否则脚本打印"4/4 完成"而实际 DNS 已停。
    sleep 3
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
      echo "    [ERROR] 重启后 ${SERVICE_NAME} 未进入 active 状态, 新代码可能启动失败," >&2
      echo "             请检查: sudo journalctl -u ${SERVICE_NAME} -n 50" >&2
    fi
  else
    # v1.9.150 R-fix(Debian 13 实测): 首次安装路径原本**完全不复核服务状态**,
    # 脚本照样打印"4/4 完成"。当 /opt/ebpdns 下代码/入口对服务用户不可读时
    # (发布包 umask 077 解包、从受限介质拷贝等), systemd 会以
    # status=203/EXEC 失败并反复重启, 而运维看到的是"装好了但 53 端口没有服务",
    # 毫无线索。这里做一次**不改变行为**的预检: 只启动→观察→停止, 明确报告结果。
    # 仅在用户尚未让服务运行时执行(避免干扰"由用户手动 start"的既有语义)。
    echo "    首次安装: 做一次启动预检(启停各一次, 不改变服务最终状态)..."
    if systemctl start "${SERVICE_NAME}" >/dev/null 2>&1; then
      sleep 3
      if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo "    预检通过: ${SERVICE_NAME} 可正常启动"
        systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
      else
        echo "    [ERROR] 预检失败: ${SERVICE_NAME} 启动后未进入 active 状态" >&2
        echo "             常见原因: 代码/入口对 ${SERVICE_NAME} 用户不可读(权限)," >&2
        echo "                       端口 53 被占用, 或配置非法。" >&2
        echo "             排查: sudo journalctl -u ${SERVICE_NAME} -n 50" >&2
        echo "                   sudo -u ebpdns test -r ${INSTALL_DIR}/ebpdns/cli.py && echo readable" >&2
      fi
    else
      echo "    [WARN] 预检无法启动 ${SERVICE_NAME}, 请手动确认: sudo systemctl start ${SERVICE_NAME}"
    fi
  fi
else
  echo "    (未检测到运行中的 systemd, 跳过 daemon-reload/enable; 请手动启动 ebpdns)"
fi

# ---------- 4/4 完成 ----------
echo "==> 4/4 完成"
echo ""
echo "  已安装:"
echo "    代码     ${INSTALL_DIR}"
echo "    配置     ${CONF_DIR}/config.json"
echo "    服务     ${SERVICE_NAME} (systemd)"
echo ""
echo "  下一步:"
echo "    1. 编辑配置:  sudo nano ${CONF_DIR}/config.json"
echo "       - 默认监听 127.0.0.1:53 (DNS) + 127.0.0.1:8080 (控制台, 仅本机)"
echo "       - 如 53 端口被占用(systemd-resolved), 先禁用或改用其他端口"
echo "       - 需局域网访问时把 api.host 改为 0.0.0.0 并注意安全"
echo "    2. 启动:      sudo systemctl start ${SERVICE_NAME}"
echo "    3. 状态:      sudo systemctl status ${SERVICE_NAME}"
echo "    4. 控制台:    本机浏览器打开 http://127.0.0.1:8080/  (局域网访问需改 api.host)"
echo "    5. 测试解析:  dig @127.0.0.1 www.baidu.com"
echo ""
echo "  数据面: 用户态 LRU 已启用; eBPF XDP 内核旁路为预留接口(参考实现见 ${INSTALL_DIR}/bpf/README.md)"
echo ""
echo "  可选 DoQ/DoH3 上游(需要 aioquic):"
if python3 -c 'import aioquic' 2>/dev/null; then
  echo "    - aioquic 已安装, DoQ/DoH3 上游可直接使用"
else
  echo "    - 未检测到 aioquic, 使用 DoQ/DoH3 上游需先:  sudo python3 -m pip install aioquic"
  echo "      (UDP/TCP/DoH/DoT 上游不受影响)"
fi
