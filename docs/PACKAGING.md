# ebpdns 打包 / 安装 / 升级说明

**适用范围：ebpdns 2.1.49**（版本单一来源 = 根 `Cargo.toml` 的 `[workspace.package] version`）。

本文件是 `packaging/`（`install.sh` / `systemd/` / `etc/`）与 `scripts/make_packages_221r2.sh`
的**行为契约**：产物形态、安装/升级/卸载语义、**安装器隔离判据（§3.3）**、双清单作用域、
六道打包门、**14 项门禁**、构建配方与可复现口径。

---

## 1. 产物形态

| 形态 | 谁生成 | 内容 |
|---|---|---|
| 源码树 | 开发者 | `crates/` + `web/` + `packaging/` + `scripts/` |
| prod 包（`ebpdns-2.1.49-prod.tar.gz`） | `scripts/make_packages_221r2.sh` | 白名单 13 个文件（含 `_md5_prod.txt`）：`bin/ebpdns`、`web/{app_bg.wasm,app.js,index.html,style.css,echarts.min.js,favicon.svg}`、`etc/ebpdns/config.json`、`systemd/ebpdns.service`、`install.sh`、`LICENSE`、`NOTICE`；根目录名 `ebpdns-2.1.49/` |
| src 包（`ebpdns-2.1.49-src.tar.gz`） | 同上 | 完整源码树（排除 `target/`、`web/target/`、`web/dist/`、`dist-packages/`），根目录名 `ebpdns-2.1.49/` |

prod 包的目录结构**就是** `install.sh` 的输入契约：

```text
ebpdns-2.1.49/
├── bin/ebpdns                 # 已嵌入前端的 release 二进制
├── web/                       # 前端静态资源（额外留档；二进制内也已嵌入）
├── etc/ebpdns/config.json     # 默认配置
├── systemd/ebpdns.service
├── install.sh
├── LICENSE
├── NOTICE
└── _md5_prod.txt
```

**解包必须保留权限**：用 `tar -xzf`（Linux）或解包后 `chmod +x bin/ebpdns install.sh`（Windows）。
安装器对包内二进制缺执行位会自愈（临时 0755 副本），但 `install.sh` 本身没有执行位时只能手工 `bash install.sh`。

---

## 2. 出厂默认的已知取舍

随包模板 `packaging/etc/ebpdns/config.json` 与 `default_config()` **逐键一致**（门禁
`default_config_matches_packaging_template` / `new_install_config_matches_default_and_template`）。
既有安装不会被覆盖；只有 `--adopt-new-defaults` 才用模板覆盖（先备份 `config.json.bak.<ts>`）。

| 键 | 默认 | 取舍 |
|---|---|---|
| `cache_size` | `131072` | 内存上界偏大（每条约 117 kB 常驻；小内存机请按 `容量 × 117 kB` 下调） |
| `ttl_min` | `5` | 对上游 <5 s 记录做 TTL 抬升（在意 TTL 契约设 0） |
| `speed_test` / `speed_interval_ms` | `true` / `2000` | 默认带背景测速流量 |
| `serve_stale` / `stale_ttl` | `true` / `604800` | 最长 7 天提供陈旧数据 |
| `rule_sub_interval` | `3600` | 每小时订阅轮询；内容未变不清缓存/索引 |
| `cache_persist` / `cache_save_interval` | `true` / `60` | v2 快照 + WAL：非优雅退出丢失窗口 ≤ 1 s（WAL 每 1 s `fdatasync`），不是整个周期 |

**快照年龄与 TTL**：v2 恢复只承接未过期条目，重启后命中率恢复取决于 `snapshot_age_s` 与 TTL 的关系，
而不是 `cache_save_interval`。快照按时间重写，节拍 = `min(1800 s, TTL/2)`（`TTL = max(ttl, ttl_max)`）；
`/api/status.cache.persist.snapshot_age_s` 供运维预判。经验判据：`snapshot_age_s ≤ TTL/2` 时重启后 5 s
命中率与重启前基本一致；长期接近/超过 TTL ⇒ 查 ERROR 日志与磁盘。

**升级时的 XDP 键清理**：启动/`check-config` 自动剔除 8 个已移除键
（`hook` / `iface` / `kernel_cache` / `kernel_cache_iface` / `kernel_cache_max` / `kernel_direct` /
`map_type` / `percpu`），原子重写 `config.json`，`config_version` 保持 3。

---

## 3. `install.sh` 开关与退出码

```bash
sudo ./install.sh                      # 安装 + enable，不自动启动
sudo ./install.sh start                # 安装 + enable + 启动（旧实例先停后启）
sudo ./install.sh --dry-run start      # 只打印动作，不改系统
sudo ./install.sh --restart start      # 显式先停后启
sudo ./install.sh --keep-running start # 只更新文件，不动运行中的进程
sudo ./install.sh uninstall            # 卸载（保留 /etc/ebpdns 与 state_dir）
sudo ./install.sh --uninstall --purge  # 连配置与 state_dir 一起删除
sudo ./install.sh --help               # 全部开关与退出码
sudo ./install.sh --unit-name          # 只读打印本前缀派生的 unit 名（不写任何文件）
```

| 开关 | 语义 |
|---|---|
| `--strict-config` | 配置预检/装后复核报 ERROR 时中止（退出码 2） |
| `--migrate-config` | 已有配置**只做加法**补齐缺失键；写前备份 `config.json.bak.<ts>`；与 `--adopt-new-defaults` 同给时以加法为准 |
| `--state-dir <DIR>` | 仅对 `--migrate-config` 生效：显式透传；缺省只用配置里的 `state_dir`；两者都没有 ⇒ rc=3 且零写入 |
| `--adopt-new-defaults` | 备份后用包内模板覆盖（会丢本地改动） |
| `--restart` | 显式「先停后启」；`start` 的默认行为已如此 |
| `--keep-running` | 只更新文件，不停止/不重启（pid 不变；端口占用只 WARN；下次重启生效） |
| `--dry-run` | 只打印计划（账号/目录/文件/停止或启动）并做只读预检；**任何拒绝都发生在打印计划之前**（见 §3.3） |
| `--force` | **2.1.38**：只放开两处具名例外（uninstall 删旧布局遗留 unit 文件；uninstall 时 FragmentPath 在前缀外仍按**派生** unit 名执行）。**进程归属判定不可覆盖** |
| `--purge` | 仅与 uninstall 同用：删除 `/etc/ebpdns` 与 `state_dir` |
| `--unit-name` | **2.1.38**：只读打印派生 unit 名后退出（默认前缀 ⇒ `ebpdns.service`） |
| `-h`, `--help` | 打印用法后退出，不写任何文件 |
| `start` | 安装后启动；检测到**前缀内**自家旧实例 ⇒ 打印 INFO + 目标 pid/exe、先停后启、rc=0；无 systemd 时只打印手动启动命令 |
| `uninstall` | 停服务、disable、删 unit/二进制/静态资源；默认保留配置与 state_dir；**unit 路径必须在前缀内**，否则 rc=1 且不调用 systemctl |

**退出码**：

| 码 | 含义 |
|---|---|
| `0` | 安装完成（含配置 WARN 非严格、无 systemd、账号降级、旧实例成功先停后启、`--keep-running` 跳过重启） |
| `1` | 前置失败：非 root / 缺 `bin/ebpdns` / 用法错误（`--state-dir` 缺值、多余位置参数、`--restart` 与 `--keep-running` 同给）/ 端口被别的进程占用 / **端口被前缀外的 ebpdns 占用（拒绝误停）** / 旧实例停止失败 / **uninstall 的 unit 路径不在前缀内或为旧布局遗留** / GLIBC 不满足 / 系统命令失败 |
| `2` | 布局预检失败；或 `--strict-config` 下配置预检/装后复核失败 |
| `3` | `--migrate-config` 未落盘（无 `state_dir` 且未给 `--state-dir`）⇒ 只读报告、零写入 |
| `4` | 配置已写回、但提交点未重锚（最常见：服务在运行、持有 `state/.lock`） |

**执行顺序**：布局预检 → 装前配置预检 → 二进制可运行性预检（GLIBC）→ 运行实例检测（含**前缀归属**判定，
拒绝即 rc=1 且零写入）→（start/restart 且**前缀内**自家旧实例 ⇒ 先打印目标并 stop/SIGTERM，等端口释放）→
端口占用预检 →（`--dry-run` 到此打印计划并退出）→
建用户/组（幂等 + 分级回退）→ 建目录 → 装二进制/前端 → 装/检查配置 → 属主 → `setcap` →
装后配置复核 → systemd（可用则 unit + daemon-reload + enable + 可选 start；不可用则只装文件 + 打印命令）。

### 3.1 安装前置条件与降级行为

| 前置 | 缺失时的行为 |
|---|---|
| **root** | 必须；非 root 直接 rc=1（演练用 `EBP_INSTALL_ROOT` 前缀到临时目录） |
| **`passwd` 包** | 可选。`groupadd→addgroup→直接追加 /etc/group`、`useradd→adduser→直接追加 /etc/passwd`；全失败只 WARN，`chown` 退化 `root:root`，unit 退化 `User=root` |
| **systemd** | 可选。`systemctl` 不存在或系统非 running/degraded/starting ⇒ 只装文件 + 打印手动启动命令，rc=0 |
| **`ip`/`ss`/`lsof`** | 端口检查依次退化 `ss` → `lsof` → `/proc/net/*`；都没有则 WARN 跳过，不硬失败 |
| **glibc** | 装前用临时副本执行 `--version`；失败打印加载器错误与缺失符号，rc=1。最低要求 **glibc ≥ 2.34**（§7）；不提供 musl 静态构建 |
| **端口冲突** | 来源见 §3.3：被前缀内的自家旧实例占用 ⇒ start 先停后启或 `--keep-running` WARN；被**别的进程**或**前缀外的 ebpdns** 占用 ⇒ 报 pid/exe/端口并 rc=1，在任何写操作之前中止 |
| **解包权限** | 见 §1；安装器对二进制缺执行位自愈 |

### 3.2 部署约束：单机单实例

**部署约束：单机单实例**（`state_dir` 独占锁；第二实例会被拒；隔离实例必须显式 `--state-dir`）。

- 一台机器只跑一个实例；同一 `state_dir` 上的第二实例启动被 `flock` 拒（退出码 2）。
- 服务运行中执行 `--migrate-config` 会拿不到 `state/` 锁 ⇒ rc=4（配置已写回、提交点未更新），不是笼统的 1。
- 审查/联调/A-B 实例必须显式给专用 `--state-dir`，不得沿用默认生产路径。
- 运行时观测：`/api/status.state_persist.lock_held` / `lock_note`。

### 3.3 安装器隔离判据（2.1.38：两条生产事故的根因与五条修法）

两次真实事故（时间线见交付报告）：

- **22:38:42**：`install.sh` 的端口预检读**包内**默认配置 `$(dirname "$0")/etc/ebpdns/config.json`
  （`53` / `8353`），**不跟随** `EBP_INSTALL_ROOT` ⇒ 隔离前缀安装把**生产实例**当成"自家旧实例" `SIGTERM`。
- **23:06:19**：包自测的 PATH 里没有隔离 shim ⇒ `install.sh uninstall` 直接 `stop` + `disable`
  **真 systemd unit**（生产中断 35 min）。

五条修法（每条都有机器判据，回归脚本 `scripts/t-install-isolation.sh`）：

| # | 修法 | 判据（可复核） |
|---:|---|---|
| ① | **端口来源**：只从**目标前缀**配置 `$EBP_INSTALL_ROOT/etc/ebpdns/config.json` 取；显式 `EBP_INSTALL_PORTS` 优先；**不再**无条件读包内默认配置 | 日志恒打印 `端口来源 = …`。目标配置存在时包内模板**永不参与**判定（S6：模板 `53/8353` + 前缀 `1985x` ⇒ rc=0；若读模板则必 rc≠0） |
| ② | **"自家实例"加路径约束**：`realpath(/proc/<pid>/exe)` 必须落在目标前缀内（或 unit 文件在前缀内）才可停 | 前缀外的 `ebpdns` 占端口 ⇒ **rc=1** 且打印 `pid=` / `exe=` / `端口=`，**不发送任何信号**（S1/S5/S5b） |
| ③ | **unit 名与前缀绑定**：非默认前缀派生 `ebpdns-<hash8>.service`（`--unit-name` 可查）；`uninstall` 先校验 unit 路径在前缀内 | `systemctl` 只被指向派生名；旧布局遗留 `etc/systemd/system/ebpdns.service` ⇒ rc=1、零 stop/disable（S4a/S4b/S4c） |
| ④ | **默认安全**：`--dry-run` 与前缀模式默认**不执行**破坏性动作；破坏性动作先打印目标 `pid/exe/unit`；无法证明归属时拒绝（`--force` 只放开两处具名例外） | `--dry-run` 下拒绝分支**不会**打印"将先停止旧实例"（S5）；`[target]` 行给出 pid/exe/unit |
| ⑤ | **回归**：fake systemctl + 前缀，五类场景常跑（并入 `check_all` 第 13 项） | `T_INSTALL_ISOLATION=PASS`；fake shim 调用日志证明**真 systemd 0 次**，生产 `MainPID`/`NRestarts`/`ActiveState`/unit 文件 md5 前后相等 |

端口来源的三种情形（优先级从高到低）：

1. `EBP_INSTALL_PORTS="<dns> <api>"`（显式覆盖，部署代理/回归测试用）；
2. `$EBP_INSTALL_ROOT/etc/ebpdns/config.json`（**目标**配置，正常路径）；
3. 目标前缀尚无配置 ⇒ 本次会安装的**包内模板**（日志明写来源）。这一分支下 ② 仍然生效，
   所以"端口取自模板"**不可能**导致停掉前缀外的进程 —— 那是事故 #1 的另一半根因。

破坏性动作的审计行（`install.sh` 与 `uninstall` 都有）：

```text
[target] pid=245358 exe=/usr/local/bin/ebpdns 端口=53 8353
[target] unit=ebpdns-1a2b3c4d.service unit_path=/tmp/iso/etc/systemd/system/ebpdns-1a2b3c4d.service FragmentPath=…
```

---

## 4. 两道配置预检

| 阶段 | 函数 | 用哪份二进制 | 校验哪份配置 | 何时 |
|---|---|---|---|---|
| 装前 | `preflight_config()` | 包内 `bin/ebpdns`（不可执行时用临时 0755 副本） | 包内 `etc/ebpdns/config.json` | 任何写操作之前 |
| 装后 | `postinstall_check_config()` | 已安装的 `/usr/local/bin/ebpdns` | 目标 `/etc/ebpdns/config.json` | `systemctl enable` 之前 |

两道预检缺一不可：装前校验"包内那份"，装后复核"服务将要面对的那份"。

---

## 5. 配置迁移：`check-config` / `migrate-config`

### 5.1 `check-config`

```bash
ebpdns check-config --config /etc/ebpdns/config.json
```

读配置 → `migrate_cfg` 迁移到当前 schema → 全键类型/范围/枚举校验 + 未知键告警。
退出码：`0` 无错误（告警不致命）；`2` 有错误（配置不可用）。

### 5.2 `migrate-config`（只做加法）

```bash
ebpdns migrate-config --config /etc/ebpdns/config.json --dry-run
ebpdns migrate-config --config /etc/ebpdns/config.json --state-dir /var/lib/ebpdns/state
ebpdns migrate-config --config /etc/ebpdns/config.json --export-legacy
```

补 `default_config()` 有而文件里缺的**顶层键**（绝不改/删用户已给出的值）→ schema 迁移 →
备份 `config.json.bak.<ts>` → 原子写回 → 打印逐键差异。

| 退出码 | 含义 |
|---|---|
| `0` | 完成（含无缺失键的 no-op 与 `--dry-run`） |
| `1` | 文件系统/备份/写回失败 |
| `2` | 不是合法 JSON 对象 / 迁移后仍有错误（不改文件）；`--export-legacy` 真源不可解析同样 rc=2 |
| `3` | 未落盘：既无 `--state-dir`、配置里也无 `state_dir` ⇒ 只读报告、零写入 |
| `4` | 配置已写回、提交点未更新（服务运行持有 `state/.lock`） |

`--export-legacy`：把 `state/rules.json` **逐字节**导出回 `config.json.rules` 并把 `config_version`
降为 2，供旧二进制读取；先备份、原子替换；真源不存在/不可解析 ⇒ 不改任何文件。

### 5.3 控制台写路径与只读桶

`PUT /api/config` 只接受 `CFG_WRITABLE`；只读键不改内存/磁盘，响应分
`ignored_keys`（未知）/ `readonly_keys` + `readonly_detail`（只读及原因）/ `written_keys`（实际写入）。
路径类（`rule_local_file` / `rule_sub_file` / `cache_file` / `state_dir`）与进程级（`state_persist`）永远只读。

**规则契约：`/api/config.rules` 在任何情况下都恒为数组，由真源派生（无规则时为 `[]`，不是 `null`）。**

---

## 6. 打包流程与六道门

```bash
cd <源码树>
bash scripts/make_packages_221r2.sh
```

顺序**硬编码不可调换**：固定路径重编 wasm → embed-frontend 二进制 → 门禁（EMBEDDED==DIST + dist 新鲜度）
→ 重算清单（dist 定稿后）→ **权限规范化（第 4b/5b 步）** → 出 prod/src 两包 → 包内自证
→ **解包后权限自证（第 6a 步，`t-pkg-modes.sh`）**。

**双清单与作用域**：

- `_md5_prod.txt`：树根相对，行数 = 源码文件数 + `web/dist/*` 条数（由第 1 步现编产物决定，不是常数）；
- `_md5_src.txt`：只随源码包交付，= `_md5_prod.txt` 去掉 `web/dist/` 前缀的行（顺序与字节格式相同）；
- 两包内的 `_md5_prod.txt` **逐字节相同**；`_md5_src.txt` 只存在于 src 包。

**清单作用域：树内用 _md5_prod.txt 自校验（含 web/dist），src 包内用 _md5_src.txt 自校验（不含 web/dist）；src 包内跑 _md5_prod.txt 会缺 web/dist 那几行，属设计而非损坏。**

| 位置 | 自校验命令 | 期望（**本树实测值**，由 `scripts/_doc_counts.py` 逐行断言） |
|---|---|---|
| 树内（构建树，含 `web/dist`） | `md5sum -c _md5_prod.txt` | **217/217 OK** |
| prod 包内 | `md5sum -c _md5_prod.txt` | **6 OK / 211 FAILED**（按设计：prod 只装白名单，前端资产摊平在 `web/`；prod 完整性不由这条命令判） |
| **src 包内** | **`md5sum -c _md5_src.txt`** | **211/211 OK** |
| src 包内 | `md5sum -c _md5_prod.txt` | 211 OK / 6 FAILED（按设计：缺的正是 `web/dist/*`） |

**prod 包完整性判据**（`scripts/_pack_verify.py` 四条硬断言；白名单 **13 个文件**，多一个或少一个都失败）：
① 包内文件集合 == `ALLOWED`；② `bin/ebpdns` 内嵌前端 == `web/app_bg.wasm`（`EMBEDDED==DIST`）；
③ 包内 `_md5_prod.txt` 与树内清单逐字节相同；④ 两包清单同字节。
`_doc_counts.py --require-pkgs` 必须在**真实包产物**里执行 prod/src 两行命令；缺包产物即红。

**六道门**（任一道不满足 ⇒ 打包 `exit 1`）：

| # | 门 | 判据 |
|---:|---|---|
| 1 | 版本一致性 | 七处同版本，且与 `CARGO_PKG_VERSION` 一致 |
| 2 | 源码包字节码 | 包内 `*.pyc` / `*.pyo` / `__pycache__` == 0 |
| 3 | 清单一致性 | 树内 prod 清单逐行 OK；两包清单逐字节相同；src 包内 `_md5_src.txt` 行数 = prod 清单减去 `web/dist` 行数且逐行相符；唯一顶层目录 |
| 4 | 文档契约 | 四条文件各含两条契约；PACKAGING 另含清单作用域；逐字比对 |
| 5 | 计数一致性 | 清单行数/文件数 == 动态实测；表格里的 `md5sum -c` 必须由带作用域的 claim 在包内真的执行；未登记计数数字即红 |
| 6 | 离线重建等价 | 上一版源码包 + 补丁 == 本树（`CHANGED=ADDED=REMOVED=0`，排除两份清单），不跑构建 |

> 第 7 道接口键集、第 11 道配置键集由 `check_all` 覆盖，不在打包链内跑（需要隔离实例）。

---

### 6b. 门禁单入口（14 项；脚本自测会解析本代码块）

```bash
OFFLINE=1 RELEASE=1 JOBS=1 bash scripts/check_all.sh                 # 全跑（含 cargo test 全量）
SKIP_TEST=1 OFFLINE=1 RELEASE=1 JOBS=1 bash scripts/check_all.sh     # 只跑快门禁（不含 cargo test）
```

> 本节的开关集合必须与 `scripts/check_all.sh` 头部注释逐字一致（`SKIP_TEST` / `RELEASE` /
> `OFFLINE` / `JOBS`），由 `scripts/check_all_selftest.sh` 第 5 项机器判定。

---

## 7. 构建配方与可复现口径

四条不可协商：

1. **RUSTFLAGS 单一来源** = `scripts/_repro_flags.sh <tree> [--wasm]`，输出三条 remap：
   `<tree>=/build/ebpdns`、`<cargo registry>=/cargo/registry`、`$HOME/.rustup=/rust`；
   `make build` / `make wasm` / 打包脚本 / 跨路径脚本都调它，任何地方不得手写。
2. **`SOURCE_DATE_EPOCH = BUILD_EPOCH`**：`rust-embed` 把 dist 文件的 `last_modified`/`created`
   编进二进制；不设它则同源码两轮构建字节不同。
3. **固定构建路径 `/build/ebpdns`**：交付链把源码（排除 `target/`、`web/dist/`、`dist-packages/`、`.git`）
   复制到固定路径再编 wasm 与二进制，产物拷回源码树；`EBP_BUILD_ROOT` 可覆盖。
4. **`[profile.release]` 一行不可改**：`opt-level=3` / `lto="thin"` / `codegen-units=1` / `debug=false`。

**实测结论**：

| 判据 | 结果 |
|---|---|
| wasm 逐字节 | 交付链第 1 步带 `--wasm` remap 重编；`app_bg.wasm` 与 dist 逐字节一致（`EMBEDDED==DIST` YES） |
| bin 跨路径 | `X_PATH_BIN_IDENTICAL=YES`（两棵异路径树 → 固定路径构建，逐字节相同） |
| 同路径重复构建 | `SAME_PATH_RB_IDENTICAL=YES` |
| 构建机路径残留 | `strings -a` 的 `/root/` 与 `/root/.rustup` 命中均为 0（归一为 `/cargo/registry`、`/rust`） |

```bash
bash scripts/_repro_crosspath.sh     # 异路径/同路径双构建 + 路径残留计数 + 行为面比对
bash scripts/make_packages_221r2.sh  # 交付链
```

**最低 glibc**：`objdump -T bin/ebpdns | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1` ⇒ `GLIBC_2.34`；
依赖 `libgcc_s.so.1` / `libm.so.6` / `libc.so.6`。静态 musl 构建未提供（登记为后续项）。

---

## 8. 门禁单入口：14 项 `check_all`

```bash
OFFLINE=1 RELEASE=1 JOBS=1 bash scripts/check_all.sh   # 或 make check-all
```

| # | 项 | 判据 |
|---:|---|---|
| 1 | 版本 + 文档一致 | 七处同版本 + 两条契约各四处 |
| 2 | 文档计数 | 清单行数/文件数 == 动态实测（`_doc_counts.py`） |
| 3 | 离线重建等价 | 上一版源码包 + 补丁 == 本树（`_rebuild_equiv.sh`） |
| 4 | fmt | `cargo fmt --all --check` |
| 5 | clippy | `cargo clippy --workspace --all-targets --offline -- -D warnings` |
| 6 | test | `cargo test --workspace --no-fail-fast` |
| 7 | web_dist_freshness | dist 不早于 `web/src`；每个 `cfg-*` id 都在 wasm 里 |
| 8 | web fmt | `web/` 独立 workspace `cargo fmt --all --check` |
| 9 | web clippy | wasm32 `--all-targets -- -D warnings` |
| 10 | 接口键集 | `_interface_keys.py` == 隔离实例逐键 |
| 11 | 配置键集 | `_config_keys.py`：模板 + `default_config` + 运行期注入 == 实测 |
| 12 | 安装矩阵 | `t-install-matrix.sh` 1–9；10 视容器能力 SKIP |
| 13 | install start 语义 + **安装器隔离** | `t-install-running.sh`（旧实例先停后启 / keep / dry / foreign）**+** `t-install-isolation.sh`（§3.3 五条修法的五类场景；fake systemctl 证明真 systemd 0 次） |
| 14 | 包权限规范化 | `t-pkg-modes.sh`：**解包后**无 world-writable、`*.sh`/`*.py` 0755、数据 0644、目录 0755、`install.sh`/`bin/ebpdns` 0755（修 2.1.42 的 154×0666） |

> SKIP 不等于绿：缺二进制/包产物/root 时打印 SKIP；交付前必须在具备夹具的环境重跑。
> 门禁自测：`bash scripts/check_all_selftest.sh`（含"改错必须变红"的负向对照）。

---

## 9. 容器矩阵现状

| 行 | 场景 | 状态 |
|---:|---|---|
| 1 | 全新机：有 systemd + 有 passwd 工具 | 脚本覆盖（临时前缀 + PATH shim） |
| 2 | 无 passwd 工具（PATH 遮蔽 groupadd/useradd/addgroup/adduser） | 覆盖：/etc 数据库回退，不可写 ⇒ WARN + rc=0 |
| 3 | 无 systemd | 覆盖：只装文件 + 手动启动提示 |
| 4 | 缺 `ip`/`ss`/`lsof` | 覆盖：`/proc/net` 回退 |
| 5 | 端口被别的进程占用 | 覆盖：rc≠0 且不写文件 |
| 6 | glibc 不足 | 覆盖：预检中止并报 GLIBC 原因 |
| 7 | 重复安装 ×2 | 覆盖：配置/state 不破坏 |
| 8 | `--uninstall` 后重装 | 覆盖：保留配置与 state |
| 9 | `--dry-run` | 覆盖：零文件变更 |
| 10 | 真容器 `debian:13-slim` | **未真实执行**：打包环境无 docker/podman，脚本如实 SKIP；有引擎时要求在容器内跑 `--version` + `check-config` + `install.sh start`（无 systemd） |

> 行 10 的 SKIP 是**环境能力缺失**，不是通过；发布前如需容器证据，请在具备 docker/podman 的机器上重跑
> `scripts/t-install-matrix.sh --only 10` 并保留日志。

---

**部署约束：单机单实例**（`state_dir` 独占锁；第二实例会被拒；隔离实例必须显式 `--state-dir`）。

**规则契约：`/api/config.rules` 在任何情况下都恒为数组，由真源派生（无规则时为 `[]`，不是 `null`）。**
