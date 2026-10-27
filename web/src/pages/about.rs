//! About 路由：架构说明。
//!
//! 页面骨架与 v1.9.162 `web/index.html` 第 1021–1070 行（`<section class="route" data-route="about">`）
//! 保持一致：介绍 card（`.kicker` + 大标题 + `p#about-intro`）、`.arch-grid`（左「实际数据面路径」
//! 的 `.arch-flow` 5 个 `.arch-node`，右「技术栈参考」`.stack-list` 7 行 + 「部署方式」`code.blk` + `.hint`）。
//! 保留全部 class / id / 标签层级（CSS 选择器依赖它们），**只替换文案**。
//!
//! # 文案原则：功能真实性
//!
//! 本页此前逐字复制 Python v1.9.162 的说明（`server.py`/`cache.py`/`upstream.py`/`aioquic`/
//! Python 3 技术栈），对 Rust 版（当前 [`crate::state::VERSION`]）而言**事实错误**。
//! 现行文案按真实实现书写，并明确区分：
//! - 已实现且经自动化验证（单测 / 功能验收 / 压测）；
//! - 有意简化或已知缺口（DoH3 未做真机回归等）。

use leptos::prelude::*;

use crate::state::VERSION;

#[component]
pub fn AboutPage() -> impl IntoView {
    let st = crate::poll::stats();
    view! {
        <section class="route active" data-route="about">
            // ---------- 第一张 card：SmartDNS 式智能解析 ----------
            <div class="card">
                <div class="card-bd">
                    <div class="kicker">"SmartDNS 式智能解析"</div>
                    <div style="font-size:22px;font-weight:700;margin:6px 0 10px">
                        "Rust 用户态数据面（纯用户态）"
                    </div>
                    <p style="color:var(--text2);max-width:900px;margin:0" id="about-intro">
                        "本应用是仿照 "
                        <b>"SmartDNS"</b>
                        " 构建的智能 DNS 解析软件，v"
                        {crate::state::VERSION}
                        " 为 "
                        <b>"Rust 重写版"</b>
                        "（用户态 tokio 异步服务 + Rust→WASM 控制台）。数据面运行在"
                        <b>"用户态"</b>
                        ": 守护进程按配置的 "
                        <code>"listen.udp/tcp"</code>
                        " 监听（仓库默认 "
                        <code>"0.0.0.0:53"</code>
                        "，可用 "
                        <code>"listen.udp/tcp"</code>
                        " 收窄到 "
                        <code>"127.0.0.1:53"</code>
                        "），命中时直接回包（快路径），未命中进入 SmartDNS 式解析引擎："
                        <b>"六协议上游"</b>
                        "（UDP/TCP/DoT/DoH/DoQ/DoH3 六协议真实实现）多路并发，"
                        <b>"按实测延迟/权重排序、域名分流、CNAME 链展开、TTL 预取"</b>
                        "；结果回填缓存并落盘持久化。内置 "
                        <b>"缓存投毒防护"</b>
                        "(0x20 查询名随机化 + bailiwick 锚定)、"
                        <b>"EDNS0 防分片"</b>
                        "(UDP size 1232)、"
                        <b>"加密查询填充"</b>
                        "(RFC8467)、"
                        <b>"双栈智能"</b>
                        "（有 A 记录才屏蔽 AAAA，纯 v6 不误伤）。整套运行"
                        <b>"无需内核权限"</b>
                        "。本版本不含 eBPF/XDP 内核态缓存（已移除）；DNS 全部在用户态处理。"
                    </p>
                </div>
            </div>

            // ---------- 架构网格：左（数据面路径） + 右（技术栈 / 部署） ----------
            <div class="arch-grid">
                <div class="card">
                    <div class="card-hd">
                        <span class="t">"实际数据面路径"</span>
                        <span class="s">"data path"</span>
                    </div>
                    <div class="arch-flow">
                        {arch_node_listen()}
                        {arch_node_lru_map()}
                        {arch_node_resolver()}
                        {arch_node_upstream_api()}
                    </div>
                </div>
                <div style="display:flex;flex-direction:column;gap:18px">
                    // --- 技术栈参考 ---
                    <div class="card">
                        <div class="card-hd">
                            <span class="t">"技术栈参考"</span>
                            <span class="s">"reference stack"</span>
                        </div>
                        <div class="card-bd">
                            <div class="stack-list">
                                {stack_row("用户态数据面", "Rust (tokio / axum, 自研 DNS 编解码)")}
                                {stack_row("DoH3 / DoQ", "quinn (QUIC) + 自研最小 HTTP/3 + QPACK")}
                                {stack_row("缓存", "LRU / Partitioned / TinyLFU + 负缓存 + serve-stale")}
                                {stack_row("安全防护", "0x20 随机化 / EDNS 1232 / RFC8467 填充 / 双栈智能")}
                                {stack_row("计数 / 统计", "遥测采样 + Top N + 实时日志筛选")}
                                {stack_row("管理接口", "HTTP JSON API + Web 控制台(Leptos/WASM) + 热重载 / 重启")}
                            </div>
                        </div>
                    </div>
                    // --- poll2s 刷新效率（前端埋点：请求计数 / 固定 2s 节奏 / 首屏耗时） ---
                    <div class="card">
                        <div class="card-hd">
                            <span class="t">"控制台刷新效率"</span>
                            <span class="s">{format!("v{VERSION} · 统一 2s + 按需")}</span>
                        </div>
                        <div class="card-bd">
                            <div class="stack-list">
                                <div class="stack-row">
                                    <span class="l">"累计 /api/* 请求数"</span>
                                    <span class="r" id="about-req">
                                        {move || st.calls.get().to_string()}
                                    </span>
                                </div>
                                <div class="stack-row">
                                    <span class="l">"分端点 (st/sn/pl/lg)"</span>
                                    <span class="r" id="about-req-ep">
                                        {move || {
                                            let e = st.per_ep.get();
                                            format!("{}/{}/{}/{}", e[0], e[1], e[2], e[3])
                                        }}
                                    </span>
                                </div>
                                <div class="stack-row">
                                    <span class="l">"当前轮询节奏"</span>
                                    <span class="r" id="about-cadence">{move || st.cadence.get()}</span>
                                </div>
                                <div class="stack-row">
                                    <span class="l">"首屏 (boot / 首帧)"</span>
                                    <span class="r" id="about-boot">{move || st.boot_text.get()}</span>
                                </div>
                            </div>
                            <div class="hint">
                                "刷新策略: 固定 2s 单调度器, 每 tick 只轮询当前页面需要的接口 (遥测页才拉 snapshot, 流水线页才拉 pipeline/logs), 多端点并发拉取并合并为一次渲染; 请求失败按 2s→4s→8s→16s→30s 倍增退避, 成功后立即回到 2s; 标签页不可见时暂停轮询, 切回立即补一轮; 顶栏「刷新」可手动立即补一轮; 页脚时钟由本地外推, 不再为刷新时钟发请求。"
                            </div>
                        </div>
                    </div>
                    // --- 部署方式 ---
                    <div class="card">
                        <div class="card-hd">
                            <span class="t">"部署方式"</span>
                            <span class="s">"Debian 13"</span>
                        </div>
                        <div class="card-bd">
                            <code class="blk">
                                <span class="c">"# 安装 (见 README.md)"</span>
                                "\nsudo ./install.sh\n"
                                <span class="c">"# 或手动:"</span>
                                "\nsudo cp -r ebpdns-"
                                {crate::state::VERSION}
                                " /opt/ebpdns\n\
                                 sudo cp systemd/ebpdns.service /etc/systemd/system/\n\
                                 sudo systemctl daemon-reload\n\
                                 sudo systemctl enable --now ebpdns\n"
                                <span class="c">"# 控制台"</span>
                                "\n浏览器打开 http://<服务器IP>:8353"
                            </code>
                            <div class="hint">
                                "监听默认值为 "
                                <code>"listen.udp/tcp = 0.0.0.0:53"</code>
                                " 与 "
                                <code>"udp6/tcp6 = [::]:53"</code>
                                "（即对外监听；"
                                <code>"127.0.0.1"</code>
                                " 只是配置缺失或解析失败时的回退值并会打 WARN），需对外提供服务时请设置 "
                                <code>"api.token"</code>
                                " 并把监听收窄到内网地址。DoQ 已用真实 QUIC 栈实现（未对公网服务器取得可用应答）；DoH3 的 QPACK/H3 编码由单元测试向量与 QPACK 解码器交叉验证，并对 dns.alidns.com:443 完成真实往返回归。"
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    }
}

/// `.stack-row`：左标签（`.l`）+ 右取值（`.r`）。
fn stack_row(l: &'static str, r: &'static str) -> impl IntoView {
    view! {
        <div class="stack-row">
            <span class="l">{l}</span>
            <span class="r">{r}</span>
        </div>
    }
}

/// 节点 1：DNS LISTEN（`tag-usr`）。
fn arch_node_listen() -> impl IntoView {
    view! {
        <div class="arch-node">
            <div class="tag tag-usr">"DNS LISTEN"</div>
            <div class="bd">
                <h4>"报文入口 (UDP + TCP)"</h4>
                <p>
                    <code>"ebpdns-server/src/dns.rs"</code>
                    " 起 UDP 与 TCP 监听（地址取自配置 "
                    <code>"listen.udp/tcp"</code>
                    "，默认回环 :53）: 每包做长度/QR 预检后解析 (qname, qtype)，命中走"
                    <b>"快路径"</b>
                    "直接回包（仅重拼 qid），未命中交解析引擎；UDP 处理池满时丢弃并计入 "
                    <code>"udp_dropped"</code>
                    "，TCP 支持粘包/半包与 1MB 缓冲上限。"
                </p>
            </div>
        </div>
    }
}

/// 节点 2：用户态缓存（`tag-usr`）。
fn arch_node_lru_map() -> impl IntoView {
    view! {
        <div class="arch-node">
            <div class="tag tag-usr">"CACHE"</div>
            <div class="bd">
                <h4>"用户态缓存（可热切换策略）"</h4>
                <p>
                    <code>"ebpdns-cache"</code>
                    " 提供三种可配置策略（"
                    <code>"cache_policy"</code>
                    " = lru / partitioned / tinylfu）: 存 (qname, qtype) → 答案 + 剩余 TTL; 支持"
                    <b>"按分流 group 分区"</b>
                    "淘汰、TTL 钳制（ttl_min/max）、负缓存（NXDOMAIN/NODATA）、serve-stale 过期兜底、剩余 TTL 落盘持久化（"
                    <code>"cache_persist"</code>
                    "）与重启恢复；策略或容量变更时通过可换引用原子切换，无需重启。"
                </p>
            </div>
        </div>
    }
}

/// 节点 3：RESOLVER（`tag-usr`，正文为 5 条 `<ul>`）。
fn arch_node_resolver() -> impl IntoView {
    view! {
        <div class="arch-node">
            <div class="tag tag-usr">"RESOLVER"</div>
            <div class="bd">
                <h4>"SmartDNS 式解析引擎"</h4>
                <ul>
                    <li>
                        "域名分流: 精确 / *.通配 / 中缀通配 / re:正则 / forceIp / block（索引按后缀分组，10 万条级实测 <1ms） + URL 订阅自动更新 + 独立文件持久化"
                    </li>
                    <li>
                        "多上游并发: UDP / TCP / DoT / DoH / DoQ 已实测联调, DoH3 为自研最小实现; 连接池复用 + 首答即返 + NXDOMAIN/NODATA quorum 表决"
                    </li>
                    <li>
                        "按实测延迟/权重排序（eff_lat/weight, 5s 缓存） + 候选 IP 测速择优(EWMA 0.7/0.3, 加权随机) + 熔断 + 失败降级(fallback) + IPv4 优先(双栈智能)"
                    </li>
                    <li>"CNAME 链跟踪展开 + 负缓存 + TTL 到期前预取 + 规则级 TTL 覆盖"</li>
                    <li>"安全: 0x20 投毒防护(按上游自适应降级) / EDNS0 1232 防分片 / RFC8467 加密查询填充 / bailiwick 锚定"</li>
                </ul>
            </div>
        </div>
    }
}

/// 节点 4：UPSTREAM + API（`tag-sys`）。
fn arch_node_upstream_api() -> impl IntoView {
    view! {
        <div class="arch-node">
            <div class="tag tag-sys">"UPSTREAM + API"</div>
            <div class="bd">
                <h4>"上游与观测"</h4>
                <p>
                    <code>"ebpdns-upstream"</code>
                    " 六协议连接复用（DoH/DoT/DoQ 连接池）+ 按上游健康度统计 + 熔断；"
                    <code>"ebpdns-server"</code>
                    " 提供 HTTP JSON API: 查询 / 配置热重载 / 重启 / 规则 CRUD / 上游 CRUD / 一键重测速 / 订阅管理 / Prometheus metrics，Web 控制台实时展示遥测 / 健康度 / 实时日志筛选 / 缓存占用。"
                </p>
            </div>
        </div>
    }
}
