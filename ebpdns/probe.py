"""首次启动上游延迟自动实测。

首次启动（或配置中新增上游）时，对「启用且未实测过」的上游发起一次真实
DNS 查询测量 RTT，把实测值写回该上游的 latency（基础延迟）字段，并标记
latency_measured=True 避免每次启动重复测量。后台线程执行，不阻塞 daemon 启动。
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from . import config as config_mod
from . import dnsmsg
from .upstream import query_upstream

log = logging.getLogger("ebpdns")

# 实测用固定域名：选择各上游都能稳定应答的真实域名（测 RTT 足够）
PROBE_DOMAIN = "www.baidu.com"

# P1-3(V146): 模块级引用 first-probe daemon 线程, 供退出路径 join 收尾。
# daemon 线程在 SIGTERM/os._exit 时被硬杀, 若正持 app_ctx._lock 落盘
# (save_config 的 tmp+fsync+rename), 会残留 config.json.tmp。
# R3-P3-B: 改为 list 跟踪所有在途探针线程。原单引用会被重复 start_first_probe
# (新增上游后再触发)覆盖, 旧线程句柄丢失, join_first_probe 只 join 最新一个——
# 旧线程若恰在 save_config 中途被 SIGTERM 硬杀仍会残留 .tmp。
_first_probe_threads = []
# R4-P2: R3-P3-B 残留竞态——filter 与 append 之间无锁: ":223 读旧表→列表推导
# 生成新对象→rebind 全局" 与 ":224 在新对象上 append" 不是原子操作, 两个并发
# start_first_probe(启动路径 + API add_upstream) 会先后 rebind 到同一份推导
# 新表, 后写者覆盖先写者, 先到的 append(tA) 句柄丢失, join_first_probe 看不到
# 该线程, SIGTERM 时若它正在 save_config 的 tmp+fsync+rename 中途被硬杀仍残留
# .tmp。修复: 模块级锁包住 filter+append(原地切片[:]= 而非 rebind, 避免与读端
# 竞争), join 取快照时同锁。
_threads_lock = threading.Lock()


def join_first_probe(timeout=1.0):
    """Best-effort join for all in-flight first-probe daemon threads before exit.

    P1-3(V146): 防止 SIGTERM 硬杀正在 save_config 的落盘线程导致 .tmp 残留。
    R3-P3-B: 逐个 join 所有在途探针线程(重复 start_first_probe 会起多个)。
    由 cli.py 在 os._exit 前调用; 线程已结束则立即返回。"""
    # R4-P2: 快照在 _threads_lock 内取, 与 start_first_probe 的 filter+append
    # 互斥, 保证列表内容是一致版本(不会读到推导新表 rebind 中途)。join 本身放
    # 在锁外执行, 避免退出慢路径阻塞并发 start_first_probe。
    with _threads_lock:
        snapshot = list(_first_probe_threads)
    for t in snapshot:
        if t is not None and t.is_alive():
            try:
                t.join(timeout=timeout)
            except Exception:
                pass


def _safe_int(v, default=0):
    """R3-P3-2: 安全 int() 转换, 畸形配置值(非数值字符串)不抛 ValueError。
    避免手编 config 把 latency/timeout_ms 填成非数值时, 主循环 int() 崩溃
    导致该上游及其后所有上游测量结果丢失。

    R5 修正(对齐 resolver._safe_int): 旧 `int(v or default)` 把 falsy 的 0
    也替换成 default。0 是合法值(如 latency=0/禁用), 不应被静默改写。
    现仅 v is None 或无法解析时回退 default; 可解析值(含 0)原样返回。"""
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _needs_probe(cfg):
    return any(u.get("enabled", True) and not u.get("latency_measured", False)
               for u in cfg.get("upstreams", []))


def probe_upstream_latencies(cfg, config_path=None, force=False, tag="首次实测", app_ctx=None):
    """实测上游延迟并写回。

    force=False: 仅对启用且未实测过的上游（首次启动场景）。
    force=True : 强制对全部上游重新实测, 含禁用上游（一键重新测速场景,
                 便于评估所有上游质量后决定是否启用）。
    app_ctx    : 后台线程范式(M2 修复)。传入后, 落盘阶段进 app_ctx._lock 重新取
                 最新 cfg, 仅把本次实测的 latency/latency_measured 按 id 合并进最新
                 cfg 再 save_config, 而非整体写回传入的旧 cfg 引用——后者会覆盖并发
                 PUT /api/config 对其他键的新变更。不传则沿用旧路径(持旧 cfg 整体落盘,
                 仅用于已持 app._lock 的同步调用或无并发的启动阶段)。
    返回 [{id,name,proto,addr,old,new,ok}]。
    """
    # 选择待探测上游(L2 修复): 传入 app_ctx 时, 在 app._lock 内对最新 cfg
    # 取浅拷贝快照, 避免与并发 PUT /api/config / reload 替换 self.app.cfg
    # 引用而读到半更新的旧上游列表(漏测新增/多测已删)。浅拷贝使探测阶段只改
    # 拷贝, 不在持锁外改动 live cfg; 网络探测仍在锁外, 最终按 id 合并回写。
    if app_ctx is not None:
        try:
            with app_ctx._lock:
                cur_cfg = app_ctx.cfg
                src = [dict(u) for u in cur_cfg.get("upstreams", [])]
                # v1.9.84 PR-01: timeout 也从最新 cfg 读取, 避免与快照不同步
                timeout = _safe_int(cur_cfg.get("timeout_ms"), 1500)
        except Exception:
            src = []
            timeout = _safe_int(cfg.get("timeout_ms"), 1500)
    else:
        # P2-9: 无 app_ctx 路径也对 upstreams 做浅拷贝(列表 + 每个 dict),
        # 避免后台探测线程原地修改 live cfg 的 upstream 条目。最终在 save 前
        # 把测量结果回写 cfg。
        src = [dict(u) for u in cfg.get("upstreams", [])]
        timeout = _safe_int(cfg.get("timeout_ms"), 1500)
    if force:
        ups = list(src)  # 全部上游, 含禁用
    else:
        ups = [u for u in src if u.get("enabled", True)
               and not u.get("latency_measured", False)]
    if not ups:
        return []
    try:
        # 探测仅测 RTT，无需 0x20 随机化和 EDNS
        q, _qid = dnsmsg.build_query(PROBE_DOMAIN, dnsmsg.type_code("A"), edns=False)
    except Exception:
        log.warning("%s: 构造探测查询失败, 跳过", tag)
        return []
    results = []

    def do(u):
        try:
            ok, _data, lat, _err = query_upstream(u, q, timeout)
            return u, bool(ok), _safe_int(lat)
        except Exception as e:
            # v1.9.84 PR-02: 改为 Exception(不吞 SystemExit/KeyboardInterrupt)。
            # query_upstream 953 行已兜底所有 Exception, 此处仅防御性捕获。
            log.warning("%s: 上游 %s(%s) 探测异常: %s: %s",
                        tag, u.get("name"), u.get("addr"), type(e).__name__, e)
            return u, False, 0

    try:
        # P3-6(V146): 加 thread_name_prefix 便于故障排查时识别线程栈。
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(ups))),
                                thread_name_prefix="probe-latency") as pool:
            for u, ok, lat in pool.map(do, ups):
                old = _safe_int(u.get("latency"))   # latency 可为 null(未测/待测); R3-P3-2 防畸形值
                # 仅成功才标记 latency_measured=True; 失败的保持 False, 下次启动
                # 自动复测(历史上 DoH 因 bug 全挂也被标 True, 修完代码后永不自动复测)。
                u["latency_measured"] = bool(ok)
                item = {"id": u.get("id"), "name": u.get("name"), "proto": u.get("proto"),
                        "addr": u.get("addr"), "old": old, "new": old, "ok": bool(ok)}
                # R-fix: 成功与否只看 ok, 不再叠加 `lat > 0`。回环/内网上游的实测延迟
                # 常 <1ms, int(ms) 取整为 0, 原条件 `if ok and lat > 0` 会把**成功**的
                # 实测判成失败: 既打假的"测速失败"WARNING, 又把 latency 留在默认 5000ms
                # 而 latency_measured=True, 该上游此后永久排在候选末位且不再复测。
                if ok:
                    u["latency"] = max(1, int(lat))
                    item["new"] = u["latency"]
                    log.info("上游 %s(%s) %s延迟 %dms", u.get("name"), u.get("addr"), tag,
                             u["latency"])
                else:
                    # 禁用上游测速失败属预期(未启用不参与解析), 降级 DEBUG 防噪音;
                    # 启用上游失败才是真告警
                    if u.get("enabled", True):
                        log.warning("上游 %s(%s) %s失败, 保留基础延迟 %dms",
                                    u.get("name"), u.get("addr"), tag, u.get("latency", 0))
                    else:
                        log.debug("上游 %s(%s) 禁用未测速 %s, 保留基础延迟 %dms",
                                  u.get("name"), u.get("addr"), tag, u.get("latency", 0))
                results.append(item)
    except Exception:
        import traceback
        log.warning("%s: 并发探测异常, 部分上游未测量\n%s", tag, traceback.format_exc())
    ok_n = sum(1 for r in results if r["ok"])
    if app_ctx is not None:
        # 后台线程范式(M2): 进 app._lock 重新取最新 cfg, 仅按 id 合并本次实测字段,
        # 避免旧 cfg 整体落盘覆盖并发 PUT /api/config 的新变更。网络探测已在此前完成,
        # 持锁段只做内存合并+落盘, 耗时可忽略。
        try:
            saved_ok = False
            with app_ctx._lock:
                cur = app_ctx.cfg
                cur_by_id = {u.get("id"): u for u in cur.get("upstreams", [])}
                for it in results:
                    cu = cur_by_id.get(it.get("id"))
                    if cu is None:
                        continue   # 该上游已被并发删除, 跳过
                    cu["latency_measured"] = bool(it["ok"])
                    if it["ok"] and _safe_int(it.get("new")) > 0:
                        cu["latency"] = _safe_int(it.get("new"))
                # P1-1(R3): 检查 save_config 返回值, 失败时打 warning(运行态已生效但重启后丢失)
                # P3-1(R4): "已写入"成功日志必须随成功分支打印, 写盘失败时不能与上一行 WARNING 自相矛盾。
                # P3-3(R31): save_config 成功返回实际写入路径字符串(失败返回 False)。config_path
                # 可能为 None(调用方未指定), 此时 save_config 会自动探测默认路径落盘——日志必须
                # 打印实际落盘路径(saved)而非入参 config_path, 否则会误报"已写入 None"。
                saved = config_mod.save_config(cur, config_path)
                # R42/P3-1: save_config 成功返回路径字符串, 失败返回 False; 原 `is not False`
                # 把 None 也误判为成功(日志打"已写入 None")。同时排除 False 与 None 两个哨兵。
                saved_ok = saved is not None and saved is not False
                if not saved_ok:
                    log.warning("%s: 配置写盘失败(运行态已生效, 重启后丢失)", tag)
            if saved_ok:
                log.info("%s完成(锁内合并): 已写入 %s (%d/%d 上游)", tag, saved, ok_n, len(ups))
        except Exception as e:
            log.warning("%s: 配置写回失败 %s", tag, e)
    elif config_path:
        try:
            # P2-9: src 是 upstreams 的浅拷贝(含测量结果), 回写 cfg 后落盘
            cfg["upstreams"] = src
            # P1-1(R3): 检查 save_config 返回值, 失败时打 warning(运行态已生效但重启后丢失)
            # P3-1(R4): "已写入"成功日志只在写盘成功分支打印, 失败时不再无条件打"已写入"。
            # P3-3(R31): 与上方 app_ctx 分支一致, 日志打印实际落盘路径(saved)而非入参 config_path。
            saved = config_mod.save_config(cfg, config_path)
            # R42/P3-1: 与上方 app_ctx 分支同型, 同时排除 False 与 None 哨兵。
            saved_ok = saved is not None and saved is not False
            if not saved_ok:
                log.warning("%s: 配置写盘失败(运行态已生效, 重启后丢失)", tag)
            else:
                log.info("%s完成: 已写入 %s (%d/%d 上游)", tag, saved, ok_n, len(ups))
        except Exception as e:
            log.warning("%s: 配置写回失败 %s", tag, e)
    return results


def probe_enabled_upstreams(cfg, config_path=None, app_ctx=None):
    """向后兼容别名：首次启动实测（返回成功数）。"""
    return len([r for r in probe_upstream_latencies(cfg, config_path, force=False,
               tag="首次实测", app_ctx=app_ctx) if r["ok"]])


def start_first_probe(cfg, config_path=None, app_ctx=None):
    """后台线程启动首次实测（daemon 启动后异步执行, 不阻塞）。

    app_ctx 必须透传(M1 修复): 启动路径与 _api_reprobe/_api_add_upstream 对齐,
    落盘进 app._lock 按 id 合并, 避免持启动旧 cfg 引用整体 save_config 覆盖
    API 已启动后并发 PUT /api/config 的新变更。
    """
    if not _needs_probe(cfg):
        return
    global _first_probe_threads
    t = threading.Thread(target=lambda: probe_enabled_upstreams(cfg, config_path, app_ctx),
                         name="first-probe", daemon=True)
    # R5-P3-1: 先在锁内把线程句柄加入 list, 再 t.start()。原实现 t.start() 在
    # 锁外、append 之前, 微秒级窗口内线程已运行但 join_first_probe 取快照看不到
    # 该线程。构造 Thread 对象本身不启动 OS 线程, 锁内 append 后再 start, 消除窗口。
    # R12-P3-3: t.start() 也移入锁内。原实现 filter(x.is_alive()) 对刚 append
    # 尚未 start 的新线程返回 False——并发 start_first_probe 在线程 A append(tA)
    # 后、start() 前拿到锁执行 filter, 会把 tA 当死线程滤掉, 句柄丢失(理论上
    # SIGTERM 恰在 save_config 中途硬杀残留 .tmp)。构造 Thread 不启动 OS 线程,
    # 锁内 append 后立即 start; 新线程只碰 app_ctx._lock/config, 不碰 _threads_lock,
    # 无死锁。
    with _threads_lock:
        _first_probe_threads[:] = [x for x in _first_probe_threads if x.is_alive()]
        _first_probe_threads.append(t)
        t.start()
