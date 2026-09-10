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


def _needs_probe(cfg):
    return any(u.get("enabled", True) and not u.get("latency_measured", False)
               for u in cfg.get("upstreams", []))


def probe_upstream_latencies(cfg, config_path=None, force=False, tag="首次实测"):
    """实测上游延迟并写回。

    force=False: 仅对启用且未实测过的上游（首次启动场景）。
    force=True : 强制对全部上游重新实测, 含禁用上游（一键重新测速场景,
                 便于评估所有上游质量后决定是否启用）。
    返回 [{id,name,proto,addr,old,new,ok}]。
    """
    if force:
        ups = [u for u in cfg.get("upstreams", [])]  # 全部上游, 含禁用
    else:
        ups = [u for u in cfg.get("upstreams", []) if u.get("enabled", True)
               and not u.get("latency_measured", False)]
    if not ups:
        return []
    try:
        q, _qid = dnsmsg.build_query(PROBE_DOMAIN, dnsmsg.type_code("A"), edns=False)
    except Exception:
        log.warning("%s: 构造探测查询失败, 跳过", tag)
        return []
    timeout = int(cfg.get("timeout_ms", 1500))
    results = []

    def do(u):
        try:
            ok, _data, lat, _err = query_upstream(u, q, timeout)
            return u, bool(ok), int(lat or 0)
        except BaseException as e:
            # 含 BaseException: 防止个别上游实现(如缺依赖的 QUIC 路径)抛
            # 非 Exception 异常导致整个并发池中断、其余上游全部漏测。
            log.warning("%s: 上游 %s(%s) 探测异常: %s: %s",
                        tag, u.get("name"), u.get("addr"), type(e).__name__, e)
            return u, False, 0

    try:
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(ups)))) as pool:
            for u, ok, lat in pool.map(do, ups):
                old = int(u.get("latency") or 0)   # latency 可为 null(未测/待测)
                u["latency_measured"] = True  # 无论成败都标记
                item = {"id": u.get("id"), "name": u.get("name"), "proto": u.get("proto"),
                        "addr": u.get("addr"), "old": old, "new": old, "ok": bool(ok)}
                if ok and lat > 0:
                    u["latency"] = lat
                    item["new"] = lat
                    log.info("上游 %s(%s) %s延迟 %dms", u.get("name"), u.get("addr"), tag, lat)
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
    if config_path:
        try:
            config_mod.save_config(cfg, config_path)
            ok_n = sum(1 for r in results if r["ok"])
            log.info("%s完成: 已写入 %s (%d/%d 上游)", tag, config_path, ok_n, len(ups))
        except Exception as e:
            log.warning("%s: 配置写回失败 %s", tag, e)
    return results


def probe_enabled_upstreams(cfg, config_path=None):
    """向后兼容别名：首次启动实测（返回成功数）。"""
    return len([r for r in probe_upstream_latencies(cfg, config_path, force=False, tag="首次实测") if r["ok"]])


def start_first_probe(cfg, config_path=None):
    """后台线程启动首次实测（daemon 启动后异步执行, 不阻塞）。"""
    if not _needs_probe(cfg):
        return
    t = threading.Thread(target=probe_enabled_upstreams, args=(cfg, config_path),
                         name="first-probe", daemon=True)
    t.start()
