#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""配置键集门禁（**2.1.31 / 第 11 道门**）。

背景（2.1.30 实测）：生产 `GET /api/config` 是 **75** 个顶层键，而 `web/INTERFACE.md`
与 2.1.30 交付报告写 **74**。多出来的 1 个是 `rules` 镜像键：

  * v2→v3 迁移把 `rules` 从 `config.json` **删除**（真源移到 `state/rules.json`）；
  * 运行期 `migrate_cfg()` 又用 `default_config()` 把缺失的顶层键**补回内存**，
    于是 `GET /api/config` 仍回显 `rules: []`。

本门禁以**实现为真源**，从三处推导期望键集，再与**隔离实例**的实际响应逐键比对：

  1. 随包模板 `packaging/etc/ebpdns/config.json` 的顶层键；
  2. `crates/ebpdns/src/main.rs::default_config()` 的顶层键（应与模板逐键一致）；
  3. `migrate_cfg()` 运行期注入的路径键（`rule_local_file` / `rule_sub_file`）。

并断言 `web/INTERFACE.md` 的 `<!-- CONFIG_KEYS_BEGIN -->` 块里的三个数字
（模板键数 / 运行期补键数 / 当前 `/api/config` 总键数）**全部等于实测**；
`README.md` 的配置键表必须登记这两个运行期只读键与 `rules` 镜像键的归属。

判定：
  * 缺键 / 多键 / 模板与 default_config 漂移 ⇒ rc=1；
  * 文档数字与实测不符、或仍出现旧的硬编码 "74" 口径 ⇒ rc=1。

实例来源：
  1. `--api URL --token T` 或 `EBP_CONFIG_API` / `EBP_CONFIG_TOKEN`；
  2. `--bin PATH` / `EBP_BIN` / `<tree>/target/{release,debug}/ebpdns`；
     自动拉起临时实例（复用 `_interface_keys.py` 的 Spawned：私有 state_dir + 临时端口）；
  3. 都没有 ⇒ `CONFIG_KEYS=SKIP`，rc=0（缺夹具时不冒充绿）。

用法：
    python3 scripts/_config_keys.py <tree-root>
    python3 scripts/_config_keys.py <tree-root> --api http://127.0.0.1:19831 --token TOKEN
"""
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _interface_keys as ik  # noqa: E402  （复用隔离实例/Spawned/http_json/find_bin）


def read(root, rel):
    with io.open(os.path.join(root, rel.replace("/", os.sep)), encoding="utf-8") as fh:
        return fh.read()


def template_keys(root):
    data = json.loads(read(root, "packaging/etc/ebpdns/config.json"))
    return set(data.keys())


def default_config_keys(root):
    """从 `main.rs::default_config()` 的 `json!({...})` 里取**顶层**键。

    只认 8 空格缩进的 `"key":`（顶层对象成员）；嵌套键缩进更深，不会误收。
    这不是 JSON 解析器（源码里有注释），但足以把"新增/漏登记顶层键"变成硬失败：
    任何解析遗漏都会与模板集合不等 ⇒ rc=1，而不是静默通过。
    """
    src = read(root, "crates/ebpdns/src/main.rs")
    i = src.index("fn default_config() -> Value {")
    j = src.index("\n    })", i)
    body = src[i:j]
    keys = set(re.findall(r'^        "([a-z0-9_]+)":', body, re.M))
    if not keys:
        raise SystemExit("  FAIL  无法从 default_config() 解析出任何顶层键")
    return keys


def runtime_injected_keys(root):
    """从 `migrate_cfg()` 解析运行期注入的路径键（`("rule_local_file", "x.json")`）。"""
    src = read(root, "crates/ebpdns/src/main.rs")
    i = src.index("fn migrate_cfg(")
    j = src.index("\n}", i)
    body = src[i:j]
    found = set(re.findall(r'\("([a-z0-9_]+)",\s*"[a-z0-9_]+\.json"\)', body))
    # 兜底：即使实现改成别的写法，也至少把这两个已知路径键纳入期望（漏了会与实测不等而红）。
    found |= {"rule_local_file", "rule_sub_file"}
    return found


def doc_claim(root):
    """解析 INTERFACE.md 的 CONFIG_KEYS 标记块（三个动态数字）。"""
    doc = read(root, "web/INTERFACE.md")
    m = re.search(
        r"<!--\s*CONFIG_KEYS_BEGIN\s*-->(.*?)<!--\s*CONFIG_KEYS_END\s*-->",
        doc,
        re.S,
    )
    if not m:
        raise SystemExit("  FAIL  INTERFACE.md 缺少 <!-- CONFIG_KEYS_BEGIN/END --> 标记块")
    block = m.group(1)
    pats = {
        "template": r"随包模板键数[^0-9]*(\d+)",
        "runtime": r"运行期自动补的键数[^0-9]*(\d+)",
        "total": r"`/api/config`\s*顶层键数[^0-9]*(\d+)",
    }
    out = {}
    for name, pat in pats.items():
        mm = re.search(pat, block)
        if not mm:
            raise SystemExit("  FAIL  CONFIG_KEYS 块里找不到声明：%s（正则 %s）" % (name, pat))
        out[name] = int(mm.group(1))
    return out, doc


def check_readme(root):
    """README 的配置键表必须登记两个运行期路径键（只读）与 rules（可写/镜像）。"""
    text = read(root, "README.md")
    fails = []
    for key, ownership in (
        ("rule_local_file", "只读"),
        ("rule_sub_file", "只读"),
        ("rules", "可写"),
    ):
        pat = re.compile(
            r"^\|\s*`%s`\s*\|[^\n]*%s" % (re.escape(key), re.escape(ownership)),
            re.M,
        )
        if not pat.search(text):
            fails.append("README 配置键表缺少 `%s` 行或未标注「%s」归属" % (key, ownership))
    return fails, text


def main():
    args = sys.argv[1:]
    tree = None
    api = os.environ.get("EBP_CONFIG_API")
    token = os.environ.get("EBP_CONFIG_TOKEN", "")
    bin_path = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--api" and i + 1 < len(args):
            api = args[i + 1]
            i += 2
            continue
        if a == "--token" and i + 1 < len(args):
            token = args[i + 1]
            i += 2
            continue
        if a == "--bin" and i + 1 < len(args):
            bin_path = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if tree is None:
            tree = a
        i += 1
    tree = os.path.abspath(tree or ".")

    tmpl = template_keys(tree)
    dft = default_config_keys(tree)
    runtime = runtime_injected_keys(tree)
    expected = tmpl | dft | runtime

    fails = []
    if tmpl != dft:
        fails.append(
            "随包模板与 default_config() 漂移：模板多 %s / 默认多 %s"
            % (sorted(tmpl - dft), sorted(dft - tmpl))
        )
    claim, doc = doc_claim(tree)
    fails += check_readme(tree)[0]
    if re.search(r"顶层键数示例\s*\*\*74\*\*", doc):
        fails.append("INTERFACE.md 仍残留旧硬编码 `顶层键数示例 **74**`")

    spawned = None
    try:
        if not api:
            bin_path = ik.find_bin(tree, bin_path)
            if not bin_path:
                print("  SKIP  未发现可执行二进制（target/{release,debug}/ebpdns / EBP_BIN / --bin）")
                print("  SKIP  （源码包树按设计没有构建产物；有二进制时本门禁严格执行）")
                print("CONFIG_KEYS=SKIP")
                return 0
            print("  启动临时隔离实例：%s" % bin_path)
            spawned = ik.Spawned(bin_path)
            api, token = spawned.start()
        live = ik.http_json(api, token, "/api/config")
    finally:
        if spawned is not None:
            spawned.stop()

    live_keys = set(live)
    missing = sorted(expected - live_keys)
    extra = sorted(live_keys - expected)
    if missing:
        fails.append("实际 /api/config 缺少期望键：%s" % missing)
    if extra:
        fails.append("实际 /api/config 多出未登记键：%s" % extra)

    # 文档三个数字必须 == 实测（模板 / 运行期注入 / 总键数）。
    if claim["template"] != len(tmpl):
        fails.append("文档模板键数 %d != 实测 %d" % (claim["template"], len(tmpl)))
    if claim["runtime"] != len(runtime):
        fails.append("文档运行期补键数 %d != 实测 %d" % (claim["runtime"], len(runtime)))
    if claim["total"] != len(live_keys):
        fails.append("文档 /api/config 总键数 %d != 实测 %d" % (claim["total"], len(live_keys)))
    if claim["total"] != claim["template"] + claim["runtime"]:
        fails.append(
            "文档算术不成立：%d != %d + %d"
            % (claim["total"], claim["template"], claim["runtime"])
        )

    print(
        "  推导：模板=%d default_config=%d 运行期注入=%d（%s）"
        % (len(tmpl), len(dft), len(runtime), ",".join(sorted(runtime)))
    )
    print("  期望键数=%d  实测 /api/config 键数=%d" % (len(expected), len(live_keys)))
    print(
        "  文档声明：模板=%d 运行期=%d 总键数=%d"
        % (claim["template"], claim["runtime"], claim["total"])
    )
    if fails:
        for f in fails:
            print("  FAIL  " + f)
        print("CONFIG_KEYS=FAIL (%d)" % len(fails))
        return 1
    print(
        "CONFIG_KEYS=PASS（模板 %d + 运行期 %d = 实测 %d；缺键=0 多键=0；文档数字一致）"
        % (len(tmpl), len(runtime), len(live_keys))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
