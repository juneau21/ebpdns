# 贡献指南

## 开发环境

```bash
# Python 3.10+（纯标准库；aioquic 为可选依赖，仅 DoQ/DoH3 需要）
python3 --version

# 本地运行（非特权端口，避免 53 需 root）
python3 -m ebpdns run --dns-udp 127.0.0.1:1053 --dns-tcp 127.0.0.1:1053 --api-port 8081
```

## 代码规范

- 纯 Python 标准库，零第三方依赖（aioquic 为可选依赖，仅 DoQ/DoH3 需要）
- 缩进 4 空格，行宽 120
- 模块级 docstring 说明职责
- 关键算法加注释说明设计取舍

## 测试

```bash
# 单元测试（两种等价方式）
make test
python3 -m unittest discover -s tests

# 压力/性能压测（根目录脚本，需先以非特权端口起一个 daemon）
python3 stress_test.py        # 混合负载长稳压测
python3 profile_test.py       # 性能剖析采样
python3 full_log_test.py       # 全量日志路径验证
```

> 注：历史文档中提到的 `deploy-test/errcheck.py`、`deploy-test/bench.py` 目录已不存在；
> 单元测试位于 `tests/`，压测脚本位于仓库根目录（`stress_test.py` 等）。

## 文档与代码同步

- 配置项以 `ebpdns/config.py` 的 `DEFAULTS` 字典、`_NUM_RANGES`（数值范围）、
  `_ENUM_VALUES`（枚举取值）、`_BOOL_KEYS`（布尔键）为唯一事实来源；
  修改/新增配置键时，必须同步更新：
  - `README.md` 配置说明表（键 / 默认值 / 取值范围）
  - `etc/ebpdns.conf.json` 示例配置
  - `web/index.html` 配置页标签/帮助文字（只改说明文字，不改 JS 逻辑）
  - `bpf/README.md`（涉及 map_type / 数据面语义时）
- 文档中出现的默认值、枚举取值、取值范围必须与代码一致，不得凭记忆填写。
- 注意单位：`speed_interval_ms` 等带 `_ms` 后缀的字段单位是**毫秒**，
  `health_check_interval` / `rule_sub_interval` / `stale_ttl` 等单位是**秒**，
  前端帮助文字与后端注释不得混淆。

## 提交规范

- 一个 PR 只做一件事
- 提交信息：`模块: 简要说明`
- 新功能必须附带测试
- 性能相关改动必须附压测数据

## 发布流程

1. 更新 `ebpdns/__init__.py` 版本号（`__version__`）
2. 更新 `web/index.html` 前端版本号（页脚 `foot-uptime` 与 `APP_VERSION`）
3. 更新 `README.md` 版本历史
4. `./package.sh <version>` 生成发布包（**版本号不带 `v` 前缀**，脚本会自行补 `v`；如 `./package.sh 1.9.150`，输出 `dist/ebpdns-python-v1.9.150.tar.gz` 与 `dist/ebpdns-git-v1.9.150.tar.gz`）
5. 打 tag：`git tag v1.9.150 && git push --tags`

## 审查流程（高强度逐行审查）

发版前按模块分批逐行审查，每轮产出 `artifacts/REVIEW_R<N>_<模块>.md`，
修复后产出 `artifacts/FIX_R<N>_<模块>.md`；模块划分固定为四个：

- `core`（config / resolver / cache / server / dnsmsg / probe）
- `network`（upstream / quic_upstream）
- `api`（api / telemetry）
- `frontend`（web/index.html）

典型审查轮次（R12–R16 为例）：逐文件逐行通读，按 P1/P2/P3 分级记录问题，
**P3 清零**为该轮通过标准；全部轮次结束后由功能验证代理做端到端验证，
**连续两轮零待修复**才进入发版。示例问题量级：R12 = 32 项 P3、R13 = 3 项、
R14 = 2 项、R15 = 1 项、R16 = 复核。

> 注意：审查只记录并修复问题；不得为"过审查"而改动已通过验证的数据面行为。
> 文档/注释/示例配置的对齐属独立的「文档同步版」工作，不发版数据面变更。
