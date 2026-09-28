# 贡献指南

## 开发环境

```bash
# Python 3.10+
python3 --version

# 本地运行（非特权端口）
python3 -m ebpdns run --dns-udp 127.0.0.1:1053 --dns-tcp 127.0.0.1:1053 --api-port 8081
```

## 代码规范

- 纯 Python 标准库，零第三方依赖（aioquic 为可选依赖，仅 DoQ/DoH3 需要）
- 缩进 4 空格，行宽 120
- 模块级 docstring 说明职责
- 关键算法加注释说明设计取舍

## 测试

```bash
# 单元测试
python3 -m unittest discover -s tests

# 部署自检
python3 deploy-test/errcheck.py
python3 deploy-test/bench.py
```

## 文档与代码同步

- 配置项以 `ebpdns/config.py` 的 `DEFAULTS` 字典与 `_validate_cfg` 校验逻辑为唯一事实来源；
  修改/新增配置键时，必须同步更新：
  - `README.md` 配置说明表（键 / 默认值 / 取值范围）
  - `etc/ebpdns.conf.json` 示例配置
  - `web/index.html` 配置页标签/帮助文字（只改说明文字，不改 JS 逻辑）
  - `bpf/README.md`（涉及 map_type / 数据面语义时）
- 文档中出现的默认值、枚举取值、取值范围必须与代码一致，不得凭记忆填写。

## 提交规范

- 一个 PR 只做一件事
- 提交信息：`模块: 简要说明`
- 新功能必须附带测试
- 性能相关改动必须附压测数据

## 发布流程

1. 更新 `ebpdns/__init__.py` 版本号（`__version__`）
2. 更新 `web/index.html` 前端版本号（页脚 `foot-uptime` 与 `APP_VERSION`）
3. 更新 `README.md` 版本历史
4. `./package.sh` 生成发布包
5. 打 tag：`git tag vX.Y.Z && git push --tags`
