# Heka Scanner

Heka Scanner 是一个面向内网合规场景的端口扫描工具。当前版本已从 Flask + HTML 前端迁移为 PySide6 桌面应用，扫描核心逻辑仍保留在原有 Python 模块中，可通过桌面界面或命令行调用。

## 功能特性

- PySide6 桌面图形界面，无需浏览器和 Web 服务端口
- 支持单 IP、CIDR 网段扫描
- 支持端口列表、端口范围和常用端口扫描
- 支持快速扫描、全连接扫描、UDP扫描、全面扫描等模式
- 内置合规校验，默认阻止公网 IP 扫描
- 输出开放端口、服务识别、风险等级、响应时间和统计信息
- 保留命令行扫描入口，便于脚本化使用

## 项目结构

```text
.
├── config/              # 配置文件
├── core/                # IP 校验、端口解析、扫描器等核心逻辑
├── desktop/             # PySide6 桌面界面
├── output/              # 审计、展示、风险评估和导出
├── scheduler/           # 扫描任务调度
├── services/            # 可直接调用的扫描服务层
├── tests/               # 模块测试
├── utils/               # 性能、带宽、容错辅助模块
├── port_scanner.py      # 命令行入口
├── run_desktop.py       # 桌面版入口
└── requirements.txt     # Python 依赖
```

## 环境准备

建议使用项目内虚拟环境，不要把 PySide6 安装到全局 Python。

```bash
cd "/Users/kaihuazz/Workspace/Python/heka- scanner/work-from-master"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

## 启动桌面版

```bash
.venv/bin/python run_desktop.py
```

启动后在窗口中填写目标 IP/CIDR、端口范围和扫描模式，然后点击“开始扫描”。

常用输入示例：

```text
目标: 127.0.0.1
端口: 1-1000
模式: 全连接扫描
```

如果误输入 `127001`，桌面界面会自动归一化为 `127.0.0.1`。

### 演示已耗时和 ETA

本机扫描可能很快完成，开发演示时可以通过环境变量放慢进度更新，方便观察“已耗时”和“ETA”。默认值为 `0`，正常运行不会延迟。

```bash
HEKA_PROGRESS_DELAY_MS=100 .venv/bin/python run_desktop.py
```

PyCharm 运行时，可以在 `Run/Debug Configurations` 的 `Environment variables` 中添加：

```text
HEKA_PROGRESS_DELAY_MS=100
```

建议演示输入：

```text
目标: 127.0.0.1
端口: 1-100
模式: 快速扫描
```

## 命令行用法

桌面版之外，也可以继续使用命令行入口：

```bash
.venv/bin/python port_scanner.py -i 127.0.0.1 -p 80,443
```

导出 JSON 结果：

```bash
.venv/bin/python port_scanner.py -i 127.0.0.1 -p 1-1000 -o output/result.json -f json
```

更多参数：

```bash
.venv/bin/python port_scanner.py --help
```

## 合规说明

默认配置位于 `config/settings.yaml`。当前合规策略默认只允许扫描：

- `127.0.0.1/8`
- `192.168.0.0/16`

并开启公网 IP 阻止策略。修改扫描范围前，请确认你拥有对应网络的授权。

## 测试

运行全部模块测试：

```bash
for f in tests/test_module*.py; do .venv/bin/python "$f" || exit 1; done
```

检查依赖完整性：

```bash
.venv/bin/python -m pip check
```

## 依赖

核心依赖见 `requirements.txt`：

- PySide6
- psutil
- PyYAML
- colorama
- tabulate

当前版本已移除 Flask、数据库和登录相关依赖。
