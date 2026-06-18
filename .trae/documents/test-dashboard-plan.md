# 测试流程可视化仪表盘 — 实现计划

## 一、摘要

在现有 pytest 测试基础设施之上，增加一个基于 Flask 的实时 Web 仪表盘。测试运行时，仪表盘自动读取 `health.json`、`alerts.db`、`attack_log.jsonl` 等数据文件，以卡片 + 表格 + 进度条形式实时展示检测状态、告警信息和攻击进度。

## 二、当前状态分析

项目中已存在完整的数据出口（探索阶段确认）：

| 数据源 | 路径 | 格式 | 更新方式 |
|--------|------|------|---------|
| 健康指标 | `tests/health.json` | JSON，`healthy` + `metrics` 子对象 | `HealthChecker` 每 10 秒原子替换 |
| 告警记录 | `tests/alerts.db` | SQLite `alerts` 表 | `AlertManager.trigger_alert()` 实时 INSERT |
| 攻击日志 | `tests/attack_log.jsonl` | 每行 JSON | 攻击脚本 `log_attack()` 追加 |
| 蜜罐连接 | `tests/honeypot_connections.jsonl` | 每行 JSON | 蜜罐 `_log_connection()` 追加 |

`DetectionPipeline` 还提供 `snapshot()` 方法返回完整内存快照（含 flows、alerts、correlation 状态），但实时仪表盘优先使用文件数据源以最小化对管线进程的影响。

**当前无任何 Web / 可视化代码**，项目是纯命令行工具。

## 三、方案设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│  pytest runner (或手动运行)                                    │
│  ├── honeypot.py (后台进程)                                    │
│  ├── DetectionPipeline (session fixture)                      │
│  │     ├── health.json  ◄── HealthChecker (10s)               │
│  │     └── alerts.db    ◄── AlertManager (实时)                │
│  └── attack_simulator (生成攻击)                               │
│        └── attack_log.jsonl ◄── log_attack()                  │
│                                                              │
│  共享数据文件 (tests/*.json, tests/*.db, tests/*.jsonl)       │
│         ▲                                                    │
│         │ 读取                                               │
│  ┌──────┴──────────┐                                         │
│  │ Flask Dashboard  │  http://localhost:5000                  │
│  │                  │                                        │
│  │  /               │  → 仪表盘 HTML 页面 (前端自动轮询)      │
│  │  /api/health     │  → 健康指标 JSON                        │
│  │  /api/alerts     │  → 最新告警列表 JSON                     │
│  │  /api/attacks    │  → 攻击执行日志 JSON                     │
│  │  /api/summary    │  → 汇总统计 JSON                        │
│  └──────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 新增文件清单

| 文件 | 作用 |
|------|------|
| `tests/dashboard/__init__.py` | 包初始化 |
| `tests/dashboard/app.py` | Flask 应用：API 路由 + 数据读取 |
| `tests/dashboard/templates/index.html` | 仪表盘前端（纯 HTML + CSS + 原生 JS） |

**零外部前端依赖**：HTML 使用内联 `<style>` 和原生 `fetch()` + `setInterval()`，不引入任何 JS 库/框架，无需 CDN。

### 3.3 Flask 路由设计

| 路由 | 方法 | 返回 | 说明 |
|------|------|------|------|
| `/` | GET | HTML | 仪表盘页面 |
| `/api/health` | GET | JSON | 读取 `tests/health.json`，附加 `server_time` |
| `/api/alerts?limit=50` | GET | JSON | 读取 `tests/alerts.db`，按时间倒序，支持 limit 参数 |
| `/api/alerts/stats` | GET | JSON | 告警统计：按 attack_type + alert_level 聚合计数 |
| `/api/attacks` | GET | JSON | 读取 `tests/attack_log.jsonl`，返回全量攻击记录 |
| `/api/summary` | GET | JSON | 综合摘要：总告警数、异常率、最近告警、攻击进度 |

所有 API 返回带 `Content-Type: application/json`，CORS 为 `*`（允许外部页面嵌入）。

### 3.4 前端仪表盘布局

```
┌──────────────────────────────────────────────────────────────┐
│  Open-Detect 测试仪表盘                    [最后更新: 14:32:05] │
├──────────┬──────────┬──────────┬──────────┬──────────────────┤
│ 流量总计 │ 异常流量  │ 推理次数  │ 平均延迟  │ 运行时间          │
│   1,234  │   89     │  1,100   │  45 ms   │  01:23:45        │
│   ↑ 卡片 │   ↑ 卡片  │   ↑ 卡片  │   ↑ 卡片  │   ↑ 卡片          │
├──────────────────────────────────────────────┬───────────────┤
│              攻击进度                          │  告警分布       │
│  port_scan      ████████████  ✅             │ CRITICAL: 12   │
│  syn_flood      ████████████  ✅             │ WARNING:  45   │
│  c2_beaconing   ██████░░░░░░  ⏳ 运行中      │ INFO:    200   │
│  known_malware  ░░░░░░░░░░░░  ⏸  等待       │                │
│  unknown_attack ░░░░░░░░░░░░  ⏸  等待       │                │
│  normal_traffic ░░░░░░░░░░░░  ⏸  等待       │                │
│  tls13_encrypted░░░░░░░░░░░░  ⏸  等待       │                │
├──────────────────────────────────────────────┴───────────────┤
│              最新告警 (实时滚动)                                │
│  ┌──────┬────────────────┬──────────┬────────┬────────────┐  │
│  │ 时间  │ 攻击类型         │ 分类      │ 等级    │ 源 → 目标   │  │
│  ├──────┼────────────────┼──────────┼────────┼────────────┤  │
│  │14:31 │known_malware   │CobaltStr.│CRITICAL│10.0.0→10..│  │
│  │14:30 │unknown_attack  │Unknown   │WARNING │10.0.5→10..│  │
│  │14:30 │normal          │HTTP      │INFO    │192.168→...│  │
│  └──────┴────────────────┴──────────┴────────┴────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**自动刷新**：前端每 3 秒通过 `fetch()` 轮询 `/api/health`、`/api/alerts`、`/api/attacks`，增量更新 DOM。

### 3.5 配色与告警等级

| 告警等级 | 颜色 | CSS 类 |
|---------|------|--------|
| CRITICAL | 红色 `#e74c3c` | `.alert-critical` |
| WARNING | 橙色 `#f39c12` | `.alert-warning` |
| INFO | 蓝色 `#3498db` | `.alert-info` |

整体使用深色主题，低饱和度，适合长时间盯屏。

### 3.6 与其他组件的集成

**独立运行方式**（不依赖 pytest）：
```bash
# 终端1：启动蜜罐 + 检测管线（或直接跑 orchestrator）
python tests/honeypot.py &
PYTHONPATH=. python tests/attack_simulator/orchestrator.py --target 127.0.0.1

# 终端2：启动仪表盘
python -m tests.dashboard.app
# → 打开 http://localhost:5000
```

**与 pytest 集成**：
pytest 运行期间，Fixtures 自动产生 `health.json` 和 `alerts.db`。只需在另一个终端启动仪表盘即可实时观察测试进展。Flask app 通过文件轮询读取，完全解耦，无需改动任何现有代码。

### 3.7 错误处理与边界情况

| 场景 | 处理 |
|------|------|
| health.json 不存在 | 返回 `{"healthy": false, "error": "no data"}`，前端显示"等待数据..." |
| alerts.db 不存在或空 | 返回空数组 `[]`，前端显示"暂无告警" |
| attack_log.jsonl 不存在 | 返回空数组，攻击进度区显示"等待攻击开始..." |
| SQLite 被锁定（写入中） | Flask 以只读模式打开 `?mode=ro`，设置 busy_timeout |
| 数据文件被删除/损坏 | try/except 捕获，返回错误 JSON，前端不崩溃 |

## 四、假设与决策

1. **Flask 已可用**：当前环境 pip 安装 Flask 轻量快速（约 2MB），不依赖系统级包。
2. **端口 5000**：默认使用 5000，若被占用可通过环境变量 `DASHBOARD_PORT` 覆盖。
3. **文件路径**：API 读取 `tests/health.json`、`tests/alerts.db` 等路径，由 `Path(__file__).resolve().parent.parent` 推导，保证从任意目录启动都能找到。
4. **只读访问**：仪表盘只读数据文件，不修改任何状态，安全无副作用。
5. **前端无依赖**：纯 HTML/CSS/JS，内联样式，无需 npm/webpack/CDN。

## 五、验证步骤

1. 启动蜜罐 + 攻击编排器 → `alerts.db` 和 `attack_log.jsonl` 产生数据
2. 启动 Flask dashboard → 浏览器打开 `http://localhost:5000`
3. 观察到：
   - 指标卡片随 `health.json` 更新实时刷新
   - 告警表格逐条出现，颜色按等级区分
   - 攻击进度条跟随 `attack_log.jsonl` 推进
4. 前后端通信断网时卡片保持最后一次数据，不白屏
5. 数据文件不存在时界面显示占位提示，不报错不崩溃
