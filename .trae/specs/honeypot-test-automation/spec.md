# 蜜罐测试环境自动化 Spec

## Why
当前项目缺乏自动化测试基础设施，仅依赖静态数据集回放无法验证系统在真实网络环境中的检测能力。需要构建一个可控的蜜罐攻击环境，通过自动化攻击脚本触发真实网络攻击行为，并由 pytest 驱动的测试框架自动验证检测结果，同时支持 CI 集成。

## What Changes
- 新增 `docker-compose.test.yaml` — 编排蜜罐、攻击模拟器、Open-Detect 检测系统的 Docker 网络拓扑
- 新增 `tests/` 目录 — pytest 测试框架，包含 fixtures、测试用例、conftest
- 新增 `tests/attack_simulator/` — 自动化攻击脚本集（端口扫描、DDoS、暴力破解、C2 信标、恶意 PCAP 回放、正常流量生成）
- 新增 `tests/conftest.py` — pytest fixtures：环境启停、健康检查等待、告警收集
- 新增 `tests/test_detection.py` — 核心检测能力测试
- 新增 `tests/test_performance.py` — 性能与稳定性测试
- 新增 `.github/workflows/test.yml` — CI 流水线
- 新增 `tests/Dockerfile.open-detect` — Open-Detect 容器镜像
- 新增 `tests/Dockerfile.attack-sim` — 攻击模拟器容器镜像

## Impact
- Affected specs: 无现有 spec
- Affected code: 
  - 新增：`docker-compose.test.yaml`、`tests/`、`.github/workflows/test.yml`
  - 不改动现有源码

---

## ADDED Requirements

### Requirement: Docker 化测试环境
系统 SHALL 提供一份 `docker-compose.test.yaml`，将 Open-Detect 检测引擎、蜜罐目标、攻击模拟器部署在同一个隔离的 Docker 网络中。

#### Scenario: 环境启动
- **GIVEN** 运行 `docker compose -f docker-compose.test.yaml up -d`
- **WHEN** 所有容器就绪
- **THEN** health checker 写入的 `health.json` 中 `healthy` 字段为 `true`
- **THEN** 蜜罐服务端口可被攻击模拟器访问

#### Scenario: 环境销毁
- **GIVEN** Docker 测试环境正在运行
- **WHEN** 运行 `docker compose -f docker-compose.test.yaml down -v`
- **THEN** 所有容器、网络、卷被清除，不留残留

### Requirement: 自动化攻击模拟
系统 SHALL 提供一组自动化攻击脚本，覆盖以下攻击类型，并以结构化 JSON 记录每次攻击的执行信息。

#### Scenario: 端口扫描模拟
- **WHEN** 攻击脚本执行 `nmap -sS <honeypot_ip>` 对蜜罐进行 SYN 扫描
- **THEN** 在 60 秒窗口内扫描了某 IP 的 20+ 不同端口
- **THEN** 系统 SHALL 触发 scanning 关联告警

#### Scenario: DDoS SYN Flood 模拟
- **WHEN** 攻击脚本执行 `hping3 --flood -S <honeypot_ip> -p 80`
- **THEN** 系统 SHALL 在模型推理中将该流标记为 `is_abnormal=True`

#### Scenario: C2 信标模拟
- **WHEN** 攻击脚本每 30 秒向蜜罐 443 端口发送一次 TCP 连接，持续 5 分钟
- **THEN** 系统 SHALL 触发 beaconing 关联告警（抖动 < 20%）

#### Scenario: 已知恶意 PCAP 回放
- **WHEN** 使用 `tcpreplay` 回放 CobaltStrike / Zeus PCAP 文件
- **THEN** 系统 SHALL 检出并产生 CRITICAL 级告警，`attack_type=known_malware`

#### Scenario: 未知攻击 PCAP 回放
- **WHEN** 使用 `tcpreplay` 回放 Mirai / Hajime 等训练集外 PCAP 文件
- **THEN** 系统 SHALL 检出并产生 WARNING 级告警，`attack_type=unknown_attack`

#### Scenario: 正常流量回放
- **WHEN** 回放 HTTP / DNS / FTP 正常协议 PCAP 或生成模拟正常请求
- **THEN** 系统 SHALL 将其分类为 `attack_type=normal`，`alert_level=INFO`

#### Scenario: TLS 1.3 加密恶意流量回放
- **WHEN** 回放 TLS 1.3 封装的恶意 C2 通信 PCAP
- **THEN** 系统 SHALL 至少以 `suspicious_tool` 或 `unknown_attack` 级别检出

#### Scenario: 攻击执行记录
- **WHEN** 每次攻击脚本执行完成
- **THEN** 输出一条 JSON 记录到 `attack_log.jsonl`，包含 `attack_id`、`attack_type`、`start_time`、`duration`、`target_ip` 字段

### Requirement: pytest 测试框架
系统 SHALL 提供基于 pytest 的测试套件，通过 fixture 管理测试环境生命周期，并在测试用例中对检测结果进行自动化断言。

#### Scenario: 环境 fixture 自动启停
- **GIVEN** pytest session 开始
- **WHEN** 调用 `test_env` fixture
- **THEN** Docker 环境自动启动，等待 health.json 就绪
- **THEN** session 结束后 Docker 环境自动销毁

#### Scenario: 告警准确性验证
- **GIVEN** 攻击脚本已执行
- **WHEN** 查询 AlertManager 的 SQLite 告警记录或 stdout JSON Lines
- **THEN** pytest 断言存在对应 `attack_type` 和 `alert_level` 的告警

#### Scenario: 性能指标验证
- **GIVEN** 系统持续运行
- **WHEN** 读取 `health.json`
- **THEN** 断言 `inference_avg_ms` ≤ 200ms（CPU）
- **THEN** 断言 `inference_errors` / `inference_count` ≤ 0.05

#### Scenario: 资源稳定性验证
- **GIVEN** 系统运行 10 分钟以上
- **WHEN** 采集容器内存指标（Docker stats）
- **THEN** 断言内存增长速率 ≤ 50 MB/h

### Requirement: CI 集成
系统 SHALL 提供 GitHub Actions 工作流，在代码 push 或 PR 时自动触发测试。

#### Scenario: CI 自动运行
- **GIVEN** 代码推送到仓库
- **WHEN** GitHub Actions 检测到 push 事件
- **THEN** 自动构建 Docker 镜像、启动环境、运行 pytest、输出 JUnit XML 报告
- **THEN** 测试失败时 CI 流水线标记为失败

#### Scenario: 测试报告产物
- **WHEN** CI 执行完成
- **THEN** 上传 `pytest-report.xml` 和 `health.json` 作为流水线产物
