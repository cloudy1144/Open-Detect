# Tasks

## Task 1: Docker 化 Open-Detect 检测引擎
将 Open-Detect 打包为 Docker 镜像，支持容器化运行实时检测管线。

- [ ] SubTask 1.1: 编写 `tests/Dockerfile.open-detect`
  - 基于 `python:3.10-slim`
  - 安装 `requirements.txt` 依赖（torch CPU 版本以减小镜像体积）
  - 复制项目源码和预训练模型 `save_model/mixed_44_split_0.pt`
  - 设置 `WORKDIR /app`，`ENTRYPOINT` 为检测管线启动脚本
- [ ] SubTask 1.2: 编写容器内检测管线入口脚本 `tests/entrypoint.sh`
  - 启动 `capture.py` 抓包 + `DetectionPipeline` 处理
  - 配置 `health.json` 输出到共享卷
  - 配置告警输出到 stdout JSON Lines 和 SQLite
  - 支持环境变量覆盖模型路径、阈值、网卡接口
- [ ] SubTask 1.3: 构建镜像并验证
  - `docker build -f tests/Dockerfile.open-detect -t open-detect:test .`
  - 验证模型加载成功、health.json 正常写入

## Task 2: Docker Compose 测试环境编排
编排蜜罐 + Open-Detect + 攻击模拟器三者的 Docker 环境。

- [ ] SubTask 2.1: 编写 `docker-compose.test.yaml`
  - 定义自定义 bridge 网络 `test-net`（子网 172.30.0.0/24）
  - `honeypot` 服务：部署 Cowrie（SSH 蜜罐）+ Dionaea（多协议蜜罐）轻量替代 T-Pot 核心
  - `open-detect` 服务：使用 Task 1 镜像，挂载模型文件卷，`network_mode: host` 或 `cap_add: NET_ADMIN` 以支持 Scapy 抓包
  - `attack-sim` 服务：稍后由 Task 3 构建，挂载攻击脚本和 PCAP 文件卷
- [ ] SubTask 2.2: 配置共享卷和健康检查
  - 共享卷 `test-data`：存放 health.json、alerts.db、attack_log.jsonl、PCAP 样本
  - open-detect 容器健康检查：周期性读取 health.json
  - honeypot 容器健康检查：TCP 端口探测
- [ ] SubTask 2.3: 验证环境启动
  - `docker compose -f docker-compose.test.yaml up -d`
  - 所有容器 Running 状态
  - open-detect health.json `healthy: true`

## Task 3: 攻击模拟器 Docker 镜像
构建包含攻击工具和自动化脚本的攻击模拟器容器。

- [ ] SubTask 3.1: 编写 `tests/Dockerfile.attack-sim`
  - 基于 `kalilinux/kali-rolling`（含 nmap、hping3、hydra、metasploit）
  - 安装 `tcpreplay`、`python3`、`curl`
  - 复制攻击脚本和 PCAP 样本目录
- [ ] SubTask 3.2: 编写端口扫描脚本 `tests/attack_simulator/scan.py`
  - 执行 `nmap -sS <target>` 对蜜罐 IP 进行 SYN 扫描
  - 输出 attack_log.jsonl 记录
- [ ] SubTask 3.3: 编写 DDoS 模拟脚本 `tests/attack_simulator/ddos.py`
  - 执行 `hping3 --flood -S <target> -p <port>` 持续 10 秒
  - 输出 attack_log.jsonl 记录
- [ ] SubTask 3.4: 编写 C2 信标模拟脚本 `tests/attack_simulator/beacon.py`
  - 每 30 秒向目标端口发起 TCP 连接并发送固定 payload，持续 5 分钟
  - 输出 attack_log.jsonl 记录
- [ ] SubTask 3.5: 编写 PCAP 回放脚本 `tests/attack_simulator/replay.py`
  - 使用 `tcpreplay --intf=eth0 <pcap_file>` 回放
  - 支持参数：`--type known_malware|unknown_attack|normal|tls13`
- [ ] SubTask 3.6: 编写攻击编排器 `tests/attack_simulator/orchestrator.py`
  - 按序执行全部攻击类型
  - 每种攻击间等待 30 秒（确保检测系统完成处理）
  - 收集所有 attack_log.jsonl 记录汇总
- [ ] SubTask 3.7: 测试：PYTHONPATH=/app python -m attack_simulator scan --target 172.30.0.20  --port 2222 

## Task 4: pytest 测试套件
实现 pytest 测试框架，包含 fixtures 和自动化测试用例。

- [ ] SubTask 4.1: 编写 `tests/conftest.py`
  - `test_env` session fixture：`docker compose up -d`，等待 health.json 就绪，teardown 时 `docker compose down -v`
  - `alerts_collector` fixture：读取 alerts.db 中的告警记录，返回 list[dict]
  - `health_snapshot` fixture：读取 health.json，返回 dict
  - `attack_log` fixture：读取 attack_log.jsonl，返回 list[dict]
  - `run_attacks` fixture：调用 orchestrator.py 执行全量攻击，等待完成
- [ ] SubTask 4.2: 编写 `tests/test_detection.py`
  - `test_port_scan_detection`：断言存在 scanning 关联告警
  - `test_ddos_detection`：断言存在 is_abnormal=True 的流量
  - `test_beaconing_detection`：断言存在 beaconing 关联告警
  - `test_known_malware_detection`：断言存在 attack_type=known_malware、alert_level=CRITICAL 的告警
  - `test_unknown_attack_detection`：断言存在 attack_type=unknown_attack、alert_level=WARNING 的告警
  - `test_normal_traffic_no_false_positive`：正常流量回放后，断言不存在 attack_type!=normal 的告警，或不触发 abnormal
- [ ] SubTask 4.3: 编写 `tests/test_performance.py`
  - `test_inference_latency`：断言 health.json 中 inference_avg_ms ≤ 200
  - `test_inference_error_rate`：断言 inference_errors / inference_count ≤ 0.05
  - `test_memory_stability`：获取容器内存使用，计算增长率 ≤ 50 MB/h
- [ ] SubTask 4.4: 配置 `pytest.ini`
  - 设置 `testpaths = tests/`
  - 设置 `timeout = 600`（单个测试超时 10 分钟）
  - 设置 JUnit XML 报告输出

## Task 5: GitHub Actions CI 流水线
编写 CI 工作流，在代码 push/PR 时自动执行完整测试。

- [ ] SubTask 5.1: 编写 `.github/workflows/test.yml`
  - trigger: push 到 main 分支、PR 到 main
  - job: `test`
  - runs-on: `ubuntu-22.04`
  - steps:
    1. checkout 代码
    2. 拉取 LFS 模型文件
    3. 构建 open-detect 和 attack-sim 镜像
    4. 启动 docker compose
    5. 等待 health.json 就绪（重试最多 15 次，每次间隔 20 秒）
    6. 运行 pytest（安装 pytest、pytest-timeout）
    7. 上传 pytest-report.xml 和 health.json 为产物
- [ ] SubTask 5.2: 本地验证 CI 流程
  - 模拟 CI 步骤在本地执行，确保所有命令无报错

# Task Dependencies
- Task 2 依赖 Task 1（需有 open-detect 镜像）
- Task 3 可并行于 Task 1, 2
- Task 4 依赖 Task 2, 3（需环境和攻击脚本就绪）
- Task 5 依赖 Task 4（需 pytest 测试通过后集成 CI）
