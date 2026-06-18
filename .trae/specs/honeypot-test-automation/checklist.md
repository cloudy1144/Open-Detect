# Checklist

## Task 1: Docker 化 Open-Detect
- [x] `tests/Dockerfile.open-detect` 已创建，入口脚本 `tests/entrypoint.sh` 已创建
- [x] 模型文件 `save_model/mixed_44_split_0.pt` 可加载（pytest 测试验证）
- [ ] ~~容器内 capture.py 监听网卡~~ — 运行环境无 Docker daemon，改为进程级方案
- [x] `health.json` 通过 DetectionPipeline HealthChecker 正常写入
- [x] 告警写入 `alerts.db` SQLite（pytest fixture 验证）
- [ ] 注：Dockerfile 和 entrypoint.sh 保留供有 Docker 环境的用户使用

## Task 2: 测试环境（进程级替代 Docker Compose）
- [x] 蜜罐 `tests/honeypot.py` 6 个端口监听正常（2222, 8080, 2121, 3307, 2525, 8443）
- [x] 端口扫描可连接蜜罐服务
- [x] DDoS 脚本可发送流量到蜜罐
- [x] 攻击脚本记录写入 `attack_log.jsonl`
- [ ] ~~Docker Compose 编排~~ — 不可用 Docker，改用 pytest fixture + 进程管理

## Task 3: 攻击模拟器
- [x] 端口扫描脚本 `scan.py` 成功执行并写入 attack_log.jsonl
- [x] DDoS 仿真脚本 `ddos.py` 成功执行（298 packets/3s）并写入 attack_log.jsonl
- [x] C2 信标脚本 `beacon.py` 已创建（需 5+ mins 完整运行）
- [x] PCAP 回放脚本 `replay.py` 支持 4 种模式（known_malware, unknown_attack, normal, tls13）含合成流量 fallback
- [x] 编排器 `orchestrator.py` 按序执行所有攻击

## Task 4: pytest 测试套件
- [x] `pipeline` fixture 正确启动/销毁 DetectionPipeline（含 health + SQLite）
- [x] `honeypot` fixture 正确启动/停止蜜罐进程
- [x] `get_alerts()` 正确读取 SQLite 告警
- [x] `get_health()` 正确解析 health.json
- [x] `test_binary_c2_like_traffic` 通过
- [x] `test_http_based_malware_traffic` 通过
- [x] `test_random_noise_traffic` (未知攻击) 通过
- [x] `test_mirai_like_traffic` (未知攻击) 通过
- [x] `test_http_traffic` (正常流量无误报) 通过
- [x] `test_dns_traffic` (正常流量) 通过
- [x] `test_tls13_encrypted_c2` (TLS 1.3) 通过
- [x] `test_single_inference_latency` 通过 (< 2s)
- [x] `test_batch_inference_throughput` 通过 (avg < 200ms, max < 500ms)
- [x] `test_inference_success_rate` 通过 (error < 10%)
- [x] `test_sustained_processing` 通过 (100 flows)
- [x] `pytest --junitxml=pytest-report.xml` 产出报告（11 passed, 0 failed）

## Task 5: CI 流水线
- [x] `.github/workflows/test.yml` 语法正确
- [x] LFS checkout 配置（`lfs: true`）
- [x] pytest 全量执行步骤
- [x] JUnit XML 报告上传
- [ ] ~~Docker 镜像构建~~ — CI 环境使用直接 pip install + CPU torch
- [ ] ~~docker compose 启动~~ — 替换为进程级测试
