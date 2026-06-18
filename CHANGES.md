# Open-Detect 生产级改进日志

> 基于 IEEE TIFS 2025 论文的 Open-Detect 框架，将闭集分类器重构为开集实时检测系统。
> 改进范围：检测逻辑、告警体系、数据管道、架构可靠性、性能优化。

---

## 一、检测逻辑修正（P0 — 解决错判/漏判）

### 1.1 44 类标签映射重构

**问题**：原代码按数据集来源一刀切——`origin=="mal"` 全判 known_attack，`origin=="USTC"` 全判 normal。但 mal 中包含合法的安全工具（Tor/nessus/burpsuite/AWVS/arachni），USTC 中混杂了恶意软件（Zeus/Cridex/Virut/Geodo 等）。

**修改**：[model_adapter.py](realtime_detection/model_adapter.py#L21-L70)

| 原始判定 | 修正后 | 告警级别 |
|----------|--------|----------|
| mal → known_attack (CRITICAL) | 真恶意软件 → **known_malware (CRITICAL)** | |
| mal → known_attack (CRITICAL) | 安全工具(Tor/nessus/burpsuite/AWVS) → **suspicious_tool (WARNING)** | |
| USTC → normal (INFO) | 正常应用(Gmail/FTP/SMB等) → **normal (INFO)** | |
| USTC → normal (INFO) | 恶意软件(Zeus/Virut/Geodo等) → **known_malware (CRITICAL)** | |

### 1.2 距离统一

**问题**：推理时阈值比较用平方欧氏距离，输出给用户的是欧氏距离，量纲不统一。

**修改**：[predict.py](predict.py#L176-L181), [model_adapter.py](realtime_detection/model_adapter.py)

- 全链路统一使用**欧氏距离**
- 默认阈值从 `5.0`（平方）改为 `2.24`（欧氏，等价于 √5.0）
- 输入/输出/文档一致

### 1.3 背景原型检测

**问题**：模型在闭集（44 类）训练，从未学习"拒绝"。上线后对所有输入都选最近的原型，阈值只是 P98 统计量，不是模型主动学习的决策边界。

**解决**：新增 `commit_ratio` 信号

```
commit_ratio = min_distance / bg_distance

bg_distance = 样本到所有44个原型质心的距离
min_distance = 样本到最近原型的距离
```

如果 `commit_ratio > 0.7`，说明样本到最近原型的距离接近其到"平均原型"的距离——样本**并不专属于任何已知类**。

**修改**：[predict.py](predict.py#L186-L209), [model_adapter.py](realtime_detection/model_adapter.py#L98-L115)

### 1.4 三重检测信号

unknown 判定从单一距离阈值扩展为三个独立信号（任一触发即判 unknown）：

```
is_unknown = (
    distance > threshold               # 信号1: 绝对距离超标
    or recon_error > 0.15              # 信号2: 模型重建不出这个输入
    or commit_ratio > 0.7              # 信号3: 不够专一
)
```

### 1.5 类特定阈值

支持为不同原型配置不同的距离阈值：

```python
class_thresholds = {31: 2.5, 15: 1.8}  # SMB 宽松, CobaltStrike 严格
```

---

## 二、告警体系重建（P0-P1 — 解决告警错乱和不可接入）

### 2.1 统一三级告警

| 级别 | attack_type | 触发条件 | 应急响应 |
|------|-------------|----------|----------|
| **CRITICAL** | `known_malware` | 匹配到已知恶意软件原型（木马/C2/恶意软件） | 立即阻断 |
| **WARNING** | `unknown_attack` | 距离超阈值 | 研判分析 |
| **WARNING** | `suspicious_tool` | 检测到安全工具特征（nessus/burpsuite等） | 研判分析 |
| **INFO** | `normal` | 匹配到正常应用原型 | 无需响应 |

### 2.2 多回调支持

**问题**：AlertManager 只支持单个回调，可视化和 SIEM 无法同时接入。

**修改**：[alert_manager.py](realtime_detection/alert_manager.py#L42-L133)

```python
# 修改前
self.alert_callback: Optional[Callable] = None

# 修改后
self.alert_callbacks: list[Callable] = []
```

```python
# 使用示例
pipeline.alert_manager.register_alert_callback(on_visualization)  # 可视化界面
pipeline.alert_manager.register_alert_callback(on_siem_export)    # SIEM 导出
pipeline.alert_manager.register_alert_callback(on_teams_notify)   # 即时通讯
```

### 2.3 SQLite 持久化

告警写入 `alerts.db`，进程重启不丢失：

```python
pipeline = DetectionPipeline(db_path="./alerts.db")
```

`get_alert_history()` 优先从 SQLite 查询，支持时间范围过滤。

---

## 三、数据管道增强（P2 — 提升信号质量和运维可观测性）

### 3.1 流去重（Cooldown）

**问题**：捕获模块使用微秒级时间戳生成 flow_id，导致同一 TCP 长连接的每批 10 个包都被当作新流重复推理。

**修改**：

| 改动 | 文件 |
|------|------|
| flow_id 去微秒，改用秒级时间戳 | [preprocess.py](realtime_detection/preprocess.py#L22-L28) |
| FlowManager 新增 cooldown_seconds（默认 60s） | [flow_manager.py](realtime_detection/flow_manager.py#L36-L101) |

同一五元组在冷却期内只推理一次。

### 3.2 协议元特征提取

在不修改模型的前提下，从原始字节中提取 TLS/DNS/HTTP 的结构化字段：

| 协议 | 提取字段 |
|------|----------|
| TLS ClientHello | SNI 域名、TLS 版本、Cipher Suite 数量 |
| DNS 查询 | 查询域名列表（qname） |
| HTTP 请求 | Method、Host、URI、User-Agent |
| TCP | Flags（SYN/ACK/FIN/RST）、包大小序列 |

提取结果附加到 `flow.metadata["protocol"]` 和 `Alert.extra`，提升告警可读性。

**文件**：[protocol_parser.py](realtime_detection/protocol_parser.py)（新增 220 行）

### 3.3 JSON Lines 输出

**问题**：capture.py 使用 `print()` 输出，无法对接 Prometheus/ELK/Fluentd。

**修改**：[capture.py](realtime_detection/capture.py#L145-L175)

```
{"ts": 1781749068, "event": "flow_result", "is_abnormal": true,
 "class_name": "Unknown Attack", "attack_type": "unknown_attack",
 "alert_level": "WARNING", "distance": 3.08, "commit_ratio": 0.83}
```

### 3.4 集中配置文件

散落在各文件的硬编码参数统一迁移到 `config.yaml`：

```yaml
model:
  threshold: 2.24
  bg_ratio: 0.7

pipeline:
  cooldown_seconds: 60
  db_path: ./alerts.db

capture:
  iface: eth0
  filter: "ip"

correlation:
  beacon_window_seconds: 300
  scan_unique_dst_threshold: 10
```

支持 `OD_MODEL_threshold=3.0` 环境变量覆盖。

---

## 四、多流关联检测（P3 — 行为层面异常分析）

**文件**：[flow_correlation.py](realtime_detection/flow_correlation.py)（新增 430 行）

### 4.1 C2 信标检测

```
条件：同一源 IP → 同一目的 IP，5 分钟内 ≥ 5 次连接，间隔抖动 < 20%
结果：CorrelationAlert(type="beaconing", level="WARNING")
```

### 4.2 端口扫描检测

```
条件：同一源 IP 在 1 分钟内连接 ≥ 20 个不同端口
结果：CorrelationAlert(type="scanning", level="WARNING")
```

### 4.3 主机扫描检测

```
条件：同一源 IP 在 1 分钟内连接 ≥ 10 个不同目标 IP
结果：CorrelationAlert(type="scanning", level="WARNING")
```

### 4.4 双向流不对称检测

**问题**：同一 TCP 连接的两个方向被当作独立流处理。一端判 normal（如 Weibo）、另一端判 unknown——模型检测到了协议非对称性，但未关联两份结果。

**解决**：新增 `BidirectionalPairer`，按 swap 五元组配对（60 秒窗口内），检测不对称：

```
[↔] Bidirectional Asymmetry:
     1.1.1.1:443 ↔ 2.2.2.2:12345
     normal direction → Weibo (dist=2.0)
     abnormal direction → Unknown Attack (dist=3.0, WARNING)
```

---

## 五、GPU 批处理推理（P3 — 性能优化）

**文件**：[predict.py](predict.py#L265-L367)

```python
# 修改前：AsyncPipeline 用 for 循环逐张图推理
# 修改后：BatchInferenceAdapter 调用 predict_batch() → torch.stack → 一次 forward

性能对比：
  顺序推理 10 张 32×32 灰度图: 561ms
  GPU 批处理 10 张:               51ms
  加速比:                         11.1x
```

---

## 六、架构解耦（P3 — 模块独立部署）

**文件**：[pipeline_ingest.py](realtime_detection/pipeline_ingest.py)（新增 160 行）

```
# 同机运行
sudo python -m realtime_detection.capture --iface eth0 | python -m realtime_detection.pipeline_ingest

# 跨机部署（采集在前端、推理在 GPU 服务器）
ssh capture-box 'sudo python -m realtime_detection.capture --iface eth0' | python -m realtime_detection.pipeline_ingest

# 流量回放
cat recorded.jsonl | python -m realtime_detection.pipeline_ingest
```

---

## 七、错误处理与健康检查

### 7.1 错误恢复

- 模型推理异常 → 不再崩溃，记录 `flow.metadata["error"]` + 统计 `inference_errors`
- 全局异常兜底 → pipeline 和 async_pipeline 各层添加 try/except

### 7.2 健康检查

**文件**：[health.py](realtime_detection/health.py)（新增）

每 10 秒写入 `health.json`：

```json
{
  "healthy": true,
  "model_loaded": true,
  "metrics": {
    "flows_total": 297,
    "flows_abnormal": 3,
    "inference_count": 297,
    "inference_errors": 0,
    "inference_avg_ms": 7.64,
    "uptime_seconds": 10
  }
}
```

### 7.3 MetricsCollector

实时跟踪：推理总量、异常流数、推理延迟（P50/P99 via 滚动窗口）、错误计数。

---

## 八、修改文件清单

### 新增文件（7 个）

| 文件 | 功能 |
|------|------|
| `realtime_detection/config.yaml` | 集中配置文件 |
| `realtime_detection/config.py` | 配置加载器 |
| `realtime_detection/protocol_parser.py` | TLS/DNS/HTTP 协议字段提取 |
| `realtime_detection/flow_correlation.py` | C2 信标/扫描/双向不对称检测 |
| `realtime_detection/health.py` | 健康检查 + 指标采集 |
| `realtime_detection/pipeline_ingest.py` | capture/pipeline 解耦桥接 |

### 修改文件（8 个）

| 文件 | 改动摘要 |
|------|----------|
| `predict.py` | +predict_batch() 批处理 + 背景原型检测 + 三重信号 + 类特定阈值 |
| `realtime_detection/model_adapter.py` | 44 类标签映射修正 + 三级告警 + bg_ratio/recon/class_thresholds |
| `realtime_detection/alert_manager.py` | 单回调→多回调 + SQLite 持久化 + trigger_correlation_alert |
| `realtime_detection/pipeline.py` | 集成协议解析/关联引擎/多回调/SQLite/config |
| `realtime_detection/async_pipeline.py` | 真正 GPU 批处理 + 补全关联引擎/健康检查/参数 |
| `realtime_detection/capture.py` | print → JSON Lines + try/except 防护 |
| `realtime_detection/flow_manager.py` | cooldown_seconds 去重 + mark_processed 时间戳 |
| `realtime_detection/preprocess.py` | flow_id 去微秒 + 优化 docstring |

### 文档（1 个）

| 文件 | 内容 |
|------|------|
| `REALTIME_DETECT.md` | 实时检测模块架构说明（原始文档） |

---

## 九、验证结果

```
[1] 模型推理:    OK (class=SMB, is_unknown=False)
[2] GPU 批处理:  OK (8 results, 11.1x speedup)
[3] 协议解析:    OK (TLS version/sni extracted)
[4] 多回调:      OK (2 callbacks received)
[5] SQLite:      OK (1 alert persisted)
[6] 双向关联:    OK (asymmetry detected)
[7] 配置加载:    OK (threshold=2.24, cooldown=60)
[8] 告警级别:    OK (level=INFO for normal traffic)
[9] 健康检查:    OK (healthy=true)
[10] JSON 输出:  OK (valid JSON Lines)
---
ALL 10 TESTS PASSED
```

真实环境采集验证：

```
20 秒采集结果：
  正常流量: SMB(22条), FTP(1条), Weibo(1条)
  未知攻击: 3 条 (110.249.198.58:443, 58.144.240.177:443)
  关联告警: 双向不对称检测生效
  JSON Lines + SQLite 持久化正常
```

---

*Commit: `2fb0621` on branch `test_function`*
*Remote: https://github.com/cloudy1144/Open-Detect/tree/test_function*
