# 实时检测模块说明

本目录是队员3负责的实时检测链路实现，重点是把"流量抓取/模拟输入 -> 预处理 -> 模型推理 -> 告警 -> 异常导出"串起来，方便后续接入队员1的抓包结果和队员2的模型推理接口。

---

## 一、模块架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   队员1:        │    │   队员2:        │    │   队员4:        │
│   数据采集      │    │   模型推理      │    │   可视化界面    │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                      │                      │
         ▼                      ▼                      ▼
┌───────────────────────────────────────────────────────────────┐
│                     队员3: 实时检测链路                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │ flow_manager│→│ preprocess  │→│model_adapter│→│alert_manager││
│  │  (流管理)   │ │  (预处理)   │ │  (推理适配) │ │  (告警管理) │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────┬─────┘ │
│       │                                                  │     │
│       ▼                                                  ▼     │
│  ┌─────────────┐                               ┌─────────────┐ │
│  │   exporter  │◄─────────────────────────────│   pipeline  │ │
│  │  (PCAP导出) │                               │  (管道编排) │ │
│  └─────────────┘                               └─────────────┘ │
│       │                                                  │     │
│       ▼                                                  ▼     │
│  ┌─────────────┐                               ┌─────────────┐ │
│  │dynamic_thres│                               │async_pipeline││
│  │  (动态阈值) │                               │ (异步管道)  │ │
│  └─────────────┘                               └─────────────┘ │
│       │                                                  │     │
│       └──────────────────────────────────────────────────┘     │
│                               │                               │
│                               ▼                               │
│                    ┌─────────────────┐                        │
│                    │    logger       │                        │
│                    │   (日志系统)    │                        │
│                    └─────────────────┘                        │
└───────────────────────────────────────────────────────────────┘
```

---

## 二、核心功能模块

### 2.1 流管理模块 (`flow_manager.py`) ✅

**职责**：流数据结构定义、生命周期管理、重复检测避免

**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| FlowData 数据结构 | 统一流记录格式，包含五元组、时间戳、数据包、灰度图等字段 | ✅ |
| 线程安全存储 | 使用锁机制保证并发安全 | ✅ |
| 重复检测避免 | `is_flow_processed()` 判断流是否已处理 | ✅ |
| 自动过期清理 | 后台守护线程定时清理过期流（默认5分钟） | ✅ |
---

### 2.2 预处理模块 (`preprocess.py`) ✅
**职责**：数据包 → 灰度图转换、流ID生成、Mock数据生成
**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| 灰度图构建 | `build_gray_image()` 将数据包转换为32×32灰度图 | ✅ |
| 流ID生成 | `build_flow_id()` 基于五元组+时间戳构造唯一标识 | ✅ |
| Mock数据生成 | `mock_flow_data()` 生成模拟流量用于测试 | ✅ |

---

### 2.3 推理适配器 (`model_adapter.py`) ✅
**职责**：封装队员2的模型推理接口，统一输入输出格式
**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| 统一推理接口 | 封装 `predict()` 函数，提供稳定调用接口 | ✅ |
| 配置化参数 | 支持模型路径、阈值、top_k、温度系数等 | ✅ |
| 标准化输出 | 统一返回 `is_abnormal`、`attack_type`、`confidence`、`distance` | ✅ |

**推理结果格式**：
```python
{
    "top_results": [...],          # 全部推理结果
    "top1": {...},                 # 最佳匹配结果
    "class_name": "Normal",        # 类别名称
    "label": 0,                    # 类别标签
    "confidence": 0.95,            # 置信度
    "distance": 2.3,               # KL距离
    "origin": "normal",            # 来源类型
    "is_unknown": False,           # 是否未知
    "is_abnormal": False,          # 是否异常
    "attack_type": "normal",       # 攻击类型
    "alert_level": "INFO"          # 告警级别
}
```
---

### 2.4 动态阈值模块 (`dynamic_threshold.py`) ✅
**职责**：基于队员2的基线数据动态计算检测阈值
**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| 动态阈值计算 | 阈值 = 均值 + multiplier × 标准差 | ✅ |
| FPR自动推荐 | 根据目标误报率推荐multiplier值 | ✅ |
| 自动更新机制 | 定期从队员2获取最新基线数据（默认5分钟） | ✅ |
| 手动触发更新 | `trigger_manual_update()` 立即更新 | ✅ |
**配置参数**：
| 参数 | 默认值 | 说明 |
|------|--------|------|
| `update_interval_seconds` | 300 | 自动更新间隔（秒） |
| `auto_update_enabled` | True | 是否启用自动更新 |
| `multiplier` | 1.5 | 标准差倍数 |
| `min_threshold` | 0.0 | 阈值最小值 |
| `max_threshold` | 10.0 | 阈值最大值 |
---

### 2.5 告警管理模块 (`alert_manager.py`) ✅
**职责**：告警生成、级别判定、记录存储、回调分发
**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| 告警级别判定 | 已知攻击(CRITICAL) / 未知攻击(WARNING) | ✅ |
| 告警记录存储 | 支持时间范围查询 | ✅ |
| 回调机制 | 注册回调供可视化界面实时接收告警 | ✅ |
| 结构化输出 | 包含源/目的IP、端口、时间戳、置信度、KL距离 | ✅ |
---

### 2.6 导出模块 (`exporter.py`) ✅
**职责**：异常流量导出为PCAP文件，便于溯源分析
**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| PCAP导出 | `export_abnormal_flow()` 将异常流保存为PCAP | ✅ |
| 自定义目录 | 支持配置导出路径 | ✅ |
---

### 2.7 实时检测管道 (`pipeline.py`) ✅
**职责**：串联所有模块，提供统一的检测入口
**核心接口**：
| 接口 | 说明 |
|------|------|
| `process_captured_flow(flow)` | 处理FlowData对象 |
| `process_raw_packets(...)` | 处理原始数据包（队员1格式） |
| `get_alert_history(start, end)` | 获取告警历史 |
| `get_flow_history()` | 获取流历史 |
| `snapshot()` | 获取系统状态快照 |
| `register_alert_callback(cb)` | 注册告警回调 |
| `update_dynamic_threshold(data)` | 更新动态阈值 |
| `get_threshold_statistics()` | 获取阈值统计 |

**完整处理流程**：
```
输入(FlowData/原始包) → 添加到流管理器 → 检查重复 → 灰度图生成(若缺失)
       → 模型推理 → 异常判定 → 告警触发 → PCAP导出(若异常) → 返回结果
```
---

### 2.8 异步高性能管道 (`async_pipeline.py`) ✅
**职责**：大流量场景下的高性能并发处理
**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| 异步并发处理 | 使用ThreadPoolExecutor实现多线程并行 | ✅ |
| 批量处理模式 | 支持批量处理多条流，提高吞吐量 | ✅ |
| 性能统计 | 返回处理数、异常数、总耗时、平均耗时 | ✅ |
```python
# 异步处理单条流
flow = await async_pipeline.process_captured_flow_async(flow_data)
# 批量处理
result = await async_pipeline.process_batch_async(list_of_flows)
```
---

### 2.9 日志系统 (`logger.py`) ✅
**职责**：集中式日志管理，支持文件轮转和控制台输出
**核心功能**：
| 功能 | 说明 | 状态 |
|------|------|------|
| 多输出目标 | 同时输出到文件和控制台 | ✅ |
| 文件轮转 | 自动按大小分割日志文件 | ✅ |
| 结构化日志 | 支持JSON格式输出 | ✅ |
| 专用日志方法 | `log_alert()`、`log_flow_processed()` | ✅ |

**日志配置**：
| 参数 | 默认值 | 说明 |
|------|--------|------|
| `log_level` | INFO | 日志级别 |
| `log_dir` | ./logs | 日志目录 |
| `max_file_size_mb` | 50 | 单文件最大大小 |
| `backup_count` | 5 | 备份文件数 |
| `console_output` | True | 是否输出到控制台 |
---

## 三、模块对接说明

### 3.1 与队员1（数据采集模块）对接
**输入方式**：
```python
# 方式1：直接传入FlowData对象
flow = FlowData(...)
pipeline.process_captured_flow(flow)

# 方式2：传入原始数据包
pipeline.process_raw_packets(
    flow_id="flow-xxx",
    src_ip="192.168.1.1",
    dst_ip="10.0.0.1",
    src_port=12345,
    dst_port=443,
    protocol="TLS",
    timestamp=1234567890.0,
    packets_data=[b"...", b"..."]
)
```
**约定**：
- 每流保留前10个包用于预处理
- `packets_data` 格式为 `list[bytes]`
---

### 3.2 与队员2（模型推理模块）对接
**集成方式**：
```python
# 动态阈值数据源注册
def fetch_baseline():
    return teammate2_api.get_latest_baseline_kl_distances()

pipeline.threshold_manager.register_data_source_callback(fetch_baseline)

# 阈值将自动定期更新（默认5分钟）
```
**数据交互**：
- 输入：正常流量的KL距离列表
- 输出：动态计算的检测阈值
---

### 3.3 与队员4（可视化模块）对接
**数据消费接口**：
```python
# 获取流历史（流量监控看板）
flows = pipeline.get_flow_history()
# 获取告警历史（威胁告警中心）
alerts = pipeline.get_alert_history(start_time, end_time)
# 实时告警回调（弹窗告警）
def on_alert(alert):
    # 更新可视化界面
    print(f"[告警] {alert.alert_level}: {alert.src_ip} -> {alert.dst_ip}")
pipeline.register_alert_callback(on_alert)
# 获取系统状态快照（性能指标面板）
snapshot = pipeline.snapshot()
# {
#     "flows": [...],
#     "alerts": [...],
#     "flow_count": 100,
#     "alert_count": 5,
#     "threshold_statistics": {...}
# }
```
---

## 四、目录职责汇总
| 文件 | 职责 | 状态 |
|------|------|------|
| `flow_manager.py` | 流数据结构、去重、过期清理、状态管理 | ✅ |
| `preprocess.py` | 灰度图构建、流ID生成、Mock数据 | ✅ |
| `model_adapter.py` | 队员2推理接口适配、标准化输出 | ✅ |
| `dynamic_threshold.py` | 动态阈值计算、自动更新 | ✅ |
| `alert_manager.py` | 告警记录、级别判定、回调分发 | ✅ |
| `exporter.py` | 异常流PCAP导出 | ✅ |
| `pipeline.py` | 同步检测管道、模块串联 | ✅ |
| `async_pipeline.py` | 异步高性能管道、批量处理 | ✅ |
| `logger.py` | 集中式日志管理 | ✅ |
---

## 五、快速开始
### 5.1 安装依赖
```bash
pip install -r requirements.txt
```
### 5.2 基础使用
```python
from realtime_detection.pipeline import DetectionPipeline

# 初始化管道
pipeline = DetectionPipeline(
    model_path="save_model/mixed_44_split_0.pt",
    threshold=5.0,
    expire_minutes=5,
    export_dir="./abnormal_flows",
    enable_export=True
)
# 注册告警回调
def alert_callback(alert):
    print(f"[告警] {alert.alert_level} - {alert.attack_type}")
pipeline.register_alert_callback(alert_callback)
# 处理流量
flow = pipeline.process_raw_packets(
    flow_id="flow-001",
    src_ip="192.168.1.10",
    dst_ip="172.16.0.8",
    src_port=52001,
    dst_port=443,
    protocol="TLS1.3",
    timestamp=1234567890.0,
    packets_data=[b"packet1", b"packet2"]
)

# 获取状态
snapshot = pipeline.snapshot()
print(f"流数: {snapshot['flow_count']}, 告警数: {snapshot['alert_count']}")
```

### 5.3 动态阈值配置

```python
# 注册数据源回调
def fetch_baseline():
    # 从队员2获取最新基线数据
    return [2.1, 1.8, 2.3, 1.9, 2.0, 2.2, 1.7, 2.1]

pipeline.threshold_manager.register_data_source_callback(fetch_baseline)

# 手动触发更新
new_threshold = pipeline.threshold_manager.trigger_manual_update()
print(f"新阈值: {new_threshold}")

# 获取阈值统计
stats = pipeline.get_threshold_statistics()
print(f"均值: {stats['mean']}, 标准差: {stats['std']}")
```