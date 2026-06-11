# 实时检测模块说明

本目录是队员3负责的实时检测链路实现，重点是把“流量抓取/模拟输入 -> 预处理 -> 模型推理 -> 告警 -> 异常导出”串起来，方便后续接入队员1的抓包结果和队员2的模型推理接口。

## 当前实现方案

当前仓库采用的是 Open-Detect 的原型距离检测方案，不是 CNN + LSTM。核心流程是：

1. 将网络流量转换成 32 x 32 灰度图。
2. 调用 `predict.py` 中的 Open-Detect 推理逻辑。
3. 根据原型距离阈值判断是否为未知攻击。
4. 由实时检测模块统一管理流、生成告警、按需导出 PCAP。

## 目录职责

- `flow_manager.py`：流数据结构、去重、过期清理、处理状态管理。
- `preprocess.py`：灰度图构建、mock 流量数据生成、流 ID 构造。
- `model_adapter.py`：队员2推理接口适配层，统一输出告警所需字段。
- `alert_manager.py`：告警记录、级别判定、回调分发。
- `exporter.py`：异常流导出为 PCAP。
- `pipeline.py`：把上述模块串成完整链路。

## demo 文件做什么

根目录下的 `realtime_detection_demo.py` 是命令行联调入口，不是训练脚本，也不是正式服务端。

它的作用是：

- 生成一条 mock 流，模拟队员1还没接入时的输入。
- 调用 `DetectionPipeline.process_captured_flow()` 跑完整个链路。
- 打印推理结果、告警历史和快照信息。
- 在开启导出时，将异常流保存为 PCAP，便于溯源检查。

## 运行方式

```bash
python realtime_detection_demo.py --model save_model/mixed_44_split_0.pt --no-export
```

如果后续队员1已经能提供真实流数据，只需要把 `FlowData` 交给 `DetectionPipeline.process_captured_flow()`，下游逻辑不用改。

## 接入约定

- 队员1负责产出 `FlowData` 或等价结构。
- 队员2负责提供稳定的推理输入输出。
- 队员3负责实时链路、告警和导出。
- 队员4可以直接消费 `get_flow_history()` 和 `get_alert_history()`。