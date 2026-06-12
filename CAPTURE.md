# capture.py 使用说明

本文档面向队友3，描述 `realtime_detection/capture.py` 做了什么、常用参数含义、它如何与 `realtime_detection` 实时检测链路联动，以及排查/调试建议。

## 概述
- 作用：使用 Scapy 实时抓包，按五元组（src_ip, dst_ip, src_port, dst_port, protocol）将报文聚成流，保留每条流的前若干包，转换为 32×32 灰度图，组装为 `FlowData` 并（默认）交给 `DetectionPipeline.process_captured_flow()` 做推理、告警与导出。
- 位置：`realtime_detection/capture.py`

## 工作流程（简要）
1. 启动并解析命令行参数（接口选择、时长、包数上限等）。
2. 自动或手动解析监听接口（支持 NPF GUID、适配器名或本机 IP；可使用 `--auto-iface`）。
3. 用 `AsyncSniffer` 持续捕获满足 BPF 的报文（默认 `ip and (tcp or udp)`）。
4. 按五元组聚合流，每条流保留前 `--max-packets-per-flow` 包。
5. 当达成“包数上限”或“闲置超时”时，构造 `FlowData`（含 `gray_img`）并交由 `DetectionPipeline` 处理（除非指定 `--no-pipeline`）。
6. `DetectionPipeline` 会执行推理、标记 `is_abnormal`、触发告警回调并按需导出异常流为 pcap。

## `FlowData` 关键字段
- `flow_id`：由 `build_flow_id()` 生成（五元组+时间戳）。
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `timestamp`。
- `packets_data`：`list[bytes]`，按捕获顺序保留（受 `--max-packets-per-flow` 限制）。
- `gray_img`：`numpy.ndarray`（32×32 uint8），用于模型输入。
- `inference_result`, `is_abnormal`, `export_path`, `metadata`：推理与导出相关。

## 常用命令行参数说明
- `--auto-iface`：自动选择主出站接口（首选主出站 IPv4 所在接口，未匹配再按无线关键词匹配）。
- `--iface IFACE`：手动指定接口，接受：NPF GUID（例如 `\\Device\\NPF_{...}`），适配器名（例如 `WLAN`），或本机 IP（例如 `10.196.87.10`）。PowerShell 中传 GUID 请使用单斜杠并加引号。示例：
  ```powershell
  python realtime_detection\\capture.py --iface '\\Device\\NPF_{141D5C60-...}' --duration 60 --debug
  ```
- `--duration SECONDS`：总运行秒数（到时自动退出）。
- `--count PACKETS`：全局捕获包数上限（到达后退出）。
- `--max-packets-per-flow N`：每流保留包数（默认 10）。
- `--flow-idle-timeout SECONDS`：流闲置多长时间视为结束并触发处理（默认 1.0 秒）。
- `--filter BPF`：BPF 过滤器（默认 `ip and (tcp or udp)`）。
- `--no-pipeline`：只构建并打印 `FlowData`，不调用 `DetectionPipeline`（用于调试 / 数据采集）。
- `--list-ifaces`：列出 Scapy 可见的 NPF 接口并退出。
- `--debug`：打印诊断和抓包/流构建的详细信息。

示例（自动选接口并实时检测 60 秒）：
```powershell
python realtime_detection\\capture.py --auto-iface --duration 60 --max-packets-per-flow 10 --flow-idle-timeout 1.0 --debug
```

## 与 `realtime_detection` 的联动
- 在脚本中，默认会构造 `DetectionPipeline()` 并在每次流 flush 时调用 `DetectionPipeline.process_captured_flow(flow)`。
- `process_captured_flow` 会：
  - 使用 `build_gray_image()`（若 `gray_img` 为空）生成 32×32 输入；
  - 调用推理适配器（`model_adapter.OpenDetectInferenceAdapter`）得到 `inference_result`；
  - 标注 `is_abnormal`、触发 `AlertManager`；
  - 在异常时通过 `exporter.export_abnormal_flow()` 导出 PCAP 到 `./abnormal_flows`（可配置）。

## 调试与排查建议
- 启动前：确保以管理员权限运行并已安装 Npcap（选 WinPcap 兼容模式）。
- 若抓不到包：运行 `python realtime_detection\\capture.py --list-ifaces`，用 `ipconfig /all` 对照接口与 IP。推荐使用 `--auto-iface` 或传入本机 IP。 
- 若脚本“看起来无反应”：添加 `--duration` 或 `--debug`，并在另一终端制造流量（`ping`、`curl`、浏览网页）。
- 若出现 Scapy/libpcap 内部错误（如 `<' not supported between instances of 'int' and 'NoneType'`），脚本已实现短轮询 + 自动重试与 `AsyncSniffer`，会尽量重连和继续捕获。你也可尝试升级 Npcap/Scapy 以减少兼容性问题。

## 如何验证（快速验收）
1. 启动实时检测：
   ```powershell
   python realtime_detection\\capture.py --auto-iface --duration 60 --max-packets-per-flow 10 --flow-idle-timeout 1.0 --debug
   ```
2. 在另一终端或设备产生流量（`ping 8.8.8.8`、`curl https://example.com` 等）。
3. 检查抓包终端是否出现：`[PACKET]`、`[FLOW]`、`[RESULT]` 日志；若为异常，检查 `./abnormal_flows` 是否有导出文件。 

## 采集 200 条正常流量供队员2建基线（建议流程）
- 选项 A（简单）：长期运行 `capture.py`，在业务流量下运行直到收集到足够数量（可用 `--duration` 或 `--count` 控制）。
- 选项 B（可控）：我可以为脚本添加 `--flows N`（按流计数退出）与 `--save-json DIR`（把每条 `FlowData` 序列化到指定目录）。如果需要我可以实现并演示命令。

## 常见命令举例
- 自动选接口并运行 10 分钟：
```powershell
python realtime_detection\\capture.py --auto-iface --duration 600 --max-packets-per-flow 10 --flow-idle-timeout 1.0 --debug
```
- 指定接口并仅构建 FlowData：
```powershell
python realtime_detection\\capture.py --iface WLAN --no-pipeline --duration 300 --debug
```

---

