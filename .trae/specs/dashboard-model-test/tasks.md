# Tasks

## Task 1: 三种触发模式 API 实现
在仪表盘后端 `app.py` 新增逐一触发、批量跑、攻击链三种模式的 API 端点。

- [ ] SubTask 1.1: 重构 `app.py` 攻击路由，提取通用攻击执行器
  - 抽离 `_run_attack_in_thread` 为 `AttackExecutor` 类，支持单步/批量/链式调度
  - 添加攻击队列管理，支持按顺序排队执行
- [ ] SubTask 1.2: 新增 `/api/test/batch` 批量跑端点
  - 依次执行：已知恶意（27类）+ 正常流量（11类）+ 安全工具（6类）各 1 样本
  - 返回实时进度（已执行 N/44）
  - 完成后返回汇总结果（每类分类正确率、误报数、漏报数、平均置信度）
- [ ] SubTask 1.3: 新增 `/api/test/chain` 攻击链端点
  - 按杀伤链 5 阶段依次执行
  - 每阶段执行完毕后报告阶段结果
  - 响应体包含：阶段名称、检测类型（model/rule/both）、是否检出、告警级别
- [ ] SubTask 1.4: 修改前端按钮组，区分三种模式
  - 当前 `ctrl-buttons` 保留为逐一触发
  - 新增「批量跑」和「攻击链」按钮
  - 攻击链展示阶段时间线

## Task 2: 对比模式（模型 vs 规则）
新增对比面板，展示同一流量在模型和规则引擎下的检测差异。

- [ ] SubTask 2.1: 后端新增 `/api/test/compare` 端点
  - 接收流量数据，分别走模型推理和流关联规则
  - 返回 `{flow_id, model_result, rule_result, source}` JSON
- [ ] SubTask 2.2: 修改 `alert_manager.py` 告警记录增加 `detection_source` 字段
  - 模型检测：`detection_source = "model"`
  - 规则检测：`detection_source = "rule"`
  - 两者都有：`detection_source = "both"`
- [ ] SubTask 2.3: 前端新增对比面板 UI
  - 告警表格新增「检测来源」列
  - 展示 model / rule / both 标签
  - 对比模式下，双列并排展示模型结果 vs 规则结果
- [ ] SubTask 2.4: 对比汇总统计
  - 统计 model-only 检出数、rule-only 检出数、both 检出数
  - 展示模型覆盖率 vs 规则覆盖率

## Task 3: 参数调节面板
前端新增阈值滑动条，支持实时调整模型参数。

- [ ] SubTask 3.1: 后端新增 `/api/test/params` GET/PUT 端点
  - GET：返回当前 `threshold`, `recon_threshold`, `bg_ratio` 值
  - PUT：接收新参数值并更新 `DetectionPipeline` 的 `InferenceConfig`
- [ ] SubTask 3.2: 后端新增 `/api/test/params/stats` 端点
  - 返回当前参数下的检测统计（已知类准确率、未知检出率、总 is_unknown 比例）
- [ ] SubTask 3.3: 前端新增参数调节面板 UI
  - 三个滑动条：threshold (0.5~5.0)、recon_threshold (0.05~0.50)、bg_ratio (0.3~0.9)
  - 显示当前值、默认值标记点
  - 拖动时实时调用 PUT 更新参数
  - 显示当前参数下的实时统计

## Task 4: 训练集 payload 生成器
从训练集 `.npz` 数据中提取统计特征，生成仿真的网络流量 payload。

- [ ] SubTask 4.1: 创建 `tests/attack_simulator/payloads/payload_generator.py`
  - 加载 `mixed_44_train.npz`，提取每类的统计特征（字节熵、包长均值、包长方差、字节直方图）
  - 保存特征文件 `payloads/class_{N}_stats.json`
- [ ] SubTask 4.2: 实现 payload 合成算法
  - 根据统计特征生成近似分布的随机 bytes payload
  - 确保生成的灰度图与训练集同类别的余弦相似度 > 0.7
- [ ] SubTask 4.3: 为每类生成 payload 模板
  - 已知恶意（27类）、正常流量（11类）、安全工具（6类）
  - 每类生成 1~3 个代表性 payload
  - 保存为 `payloads/class_{N}_{name}.json`
- [ ] SubTask 4.4: 添加 payload 模板读取接口
  - `get_payload_for_class(class_id: int)` 返回对应 payload
  - `get_malware_payloads()` 返回所有恶意类 payload
  - `get_normal_payloads()` 返回所有正常类 payload

## Task 5: 8 种未知攻击 payload 生成
创建 8 种不在训练集 44 类中的未知攻击 payload 生成脚本。

- [ ] SubTask 5.1: 创建 `tests/attack_simulator/unknown_attacks/__init__.py` 和生成器基类
- [ ] SubTask 5.2: 实现 SSH 暴力破解 payload（ssh_bruteforce.py）
  - 生成 SSH 协议握手 + 多次认证尝试的 bytes payload
- [ ] SubTask 5.3: 实现 DNS 隧道 payload（dns_tunnel.py）
  - 生成含 base64 编码数据的长域名 DNS 查询 payload
- [ ] SubTask 5.4: 实现 Heartbleed payload（heartbleed.py）
  - 生成 TLS heartbeat 请求含异常 payload_length 的 bytes
- [ ] SubTask 5.5: 实现 ICMP 隧道 payload（icmp_tunnel.py）
  - 生成大型 ICMP echo 包携带隧道化 TCP 数据
- [ ] SubTask 5.6: 实现 EternalBlue payload（eternal_blue.py）
  - 生成 SMBv1 协议 Negotiate + SessionSetup + TreeConnect 序列
- [ ] SubTask 5.7: 实现 Slowloris payload（slowloris.py）
  - 生成极慢速 HTTP 请求头（分片发送）
- [ ] SubTask 5.8: 实现 DGA payload（dga_domains.py）
  - 生成大量随机域名 DNS 查询记录
- [ ] SubTask 5.9: 实现 Stratum 挖矿 payload（stratum_mining.py）
  - 生成 Stratum 协议 JSON-RPC 通信（mining.subscribe/mining.authorize）

## Task 6: 集成测试与验证
将所有组件集成到仪表盘并编写测试验证。

- [ ] SubTask 6.1: 集成三种触发模式到仪表盘前端
  - 逐一触发：现有按钮保留，增加 payload 类型选择器
  - 批量跑：新按钮 + 进度条 + 结果汇总表
  - 攻击链：新按钮 + 五阶段时间线组件
- [ ] SubTask 6.2: 集成对比模式到仪表盘前端
- [ ] SubTask 6.3: 集成参数面板到仪表盘前端
- [ ] SubTask 6.4: 集成未知攻击按钮到仪表盘（8 个新按钮或下拉选择器）
- [ ] SubTask 6.5: 编写 pytest 测试用例
  - `test_batch_run_completes`：批量跑完成后验证汇总统计正确
  - `test_attack_chain_stages`：攻击链 5 阶段全部执行
  - `test_compare_mode_model_only`：已知恶意仅模型检出
  - `test_compare_mode_rule_only`：端口扫描仅规则检出
  - `test_threshold_slider_updates`：滑动阈值后参数生效
  - `test_all_8_unknown_detected`：8 种未知攻击均被检出
- [ ] SubTask 6.6: 端到端手动测试流程文档（`tests/dashboard/README.md`）

# Task Dependencies
- Task 4 依赖：无，可独立开始
- Task 5 依赖：无，可独立开始
- Task 1 依赖：无，可独立开始
- Task 2 依赖：Task 1（需要攻击执行器的基础设施）
- Task 3 依赖：Task 1（需要 Pipeline 可动态配置）
- Task 6 依赖：Task 1, 2, 3, 4, 5（全部组件就绪后集成）
