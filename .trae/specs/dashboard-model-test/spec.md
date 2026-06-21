# 仪表盘模型检测能力测试 Spec

## Why
当前仪表盘的攻击测试存在盲区：行为攻击（port_scan/syn_flood/beacon）完全绕过模型靠规则检测；PCAP 回放用的是本地合成的假数据，无法代表训练集真实分布。需要设计一套基于模型训练集的攻击测试方案，覆盖已知恶意、正常流量、未知攻击三类，并能对比模型分类 vs 规则引擎的检测差异。

## What Changes
- 新增训练集 PCAP 数据获取/生成方案：从训练集 `.npz` 灰度图逆向生成或获取公开 PCAP 数据集
- 新增仪表盘三种触发模式：逐一触发、批量跑、攻击链
- 新增 8 种不在训练集的未知攻击 PCAP（或合成 payload）：SSH 暴力破解、DNS 隧道、Heartbleed、ICMP 隧道、SMBv1 永恒之蓝、Slowloris HTTP、DGA 域名查询、加密挖矿协议
- 新增「对比模式」面板：同一流量分别走模型推理和规则引擎，并排展示两种检测结果差异
- 新增阈值滑动条：实时调整 `threshold`、`recon_threshold`、`bg_ratio` 参数并观察对检测结果的影响

## Impact
- Affected specs: 无现有 spec 冲突
- Affected code: 
  - 修改：`tests/dashboard/app.py`（新增 API 端点）、`tests/dashboard/templates/index.html`（新增 UI）
  - 修改：`tests/attack_simulator/replay.py`（新增未知攻击 PCAP 生成）
  - 新增：`tests/attack_simulator/payloads/`（训练集对应 payload 模板）
  - 新增：`tests/attack_simulator/unknown_attacks/`（8 种未知攻击脚本）

---

## ADDED Requirements

### Requirement: 训练集流量测试
系统 SHALL 支持使用与模型训练集相同分布的真实/仿真 PCAP 数据进行回放测试，覆盖 44 个训练类别中的恶意软件、正常流量和安全工具。

#### Scenario: 已知恶意软件回放
- **WHEN** 用户在仪表盘触发「已知恶意回放」
- **THEN** 系统 SHALL 回放与训练集中恶意软件类别（如 Zeus、CobaltStrike、TrickBot 等）对应的 PCAP 或合成 payload
- **THEN** 模型 SHALL 将其分类为对应类别，`attack_type=known_malware`，`alert_level=CRITICAL`

#### Scenario: 正常流量回放
- **WHEN** 用户在仪表盘触发「正常流量回放」
- **THEN** 系统 SHALL 回放与训练集中正常应用类别（如 Gmail、FTP、MySQL、SMB 等）对应的 PCAP 或合成 payload
- **THEN** 模型 SHALL 将其分类为对应正常类别，`attack_type=normal`，`alert_level=INFO`

#### Scenario: 安全工具回放
- **WHEN** 用户在仪表盘触发「安全工具回放」
- **THEN** 系统 SHALL 回放 Tor、nessus、burpsuite、awvs、arachni 等安全工具的流量
- **THEN** 模型 SHALL 将其分类为 `attack_type=suspicious_tool`，`alert_level=WARNING`

---

### Requirement: 未知攻击测试
系统 SHALL 支持 8 种不在训练集 44 类中的未知攻击回放，验证模型的开放集识别能力。

#### Scenario: SSH 暴力破解检测
- **WHEN** 回放 SSH 暴力破解流量（大量短时间内到 22 端口的连接，含不同密码尝试的协议 payload）
- **THEN** 模型 SHALL 触发开放集识别：`is_unknown=True`，`attack_type=unknown_attack`，`alert_level=WARNING`
- **THEN** 记录 `unknown_reason`，说明触发原因（距离/重构/背景比率）

#### Scenario: DNS 隧道检测
- **WHEN** 回放 DNS 隧道流量（大量超长域名查询，含 base64 编码数据的 TXT 记录）
- **THEN** 模型 SHALL 触发开放集识别，`attack_type=unknown_attack`，`alert_level=WARNING`

#### Scenario: Heartbleed TLS 异常
- **WHEN** 回放 Heartbleed 漏洞利用流量（TLS heartbeat 请求含超长 payload_length 字段）
- **THEN** 模型 SHALL 触发开放集识别，`attack_type=unknown_attack`，`alert_level=WARNING`

#### Scenario: ICMP 隧道检测
- **WHEN** 回放 ICMP 隧道流量（大型 ICMP echo 包携带 TCP 流量的隧道化数据）
- **THEN** 模型 SHALL 触发开放集识别，`attack_type=unknown_attack`，`alert_level=WARNING`

#### Scenario: SMBv1 永恒之蓝检测
- **WHEN** 回放 SMBv1 EternalBlue 漏洞利用流量
- **THEN** 模型 SHALL 触发开放集识别，`attack_type=unknown_attack`，`alert_level=WARNING`

#### Scenario: Slowloris HTTP 慢速攻击
- **WHEN** 回放 Slowloris 攻击流量（HTTP 请求极慢发送，保持大量半开连接）
- **THEN** 模型 SHALL 触发开放集识别，`attack_type=unknown_attack`，`alert_level=WARNING`

#### Scenario: DGA 域名频繁查询
- **WHEN** 回放 DGA 域名生成算法流量（大量随机生成域名的 DNS 查询）
- **THEN** 模型 SHALL 触发开放集识别，`attack_type=unknown_attack`，`alert_level=WARNING`

#### Scenario: 加密挖矿协议检测
- **WHEN** 回放 Stratum 加密挖矿协议流量（连接到矿池的 JSON-RPC 通信）
- **THEN** 模型 SHALL 触发开放集识别，`attack_type=unknown_attack`，`alert_level=WARNING`

---

### Requirement: 三种触发模式
仪表盘 SHALL 提供三种攻击触发模式，满足不同的测试场景。

#### Scenario: 逐一触发（单步测试）
- **WHEN** 用户点击任意单一攻击按钮（如「已知恶意回放」）
- **THEN** 系统 SHALL 执行该单一攻击
- **THEN** 执行完成后仪表盘 SHALL 展示：分类结果、置信度、距离、告警级别
- **THEN** 攻击进度面板 SHALL 显示该攻击的完成状态

#### Scenario: 批量跑（全量验证）
- **WHEN** 用户点击「批量跑」按钮
- **THEN** 系统 SHALL 依次执行所有测试项：已知恶意（27类）× 1 样本 + 正常流量（11类）× 1 样本 + 安全工具（6类）× 1 样本
- **THEN** 执行完成后仪表盘 SHALL 展示汇总表格：各类别分类正确率、误报率、漏报率
- **THEN** 支持导出 CSV 报告（含每个样本的详细信息）

#### Scenario: 攻击链（杀伤链模拟）
- **WHEN** 用户点击「攻击链」按钮
- **THEN** 系统 SHALL 按攻击杀伤链阶段依次执行：
  1. 侦察阶段：端口扫描（行为攻击）
  2. 武器化阶段：回放 CobaltStrike 植入（已知恶意）
  3. C2 通信阶段：C2 信标（行为攻击）
  4. 横向移动阶段：SMB 扫描 + EternalBlue 利用（未知攻击）
  5. 数据渗出阶段：DNS 隧道（未知攻击）
- **THEN** 仪表盘 SHALL 展示攻击链时间线视图，标注每个阶段的检测结果
- **THEN** 输出完整的攻击链报告中标注模型检测点 vs 规则检测点

---

### Requirement: 模型 vs 规则对比模式
仪表盘 SHALL 提供对比模式，展示同一流量在使用模型推理和规则引擎时的检测差异。

#### Scenario: 对比面板展示
- **WHEN** 用户点击「对比模式」开关
- **THEN** 仪表盘 SHALL 在告警表格中新增「检测来源」列（model / rule / both）
- **THEN** 每个告警行 SHALL 标注由谁检测到：模型分类、流关联规则、或两者皆有

#### Scenario: 已知恶意对比
- **WHEN** 回放 Zeus PCAP（训练集内恶意软件）
- **THEN** 模型 SHALL 检出（分类为 known_malware）
- **THEN** 规则引擎 SHALL 不检出（非行为模式）
- **THEN** 对比面板 SHALL 显示：模型 ✅ / 规则 ❌

#### Scenario: 端口扫描对比
- **WHEN** 执行端口扫描攻击
- **THEN** 规则引擎 SHALL 检出（scanning 关联告警）
- **THEN** 模型可能检出（若 payload 在训练集中有相似模式）或判定为 unknown
- **THEN** 对比面板 SHALL 显示双方检测结果及差异

#### Scenario: C2 信标对比
- **WHEN** 执行 C2 信标攻击
- **THEN** 规则引擎 SHALL 检出（beaconing 关联告警，基于周期性行为）
- **THEN** 模型 SHALL 基于 payload 分类（可能为 known_malware 或 unknown_attack）
- **THEN** 对比面板 SHALL 可视化对比：行为特征检测 vs 流量内容检测

---

### Requirement: 参数调节面板
仪表盘 SHALL 提供阈值参数实时调节功能，允许用户在测试过程中调整模型检测参数并立即观察结果变化。

#### Scenario: 阈值滑动条
- **WHEN** 用户拖动 `threshold` 滑动条（范围 0.5 ~ 5.0，默认 2.24）
- **THEN** 系统 SHALL 立即更新 DetectionPipeline 的阈值参数
- **THEN** 后续推理 SHALL 使用新阈值
- **THEN** 仪表盘 SHALL 显示当前阈值下已处理流量的 `is_unknown` 比例变化

#### Scenario: 其他参数调节
- **WHEN** 用户调整 `recon_threshold`（范围 0.05 ~ 0.50，默认 0.15）
- **WHEN** 用户调整 `bg_ratio`（范围 0.3 ~ 0.9，默认 0.7）
- **THEN** 参数 SHALL 实时生效
- **THEN** 仪表盘 SHALL 展示每个参数对应的检测统计

---

### Requirement: PCAP 数据来源
系统 SHALL 支持多种方式获取/生成用于测试的 PCAP 数据。

#### Scenario: 从公开数据集获取
- **WHEN** 首次启动测试环境
- **THEN** 系统 SHALL 检查本地是否存在 PCAP 目录
- **THEN** 若不存在，SHALL 提供下载指引（USTC-TFC2016、malicious TLS dataset、CIC-IDS 等公开数据集 URL）
- **THEN** 系统 SHALL 提供自动化下载脚本 `scripts/download_pcaps.sh`

#### Scenario: 合成 payload 生成（fallback）
- **WHEN** 公开数据集不可用
- **THEN** 系统 SHALL 使用 44 类训练集中每类的统计特征（字节分布、包长分布、协议特征等）生成仿真的 payload
- **THEN** 生成的 payload SHALL 与对应类别具有相似的灰度图特征
- **THEN** 每一类 SHALL 有对应的 payload 模板文件存储于 `tests/attack_simulator/payloads/`

#### Scenario: 未知攻击 payload 生成
- **WHEN** 执行未知攻击测试
- **THEN** 系统 SHALL 加载 `tests/attack_simulator/unknown_attacks/` 下预定义的 8 种未知攻击 payload 生成脚本
- **THEN** 每种未知攻击 SHALL 生成具有明显协议特征差异的 payload（确保与 44 类数据分布不同）
