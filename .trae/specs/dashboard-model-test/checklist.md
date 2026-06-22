# Checklist

## Task 1: 三种触发模式 API 实现
- [ ] `AttackExecutor` 类已从 `_run_attack_in_thread` 抽离，支持单步/批量/链式调度
- [ ] `/api/test/batch` 端点正确返回 44 类逐一执行结果和汇总统计
- [ ] `/api/test/chain` 端点正确按 5 阶段执行攻击链并返回每阶段结果
- [ ] 前端新增「批量跑」和「攻击链」按钮，点击后正常触发
- [ ] 攻击链前端展示五阶段时间线，每个阶段显示检测结果

## Task 2: 对比模式（模型 vs 规则）
- [ ] `/api/test/compare` 端点正确返回 `model_result` 和 `rule_result`
- [ ] `alert_manager.py` 告警记录包含 `detection_source` 字段
- [ ] 告警表格新增「检测来源」列，正确显示 model/rule/both
- [ ] 对比面板双列并排展示模型 vs 规则结果
- [ ] 对比汇总统计正确（model-only/rule-only/both 数量）

## Task 3: 参数调节面板
- [ ] `/api/test/params` GET 正确返回当前参数值
- [ ] `/api/test/params` PUT 正确更新 Pipeline 参数
- [ ] `/api/test/params/stats` 正确返回当前参数下的检测统计
- [ ] 前端三个滑动条渲染正常，拖动时实时更新参数
- [ ] 参数调整后流量检测结果随之变化（如降低 threshold 后更多流量被判 unknown）

## Task 4: 训练集 payload 生成器
- [ ] `payload_generator.py` 成功加载 `mixed_44_train.npz` 并提取每类统计特征
- [ ] `payloads/class_{N}_stats.json` 文件按类生成
- [ ] 合成 payload 灰度图与训练集同类余弦相似度 ≥ 0.7
- [ ] 44 类 payload 模板文件全部生成
- [ ] `get_payload_for_class()` / `get_malware_payloads()` / `get_normal_payloads()` 接口正常

## Task 5: 8 种未知攻击 payload 生成
- [ ] `unknown_attacks/` 目录下 8 个脚本全部可运行
- [ ] SSH 暴力破解 payload 含 SSH 协议特征
- [ ] DNS 隧道 payload 含 base64 长域名
- [ ] Heartbleed payload 含异常 TLS heartbeat
- [ ] ICMP 隧道 payload 含 ICMP 封装
- [ ] EternalBlue payload 含 SMBv1 协议序列
- [ ] Slowloris payload 含慢速 HTTP
- [ ] DGA payload 含随机域名
- [ ] Stratum 挖矿 payload 含 JSON-RPC

## Task 6: 集成测试与验证
- [ ] 三种触发模式前端 UI 完整渲染
- [ ] 对比模式开关可用，切换后表格增加检测来源列
- [ ] 参数面板渲染正常，滑动条可拖动
- [ ] 未知攻击 8 个按钮或下拉选择器可用
- [ ] `pytest tests/test_detection.py` 新增用例全部通过
- [ ] `tests/dashboard/README.md` 包含完整手动测试流程
- [ ] 仪表盘整体功能正常（不破坏现有功能）
