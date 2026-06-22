# 混合训练计划：USTC + mal 数据集 44 类闭集分类

## 概述

将 mal（24类）和 USTC（20类）两个数据集的全部样本合并，统一重新分配全局标签（mal: 0-23, USTC: 24-43），按类别分层采样，以 8:1:1 比例划分为训练/验证/测试集，进行 44 类闭集分类训练。

## 当前状态分析

### 数据情况

| 数据集 | 类别数 | 原始标签 | Train 样本数 | Test 样本数 | 总计 |
|--------|--------|----------|-------------|------------|------|
| mal    | 24     | 0-23     | 80,945      | 34,691     | 115,636 |
| USTC   | 20     | 0-19     | 31,126      | 3,459      | 34,585 |
| **合计** | **44** | - | - | - | **~150,221** |

数据文件位置（均为 32x32 单通道灰度图）：

- `/root/Open-Detect-master/data/dataset/mal_32_1c_train.npz`
- `/root/Open-Detect-master/data/dataset/mal_32_1c_test.npz`
- `/root/Open-Detect-master/data/dataset/USTC_1c_train.npz`
- `/root/Open-Detect-master/data/dataset/USTC_1c_test.npz`

每个 `.npz` 包含 `data`（图像数组）和 `target`（标签数组）。

### 现有代码架构

- `data/dataset.py` — 定义了 `OPENWORLDmal`、`USTC`、`combined_USTC_mal` 三个 Dataset 类；`get_dataset()` 工厂函数按 `train=True/False` 返回对应数据集
- `data/splits.py` — 定义了三组数据集的 split 配置（mal / USTC / combined_USTC_mal），均为开集检测范式（known_classes + unknown_classes）
- `train.py` — 训练入口，通过 `get_splits()` 获取已知/未知类，通过 `get_dataset()` 构建 DataLoader，当前只有 train（训练）和 val（验证=原始test数据）两个集合
- `model.py` — 定义了 `OpenDetectNet` 模型、`train_model()` 和 `validate_model()` 函数

### 现有 combined_USTC_mal 的问题

- `splits.py` 中的 `combined_USTC_mal` 配置是开集范式（全部 mal 类为已知 / 全部 USTC 类为未知，或反之），不符合闭集分类需求
- `dataset.py` 中的 `combined_USTC_mal` 类尝试加载不存在的 `combined_train_data.npz` 和 `combined_test_data.npz` 文件

## 修改方案

### 1. 新建：`data/preprocess_mixed.py` — 数据预处理脚本

**目的**：生成混合数据集的三份 `.npz` 文件（train/val/test）

**逻辑**：
1. 加载 4 个原始 npz 文件
2. USTC 标签重新映射：原始 0-19 → 全局 24-43
3. mal 标签不变：0-23
4. 合并全部数据和标签
5. 对每个类别（0-43）独立做 `train_test_split`，按 8:1:1 分层采样
6. 全量打乱各集合内部顺序
7. 保存为：
   - `data/dataset/mixed_44_train.npz`（~120k 样本）
   - `data/dataset/mixed_44_val.npz`（~15k 样本）
   - `data/dataset/mixed_44_test.npz`（~15k 样本）

### 2. 修改：`data/dataset.py` — 新增 MIXED44 数据集类

**变更**：
- 新增 `MIXED44` 类，结构参照现有 `OPENWORLDmal` 类，根据 `mode` 参数加载不同的 npz 文件：
  - `mode='train'` → `mixed_44_train.npz`
  - `mode='val'` → `mixed_44_val.npz`
  - `mode='test'` → `mixed_44_test.npz`
- 修改 `get_dataset()` 函数，新增 `mode` 参数（兼容旧接口 `train` 参数），新增 `'mixed_44'` 分支

### 3. 修改：`data/splits.py` — 新增 mixed_44 配置

**变更**：
- 新增 `mixed_44` 字典配置：
  ```python
  mixed_44 = {
      'known_set': 'mixed_44',
      'unknown_set': None,  # 闭集分类，无未知类
      'splits': [
          {'known_classes': list(range(44)), 'unknown_classes': []},
      ]
  }
  ```
- 在 `datasets` 字典中注册 `'mixed_44': mixed_44`

### 4. 修改：`train.py` — 支持三路数据划分和闭集训练

**变更**：
- `datasets` 列表新增 `'mixed_44'`
- 修改数据加载逻辑：
  - `train_set = get_dataset(known_dataset, mode='train', ...)`
  - `val_set = get_dataset(known_dataset, mode='val', ...)`
  - `test_set = get_dataset(known_dataset, mode='test', ...)`（新增）
- 当 `unknown_classes` 为空时，跳过 `open_set` 和 `open_loader` 的创建
- 新增 `test_loader` 和训练结束后在测试集上的最终评估
- 模型保存路径适配

### 5. 修改：`model.py` — 支持三路评估（少量改动）

**变更**：
- 新增 `test_model()` 函数，结构与 `validate_model()` 相同，用于最终测试集评估

## 使用方式

```bash
# Step 1: 生成混合数据集（仅需执行一次）
python data/preprocess_mixed.py

# Step 2: 训练
python train.py --dset mixed_44 --split 0 --epoch 100 --batch_size 128 --lr 0.001 --num_classes 44 --gpu 0
```

## 验证步骤

1. 运行 `data/preprocess_mixed.py`，确认生成 3 个 `.npz` 文件
2. 打印各 npz 文件的 shape 和各标签样本数，确认 8:1:1 比例
3. 运行 `python train.py --dset mixed_44 --split 0 --epoch 5 --batch_size 128 --lr 0.001 --gpu 0` 进行小规模训练验证
4. 确认 DataLoader 正常加载、模型前向传播无错误、训练 loss 正常下降

## 假设与决策

- mal 标签映射为全局 0-23，USTC 标签映射为全局 24-43（与 `splits.py` 注释中描述一致）
- 每个类别单独做 8:1:1 分层划分，保证稀有类别在各集合中均有分布
- `unknown_set` 为 None 且 `unknown_classes` 为空时，训练流程跳过开集检测相关逻辑
- 保持现有模型架构不变（`OpenDetectNet`，`n_classes=44`）
- 图片尺寸 32x32 单通道，与现有一致
