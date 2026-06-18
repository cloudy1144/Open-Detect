# 模型推理接口封装与 GitHub 上传计划

## 概述

将训练好的 `mixed_44_split_0.pt`（44类，104MB）封装为可直接调用的 Python 推理接口。支持 44 类已知流量分类 + 未知攻击检测（基于原型距离阈值）。使用 Git LFS 托管大文件，完整推送至 GitHub。

## 当前状态分析

### 模型信息

* 模型文件：`save_model/mixed_44_split_0.pt`，大小 104MB

* 架构：`OpenDetectNet(resnet18, channel=1, latent_dim=128, n_classes=44)`

* 精度：Test Accuracy 99.30%, Test F1 99.29%

### 模型输入/输出

| 方向 | 格式                                             | 说明                       |
| -- | ---------------------------------------------- | ------------------------ |
| 输入 | `torch.Tensor` `(B, 1, 32, 32)` float32 \[0,1] | 32×32 单通道灰度图             |
| 输出 | `dist` `(B, 44)`                               | 到 44 个原型的平方欧氏距离，越小越可能是该类 |

### 未知攻击检测原理

模型输出到各原型的距离 `dist`。已知类样本距离小，未知攻击样本到所有原型距离都大。通过设定距离阈值 `threshold` 判断：

* `min_dist <= threshold` → 归属最近已知类（类别名 + 置信度）

* `min_dist > threshold`  → **Unknown Attack**（未知攻击告警）

**阈值选取依据**（测试集 5000 样本距离统计）：

| 类型   | mean | median | P95  | P99  | P99.9 |
| ---- | ---- | ------ | ---- | ---- | ----- |
| 正确预测 | 1.26 | 0.86   | 3.52 | 6.03 | 11.09 |
| 错误预测 | 3.37 | 2.19   | -    | -    | -     |

* **默认阈值 5.0**（约 P98 分位），用户可配置

### 44 类标签

| 全局标签 | 来源   | 类别名             |
| ---- | ---- | --------------- |
| 0    | mal  | Vawtrak.C       |
| 1    | mal  | Upatre          |
| 2    | mal  | TrickBotCC      |
| 3    | mal  | Totbrick        |
| 4    | mal  | Tor             |
| 5    | mal  | Tiggre          |
| 6    | mal  | Shifu.A         |
| 7    | mal  | Qakbot          |
| 8    | mal  | PandaZeuSCC     |
| 9    | mal  | Panda.BZA!tr    |
| 10   | mal  | nessus          |
| 11   | mal  | golistmero      |
| 12   | mal  | Dynamer!ac      |
| 13   | mal  | Drixed          |
| 14   | mal  | DridexCC        |
| 15   | mal  | CobaltStrike    |
| 16   | mal  | Caphaw\.A       |
| 17   | mal  | Caphaw\.AH      |
| 18   | mal  | burpsuite       |
| 19   | mal  | BuerLoader      |
| 20   | mal  | Banker          |
| 21   | mal  | awvs-v12        |
| 22   | mal  | awvs-v11        |
| 23   | mal  | arachni         |
| 24   | USTC | Gmail           |
| 25   | USTC | FTP             |
| 26   | USTC | Nsis-ay         |
| 27   | USTC | Facetime        |
| 28   | USTC | Weibo           |
| 29   | USTC | Cridex          |
| 30   | USTC | Zeus            |
| 31   | USTC | SMB             |
| 32   | USTC | BitTorrent      |
| 33   | USTC | WorldOfWarcraft |
| 34   | USTC | Shifu           |
| 35   | USTC | Outlook         |
| 36   | USTC | Virut           |
| 37   | USTC | Geodo           |
| 38   | USTC | MySQL           |
| 39   | USTC | Htbot           |
| 40   | USTC | Tinba           |
| 41   | USTC | Skype           |
| 42   | USTC | Miuref          |
| 43   | USTC | Neris           |

## 修改方案

### 1. 新建：`predict.py` — 推理接口

结构：

```
predict.py
├── CLASS_NAMES          — 0-43 → 类别名映射
├── CLASS_ORIGIN         — 类别名 → "mal"/"USTC" 映射
├── UNKNOWN_LABEL = -1   — 未知攻击标签
├── load_model(path, device)
│   └── 加载 .pt 模型，返回 eval mode
├── preprocess(input)
│   └── np.ndarray(32,32) / PIL / str路径 → (1,1,32,32) tensor [0,1]
├── predict(model, input, top_k=5, threshold=5.0)
│   └── 核心函数，返回 list[dict]
└── main()
    └── CLI 入口
```

**`predict()`** **输出格式**：

已知类场景（min\_dist <= threshold）：

```python
[
    {"class": "CobaltStrike", "label": 15, "confidence": 0.9876, "origin": "mal", "is_unknown": false},
    {"class": "DridexCC",     "label": 14, "confidence": 0.0098, "origin": "mal", "is_unknown": false},
    ...
]
```

未知攻击场景（min\_dist > threshold）：

```python
[
    {"class": "Unknown Attack", "label": -1, "confidence": 1.0, "origin": "unknown", "is_unknown": true},
]
```

* `is_unknown`：布尔值标记是否为未知攻击

* `confidence`：基于 softmax(-dist / temperature) 归一化

* 未知攻击时 Top-1 即为 Unknown Attack，不返 Top-K

### 2. 新建：`requirements.txt`

```
torch>=1.10.0
torchvision>=0.11.0
numpy>=1.20.0
Pillow>=8.0.0
tqdm>=4.60.0
```

### 3. 新建：`.gitattributes` — Git LFS 配置

```
*.pt filter=lfs diff=lfs merge=lfs -text
*.pth filter=lfs diff=lfs merge=lfs -text
```

### 4. 新建：`.gitignore`

```
__pycache__/
*.pyc
*.npz
data/dataset/*.npz
train_*.log
```

### 5. 更新：`README.md`

包含：项目简介、环境要求、模型下载/加载、使用方法、输出示例。

## GitHub 上传清单

```
Open-Detect/
├── predict.py                  # 推理接口
├── model.py                    # 模型定义（推理依赖）
├── utils.py                    # 工具函数（推理依赖）
├── networks/
│   ├── __init__.py
│   └── resnet.py               # ResNet 编码器/解码器
├── save_model/
│   └── mixed_44_split_0.pt     # 模型权重 (Git LFS)
├── requirements.txt
├── .gitattributes              # Git LFS 追踪规则
├── .gitignore
└── README.md
```

## 使用方式

```python
# Python SDK 调用
from predict import load_model, predict

model = load_model("save_model/mixed_44_split_0.pt")
result = predict(model, "sample.png", top_k=5, threshold=5.0)

for r in result:
    tag = "[UNKNOWN]" if r["is_unknown"] else ""
    print(f"{tag} {r['class']}: {r['confidence']:.4f}")
```

```bash
# CLI 调用
python predict.py --model save_model/mixed_44_split_0.pt --input sample.png --top_k 3 --threshold 5.0

# 批量预测
python predict.py --model save_model/mixed_44_split_0.pt --input batch.npz
```

## 验证步骤

1. 用已知类测试样本验证 Top-1 准确率与训练日志一致（\~99%）
2. 用错误预测样本验证其距离 > 正确预测样本距离
3. 调整 `threshold` 参数到 2.0，验证部分已知类样本被标记为 Unknown（阈值过低）
4. 调整 `threshold` 参数到 10.0，验证全部已知类样本正确分类（阈值过高）
5. `git lfs track` 确认 .pt 文件被 LFS 追踪
6. GitHub 仓库确认模型权重文件带有 LFS 标记

## 假设与决策

* 原型距离阈值默认 5.0（≈P98 分位），用户可通过 `--threshold` 自行调节；阈值越低越敏感（更多流量被判为未知攻击）

* 模型权重 104MB，超过 GitHub 100MB 限制，必须用 Git LFS

* 置信度 = softmax(-dist / temperature)，temperature 默认 1.0

* 输入图像若非 32×32，自动 resize（保持灰度）

* 不包含 pcap 预处理（pcap→图片）逻辑在接口内部，保持接口简洁

