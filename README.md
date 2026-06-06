# Detection of Unknown Attacks Through Encrypted Traffic: A Gaussian Prototype-Aided Variational Autoencoder Framework
IEEE TIFS 2025 ([https://ieeexplore.ieee.org/document/11173980](https://ieeexplore.ieee.org/document/11173696))

---

### Abstract

The identification of encrypted network traffic presents a pivotal challenge in detecting unknown malicious traffic. Unlike closed-set identification, which primarily classifies known traffic classes, detecting unknown malicious traffic necessitates both accurate classification of known traffic and the identification of previously unseen traffic classes. Existing methods often face difficulties in effectively constraining the distribution size of known classes in the representation space and frequently misclassifying unknown classes as known. To address these challenges, we propose Open-Detect, a robust theoretical framework for detecting unknown malicious traffic, which leverages advanced deep learning techniques, such as variational autoencoders and Gaussian prototypes. Open-Detect introduces two primary constraints: a generative constraint, which enhances intra-class compactness, and a discriminative constraint, which optimizes inter-class separation. These constraints collectively mitigate the risks of misclassifying known classes and failing to detect unknown classes. In Open-Detect, network flows are transformed into grayscale images, and each known traffic class is mapped to a unique Gaussian prototype in the latent space. This design ensures tight clustering of samples within the same class and clear separation of samples between different classes. The detection of unknown malicious traffic is performed based on the distance between samples and these prototypes. Extensive experiments conducted on multiple publicly available datasets substantiate the efficacy of Open-Detect. The results reveal significant improvements in intra-class compactness and inter-class separation, enabling superior performance in both closed-world and open-world scenarios, particularly for detecting unknown malicious traffic. 

![Framework Overview](README.assets/image-20250522103530795.png)
*Overview of the Open-Detect framework for unknown network traffic detection.*

---

## Table of Contents

- [Features](#features)
- [Dataset](#dataset)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Model Details](#model-details)
- [Results & Scenarios](#results--scenarios)

---

## Features

- **Unknown Attack Detection:** Detects both known and unknown attacks using latent Gaussian prototypes.
- **Ready-to-Run Scripts:** Includes training and evaluation scripts.

---

## Dataset

The dataset used for experiments is located in `data/dataset`.  
It contains network traffic from **8 different scenarios**, simulating a range of attack and normal behaviors.

You can download the dataset from Baidu Cloud:

```
Open-Detect dataset:
Link: https://pan.baidu.com/s/1DYSDeyLgDhMVHO2BAsR0aQ?pwd=8b8z 
Extraction code: 8b8z
```

**Scenarios included:**

<img src="README.assets/image-20250522105230233.png" alt="Scenarios" style="zoom: 67%;" />

Each scenario contains labeled traffic data for both benign and attack samples. The dataset is organized for easy integration with provided scripts.

---

## Quickstart

### 1. Clone the repository

```bash
git clone https://github.com/niebikong/Open-Detect.git
cd Open-Detect
```

### 2. Install requirements

```bash
pip install -r requirements.txt
```

### 3. Download pre-trained model (44-class mixed model)

The pre-trained model `mixed_44_split_0.pt` is tracked via Git LFS. After cloning, pull LFS files:

```bash
git lfs pull
```

Or download directly from [Releases](https://github.com/niebikong/Open-Detect/releases).

### 4. Run inference

```bash
# Single image
python predict.py --input sample.png

# Batch prediction
python predict.py --input data/dataset/mixed_44_test.npz

# With custom threshold (lower = more aggressive unknown detection)
python predict.py --input sample.png --threshold 3.0
```

### 5. Download training dataset (optional)

Download and extract the dataset as described above. Place the files in `data/dataset`.

---

## Usage

### Training

To train the Open-Detect model on your dataset:

```python
python train.py
```

### Testing / Evaluation

To evaluate the model (including detection of unknown attacks):

```python
python test.py
```

---

---

## Inference API

### Pre-trained Model

| Model | Classes | Test Acc | Test F1 | Size |
|-------|---------|----------|---------|------|
| `mixed_44_split_0.pt` | 44 (mal 24 + USTC 20) | 99.30% | 99.29% | 104MB |

The model supports **44 known traffic classes** and **unknown attack detection** via distance thresholding.

### Python SDK

```python
from predict import load_model, predict

model = load_model("save_model/mixed_44_split_0.pt")
result = predict(model, "sample.png", top_k=5, threshold=5.0)

for r in result:
    tag = "[UNKNOWN]" if r["is_unknown"] else f"Top-{i+1}"
    print(f"{tag} {r['class']} conf={r['confidence']:.4f}")
```

### Input

| Type | Format |
|------|--------|
| `np.ndarray` | `(32, 32)` uint8 [0, 255] |
| `PIL.Image` | Grayscale (L mode) |
| `str` | Image file path (.png, .jpg) |
| `.npz` | Batch file with `data` array (CLI only) |

### Output

Each prediction returns a `list[dict]`:

```python
[
    {
        "class": "CobaltStrike",  # 类别名称
        "label": 15,               # 类别索引 (0-43), -1 = 未知
        "confidence": 0.9876,      # 置信度 [0, 1]
        "origin": "mal",           # 来源: "mal" | "USTC" | "unknown"
        "is_unknown": false,       # 是否判为未知攻击
        "distance": 1.863,         # 欧氏距离 (到最近原型)
    }
]
```

### Unknown Attack Detection

When `min_distance > threshold`, the sample is classified as **Unknown Attack**:

```python
[
    {
        "class": "Unknown Attack",
        "label": -1,
        "confidence": 1.0,
        "origin": "unknown",
        "is_unknown": true,
        "distance": 7.234,
    }
]
```

**Threshold tuning:**
- Lower threshold → more aggressive detection (more samples flagged as unknown)
- Higher threshold → more conservative (fewer false unknown alerts)
- Default `5.0` based on P98 percentile of known class distances
- Test set at threshold=5.0: 97.39% accuracy, 1.88% flagged as unknown

### 44 Class Labels

| Label | Source | Name | Label | Source | Name |
|-------|--------|------|-------|--------|------|
| 0 | mal | Vawtrak.C | 24 | USTC | Gmail |
| 1 | mal | Upatre | 25 | USTC | FTP |
| 2 | mal | TrickBotCC | 26 | USTC | Nsis-ay |
| 3 | mal | Totbrick | 27 | USTC | Facetime |
| 4 | mal | Tor | 28 | USTC | Weibo |
| 5 | mal | Tiggre | 29 | USTC | Cridex |
| 6 | mal | Shifu.A | 30 | USTC | Zeus |
| 7 | mal | Qakbot | 31 | USTC | SMB |
| 8 | mal | PandaZeuSCC | 32 | USTC | BitTorrent |
| 9 | mal | Panda.BZA!tr | 33 | USTC | WorldOfWarcraft |
| 10 | mal | nessus | 34 | USTC | Shifu |
| 11 | mal | golistmero | 35 | USTC | Outlook |
| 12 | mal | Dynamer!ac | 36 | USTC | Virut |
| 13 | mal | Drixed | 37 | USTC | Geodo |
| 14 | mal | DridexCC | 38 | USTC | MySQL |
| 15 | mal | CobaltStrike | 39 | USTC | Htbot |
| 16 | mal | Caphaw.A | 40 | USTC | Tinba |
| 17 | mal | Caphaw.AH | 41 | USTC | Skype |
| 18 | mal | burpsuite | 42 | USTC | Miuref |
| 19 | mal | BuerLoader | 43 | USTC | Neris |
| 20 | mal | Banker | | | |
| 21 | mal | awvs-v12 | | | |
| 22 | mal | awvs-v11 | | | |
| 23 | mal | arachni | | | |

---

## Project Structure

```
Open-Detect/
│
├── predict.py              # Inference API (Python SDK + CLI)
├── model.py                # OpenDetectNet model definition
├── train.py                # Training script
├── test.py                 # Evaluation script
├── utils.py                # Utilities
├── networks/               # ResNet encoder/decoder
│   ├── __init__.py
│   └── resnet.py
├── save_model/
│   └── mixed_44_split_0.pt # Pre-trained 44-class model (Git LFS)
├── data/
│   ├── dataset/            # .npz dataset files
│   ├── dataset.py          # Dataset classes
│   ├── splits.py           # Split configurations
│   └── Preprocessing/      # pcap to image pipeline
├── requirements.txt        # Python dependencies
├── .gitattributes          # Git LFS rules
├── .gitignore
└── README.md
```

---

## Setup & Installation

- **Python:** 3.10.13
- **PyTorch:** 2.1.1
- **NumPy:** 1.26.1
- **Pandas:** 2.1.3

Install dependencies (use a virtual environment for best results):

```python
pip install torch==2.1.1 numpy==1.26.1 pandas==2.1.3
```

---

## Model Details

The core model is a **Gaussian Prototype-Aided Variational Autoencoder (Open-Detect)**.  
Key characteristics:

- **Encoder/Decoder:** Learns compact representations of network traffic.
- **Gaussian Prototypes:** Each class (including unknown) is represented by a latent Gaussian, aiding unknown traffic recognition.
- **Novelty Detection:** Samples far from known prototypes are flagged as unknown.

For more technical details, see the code in `model.py`.

---

## Results & Scenarios

The framework is evaluated across 8 scenarios, including multiple attack types.  
Performance metrics, confusion matrices, and ROC curves can be generated using the test script.

---

## Citation

```
@article{meng2025detection,
  title={Detection of Unknown Attacks Through Encrypted Traffic: A Gaussian Prototype-Aided Variational Autoencoder Framework},
  author={Meng, Qianwei and Tao, Jing and Yuan, Qingjun and Li, Guangsong and Wang, Yongjuan and Gao, Bing and Lu, Siqi},
  journal={IEEE Transactions on Information Forensics and Security},
  year={2025},
  publisher={IEEE}
}
```

---

**For any questions, please open an issue or contact the authors.**
