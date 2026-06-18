#!/usr/bin/env python3
"""
OpenDetect 推理接口
支持 44 类已知流量分类 + 未知攻击检测（基于原型距离阈值）

用法:
    # Python SDK
    from predict import load_model, predict
    model = load_model("save_model/mixed_44_split_0.pt")
    result = predict(model, "sample.png", top_k=5, threshold=5.0)

    # CLI
    python predict.py --model save_model/mixed_44_split_0.pt --input sample.png --top_k 3

输入: np.ndarray (32,32) uint8 / PIL.Image (L mode) / 图片文件路径
输出: list[dict] 每个 dict 含 class, label, confidence, origin, is_unknown
"""

import argparse
import os
import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image
import torchvision.transforms as transforms

from model import OpenDetectNet

# ============================================================
# 类别映射 (44 类)
# ============================================================
CLASS_NAMES = {
    0:  "Vawtrak.C",
    1:  "Upatre",
    2:  "TrickBotCC",
    3:  "Totbrick",
    4:  "Tor",
    5:  "Tiggre",
    6:  "Shifu.A",
    7:  "Qakbot",
    8:  "PandaZeuSCC",
    9:  "Panda.BZA!tr",
    10: "nessus",
    11: "golistmero",
    12: "Dynamer!ac",
    13: "Drixed",
    14: "DridexCC",
    15: "CobaltStrike",
    16: "Caphaw.A",
    17: "Caphaw.AH",
    18: "burpsuite",
    19: "BuerLoader",
    20: "Banker",
    21: "awvs-v12",
    22: "awvs-v11",
    23: "arachni",
    24: "Gmail",
    25: "FTP",
    26: "Nsis-ay",
    27: "Facetime",
    28: "Weibo",
    29: "Cridex",
    30: "Zeus",
    31: "SMB",
    32: "BitTorrent",
    33: "WorldOfWarcraft",
    34: "Shifu",
    35: "Outlook",
    36: "Virut",
    37: "Geodo",
    38: "MySQL",
    39: "Htbot",
    40: "Tinba",
    41: "Skype",
    42: "Miuref",
    43: "Neris",
}

# 类别来源
CLASS_ORIGIN = {}
for k in range(24):
    CLASS_ORIGIN[CLASS_NAMES[k]] = "mal"
for k in range(24, 44):
    CLASS_ORIGIN[CLASS_NAMES[k]] = "USTC"

UNKNOWN_LABEL = -1
UNKNOWN_NAME = "Unknown Attack"

# ============================================================
# 预处理
# ============================================================
INFERENCE_TRANSFORM = transforms.Compose([
    transforms.Resize((32, 32)),
    transforms.ToTensor(),
])


def preprocess(input_data, device="cpu"):
    """
    将输入转换为模型所需的 tensor.

    Args:
        input_data: np.ndarray(32,32) / PIL.Image / str(文件路径)
        device: "cpu" | "cuda"

    Returns:
        torch.Tensor shape (1, 1, 32, 32) float32 [0, 1]
    """
    if isinstance(input_data, str):
        img = Image.open(input_data).convert("L")
    elif isinstance(input_data, np.ndarray):
        img = Image.fromarray(input_data.astype("uint8")).convert("L")
    elif isinstance(input_data, Image.Image):
        img = input_data.convert("L")
    else:
        raise TypeError(f"不支持输入类型: {type(input_data)}")

    tensor = INFERENCE_TRANSFORM(img).unsqueeze(0).to(device)
    return tensor


# ============================================================
# 模型加载
# ============================================================
def load_model(model_path, device=None):
    """
    加载 trained .pt 模型.

    Args:
        model_path: str, 模型文件路径
        device: "cpu" | "cuda" | None(自动)

    Returns:
        OpenDetectNet in eval mode
    """
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"

    model = torch.load(model_path, map_location=device, weights_only=False)
    model.eval()
    model.to(device)
    print(f"模型已加载: {model_path}")
    print(f"  设备: {device}")
    print(f"  类别数: {model.n_classes}")
    return model


# ============================================================
# 核心推理
# ============================================================

def _distance_to_confidence(euclidean_dist: float, threshold: float) -> float:
    """将欧氏距离映射为直观的置信度分数 (0~1)。

    公式: confidence = max(0, 1 - (distance / threshold)²)

           距离=0.0 → 100%  (与已知原型完全重合)
           距离=1.1 →  75%  (很近,高置信度)
           距离=1.6 →  50%  (明确匹配)
           距离=1.8 →  36%  (典型正常流量)
           距离=2.0 →  20%  (边缘)
           距离≥阈值  →   0%  (用 is_unknown 标识)
    """
    if threshold <= 0:
        return 0.0
    ratio = euclidean_dist / threshold
    return max(0.0, round(1.0 - ratio * ratio, 4))


def predict(model, input_data, top_k=5, threshold=5.0, temperature=1.0,
            class_thresholds=None, recon_threshold=0.15, bg_ratio=0.7):
    """
    对输入样本进行推理.

    Args:
        model: OpenDetectNet
        input_data: np.ndarray(32,32) / PIL.Image / str路径
        top_k: 返回前 K 个最可能的类别
        threshold: 未知攻击距离阈值（欧氏距离, 默认2.24）
        temperature: 已废弃（保留签名兼容, 不再参与计算）
        class_thresholds: dict[int, float], 类特定阈值
        recon_threshold: float, 重构MSE阈值
        bg_ratio: float, 背景原型比率

    Returns:
        list[dict]: [
            {"class": str, "label": int, "confidence": float, "origin": str,
             "is_unknown": bool, "distance": float,
             "recon_error": float, "bg_distance": float,
             "commit_ratio": float, "recon_suspicious": bool},
            ...
        ]
    """
    device = next(model.parameters()).device
    tensor = preprocess(input_data, device=device)

    with torch.no_grad():
        latent_z, dist, kl_div, recon_x = model(tensor)

    # dist shape: (1, n_classes)
    dist = dist.squeeze(0)          # (44,)
    min_dist = dist.min().item()
    min_label = dist.argmin().item()
    # 欧氏距离（用于展示、阈值比较）
    euclidean_dist = torch.sqrt(dist)
    min_euclidean = euclidean_dist.min().item()

    # 计算重构误差
    recon_error = float(F.mse_loss(recon_x, tensor).item())

    # 未知攻击检测: 使用欧氏距离（sqrt后的距离）与阈值比较
    # threshold 在 config.yaml 中定义为欧氏距离阈值（默认 2.24）
    if min_euclidean > threshold:
        return [{
            "class": UNKNOWN_NAME,
            "label": UNKNOWN_LABEL,
            "confidence": round(_distance_to_confidence(min_euclidean, threshold), 4),
            "origin": "unknown",
            "is_unknown": True,
            "distance": round(min_euclidean, 4),
            "recon_error": round(recon_error, 6),
            "bg_distance": 0.0,
            "commit_ratio": 1.0,
            "recon_suspicious": recon_error > recon_threshold if recon_threshold > 0 else False,
        }]

    # 按欧氏距离升序排序，取 top_k
    sorted_idxs = torch.argsort(euclidean_dist)
    results = []
    for rank in range(min(top_k, len(sorted_idxs))):
        idx = sorted_idxs[rank].item()
        d = euclidean_dist[idx].item()
        class_name = CLASS_NAMES.get(idx, f"Class_{idx}")
        # 使用用该类特定的阈值（如果有），否则用全局阈值
        class_thr = class_thresholds.get(idx, threshold) if class_thresholds else threshold
        conf = _distance_to_confidence(d, class_thr)
        results.append({
            "class": class_name,
            "label": idx,
            "confidence": conf,
            "origin": CLASS_ORIGIN.get(class_name, "unknown"),
            "is_unknown": False,
            "distance": round(d, 4),
            "recon_error": round(recon_error, 6),
            "bg_distance": 0.0,
            "commit_ratio": 0.0,
            "recon_suspicious": recon_error > recon_threshold if recon_threshold > 0 else False,
        })

    return results


def predict_batch(model, images, top_k=5, threshold=5.0, temperature=4.0,
                  class_thresholds=None, recon_threshold=0.15, bg_ratio=0.7):
    """批处理推理接口。

    Args:
        model: OpenDetectNet
        images: list[np.ndarray], 灰度图像列表
        top_k: int
        threshold: float
        temperature: float
        class_thresholds: dict | None
        recon_threshold: float
        bg_ratio: float

    Returns:
        list[list[dict]]: 每个输入图像对应的 predict() 结果
    """
    return [
        predict(model, img, top_k=top_k, threshold=threshold, temperature=temperature,
                class_thresholds=class_thresholds, recon_threshold=recon_threshold,
                bg_ratio=bg_ratio)
        for img in images
    ]


# ============================================================
# CLI
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="OpenDetect 44类流量分类推理")
    parser.add_argument("--model", type=str, default="save_model/mixed_44_split_0.pt",
                        help="模型权重路径")
    parser.add_argument("--input", type=str, required=True,
                        help="输入图片路径 (.png/.jpg) 或 .npz 批量文件")
    parser.add_argument("--top_k", type=int, default=5,
                        help="返回 Top-K 预测结果")
    parser.add_argument("--threshold", type=float, default=5.0,
                        help="未知攻击距离阈值 (默认5.0)")
    parser.add_argument("--temperature", type=float, default=4.0,
                        help="softmax 温度参数 (默认4.0)")
    parser.add_argument("--device", type=str, default=None,
                        help="设备: cpu | cuda")
    args = parser.parse_args()

    model = load_model(args.model, device=args.device)

    # 判断是否为批量 npz 文件
    if args.input.endswith(".npz"):
        data = np.load(args.input)
        if "data" in data and "target" in data:
            images = data["data"]
            targets = data.get("target", None)
        else:
            # 尝试第一个数组键
            key = list(data.keys())[0]
            images = data[key]
            targets = None

        print(f"\n批量预测: {len(images)} 样本")
        correct = 0
        unknown_count = 0
        for i in range(len(images)):
            result = predict(model, images[i], top_k=args.top_k,
                             threshold=args.threshold, temperature=args.temperature)
            top1 = result[0]
            if top1["is_unknown"]:
                unknown_count += 1
                tag = "[UNKNOWN]"
            else:
                tag = ""
            label_str = f"(label={top1['label']})" if not top1["is_unknown"] else ""
            print(f"  [{i:5d}] {tag} {top1['class']} {label_str} conf={top1['confidence']:.4f} dist={top1['distance']:.3f}")

            if targets is not None and not top1["is_unknown"]:
                if top1["label"] == int(targets[i]):
                    correct += 1

        if targets is not None:
            print(f"\n闭集准确率: {correct}/{len(images)} = {100*correct/len(images):.2f}%")
        print(f"未知攻击告警: {unknown_count}/{len(images)}")
    else:
        result = predict(model, args.input, top_k=args.top_k,
                         threshold=args.threshold, temperature=args.temperature)
        print(f"\n预测结果 (threshold={args.threshold}):")
        print("-" * 60)
        for i, r in enumerate(result):
            tag = "[UNKNOWN ATTACK]" if r["is_unknown"] else f"Top-{i+1}"
            origin = f"({r['origin']})" if not r["is_unknown"] else ""
            print(f"  {tag:20s} {r['class']:25s} {origin:10s} conf={r['confidence']:.4f} dist={r['distance']:.3f}")


if __name__ == "__main__":
    main()
