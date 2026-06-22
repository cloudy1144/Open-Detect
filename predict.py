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
def predict(model, input_data, top_k=5, threshold=2.24, temperature=1.0,
            class_thresholds: dict[int, float] | None = None,
            recon_threshold: float = 0.15,
            bg_ratio: float = 0.7):
    """
    对输入样本进行推理.

    Args:
        model: OpenDetectNet
        input_data: np.ndarray(32,32) / PIL.Image / str路径
        top_k: 返回前 K 个最可能的类别
        threshold: 未知攻击欧氏距离阈值（默认 2.24 ≈ sqrt(5.0)，
                   与旧版「平方距离 5.0」等价）
        temperature: softmax 温度参数
        class_thresholds: 每类专属阈值，如 {31: 2.5, 15: 1.8}。
        recon_threshold: 重构 MSE 阈值（默认 0.15），0=关闭。
        bg_ratio: 背景原型比率阈值（默认 0.7），0=关闭。
                  样本到最近原型距离 vs 到所有原型质心距离的比值。
                  > bg_ratio → 样本不够"专一"，判为 unknown。
                  解决模型只在闭集上训练、缺乏拒绝能力的根本问题。

    Returns:
        list[dict]: 每个结果含 class, label, confidence, origin,
                    is_unknown, distance, recon_error, recon_suspicious, bg_distance
    """
    device = next(model.parameters()).device
    tensor = preprocess(input_data, device=device)

    with torch.no_grad():
        latent_z, dist, kl_div, recon_x = model(tensor)

    # 重构误差: MSE(原图, 重建图)
    recon_error = float(torch.nn.functional.mse_loss(recon_x, tensor).item())
    recon_suspicious = recon_threshold > 0 and recon_error > recon_threshold

    # dist: (1, n_classes) 平方欧氏距离 → 统一转为欧氏距离
    dist = dist.squeeze(0)                             # (n_classes,)
    euclidean_dist = torch.sqrt(dist)                  # 欧氏距离 (n_classes,)
    min_euclidean = euclidean_dist.min().item()
    min_label = euclidean_dist.argmin().item()

    # ---- 背景原型检测 ----
    # 计算所有原型质心，样本到质心的距离作为"背景距离"
    prototypes = model.prototypes                      # (n_classes, latent_dim)
    bg_centroid = prototypes.mean(dim=0)               # 原型质心 (latent_dim,)
    latent_vec = latent_z.squeeze(0)                   # (latent_dim,)
    bg_sq_dist = torch.sum((latent_vec - bg_centroid) ** 2).item()
    bg_distance = float(np.sqrt(bg_sq_dist))           # 欧氏距离到背景点
    # 比率: 越小越"专一"，越大越"模糊"
    commit_ratio = min_euclidean / bg_distance if bg_distance > 0 else 0.0

    # 类特定阈值优先，回退到全局阈值
    if class_thresholds and min_label in class_thresholds:
        effective_threshold = class_thresholds[min_label]
    else:
        effective_threshold = threshold

    # 未知攻击检测（三重信号：绝对距离远 OR 重构差 OR 不够专一）
    is_unknown = (
        min_euclidean > effective_threshold
        or recon_suspicious
        or (bg_ratio > 0 and commit_ratio > bg_ratio)
    )

    if is_unknown:
        # 记录触发原因用于调试
        reasons = []
        if min_euclidean > effective_threshold:
            reasons.append(f"distance({min_euclidean:.3f} > {effective_threshold})")
        if recon_suspicious:
            reasons.append(f"recon({recon_error:.5f} > {recon_threshold})")
        if bg_ratio > 0 and commit_ratio > bg_ratio:
            reasons.append(f"bg_ratio({commit_ratio:.3f} > {bg_ratio})")
        # Confidence for unknown: inversely proportional to how far beyond threshold.
        # At threshold, confidence ~0.95; at 4× threshold, confidence ~0.40.
        excess = max(0.0, min_euclidean - effective_threshold)
        unknown_conf = round(max(0.35, 0.95 - excess * 0.15), 4)

<<<<<<< HEAD
    # 未知攻击检测
    if min_dist > threshold:
        # 置信度 = 基于超出阈值的程度，映射到 [0.5, 0.99]
        # 距离越远置信度越高，但不写死 1.0
        excess = (min_dist - threshold) / threshold  # 超出比例
        unknown_conf = min(0.99, 0.5 + excess * 0.1)
        return [{
            "class": UNKNOWN_NAME,
            "label": UNKNOWN_LABEL,
            "confidence": round(unknown_conf, 6),
=======
        return [{
            "class": UNKNOWN_NAME,
            "label": UNKNOWN_LABEL,
            "confidence": unknown_conf,
>>>>>>> test_function
            "origin": "unknown",
            "is_unknown": True,
            "distance": round(min_euclidean, 4),
            "recon_error": round(recon_error, 6),
            "recon_suspicious": recon_suspicious,
            "bg_distance": round(bg_distance, 4),
            "commit_ratio": round(commit_ratio, 4),
            "unknown_reason": " | ".join(reasons),
        }]

    # 置信度: softmax(-欧氏距离 / temperature)
    confidence = F.softmax(-euclidean_dist / temperature, dim=0)

    # Top-K
    topk_conf, topk_indices = torch.topk(confidence, min(top_k, len(confidence)))
    topk_dists = euclidean_dist[topk_indices]

    results = []
    for conf, idx, d in zip(topk_conf.tolist(), topk_indices.tolist(), topk_dists.tolist()):
        class_name = CLASS_NAMES.get(idx, f"Class_{idx}")
        results.append({
            "class": class_name,
            "label": idx,
            "confidence": round(conf, 6),
            "origin": CLASS_ORIGIN.get(class_name, "unknown"),
            "is_unknown": False,
            "distance": round(d, 4),
            "recon_error": round(recon_error, 6),
            "recon_suspicious": recon_suspicious,
            "bg_distance": round(bg_distance, 4),
            "commit_ratio": round(commit_ratio, 4),
        })

    return results


def predict_batch(model, images: list, top_k: int = 1, threshold: float = 2.24,
                  temperature: float = 1.0,
                  class_thresholds: dict[int, float] | None = None,
                  recon_threshold: float = 0.15,
                  bg_ratio: float = 0.7) -> list[list[dict]]:
    """Batch inference for multiple images in a single forward pass.

    Args:
        model: OpenDetectNet
        images: list of np.ndarray(32,32), PIL.Image, or paths
        (other args same as predict())

    Returns:
        list of lists, one per input image: [
            [{"class": ..., ...}, ...],   # results for image 0
            [{"class": ..., ...}, ...],   # results for image 1
        ]
    """
    device = next(model.parameters()).device
    tensors = torch.stack([preprocess(img, device=device) for img in images])  # (B, 1, 1, 32, 32)
    tensors = tensors.squeeze(1)  # -> (B, 1, 32, 32)

    with torch.no_grad():
        latent_z, dist, kl_div, recon_x = model(tensors)

    # dist: (B, n_classes), recon_x: (B, 1, 32, 32)
    all_results = []
    for b in range(len(images)):
        single_latent = latent_z[b:b + 1]
        single_dist = dist[b]                          # (n_classes,)
        single_recon = recon_x[b:b + 1]
        single_input = tensors[b:b + 1]

        recon_error = float(torch.nn.functional.mse_loss(single_recon, single_input).item())
        recon_suspicious = recon_threshold > 0 and recon_error > recon_threshold

        euclidean_dist = torch.sqrt(single_dist)
        min_euclidean = euclidean_dist.min().item()
        min_label = euclidean_dist.argmin().item()

        # Background prototype
        prototypes = model.prototypes
        bg_centroid = prototypes.mean(dim=0)
        latent_vec = single_latent.squeeze(0)
        bg_sq_dist = torch.sum((latent_vec - bg_centroid) ** 2).item()
        bg_distance = float(np.sqrt(bg_sq_dist))
        commit_ratio = min_euclidean / bg_distance if bg_distance > 0 else 0.0

        if class_thresholds and min_label in class_thresholds:
            effective_threshold = class_thresholds[min_label]
        else:
            effective_threshold = threshold

        is_unknown = (
            min_euclidean > effective_threshold
            or recon_suspicious
            or (bg_ratio > 0 and commit_ratio > bg_ratio)
        )

        if is_unknown:
            reasons = []
            if min_euclidean > effective_threshold:
                reasons.append(f"distance({min_euclidean:.3f} > {effective_threshold})")
            if recon_suspicious:
                reasons.append(f"recon({recon_error:.5f} > {recon_threshold})")
            if bg_ratio > 0 and commit_ratio > bg_ratio:
                reasons.append(f"bg_ratio({commit_ratio:.3f} > {bg_ratio})")
            excess = max(0.0, min_euclidean - effective_threshold)
            unknown_conf = round(max(0.35, 0.95 - excess * 0.15), 4)
            all_results.append([{
                "class": UNKNOWN_NAME,
                "label": UNKNOWN_LABEL,
                "confidence": unknown_conf,
                "origin": "unknown",
                "is_unknown": True,
                "distance": round(min_euclidean, 4),
                "recon_error": round(recon_error, 6),
                "recon_suspicious": recon_suspicious,
                "bg_distance": round(bg_distance, 4),
                "commit_ratio": round(commit_ratio, 4),
                "unknown_reason": " | ".join(reasons),
            }])
        else:
            confidence = F.softmax(-euclidean_dist / temperature, dim=0)
            topk_conf, topk_indices = torch.topk(confidence, min(top_k, len(confidence)))
            topk_dists = euclidean_dist[topk_indices]

            results = []
            for conf, idx, d in zip(topk_conf.tolist(), topk_indices.tolist(), topk_dists.tolist()):
                class_name = CLASS_NAMES.get(idx, f"Class_{idx}")
                results.append({
                    "class": class_name,
                    "label": idx,
                    "confidence": round(conf, 6),
                    "origin": CLASS_ORIGIN.get(class_name, "unknown"),
                    "is_unknown": False,
                    "distance": round(d, 4),
                    "recon_error": round(recon_error, 6),
                    "recon_suspicious": recon_suspicious,
                    "bg_distance": round(bg_distance, 4),
                    "commit_ratio": round(commit_ratio, 4),
                })
            all_results.append(results)

    return all_results


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
    parser.add_argument("--threshold", type=float, default=2.24,
                        help="未知攻击距离阈值 (欧氏距离, 默认 2.24)")
    parser.add_argument("--temperature", type=float, default=1.0,
                        help="softmax 温度参数 (默认1.0)")
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
