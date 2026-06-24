"""从训练数据集 .npz 文件中提取样本图像，构造 FlowData 注入检测管线。

用于测试仪表盘的"发起模型检测攻击"按钮 ——
直接使用模型训练数据的 32×32 图像，确保模型能正确分类为各类攻击类型。
"""

from __future__ import annotations

import random
import time
from typing import Optional

import numpy as np

try:
    from predict import CLASS_NAMES
except ImportError:
    CLASS_NAMES = {}
try:
    from realtime_detection.model_adapter import CLASS_ATTACK_TYPE
except ImportError:
    CLASS_ATTACK_TYPE = {}

from .flow_manager import FlowData

_NPZ_PATH = "data/dataset/mixed_44_train.npz"
_dataset_cache: Optional[tuple[np.ndarray, np.ndarray]] = None


def _load_dataset() -> tuple[np.ndarray, np.ndarray]:
    """延迟加载 npz 数据集，返回 (images, labels)。"""
    global _dataset_cache
    if _dataset_cache is not None:
        return _dataset_cache
    d = np.load(_NPZ_PATH)
    _dataset_cache = (d["data"], d["target"])
    return _dataset_cache


def get_samples(per_class: int = 2,
                attack_types: tuple = ("known_malware", "suspicious_tool"),
                seed: int = 42) -> list[dict]:
    """从数据集中按类抽取样本。

    Args:
        per_class: 每类抽取的样本数。
        attack_types: 需要抽取的 attack_type（用于过滤）。
        seed: 随机种子。

    Returns:
        list[dict]: 每个 dict 包含 class_id, class_name, image(32×32 uint8), attack_type。
    """
    images, labels = _load_dataset()
    rng = random.Random(seed)
    samples = []

    for class_id in range(44):
        atype = CLASS_ATTACK_TYPE.get(class_id, "normal")
        if atype not in attack_types:
            continue

        indices = np.where(labels == class_id)[0]
        if len(indices) == 0:
            continue

        n = min(per_class, len(indices))
        chosen = rng.sample(list(indices), n)
        for idx in chosen:
            samples.append({
                "class_id": class_id,
                "class_name": CLASS_NAMES.get(class_id, f"Class_{class_id}"),
                "image": images[idx].copy(),
                "attack_type": atype,
            })

    rng.shuffle(samples)
    return samples


def make_flow(sample: dict, index: int) -> FlowData:
    """用样本图像构造一个合成 FlowData 对象。

    填充合理的伪造 IP/端口，使仪表盘能显示有意义的来源信息。
    设置 metadata source 避免被 demo 旁路逻辑拦截。
    """
    class_id = sample["class_id"]
    class_name = sample["class_name"]
    now = time.time()

    # 用 class_id 生成差异化 IP
    src_ip = f"10.0.{class_id // 10}.{class_id % 10}"
    dst_ip = "172.17.0.14"
    src_port = 40000 + class_id * 10 + index
    dst_port = 443

    # 对于扫描器类，使用对应的常见端口
    if class_id == 10:   # nessus
        dst_port = 8834
    elif class_id == 18:  # burpsuite
        dst_port = 8080
    elif class_id in (21, 22):  # awvs
        dst_port = 3443
    elif class_id == 23:  # arachni
        dst_port = 9292

    flow_id = f"dataset_{class_id}_{index}_{int(now * 1000)}"

    return FlowData(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TLS",
        timestamp=now,
        packets_data=[],
        gray_img=sample["image"],
        metadata={
            "source": "dataset",
            "class_id": class_id,
            "class_name": class_name,
            "attack_type": sample["attack_type"],
        },
    )


def inject(pipeline, per_class: int = 2) -> int:
    """将数据集样本注入检测管线。

    Args:
        pipeline: DetectionPipeline 实例。
        per_class: 每类抽取的样本数。

    Returns:
        int: 注入的样本总数。
    """
    samples = get_samples(
        per_class=per_class,
        attack_types=("known_malware", "suspicious_tool"),
    )
    for i, sample in enumerate(samples):
        flow = make_flow(sample, i)
        pipeline.process_captured_flow(flow)
        # 小延迟避免同一秒内的 flow_id 冲突
        time.sleep(0.02)

    return len(samples)
