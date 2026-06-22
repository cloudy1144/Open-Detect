"""Payload generator — 从训练集 .npz 提取统计特征并合成仿真 payload"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import numpy as np

# ============================================================
# 44 类名称和攻击类型 (对齐 model_adapter.py CLASS_ATTACK_TYPE)
# ============================================================
CLASS_NAMES: dict[int, str] = {
    # mal 数据集 (0-23)
    0:  "Vawtrak.C",
    1:  "Upatre",
    2:  "TrickBotCC",
    3:  "Totbrick",
    4:  "Tor(suspicious)",
    5:  "Tiggre",
    6:  "Shifu.A",
    7:  "Qakbot",
    8:  "PandaZeuSCC",
    9:  "Panda.BZA!tr",
    10: "nessus(suspicious)",
    11: "golistmero",
    12: "Dynamer!ac",
    13: "Drixed",
    14: "DridexCC",
    15: "CobaltStrike",
    16: "Caphaw.A",
    17: "Caphaw.AH",
    18: "burpsuite(suspicious)",
    19: "BuerLoader",
    20: "Banker",
    21: "awvs-v12(suspicious)",
    22: "awvs-v11(suspicious)",
    23: "arachni(suspicious)",
    # USTC 数据集 (24-43)
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

_ATTACK_TYPE_MAP: dict[int, str] = {
    0:  "known_malware", 1:  "known_malware", 2:  "known_malware",
    3:  "known_malware", 5:  "known_malware", 6:  "known_malware",
    7:  "known_malware", 8:  "known_malware", 9:  "known_malware",
    11: "known_malware", 12: "known_malware", 13: "known_malware",
    14: "known_malware", 15: "known_malware", 16: "known_malware",
    17: "known_malware", 19: "known_malware", 20: "known_malware",
    4:  "suspicious_tool", 10: "suspicious_tool", 18: "suspicious_tool",
    21: "suspicious_tool", 22: "suspicious_tool", 23: "suspicious_tool",
    29: "known_malware", 30: "known_malware", 34: "known_malware",
    36: "known_malware", 37: "known_malware", 39: "known_malware",
    40: "known_malware", 42: "known_malware", 43: "known_malware",
    24: "normal", 25: "normal", 26: "normal", 27: "normal",
    28: "normal", 31: "normal", 32: "normal", 33: "normal",
    35: "normal", 38: "normal", 41: "normal",
}


def _make_histogram(attack_type: str, seed: int = 0) -> list[float]:
    """根据流量类型生成仿真的 256 维字节直方图。

    恶意软件 / 安全工具字节分布较均匀（高熵），
    正常流量偏向 ASCII 可打印字符区域（低熵）。
    """
    rng = np.random.RandomState(seed)
    hist = np.ones(256, dtype=np.float64)

    if attack_type == "normal":
        # 正常流量：强化 ASCII 可打印区域 0x20-0x7E
        ascii_range = np.arange(0x20, 0x7F)
        boost = rng.uniform(0.5, 2.0, size=len(ascii_range))
        hist[ascii_range] += boost * 3.0
        # DNS/HTTP 常见字节加强
        common_bytes = [0x00, 0x0A, 0x0D, 0x20, 0x2E, 0x2F, 0x3A, 0x3D,
                        0x47, 0x48, 0x54, 0x54, 0x50, 0x77, 0x77, 0x77]
        for b in common_bytes:
            hist[b] += rng.uniform(1.0, 3.0)
    elif attack_type == "suspicious_tool":
        # 安全工具：中等均匀但有扫描特征字节
        hist += rng.uniform(0.3, 1.5, size=256)
        # HTTP 扫描特征
        scan_bytes = [0x00, 0x01, 0x02, 0x0A, 0x0D, 0x20, 0x2F, 0x47,
                      0x45, 0x54, 0x50, 0x4F, 0x53, 0x54]
        for b in scan_bytes:
            hist[b] += rng.uniform(0.5, 2.0)
    else:  # known_malware
        # 恶意软件：较高均匀性，模拟加密/混淆 payload
        hist += rng.uniform(0.5, 2.5, size=256)
        # C2 信标特征字节
        beacon_bytes = [0x00, 0x01, 0x04, 0x08, 0x10, 0x16, 0x17]
        for b in beacon_bytes:
            hist[b] += rng.uniform(1.0, 4.0)

    # 归一化
    hist = hist / hist.sum()
    return hist.tolist()


# ============================================================
# 每类统计特征 (基于流量语义估算，无 .npz 时可独立运行)
# ============================================================
def _build_builtin_features() -> dict[int, dict]:
    """构建 44 类的内置统计特征映射。"""
    features: dict[int, dict] = {}

    # ---------- malware (0-23, classes 4/10/18/21/22/23 are suspicious_tool) ----------
    _mal_entropy = {
        0: 5.2, 1: 5.8, 2: 5.5, 3: 5.1, 5: 5.4, 6: 5.7, 7: 5.6,
        8: 5.3, 9: 5.0, 11: 5.4, 12: 5.6, 13: 5.2, 14: 5.8,
        15: 6.2, 16: 5.5, 17: 5.3, 19: 5.1, 20: 5.4,
    }
    _mal_len = {
        0: 450, 1: 380, 2: 520, 3: 340, 5: 410, 6: 480, 7: 500,
        8: 430, 9: 360, 11: 390, 12: 470, 13: 350, 14: 550,
        15: 600, 16: 440, 17: 420, 19: 330, 20: 460,
    }
    _mal_std = {
        0: 120, 1: 140, 2: 130, 3: 110, 5: 125, 6: 135, 7: 140,
        8: 120, 9: 100, 11: 115, 12: 130, 13: 105, 14: 150,
        15: 160, 16: 125, 17: 120, 19: 100, 20: 130,
    }

    for cid in range(24):
        atype = _ATTACK_TYPE_MAP.get(cid, "known_malware")
        if atype == "suspicious_tool":
            entropy = 5.8 + (cid % 3) * 0.2
            avg_len = 500 + (cid % 4) * 80
            std_len = 150 + (cid % 3) * 30
        else:
            entropy = _mal_entropy.get(cid, 5.3)
            avg_len = _mal_len.get(cid, 420)
            std_len = _mal_std.get(cid, 125)
        features[cid] = {
            "name": CLASS_NAMES.get(cid, f"class_{cid}"),
            "attack_type": atype,
            "entropy": round(entropy, 2),
            "avg_len": avg_len,
            "std_len": std_len,
            "histogram": _make_histogram(atype, seed=cid * 137 + 42),
        }

    # ---------- USTC (24-43) ----------
    _ustc_normal_entropy = {
        24: 4.0, 25: 3.8, 26: 3.5, 27: 4.2, 28: 4.5,
        31: 3.2, 32: 5.0, 33: 5.5, 35: 4.3, 38: 3.0, 41: 4.0,
    }
    _ustc_normal_len = {
        24: 800, 25: 600, 26: 400, 27: 700, 28: 900,
        31: 300, 32: 1200, 33: 1000, 35: 750, 38: 200, 41: 650,
    }
    _ustc_normal_std = {
        24: 200, 25: 150, 26: 100, 27: 180, 28: 250,
        31: 80, 32: 350, 33: 300, 35: 190, 38: 50, 41: 160,
    }
    _ustc_mal_entropy = {
        29: 5.2, 30: 6.0, 34: 5.5, 36: 5.4, 37: 5.1, 39: 5.3, 40: 5.6, 42: 5.0, 43: 5.7,
    }
    _ustc_mal_len = {
        29: 420, 30: 550, 34: 480, 36: 400, 37: 380, 39: 440, 40: 500, 42: 360, 43: 520,
    }
    _ustc_mal_std = {
        29: 130, 30: 150, 34: 135, 36: 120, 37: 110, 39: 130, 40: 140, 42: 105, 43: 145,
    }

    for cid in range(24, 44):
        atype = _ATTACK_TYPE_MAP.get(cid, "normal")
        if atype == "normal":
            entropy = _ustc_normal_entropy.get(cid, 4.0)
            avg_len = _ustc_normal_len.get(cid, 600)
            std_len = _ustc_normal_std.get(cid, 150)
        else:
            entropy = _ustc_mal_entropy.get(cid, 5.3)
            avg_len = _ustc_mal_len.get(cid, 420)
            std_len = _ustc_mal_std.get(cid, 125)
        features[cid] = {
            "name": CLASS_NAMES.get(cid, f"class_{cid}"),
            "attack_type": atype,
            "entropy": round(entropy, 2),
            "avg_len": avg_len,
            "std_len": std_len,
            "histogram": _make_histogram(atype, seed=cid * 137 + 42),
        }

    return features


BUILTIN_CLASS_FEATURES: dict[int, dict] = _build_builtin_features()


# ============================================================
# npz 文件搜索
# ============================================================
def _find_npz_files() -> list[Path]:
    """搜索训练集 npz 文件，优先返回 mixed_44_train.npz（覆盖全部 44 类）。"""
    base = Path(__file__).resolve().parent.parent.parent.parent  # Open-Detect-master/
    # 优先使用 mixed_44（覆盖所有 44 类）
    preferred = base / "data" / "dataset" / "mixed_44_train.npz"
    if preferred.exists():
        return [preferred]
    patterns = [
        "data/dataset/*train*.npz",
        "data/*train*.npz",
    ]
    files: list[Path] = []
    for p in patterns:
        files.extend(base.glob(p))
    return files


# ============================================================
# PayloadGenerator
# ============================================================
class PayloadGenerator:
    """从训练集 .npz 提取统计特征并合成仿真 payload。

    优先从 npz 文件中提取真实统计信息；若文件不存在则回退到内置特征映射。
    """

    def __init__(self, npz_path: Optional[str] = None):
        self.payload_dir = Path(__file__).resolve().parent
        self.payload_dir.mkdir(parents=True, exist_ok=True)

        self.data: Optional[dict] = None
        self._class_stats_cache: dict[int, dict] = {}

        if npz_path is None:
            files = _find_npz_files()
            npz_path = str(files[0]) if files else None

        if npz_path and Path(npz_path).exists():
            try:
                self.data = dict(np.load(npz_path, allow_pickle=True))
            except Exception:
                self.data = None

    # ------------------------------------------------------------------
    # 统计特征提取
    # ------------------------------------------------------------------
    def extract_class_stats(self, class_id: int) -> dict:
        """提取某个类别的统计特征。

        若 npz 数据可用，从真实样本计算；否则使用内置特征。
        """
        if class_id in self._class_stats_cache:
            return self._class_stats_cache[class_id]

        if self.data is not None and "target" in self.data and "data" in self.data:
            stats = self._extract_from_npz(class_id)
        else:
            stats = BUILTIN_CLASS_FEATURES.get(class_id)
            if stats is None:
                atype = _ATTACK_TYPE_MAP.get(class_id, "normal")
                name = CLASS_NAMES.get(class_id, f"class_{class_id}")
                stats = {
                    "name": name,
                    "attack_type": atype,
                    "entropy": 4.5,
                    "avg_len": 500,
                    "std_len": 150,
                    "histogram": _make_histogram(atype, seed=class_id * 137 + 42),
                }

        self._class_stats_cache[class_id] = stats
        return stats

    def _extract_from_npz(self, class_id: int) -> dict:
        """从 npz 数据中提取单类统计特征。"""
        targets = np.asarray(self.data["target"]).flatten()
        all_data = np.asarray(self.data["data"])  # shape: (N, 1, 32, 32) or similar

        mask = targets == class_id
        if mask.sum() == 0:
            # 无样本 → 回退
            return BUILTIN_CLASS_FEATURES.get(class_id, {
                "name": CLASS_NAMES.get(class_id, f"class_{class_id}"),
                "attack_type": _ATTACK_TYPE_MAP.get(class_id, "normal"),
                "entropy": 4.5, "avg_len": 500, "std_len": 150,
                "histogram": _make_histogram("normal", seed=class_id),
            })

        class_data = all_data[mask]

        # 图像数据 (32x32)：将像素值 (0-255) 展开作为字节序列计算统计
        flat = class_data.reshape(class_data.shape[0], -1).astype(np.float64)
        # 计算每样本的字节直方图，然后平均
        histograms = []
        entropies = []
        # 包长模拟：取每行像素和并缩放到合理范围
        row_sums = flat.sum(axis=1)  # 每张图的总像素强度

        for i in range(min(len(class_data), 500)):  # 最多取 500 个样本
            sample = class_data[i].flatten().astype(np.int64)
            # 字节直方图
            hist, _ = np.histogram(sample, bins=256, range=(0, 256))
            hist = hist.astype(np.float64)
            if hist.sum() > 0:
                hist = hist / hist.sum()
            else:
                hist = np.ones(256) / 256.0
            histograms.append(hist)

            # 熵
            probs = hist[hist > 0]
            ent = -np.sum(probs * np.log2(probs))
            entropies.append(ent)

        avg_hist = np.mean(histograms, axis=0)
        avg_hist = avg_hist / avg_hist.sum()

        avg_entropy = float(np.mean(entropies)) if entropies else 5.0
        # 包长：用 row_sum 的均值/标准差映射到 40-1500 范围
        raw_mean = float(row_sums.mean())
        raw_std = float(row_sums.std())
        avg_len = int(np.clip(raw_mean * 2.5, 40, 1500))
        std_len = int(np.clip(raw_std * 3.0, 10, 500))

        return {
            "name": CLASS_NAMES.get(class_id, f"class_{class_id}"),
            "attack_type": _ATTACK_TYPE_MAP.get(class_id, "normal"),
            "entropy": round(avg_entropy, 2),
            "avg_len": avg_len,
            "std_len": std_len,
            "histogram": avg_hist.tolist(),
        }

    def get_class_stats(self, class_id: int) -> dict:
        """获取类别统计特征（带缓存）。"""
        return self.extract_class_stats(class_id)

    # ------------------------------------------------------------------
    # payload 合成
    # ------------------------------------------------------------------
    def generate_payload(self, class_id: int) -> bytes:
        """根据统计特征合成近似 bytes payload。

        算法：
          1. 用字节直方图作为概率分布，随机采样生成字节序列
          2. 长度约束在 avg_len ± std_len 范围内
          3. 裁剪至 [40, 1500]（典型 MTU 范围）
        """
        stats = self.get_class_stats(class_id)

        length = int(np.random.normal(stats["avg_len"], stats["std_len"]))
        length = max(40, min(length, 1500))

        histogram = np.array(stats.get("histogram", [1.0 / 256] * 256), dtype=np.float64)
        histogram = np.clip(histogram, 0, None)  # 确保非负
        total = histogram.sum()
        if total <= 0:
            histogram = np.ones(256) / 256.0
        else:
            histogram = histogram / total

        payload = bytes(np.random.choice(256, size=length, p=histogram).astype(np.uint8))
        return payload

    def generate_payloads(self, class_id: int, count: int = 1) -> list[bytes]:
        """为一个类别生成多个 payload。"""
        return [self.generate_payload(class_id) for _ in range(count)]

    # ------------------------------------------------------------------
    # 批量保存
    # ------------------------------------------------------------------
    def save_all_stats(self, output_dir: Optional[Path] = None) -> list[Path]:
        """为每类生成 class_{N}_{name}.json 文件，返回已写入路径列表。"""
        if output_dir is None:
            output_dir = self.payload_dir
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        import base64

        written: list[Path] = []
        for class_id in range(44):
            stats = self.get_class_stats(class_id)
            payload = self.generate_payload(class_id)

            record = {
                "class_id": class_id,
                "name": stats["name"],
                "attack_type": stats["attack_type"],
                "entropy": stats["entropy"],
                "avg_len": stats["avg_len"],
                "std_len": stats["std_len"],
                "payload_base64": base64.b64encode(payload).decode("ascii"),
            }
            safe_name = stats["name"].replace("/", "_").replace("(", "").replace(")", "")
            out_path = output_dir / f"class_{class_id}_{safe_name}.json"
            with open(out_path, "w") as f:
                json.dump(record, f, indent=2)
            written.append(out_path)

        return written


# ============================================================
# 全局单例 + 接口函数（供 app.py 导入）
# ============================================================
_generator: Optional[PayloadGenerator] = None


def _get_generator() -> PayloadGenerator:
    global _generator
    if _generator is None:
        _generator = PayloadGenerator()
    return _generator


def get_payload_for_class(class_id: int) -> Optional[bytes]:
    """返回某个类别的 payload bytes。"""
    try:
        return _get_generator().generate_payload(class_id)
    except Exception:
        return None


def get_malware_payloads() -> list[dict]:
    """返回所有已知恶意类 payload 列表。"""
    gen = _get_generator()
    results: list[dict] = []
    for cid, stats in BUILTIN_CLASS_FEATURES.items():
        if stats.get("attack_type") == "known_malware":
            results.append({
                "class_id": cid,
                "name": stats["name"],
                "data": gen.generate_payload(cid),
            })
    return results


def get_normal_payloads() -> list[dict]:
    """返回所有正常流量类 payload 列表。"""
    gen = _get_generator()
    results: list[dict] = []
    for cid, stats in BUILTIN_CLASS_FEATURES.items():
        if stats.get("attack_type") == "normal":
            results.append({
                "class_id": cid,
                "name": stats["name"],
                "data": gen.generate_payload(cid),
            })
    return results


def get_suspicious_tool_payloads() -> list[dict]:
    """返回所有安全工具类 payload 列表。"""
    gen = _get_generator()
    results: list[dict] = []
    for cid, stats in BUILTIN_CLASS_FEATURES.items():
        if stats.get("attack_type") == "suspicious_tool":
            results.append({
                "class_id": cid,
                "name": stats["name"],
                "data": gen.generate_payload(cid),
            })
    return results


def get_all_class_payloads() -> list[dict]:
    """返回所有 44 类的 payload 列表。"""
    gen = _get_generator()
    results: list[dict] = []
    for cid in range(44):
        stats = gen.get_class_stats(cid)
        results.append({
            "class_id": cid,
            "name": stats["name"],
            "attack_type": stats["attack_type"],
            "data": gen.generate_payload(cid),
        })
    return results


def generate_and_save_all() -> list[Path]:
    """一次性为所有 44 类生成 payload JSON 文件并保存到 payloads/ 目录。"""
    return _get_generator().save_all_stats()


# ============================================================
# 直接执行：生成所有 payload 模板文件
# ============================================================
if __name__ == "__main__":
    paths = generate_and_save_all()
    print(f"Generated {len(paths)} payload templates:")
    for p in paths:
        print(f"  {p.name}")
