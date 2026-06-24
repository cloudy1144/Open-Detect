"""A thin adaptation layer around teammate 2's inference API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import numpy as np

from predict import load_model, predict

# ============================================================
# 每个类别的流量性质标注 (label -> attack_type)
# 来源独立于数据集，按真实语义标注：
#   known_malware   - 确认的恶意软件 / 木马 / C2
#   suspicious_tool - 合法安全工具但出现在网络中属可疑行为
#   normal          - 正常业务 / 应用流量
# ============================================================

CLASS_ATTACK_TYPE: dict[int, str] = {
    # ── mal 数据集 (0-23) ──
    # 真正恶意软件 → known_malware
    0:  "known_malware",    # Vawtrak.C     - 银行木马
    1:  "known_malware",    # Upatre         - 下载器木马
    2:  "known_malware",    # TrickBotCC     - 银行木马C2
    3:  "known_malware",    # Totbrick       - 恶意软件
    5:  "known_malware",    # Tiggre         - 恶意软件
    6:  "known_malware",    # Shifu.A        - 银行木马
    7:  "known_malware",    # Qakbot         - 银行木马
    8:  "known_malware",    # PandaZeuSCC    - Zeus变种
    9:  "known_malware",    # Panda.BZA!tr   - 恶意软件
    11: "known_malware",    # golistmero     - 恶意软件
    12: "known_malware",    # Dynamer!ac     - 恶意软件
    13: "known_malware",    # Drixed         - 恶意软件
    14: "known_malware",    # DridexCC       - 银行木马
    15: "known_malware",    # CobaltStrike   - 渗透框架(攻击者常用)
    16: "known_malware",    # Caphaw.A       - 恶意软件
    17: "known_malware",    # Caphaw.AH      - 恶意软件
    19: "known_malware",    # BuerLoader     - 恶意加载器
    20: "known_malware",    # Banker         - 银行木马
    # 合法安全工具 → suspicious_tool
    4:  "suspicious_tool",  # Tor            - 匿名网络(合法但高风险)
    10: "suspicious_tool",  # nessus         - 漏洞扫描器(合法安全产品)
    18: "suspicious_tool",  # burpsuite      - Web安全代理(合法工具)
    21: "suspicious_tool",  # awvs-v12       - Acunetix扫描器(合法商业产品)
    22: "suspicious_tool",  # awvs-v11       - Acunetix扫描器(合法商业产品)
    23: "suspicious_tool",  # arachni        - Web扫描器(合法开源工具)

    # ── USTC 数据集 (24-43) ──
    # 真正恶意软件 → known_malware
    29: "known_malware",    # Cridex         - 恶意软件
    30: "known_malware",    # Zeus           - 银行木马
    34: "known_malware",    # Shifu          - 恶意软件
    36: "known_malware",    # Virut          - 恶意软件
    37: "known_malware",    # Geodo          - 恶意软件
    39: "known_malware",    # Htbot          - 恶意软件
    40: "known_malware",    # Tinba          - 银行木马
    42: "known_malware",    # Miuref         - 恶意软件
    43: "known_malware",    # Neris          - 恶意软件
    # 正常应用流量 → normal (未列出的 USTC 类默认为 normal)
    24: "normal",           # Gmail
    25: "normal",           # FTP
    26: "normal",           # Nsis-ay
    27: "normal",           # Facetime
    28: "normal",           # Weibo
    31: "normal",           # SMB
    32: "normal",           # BitTorrent
    33: "normal",           # WorldOfWarcraft
    35: "normal",           # Outlook
    38: "normal",           # MySQL
    41: "normal",           # Skype
}

# 告警级别映射
ALERT_LEVEL_MAP = {
    "known_malware":   "CRITICAL",
    "unknown_attack":  "WARNING",
    "suspicious_tool": "WARNING",
    "normal":          "INFO",
}


def _get_attack_type(label: int, is_unknown: bool) -> str:
    """Return the canonical attack_type for a prediction result."""
    if is_unknown:
        return "unknown_attack"
    return CLASS_ATTACK_TYPE.get(label, "normal")


def _get_alert_level(attack_type: str) -> str:
    """Return the alert level for a given attack_type."""
    return ALERT_LEVEL_MAP.get(attack_type, "INFO")


@dataclass
class InferenceConfig:
    model_path: str = "save_model/mixed_44_split_0.pt"
    threshold: float = 2.24                  # 欧氏距离阈值 (≈ sqrt(5.0))
    top_k: int = 1
    temperature: float = 4.0
    device: Optional[str] = None
    class_thresholds: dict[int, float] | None = None  # 类特定阈值, 如 {31: 2.5}
    recon_threshold: float = 0.0             # 重构MSE阈值, 0=关闭此检查
    bg_ratio: float = 0.0                    # 背景原型比率, 0=关闭


class OpenDetectInferenceAdapter:
    """Wrap the repository model into a stable call surface for teammate 3."""

    def __init__(self, config: InferenceConfig | None = None):
        self.config = config or InferenceConfig()
        self.model = load_model(self.config.model_path, device=self.config.device)

    def infer(self, gray_img: np.ndarray) -> dict[str, Any]:
        """Run model inference and normalize the result for downstream modules."""

        results = predict(
            self.model,
            gray_img,
            top_k=self.config.top_k,
            threshold=self.config.threshold,
            temperature=self.config.temperature,
            class_thresholds=self.config.class_thresholds,
            recon_threshold=self.config.recon_threshold,
            bg_ratio=self.config.bg_ratio,
        )

        top1 = results[0]
        is_unknown = bool(top1["is_unknown"])
        attack_type = _get_attack_type(top1["label"], is_unknown)

        return {
            "top_results": results,
            "top1": top1,
            "class_name": top1["class"],
            "label": top1["label"],
            "confidence": top1["confidence"],
            "distance": top1["distance"],
            "recon_error": top1.get("recon_error", 0.0),
            "recon_suspicious": bool(top1.get("recon_suspicious", False)),
            "bg_distance": top1.get("bg_distance", 0.0),
            "commit_ratio": top1.get("commit_ratio", 0.0),
            "origin": top1.get("origin", "unknown"),
            "is_unknown": is_unknown,
            "is_abnormal": (attack_type != "normal"),
            "attack_type": attack_type,
            "alert_level": _get_alert_level(attack_type),
        }


def model_inference(gray_img: np.ndarray, config: InferenceConfig | None = None) -> dict[str, Any]:
    """One-shot helper matching teammate 1 / teammate 3 integration expectations."""

    return OpenDetectInferenceAdapter(config).infer(gray_img)
