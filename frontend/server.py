#!/usr/bin/env python3
"""
OpenDetect 实时后端服务器
自动捕获网卡流量 → 模型推理 → WebSocket 推送至前端

用法:
    # 管理员身份运行（Windows 需要管理员权限抓包）
    python frontend/server.py

    # 指定网卡
    python frontend/server.py --iface "Wi-Fi"

    # 仅启动 API 服务，不抓包（调试/开发）
    python frontend/server.py --no-capture

    # 监听所有网卡（需要管理员 + Npcap）
    python frontend/server.py --promiscuous
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

# ── 确保项目根目录可导入 ─────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# ── FastAPI / WebSocket ─────────────────────────────────
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

# 后端检测引擎
from realtime_detection.pipeline import DetectionPipeline
from realtime_detection.flow_manager import FlowData
from realtime_detection.preprocess import build_flow_id, build_gray_image, build_gray_image_training_compat
from realtime_detection.alert_manager import Alert

# 确保 tests/ 可导入（攻击模拟器）
_TESTS_DIR = ROOT_DIR / "tests"
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


# ══════════════════════════════════════════════════════════
# 全局状态
# ══════════════════════════════════════════════════════════

pipeline: Optional[DetectionPipeline] = None
ws_clients: set[WebSocket] = set()
capture_thread: Optional[threading.Thread] = None
stop_capture = threading.Event()
_training_compat: bool = False  # 训练兼容预处理模式
_bpf_exclude: str = ""           # BPF 排除表达式

# 累计统计计数器（不随告警历史刷新而丢失）
_cumulative_model_warning: int = 0
_cumulative_model_critical: int = 0
_cumulative_lock = threading.Lock()

# 最近正常流量缓存 (供 /api/flows/normal 使用)
_recent_normal_flows: list[dict] = []

# 统计周期推送
last_stats_time = time.time()
stats_interval = 2.0  # 每 2 秒推送一次统计

# 性能指标
perf_metrics = {
    "processing_times": [],  # 最近 100 条处理延迟
    "total_flows": 0,
    "total_abnormal": 0,
    "total_alerts": 0,
    "start_time": time.time(),
    # 基准评测指标（启动时在测试集上计算一次）
    "accuracy": None,
    "f1_score": None,
    "fpr": None,
    "precision": None,
    "recall": None,
    "benchmark_samples": 0,
}

# ══════════════════════════════════════════════════════════
# FastAPI 应用
# ══════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════
# 延迟网卡配置（由 server_main 在 uvicorn 启动前设置）
# ══════════════════════════════════════════════════════════

_target_iface: Optional[str] = None

# ══════════════════════════════════════════════════════════
# Lifespan（替代废弃的 on_event）
# ══════════════════════════════════════════════════════════

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline, capture_thread, loop

    # ── startup ──
    loop = asyncio.get_event_loop()

    # 1. 加载模型
    model_path = os.path.join(ROOT_DIR, "save_model", "mixed_44_split_0.pt")
    if os.path.exists(model_path):
        try:
            pipeline = DetectionPipeline(
                model_path=model_path,
                threshold=2.0,
                top_k=3,
                temperature=1.0,
                expire_minutes=10,
                enable_export=False,
            )
            print(f"[INIT] 模型加载成功: {model_path}")
            print(f"[INIT]   类别数: {pipeline.predictor.model.n_classes}")
        except Exception as e:
            print(f"[INIT] 模型加载失败: {e}")
            pipeline = None
    else:
        print(f"[INIT] 模型文件不存在: {model_path}")
        pipeline = None

    # 2. 启动统计推送
    asyncio.create_task(stats_ticker())

    # 3. 启动抓包（在 loop 就绪后启动）
    if _target_iface is not None and capture_thread is None:
        stop_capture.clear()
        capture_thread = threading.Thread(
            target=capture_worker,
            args=(_target_iface,),
            daemon=True,
            name="capture-worker",
        )
        capture_thread.start()
        print(f"[INIT] 抓包线程已启动 (iface={_target_iface})")

    yield

    # ── shutdown ──
    stop_capture.set()
    print("[SHUTDOWN] 系统已停止")


app = FastAPI(title="OpenDetect", version="1.0.0", lifespan=lifespan)

# 前端静态文件目录
frontend_dir = Path(__file__).parent


@app.get("/")
async def index():
    """返回主页面"""
    return FileResponse(str(frontend_dir / "index.html"))


# 单独挂载子目录（这些 StaticFiles mount 只处理对应前缀）
if (frontend_dir / "css").exists():
    app.mount("/css", StaticFiles(directory=str(frontend_dir / "css")), name="css")
if (frontend_dir / "js").exists():
    app.mount("/js", StaticFiles(directory=str(frontend_dir / "js")), name="js")


@app.get("/api/status")
async def api_status():
    """系统状态 API"""
    return {
        "status": "running",
        "capture_active": not stop_capture.is_set() and capture_thread is not None,
        "model_loaded": pipeline is not None,
        "total_flows": perf_metrics["total_flows"],
        "total_abnormal": perf_metrics["total_abnormal"],
        "total_alerts": perf_metrics["total_alerts"],
        "uptime": time.time() - perf_metrics["start_time"],
        "ws_clients": len(ws_clients),
    }


@app.get("/api/health")
async def api_health():
    """健康检查（供前端探测）"""
    return {
        "ok": True,
        "model_loaded": pipeline is not None,
        "capture_active": not stop_capture.is_set() and capture_thread is not None,
    }


# ══════════════════════════════════════════════════════════
# 攻击状态管理
# ══════════════════════════════════════════════════════════

_attack_state = {
    "running": False,
    "name": "",
    "started_at": 0.0,
    "progress": 0,
    "status": "idle",
}
_ATTACK_LOCK = threading.Lock()
_ATTACK_STOP_EVENT = threading.Event()

# ── 安全导入攻击模拟器模块 ──
try:
    from attack_simulator.scan import run_port_scan
    from attack_simulator.ddos import run_syn_flood
    from attack_simulator.beacon import run_beacon
    from attack_simulator.replay import run_replay
    from attack_simulator.orchestrator import run_all_with_stop
    _HAS_ATTACK_SIM = True
except ImportError:
    _HAS_ATTACK_SIM = False

# ── PCAP 网络回放 (仪表盘模型攻击) ──
try:
    from replay_pcap import rewrite_pcap_for_loopback, DummyTCPListener, DUMMY_PORT as _REPLAY_PORT
    from scapy.all import rdpcap, sendp
    _HAS_PCAP_REPLAY = True
except ImportError:
    _HAS_PCAP_REPLAY = False


def _run_attack_thread(name: str, fn, args: tuple = ()):
    """在后台线程中运行攻击"""
    global _attack_state
    with _ATTACK_LOCK:
        if _attack_state["running"]:
            return False, f"已有攻击运行中: {_attack_state['name']}"
        _ATTACK_STOP_EVENT.clear()
        _attack_state = {
            "running": True, "name": name,
            "started_at": time.time(), "progress": 0, "status": "running",
        }

    def _wrapper():
        try:
            fn(*args)
        except Exception as e:
            print(f"[ATTACK] {name} 异常: {e}")
        finally:
            _attack_state["running"] = False
            _attack_state["status"] = "done"
            _attack_state["progress"] = 100

    threading.Thread(target=_wrapper, daemon=True).start()
    return True, f"{name} 已启动"


# ══════════════════════════════════════════════════════════
# REST API — 数据端点（兼容旧版仪表盘）
# ══════════════════════════════════════════════════════════

@app.get("/api/summary")
async def api_summary():
    """返回仪表盘综合摘要（仅模型检测统计）"""
    global _cumulative_model_warning, _cumulative_model_critical
    alerts = pipeline.get_alert_history() if pipeline else []
    attack_flow_count = 1 if _attack_state["running"] else 0

    # 模型检测统计
    total_flows = perf_metrics["total_flows"]
    total_abnormal = perf_metrics["total_abnormal"]
    model_normal = max(0, total_flows - total_abnormal)

    # 从告警中统计模型检出的 WARNING / CRITICAL 数量（累加计数器）
    from_history_warning = 0
    from_history_critical = 0
    for a in alerts:
        extra = getattr(a, 'extra', {}) or {}
        mr = extra.get("model_result", {})
        if mr.get("attack_type"):
            lv = mr.get("alert_level", "")
            if lv == "CRITICAL":
                from_history_critical += 1
            elif lv == "WARNING":
                from_history_warning += 1

    with _cumulative_lock:
        # 取累计计数器和历史计数中的较大值（防止数据集注入漏计）
        cur_w = _cumulative_model_warning
        cur_c = _cumulative_model_critical
    model_warning = max(cur_w, from_history_warning)
    model_critical = max(cur_c, from_history_critical)
    with _cumulative_lock:
        _cumulative_model_warning = model_warning
        _cumulative_model_critical = model_critical

    return {
        "flows_total": total_flows + attack_flow_count,
        "flows_abnormal": total_abnormal + attack_flow_count,
        "alerts_total": len(alerts),
        "alerts_critical": sum(1 for a in alerts if getattr(a, 'alert_level', '') == 'CRITICAL'),
        "alerts_warning": sum(1 for a in alerts if getattr(a, 'alert_level', '') == 'WARNING'),
        "capture_active": not stop_capture.is_set(),
        "model_loaded": pipeline is not None,
        "uptime": time.time() - perf_metrics["start_time"],
        "attack_running": _attack_state["running"],
        "attack_name": _attack_state["name"],
        # 模型检测统计卡片
        "model_normal": model_normal,
        "model_warning": model_warning,
        "model_critical": model_critical,
        "accuracy": perf_metrics.get("accuracy"),
        "server_time": time.time(),
    }


@app.get("/api/alerts")
async def api_alerts(limit: int = 50, source: str = ""):
    """返回最近告警列表。source=model 仅返回模型检出的告警。"""
    alerts = pipeline.get_alert_history(
        start_time=perf_metrics["start_time"]  # 仅返回当前会话的告警
    ) if pipeline else []
    recent = sorted(alerts, key=lambda a: a.timestamp, reverse=True)

    if source == "model":
        recent = [a for a in recent
                  if (getattr(a, 'extra', {}) or {}).get("model_result", {}).get("attack_type")]

    recent = recent[:limit]
    return {
        "alerts": [asdict(a) for a in recent],
        "count": len(recent),
        "server_time": time.time(),
    }


@app.get("/api/attack/status")
async def api_attack_status():
    """返回攻击执行状态"""
    return _attack_state


# ══════════════════════════════════════════════════════════
# 攻击模拟器 API
# ══════════════════════════════════════════════════════════

@app.post("/api/attack/scan")
async def api_attack_scan(data: dict = Body(None)):
    """执行端口扫描攻击"""
    if not _HAS_ATTACK_SIM:
        return {"ok": False, "message": "攻击模拟器模块不可用"}
    data = data or {}
    target = data.get("target", "172.17.0.1")
    start = data.get("start_port", 20)
    end = data.get("end_port", 50)
    ok, msg = _run_attack_thread("port_scan", run_port_scan, (target, start, end))
    return {"ok": ok, "message": msg, "attack_type": "port_scan", "target": target}


@app.post("/api/attack/ddos")
async def api_attack_ddos(data: dict = Body(None)):
    """执行 SYN Flood 攻击"""
    if not _HAS_ATTACK_SIM:
        return {"ok": False, "message": "攻击模拟器模块不可用"}
    data = data or {}
    target = data.get("target", "172.17.0.1")
    port = data.get("port", 8080)
    duration = data.get("duration", 5.0)
    rate = data.get("rate", 50)
    ok, msg = _run_attack_thread("syn_flood", run_syn_flood, (target, port, duration, rate))
    return {"ok": ok, "message": msg, "attack_type": "syn_flood", "target": target}


@app.post("/api/attack/beacon")
async def api_attack_beacon(data: dict = Body(None)):
    """执行 C2 Beaconing 攻击"""
    if not _HAS_ATTACK_SIM:
        return {"ok": False, "message": "攻击模拟器模块不可用"}
    data = data or {}
    target = data.get("target", "172.17.0.1")
    port = data.get("port", 8443)
    interval = data.get("interval", 30.0)
    count = data.get("count", 6)
    ok, msg = _run_attack_thread("c2_beaconing", run_beacon, (target, port, interval, count))
    return {"ok": ok, "message": msg, "attack_type": "c2_beaconing", "target": target}


@app.post("/api/attack/replay")
async def api_attack_replay(data: dict = Body(None)):
    """执行 PCAP 回放"""
    if not _HAS_ATTACK_SIM:
        return {"ok": False, "message": "攻击模拟器模块不可用"}
    data = data or {}
    pcap_type = data.get("type", "known_malware")
    target = data.get("target", "172.17.0.1")
    ok, msg = _run_attack_thread(f"pcap_replay_{pcap_type}", run_replay, (pcap_type, target))
    return {"ok": ok, "message": msg, "attack_type": f"pcap_replay_{pcap_type}", "target": target}


@app.post("/api/attack/orchestrate")
async def api_attack_orchestrate(data: dict = Body(None)):
    """执行全套攻击编排（port_scan → syn_flood → beacon → replays）"""
    if not _HAS_ATTACK_SIM:
        return {"ok": False, "message": "攻击模拟器模块不可用"}
    data = data or {}
    target = data.get("target", "172.17.0.1")
    wait = data.get("wait", 5.0)

    with _ATTACK_LOCK:
        if _attack_state["running"]:
            return {"ok": False, "message": f"已有攻击运行中: {_attack_state['name']}"}
        _ATTACK_STOP_EVENT.clear()
        _attack_state = {
            "running": True, "name": "orchestrate_full",
            "started_at": time.time(), "progress": 0, "status": "running",
        }

    def _run():
        try:
            run_all_with_stop(target=target, wait_seconds=wait, stop_event=_ATTACK_STOP_EVENT)
        except Exception as e:
            print(f"[ATTACK] orchestrate 异常: {e}")
        finally:
            _attack_state["running"] = False
            _attack_state["status"] = "done"
            _attack_state["progress"] = 100

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": "全套攻击已启动", "target": target}


@app.post("/api/test/trigger")
async def api_test_trigger(data: dict = Body(None)):
    """触发模型检测攻击 —— PCAP 网络回放 → 网卡捕获 → 训练兼容预处理 → 模型推理
    
    完整管线: PCAP → sendp(lo) → sniff → build_gray_image_training_compat → model
    
    可选参数:
        level: "CRITICAL" | "WARNING" | "INFO" | "ALL" (默认 CRITICAL)
        pps: 每秒发包数 (默认 50)
    """
    global _attack_state, _ATTACK_STOP_EVENT
    if not _HAS_PCAP_REPLAY:
        return {"ok": False, "message": "PCAP 回放模块不可用 (缺少 scapy 或 replay_pcap)"}

    data = data or {}
    level_filter = data.get("level", "CRITICAL").upper()
    pps = data.get("pps", 50)
    pcaps_dir = os.path.join(os.path.dirname(__file__), "..", "output", "pcaps")
    manifest_path = os.path.join(pcaps_dir, "manifest.json")

    if not os.path.exists(manifest_path):
        return {"ok": False, "message": f"manifest 不存在: {manifest_path}"}

    with open(manifest_path) as f:
        manifest = json.load(f)

    entries = manifest
    if level_filter != "ALL":
        entries = [e for e in entries if e["alert_level"] == level_filter]
    if not entries:
        return {"ok": False, "message": f"无匹配 PCAP (level={level_filter})"}

    with _ATTACK_LOCK:
        if _attack_state["running"]:
            return {"ok": False, "message": f"已有攻击运行中: {_attack_state['name']}"}
        _ATTACK_STOP_EVENT.clear()
        _attack_state = {
            "running": True, "name": f"pcap_replay_{level_filter.lower()}",
            "started_at": time.time(), "progress": 0, "status": "running",
        }

    send_iface = _target_iface or "lo"
    total = len(entries)

    def _run():
        listener = DummyTCPListener("127.0.0.1", _REPLAY_PORT)
        listener.start()
        time.sleep(0.3)

        try:
            completed = 0
            for i, entry in enumerate(entries):
                if _ATTACK_STOP_EVENT.is_set():
                    print(f"[PCAP-REPLAY] 攻击已停止 ({completed}/{total})")
                    break

                pcap_path = os.path.join(pcaps_dir, entry["file"])
                if not os.path.exists(pcap_path):
                    print(f"[PCAP-REPLAY] SKIP: {pcap_path} 不存在")
                    continue

                pkts = rdpcap(pcap_path)
                if not pkts:
                    continue

                rewritten = rewrite_pcap_for_loopback(pkts, _REPLAY_PORT)
                delay = 1.0 / max(pps, 1)

                print(f"[PCAP-REPLAY] {i+1}/{total} [{entry['alert_level']}] {entry['class_name']} ({len(rewritten)} pkts)")
                for pkt in rewritten:
                    sendp(pkt, iface=send_iface, verbose=False)
                    time.sleep(delay)

                time.sleep(2)  # 流间间隔，确保 flush_flow 触发
                completed = i + 1
                _attack_state["progress"] = int((completed / total) * 100)

            print(f"[PCAP-REPLAY] 完成: {completed}/{total} 个 PCAP")
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"[PCAP-REPLAY] 异常: {e}")
        finally:
            listener.stop()
            _attack_state["running"] = False
            _attack_state["status"] = "done"
            _attack_state["progress"] = 100

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "message": f"已启动 PCAP 回放攻击 (level={level_filter})", "total": total}


@app.post("/api/attack/stop")
async def api_attack_stop():
    """停止当前攻击"""
    was_running = _attack_state["running"]
    _ATTACK_STOP_EVENT.set()
    _attack_state["running"] = False
    _attack_state["status"] = "stopped"
    return {
        "ok": True,
        "was_running": was_running,
        "message": "攻击已停止" if was_running else "无运行中的攻击",
    }


@app.post("/api/admin/clear")
async def api_admin_clear():
    """清除后端缓存：告警历史、累计计数器、性能统计"""
    global _cumulative_model_warning, _cumulative_model_critical

    # 清除告警历史
    if pipeline and hasattr(pipeline, 'alert_manager'):
        pipeline.alert_manager.clear()

    # 重置累计计数器
    _cumulative_model_warning = 0
    _cumulative_model_critical = 0

    # 重置性能统计
    perf_metrics["start_time"] = time.time()
    perf_metrics["total_flows"] = 0
    perf_metrics["total_packets"] = 0
    perf_metrics["total_abnormal"] = 0
    perf_metrics["total_alerts"] = 0
    perf_metrics["queue_size"] = 0
    perf_metrics["processing_times"].clear()

    # 重置正常流量缓存
    _recent_normal_flows.clear()

    return {
        "ok": True,
        "message": "缓存已清除 (告警、计数器、性能统计已重置)",
        "server_time": time.time(),
    }


@app.get("/api/flows/normal")
async def api_flows_normal(limit: int = 100):
    """返回最近 N 条正常流量（INFO 级别）"""
    global _recent_normal_flows
    recent = _recent_normal_flows[-limit:] if len(_recent_normal_flows) > limit else list(_recent_normal_flows)
    return {
        "ok": True,
        "count": len(recent),
        "flows": recent[::-1],  # 最新的在前
    }


# ══════════════════════════════════════════════════════════
# 旧版测试仪表盘（含攻击按钮界面）
# ══════════════════════════════════════════════════════════

@app.get("/test")
async def test_dashboard():
    """返回旧版测试仪表盘（含攻击按钮）"""
    test_html = ROOT_DIR / "tests" / "dashboard" / "templates" / "index.html"
    if test_html.exists():
        return FileResponse(str(test_html))
    return {"error": "test dashboard HTML not found"}


# ══════════════════════════════════════════════════════════
# WebSocket 管理器
# ══════════════════════════════════════════════════════════

async def broadcast(message: dict):
    """向所有连接的客户端广播消息"""
    if not ws_clients:
        return
    payload = json.dumps(message, default=str)
    dead = set()
    for client in ws_clients:
        try:
            await client.send_text(payload)
        except Exception:
            dead.add(client)
    ws_clients.difference_update(dead)


async def broadcast_flow(flow: FlowData):
    """广播一条新流量"""
    data = {
        "flow_id": flow.flow_id,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "timestamp": flow.timestamp,
        "class_name": flow.inference_result.get("class_name", ""),
        "confidence": flow.inference_result.get("confidence", 0),
        "distance": flow.inference_result.get("distance", 0),
        "is_unknown": flow.inference_result.get("is_unknown", False),
        "is_abnormal": flow.is_abnormal,
        "attack_type": flow.inference_result.get("attack_type", "normal"),
        "alert_level": flow.inference_result.get("alert_level", "INFO"),
    }
    await broadcast({"type": "flow", "data": data})


async def broadcast_alert(alert: Alert):
    """广播一条新告警"""
    data = asdict(alert)
    data["timestamp"] = alert.timestamp
    await broadcast({"type": "alert", "data": data})


async def broadcast_stats():
    """广播性能统计数据"""
    times = perf_metrics["processing_times"]
    avg_latency = sum(times) / len(times) if times else 0
    max_latency = max(times) if times else 0
    min_latency = min(times) if times else 0

    # 获取当前流量窗口数据
    flows = pipeline.get_flow_history() if pipeline else []
    recent_flows = [f for f in flows if time.time() - f.timestamp <= 60]
    window_abnormal = sum(1 for f in recent_flows if f.is_abnormal)

    await broadcast({
        "type": "stats",
        "data": {
            "total_flows": perf_metrics["total_flows"],
            "total_abnormal": perf_metrics["total_abnormal"],
            "total_alerts": perf_metrics["total_alerts"],
            "window_flows": len(recent_flows),
            "window_abnormal": window_abnormal,
            "avg_latency_ms": round(avg_latency, 2),
            "min_latency_ms": round(min_latency, 2),
            "max_latency_ms": round(max_latency, 2),
            "throughput": round(len(recent_flows) / 60, 1) if recent_flows else 0,
            "uptime": time.time() - perf_metrics["start_time"],
            # 基准评测指标
            "accuracy": perf_metrics.get("accuracy"),
            "f1_score": perf_metrics.get("f1_score"),
            "fpr": perf_metrics.get("fpr"),
            "precision": perf_metrics.get("precision"),
            "recall": perf_metrics.get("recall"),
        },
    })


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.add(websocket)
    print(f"[WS] 客户端已连接 ({len(ws_clients)} 个)")
    try:
        # 发送初始状态
        await websocket.send_text(json.dumps({
            "type": "connected",
            "data": {
                "message": "已连接到 OpenDetect 检测引擎",
                "capture_active": not stop_capture.is_set(),
                "model_loaded": pipeline is not None,
            },
        }))

        # 持续接收客户端消息（指令）
        while True:
            raw = await websocket.receive_text()
            try:
                cmd = json.loads(raw)
            except json.JSONDecodeError:
                continue

            action = cmd.get("action", "")
            if action == "pause":
                stop_capture.set()
                print("[CMD] 捕获已暂停")
                await websocket.send_text(json.dumps({
                    "type": "command_ack",
                    "data": {"action": "pause", "capture_active": False},
                }))
            elif action == "resume":
                stop_capture.clear()
                print("[CMD] 捕获已恢复")
                await websocket.send_text(json.dumps({
                    "type": "command_ack",
                    "data": {"action": "resume", "capture_active": True},
                }))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_clients.discard(websocket)
        print(f"[WS] 客户端已断开 ({len(ws_clients)} 个)")


# ══════════════════════════════════════════════════════════
# 流量捕获 + 推理
# ══════════════════════════════════════════════════════════

CAPTURE_CONFIG = {
    "max_packets_per_flow": 10,
    "flow_idle_timeout": 3.0,
    "bpf_filter": "ip and (tcp or udp)",
}


def list_ifaces() -> list[dict]:
    """列出所有可用网卡，支持多种 Scapy 接口枚举方式"""
    # 方式一：get_windows_if_list (Windows 专用，返回详细信息)
    try:
        from scapy.arch import get_windows_if_list
        ifaces = get_windows_if_list()
        if ifaces:
            result = []
            for entry in ifaces:
                guid = entry.get("guid", "")
                name = entry.get("name", "")
                desc = entry.get("description", "")
                ips = [str(ip) for ip in entry.get("ips", []) or []]
                result.append({
                    "name": name,
                    "desc": desc,
                    "guid": f"\\Device\\NPF_{{{guid.strip('{}')}}}" if guid else None,
                    "ips": ips,
                })
            return result
    except Exception:
        pass

    # 方式二：get_if_list (通用，返回名称列表)
    try:
        from scapy.all import get_if_list, conf
        names = get_if_list()
        if names:
            result = []
            for name in names:
                if name.startswith("\\Device\\NPF_"):
                    result.append({
                        "name": name.replace("\\Device\\NPF_", "").strip("{}"),
                        "desc": name,
                        "guid": name,
                        "ips": [],
                    })
                else:
                    result.append({
                        "name": name,
                        "desc": name,
                        "guid": None,
                        "ips": [],
                    })
            return result
    except Exception:
        pass

    return []


def get_default_iface() -> Optional[str]:
    """自动选择 Windows 网卡"""
    ifaces = list_ifaces()
    if not ifaces:
        print("[DIAG] 未检测到网卡，尝试 Scapy 自动选择")
        return None  # None = 让 Scapy auto-detect

    # 打印所有网卡供调试
    print("[DIAG] 检测到以下网卡:")
    for i, entry in enumerate(ifaces):
        ips_str = ", ".join(entry["ips"][:3]) if entry["ips"] else "无 IP"
        print(f"       [{i}] {entry['name']:30s} IP: {ips_str}")

    # 评分制选择最佳网卡
    def score(entry: dict) -> int:
        name_desc = (entry.get("name", "") + entry.get("desc", "")).lower()
        s = 0
        if any(k in name_desc for k in ("wlan", "wi-fi", "wifi", "wireless", "无线")):
            s += 30  # Wi-Fi 优先
        if any(k in name_desc for k in ("eth", "以太网", "以太", "ethernet", "lan")):
            s += 20
        if any(k in name_desc for k in ("virtual", "vmware", "virtualbox", "docker", "bluetooth", "loopback", "pbl")):
            s -= 10  # 虚拟网卡降权
        for ip in entry.get("ips", []):
            if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("172."):
                s += 15  # 有私有 IPv4
                break
        if not entry.get("ips"):
            s -= 5  # 无 IP 地址降权
        if not entry.get("guid"):
            s = -999  # 无 GUID 不可用
        return s

    scored = [(score(e), e) for e in ifaces if e.get("guid")]
    if not scored:
        print("[DIAG] 没有找到有 GUID 的网卡，尝试 Scapy 自动选择")
        return None

    scored.sort(key=lambda x: x[0], reverse=True)
    best = scored[0][1]
    print(f"[DIAG] 自动选择: {best['name']} (得分={scored[0][0]})")
    return best.get("guid")


def capture_worker(iface: Optional[str]):
    """后台抓包线程"""
    try:
        from scapy.all import IP, TCP, UDP, sniff
    except ImportError as e:
        print(f"[ERROR] Scapy 未安装: {e}")
        asyncio.run(broadcast({
            "type": "error",
            "data": {"message": f"Scapy 未安装: {e}"},
        }))
        return

    print(f"[CAPTURE] 启动网卡捕获: iface={iface}")
    print(f"[CAPTURE] BPF 过滤: {CAPTURE_CONFIG['bpf_filter']}")
    if _training_compat:
        CAPTURE_CONFIG["max_packets_per_flow"] = 8
        # 排除 127.0.0.0/8 背景流量，仅捕获回放流量 (172.31.0.0/16)
        CAPTURE_CONFIG["bpf_filter"] = "ip and (tcp or udp) and not net 127.0.0.0/8"
        print(f"[CAPTURE] 训练兼容模式: max_packets=8, filter={CAPTURE_CONFIG['bpf_filter']}")
    if _bpf_exclude:
        for expr in _bpf_exclude.split(","):
            expr = expr.strip()
            if expr:
                CAPTURE_CONFIG["bpf_filter"] += f" and not ({expr})"
        print(f"[CAPTURE] BPF 排除规则已应用: {_bpf_exclude}")
    print(f"[CAPTURE] 最大包数/流: {CAPTURE_CONFIG['max_packets_per_flow']}")
    print(f"[CAPTURE] 流空闲超时: {CAPTURE_CONFIG['flow_idle_timeout']}s")

    flow_state: dict[tuple, dict] = {}

    def get_flow_key(packet) -> Optional[tuple]:
        if IP not in packet:
            return None
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "UNKNOWN"
        src_port = 0
        dst_port = 0
        if TCP in packet:
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        else:
            protocol = str(ip_layer.proto)

        if _training_compat:
            # 双向流键 (仅 IP, 忽略端口 — 因为 replay 会重写 dst port)
            ip_a, ip_b = sorted([src_ip, dst_ip])
            return (ip_a, ip_b, protocol)
        else:
            return (src_ip, dst_ip, src_port, dst_port, protocol)

    def flush_flow(key: tuple):
        """完成一个流 → 推理 → 广播"""
        nonlocal flow_state
        global _cumulative_model_warning, _cumulative_model_critical
        state = flow_state.pop(key, None)
        if state is None or not state["packets"]:
            return

        # 使用存储的原始方向信息 (training_compat 模式下的双向键可能丢失方向)
        src_ip = state.get("src_ip", "0.0.0.0")
        dst_ip = state.get("dst_ip", "0.0.0.0")
        src_port = state.get("src_port", 0)
        dst_port = state.get("dst_port", 0)
        protocol = state.get("protocol", key[2] if len(key) > 2 else "TCP")
        if _training_compat:
            gray_img = build_gray_image_training_compat(state["packets"], max_packets=8)
        else:
            gray_img = build_gray_image(state["packets"])
        flow = FlowData(
            flow_id=build_flow_id(src_ip, src_port, dst_ip, dst_port, state["start_time"]),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            timestamp=state["start_time"],
            packets_data=state["packets"],
            gray_img=gray_img,
            metadata={"packet_count": len(state["packets"])},
        )

        # 推理
        start_proc = time.time()
        try:
            result = pipeline.process_captured_flow(flow)
            proc_time = (time.time() - start_proc) * 1000

            # 记录性能
            perf_metrics["total_flows"] += 1
            perf_metrics["processing_times"].append(proc_time)
            if len(perf_metrics["processing_times"]) > 200:
                perf_metrics["processing_times"] = perf_metrics["processing_times"][-100:]
            if result.is_abnormal:
                perf_metrics["total_abnormal"] += 1

            # 广播流
            coro = broadcast_flow(result)
            asyncio.run_coroutine_threadsafe(coro, loop)

            # 广播告警
            if result.is_abnormal and result.metadata.get("alert_id"):
                alert = pipeline.alert_manager.get_alert_history()[-1]
                if alert:
                    perf_metrics["total_alerts"] += 1

                    # 累计模型检测告警计数器
                    if alert.extra and alert.extra.get("model_result", {}).get("attack_type"):
                        lv = alert.extra["model_result"].get("alert_level", "")
                        with _cumulative_lock:
                            if lv == "CRITICAL":
                                _cumulative_model_critical += 1
                            elif lv == "WARNING":
                                _cumulative_model_warning += 1

                    coro2 = broadcast_alert(alert)
                    asyncio.run_coroutine_threadsafe(coro2, loop)
            else:
                # 正常流量 → 加入缓存（供 /api/flows/normal）
                _recent_normal_flows.append({
                    "timestamp": flow.timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "class_name": result.class_name,
                    "confidence": result.confidence,
                    "is_abnormal": False,
                })
                if len(_recent_normal_flows) > 200:
                    _recent_normal_flows[:] = _recent_normal_flows[-100:]

        except Exception as e:
            print(f"[ERROR] 推理失败 {flow.flow_id}: {e}")
            asyncio.run_coroutine_threadsafe(
                broadcast({"type": "error", "data": {"message": f"推理失败: {e}"}}),
                loop,
            )

    def packet_handler(packet):
        """Scapy 包回调"""
        if stop_capture.is_set():
            raise StopIteration

        key = get_flow_key(packet)
        if key is None:
            return

        now = time.time()
        state = flow_state.get(key)

        # 新流 或 流已超时
        if state is None or now - state["last_seen"] >= CAPTURE_CONFIG["flow_idle_timeout"]:
            # 先刷掉旧的
            if state is not None:
                flush_flow(key)
            state = {
                "packets": [],
                "start_time": now,
                "last_seen": now,
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": "TCP" if TCP in packet else ("UDP" if UDP in packet else str(packet[IP].proto)),
            }
            if TCP in packet:
                state["src_port"] = int(packet[TCP].sport)
                state["dst_port"] = int(packet[TCP].dport)
            elif UDP in packet:
                state["src_port"] = int(packet[UDP].sport)
                state["dst_port"] = int(packet[UDP].dport)
            else:
                state["src_port"] = 0
                state["dst_port"] = 0
            flow_state[key] = state

        packet_bytes = bytes(packet)
        # 去重: lo 上每个包出现两次, 跳过连续重复
        if state["packets"] and state["packets"][-1] == packet_bytes:
            return
        if len(state["packets"]) < CAPTURE_CONFIG["max_packets_per_flow"]:
            state["packets"].append(packet_bytes)
        state["last_seen"] = now

        # 流已满 → 送出
        if len(state["packets"]) >= CAPTURE_CONFIG["max_packets_per_flow"]:
            flush_flow(key)

    # 主嗅探循环（支持暂停/恢复 + 异常重连）
    # 使用 timeout 循环代替 stop_filter，避免 scapy 在 lo 上的 socket 崩溃
    paused_logged = False
    while True:
        # ── 暂停等待 ──
        while stop_capture.is_set():
            if not paused_logged:
                print("[CAPTURE] 已暂停")
                paused_logged = True
            time.sleep(0.5)
        paused_logged = False

        # ── 嗅探 ──
        # 使用超时循环，每次超时后重新打开 socket
        sniff_kwargs = dict(
            iface=iface,
            filter=CAPTURE_CONFIG["bpf_filter"],
            prn=packet_handler,
            store=False,
            timeout=1,
        )

        try:
            sniff(**sniff_kwargs)
        except StopIteration:
            pass  # stop_capture 触发的正常退出，回到外层循环进入暂停
        except PermissionError:
            print("[ERROR] 权限不足！请以管理员身份运行。")
            asyncio.run_coroutine_threadsafe(
                broadcast({
                    "type": "error",
                    "data": {"message": "权限不足！请以管理员身份运行。"},
                }),
                loop,
            )
            return
        except Exception as e:
            print(f"[ERROR] 捕获异常: {e}")
            asyncio.run_coroutine_threadsafe(
                broadcast({"type": "error", "data": {"message": f"捕获异常: {e}"}}),
                loop,
            )
            time.sleep(1)  # 避免异常后疯狂循环


# ══════════════════════════════════════════════════════════
# 统计定时推送任务
# ══════════════════════════════════════════════════════════

loop: asyncio.AbstractEventLoop = None  # type: ignore


async def stats_ticker():
    """每 2 秒推送一次统计"""
    while True:
        await asyncio.sleep(stats_interval)
        await broadcast_stats()


# ══════════════════════════════════════════════════════════
# 入口
# ══════════════════════════════════════════════════════════

def server_main():
    global capture_thread, stop_capture, _target_iface, _training_compat, _bpf_exclude

    parser = argparse.ArgumentParser(description="OpenDetect 实时后端服务器")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="监听端口 (默认 8000)")
    parser.add_argument("--iface", default=None, help="网卡名称或 GUID")
    parser.add_argument("--no-capture", action="store_true", help="不启动抓包（仅 API 服务）")
    parser.add_argument("--promiscuous", action="store_true", help="混杂模式")
    parser.add_argument("--list-ifaces", action="store_true", help="列出可用网卡并退出")
    parser.add_argument("--reload", action="store_true", help="开发模式热重载")
    parser.add_argument(
        "--training-compat",
        action="store_true",
        help="使用训练兼容预处理 (strip Ethernet, 零化IP, 8包128B/包格式)",
    )
    parser.add_argument(
        "--bpf-exclude",
        default="",
        help="BPF 排除表达式 (如 'host 172.26.1.28 and port 7000'，多个用逗号分隔)",
    )
    args = parser.parse_args()

    # 设置训练兼容模式
    _training_compat = args.training_compat
    _bpf_exclude = args.bpf_exclude
    if _training_compat:
        print("[INIT] 训练兼容预处理模式已启用 (8-packet, 128B/pkt, zeroed IPs)")

    # --list-ifaces 直接列出并退出
    if args.list_ifaces:
        ifaces = list_ifaces()
        if not ifaces:
            print("未检测到任何网卡")
            return
        print("\n可用网卡列表:")
        print("=" * 60)
        for i, entry in enumerate(ifaces):
            ips_str = ", ".join(entry["ips"][:3]) if entry["ips"] else "无 IP"
            guid_str = entry["guid"] or "无 GUID"
            print(f"  [{i}] {entry['name']}")
            print(f"      描述: {entry['desc']}")
            print(f"      GUID: {guid_str}")
            print(f"      IP:   {ips_str}")
            print()
        return

    # 决定网卡（延迟到 startup 事件中启动，避免 loop 未就绪）
    iface = args.iface
    if not iface and not args.no_capture:
        iface = get_default_iface()
        if iface:
            print(f"[INIT] 自动选择网卡: {iface}")
        else:
            print("[INIT] 未找到可用网卡，将以 --no-capture 模式启动")
            print("[INIT] 可通过 --iface 参数指定网卡")
            args.no_capture = True

    if args.no_capture:
        _target_iface = None
        print("[INIT] 以 API 模式启动（不抓包）")
    else:
        _target_iface = iface
        print(f"[INIT] 抓包将在服务器就绪后自动启动 (iface={iface})")

    # 启动 FastAPI
    print(f"[INIT] 前端页面: http://localhost:{args.port}")
    print(f"[INIT] WebSocket: ws://localhost:{args.port}/ws")
    print(f"[INIT] API 状态: http://localhost:{args.port}/api/status")
    print()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    server_main()
