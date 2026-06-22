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
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn

# 后端检测引擎
from realtime_detection.pipeline import DetectionPipeline
from realtime_detection.flow_manager import FlowData
from realtime_detection.preprocess import build_flow_id, build_gray_image
from realtime_detection.alert_manager import Alert


# ══════════════════════════════════════════════════════════
# 全局状态
# ══════════════════════════════════════════════════════════

pipeline: Optional[DetectionPipeline] = None
ws_clients: set[WebSocket] = set()
capture_thread: Optional[threading.Thread] = None
stop_capture = threading.Event()

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
                threshold=5.0,
                top_k=3,
                temperature=4.0,
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
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def flush_flow(key: tuple):
        """完成一个流 → 推理 → 广播"""
        nonlocal flow_state
        state = flow_state.pop(key, None)
        if state is None or not state["packets"]:
            return

        (src_ip, dst_ip, src_port, dst_port, protocol) = key
        gray_img = build_gray_image(state["packets"], mask_ips=pipeline.enable_ip_masking if pipeline else True)
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
                    coro2 = broadcast_alert(alert)
                    asyncio.run_coroutine_threadsafe(coro2, loop)

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
            }
            flow_state[key] = state

        packet_bytes = bytes(packet)
        if len(state["packets"]) < CAPTURE_CONFIG["max_packets_per_flow"]:
            state["packets"].append(packet_bytes)
        state["last_seen"] = now

        # 流已满 → 送出
        if len(state["packets"]) >= CAPTURE_CONFIG["max_packets_per_flow"]:
            flush_flow(key)

    # 主嗅探循环（支持暂停/恢复 + 异常重连）
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
        print("[CAPTURE] 开始嗅探...")
        try:
            sniff(
                iface=iface,
                filter=CAPTURE_CONFIG["bpf_filter"],
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: stop_capture.is_set(),
            )
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
    global capture_thread, stop_capture, _target_iface

    parser = argparse.ArgumentParser(description="OpenDetect 实时后端服务器")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址 (默认 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="监听端口 (默认 8000)")
    parser.add_argument("--iface", default=None, help="网卡名称或 GUID")
    parser.add_argument("--no-capture", action="store_true", help="不启动抓包（仅 API 服务）")
    parser.add_argument("--promiscuous", action="store_true", help="混杂模式")
    parser.add_argument("--list-ifaces", action="store_true", help="列出可用网卡并退出")
    parser.add_argument("--reload", action="store_true", help="开发模式热重载")
    args = parser.parse_args()

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
