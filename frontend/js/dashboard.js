/* ============================================================
   OpenDetect — 主面板逻辑
   通过 WebSocket 连接后端引擎，渲染实时检测数据
   ============================================================ */

// ============================================================
// 状态管理
// ============================================================
const State = {
    flows: [],
    alerts: [],
    trendTotal: Array(60).fill(0),
    trendAbnormal: Array(60).fill(0),
    trendLabels: [],
    paused: false,
    startTime: Date.now(),
    wsConnected: false,

    // 性能统计（由后端推送）
    stats: {
        total_flows: 0,
        total_abnormal: 0,
        total_alerts: 0,
        avg_latency_ms: 0,
        min_latency_ms: 0,
        max_latency_ms: 0,
        throughput: 0,
        window_flows: 0,
        window_abnormal: 0,
        uptime: 0,
    },

    // 累积的延迟数据（用于直方图）
    latencySamples: [],
    accuracyHistory: [],   // 用于 Acc 趋势图（后端没有真实准确率时用回推数据）
    f1History: [],
};

// 初始化趋势标签
(function initTrendLabels() {
    const now = new Date();
    State.trendLabels = Array.from({ length: 60 }, (_, i) => {
        const d = new Date(now - (59 - i) * 1000);
        return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    });
})();

// ============================================================
// 工具函数
// ============================================================
function formatTime(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatFullTime(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleString('zh-CN');
}

function fmtPercent(v) { return (v * 100).toFixed(1) + '%'; }

function fmtLatency(v) { return (v || 0).toFixed(1) + ' ms'; }

function fmtThroughput(v) { return (v || 0).toFixed(1) + ' 条/s'; }

function flowTag(flow) {
    if (flow.is_unknown) return '<span class="tag tag-unknown">未知攻击</span>';
    if (flow.is_abnormal) return '<span class="tag tag-abnormal">异常</span>';
    return '<span class="tag tag-normal">正常</span>';
}

function alertLevelTag(level) {
    const l = (level || 'INFO').toUpperCase();
    if (l === 'CRITICAL') return '<span class="tag tag-critical">严重</span>';
    if (l === 'WARNING') return '<span class="tag tag-warning">警告</span>';
    return '<span class="tag tag-info">信息</span>';
}

// ============================================================
// Toast 通知
// ============================================================
function showToast({ title, desc, level = 'warning', duration = 5000 }) {
    const container = document.getElementById('toastContainer');
    const icons = {
        critical: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };

    const toast = document.createElement('div');
    toast.className = `toast ${level}`;
    toast.innerHTML = `
        <div class="toast-icon">${icons[level] || icons.info}</div>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-desc">${desc}</div>
            <div class="toast-time">${new Date().toLocaleTimeString('zh-CN')}</div>
        </div>
    `;
    toast.addEventListener('click', () => toast.remove());
    container.appendChild(toast);

    setTimeout(() => {
        if (toast.parentNode) toast.remove();
    }, duration);
}

// ============================================================
// 告警弹窗
// ============================================================
function showAlertModal(alert) {
    document.getElementById('alertModal').classList.add('active');
    document.getElementById('modalAttackType').textContent = alert.class_name || alert.attack_type || '未知';
    document.getElementById('modalLevel').textContent = alert.alert_level || 'INFO';
    document.getElementById('modalLevel').style.color =
        (alert.alert_level || '').toUpperCase() === 'CRITICAL' ? '#EF4444' :
        (alert.alert_level || '').toUpperCase() === 'WARNING' ? '#F59E0B' : '#64748B';
    document.getElementById('modalSrcIP').textContent = `${alert.src_ip}:${alert.src_port}`;
    document.getElementById('modalDstIP').textContent = `${alert.dst_ip}:${alert.dst_port}`;
    document.getElementById('modalConfidence').textContent = fmtPercent(alert.confidence);
    document.getElementById('modalDistance').textContent = (alert.kl_distance || 0).toFixed(4);
    document.getElementById('modalTime').textContent = formatFullTime(alert.timestamp);
}

function closeAlertModal() {
    document.getElementById('alertModal').classList.remove('active');
}

document.getElementById('alertModal').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeAlertModal();
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAlertModal();
});

// ============================================================
// 面板切换
// ============================================================
document.querySelectorAll('.nav-tab').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const tab = btn.dataset.tab;
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.getElementById(`panel-${tab}`).classList.add('active');
    });
});

// ============================================================
// 流量表格更新（全部历史保留，滚动查看）
// ============================================================
function updateFlowTable() {
    const tbody = document.getElementById('flowTableBody');
    const flows = State.flows;

    if (flows.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">等待后端流量数据接入 ...</td></tr>';
        return;
    }

    // 全部保留，最新在上（倒序）
    tbody.innerHTML = flows.slice().reverse().map(f => `
        <tr>
            <td>${formatTime(f.timestamp)}</td>
            <td>${f.src_ip}</td>
            <td>${f.dst_ip}</td>
            <td>${f.protocol || '--'}</td>
            <td>${f.class_name || '--'}</td>
            <td>${(f.confidence * 100).toFixed(1)}%</td>
            <td>${flowTag(f)}</td>
        </tr>
    `).join('');
}

// ============================================================
// 告警筛选状态（stat-card 点击 + 下拉框联动）
// ============================================================
State.alertFilter = 'all';

function filterAlerts(value) {
    State.alertFilter = value;
    // 同步下拉框
    const dropdown = document.getElementById('alertLevelFilter');
    if (value === 'today') dropdown.value = 'all';
    else dropdown.value = value;
    // 高亮选中的 stat-card
    document.querySelectorAll('#panel-alerts .stats-row .stat-card.clickable').forEach(el => {
        el.classList.toggle('active-filter', (el.getAttribute('onclick') || '').includes(`'${value}'`));
    });
    updateAlertTable();
}

// ============================================================
// 告警表格更新
// ============================================================
function updateAlertTable() {
    const tbody = document.getElementById('alertTableBody');
    const dropdown = document.getElementById('alertLevelFilter').value;
    let alerts = State.alerts;

    // 基于 stat-card 筛选
    const filter = State.alertFilter;
    if (filter === 'today') {
        const todayStr = new Date().toDateString();
        alerts = alerts.filter(a => new Date(a.timestamp * 1000).toDateString() === todayStr);
    } else if (filter !== 'all') {
        alerts = alerts.filter(a => (a.alert_level || '').toUpperCase() === filter);
    }
    // 下拉框附加筛选（当 stat-card = all 时）
    if (dropdown !== 'all' && filter === 'all') {
        alerts = alerts.filter(a => (a.alert_level || '').toUpperCase() === dropdown);
    }

    if (alerts.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">暂无告警记录</td></tr>';
        return;
    }

    const display = alerts.slice().reverse();
    tbody.innerHTML = display.map(a => {
        const safeAttrs = {
            class_name: a.class_name || '未知',
            attack_type: a.attack_type || '',
            alert_level: a.alert_level || 'INFO',
            src_ip: a.src_ip || '--',
            dst_ip: a.dst_ip || '--',
            src_port: a.src_port || 0,
            dst_port: a.dst_port || 0,
            confidence: a.confidence || 0,
            kl_distance: a.kl_distance || 0,
            timestamp: a.timestamp,
        };
        return `<tr style="cursor:pointer" onclick='showAlertModal(${JSON.stringify(safeAttrs)})'>
            <td>${formatTime(a.timestamp)}</td>
            <td>${a.class_name || a.attack_type || '未知'}</td>
            <td>${a.src_ip}</td>
            <td>${a.dst_ip}</td>
            <td>${alertLevelTag(a.alert_level)}</td>
            <td>${fmtPercent(a.confidence)}</td>
            <td>${(a.kl_distance || 0).toFixed(4)}</td>
        </tr>`;
    }).join('');
}

// ============================================================
// 概览统计数据更新
// ============================================================
function updateStats() {
    const s = State.stats;
    const total = s.total_flows || 0;
    const abnormal = s.total_abnormal || 0;
    const lat = s.avg_latency_ms || 0;
    const alertsCount = State.alerts.length;

    document.getElementById('totalFlows').textContent = total;
    document.getElementById('abnormalFlows').textContent = abnormal;
    document.getElementById('accuracyDisplay').textContent = s.accuracy != null ? fmtPercent(s.accuracy) : '--';
    document.getElementById('latencyDisplay').textContent = lat ? fmtLatency(lat) : '--';
    document.getElementById('flowCountLabel').textContent = `${State.flows.length} 条`;

    // 告警概览
    const critical = State.alerts.filter(a => (a.alert_level || '').toUpperCase() === 'CRITICAL').length;
    const warning = State.alerts.filter(a => (a.alert_level || '').toUpperCase() === 'WARNING').length;
    const today = State.alerts.filter(a => {
        const d = new Date(a.timestamp * 1000);
        return d.toDateString() === new Date().toDateString();
    }).length;

    document.getElementById('totalAlerts').textContent = alertsCount;
    document.getElementById('criticalAlerts').textContent = critical;
    document.getElementById('warningAlerts').textContent = warning;
    document.getElementById('todayAlerts').textContent = today;

    // 告警徽章
    const badge = document.getElementById('alertBadge');
    badge.textContent = alertsCount;
    badge.style.display = alertsCount > 0 ? 'inline' : 'none';

    // 性能指标面板
    document.getElementById('metricAccuracy').textContent = s.accuracy != null ? fmtPercent(s.accuracy) : '--';
    document.getElementById('metricF1').textContent = s.f1_score != null ? fmtPercent(s.f1_score) : '--';
    document.getElementById('metricFPR').textContent = s.fpr != null ? fmtPercent(s.fpr) : '--';
    document.getElementById('metricLatency').textContent = lat ? fmtLatency(lat) : '--';

    // 性能详情表
    document.getElementById('mCurLatency').textContent = lat ? fmtLatency(lat) : '--';
    document.getElementById('mBestLatency').textContent = s.min_latency_ms ? fmtLatency(s.min_latency_ms) : '--';
    document.getElementById('mAvgLatency').textContent = lat ? fmtLatency(lat) : '--';
    document.getElementById('mCurThroughput').textContent = s.throughput ? fmtThroughput(s.throughput) : '--';
    document.getElementById('mBestThroughput').textContent = '--';
    document.getElementById('mAvgThroughput').textContent = s.throughput ? fmtThroughput(s.throughput) : '--';
    document.getElementById('mCurAcc').textContent = s.accuracy != null ? fmtPercent(s.accuracy) : '--';
    document.getElementById('mBestAcc').textContent = s.accuracy != null ? fmtPercent(s.accuracy) : '--';
    document.getElementById('mAvgAcc').textContent = s.accuracy != null ? fmtPercent(s.accuracy) : '--';
    document.getElementById('mCurDetect').textContent = s.recall != null ? fmtPercent(s.recall) : '--';
    document.getElementById('mBestDetect').textContent = s.recall != null ? fmtPercent(s.recall) : '--';
    document.getElementById('mAvgDetect').textContent = s.recall != null ? fmtPercent(s.recall) : '--';

    // 系统信息
    document.getElementById('sysThreshold').textContent = `5.0（测试集 ${s.accuracy != null ? fmtPercent(s.accuracy) : '--'} / ${s.benchmark_samples || '--'} 样本）`;
    document.getElementById('sysTotalFlows').textContent = total;
    document.getElementById('sysTotalAlerts').textContent = alertsCount;

    const uptime = Math.floor((Date.now() - State.startTime) / 1000);
    const h = Math.floor(uptime / 3600);
    const m = Math.floor((uptime % 3600) / 60);
    const s2 = uptime % 60;
    document.getElementById('sysUptime').textContent = `${h} 小时 ${m} 分 ${s2} 秒`;
}

// ============================================================
// 趋势数据更新
// ============================================================
function shiftTrend(windowTotal, windowAbnormal) {
    State.trendTotal.push(windowTotal);
    State.trendAbnormal.push(windowAbnormal);
    State.trendTotal.shift();
    State.trendAbnormal.shift();
    State.trendLabels.shift();
    State.trendLabels.push(new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
}

// ============================================================
// 处理来自后端的实时消息
// ============================================================
function handleWSMessage(data) {
    switch (data.type) {

        // ── 新流量 ──
        case 'flow': {
            const f = data.data;
            const flow = {
                flow_id: f.flow_id,
                src_ip: f.src_ip,
                dst_ip: f.dst_ip,
                src_port: f.src_port,
                dst_port: f.dst_port,
                protocol: f.protocol,
                timestamp: f.timestamp,
                class_name: f.class_name || '--',
                confidence: f.confidence || 0,
                distance: f.distance || 0,
                is_unknown: f.is_unknown || false,
                is_abnormal: f.is_abnormal || false,
                attack_type: f.attack_type || 'normal',
                alert_level: f.alert_level || 'INFO',
            };

            State.flows.push(flow);

            // 限制内存
            if (State.flows.length > 2000) {
                State.flows.splice(0, State.flows.length - 1000);
            }

            // 更新流量表格
            updateFlowTable();

            // 更新协议分布
            updateProtocolChart(State.flows.slice(-200));
            // 趋势由定时器驱动，不在 flow 里更新

            break;
        }

        // ── 新告警 ──
        case 'alert': {
            const a = data.data;
            const alert = {
                alert_id: a.alert_id || `alert-${Date.now()}`,
                flow_id: a.flow_id || '',
                src_ip: a.src_ip || '--',
                dst_ip: a.dst_ip || '--',
                src_port: a.src_port || 0,
                dst_port: a.dst_port || 0,
                alert_level: a.alert_level || 'WARNING',
                attack_type: a.attack_type || 'unknown_attack',
                timestamp: a.timestamp || (Date.now() / 1000),
                class_name: a.class_name || 'Unknown Attack',
                confidence: a.confidence || 0,
                kl_distance: a.kl_distance || 0,
            };

            State.alerts.push(alert);

            if (State.alerts.length > 500) {
                State.alerts.splice(0, State.alerts.length - 300);
            }

            // 更新告警表格
            updateAlertTable();

            // 更新告警图表
            updateAttackTypeChart(State.alerts);
            updateAlertLevelChart(State.alerts);

            // Toast 通知
            const level = alert.alert_level === 'CRITICAL' ? 'critical' : 'warning';
            showToast({
                title: `🚨 检测到 ${alert.class_name || '未知攻击'}`,
                desc: `源 ${alert.src_ip}:${alert.src_port} → 目标 ${alert.dst_ip}:${alert.dst_port}`,
                level,
                duration: 6000,
            });

            // 严重告警弹窗（前 3 条自动弹出）
            if (alert.alert_level === 'CRITICAL' && State.alerts.length <= 3) {
                setTimeout(() => showAlertModal(alert), 500);
            }

            break;
        }

        // ── 统计数据（每 2 秒推送） ──
        case 'stats': {
            const s = data.data;
            State.stats = {
                total_flows: s.total_flows || 0,
                total_abnormal: s.total_abnormal || 0,
                total_alerts: s.total_alerts || 0,
                avg_latency_ms: s.avg_latency_ms || 0,
                min_latency_ms: s.min_latency_ms || 0,
                max_latency_ms: s.max_latency_ms || 0,
                throughput: s.throughput || 0,
                window_flows: s.window_flows || 0,
                window_abnormal: s.window_abnormal || 0,
                uptime: s.uptime || 0,
                accuracy: s.accuracy,
                f1_score: s.f1_score,
                fpr: s.fpr,
                precision: s.precision,
                recall: s.recall,
                benchmark_samples: s.benchmark_samples,
            };

            // 收集延迟样本用于直方图
            if (s.avg_latency_ms > 0) {
                State.latencySamples.push(s.avg_latency_ms);
                if (State.latencySamples.length > 100) {
                    State.latencySamples = State.latencySamples.slice(-50);
                }
                updateLatencyHist(State.latencySamples);
            }

            // 更新准确率趋势图
            if (s.accuracy != null) {
                updateAccuracyTrend(s.accuracy, s.f1_score || s.accuracy);
            }

            // 更新所有统计数字
            updateStats();

            break;
        }

        // ── 连接成功 ──
        case 'connected': {
            State.wsConnected = true;
            document.querySelector('.status-dot').classList.add('live');
            document.getElementById('statusText').textContent = '后端已连接';
            document.getElementById('statusText').style.color = '#10B981';
            showToast({
                title: '已连接后端检测引擎',
                desc: data.data?.message || 'WebSocket 连接成功',
                level: 'info',
                duration: 3000,
            });
            break;
        }

        // ── 错误消息 ──
        case 'error': {
            const msg = data.data?.message || '未知错误';
            console.error('[WS ERROR]', msg);
            showToast({
                title: '⚠ 系统错误',
                desc: msg,
                level: 'warning',
                duration: 8000,
            });
            break;
        }

        // ── 命令确认（暂停/恢复） ──
        case 'command_ack': {
            const info = data.data || {};
            document.querySelector('.status-dot').classList.toggle('live', info.capture_active);
            document.getElementById('statusText').textContent =
                info.capture_active ? '系统运行中' : '已暂停';
            document.getElementById('statusText').style.color =
                info.capture_active ? '#10B981' : '#F59E0B';
            break;
        }
    }
}

// ============================================================
// WebSocket 连接管理（自动重连）
// ============================================================
function connectWebSocket() {
    // 自动推导地址：如果页面由后端提供就用当前地址，否则默认 8000
    const host = location.hostname || 'localhost';
    const port = location.port || '8000';
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${host}:${port}/ws`;

    console.log(`[WS] 正在连接 ${wsUrl} ...`);

    const ws = new WebSocket(wsUrl);
    let reconnectTimer = null;
    let isClosed = false;

    ws.onopen = () => {
        console.log('[WS] 已连接');
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleWSMessage(data);
        } catch (e) {
            console.warn('[WS] 数据解析失败:', e);
        }
    };

    ws.onclose = (event) => {
        State.wsConnected = false;
        document.querySelector('.status-dot').classList.remove('live');
        document.getElementById('statusText').textContent = '连接断开，正在重连...';
        document.getElementById('statusText').style.color = '#EF4444';

        // 非正常关闭时自动重连
        if (!isClosed && !event.wasClean) {
            console.log(`[WS] 断开(code=${event.code})，3 秒后重连...`);
            reconnectTimer = setTimeout(connectWebSocket, 3000);
        }
    };

    ws.onerror = () => {
        console.error('[WS] 连接错误');
        ws.close();
    };

    // 提供给外部用于手动关闭
    State.ws = ws;
    State._closeWS = () => {
        isClosed = true;
        clearTimeout(reconnectTimer);
        ws.close();
    };
}

// ============================================================
// 暂停 / 恢复（通过 WebSocket 通知后端）
// ============================================================
document.getElementById('pauseBtn').addEventListener('click', () => {
    State.paused = !State.paused;
    const btn = document.getElementById('pauseBtn');

    if (State.ws && State.ws.readyState === WebSocket.OPEN) {
        State.ws.send(JSON.stringify({
            action: State.paused ? 'pause' : 'resume',
        }));
    }

    btn.innerHTML = State.paused
        ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>'
        : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>';
    document.getElementById('statusText').textContent = State.paused ? '已暂停' : '系统运行中';
    document.getElementById('statusText').style.color = State.paused ? '#F59E0B' : State.wsConnected ? '#10B981' : '#94A3B8';
    document.querySelector('.status-dot').classList.toggle('live', !State.paused && State.wsConnected);
});

// ============================================================
// 清空告警
// ============================================================
document.getElementById('clearAlertsBtn').addEventListener('click', () => {
    State.alerts = [];
    updateAlertTable();
    updateStats();
    updateAttackTypeChart(State.alerts);
    updateAlertLevelChart(State.alerts);
    document.getElementById('alertBadge').style.display = 'none';
    showToast({ title: '告警已清空', desc: '所有告警记录已被清除', level: 'info', duration: 3000 });
});

// ============================================================
// 告警等级筛选
// ============================================================
document.getElementById('alertLevelFilter').addEventListener('change', function() {
    // 下拉框变化时触发对应的 stat-card 筛选
    filterAlerts(this.value);
});

// ============================================================
// 时钟更新
// ============================================================
function updateClock() {
    document.getElementById('currentTime').textContent =
        new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ============================================================
// 初始化
// ============================================================
function init() {
    initAllCharts();
    updateStats();
    updateFlowTable();
    updateAlertTable();
    updateClock();

    // 时钟
    setInterval(updateClock, 1000);

    // 趋势图定时器：每秒基于全部历史重新计算 60s 窗口（暂停时冻结）
    setInterval(() => {
        if (State.paused) return;
        const now = Date.now() / 1000;
        const windowTotal = State.flows.filter(f => (now - f.timestamp) <= 60).length;
        const windowAbnormal = State.flows.filter(f => f.is_abnormal && (now - f.timestamp) <= 60).length;
        shiftTrend(windowTotal, windowAbnormal);
        updateTrendChart(State.trendTotal, State.trendAbnormal, State.trendLabels);
    }, 1000);

    // 连接 WebSocket
    connectWebSocket();

    // 如果 5 秒后还未收到任何数据，给出提示
    setTimeout(() => {
        if (State.flows.length === 0) {
            showToast({
                title: '等待数据中...',
                desc: '请确认后端服务器已启动，并且网卡捕获正在运行',
                level: 'info',
                duration: 8000,
            });
        }
    }, 5000);

    console.log('[OpenDetect] 可视化界面已初始化（WebSocket 模式）');
    console.log('[OpenDetect] 等待后端检测引擎数据推送...');
    console.log('[OpenDetect] 启动方式: cd 项目根目录 && python frontend/server.py');
}

document.addEventListener('DOMContentLoaded', init);
