/* ============================================================
   OpenDetect — 图表初始化与更新
   ============================================================ */

const Charts = {};

// ---------- 全局 Chart.js 默认配置 (蓝白科技风) ----------
Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.color = '#64748B';

// 蓝色系调色板
const BLUE_PALETTE = [
    '#2563EB', '#3B82F6', '#60A5FA', '#93C5FD', '#BFDBFE',
    '#1D4ED8', '#1E40AF', '#1E3A8A'
];
const ALERT_PALETTE = ['#EF4444', '#F59E0B', '#10B981', '#64748B'];

// ---------- 通用 tooltip ----------
const tooltipStyle = {
    backgroundColor: 'rgba(15,23,42,0.9)',
    titleFont: { size: 13, weight: '600' },
    bodyFont: { size: 12 },
    padding: 10,
    cornerRadius: 8,
    titleColor: '#F1F5F9',
    bodyColor: '#CBD5E1',
};

// ============================================================
// 1. 协议分布图 — 环形图
// ============================================================
function initProtocolChart() {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    Charts.protocol = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', '其他'],
            datasets: [{
                data: [35, 20, 18, 15, 8, 4],
                backgroundColor: ['#2563EB', '#3B82F6', '#60A5FA', '#93C5FD', '#BFDBFE', '#E2E8F0'],
                borderWidth: 0,
                hoverOffset: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 12,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        font: { size: 12 },
                    }
                },
                tooltip: tooltipStyle,
            },
        }
    });
}

function updateProtocolChart(flows) {
    if (!Charts.protocol) return;
    const counts = {};
    const total = flows.length || 1;
    flows.forEach(f => {
        const proto = f.protocol || '其他';
        counts[proto] = (counts[proto] || 0) + 1;
    });

    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const top = sorted.slice(0, 5);
    const others = sorted.slice(5).reduce((sum, [, c]) => sum + c, 0);

    const labels = top.map(([k]) => k);
    const data = top.map(([, v]) => v);
    if (others > 0) { labels.push('其他'); data.push(others); }

    Charts.protocol.data.labels = labels;
    Charts.protocol.data.datasets[0].data = data;
    Charts.protocol.data.datasets[0].backgroundColor = BLUE_PALETTE.slice(0, labels.length);
    Charts.protocol.update('none');
}

// ============================================================
// 2. 流量趋势图 — 折线图 (60 秒滑动窗口)
// ============================================================
function initTrendChart() {
    const ctx = document.getElementById('trendChart').getContext('2d');
    const now = new Date();
    const labels = Array.from({length: 60}, (_, i) => {
        const d = new Date(now - (59 - i) * 1000);
        return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    });

    Charts.trend = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: '总流量',
                    data: Array(60).fill(0),
                    borderColor: '#3B82F6',
                    backgroundColor: 'rgba(59,130,246,0.06)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 1,
                    pointHoverRadius: 4,
                    borderWidth: 2,
                },
                {
                    label: '异常流量',
                    data: Array(60).fill(0),
                    borderColor: '#EF4444',
                    backgroundColor: 'rgba(239,68,68,0.06)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 1,
                    pointHoverRadius: 4,
                    borderWidth: 2,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        padding: 16,
                        font: { size: 12 },
                    }
                },
                tooltip: tooltipStyle,
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { maxTicksLimit: 10, font: { size: 11 } },
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0,0,0,0.04)' },
                    ticks: { font: { size: 11 }, stepSize: 1 },
                }
            },
        }
    });
}

function updateTrendChart(totalCounts, abnormalCounts, labels) {
    if (!Charts.trend) return;
    Charts.trend.data.datasets[0].data = totalCounts;
    Charts.trend.data.datasets[1].data = abnormalCounts;
    if (labels) Charts.trend.data.labels = labels;
    Charts.trend.update('none');
}

// ============================================================
// 3. 准确率 & F1 趋势图
// ============================================================
function initAccuracyTrendChart() {
    const ctx = document.getElementById('accuracyTrendChart').getContext('2d');
    const labels = Array.from({length: 20}, (_, i) => `T-${20 - i}`);

    Charts.accuracy = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: '准确率',
                    data: Array(20).fill(0.967),
                    borderColor: '#2563EB',
                    backgroundColor: 'rgba(37,99,235,0.08)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 2,
                    pointHoverRadius: 5,
                    borderWidth: 2,
                },
                {
                    label: 'F1 分数',
                    data: Array(20).fill(0.954),
                    borderColor: '#10B981',
                    backgroundColor: 'rgba(16,185,129,0.08)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 2,
                    pointHoverRadius: 5,
                    borderWidth: 2,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { usePointStyle: true, padding: 16, font: { size: 12 } },
                },
                tooltip: {
                    ...tooltipStyle,
                    callbacks: {
                        label: ctx => `${ctx.dataset.label}: ${(ctx.parsed.y * 100).toFixed(1)}%`
                    }
                },
            },
            scales: {
                x: { grid: { display: false }, ticks: { font: { size: 11 } } },
                y: {
                    min: 0.85,
                    max: 1.0,
                    grid: { color: 'rgba(0,0,0,0.04)' },
                    ticks: {
                        font: { size: 11 },
                        callback: v => (v * 100).toFixed(0) + '%',
                    }
                }
            },
        }
    });
}

function updateAccuracyTrend(newAcc, newF1) {
    if (!Charts.accuracy) return;
    const accData = Charts.accuracy.data.datasets[0].data;
    const f1Data = Charts.accuracy.data.datasets[1].data;
    accData.push(newAcc);
    f1Data.push(newF1);
    if (accData.length > 30) { accData.shift(); f1Data.shift(); }
    Charts.accuracy.update('none');
}

// ============================================================
// 4. 检测延迟直方图
// ============================================================
function initLatencyHistChart() {
    const ctx = document.getElementById('latencyHistChart').getContext('2d');
    Charts.latency = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['0-5', '5-10', '10-15', '15-20', '20-30', '30-50', '50+'],
            datasets: [{
                label: '延迟分布',
                data: [5, 18, 35, 22, 12, 6, 2],
                backgroundColor: ['#BFDBFE', '#93C5FD', '#60A5FA', '#3B82F6', '#2563EB', '#1D4ED8', '#1E40AF'],
                borderRadius: 4,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    ...tooltipStyle,
                    callbacks: {
                        label: ctx => `${ctx.parsed.y} 条 (${ctx.label} ms)`
                    }
                },
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 11 } },
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0,0,0,0.04)' },
                    ticks: { font: { size: 11 }, stepSize: 5 },
                }
            },
        }
    });
}

function updateLatencyHist(newLatencies) {
    if (!Charts.latency) return;
    const bins = [0, 5, 10, 15, 20, 30, 50, Infinity];
    const counts = Array(7).fill(0);
    newLatencies.forEach(l => {
        for (let i = 0; i < bins.length - 1; i++) {
            if (l >= bins[i] && l < bins[i + 1]) { counts[i]++; break; }
        }
    });
    // 平滑融合: 70% 旧值 + 30% 新值
    Charts.latency.data.datasets[0].data = Charts.latency.data.datasets[0].data.map((old, i) =>
        +(old * 0.7 + counts[i] * 0.3).toFixed(0)
    );
    Charts.latency.update('none');
}

// ============================================================
// 5. 攻击类型分布图
// ============================================================
function initAttackTypeChart() {
    const ctx = document.getElementById('attackTypeChart').getContext('2d');
    Charts.attackType = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '攻击次数',
                data: [],
                backgroundColor: '#EF4444',
                borderRadius: 4,
                borderSkipped: false,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: tooltipStyle,
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(0,0,0,0.04)' },
                    ticks: { font: { size: 11 }, stepSize: 1 },
                },
                y: {
                    grid: { display: false },
                    ticks: { font: { size: 11 } },
                }
            },
        }
    });
}

function updateAttackTypeChart(alerts) {
    if (!Charts.attackType) return;
    const counts = {};
    alerts.forEach(a => {
        const name = a.class_name || a.attack_type || 'unknown';
        counts[name] = (counts[name] || 0) + 1;
    });
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const top6 = sorted.slice(0, 6);
    Charts.attackType.data.labels = top6.map(([k]) => k);
    Charts.attackType.data.datasets[0].data = top6.map(([, v]) => v);
    Charts.attackType.data.datasets[0].backgroundColor = top6.map((_, i) =>
        i === 0 ? '#EF4444' : `rgba(239,68,68,${1 - i * 0.12})`
    );
    Charts.attackType.update('none');
}

// ============================================================
// 6. 告警等级占比图
// ============================================================
function initAlertLevelChart() {
    const ctx = document.getElementById('alertLevelChart').getContext('2d');
    Charts.alertLevel = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['严重 (CRITICAL)', '警告 (WARNING)', '信息 (INFO)'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#EF4444', '#F59E0B', '#94A3B8'],
                borderWidth: 0,
                hoverOffset: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 12, usePointStyle: true, font: { size: 11 } },
                },
                tooltip: tooltipStyle,
            },
        }
    });
}

function updateAlertLevelChart(alerts) {
    if (!Charts.alertLevel) return;
    let critical = 0, warning = 0, info = 0;
    alerts.forEach(a => {
        const level = (a.alert_level || 'INFO').toUpperCase();
        if (level === 'CRITICAL') critical++;
        else if (level === 'WARNING') warning++;
        else info++;
    });
    Charts.alertLevel.data.datasets[0].data = [critical, warning, info || 1];
    Charts.alertLevel.update('none');
}

// ============================================================
// 初始化所有图表
// ============================================================
function initAllCharts() {
    initProtocolChart();
    initTrendChart();
    initAccuracyTrendChart();
    initLatencyHistChart();
    initAttackTypeChart();
    initAlertLevelChart();
}
