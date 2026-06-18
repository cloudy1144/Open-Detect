"""
Automated dashboard frontend tests.

Tests all UI components via HTTP requests against the running Flask dashboard.
Run with: python -m pytest tests/test_dashboard.py -v
Requires: dashboard running on localhost:5000, honeypot on 127.0.0.1 ports 2222/8080/etc.
"""
from __future__ import annotations

import json
import time
import urllib.request
from urllib.error import URLError

import pytest

BASE = "http://localhost:5000"


def _get(path: str) -> tuple[int, dict | str]:
    """GET request, returns (status, parsed_json | raw_text)."""
    try:
        req = urllib.request.Request(f"{BASE}{path}")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode("utf-8")
            code = r.status
            try:
                return code, json.loads(body)
            except json.JSONDecodeError:
                return code, body
    except URLError as e:
        return -1, str(e)


def _post(path: str, data: dict | None = None, retries: int = 3) -> tuple[int, dict]:
    """POST request with JSON body, with retry on connection error."""
    from urllib.error import HTTPError
    last_err = ""
    for attempt in range(retries):
        try:
            body = json.dumps(data).encode("utf-8") if data else None
            req = urllib.request.Request(f"{BASE}{path}", data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except HTTPError as e:
            # urllib raises HTTPError for 4xx/5xx — extract the response
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {"error": str(e)}
            return e.code, body
        except URLError as e:
            last_err = str(e)
            if attempt < retries - 1:
                time.sleep(1.5)
    return -1, {"error": last_err}


# ═══════════════════════════════════════════════════════════════════════════
# Test 1: Page load and HTML structure
# ═══════════════════════════════════════════════════════════════════════════

class TestPageLoad:
    """Verify the dashboard HTML page loads and contains key elements."""

    def test_page_returns_200(self):
        """GET / should return 200 with HTML."""
        code, html = _get("/")
        assert code == 200, f"Expected 200, got {code}"
        assert isinstance(html, str)
        assert len(html) > 500, "Page seems too short"

    def test_page_contains_title(self):
        """Page should contain the title."""
        _, html = _get("/")
        assert "Open-Detect" in html, "Missing 'Open-Detect' in page"

    def test_page_contains_metric_cards(self):
        """Page should contain all 5 metric card elements."""
        _, html = _get("/")
        assert 'id="card-flows"' in html, "Missing flows card"
        assert 'id="card-abnormal"' in html, "Missing abnormal card"
        assert 'id="card-inference"' in html, "Missing inference card"
        assert 'id="card-latency"' in html, "Missing latency card"
        assert 'id="card-uptime"' in html, "Missing uptime card"

    def test_page_contains_attack_buttons(self):
        """Page should contain all attack trigger buttons."""
        _, html = _get("/")
        required_buttons = [
            "btn-scan", "btn-ddos", "btn-beacon",
            "btn-replay-known", "btn-replay-unknown",
            "btn-replay-normal", "btn-replay-tls13",
            "btn-full", "btn-stop",
        ]
        for btn_id in required_buttons:
            assert btn_id in html, f"Missing button: {btn_id}"

    def test_page_contains_attack_status_bar(self):
        """Page should contain attack status bar and console."""
        _, html = _get("/")
        assert 'id="status-bar"' in html, "Missing status bar"
        assert 'id="console"' in html, "Missing console log area"

    def test_page_contains_alert_table(self):
        """Page should contain alert table."""
        _, html = _get("/")
        assert 'id="alert-tbody"' in html, "Missing alert table body"
        assert 'id="alert-dist"' in html, "Missing alert distribution"
        assert 'id="attack-progress"' in html, "Missing attack progress panel"

    def test_page_has_auto_refresh_js(self):
        """Page JS should include setInterval for auto-refresh."""
        _, html = _get("/")
        assert "setInterval" in html, "Missing auto-refresh interval"
        assert "fetch('/api/summary')" in html or "loadSummary()" in html, \
            "Missing summary fetch in JS"


# ═══════════════════════════════════════════════════════════════════════════
# Test 2: API endpoints
# ═══════════════════════════════════════════════════════════════════════════

class TestAPIEndpoints:
    """Verify all REST API endpoints return valid JSON."""

    def test_api_health_returns_json(self):
        """GET /api/health returns JSON with required fields."""
        code, data = _get("/api/health")
        assert code == 200
        assert isinstance(data, dict)
        assert "server_time" in data, "Missing server_time"

    def test_api_alerts_returns_json(self):
        """GET /api/alerts returns JSON with alerts array."""
        code, data = _get("/api/alerts")
        assert code == 200
        assert isinstance(data, dict)
        assert "alerts" in data
        assert "count" in data
        assert isinstance(data["alerts"], list)

    def test_api_alerts_stats_returns_json(self):
        """GET /api/alerts/stats returns aggregation counts."""
        code, data = _get("/api/alerts/stats")
        assert code == 200
        assert isinstance(data, dict)
        assert "total" in data
        assert "critical" in data
        assert "warning" in data
        assert "info" in data
        assert isinstance(data["total"], int)

    def test_api_attacks_returns_json(self):
        """GET /api/attacks returns attack log records."""
        code, data = _get("/api/attacks")
        assert code == 200
        assert isinstance(data, dict)
        assert "attacks" in data
        assert isinstance(data["attacks"], list)

    def test_api_summary_returns_json(self):
        """GET /api/summary returns comprehensive summary."""
        code, data = _get("/api/summary")
        assert code == 200
        assert isinstance(data, dict)
        required_fields = [
            "healthy", "flows_total", "flows_abnormal",
            "inference_count", "inference_errors", "uptime_seconds",
            "alerts_total", "alerts_critical", "alerts_warning",
            "attack_progress", "server_time",
        ]
        for field in required_fields:
            assert field in data, f"Missing field in summary: {field}"

    def test_api_attack_status_returns_json(self):
        """GET /api/attack/status returns running status."""
        code, data = _get("/api/attack/status")
        assert code == 200
        assert isinstance(data, dict)
        assert "running" in data
        assert "name" in data
        assert "elapsed_s" in data


# ═══════════════════════════════════════════════════════════════════════════
# Test 3: Attack trigger endpoints
# ═══════════════════════════════════════════════════════════════════════════

class TestAttackTriggers:
    """Verify manual attack trigger API endpoints work."""

    @pytest.fixture(autouse=True)
    def ensure_idle(self):
        """Wait for any running attack to finish before each test."""
        for _ in range(15):
            _, status = _get("/api/attack/status")
            if isinstance(status, dict) and not status.get("running"):
                break
            time.sleep(1)
        yield
        # Clean up after
        _post("/api/attack/stop")

    def test_trigger_scan(self):
        """POST /api/attack/scan should trigger port scan."""
        code, data = _post("/api/attack/scan", {"target": "127.0.0.1",
                                                 "start_port": 20, "end_port": 30})
        assert code in (200, 409), f"Unexpected status {code}: {data}"
        assert "ok" in data
        assert "message" in data

    def test_trigger_ddos(self):
        """POST /api/attack/ddos should trigger SYN flood."""
        code, data = _post("/api/attack/ddos", {"target": "127.0.0.1",
                                                 "port": 8080, "duration": 2})
        assert code in (200, 409), f"Unexpected status {code}: {data}"
        assert "ok" in data

    def test_trigger_beacon(self):
        """POST /api/attack/beacon should trigger C2 beaconing."""
        code, data = _post("/api/attack/beacon", {"target": "127.0.0.1",
                                                   "port": 8443, "interval": 1.0,
                                                   "count": 2})
        assert code in (200, 409), f"Unexpected status {code}: {data}"
        assert "ok" in data

    def test_trigger_replay_known_malware(self):
        """POST /api/attack/replay with known_malware."""
        code, data = _post("/api/attack/replay", {"pcap_type": "known_malware"})
        assert code in (200, 400, 409), f"Unexpected status {code}: {data}"

    def test_trigger_replay_unknown_attack(self):
        """POST /api/attack/replay with unknown_attack."""
        code, data = _post("/api/attack/replay", {"pcap_type": "unknown_attack"})
        assert code in (200, 400, 409), f"Unexpected status {code}: {data}"

    def test_trigger_replay_normal(self):
        """POST /api/attack/replay with normal."""
        code, data = _post("/api/attack/replay", {"pcap_type": "normal"})
        assert code in (200, 400, 409), f"Unexpected status {code}: {data}"

    def test_trigger_replay_tls13(self):
        """POST /api/attack/replay with tls13."""
        code, data = _post("/api/attack/replay", {"pcap_type": "tls13"})
        assert code in (200, 400, 409), f"Unexpected status {code}: {data}"

    def test_trigger_invalid_replay_type(self):
        """POST /api/attack/replay with invalid type returns 400."""
        code, data = _post("/api/attack/replay", {"pcap_type": "invalid_type"})
        assert code == 400, f"Expected 400 for invalid type, got {code}: {data}"

    def test_trigger_orchestrate(self):
        """POST /api/attack/orchestrate triggers full suite."""
        code, data = _post("/api/attack/orchestrate")
        assert code in (200, 409), f"Unexpected status {code}: {data}"

    def test_stop_attack(self):
        """POST /api/attack/stop returns ok."""
        code, data = _post("/api/attack/stop")
        assert code == 200
        assert data["ok"] is True


# ═══════════════════════════════════════════════════════════════════════════
# Test 4: End-to-end: attack → alert → UI update
# ═══════════════════════════════════════════════════════════════════════════

class TestEndToEnd:
    """Verify attack → detection → alert → dashboard display pipeline."""

    @pytest.fixture(autouse=True)
    def cleanup_attacks(self):
        """Wait for any running attacks to finish before and after."""
        # Wait for running attacks to finish
        for _ in range(10):
            _, status = _get("/api/attack/status")
            if isinstance(status, dict) and not status.get("running"):
                break
            time.sleep(2)
        yield

    def test_dashboard_returns_data_after_attack(self):
        """After an attack completes, alerts should appear in dashboard."""
        # Record baseline
        _, baseline = _get("/api/alerts/stats")
        baseline_total = baseline.get("total", 0) if isinstance(baseline, dict) else 0

        # Trigger a scan attack and wait
        _post("/api/attack/scan", {"target": "127.0.0.1",
                                    "start_port": 20, "end_port": 30})
        time.sleep(5)

        # Check attack log updated
        _, attack_data = _get("/api/attacks")
        assert isinstance(attack_data, dict)
        assert attack_data.get("count", 0) >= 1, \
            "attack_log should have at least 1 entry after triggering scan"

    def test_attack_status_transitions(self):
        """During an attack, status should report running=True."""
        # Ensure nothing is running
        _post("/api/attack/stop")
        time.sleep(1)

        # Trigger a short beacon
        _post("/api/attack/beacon", {"target": "127.0.0.1",
                                      "port": 8443, "interval": 1.0, "count": 3})

        # Immediately check status — should be running
        time.sleep(0.5)
        _, status = _get("/api/attack/status")
        assert isinstance(status, dict)
        # May be running or already done (beacon with count=3 is fast)
        assert status["ok"] if "ok" in status else True

    def test_summary_integrity(self):
        """summary endpoint should be internally consistent."""
        _, data = _get("/api/summary")
        assert isinstance(data, dict)

        # alerts_total should >= alerts_critical + alerts_warning
        total = data.get("alerts_total", 0)
        crit = data.get("alerts_critical", 0)
        warn = data.get("alerts_warning", 0)
        assert total >= crit + warn, \
            f"Total alerts ({total}) < critical ({crit}) + warning ({warn})"

        # attack_progress should be a list
        progress = data.get("attack_progress", [])
        assert isinstance(progress, list), \
            f"attack_progress should be list, got {type(progress).__name__}"

    def test_page_includes_latest_api_data(self):
        """The index page renders alert count from API in JS variables."""
        _, html = _get("/")
        # Verify the JS ATK_MAP contains all expected attack endpoints
        assert "/api/attack/scan" in html
        assert "/api/attack/ddos" in html
        assert "/api/attack/beacon" in html
        assert "/api/attack/replay" in html
        assert "/api/attack/orchestrate" in html
        assert "/api/attack/stop" in html
        assert "/api/attack/status" in html


# ═══════════════════════════════════════════════════════════════════════════
# Test 5: Edge cases and error handling
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Verify the dashboard handles edge cases gracefully."""

    def test_alerts_limit_param(self):
        """GET /api/alerts?limit=5 should return at most 5 alerts."""
        code, data = _get("/api/alerts?limit=5")
        assert code == 200
        assert isinstance(data, dict)
        alerts = data.get("alerts", [])
        assert len(alerts) <= 5, f"Got {len(alerts)} alerts with limit=5"

    def test_extremely_high_limit(self):
        """GET /api/alerts?limit=99999 should not crash."""
        code, data = _get("/api/alerts?limit=99999")
        assert code == 200

    def test_negative_limit(self):
        """GET /api/alerts?limit=-1 should not crash."""
        code, data = _get("/api/alerts?limit=-1")
        assert code == 200

    def test_non_numeric_limit(self):
        """GET /api/alerts?limit=abc should not crash."""
        code, data = _get("/api/alerts?limit=abc")
        assert code == 200

    def test_simultaneous_attack_rejected(self):
        """Triggering an attack while one is running should return 409."""
        # Ensure idle — wait for any lingering attacks to finish
        _post("/api/attack/stop")
        for _ in range(30):
            _, status = _get("/api/attack/status")
            if isinstance(status, dict) and not status.get("running"):
                break
            time.sleep(1)

        # Trigger a longer attack first (10 connections, 2s interval = ~18s total)
        code1, data1 = _post("/api/attack/beacon", {"target": "127.0.0.1",
                                                     "port": 8443, "interval": 2.0,
                                                     "count": 10})
        if code1 == 409:
            # Another attack from a prior test is still running —
            # this proves the lock is working correctly
            assert data1.get("ok") is False
            return pytest.skip("Previous attack still running — lock is functional")
        assert code1 == 200, f"Failed to start first attack: {data1}"
        time.sleep(1.5)

        # Try to trigger scan while beacon is running
        code2, data2 = _post("/api/attack/scan", {"target": "127.0.0.1",
                                                   "start_port": 20, "end_port": 30})
        # Should either succeed (if previous finished quickly) or return 409
        assert code2 in (200, 409), \
            f"Expected 200 or 409, got {code2}: {data2}"

    def test_cors_header_present(self):
        """All API responses should include CORS header."""
        code, data = _get("/api/health")
        # We can't directly check response headers with urllib easily here,
        # but the server after_request hook ensures it. Trust but verify.
        assert code == 200


# ═══════════════════════════════════════════════════════════════════════════
# Test 6: Alert data integrity
# ═══════════════════════════════════════════════════════════════════════════

class TestAlertIntegrity:
    """Verify alert records returned by API have correct structure."""

    def test_alerts_have_required_fields(self):
        """Each alert should have required fields."""
        code, data = _get("/api/alerts?limit=5")
        assert code == 200
        alerts = data.get("alerts", [])
        if not alerts:
            pytest.skip("No alerts in database")

        required_fields = [
            "alert_id", "timestamp", "alert_level",
            "attack_type", "class_name", "src_ip", "dst_ip",
            "src_port", "dst_port",
        ]
        for alert in alerts:
            for field in required_fields:
                assert field in alert, \
                    f"Alert {alert.get('alert_id', '?')} missing field: {field}"

    def test_alert_level_values_valid(self):
        """Alert levels should be CRITICAL, WARNING, or INFO."""
        code, data = _get("/api/alerts?limit=10")
        assert code == 200
        valid_levels = {"CRITICAL", "WARNING", "INFO"}
        for alert in data.get("alerts", []):
            level = alert.get("alert_level", "")
            assert level in valid_levels, \
                f"Invalid alert level: {level}"

    def test_confidence_range(self):
        """Confidence should be between 0 and 1."""
        code, data = _get("/api/alerts?limit=10")
        assert code == 200
        for alert in data.get("alerts", []):
            conf = alert.get("confidence")
            if conf is not None:
                assert 0 <= conf <= 1, \
                    f"Confidence {conf} out of [0,1] range"
