"""Protocol metadata extractors for alert enrichment.

Parses raw packet bytes to extract human-readable protocol fields
without modifying the model or inference pipeline. Output fields
are pure annotations appended to alert.extra and log output.

Supported:
  - TLS ClientHello: SNI, version, cipher suites
  - DNS queries: qname, qtype
  - HTTP requests: Host, URI, Method
  - Generic: TCP flags, payload sizes, inter-arrival times
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from .flow_manager import FlowData


@dataclass
class ProtocolMetadata:
    """Extracted protocol fields from a flow."""
    # TLS
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher_count: int = 0

    # DNS
    dns_queries: list[str] = field(default_factory=list)

    # HTTP
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    http_method: Optional[str] = None
    http_user_agent: Optional[str] = None

    # Generic
    payload_total_bytes: int = 0
    packet_sizes: list[int] = field(default_factory=list)
    inter_arrival_ms: list[float] = field(default_factory=list)
    tcp_flags_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Compact serialization, omitting None/empty fields."""
        d: dict[str, Any] = {}
        if self.tls_sni:
            d["tls_sni"] = self.tls_sni
        if self.tls_version:
            d["tls_version"] = self.tls_version
        if self.tls_cipher_count:
            d["tls_cipher_count"] = self.tls_cipher_count
        if self.dns_queries:
            d["dns_queries"] = self.dns_queries
        if self.http_host:
            d["http_host"] = self.http_host
        if self.http_uri:
            d["http_uri"] = self.http_uri
        if self.http_method:
            d["http_method"] = self.http_method
        if self.http_user_agent:
            d["http_user_agent"] = self.http_user_agent
        d["payload_total_bytes"] = self.payload_total_bytes
        d["packet_sizes"] = self.packet_sizes[:10]  # top 10
        if self.inter_arrival_ms:
            d["inter_arrival_ms"] = [round(x, 2) for x in self.inter_arrival_ms[:10]]
        if self.tcp_flags_summary:
            d["tcp_flags"] = self.tcp_flags_summary
        return d


# ============================================================
# TLS ClientHello parser
# ============================================================

def _parse_tls_clienthello(payload: bytes) -> dict[str, Any]:
    """Extract SNI, version, and cipher count from a TLS ClientHello."""
    result: dict[str, Any] = {}
    if len(payload) < 43:
        return result

    try:
        # Record layer
        content_type = payload[0]
        if content_type != 0x16:  # handshake
            return result

        tls_version = struct.unpack("!H", payload[1:3])[0]
        if tls_version == 0x0301:
            result["tls_version"] = "TLS1.0"
        elif tls_version == 0x0302:
            result["tls_version"] = "TLS1.1"
        elif tls_version == 0x0303:
            result["tls_version"] = "TLS1.2"
        elif tls_version == 0x0304:
            result["tls_version"] = "TLS1.3"
        else:
            result["tls_version"] = f"0x{tls_version:04x}"

        # Handshake header
        offset = 5
        if payload[offset] != 0x01:  # ClientHello
            return result

        # Skip 3-byte handshake length + 2-byte version + 32-byte random
        offset = 5 + 3 + 2 + 32

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(payload):
            return result
        cipher_suites_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        result["tls_cipher_count"] = cipher_suites_len // 2
        offset += 2 + cipher_suites_len

        # Compression methods (1 byte len + values)
        if offset >= len(payload):
            return result
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(payload):
            return result
        ext_len = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 <= min(ext_end, len(payload)):
            ext_type = struct.unpack("!H", payload[offset:offset + 2])[0]
            ext_data_len = struct.unpack("!H", payload[offset + 2:offset + 4])[0]
            offset += 4

            if ext_type == 0x0000 and offset + 5 <= len(payload):
                # SNI extension (server_name)
                sni_list_len = struct.unpack("!H", payload[offset:offset + 2])[0]
                sni_offset = offset + 2
                if sni_offset + 3 <= len(payload):
                    entry_type = payload[sni_offset]
                    entry_len = struct.unpack("!H", payload[sni_offset + 1:sni_offset + 3])[0]
                    sni_data = payload[sni_offset + 3:sni_offset + 3 + entry_len]
                    if entry_type == 0:
                        try:
                            result["tls_sni"] = sni_data.decode("ascii", errors="replace")
                        except Exception:
                            pass
                break  # SNI found, stop

            offset += ext_data_len

    except (struct.error, IndexError):
        pass

    return result


# ============================================================
# DNS parser
# ============================================================

def _parse_dns_query(payload: bytes) -> dict[str, Any]:
    """Extract DNS query names from a DNS packet payload."""
    result: dict[str, Any] = {"dns_queries": []}
    if len(payload) < 12:
        return result

    try:
        # DNS header: skip 12 bytes to get to question section
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount == 0:
            return result

        offset = 12
        for _ in range(min(qdcount, 5)):  # max 5 queries
            labels = []
            while offset < len(payload) and payload[offset] != 0:
                label_len = payload[offset]
                if label_len >= 0xC0:  # pointer (compressed name)
                    break
                offset += 1
                if offset + label_len <= len(payload):
                    label = payload[offset:offset + label_len]
                    try:
                        labels.append(label.decode("ascii", errors="replace"))
                    except Exception:
                        labels.append("?")
                    offset += label_len
                else:
                    break
            offset += 1  # skip zero byte
            if labels:
                result["dns_queries"].append(".".join(labels))
            # Skip QTYPE (2) + QCLASS (2)
            offset += 4

    except (struct.error, IndexError):
        pass

    return result


# ============================================================
# HTTP parser
# ============================================================

def _parse_http_request(payload: bytes) -> dict[str, Any]:
    """Extract HTTP method, Host, URI, User-Agent from an HTTP request."""
    result: dict[str, Any] = {}
    try:
        text = payload.decode("ascii", errors="replace")
        lines = text.split("\r\n")

        # Request line
        if lines and " " in lines[0]:
            parts = lines[0].split(" ", 2)
            if len(parts) >= 1 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"):
                result["http_method"] = parts[0]
            if len(parts) >= 2:
                result["http_uri"] = parts[1][:200]  # truncate

        # Headers
        for line in lines[1:30]:
            if not line or line == "\r":
                break
            if ":" in line:
                key, _, value = line.partition(":")
                key_lower = key.strip().lower()
                value = value.strip()[:200]
                if key_lower == "host":
                    result["http_host"] = value
                elif key_lower == "user-agent":
                    result["http_user_agent"] = value

    except Exception:
        pass

    return result


# ============================================================
# Generic flow statistics
# ============================================================

def _extract_flow_stats(flow: FlowData) -> dict[str, Any]:
    """Compute payload sizes, inter-arrival times, and TCP flags."""
    result: dict[str, Any] = {}
    sizes = [len(p) for p in flow.packets_data]
    result["payload_total_bytes"] = sum(sizes)
    result["packet_sizes"] = sizes[:10]

    # TCP flags: probe first packet for SYN/ACK/FIN/RST pattern
    if flow.protocol == "TCP" and flow.packets_data:
        first = flow.packets_data[0]
        # TCP header starts after IP header (usually 20 bytes)
        # Quick heuristic: find TCP flags byte at offset 33
        if len(first) > 34:
            flags = first[33]
            parts = []
            if flags & 0x02:
                parts.append("SYN")
            if flags & 0x10:
                parts.append("ACK")
            if flags & 0x01:
                parts.append("FIN")
            if flags & 0x04:
                parts.append("RST")
            if flags & 0x08:
                parts.append("PSH")
            result["tcp_flags_summary"] = "-".join(parts) if parts else f"0x{flags:02x}"

    return result


# ============================================================
# Main extraction entry point
# ============================================================

def extract_protocol_metadata(flow: FlowData) -> ProtocolMetadata:
    """Extract all available protocol metadata from a flow.

    Called by pipeline after gray_img generation, before model inference.
    Results are attached to flow.metadata for alert enrichment.
    """
    meta = ProtocolMetadata()

    # Generic stats always
    stats = _extract_flow_stats(flow)
    meta.payload_total_bytes = stats.get("payload_total_bytes", 0)
    meta.packet_sizes = stats.get("packet_sizes", [])
    meta.tcp_flags_summary = stats.get("tcp_flags_summary", "")

    if not flow.packets_data:
        return meta

    # Try to parse the first packet payload
    # Scapy adds full packet bytes including headers; skip IP+TCP/UDP headers
    first_pkt = flow.packets_data[0]

    # Best-effort: search for TLS ClientHello magic in the raw bytes
    for pkt in flow.packets_data[:3]:  # check first 3 packets
        # Look for TLS handshake at any offset (in case of different header lengths)
        for offset in range(0, min(len(pkt) - 5, 80)):
            if pkt[offset] == 0x16 and pkt[offset + 1] in (0x03,):
                tls_data = _parse_tls_clienthello(pkt[offset:])
                if tls_data.get("tls_version"):
                    meta.tls_sni = tls_data.get("tls_sni")
                    meta.tls_version = tls_data.get("tls_version")
                    meta.tls_cipher_count = tls_data.get("tls_cipher_count", 0)
                    break
        if meta.tls_version:
            break

    # DNS
    for pkt in flow.packets_data[:3]:
        # DNS over UDP: look for DNS header after IP+UDP header (~28 bytes)
        for offset in range(20, min(len(pkt) - 12, 60)):
            if pkt[offset:offset + 2] == b"\x00\x00":  # likely DNS ID=0
                dns = _parse_dns_query(pkt[offset:])
                if dns.get("dns_queries"):
                    meta.dns_queries = dns["dns_queries"]
                    break
        if meta.dns_queries:
            break

    # HTTP
    for pkt in flow.packets_data[:3]:
        for method in (b"GET ", b"POST ", b"PUT ", b"DELETE "):
            idx = pkt.find(method)
            if idx >= 0 and idx < 100:
                http = _parse_http_request(pkt[idx:])
                if http.get("http_method"):
                    meta.http_method = http.get("http_method")
                    meta.http_host = http.get("http_host")
                    meta.http_uri = http.get("http_uri")
                    meta.http_user_agent = http.get("http_user_agent")
                    break
        if meta.http_method:
            break

    return meta
