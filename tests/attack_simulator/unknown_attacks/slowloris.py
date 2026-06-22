"""Slowloris HTTP slow-DoS payload generator.

Protocol fingerprint:
  - Incomplete HTTP GET requests (missing the terminating CRLF+CRLF)
  - Fragmented HTTP headers sent one at a time
  - Keep-Alive connection headers
  - Multiple partial requests in a single byte stream

Why not in 44-class training set:
  Training data contains complete, well-formed HTTP requests with
  proper CRLF+CRLF termination.  Slowloris sends deliberately
  unfinished HTTP headers that never reach the double-CRLF,
  keeping server sockets occupied indefinitely.  The byte
  distribution (many partial fragments) is completely different.
"""

import random

from . import register_attack

# HTTP header fragments — each one is sneaky in its own way
USER_AGENTS = [
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
    b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    b"curl/7.68.0",
    b"Wget/1.21",
]

ACCEPT_HEADERS = [
    b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    b"text/html,application/xhtml+xml",
    b"*/*",
]

CONNECTION_HEADERS = [
    b"keep-alive",
    b"Keep-Alive",
]

CACHE_HEADERS = [
    b"no-cache",
    b"max-age=0",
]


def _fragment_header(header_line: bytes, frag_size: int) -> list[bytes]:
    """Split a header line into fragments for slow sending."""
    fragments = []
    remaining = header_line
    while remaining:
        frag = remaining[:frag_size]
        remaining = remaining[frag_size:]
        fragments.append(frag)
    return fragments


@register_attack("slowloris")
def generate_slowloris(count: int = 1) -> list[bytes]:
    """Generate Slowloris attack payload(s).

    Each payload is a concatenation of multiple incomplete HTTP
    request fragments — the raw bytes that would be sent over the
    wire.  Key characteristics:
      - No double-CRLF termination (request never completes)
      - Headers broken into tiny fragments
      - Keep-Alive connection directive
      - Multiple "sockets" (simulated by multiple request lines)

    Returns:
        List of bytes payloads, each 400-1200 bytes.
    """
    payloads = []
    for i in range(count):
        fragments = []

        # Simulate multiple connection-producing "sockets" in the attack
        num_sockets = random.randint(3, 8)
        for sock_idx in range(num_sockets):
            # Each "socket" starts a new partial GET request
            path = b"/" if sock_idx == 0 else f"/page{sock_idx}".encode()
            request_line = b"GET " + path + b" HTTP/1.1\r\n"
            fragments.append(request_line)

            # Host header
            fragments.append(
                f"Host: 192.168.{random.randint(1, 254)}.{random.randint(1, 254)}\r\n".encode()
            )

            # User-Agent
            ua = random.choice(USER_AGENTS)
            fragments.append(b"User-Agent: " + ua + b"\r\n")

            # Accept
            fragments.append(b"Accept: " + random.choice(ACCEPT_HEADERS) + b"\r\n")

            # Connection: keep-alive
            fragments.append(
                b"Connection: " + random.choice(CONNECTION_HEADERS) + b"\r\n"
            )

            # Extra slow header: send it one character at a time
            extra_key = f"X-Slowloris-{sock_idx}"
            extra_val = "a" * random.randint(10, 40)
            full_extra = f"{extra_key}: {extra_val}\r\n".encode()

            # Fragment the extra header into tiny pieces (Slowloris hallmark)
            frag_size = random.randint(1, 5)
            for j in range(0, len(full_extra), frag_size):
                fragments.append(full_extra[j:j + frag_size])

            # Occasionally add one full header
            fake_headers = [
                b"Accept-Language: en-US,en;q=0.5\r\n",
                b"Accept-Encoding: gzip, deflate\r\n",
                b"Cache-Control: " + random.choice(CACHE_HEADERS) + b"\r\n",
                b"DNT: 1\r\n",
                b"Upgrade-Insecure-Requests: 1\r\n",
            ]
            fragments.append(random.choice(fake_headers))

        # CRITICAL: NO final CRLF+CRLF — this is the Slowloris hallmark.
        # The request is left deliberately incomplete so the server
        # keeps the connection open waiting for the rest.

        payloads.append(b"".join(fragments))

    return payloads
