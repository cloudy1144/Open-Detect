"""Stratum crypto-mining protocol payload generator.

Protocol fingerprint:
  - JSON-RPC 2.0 formatted request/response messages
  - mining.subscribe — register with mining pool
  - mining.authorize — authenticate worker credentials
  - mining.submit — submit a valid share (proof-of-work)
  - mining.set_difficulty / mining.notify — pool directives
  - Connection to well-known pool ports (3333, 4444, etc.)

Why not in 44-class training set:
  The Stratum protocol is a specialised JSON-RPC-based protocol used
  exclusively for cryptocurrency mining pools.  CIC-IDS datasets do
  not include any Stratum or mining-pool traffic.  The combination of
  JSON-RPC framing with mining-specific method names is a completely
  novel traffic pattern for the model.
"""

import json
import os
import random
import struct

from . import register_attack

# Common Stratum mining pool endpoints
MINING_WALLETS = [
    b"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    b"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    b"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb2",
]

MINING_WORKERS = [
    b"worker01", b"rig01", b"gpu01", b"miner01",
    b"antminer1", b"asic01",
]

MINING_PASSWORDS = [
    b"x", b"123", b"password", b"",
]


def _build_jsonrpc(method: str, params: list | dict, req_id: int) -> bytes:
    """Build a JSON-RPC 2.0 request as bytes."""
    msg = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": req_id,
    }
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


def _build_mining_subscribe(req_id: int,
                            user_agent: bytes | None = None) -> bytes:
    """Build mining.subscribe request — initial pool registration.

    The client sends:
      {"id": 1, "method": "mining.subscribe", "params": ["agent/version", "session_id"]}

    This is the first message a miner sends to a pool.
    """
    if user_agent is None:
        agents = [
            b"cgminer/4.11.1", b"bfgminer/5.5.0",
            b"xmrig/6.18.0", b"cpuminer/2.5.1",
            b"sgminer/5.1.1",
        ]
        user_agent = random.choice(agents)

    params = [user_agent.decode("utf-8", errors="replace")]
    # Some miners also send a session ID on reconnection
    if random.random() < 0.3:
        params.append(f"{random.randint(0, 2**32 - 1):08x}")

    return _build_jsonrpc("mining.subscribe", params, req_id)


def _build_mining_authorize(req_id: int) -> bytes:
    """Build mining.authorize request — worker authentication.

    The client sends:
      {"id": 2, "method": "mining.authorize",
       "params": ["wallet.worker", "password"]}
    """
    wallet = random.choice(MINING_WALLETS)
    worker = random.choice(MINING_WORKERS)
    password = random.choice(MINING_PASSWORDS)

    username = wallet + b"." + worker
    params = [
        username.decode("utf-8", errors="replace"),
        password.decode("utf-8", errors="replace"),
    ]
    return _build_jsonrpc("mining.authorize", params, req_id)


def _build_mining_submit(req_id: int) -> bytes:
    """Build mining.submit request — share submission.

    The miner submits a solved share to the pool:
      {"id": 4, "method": "mining.submit",
       "params": ["worker", "job_id", "extranonce2", "ntime", "nonce"]}
    """
    worker = random.choice(MINING_WORKERS).decode("utf-8", errors="replace")
    job_id = f"{random.randint(100000, 999999):06d}"
    extranonce2 = f"{random.randint(0, 2**32 - 1):08x}"
    ntime = f"{random.randint(0, 2**32 - 1):08x}"
    nonce = f"{random.randint(0, 2**32 - 1):08x}"

    params = [worker, job_id, extranonce2, ntime, nonce]
    return _build_jsonrpc("mining.submit", params, req_id)


def _build_pool_response(method: str, req_id: int) -> bytes:
    """Build a fake pool -> miner response (JSON-RPC result)."""
    msg = {
        "jsonrpc": "2.0",
        "result": True,
        "id": req_id,
    }
    if method == "mining.subscribe":
        msg["result"] = [
            [
                ["mining.notify", f"{random.randint(100000, 999999):06x}"],
                ["mining.set_difficulty", f"{random.randint(100000, 999999):06x}"],
            ],
            f"{random.randint(0, 2**32 - 1):08x}",  # extranonce1
            random.randint(4, 8),  # extranonce2_size
        ]
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


def _build_mining_notify(req_id: int) -> bytes:
    """Build a mining.notify — pool sends new work to miner."""
    job_id = f"{random.randint(100000, 999999):06x}"
    prev_hash = os.urandom(32).hex()
    coinb1 = os.urandom(40).hex()
    coinb2 = os.urandom(40).hex()
    merkle_branches = [os.urandom(32).hex() for _ in range(random.randint(1, 4))]
    version = f"{random.randint(1, 4):08x}"
    nbits = f"{random.randint(0x17000000, 0x1d00ffff):08x}"
    ntime = f"{int(random.random() * 2**32):08x}"
    clean_jobs = True

    params = [
        job_id, prev_hash, coinb1, coinb2,
        merkle_branches, version, nbits, ntime, clean_jobs,
    ]
    # mining.notify is typically sent from server to client, but
    # some miners also acknowledge or forward these.
    msg = {
        "jsonrpc": "2.0",
        "method": "mining.notify",
        "params": params,
        "id": None,
    }
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")


@register_attack("stratum_mining")
def generate_stratum_mining(count: int = 1) -> list[bytes]:
    """Generate Stratum crypto-mining protocol payload(s).

    Each payload mimics a complete Stratum mining session
    in bytes: subscribe -> authorize -> submit cycles with
    pool responses interleaved.

    Returns:
        List of bytes payloads, each 400-2000 bytes.
    """
    payloads = []
    for i in range(count):
        parts = []

        # Step 1: mining.subscribe (register with pool)
        parts.append(_build_mining_subscribe(1))
        parts.append(_build_pool_response("mining.subscribe", 1))

        # Step 2: mining.authorize (authenticate worker)
        parts.append(_build_mining_authorize(2))
        parts.append(_build_pool_response("mining.authorize", 2))

        # Step 3: Pool sends mining.notify (new work)
        parts.append(_build_mining_notify(3))

        # Step 4: Miner submits share(s)
        num_shares = random.randint(1, 5)
        for j in range(num_shares):
            req_id = 4 + j
            parts.append(_build_mining_submit(req_id))
            parts.append(_build_pool_response("mining.submit", req_id))

        # Optionally add a mining.set_difficulty from pool
        if random.random() < 0.5:
            difficulty_msg = {
                "jsonrpc": "2.0",
                "method": "mining.set_difficulty",
                "params": [random.randint(256, 65536)],
                "id": None,
            }
            parts.append(
                (json.dumps(difficulty_msg, separators=(",", ":")) + "\n").encode()
            )

        payloads.append(b"".join(parts))

    return payloads
