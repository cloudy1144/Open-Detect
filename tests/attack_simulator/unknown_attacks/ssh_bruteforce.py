"""SSH brute-force payload generator.

Protocol fingerprint:
  - SSH-2.0 banner exchange
  - Key exchange init (diffie-hellman-group14-sha1, etc.)
  - Multiple consecutive SSH_MSG_USERAUTH_REQUEST messages with different passwords
  - Mimics a lateral-movement bruteforce against an SSH server

Why not in 44-class training set:
  The CIC-IDS/CSE-CIC datasets contain FTP, SMB, and HTTP traffic but do
  NOT include raw SSH protocol sessions.  SSH bruteforce would appear as
  an entirely new protocol class to the model.
"""

import os
import random

from . import register_attack

# SSH protocol constants
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_SERVICE_REQUEST = 5
SSH_MSG_USERAUTH_REQUEST = 50
SSH_MSG_USERAUTH_FAILURE = 51
SSH_MSG_USERAUTH_SUCCESS = 52

COMMON_PASSWORDS = [
    b"password", b"123456", b"admin", b"root", b"test",
    b"password123", b"qwerty", b"letmein", b"monkey", b"dragon",
]


def _ssh_string(s: bytes) -> bytes:
    """Encode an SSH string: 4-byte big-endian length + data."""
    return len(s).to_bytes(4, "big") + s


def _ssh_mpint(n: int) -> bytes:
    """Encode an SSH mpint (multi-precision integer)."""
    if n == 0:
        return b"\x00\x00\x00\x00"
    data = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if data[0] & 0x80:
        data = b"\x00" + data
    return len(data).to_bytes(4, "big") + data


def _random_bytes(n: int) -> bytes:
    """Random bytes, used for nonces/session IDs."""
    return os.urandom(n)


def _build_ssh_banner() -> bytes:
    """SSH-2.0 banner line."""
    banners = [
        b"SSH-2.0-OpenSSH_7.4\r\n",
        b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
        b"SSH-2.0-dropbear_2020.81\r\n",
        b"SSH-2.0-libssh-0.9.6\r\n",
    ]
    return random.choice(banners)


def _build_kexinit() -> bytes:
    """Build an SSH_MSG_KEXINIT packet."""
    cookie = _random_bytes(16)
    kex_algs = b"diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
    host_key_algs = b"ssh-rsa,ssh-dss"
    ciphers_cts = b"aes128-ctr,aes256-ctr"
    ciphers_sts = b"aes128-ctr,aes256-ctr"
    macs_cts = b"hmac-sha2-256,hmac-sha1"
    macs_sts = b"hmac-sha2-256,hmac-sha1"
    comp_cts = b"none"
    comp_sts = b"none"
    lang_cts = b""
    lang_sts = b""

    payload = cookie
    payload += _ssh_string(kex_algs)
    payload += _ssh_string(host_key_algs)
    payload += _ssh_string(ciphers_cts)
    payload += _ssh_string(ciphers_sts)
    payload += _ssh_string(macs_cts)
    payload += _ssh_string(macs_sts)
    payload += _ssh_string(comp_cts)
    payload += _ssh_string(comp_sts)
    payload += _ssh_string(lang_cts)
    payload += _ssh_string(lang_sts)
    payload += b"\x00"  # first_kex_packet_follows = false
    payload += b"\x00\x00\x00\x00"  # reserved

    padding_len = 8
    padding = _random_bytes(padding_len)
    packet = bytes([SSH_MSG_KEXINIT]) + payload
    packet_len = 1 + len(packet) + padding_len
    return packet_len.to_bytes(4, "big") + bytes([padding_len]) + packet + padding


def _build_userauth_request(username: bytes, service: bytes, password: bytes) -> bytes:
    """Build SSH_MSG_USERAUTH_REQUEST with password method.

    Format:
      byte      SSH_MSG_USERAUTH_REQUEST
      string    user name
      string    service name
      string    "password"
      boolean   FALSE
      string    password (plaintext)
    """
    payload = bytes([SSH_MSG_USERAUTH_REQUEST])
    payload += _ssh_string(username)
    payload += _ssh_string(service)
    payload += _ssh_string(b"password")
    payload += b"\x00"  # FALSE = no new password follows
    payload += _ssh_string(password)

    padding_len = random.randint(4, 16)
    padding = _random_bytes(padding_len)
    # Block size field: (block_size * 8) for block cipher, or 8 for stream
    block_size = 8
    packet_len = 1 + len(payload) + padding_len
    # SSH binary packet: 4-byte length | 1-byte padding_len | payload | padding
    return packet_len.to_bytes(4, "big") + bytes([padding_len]) + payload + padding


def _build_service_request(service: bytes) -> bytes:
    """Build SSH_MSG_SERVICE_REQUEST."""
    payload = bytes([SSH_MSG_SERVICE_REQUEST]) + _ssh_string(service)
    padding_len = random.randint(4, 16)
    padding = _random_bytes(padding_len)
    packet_len = 1 + len(payload) + padding_len
    return packet_len.to_bytes(4, "big") + bytes([padding_len]) + payload + padding


def _generate_auth_pair(seed: int) -> tuple[bytes, bytes]:
    """Generate a (username, password) pair seeded by index."""
    usernames = [b"root", b"admin", b"ubuntu", b"pi", b"oracle", b"postgres"]
    passwords = COMMON_PASSWORDS
    rng = random.Random(seed)
    return (
        usernames[rng.randint(0, len(usernames) - 1)],
        passwords[rng.randint(0, len(passwords) - 1)],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@register_attack("ssh_bruteforce")
def generate_ssh_bruteforce(count: int = 1) -> list[bytes]:
    """Generate SSH bruteforce payload(s).

    Each payload simulates one complete SSH connection attempt stringing
    together banner + kex + multiple auth requests — exactly the bytes
    that would traverse the wire during a bruteforce attack.

    Returns:
        List of bytes payloads, each 400-1800 bytes.
    """
    payloads = []
    for i in range(count):
        parts = []
        # 1. SSH banner exchange (client -> server banner is sent first in
        #    most implementations; here we embed it in the byte stream)
        parts.append(_build_ssh_banner())

        # 2. Client KEXINIT
        parts.append(_build_kexinit())

        # 3. Service request ("ssh-userauth")
        parts.append(_build_service_request(b"ssh-userauth"))

        # 4. Multiple authentication attempts (bruteforce core)
        num_auth_attempts = random.randint(4, 10)
        for j in range(num_auth_attempts):
            username, password = _generate_auth_pair(i * 100 + j)
            parts.append(_build_userauth_request(username, b"ssh-connection", password))

        payloads.append(b"".join(parts))

    return payloads
