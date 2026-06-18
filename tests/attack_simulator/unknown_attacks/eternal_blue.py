"""EternalBlue (MS17-010) SMBv1 exploit payload generator.

Protocol fingerprint:
  - SMB Negotiate Protocol Request (0x72)
  - SMB Session Setup AndX Request (0x73)
  - Multiple NT Trans and Trans2 requests (0xA0, 0x25, 0x32)
  - The specific FEA (File Extended Attribute) list buffer overflow
    pattern that triggers the SMBv1 kernel vulnerability

Why not in 44-class training set:
  Although SMB traffic is present in CIC-IDS datasets (SMB brute-force
  and SMB exploits), the multi-stage EternalBlue exploit chain with its
  distinctive NT_TRANSACT + FEA_LIST overflow pattern is absent — the
  byte-level structure of OS-level exploits differs significantly from
  application-layer SMB attacks.
"""

import os
import random
import struct

from . import register_attack

# SMB command codes
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_NT_TRANSACT = 0xA0
SMB_COM_TRANSACTION2 = 0x32
SMB_COM_NT_CREATE_ANDX = 0xA2

# SMB header constants
SMB_SIGNATURE = b"\xffSMB"
SMB_STATUS_SUCCESS = 0x00000000


def _build_netbios_session(payload: bytes) -> bytes:
    """Wrap payload in a NetBIOS session message (4-byte length header)."""
    return struct.pack(">I", len(payload)) + payload


def _build_smb_header(command: int, pid: int = 0x1234,
                      tid: int = 0x0000, uid: int = 0x0000,
                      mid: int = 0x0001) -> bytes:
    """Build a standard SMBv1 32-byte header."""
    header = bytearray()
    header.extend(SMB_SIGNATURE)  # protocol identifier
    header.append(command)        # command code
    # NT status (4 bytes, little-endian)
    header.extend(struct.pack("<I", SMB_STATUS_SUCCESS))
    # Flags
    header.extend(b"\x18")  # flags: canonicalized pathnames, case insensitive
    # Flags2
    header.extend(b"\x07\xc8")  # flags2: unicode, nt status, extended security
    # PID high (2 bytes), reserved
    header.extend(b"\x00\x00\x00\x00\x00\x00\x00\x00")
    # TID, PID, UID, MID
    header.extend(struct.pack("<HHHH", tid, pid, uid, mid))
    return bytes(header)


def _smb_string_unicode(s: str) -> bytes:
    """Encode a string as Unicode (UTF-16LE) with length prefix for SMB."""
    encoded = s.encode("utf-16-le")
    return struct.pack("<B", len(encoded)) + encoded


def _build_negotiate_proto() -> bytes:
    """SMB Negotiate Protocol Request — first stage of SMB connection."""
    dialects = b"\x02NT LM 0.12\x00"  # NT LM 0.12 dialect
    payload = b"\x00"  # word count = 0
    payload += struct.pack("<H", len(dialects))  # byte count
    payload += dialects

    header = _build_smb_header(SMB_COM_NEGOTIATE, mid=random.randint(1, 65535))
    pkt = _build_netbios_session(header + payload)
    return pkt


def _build_session_setup_andx() -> bytes:
    """SMB Session Setup AndX Request."""
    # Word count = 13 for extended security
    word_count = 13
    payload = struct.pack("<B", word_count)
    # AndX command: 0xFF = no further commands
    payload += b"\xff"  # AndXCommand
    payload += b"\x00"  # reserved
    payload += struct.pack("<H", 0x0000)  # AndXOffset
    payload += struct.pack("<H", 0xFFFF)  # MaxBufferSize
    payload += struct.pack("<H", 0x0001)  # MaxMpxCount
    payload += struct.pack("<H", 0x0001)  # VcNumber (virtual circuit number)
    payload += struct.pack("<I", random.randint(0, 2**32 - 1))  # SessionKey
    payload += struct.pack("<H", 0x0000)  # OEMPasswordLen (NTLMSSP in blob)
    payload += struct.pack("<H", 0x0000)  # UnicodePasswordLen
    payload += struct.pack("<I", 0x00000000)  # reserved
    payload += struct.pack("<I", 0x00000000)  # reserved / capabilities
    # OS / Native OS / Native LAN Manager strings
    os_str = _smb_string_unicode("Windows 10 Pro 1803")
    lm_str = _smb_string_unicode("Windows 10 Pro 1803")
    security_blob = b"\x60" + os.urandom(40)  # fake NTLMSSP negotiate
    # Byte count
    bc = len(os_str) + len(lm_str) + len(security_blob)
    payload += struct.pack("<H", bc)
    payload += os_str
    payload += lm_str
    payload += security_blob

    header = _build_smb_header(SMB_COM_SESSION_SETUP_ANDX,
                               pid=random.randint(1, 65535),
                               uid=random.randint(1, 65535),
                               mid=random.randint(1, 65535))
    pkt = _build_netbios_session(header + payload)
    return pkt


def _build_nt_trans_peek() -> bytes:
    """NT Transact request — EternalBlue uses NT_TRANSACT to send
    the FEA list overflow payload to the target."""
    word_count = 19
    payload = struct.pack("<B", word_count)
    payload += struct.pack("<B", 0x01)  # MaxSetupCount
    payload += struct.pack("<H", 0x0000)  # reserved
    payload += struct.pack("<I", 1200)   # TotalParameterCount
    payload += struct.pack("<I", 4096)   # TotalDataCount
    payload += struct.pack("<I", 1000)   # MaxParameterCount
    payload += struct.pack("<I", 3500)   # MaxDataCount
    payload += struct.pack("<I", 0x0000)  # MaxSetupCount
    payload += struct.pack("<I", 0x0000)  # reserved
    payload += struct.pack("<H", 0x0000)  # ParameterCount
    payload += struct.pack("<H", 0x0000)  # ParameterOffset
    payload += struct.pack("<H", 0x0000)  # DataCount
    payload += struct.pack("<H", 0x0000)  # DataOffset
    payload += struct.pack("<B", 0x00)    # SetupCount
    # Subcommand: NT_TRANSACT_CREATE (1) followed by FEA list
    payload += struct.pack("<H", 0x0001)  # Function: NT_TRANSACT_CREATE
    # Byte count
    bc = 0
    payload += struct.pack("<H", bc)

    header = _build_smb_header(SMB_COM_NT_TRANSACT,
                               tid=random.randint(1, 65535),
                               uid=random.randint(1, 65535),
                               pid=random.randint(1, 65535),
                               mid=random.randint(1, 65535))
    pkt = _build_netbios_session(header + payload)
    return pkt


def _build_trans2_fea_list() -> bytes:
    """Trans2 request with FEA list — the actual overflow trigger.

    FEA list entries have a 1-byte size field, enabling overflow
    when the list size exceeds 255.  The EternalBlue exploit chain
    sends a crafted FEA list that overwrites adjacent SMB buffer.
    """
    # Trans2 SMB header
    word_count = 15
    payload = struct.pack("<B", word_count)
    payload += struct.pack("<H", 1000)   # TotalParameterCount
    payload += struct.pack("<H", 5000)   # TotalDataCount
    payload += struct.pack("<H", 1000)   # MaxParameterCount
    payload += struct.pack("<H", 5000)   # MaxDataCount
    payload += b"\x00"                   # MaxSetupCount
    payload += b"\x00"                   # reserved
    payload += struct.pack("<H", 0x0000)  # Flags
    payload += struct.pack("<I", 0x0000)  # Timeout
    payload += struct.pack("<H", 0x0000)  # reserved
    payload += struct.pack("<H", 0)       # ParameterCount
    payload += struct.pack("<H", 68)      # ParameterOffset (after header, before data)
    payload += struct.pack("<H", 50)      # DataCount
    payload += struct.pack("<H", 68)      # DataOffset (parameter area size)
    # Setup words
    payload += struct.pack("<B", 1)       # SetupCount
    payload += b"\x00"                    # reserved
    # Setup word: TRANS2_FIND_FIRST2 = 0x0001
    payload += struct.pack("<H", 0x000D)  # TRANS2_QUERY_PATH_INFORMATION

    # FEA data area — the overflow region
    fea_data = bytearray()
    # Build a large FEA list to overflow
    for j in range(10):
        # FEA entry: 1-byte flags + 1-byte name_len + 2-byte value_len + name + value
        fea_entry = bytearray()
        fea_entry.append(0x80)  # FEA flag
        fea_name = f"ATTRIB{j:02d}"
        fea_name_enc = fea_name.encode("ascii")
        fea_entry.append(len(fea_name_enc))
        fea_entry.extend(struct.pack("<H", 4))  # value length
        fea_entry.extend(fea_name_enc)
        fea_entry.extend(b"\x00\x00\x00\x00")  # value
        fea_data.extend(fea_entry)

    # XOR-encoded shellcode placeholder (the EternalBlue exploit uses
    # XOR'd shellcode in the FEA data to gain execution)
    shellcode_placeholder = os.urandom(random.randint(50, 150))

    # Assemble parameters + data
    params = b"\x00\x00" + struct.pack("<H", 0x0104)  # SMB_INFO_QUERY_EAS_FROM_LIST
    params += struct.pack("<I", 100)    # max data

    # Full packet assembly
    header = _build_smb_header(SMB_COM_TRANSACTION2,
                               tid=random.randint(1, 65535),
                               uid=random.randint(1, 65535),
                               pid=random.randint(1, 65535),
                               mid=random.randint(1, 65535))

    data = params + bytes(fea_data) + shellcode_placeholder
    payload += data

    pkt = _build_netbios_session(header + payload)
    return pkt


@register_attack("eternal_blue")
def generate_eternal_blue(count: int = 1) -> list[bytes]:
    """Generate EternalBlue SMBv1 exploit payload(s).

    Each payload chains together the full EternalBlue attack
    sequence: Negotiate -> SessionSetup -> NT_TRANSACT ->
    Trans2(FEA list overflow).

    Returns:
        List of bytes payloads, each 800-2000 bytes.
    """
    payloads = []
    for i in range(count):
        parts = [
            _build_negotiate_proto(),
            _build_session_setup_andx(),
            _build_nt_trans_peek(),
            _build_trans2_fea_list(),
        ]
        payloads.append(b"".join(parts))

    return payloads
