"""YouFs / Tuya BLE protocol codec — pure Python, no hardware dependency.

Every constant and algorithm in this module is reproduced from static analysis
of YouFs-A_1.0.3_APKPure.apk (Tuya ThingClips BLE stack + libBleLib.so).
Evidence: docs/protocol.md, docs/checksum.md, docs/auth.md (file:line citations).

Three wire layers, bottom-up:

1. trsmitr GATT framing (libBleLib.so trsmitr_send_pkg_encode / Java Packer):
       [pkg_idx varint][total_len varint (first packet only)][(type<<4) (first only)][payload ...]
   Each BLE write <= chunk_size (default 20, max mtu-3).

2. Application frame (X2Request.pack / Ret.parse):
       [flag 1B]  flag==0: plaintext body follows
                  flag!=0: [iv 16B][AES-128-CBC(body) with zero padding]
       body = [sn 4B BE][sn_ack 4B BE][code 2B BE][len 2B BE][data][crc16_modbus 2B BE]

3. Data point (DP) payload: [dpId 1B][type 1B][len 1B][value] x N
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# Checksums (docs/checksum.md)
# --------------------------------------------------------------------------- #


def crc8(data: bytes) -> int:
    """CRC-8, poly 0x07, init 0x00, MSB-first (libBleLib.so init_crc8 table).

    Check value: crc8(b"123456789") == 0xF4.
    """
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) if crc & 0x80 else crc << 1
        crc &= 0xFF
    return crc


def crc16_arc(data: bytes) -> int:
    """CRC-16/ARC, poly 0xA001 (reflected 0x8005), init 0x0000.

    blelib/channel/CRC16.java — written little-endian into the OTA channel's
    trailing 2 bytes.  Check value: crc16_arc(b"123456789") == 0xB4C8.
    """
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS, poly 0xA001 reflected, init 0xFFFF.

    bluetooth/qdqbdbd.java (CRCUtils) — v2 application-frame checksum, written
    big-endian.  Check value: crc16_modbus(b"123456789") == 0x4B37.
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


# --------------------------------------------------------------------------- #
# varint / LEB128 (trsmitr header encoding)
# --------------------------------------------------------------------------- #


def varint_encode(value: int) -> bytes:
    """LEB128 encode (bit7 = more bytes follow). 0 <= value < 2**28."""
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def varint_decode(data: bytes, pos: int = 0) -> Tuple[int, int]:
    """LEB128 decode. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 21:
            raise ValueError("varint too long")


# --------------------------------------------------------------------------- #
# Layer 1: trsmitr GATT framing
# --------------------------------------------------------------------------- #

TRS_DEFAULT_CHUNK = 20  # Packet.BUFFER_SIZE; native receiver hard-checks <= 20
TRS_TYPE_NORMAL = 2     # Packer.bdpdqbp(2, ...) — v2 normal request


def trsmitr_encode(payload: bytes, chunk_size: int = TRS_DEFAULT_CHUNK,
                   type_nibble: int = TRS_TYPE_NORMAL) -> List[bytes]:
    """Split an application frame into trsmitr BLE writes.

    Java: bluetooth/pbqbqbq.java (Packer) bdpdqbp(type, data, len, mtu).
    First packet: varint(0) + varint(total_len) + byte(type<<4) + data
    Rest:         varint(idx) + data
    """
    if chunk_size < 20:
        chunk_size = 20
    packets: List[bytes] = []
    offset = 0
    idx = 0
    total = len(payload)
    while offset < total or idx == 0:
        header = varint_encode(idx)
        if idx == 0:
            header += varint_encode(total) + bytes([(type_nibble & 0xF) << 4])
        room = chunk_size - len(header)
        if room <= 0:
            raise ValueError("chunk_size too small for trsmitr header")
        chunk = payload[offset:offset + room]
        packets.append(header + chunk)
        offset += len(chunk)
        idx += 1
    return packets


class TrsmitrAssembler:
    """Reassemble trsmitr packets streamed from the notify characteristic.

    Native counterpart: libBleLib.so trsmitr_recv_pkg_decode /
    BLEJniLib.parseDataRecived.
    """

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._total: Optional[int] = None
        self._cmd_nibble = 0
        self._seq = 0
        self._buf = bytearray()
        self._next_idx = 0

    def feed(self, packet: bytes) -> Optional[Tuple[int, int, bytes]]:
        """Feed one BLE packet. Returns (cmd_nibble, seq, payload) when the
        frame is complete, else None.  Raises ValueError on non-increasing
        index/oversize.

        The APK BaseReceiver accepts any strictly increasing packet index
        (``index <= last`` is the only error) and ignores the header's low
        nibble on receive; both behaviours are reproduced here.
        """
        idx, pos = varint_decode(packet)
        if idx == 0:
            total, pos = varint_decode(packet, pos)
            if pos >= len(packet):
                raise ValueError("trsmitr first packet missing header byte")
            hdr = packet[pos]
            pos += 1
            self._cmd_nibble = (hdr >> 4) & 0xF
            self._seq = hdr & 0xF
            self._total = total
            self._buf = bytearray()
            self._next_idx = 0
        elif self._total is None:
            raise ValueError("trsmitr continuation before first packet")
        elif idx <= self._next_idx - 1:
            self.reset()
            raise ValueError(f"trsmitr packet index not increasing: got {idx}, last was {self._next_idx - 1}")
        self._next_idx = idx + 1
        self._buf += packet[pos:]
        if self._total is not None and len(self._buf) >= self._total:
            payload = bytes(self._buf[:self._total])
            cmd, seq = self._cmd_nibble, self._seq
            self.reset()
            return cmd, seq, payload
        return None


# --------------------------------------------------------------------------- #
# AES-128-CBC (pure Python; SecurityUtil bpdpppq.java = "AES/CBC/NoPadding")
# --------------------------------------------------------------------------- #

_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _aes128_expand_key(key: bytes) -> List[List[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return [words[4 * r:4 * r + 4] for r in range(11)]


def _aes128_encrypt_block(round_keys: List[List[int]], block: bytes) -> bytes:
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    def add_round_key(rk: List[List[int]]) -> None:
        for c in range(4):
            for r in range(4):
                state[r][c] ^= rk[c][r]

    def sub_shift() -> None:
        for r in range(4):
            for c in range(4):
                state[r][c] = _SBOX[state[r][c]]
        for r in range(1, 4):
            state[r] = state[r][r:] + state[r][:r]

    def mix_columns() -> None:
        for c in range(4):
            a = [state[r][c] for r in range(4)]
            state[0][c] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
            state[1][c] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
            state[2][c] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
            state[3][c] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])

    add_round_key(round_keys[0])
    for rnd in range(1, 10):
        sub_shift()
        mix_columns()
        add_round_key(round_keys[rnd])
    sub_shift()
    add_round_key(round_keys[10])
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _gf_mul(coeff: int, val: int) -> int:
    out = 0
    while coeff:
        if coeff & 1:
            out ^= val
        val = _xtime(val)
        coeff >>= 1
    return out & 0xFF


def _aes128_decrypt_block(round_keys: List[List[int]], block: bytes) -> bytes:
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    def inv_shift_sub() -> None:
        for r in range(1, 4):
            state[r] = state[r][-r:] + state[r][:-r]
        for r in range(4):
            for c in range(4):
                state[r][c] = _INV_SBOX[state[r][c]]

    def inv_mix_columns() -> None:
        for c in range(4):
            a = [state[r][c] for r in range(4)]
            state[0][c] = _gf_mul(0x0E, a[0]) ^ _gf_mul(0x0B, a[1]) ^ _gf_mul(0x0D, a[2]) ^ _gf_mul(0x09, a[3])
            state[1][c] = _gf_mul(0x09, a[0]) ^ _gf_mul(0x0E, a[1]) ^ _gf_mul(0x0B, a[2]) ^ _gf_mul(0x0D, a[3])
            state[2][c] = _gf_mul(0x0D, a[0]) ^ _gf_mul(0x09, a[1]) ^ _gf_mul(0x0E, a[2]) ^ _gf_mul(0x0B, a[3])
            state[3][c] = _gf_mul(0x0B, a[0]) ^ _gf_mul(0x0D, a[1]) ^ _gf_mul(0x09, a[2]) ^ _gf_mul(0x0E, a[3])

    def ark(rk: List[List[int]]) -> None:
        for c in range(4):
            for r in range(4):
                state[r][c] ^= rk[c][r]

    ark(round_keys[10])
    for rnd in range(9, 0, -1):
        inv_shift_sub()
        ark(round_keys[rnd])
        inv_mix_columns()
    inv_shift_sub()
    ark(round_keys[0])
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-128-CBC encrypt with zero padding (ThingDataPacket ppbpqqq.java:535-548)."""
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    round_keys = _aes128_expand_key(key)
    pad = (-len(plaintext)) % 16
    padded = plaintext + b"\x00" * pad
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i + 16], prev))
        enc = _aes128_encrypt_block(round_keys, block)
        out += enc
        prev = enc
    return bytes(out)


def aes128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != 16 or len(ciphertext) % 16:
        raise ValueError("bad iv/ciphertext length")
    round_keys = _aes128_expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = _aes128_decrypt_block(round_keys, block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


# --------------------------------------------------------------------------- #
# Layer 2: application frame (X2Request / Ret)
# --------------------------------------------------------------------------- #


def build_app_frame(sn: int, sn_ack: int, code: int, data: bytes = b"",
                    key: Optional[bytes] = None, flag: int = 0,
                    iv: Optional[bytes] = None) -> bytes:
    """Assemble the over-the-air application frame.

    plaintext = sn(4 BE) + sn_ack(4 BE) + code(2 BE) + len(2 BE) + data
                + crc16_modbus(2 BE)                      (ThingDataPacket :197-211)
    wire      = [0x00] + plaintext                          (flag 0, no iv)
             or [flag] + iv(16) + AES-CBC(zeropad(plaintext)) (ppbpqqq.java:535-562)
    """
    body = (sn.to_bytes(4, "big") + sn_ack.to_bytes(4, "big") +
            code.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data)
    body += crc16_modbus(body).to_bytes(2, "big")
    if flag == 0:
        if key is not None:
            raise ValueError("key given but flag==0")
        return b"\x00" + body
    if key is None or len(key) != 16:
        raise ValueError("encrypted frame needs a 16-byte key")
    if iv is None:
        iv = os.urandom(16)
    return bytes([flag & 0xFF]) + iv + aes128_cbc_encrypt(key, iv, body)


@dataclass
class Ret:
    """Parsed device response (Ret.parse, ble/core/packet/bean/Ret.java:432+)."""
    flag: int
    sn: int
    sn_ack: int
    code: int
    data: bytes
    crc_ok: bool
    raw: bytes = b""


def parse_ret(raw: bytes, key: Optional[bytes] = None,
              flags_to_key: Optional[Mapping[int, bytes]] = None) -> Ret:
    """Parse a device frame (after trsmitr reassembly).

    key        — used when flag!=0 and no flags_to_key mapping matches.
    flags_to_key — mapping securityFlag -> key (docs/auth.md §3).
    """
    if not raw:
        raise ValueError("empty frame")
    flag = raw[0]
    if flag == 0:
        body = raw[1:]
    else:
        mapping = dict(flags_to_key or {})
        frame_key = mapping.get(flag, key)
        if frame_key is None:
            raise ValueError(f"encrypted frame (flag={flag}) without key")
        if len(raw) < 33 or (len(raw) - 17) % 16:
            raise ValueError("encrypted frame has invalid IV/ciphertext length")
        iv = raw[1:17]
        body = aes128_cbc_decrypt(frame_key, iv, raw[17:])
    if len(body) < 14:
        raise ValueError("frame body too short")
    sn = int.from_bytes(body[0:4], "big")
    sn_ack = int.from_bytes(body[4:8], "big")
    code = int.from_bytes(body[8:10], "big")
    length = int.from_bytes(body[10:12], "big")
    frame_end = 14 + length
    if frame_end > len(body):
        raise ValueError("declared frame length exceeds available body")
    # The APK (Ret.parse) never rejects trailing bytes after the declared
    # frame; the CRC over sn..data is the integrity check. Observed on the
    # real vehicle: the device pads encrypted frames with its pad length
    # (e.g. 02 02) instead of zeros, so encrypted tails must not be compared
    # against zero padding.
    if flag == 0 and frame_end != len(body):
        raise ValueError("plaintext frame length does not match body")
    data = body[12:12 + length]
    recv_crc = int.from_bytes(body[12 + length:14 + length], "big")
    calc_crc = crc16_modbus(body[:12 + length])
    return Ret(flag=flag, sn=sn, sn_ack=sn_ack, code=code, data=data,
               crc_ok=recv_crc == calc_crc, raw=raw)


# --------------------------------------------------------------------------- #
# Key derivation (docs/auth.md §3/§4)
# --------------------------------------------------------------------------- #


def derive_key5(local_key: bytes, srand: bytes) -> bytes:
    """key5 = MD5(loginKey || srand) — legacy session key (dpqbbpd.java:4283-4322)."""
    return hashlib.md5(local_key + srand).digest()


def derive_key4(login_key: bytes) -> bytes:
    """key4 = MD5(loginKey) for the P4 legacy cmd0 exchange.

    Evidence: original dpqbbpd.getSecretKey4() hashes the UTF-8 loginKey via
    ppbpqqq.pdqppqb(); this is distinct from flag-5 key derivation.
    """
    return hashlib.md5(login_key).digest()


def derive_key14(login_key_complete: str, secret_key: str) -> bytes:
    """key14 = MD5(UTF-8(loginKeyComplete + secretKey)) — P4 new-security cmd0.

    Evidence: dpqbbpd.getSecretKey14() hashes bddqpdp.bppdpdq(str + str2),
    i.e. plain UTF-8 of the concatenated cloud localKey and secKey strings
    with no separator and no inner hash.
    """
    return hashlib.md5((login_key_complete + secret_key).encode("utf-8")).digest()


def derive_key15(login_key_complete: str, secret_key: str, srand: bytes) -> bytes:
    """key15 = MD5(UTF-8(loginKeyComplete + secretKey) || srand) — new-security session.

    Evidence: dpqbbpd.getSecretKey15() = MD5(concat(getBytes(loginKeyComplete+
    secretKey), srand)).  Unlike key2 there is NO inner MD5 of the secret input.
    """
    return hashlib.md5(
        (login_key_complete + secret_key).encode("utf-8") + srand).digest()


def derive_key2(secret: bytes, srand: bytes) -> bytes:
    """key2 = MD5(MD5(secret) || srand) (dpqbbpd.java:4210-4224)."""
    return hashlib.md5(hashlib.md5(secret).digest() + srand).digest()


def derive_key12(encrypted_auth_key_hex: str, srand: bytes) -> bytes:
    """key12 = MD5(hexDecode(encryptedAuthKey) || srand) (dpqbbpd.java:3980-3993)."""
    return hashlib.md5(bytes.fromhex(encrypted_auth_key_hex) + srand).digest()


def made_session_key(data: bytes) -> bytes:
    """libBleLib.so made_session_key: out[i] = crc8_table[in[i]] for i<16.

    Short inputs follow the native wrap-around path
    (out[i] = table[(in[i-len] + in[i-len+1]) & 0xff]); the common call passes
    16 bytes (BLEJniLib.madeSessionKey).
    """
    table = _crc8_table()
    out = bytearray(16)
    n = len(data)
    for i in range(16):
        if i < n:
            out[i] = table[data[i]]
        else:
            out[i] = table[(data[i - n] + data[i - n + 1]) & 0xFF]
    return bytes(out)


_CRC8_TABLE_CACHE: Optional[List[int]] = None


def _crc8_table() -> List[int]:
    global _CRC8_TABLE_CACHE
    if _CRC8_TABLE_CACHE is None:
        table = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = ((c << 1) ^ 0x07) if c & 0x80 else c << 1
            table.append(c & 0xFF)
        _CRC8_TABLE_CACHE = table
    return _CRC8_TABLE_CACHE


# --------------------------------------------------------------------------- #
# Layer 3: data points (DP TLV)
# --------------------------------------------------------------------------- #

DP_RAW, DP_BOOL, DP_VALUE, DP_STRING, DP_ENUM, DP_BITMAP = 0, 1, 2, 3, 4, 5


@dataclass
class Dp:
    dp_id: int
    dp_type: int
    value: object  # bytes | bool | int | str
    raw: bytes = b""

    def as_int(self) -> Optional[int]:
        if self.dp_type == DP_VALUE:
            return int.from_bytes(self.raw, "little", signed=True)
        if self.dp_type in (DP_BOOL, DP_ENUM):
            return self.raw[0] if self.raw else None
        if self.dp_type == DP_BITMAP:
            return int.from_bytes(self.raw, "little")
        return None


def dp_encode(dp_id: int, dp_type: int, value) -> bytes:
    """Encode one DP to [id][type][len][value] (DpsParseHelper.java).

    type 2 (value) is 4 bytes LITTLE-endian on the wire
    (bbpqqpq.java:2160-2163 reversal)."""
    if dp_type == DP_BOOL:
        val = b"\x01" if value else b"\x00"
    elif dp_type == DP_ENUM:
        val = bytes([int(value) & 0xFF])
    elif dp_type == DP_VALUE:
        val = int(value).to_bytes(4, "little", signed=True)
    elif dp_type == DP_BITMAP:
        val = int(value).to_bytes(4, "little")
    elif dp_type == DP_STRING:
        val = str(value).encode("utf-8")
    elif dp_type == DP_RAW:
        val = bytes(value)
    else:
        raise ValueError(f"unsupported dp_type {dp_type}")
    if len(val) > 255:
        raise ValueError("dp value too long")
    return bytes([dp_id & 0xFF, dp_type & 0xFF, len(val)]) + val


def dp_decode(data: bytes, wide_len: bool = False) -> List[Dp]:
    """Parse a TLV stream.

    wide_len=False: [dpId 1B][type 1B][len 1B][value]      (pv3 / classic KLV)
    wide_len=True:  [dpId 1B][type 1B][len 2B BE][value]   (pv4, DpsReportRep)
    """
    out: List[Dp] = []
    pos = 0
    n = len(data)
    while pos + 3 <= n:
        dp_id = data[pos]
        dp_type = data[pos + 1]
        if wide_len:
            if pos + 4 > n:
                break
            length = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
        else:
            length = data[pos + 2]
            pos += 3
        if pos + length > n:
            break
        raw = data[pos:pos + length]
        pos += length
        if dp_type == DP_BOOL:
            value: object = bool(raw[0]) if raw else False
        elif dp_type == DP_VALUE:
            value = int.from_bytes(raw, "little", signed=True)
        elif dp_type == DP_ENUM:
            value = raw[0] if raw else None
        elif dp_type == DP_BITMAP:
            value = int.from_bytes(raw, "little")
        elif dp_type == DP_STRING:
            value = raw.decode("utf-8", "replace")
        else:
            value = raw
        out.append(Dp(dp_id=dp_id, dp_type=dp_type, value=value, raw=raw))
    return out


# --------------------------------------------------------------------------- #
# DeviceInfo (cmd 0 response) — DeviceInfoRep.parseRep
# --------------------------------------------------------------------------- #


@dataclass
class DeviceInfo:
    device_version: str = ""
    protocol_version: str = ""
    flag: int = 0
    need_beacon_key: bool = False
    is_bind: bool = False
    srand: bytes = b""
    hardware_version: str = ""
    auth_key: str = ""
    dev_id: str = ""
    security_level: int = -1
    raw: bytes = b""


def parse_device_info(data: bytes) -> DeviceInfo:
    """Parse cmd 0 response (DeviceInfoRep.parseRep, base + proto>=3.0 branch)."""
    info = DeviceInfo(raw=data)
    if len(data) < 12:
        raise ValueError("device info too short")
    dev_ver = data[0:2]
    proto_ver = data[2:4]
    info.flag = data[4]
    info.need_beacon_key = bool(info.flag & 0x10)
    info.is_bind = data[5] == 1
    info.srand = data[6:12]
    info.device_version = f"{dev_ver[0]}.{dev_ver[1]}"
    info.protocol_version = f"{proto_ver[0]}.{proto_ver[1]}"
    proto_num = (proto_ver[0] & 0xFF) * 10 + (proto_ver[1] & 0xFF)
    pos = 12
    if len(data) >= pos + 2:
        info.hardware_version = f"{data[pos]}.{data[pos + 1]}"
    pos += 2
    if len(data) >= pos + 32:
        info.auth_key = data[pos:pos + 32].decode("ascii", "replace")
    pos += 32
    if proto_num >= 30 and len(data) >= pos + 31:
        pos += 3 + 3 + 2          # devVer2(3) + hwVer2(3) + reserved(2)
        pos += 1                  # flag2
        dev_id = data[pos:pos + 22]
        info.dev_id = dev_id.split(b"\x00")[0].decode("ascii", "replace")
    return info
