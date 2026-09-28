"""Checksum tests — known-answer values from docs/checksum.md."""

import pytest

from youfs.protocol import crc8, crc16_arc, crc16_modbus, made_session_key


def test_crc8_poly07_known_answer():
    # libBleLib.so init_crc8 table = CRC-8/SMBUS parameters;
    # "123456789" -> 0xF4 verified in disassembly report.
    assert crc8(b"123456789") == 0xF4
    assert crc8(b"") == 0x00
    assert crc8(b"\x00") == 0x00


def test_crc16_arc_known_answer():
    # CRC-16/ARC ("CRC-16/IBM") standard check value
    assert crc16_arc(b"123456789") == 0xBB3D


def test_crc16_modbus_known_answer():
    # matches native crc4otaPackage / Java CRCUtils.bdpdqbp(byte[])
    assert crc16_modbus(b"123456789") == 0x4B37


def test_crc16_arc_matches_java_table_variant():
    # CRC16.java TABLE variant (init 0) must equal the bitwise implementation
    data = bytes(range(64))
    crc = 0
    table = _build_table()
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    assert crc == crc16_arc(data)


def _build_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
        table.append(c)
    return table


def _crc8_poly07_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c << 1) ^ 0x07) if c & 0x80 else c << 1
        table.append(c & 0xFF)
    return table


def test_made_session_key_is_sbox_substitution():
    data = bytes(range(16))
    out = made_session_key(data)
    assert len(out) == 16
    table = _crc8_poly07_table()
    assert out == bytes(table[b] for b in data)


def test_made_session_key_len12_wrap_path():
    # native len<16 path (P1Normal calls madeSessionKey(in, 12, out)):
    # out[i] = table[in[i]] for i<12; out[i] = table[(in[i-12]+in[i-11]) & 0xff]
    data = bytes(range(12))
    out = made_session_key(data)
    table = _crc8_poly07_table()
    assert out[:12] == bytes(table[b] for b in data)
    assert out[12] == table[(data[0] + data[1]) & 0xFF]
    assert out[15] == table[(data[3] + data[4]) & 0xFF]
