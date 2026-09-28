"""Protocol codec round-trips: trsmitr, app frame, AES, DP TLV, device info."""

import pytest

from youfs.protocol import (Dp, TrsmitrAssembler, aes128_cbc_decrypt,
                            aes128_cbc_encrypt, build_app_frame,
                            derive_key4, derive_key5, dp_decode, dp_encode,
                            parse_device_info, parse_ret,
                            trsmitr_encode, varint_decode, varint_encode)


# --- AES sanity (FIPS-197 vector) ------------------------------------------- #

def test_aes128_fips197_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aes128_cbc_encrypt(key, b"\x00" * 16, pt)
    # single ECB block with zero IV == AES-ECB of the plaintext block
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert aes128_cbc_decrypt(key, b"\x00" * 16, ct) == pt


def test_aes_cbc_multi_block_roundtrip():
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    pt = b"tuya-ble-payload" * 7      # > 1 block
    ct = aes128_cbc_encrypt(key, iv, pt)
    assert len(ct) % 16 == 0
    assert aes128_cbc_decrypt(key, iv, ct) == pt


# --- varint ----------------------------------------------------------------- #

def test_varint_roundtrip():
    for n in (0, 1, 127, 128, 255, 300, 16383, 16384, 100000):
        raw = varint_encode(n)
        val, pos = varint_decode(raw)
        assert val == n and pos == len(raw)


# --- trsmitr framing (Java Packer / native trsmitr) -------------------------- #

def test_trsmitr_single_packet():
    packets = trsmitr_encode(b"\x01\x02\x03", chunk_size=20, type_nibble=2)
    assert packets == [b"\x00\x03\x20\x01\x02\x03"]


def test_trsmitr_multi_packet_roundtrip():
    payload = bytes(range(100))
    packets = trsmitr_encode(payload, chunk_size=20, type_nibble=2)
    asm = TrsmitrAssembler()
    out = None
    for p in packets:
        out = asm.feed(p)
    assert out is not None
    cmd, seq, data = out
    assert data == payload and cmd == 2


def test_trsmitr_gap_raises():
    payload = bytes(range(60))
    packets = trsmitr_encode(payload)
    asm = TrsmitrAssembler()
    asm.feed(packets[0])
    with pytest.raises(ValueError):
        asm.feed(packets[2])


# --- application frame ------------------------------------------------------- #

def test_app_frame_plain_layout():
    frame = build_app_frame(sn=1, sn_ack=0, code=0x0003, data=b"\x01\x02")
    assert frame[0] == 0
    body = frame[1:]
    assert body[0:4] == (1).to_bytes(4, "big")        # sn BE
    assert body[4:8] == (0).to_bytes(4, "big")        # sn_ack BE
    assert body[8:10] == (0x0003).to_bytes(2, "big")  # code BE
    assert body[10:12] == (2).to_bytes(2, "big")      # len BE
    assert body[12:14] == b"\x01\x02"
    ret = parse_ret(frame)
    assert ret.sn == 1 and ret.code == 0x0003 and ret.data == b"\x01\x02"
    assert ret.crc_ok


def test_app_frame_encrypted_roundtrip():
    key = bytes(range(16))
    frame = build_app_frame(sn=7, sn_ack=3, code=0x0002,
                            data=b"\x14\x01\x01", key=key, flag=15)
    assert frame[0] == 15
    assert len(frame[17:]) % 16 == 0          # zero-padded AES-CBC
    ret = parse_ret(frame, key=key)
    assert ret.sn == 7 and ret.sn_ack == 3
    assert ret.code == 0x0002 and ret.data == b"\x14\x01\x01"
    assert ret.crc_ok


# --- key derivation ----------------------------------------------------------- #

def test_derive_key5_formula():
    import hashlib
    key = derive_key5(b"LOCALKEY", b"\x01\x02\x03")
    assert key == hashlib.md5(b"LOCALKEY" + b"\x01\x02\x03").digest()


def test_derive_key4_is_md5_of_login_key_only():
    import hashlib
    assert derive_key4(b"0123456789abcdef") == hashlib.md5(
        b"0123456789abcdef").digest()


def test_p4_legacy_cmd0_uses_key4_flag4_and_mtu_payload():
    from youfs.commands import device_info_request

    login_key = b"012345"
    frame = device_info_request(login_key, 23, sn=0, sn_ack=9)
    ret = parse_ret(frame, flags_to_key={4: derive_key4(login_key)})
    assert ret.flag == 4
    assert ret.code == 0
    assert ret.sn == 0 and ret.sn_ack == 9
    assert ret.data == b"\x00\x17"
    assert ret.crc_ok


def test_parse_ret_rejects_truncated_or_extra_plaintext_bytes():
    frame = build_app_frame(sn=1, sn_ack=0, code=0, data=b"")
    with pytest.raises(ValueError, match="short|length"):
        parse_ret(frame[:-1])
    with pytest.raises(ValueError, match="length"):
        parse_ret(frame + b"\x00")


# --- DP TLV -------------------------------------------------------------------- #

def test_dp_encode_bool_and_value():
    assert dp_encode(20, 1, True) == b"\x14\x01\x01\x01"
    # type 2 (value) is little-endian on the wire
    assert dp_encode(2, 2, 0x01020304) == b"\x02\x02\x04\x04\x03\x02\x01"


def test_dp_tlv_roundtrip_all_types():
    blob = (dp_encode(1, 1, True) + dp_encode(2, 2, -12345) +
            dp_encode(3, 3, "hello") + dp_encode(4, 4, 2) +
            dp_encode(5, 5, 0x01020304) + dp_encode(6, 0, b"\xaa\xbb"))
    dps = dp_decode(blob)
    assert [(d.dp_id, d.dp_type, d.value) for d in dps] == [
        (1, 1, True), (2, 2, -12345), (3, 3, "hello"),
        (4, 4, 2), (5, 5, 0x01020304), (6, 0, b"\xaa\xbb")]


# --- device info ---------------------------------------------------------------- #

def test_parse_device_info_proto30():
    srand = bytes.fromhex("112233445566")
    data = (b"\x01\x02"              # device version 1.2
            b"\x03\x05"              # protocol version 3.5
            b"\x0f"                  # flag
            b"\x00"                  # is_bind = false
            + srand +
            b"\x04\x05"              # hardware version 4.5
            + b"A" * 32 +            # authKey
            b"\x01\x02\x03"          # devVer2
            b"\x04\x05\x06"          # hwVer2
            b"\x00\x00"              # reserved
            b"\x00"                  # flag2
            + b"devid123".ljust(22, b"\x00"))
    info = parse_device_info(data)
    assert info.srand == srand
    assert info.protocol_version == "3.5"
    assert info.is_bind is False
    assert info.auth_key == "A" * 32
    assert info.dev_id == "devid123"


def test_parse_device_info_exposes_need_beacon_key_flag():
    data = b"\x01\x02\x03\x05\x10\x01" + b"123456"
    assert parse_device_info(data).need_beacon_key is True


# --- Tuya advertisement parsing (real captures, see docs/gatt.md) ----------- #

def test_parse_tuya_service_data_fe95_mac_matches_address():
    """Real 0xFE95 advertisements: the MAC inside the payload must equal the
    device's own BLE address. Two independent devices, both exact matches —
    this is what fixes the data[5:11]-reversed offset."""
    from youfs.scanner import parse_tuya_service_data

    cases = [
        # service data (hex)                    expected MAC
        ("b0543d450001eeddccbbaa080e00", "AA:BB:CC:DD:EE:01"),
        ("b054501301665544332211080e00", "11:22:33:44:55:66"),
    ]
    for hexdata, want_mac in cases:
        adv = parse_tuya_service_data(bytes.fromhex(hexdata))
        assert adv is not None
        assert adv.mac == want_mac
        assert adv.raw == bytes.fromhex(hexdata)


def test_parse_tuya_service_data_rejects_short_payload():
    from youfs.scanner import parse_tuya_service_data

    assert parse_tuya_service_data(b"") is None
    assert parse_tuya_service_data(b"\x01" * 10) is None


def test_parse_tuya_mfd_company_id_and_bound_flag():
    from youfs.scanner import parse_tuya_mfd

    # 0x5904 little-endian, unbound, MAC 11:22:33:44:55:66, type 1, ASCII UUID.
    # Original parser requires the complete 18-byte minimum manufacturer field.
    mfd = bytes.fromhex("0459") + bytes.fromhex("112233445566") + b"\x01" + b"keyabcdefg"
    adv = parse_tuya_mfd(mfd)
    assert adv is not None
    assert adv.company_id == 0x5904
    assert adv.bound is False
    assert adv.mac == "66:55:44:33:22:11"  # APK reverses MAC octets for UUIDs prefixed by "key".
    assert adv.adv_type == 1
    assert adv.device_uuid == "keyabcdefg"

    # 0x5984 => bit7 of mfd[0] set => bound
    bound = parse_tuya_mfd(bytes.fromhex("8459") + bytes.fromhex("112233445566") + b"\x00" + b"uuid-data")
    assert bound is not None and bound.bound is True


def test_parse_tuya_mfd_ignores_unknown_company():
    from youfs.scanner import parse_tuya_mfd

    # Apple (0x004C) is not a Tuya company id
    assert parse_tuya_mfd(bytes.fromhex("4c00") + b"\x10\x05\x0b") is None
