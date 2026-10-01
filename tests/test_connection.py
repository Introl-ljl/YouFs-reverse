"""Offline checks for the APK-backed fail-closed connection state machine."""

import asyncio
import hashlib

import pytest

from youfs import commands as C
from youfs.connection import (ConnectionError, ConnectionState,
                              DeviceConnectionConfig, PairRep, ProtocolFamily,
                              YouFsConnection, protocol_family_for_type,
                              build_p4_legacy_pair_payload)
from youfs.protocol import (Ret, build_app_frame, derive_key14, derive_key15,
                            derive_key4, derive_key5, parse_ret,
                            trsmitr_encode)


def config(**overrides):
    values = {
        "protocolType": 413,
        "connectType": 0,
        "securityMode": "legacy",
        "uuid": "0123456789abcdef0123",
        "devId": "device-123",
        "localKey": "abcdef1234567890",
    }
    values.update(overrides)
    return values


def ret(code, sn, sn_ack, flag, data, key):
    raw = build_app_frame(sn=sn, sn_ack=sn_ack, code=code, data=data,
                          key=key, flag=flag, iv=b"\x11" * 16)
    return parse_ret(raw, key=key)


def device_info_response(*, srand, flags=0, protocol=(3, 0), flag2=0,
                         auth_field=b"0" * 32):
    """P4 DeviceInfoRep base fields plus the 3.0+ flag2/devId extension."""
    data = bytearray(77)
    data[0:4] = bytes((1, 2, protocol[0], protocol[1]))
    data[4] = flags
    data[5] = 1
    data[6:12] = srand
    data[12:14] = bytes((1, 0))
    data[14:46] = auth_field
    data[46:54] = bytes((1, 0, 0, 1, 0, 0, 0, 0))
    data[54] = flag2
    data[55:77] = b"dev-id" + bytes(16)
    return bytes(data)


def test_p4_legacy_cmd0_key4_then_cmd1_key5_reaches_ready():
    captured = []
    login_key = b"abcdef"
    key4 = hashlib.md5(login_key).digest()
    srand = bytes((1, 2, 3, 4, 5, 6))
    key5 = derive_key5(login_key, srand)

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        captured.append((request, expected_sn, response_flag, timeout))
        if request.code == C.CMD_DEVICE_INFO:
            device_info = device_info_response(srand=srand)
            return ret(0, 100, expected_sn, 4, device_info, key4)
        assert request.code == C.CMD_PAIR
        assert request.flag == 5
        assert request.data == build_p4_legacy_pair_payload(
            uuid="0123456789abcdef0123", login_key=login_key,
            dev_id="device-123")
        return ret(1, 101, expected_sn, 5, b"\x02", key5)

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=True)
    info = asyncio.run(client.establish())

    assert info.srand == srand
    assert client.state is ConnectionState.READY
    assert client.session_key == key5
    assert client.bind_status is True
    assert [item[0].code for item in captured] == [0, 1]
    assert [item[2] for item in captured] == [4, 5]
    assert captured[0][0].data == b"\x00\x17"
    assert client.require_ready() == key5


def test_static_p4_cmd0_cmd1_and_trsmitr_vectors_from_apk_algorithms():
    """Static deterministic vectors; derived independently from DEX formulas.

    These are not hardware captures. They pin the source-backed field order,
    security flags, AES envelope, CRC and 20-byte Packer fragmentation.
    """
    login_key = b"012345"
    srand = b"123456"
    iv = bytes(16)
    key4 = derive_key4(login_key)
    key5 = derive_key5(login_key, srand)

    cmd0 = build_app_frame(0, 0, 0, b"\x00\x14", key4, 4, iv)
    assert cmd0.hex() == (
        "04000000000000000000000000000000005a44fd7203a717792e2e2baf1362b7e9")

    pair_data = build_p4_legacy_pair_payload(
        uuid="0123456789abcdefghij", login_key=login_key, dev_id="dev-42")
    assert pair_data.hex() == (
        "00108310518720928b30d38f411493ff3031323334356465762d3432"
        "000000000000000000000000000000000001")
    cmd1 = build_app_frame(1, 0, C.CMD_PAIR, pair_data, key5, 5, iv)
    assert cmd1.hex() == (
        "050000000000000000000000000000000009fe002b15d59080be49c5111f971dbb"
        "468fadf7943a4ccce0291085907969945c27f455d92baa1aa8dbdf5707f53ad"
        "55822fcf672d05a4f4a3771d07136dd89")
    assert [packet.hex() for packet in trsmitr_encode(cmd1, 20)] == [
        "0051200500000000000000000000000000000000",
        "0109fe002b15d59080be49c5111f971dbb468fad",
        "02f7943a4ccce0291085907969945c27f455d92b",
        "03aa1aa8dbdf5707f53ad55822fcf672d05a4f4a",
        "043771d07136dd89",
    ]


@pytest.mark.parametrize("overrides", [
    {"protocolType": 100},
    {"protocolType": 999},
    {"connectType": 1},
    {"securityMode": "unknown"},
])
def test_unverified_protocol_or_security_fails_before_exchange(overrides):
    calls = []

    async def exchange(*args, **kwargs):
        calls.append(args)
        raise AssertionError("fail-closed validation must precede exchange")

    # An unknown securityMode is rejected at profile construction (from_mapping
    # runs inside the YouFsConnection constructor); the other overrides reach
    # the pre-exchange validation inside establish().
    try:
        client = YouFsConnection(config(**overrides), exchange, mtu_payload=23,
                                 transport_ready=True)
    except ConnectionError:
        return
    with pytest.raises(ConnectionError):
        asyncio.run(client.establish())
    assert calls == []
    assert client.state is ConnectionState.FAILED
    with pytest.raises(ConnectionError, match="READY"):
        client.require_ready()


def test_need_beacon_key_without_cloud_credential_uses_apk_marker0_fallback():
    calls = []
    login_key = b"abcdef"
    key4 = hashlib.md5(login_key).digest()
    srand = b"123456"
    key5 = derive_key5(login_key, srand)

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        calls.append((request.code, request.data))
        if request.code == C.CMD_DEVICE_INFO:
            # DeviceInfoRep flag bit 0x10 is needBeaconKey. APK pairDevice
            # still uses marker 0 when the cloud beaconKey is null.
            data = device_info_response(srand=srand, flags=0x10)
            return ret(0, 30, expected_sn, 4, data, key4)
        assert request.code == C.CMD_PAIR
        return ret(1, 31, expected_sn, 5, b"\x00", key5)

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=True)
    asyncio.run(client.establish())
    assert [code for code, _ in calls] == [C.CMD_DEVICE_INFO, C.CMD_PAIR]
    assert calls[1][1] == build_p4_legacy_pair_payload(
        uuid="0123456789abcdef0123", login_key=login_key,
        dev_id="device-123", need_beacon_key=True)
    assert calls[1][1][44:46] == b"\x00\x01"
    assert client.state is ConnectionState.READY


def test_p4_pair_payload_encodes_required_beacon_key_as_16_byte_field():
    payload = build_p4_legacy_pair_payload(
        uuid="0123456789abcdef0123", login_key=b"abcdef",
        dev_id="device-123", need_beacon_key=True,
        beacon_key="aabbcc")
    # uuid(16) + loginKey(6) + devId(22) precede marker and key bytes.
    assert payload[44:61] == b"\x10\xaa\xbb\xcc" + bytes(13)
    assert payload[-1:] == b"\x01"
    fallback = build_p4_legacy_pair_payload(
        uuid="0123456789abcdef0123", login_key=b"abcdef",
        dev_id="device-123", need_beacon_key=True)
    assert fallback[44:46] == b"\x00\x01"


def test_need_beacon_key_with_activator_key_matches_apk_payload_and_can_ready():
    login_key = b"abcdef"
    srand = bytes(range(6))
    key4 = derive_key4(login_key)
    key5 = derive_key5(login_key, srand)
    seen = []

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        seen.append(request.code)
        if request.code == C.CMD_DEVICE_INFO:
            return ret(0, 50, expected_sn, 4,
                       device_info_response(srand=srand, flags=0x10), key4)
        expected_payload = build_p4_legacy_pair_payload(
            uuid="0123456789abcdef0123", login_key=login_key,
            dev_id="device-123", need_beacon_key=True,
            beacon_key="aabbcc")
        assert request.data == expected_payload
        return ret(1, 51, expected_sn, 5, b"\x00", key5)

    client = YouFsConnection(config(beaconKey="aabbcc"), exchange,
                             mtu_payload=23, transport_ready=True)
    asyncio.run(client.establish())
    assert seen == [C.CMD_DEVICE_INFO, C.CMD_PAIR]
    assert client.state is ConnectionState.READY


@pytest.mark.parametrize("flags,protocol,flag2", [
    (0x02, (3, 0), 0),  # v4NeedAuth
    (0x08, (3, 0), 0),  # v4NeedServerAuth
    (0x40, (3, 0), 0),  # supportSecurityUpdate
    (0x80, (3, 0), 0),  # enableSecurityUpdate
    (0x00, (4, 0), 0x02),  # protocol >= 4 supportSecurityUpdate
    (0x00, (4, 0), 0x04),  # protocol >= 4 enableSecurityUpdate
])
def test_unimplemented_device_info_security_flags_refuse_before_cmd1(
        flags, protocol, flag2):
    login_key = b"abcdef"
    key4 = derive_key4(login_key)
    calls = []

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        calls.append(request.code)
        return ret(0, 50, expected_sn, 4,
                   device_info_response(srand=b"123456", flags=flags,
                                        protocol=protocol, flag2=flag2), key4)

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError):
        asyncio.run(client.establish())
    assert calls == [C.CMD_DEVICE_INFO]
    assert client.state is ConnectionState.FAILED


def test_need_beacon_key_with_malformed_activator_key_refuses_before_cmd1():
    login_key = b"abcdef"
    key4 = derive_key4(login_key)
    calls = []

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        calls.append(request.code)
        return ret(0, 50, expected_sn, 4,
                   device_info_response(srand=b"123456", flags=0x10), key4)

    client = YouFsConnection(config(beaconKey="not-hex"), exchange,
                             mtu_payload=23, transport_ready=True)
    with pytest.raises(ConnectionError, match="hex"):
        asyncio.run(client.establish())
    assert calls == [C.CMD_DEVICE_INFO]


def test_notify_gatt_readiness_is_required_before_cmd0():
    calls = []

    async def exchange(*args, **kwargs):
        calls.append(args)

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=False)
    with pytest.raises(ConnectionError, match="notify"):
        asyncio.run(client.establish())
    assert not calls


@pytest.mark.parametrize("bad_ret", [
    Ret(flag=4, sn=9, sn_ack=99, code=0, data=b"", crc_ok=True),
    Ret(flag=4, sn=9, sn_ack=0, code=0, data=b"", crc_ok=False),
    Ret(flag=0, sn=9, sn_ack=0, code=0, data=b"", crc_ok=True),
    Ret(flag=4, sn=9, sn_ack=0, code=3, data=b"", crc_ok=True),
])
def test_cmd0_response_must_match_ack_code_crc_and_flag(bad_ret):
    async def exchange(*args, **kwargs):
        return bad_ret

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError):
        asyncio.run(client.establish())
    assert client.state is ConnectionState.FAILED
    assert client.session_key is None


def test_cmd0_alone_never_reaches_ready_and_empty_pairrep_fails():
    login_key = b"abcdef"
    key4 = hashlib.md5(login_key).digest()

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        if request.code == 0:
            data = bytes([1, 2, 3, 0, 0, 1]) + bytes(range(6))
            return ret(0, 50, 1, 4,
                       device_info_response(srand=bytes(range(6))), key4)
        return ret(1, 51, 2, 5, b"", derive_key5(login_key, bytes(range(6))))

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError, match="PairRep"):
        asyncio.run(client.establish())
    assert client.state is ConnectionState.FAILED
    with pytest.raises(ConnectionError, match="READY"):
        client.require_ready("DP query")


@pytest.mark.parametrize("status", [1, 255])
def test_nonaccepted_pairrep_status_does_not_reach_ready(status):
    login_key = b"abcdef"
    key4 = hashlib.md5(login_key).digest()
    srand = bytes(range(6))
    key5 = derive_key5(login_key, srand)

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        if request.code == C.CMD_DEVICE_INFO:
            return ret(0, 50, 1, 4,
                       device_info_response(srand=srand), key4)
        return ret(1, 51, 2, 5, bytes([status]), key5)

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError, match="expected 0 or 2"):
        asyncio.run(client.establish())
    assert client.state is ConnectionState.FAILED
    assert client.session_key is None


@pytest.mark.parametrize("bad_ret", [
    Ret(flag=5, sn=51, sn_ack=99, code=1, data=b"\0", crc_ok=True),
    Ret(flag=5, sn=51, sn_ack=1, code=1, data=b"\0", crc_ok=False),
    Ret(flag=4, sn=51, sn_ack=1, code=1, data=b"\0", crc_ok=True),
    Ret(flag=5, sn=51, sn_ack=1, code=3, data=b"\0", crc_ok=True),
])
def test_cmd1_response_must_match_ack_code_crc_and_flag(bad_ret):
    login_key = b"abcdef"
    key4 = hashlib.md5(login_key).digest()
    srand = bytes(range(6))

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        if request.code == C.CMD_DEVICE_INFO:
            return ret(0, 50, 0, 4,
                       device_info_response(srand=srand), key4)
        return bad_ret

    client = YouFsConnection(config(), exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError):
        asyncio.run(client.establish())
    assert client.state is ConnectionState.FAILED
    assert client.session_key is None


@pytest.mark.parametrize("uuid", ["0123456789abcdef0123", "abc", "测试uuid"])
def test_pair_payload_layout_is_deterministic(uuid):
    payload = build_p4_legacy_pair_payload(
        uuid=uuid, login_key=b"abcdef", dev_id="device-123")
    assert payload.endswith(b"device-123" + b"\0" * 12 + b"\0\1")
    assert len(payload) == len(payload[:16]) + 6 + 22 + 2


def test_profile_mapping_reports_missing_required_fields_without_values():
    with pytest.raises(ConnectionError, match="protocol_type.*connect_type"):
        DeviceConnectionConfig.from_mapping({"localKey": "secret"})


def test_config_repr_does_not_disclose_local_key():
    item = DeviceConnectionConfig.from_mapping(config())
    assert "local_key" not in repr(item)
    assert "abcdef1234567890" not in repr(item)


@pytest.mark.parametrize("field,value", [
    ("protocolType", 413.0), ("protocolType", True),
    ("connectType", 0.0), ("connectType", False),
])
def test_profile_mapping_rejects_non_exact_integer_selectors(field, value):
    with pytest.raises(ConnectionError, match="must be an integer"):
        DeviceConnectionConfig.from_mapping(config(**{field: value}))


def test_protocol_type_selection_matches_apk_factory_without_fallback_send():
    assert protocol_family_for_type(413) is ProtocolFamily.P4
    assert all(protocol_family_for_type(v) is ProtocolFamily.P4
               for v in (400, 401, 402, 403, 404, 405))
    assert protocol_family_for_type(100) is ProtocolFamily.P1_NORMAL
    assert protocol_family_for_type(101) is ProtocolFamily.P1_WIFI
    assert protocol_family_for_type(102) is ProtocolFamily.P1_SECURITY
    assert protocol_family_for_type(999) is ProtocolFamily.P2


@pytest.mark.parametrize("status,accepted", [(0, True), (2, True), (1, False), (255, False)])
def test_pairrep_apk_flag_and_strict_client_acceptance(status, accepted):
    response = PairRep.parse(bytes([status]))
    assert response.apk_success is True  # APK parser accepts any nonempty data.
    assert response.bind_status is accepted  # APK's bindStatus is 0 or 2.
    assert response.accepted is accepted  # Client only marks these READY.


# --- new-security path (flag14/key14, flag15/key15) -------------------------- #

def new_security_config(**overrides):
    values = config()
    values["securityMode"] = "new"
    values["secKey"] = "SECkEY123456789"
    values.update(overrides)
    return values


def test_new_security_cmd0_uses_key14_flag14_and_sn1():
    captured = []
    local_key = "abcdef1234567890"
    sec_key = "SECkEY123456789"
    key14 = derive_key14(local_key, sec_key)
    srand = bytes((9, 8, 7, 6, 5, 4))

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        captured.append((request, expected_sn, response_flag))
        assert expected_sn == 1 and response_flag == 14
        # proto 4.0: security-update support/enable live in flag2 bits 1/2.
        info = device_info_response(srand=srand, protocol=(4, 0), flag2=0x06)
        return ret(0, 100, expected_sn, 14, info, key14)

    client = YouFsConnection(new_security_config(), exchange, mtu_payload=23,
                             transport_ready=True)
    info = asyncio.run(client.establish.__wrapped__(client)) if False else None
    # run only cmd0 by aborting after device info via a cmd1 exchange failure
    try:
        asyncio.run(client.establish())
    except ConnectionError:
        pass
    request, expected_sn, response_flag = captured[0]
    assert request.code == C.CMD_DEVICE_INFO
    assert request.data == (23).to_bytes(2, "big")
    assert request.sn == 1 and request.sn_ack == 0
    assert client.device_info is not None
    assert client.device_info.srand == srand


def test_new_security_full_handshake_reaches_ready_with_flag15():
    local_key = "abcdef1234567890"
    sec_key = "SECkEY123456789"
    login_key = local_key[:6].encode("utf-8")
    key14 = derive_key14(local_key, sec_key)
    srand = bytes((9, 8, 7, 6, 5, 4))
    key15 = derive_key15(local_key, sec_key, srand)
    captured = []

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        captured.append((request, expected_sn, response_flag))
        if request.code == C.CMD_DEVICE_INFO:
            assert expected_sn == 1 and response_flag == 14
            info = device_info_response(srand=srand, protocol=(4, 0),
                                        flag2=0x06)
            return ret(0, 100, 1, 14, info, key14)
        assert expected_sn == 2 and response_flag == 15
        assert request.sn == 2 and request.sn_ack == 0
        return ret(1, 101, 2, 15, b"\x02", key15)

    client = YouFsConnection(new_security_config(), exchange, mtu_payload=23,
                             transport_ready=True)
    asyncio.run(client.establish())
    assert client.state is ConnectionState.READY
    assert client.session_flag == 15
    assert client.session_key == key15
    assert client.bind_status is True
    # cmd1 request encrypted with key15 carries the APK new-security tail:
    # loginKeyComplete + secretKey + 4 zero verifyKey bytes after marker 0x01.
    pair_request = captured[1][0]
    expected_tail = (local_key.encode("utf-8") + sec_key.encode("utf-8") +
                     b"\x00" * 4)
    assert pair_request.data.endswith(b"\x01" + expected_tail)
    assert len(pair_request.data) == 16 + 6 + 22 + 1 + 1 + len(expected_tail)


def test_new_security_refused_when_device_lacks_security_update_support():
    key14 = derive_key14("abcdef1234567890", "SECkEY123456789")
    calls = []

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        calls.append(request.code)
        info = device_info_response(srand=bytes(6), protocol=(4, 0), flag2=0x00)
        return ret(0, 100, expected_sn, 14, info, key14)

    client = YouFsConnection(new_security_config(), exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError, match="supportSecurityUpdate"):
        asyncio.run(client.establish())
    assert calls == [C.CMD_DEVICE_INFO]


def test_new_security_refused_without_seckey_before_any_exchange():
    calls = []

    async def exchange(*args, **kwargs):
        calls.append(args)
        raise AssertionError("no exchange without secKey")

    cfg = new_security_config()
    cfg.pop("secKey")
    client = YouFsConnection(cfg, exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError, match="secKey"):
        asyncio.run(client.establish())
    assert calls == []


def test_new_security_server_auth_flag_refuses_cmd1():
    key14 = derive_key14("abcdef1234567890", "SECkEY123456789")
    calls = []

    async def exchange(frame, *, expected_sn, response_key, response_flag,
                       timeout):
        request = parse_ret(frame, key=response_key)
        calls.append(request.code)
        # flag bit1 (0x02) = v4NeedAuth → server-cert path, not implementable.
        info = device_info_response(srand=bytes(6), protocol=(4, 0), flags=0x02,
                                    flag2=0x06)
        return ret(0, 100, expected_sn, 14, info, key14)

    client = YouFsConnection(new_security_config(), exchange, mtu_payload=23,
                             transport_ready=True)
    with pytest.raises(ConnectionError, match="v4/server authentication"):
        asyncio.run(client.establish())
    assert calls == [C.CMD_DEVICE_INFO]
