"""Offline checks for the CLI BLE connection stages and key wiring."""

import argparse
import asyncio
import json
import os
from types import SimpleNamespace

import cli
from youfs import scooter


def test_local_key_parsing_requires_exactly_16_bytes():
    assert cli._local_key_bytes("0123456789abcdef") == b"0123456789abcdef"
    assert cli._local_key_bytes("30313233343536373839616263646566") == b"0123456789abcdef"

    try:
        cli._local_key_bytes("short")
    except ValueError as exc:
        assert "16" in str(exc)
    else:
        raise AssertionError("short localKey was accepted")


def test_gatt_args_accept_explicit_channel_uuids():
    parser = argparse.ArgumentParser()
    cli._add_gatt_args(parser)
    args = parser.parse_args([
        "--service-uuid", "svc", "--write-uuid", "write",
        "--notify-uuid", "notify",
    ])
    assert (args.service_uuid, args.write_uuid, args.notify_uuid) == (
        "svc", "write", "notify")


def test_scan_target_uses_exact_live_address_not_advertisement_mac(monkeypatch):
    wanted = object()
    devices = [
        SimpleNamespace(address="AA:BB:CC:DD:EE:FF", ble_device=wanted,
                        adv=SimpleNamespace(mac="11:22:33:44:55:66")),
        SimpleNamespace(address="11:22:33:44:55:66", ble_device=object(),
                        adv=SimpleNamespace(mac="AA:BB:CC:DD:EE:FF")),
    ]

    async def fake_scan_tuya(**kwargs):
        assert kwargs["include_all"] is True
        return devices

    monkeypatch.setattr("youfs.scanner.scan_tuya", fake_scan_tuya)
    assert asyncio.run(cli._scan_ble_device("aa-bb-cc-dd-ee-ff")) is wanted


def test_scan_target_fails_when_explicit_address_is_absent(monkeypatch):
    async def fake_scan_tuya(**kwargs):
        return [SimpleNamespace(address="11:22:33:44:55:66",
                                ble_device=object())]

    monkeypatch.setattr("youfs.scanner.scan_tuya", fake_scan_tuya)
    try:
        asyncio.run(cli._scan_ble_device("AA:BB:CC:DD:EE:FF", timeout=0.01))
    except RuntimeError as exc:
        assert "not seen" in str(exc)
    else:
        raise AssertionError("scanner selected an unrelated nearby device")


def test_scan_command_passes_target_mac_and_reports_fd50_without_protocol_claim(
        monkeypatch, capsys):
    captured = {}
    device = SimpleNamespace(
        address="DC:17:2A:3B:4C:5D", rssi=-53, name="YouFs2", adv=None,
        target_address_observed=True, fd50_service_uuid_seen=True,
        fd50_service_data_seen=False, fd50_service_data_length=None)

    async def fake_scan_tuya(**kwargs):
        captured.update(kwargs)
        return [device]

    monkeypatch.setattr("youfs.scanner.scan_tuya", fake_scan_tuya)
    args = SimpleNamespace(timeout=1.0, name="", all=False,
                           target_mac="DC:17:2A:3B:4C:5D")
    result = asyncio.run(cli.cmd_scan(args))

    assert result == 0
    assert captured["target_mac"] == args.target_mac
    assert captured["include_all"] is True
    output = capsys.readouterr().out
    assert "目标地址已扫描到" in output
    assert "FD50 service UUID: 已观测" in output
    assert "FD50: 已观测；协议选择未验证" in output
    assert "仅扫描，未发送 cmd0 或控制帧" in output


def test_scan_command_discards_nonmatching_results_in_target_mode(monkeypatch,
                                                                  capsys):
    async def fake_scan_tuya(**_kwargs):
        return [SimpleNamespace(address="11:22:33:44:55:66", rssi=-40,
                                name="other", adv=None,
                                target_address_observed=False)]

    monkeypatch.setattr("youfs.scanner.scan_tuya", fake_scan_tuya)
    args = SimpleNamespace(timeout=1.0, name="", all=False,
                           target_mac="DC:17:2A:3B:4C:5D")
    result = asyncio.run(cli.cmd_scan(args))

    assert result == 1
    output = capsys.readouterr().out
    assert "not seen" in output
    assert "other" not in output


def test_transport_error_with_empty_text_keeps_type_and_layer(capsys):
    class EmptyBleError(Exception):
        layer = "BLE link"
        diagnostic = ""

    cli._print_connection_error(EmptyBleError(), "connect")
    output = capsys.readouterr().out
    assert "BLE link" in output
    assert "EmptyBleError" in output
    assert "no diagnostic text" in output


def test_status_derives_local_key_from_cmd0_srand(monkeypatch, capsys):
    captured = {}

    class FakeScooter:
        def __init__(self, address, **kwargs):
            captured["address"] = address
            captured["options"] = kwargs
            self.state = SimpleNamespace(raw_dps=[SimpleNamespace(
                dp_id=7, dp_type=1, value=True, raw=b"\x01", as_int=lambda: 1)])
            self.transport = SimpleNamespace(is_connected=True, notify_ready=True)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def fetch_device_info(self):
            return SimpleNamespace(srand=bytes(range(8)), is_bind=True)

        async def wait_for_report(self, timeout):
            captured["wait"] = timeout
            return self.state

    monkeypatch.setattr("youfs.scooter.YouFSScooter", FakeScooter)
    async def fake_scan(address, timeout=8.0):
        captured["scanned_address"] = address
        return object()
    monkeypatch.setattr(cli, "_scan_ble_device", fake_scan)
    args = SimpleNamespace(
        address="AA:BB", local_key="0123456789abcdef",
        cloud_device=None, protocol_type=413, security_mode="legacy",
        legacy=False, service_uuid="svc",
        write_uuid="write", notify_uuid="notify", wait=1.0)
    result = asyncio.run(cli.cmd_status(args))

    assert result == 0
    assert captured["options"]["service_uuid"] == "svc"
    assert captured["options"]["write_uuid"] == "write"
    assert captured["options"]["notify_uuid"] == "notify"
    assert captured["options"]["login_key"] == b"012345"
    assert captured["options"]["protocol_type"] == 413
    assert captured["options"]["security_mode"] == "legacy"
    assert captured["wait"] == 1.0
    output = capsys.readouterr().out
    assert "key5 derived in memory" in output
    assert "dp   7 type=1" in output


def test_dp_security_rejects_unverified_and_unsupported_combinations():
    base = dict(key=None, local_key=None, flag=None)
    assert cli._resolve_dp_security(SimpleNamespace(**base), None,
                                    control=False) == (None, 0)
    for flag in (None, 0, 12, 15):
        args = SimpleNamespace(key="00" * 16, local_key=None, flag=flag)
        try:
            cli._resolve_dp_security(args, None, control=True)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"unsafe flag {flag!r} was accepted")

    local = b"0123456789abcdef"
    for flag in (2, 12, 15):
        args = SimpleNamespace(key=None, local_key="unused", flag=flag)
        try:
            cli._resolve_dp_security(args, local, control=True)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"localKey + flag {flag} was accepted")

    args = SimpleNamespace(key="00" * 16, local_key=None, flag=2)
    assert cli._resolve_dp_security(args, None, control=True) == (bytes(16), 2)


def test_light_refuses_before_ble_or_control_write(monkeypatch, capsys):
    class MustNotConnect:
        def __init__(self, *args, **kwargs):
            raise AssertionError("light refusal must happen before BLE connection")

    monkeypatch.setattr("youfs.scooter.YouFSScooter", MustNotConnect)
    args = SimpleNamespace(address="AA:BB", action="on", key="00" * 16,
                           local_key=None, cloud_device=None, flag=2, dp=20,
                           legacy=False, service_uuid="svc", write_uuid="write",
                           notify_uuid="notify")
    result = asyncio.run(cli.cmd_light(args))

    assert result == 4
    assert "pairing is not implemented or verified" in capsys.readouterr().out


def test_scooter_refuses_all_dp_requests_until_pairing(monkeypatch):
    class FakeTransport:
        def __init__(self, **kwargs):
            pass

        async def send_frame(self, payload):
            raise AssertionError("no frame should be sent")

    monkeypatch.setattr(scooter, "YouFsTransport", FakeTransport)
    client = scooter.YouFSScooter("AA:BB", session_key=bytes(16), security_flag=5)

    async def attempt():
        for operation in (client.get_state(), client.set_light(True, dp_id=20),
                          client._request(scooter.C.CMD_DP_SEND)):
            try:
                await operation
            except RuntimeError as exc:
                assert "pairing" in str(exc)
            else:
                raise AssertionError("DP operation passed before pairing")

    asyncio.run(attempt())


def test_scooter_forwards_all_explicit_gatt_uuids(monkeypatch):
    captured = {}

    class FakeTransport:
        def __init__(self, **kwargs):
            captured["constructor"] = kwargs

        async def connect(self, address, **kwargs):
            captured["connect"] = (address, kwargs)

    monkeypatch.setattr(scooter, "YouFsTransport", FakeTransport)
    client = scooter.YouFSScooter("AA:BB", protocol_type=413,
                                  service_uuid="svc",
                                  write_uuid="write", notify_uuid="notify")
    asyncio.run(client.connect())

    assert captured["constructor"]["service_uuid"] == "svc"
    assert captured["constructor"]["protocol_type"] == 413
    assert captured["constructor"]["write_uuid"] == "write"
    assert captured["constructor"]["notify_uuid"] == "notify"
    assert captured["connect"] == ("AA:BB", {
        "protocol_type": 413, "service_uuid": "svc", "write_uuid": "write", "notify_uuid": "notify"})


def test_scooter_rejects_ble_device_for_different_declared_address():
    wrong_device = SimpleNamespace(address="11:22:33:44:55:66")
    try:
        scooter.YouFSScooter("AA:BB:CC:DD:EE:FF", ble_device=wrong_device)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("scooter accepted another device's Bleak object")


def test_scooter_cmd0_matches_p4_legacy_request_and_validates_response():
    from youfs.commands import device_info_request
    from youfs.protocol import build_app_frame, derive_key4, derive_key5, parse_ret

    login_key = b"012345"
    srand = b"123456"
    response_data = (b"\x01\x02\x03\x05\x00\x01" + srand +
                     b"\x02\x03" + b"A" * 32)

    class FakeTransport:
        is_connected = True
        notify_ready = True
        mtu = 23
        payload_mtu = 20
        service_uuid = "svc"
        write_uuid = "write"
        notify_uuid = "notify"

        def __init__(self, **kwargs):
            self.writes = []

        async def send_frame(self, frame):
            self.writes.append(frame)
            response = build_app_frame(sn=7, sn_ack=0, code=0,
                                       data=response_data,
                                       key=derive_key4(login_key), flag=4,
                                       iv=bytes(16))
            client._on_frame(2, 0, response)

    old_transport = scooter.YouFsTransport
    scooter.YouFsTransport = FakeTransport
    try:
        client = scooter.YouFSScooter("AA:BB", login_key=login_key,
                                      protocol_type=413,
                                      security_mode="legacy")
        info = asyncio.run(client.fetch_device_info())
    finally:
        scooter.YouFsTransport = old_transport

    assert info.srand == srand
    sent = parse_ret(client.transport.writes[0],
                     flags_to_key={4: derive_key4(login_key)})
    assert sent.flag == 4 and sent.code == 0 and sent.data == b"\x00\x14"
    assert client.session_key == derive_key5(login_key, srand)
    assert client.security_flag == 5


def test_scooter_cmd0_fails_closed_without_protocol_evidence():
    client = scooter.YouFSScooter("AA:BB", login_key=b"012345")

    async def attempt():
        try:
            await client.fetch_device_info()
        except RuntimeError as exc:
            assert "protocolType" in str(exc)
        else:
            raise AssertionError("cmd0 passed without explicit protocol type")

    asyncio.run(attempt())


def test_connect_command_requires_full_explicit_pairing_profile(capsys):
    args = SimpleNamespace(
        local_key="0123456789abcdef", cloud_device=None,
        protocol_type=413, connect_type=0, security_mode="legacy",
        uuid=None, dev_id="device-1", address="AA:BB:CC:DD:EE:FF",
        target_mac="AA:BB:CC:DD:EE:FF")
    try:
        cli._resolve_connection_config(args)
    except ValueError as exc:
        assert "uuid" in str(exc)
    else:
        raise AssertionError("pairing profile passed without device UUID")


def test_connect_profile_supplies_metadata_and_beacon_key_only_from_work(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    profile = {
        "protocolType": 413, "connectType": 0, "securityMode": "legacy",
        "uuid": "0123456789abcdefghij", "devId": "device-1",
        "localKey": "0123456789abcdef", "beaconKey": "00112233445566778899aabbccddeeff",
        "mac": "AA:BB:CC:DD:EE:FF",
    }
    profile_path = work / "scooter.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    args = SimpleNamespace(
        local_key=None, cloud_device=None, profile_file=str(profile_path),
        protocol_type=None, connect_type=None, security_mode=None,
        uuid=None, dev_id=None, address="aa-bb-cc-dd-ee-ff")

    resolved = cli._resolve_connection_config(args)
    assert resolved == {
        "protocolType": 413, "connectType": 0, "securityMode": "legacy",
        "uuid": "0123456789abcdefghij", "devId": "device-1",
        "localKey": "0123456789abcdef",
        "beaconKey": "00112233445566778899aabbccddeeff",
        "targetMac": "AA:BB:CC:DD:EE:FF",
    }


def test_connect_profile_missing_protocol_metadata_fails_closed(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    path = work / "incomplete.json"
    path.write_text(json.dumps({
        "localKey": "0123456789abcdef", "uuid": "0123456789abcdefghij",
        "devId": "device-1", "mac": "AA:BB:CC:DD:EE:FF",
    }), encoding="utf-8")
    args = SimpleNamespace(local_key=None, cloud_device=None,
                           profile_file=str(path), protocol_type=None,
                           connect_type=None, security_mode=None,
                           uuid=None, dev_id=None,
                           address="AA:BB:CC:DD:EE:FF")
    try:
        cli._resolve_connection_config(args)
    except ValueError as exc:
        assert "protocolType" in str(exc)
        assert "securityMode" in str(exc)
    else:
        raise AssertionError("incomplete profile was accepted")


def test_connection_profile_rejects_path_outside_workspace_work(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    outside = tmp_path / "secret.json"
    outside.write_text("{}", encoding="utf-8")
    try:
        cli._load_connection_profile(str(outside))
    except ValueError as exc:
        assert "inside" in str(exc)
    else:
        raise AssertionError("profile outside ignored work/ directory was accepted")


def test_connection_profile_rejects_work_directory_resolving_outside_project(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path.parent / f"{tmp_path.name}-outside-work"
    outside.mkdir()
    profile = work / "profile.json"
    profile.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    original_realpath = cli.os.path.realpath
    work_path = str(tmp_path / "work")

    def redirected_realpath(path):
        if os.fspath(path) == work_path:
            return str(outside)
        return original_realpath(path)

    monkeypatch.setattr(cli.os.path, "realpath", redirected_realpath)
    try:
        cli._load_connection_profile(str(profile))
    except ValueError as exc:
        assert "outside the project root" in str(exc)
    else:
        raise AssertionError("work/ redirected outside project root was accepted")


def test_connect_rejects_mixed_cloud_cache_and_profile(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    path = work / "device-a.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cli, "_find_cached_device", lambda _name: {
        "devId": "device-b", "localKey": "0123456789abcdef",
        "mac": "AA:BB:CC:DD:EE:FF",
    })
    args = SimpleNamespace(cloud_device="B", profile_file=str(path),
                           local_key=None, address="AA:BB:CC:DD:EE:FF")
    try:
        cli._resolve_connection_config(args)
    except ValueError as exc:
        assert "choose one device source" in str(exc)
    else:
        raise AssertionError("cloud/profile mixed identity sources were accepted")


def test_connect_rejects_profile_mac_for_different_target(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    profile_path = work / "device.json"
    profile_path.write_text(json.dumps({
        "protocolType": 413, "connectType": 0, "securityMode": "legacy",
        "uuid": "0123456789abcdefghij", "devId": "device-1",
        "localKey": "0123456789abcdef", "mac": "AA:BB:CC:DD:EE:FF",
    }), encoding="utf-8")
    args = SimpleNamespace(local_key=None, cloud_device=None,
                           profile_file=str(profile_path), protocol_type=None,
                           connect_type=None, security_mode=None, uuid=None,
                           dev_id=None, address="11:22:33:44:55:66")
    try:
        cli._resolve_connection_config(args)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("profile credentials were accepted for another BLE address")


def test_connect_rejects_explicit_mac_override_conflicting_with_profile(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    profile_path = work / "device.json"
    profile_path.write_text(json.dumps({
        "protocolType": 413, "connectType": 0, "securityMode": "legacy",
        "uuid": "0123456789abcdefghij", "devId": "device-1",
        "localKey": "0123456789abcdef", "mac": "AA:BB:CC:DD:EE:FF",
    }), encoding="utf-8")
    args = SimpleNamespace(local_key=None, cloud_device=None,
                           profile_file=str(profile_path), protocol_type=None,
                           connect_type=None, security_mode=None, uuid=None,
                           dev_id=None, address="AA:BB:CC:DD:EE:FF",
                           target_mac="11:22:33:44:55:66")
    try:
        cli._resolve_connection_config(args)
    except ValueError as exc:
        assert "conflicting MAC" in str(exc)
    else:
        raise AssertionError("explicit target MAC overrode the profile identity")


def test_connect_rejects_non_integer_profile_protocol_metadata(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(cli, "PROJECT_ROOT", str(tmp_path))
    base = {
        "protocolType": 413, "connectType": 0, "securityMode": "legacy",
        "uuid": "0123456789abcdefghij", "devId": "device-1",
        "localKey": "0123456789abcdef", "mac": "AA:BB:CC:DD:EE:FF",
    }
    args = SimpleNamespace(local_key=None, cloud_device=None,
                           profile_file=str(work / "device.json"),
                           protocol_type=None, connect_type=None,
                           security_mode=None, uuid=None, dev_id=None,
                           address="AA:BB:CC:DD:EE:FF")
    for bad_value in (413.9, True):
        profile = dict(base, protocolType=bad_value)
        (work / "device.json").write_text(json.dumps(profile), encoding="utf-8")
        try:
            cli._resolve_connection_config(args)
        except ValueError as exc:
            assert "JSON integers" in str(exc)
        else:
            raise AssertionError(f"non-integer protocolType {bad_value!r} was accepted")


def test_connect_command_calls_explicit_connection_state_machine(monkeypatch, capsys):
    captured = {}

    class FakeScooter:
        def __init__(self, address, **kwargs):
            captured["address"] = address
            captured["scooter_kwargs"] = kwargs
            self.transport = SimpleNamespace(
                is_connected=True, notify_ready=True, service_uuid="svc",
                write_uuid="write", notify_uuid="notify")
            self.connection = SimpleNamespace(bind_status=True)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def establish_protocol(self, config, timeout):
            captured["config"] = config
            captured["timeout"] = timeout
            return SimpleNamespace(protocol_version="3.5", srand=b"123456")

    monkeypatch.setattr("youfs.scooter.YouFSScooter", FakeScooter)
    async def fake_scan(address, timeout=8.0):
        captured["scanned_address"] = address
        return "scan-time-ble-device"
    monkeypatch.setattr(cli, "_scan_ble_device", fake_scan)
    args = SimpleNamespace(
        address="AA:BB:CC:DD:EE:FF", timeout=2.0, local_key="0123456789abcdef",
        cloud_device=None, protocol_type=413, connect_type=0,
        security_mode="legacy", uuid="0123456789abcdefghij",
        dev_id="device-1", target_mac="AA:BB:CC:DD:EE:FF",
        profile_file=None, legacy=False, service_uuid="svc",
        write_uuid="write", notify_uuid="notify")
    result = asyncio.run(cli.cmd_connect(args))

    assert result == 0
    assert captured["scooter_kwargs"]["login_key"] == b"012345"
    assert captured["scooter_kwargs"]["ble_device"] == "scan-time-ble-device"
    assert captured["config"]["protocolType"] == 413
    assert captured["config"]["connectType"] == 0
    assert captured["config"]["securityMode"] == "legacy"
    assert captured["timeout"] == 2.0
    assert captured["config"]["beaconKey"] is None
    output = capsys.readouterr().out
    assert "cmd 0x0001 PairRep: validated" in output
    assert "pairing-ready: established" in output
