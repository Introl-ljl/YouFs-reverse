"""Offline regression tests for original APK advertisement filtering."""

from youfs.scanner import (
    BEACON_SERVICE_UUID,
    macs_match,
    parse_tuya_mfd,
    parse_tuya_service_data,
)


def test_original_single_ble_manufacturer_layout_and_key_mac_order():
    raw = bytes.fromhex("0459 112233445566 01") + b"keyabcdef"
    parsed = parse_tuya_mfd(raw)

    assert parsed is not None
    assert parsed.original_app_supported
    assert parsed.company_id == 0x5904
    assert parsed.mac == "66:55:44:33:22:11"
    assert parsed.adv_type == 1
    assert parsed.device_uuid == "keyabcdef"


def test_original_single_ble_rejects_short_or_padded_uuid():
    prefix = bytes.fromhex("0459 112233445566 01")
    assert parse_tuya_mfd(prefix + b"key") is None
    assert parse_tuya_mfd(prefix + b"F" * 9) is None


def test_beacon_variants_require_original_service_uuid_and_minimum_length():
    # Company 0x5902 is encoded little-endian as 02 59.
    raw = bytes.fromhex("0259") + bytes(range(24))
    assert parse_tuya_mfd(raw) is None
    parsed = parse_tuya_mfd(raw, [BEACON_SERVICE_UUID])
    assert parsed is not None and parsed.kind == "tuya_beacon"
    assert parse_tuya_mfd(bytes.fromhex("0259") + bytes(range(23)),
                          [BEACON_SERVICE_UUID]) is None


def test_legacy_branch_requires_exact_28_byte_manufacturer_structure():
    # 0x0259 is encoded little-endian as 59 02.
    assert parse_tuya_mfd(bytes.fromhex("5902") + bytes(range(25))) is None
    parsed = parse_tuya_mfd(bytes.fromhex("5902") + bytes(range(26)))
    assert parsed is not None and parsed.kind == "tuya_legacy"


def test_standard_branch_is_candidate_only_and_has_minimum_length():
    parsed = parse_tuya_mfd(bytes.fromhex("d007") + bytes(range(18)))
    assert parsed is not None and parsed.kind == "tuya_standard"
    assert parsed.mac is None and parsed.original_app_supported
    assert parse_tuya_mfd(bytes.fromhex("d007") + bytes(range(17))) is None


def test_fe95_is_explicitly_non_original_extension():
    parsed = parse_tuya_service_data(bytes.fromhex("b0543d450001eeddccbbaa080e00"))
    assert parsed is not None
    assert not parsed.original_app_supported
    assert parsed.mac == "AA:BB:CC:DD:EE:01"


def test_devicebean_identity_matches_live_scan_address():
    assert macs_match("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF")
    assert not macs_match("not-a-mac", "AA:BB:CC:DD:EE:FF")


def test_scan_keeps_non_original_fe95_only_in_include_all_diagnostics(monkeypatch):
    import asyncio
    import sys
    import types

    device = types.SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name="nearby")
    advert = types.SimpleNamespace(
        manufacturer_data={},
        service_data={"0000fe95-0000-1000-8000-00805f9b34fb":
                      bytes.fromhex("b0543d450001eeddccbbaa080e00")},
        service_uuids=[],
        rssi=-48)

    class Scanner:
        def __init__(self, detection_callback):
            self.callback = detection_callback

        async def start(self):
            self.callback(device, advert)

        async def stop(self):
            pass

    monkeypatch.setitem(sys.modules, "bleak", types.SimpleNamespace(BleakScanner=Scanner))
    from youfs.scanner import scan_tuya

    assert asyncio.run(scan_tuya(timeout=0, include_all=False)) == []
    results = asyncio.run(scan_tuya(timeout=0, include_all=True))
    assert len(results) == 1
    assert results[0].adv is not None and not results[0].adv.original_app_supported
    assert results[0].ble_device is device
