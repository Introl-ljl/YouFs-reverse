"""BLE discovery and conservative parsing of Tuya-family advertisements.

The original APK parses manufacturer-specific AD type 0xFF. Service data under
0xFE95 is retained as an explicitly non-original diagnostic extension observed
on other devices; it does not establish that a YouFs vehicle uses that format.
The BLE stack's scan-object address is always kept as the connection address.
Addresses embedded in advertisements are metadata only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence

# Company ids seen in ThingBeaconParser (pbbqdqp.java:588-940), little-endian
# read of mfd[0:2].  The 0xXX84 variants have bit7 of the first byte set,
# meaning the device is already bound to an account.
TUYA_COMPANY_IDS = {
    0x5904: "tuya_single_ble",
    0x5984: "tuya_single_ble",
    0x5902: "tuya_beacon",
    0x5982: "tuya_beacon",
    0x6902: "tuya_beacon_alt",
    0x6982: "tuya_beacon_alt",
    0x07D0: "tuya_standard",
    0x0259: "tuya_legacy",
}
SINGLE_BLE_COMPANY_IDS = {0x5904, 0x5984}
BEACON_COMPANY_IDS = {0x5902, 0x5982, 0x6902, 0x6982}
LEGACY_COMPANY_ID = 0x0259
STANDARD_COMPANY_ID = 0x07D0
BEACON_SERVICE_UUID = "000001a2-0000-1000-8000-00805f9b34fb"

# 16-bit form of the service data UUID used by the newer advertising format.
FE95_UUID_16 = 0xFE95
FE95_UUID_FULL = "0000fe95-0000-1000-8000-00805f9b34fb"


@dataclass
class TuyaAdv:
    company_id: int
    bound: bool
    kind: str
    mac: Optional[str] = None
    adv_type: Optional[int] = None
    device_uuid: str = ""
    raw: bytes = b""
    original_app_supported: bool = True


def _uuid_key(value: object) -> str:
    text = str(value).strip().lower()
    if len(text) == 4:
        return f"0000{text}-0000-1000-8000-00805f9b34fb"
    if len(text) == 8:
        return f"{text}-0000-1000-8000-00805f9b34fb"
    return text


def _useful_payload(payload: bytes) -> bool:
    """Mirror the original parser's rejection of all-zero and all-0x46 IDs."""
    return bool(payload) and any(payload) and any(value != 0x46 for value in payload)


def _format_mac(data: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in data)


def parse_tuya_mfd(mfd: bytes,
                   service_uuids: Sequence[object] = ()) -> Optional[TuyaAdv]:
    """Parse the manufacturer specific data of a Tuya advertisement.

    ``mfd`` includes the 2-byte little-endian company id, matching the raw
    manufacturer structure consumed by the APK. Branches with incomplete or
    obviously padded payloads are rejected. Beacon variants additionally need
    the 0x01A2 service UUID, as in the APK parser.
    """
    if len(mfd) < 2:
        return None
    company = mfd[0] | (mfd[1] << 8)
    kind = TUYA_COMPANY_IDS.get(company)
    if kind is None:
        return None
    payload = bytes(mfd[2:])
    bound = company == 0x5984

    if company in SINGLE_BLE_COMPANY_IDS:
        # ThingBeaconParser rejects records shorter than 18 bytes, decodes
        # [MAC:6][type:1][UUID:...], and filters empty/padded UUIDs.
        if len(mfd) < 18 or len(payload) < 16:
            return None
        mac_bytes, adv_type, uuid_bytes = payload[:6], payload[6], payload[7:]
        if not _useful_payload(uuid_bytes):
            return None
        uuid = uuid_bytes.decode("ascii", "replace").rstrip("\x00\xff")
        if not uuid or "\ufffd" in uuid:
            return None
        # The APK reverses the six MAC octets when the device UUID starts "key".
        mac_data = mac_bytes[::-1] if uuid.startswith("key") else mac_bytes
        return TuyaAdv(company_id=company, bound=bound, kind=kind,
                       mac=_format_mac(mac_data), adv_type=adv_type,
                       device_uuid=uuid, raw=bytes(mfd))

    if company in BEACON_COMPANY_IDS:
        service_keys = {_uuid_key(uuid) for uuid in service_uuids}
        if BEACON_SERVICE_UUID not in service_keys or len(mfd) < 26:
            return None
        # Encrypted beacon fields are not decoded here; retain the candidate
        # only when the data is not the padding rejected by the original parser.
        if not _useful_payload(payload):
            return None
        return TuyaAdv(company_id=company, bound=bound, kind=kind,
                       raw=bytes(mfd))

    if company == LEGACY_COMPANY_ID:
        if len(mfd) != 28 or not _useful_payload(payload):
            return None
        return TuyaAdv(company_id=company, bound=bound, kind=kind,
                       raw=bytes(mfd))

    if company == STANDARD_COMPANY_ID:
        if len(mfd) < 20 or not _useful_payload(payload):
            return None
        return TuyaAdv(company_id=company, bound=bound, kind=kind,
                       raw=bytes(mfd))

    return None


def parse_tuya_service_data(data: bytes) -> Optional[TuyaAdv]:
    """Parse a 0xFE95 service-data advertisement.

    Layout measured on two independent real devices: the 6-byte device MAC
    sits at [5:11], little-endian (e.g. advert bytes `59 4e 83 83 ed dc` ->
    MAC 11:22:33:44:55:66). The surrounding bytes are preserved in `raw` but
    their meaning is NOT established, so nothing is claimed about them.

    Returns None when the payload is too short to carry a MAC.
    """
    if len(data) < 11:
        return None
    mac = ":".join(f"{b:02X}" for b in reversed(data[5:11]))
    kind = "fe95_service_data_extension" if data[:2] == b"\xb0\x54" else "service_data_extension"
    return TuyaAdv(company_id=FE95_UUID_16, bound=False, kind=kind,
                   mac=mac, raw=data, original_app_supported=False)


@dataclass
class FoundDevice:
    name: str
    address: str
    rssi: int
    adv: Optional[TuyaAdv]
    # Keep the scan-time object so callers can connect without Bleak doing an
    # implicit address lookup/re-scan. Never replace this with adv.mac.
    ble_device: Any = None


def _mac_from_address(address: str) -> Optional[str]:
    """Last 6 bytes of a BLE address, when it looks like a MAC."""
    parts = address.replace("-", ":").split(":")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(part, 16):02X}" for part in parts)
    except ValueError:
        return None


def macs_match(scan_address: str, device_mac: str) -> bool:
    """Compare a live BLE address with a bound DeviceBean MAC.

    This mirrors ThingBleUtil.convertMac matching. Advertisement payload MACs
    are deliberately not accepted here; callers must pass the scan object's
    address and the account/device record's MAC.
    """
    left = _mac_from_address(scan_address)
    right = _mac_from_address(device_mac)
    return left is not None and right is not None and left == right


async def scan_tuya(timeout: float = 8.0,
                    name_filter: str = "",
                    include_all: bool = False) -> List[FoundDevice]:
    """Scan for Tuya-advertising BLE devices (requires bleak + a BT adapter).

    include_all=True returns every device seen (adv=None when unrecognised),
    which is what to use when identifying an unknown unit in the field.
    """
    import asyncio

    from bleak import BleakScanner  # imported lazily; not needed for tests

    found: dict = {}

    def _cb(device, adv):
        name = device.name or ""
        if name_filter and name_filter.lower() not in name.lower():
            return
        parsed: Optional[TuyaAdv] = None
        for cid, data in (adv.manufacturer_data or {}).items():
            mfd = struct.pack("<H", cid) + bytes(data)
            parsed = parse_tuya_mfd(mfd, getattr(adv, "service_uuids", ()) or ())
            if parsed is not None:
                break
        if parsed is None:
            for uuid, data in (adv.service_data or {}).items():
                if _uuid_key(uuid) == FE95_UUID_FULL:
                    parsed = parse_tuya_service_data(bytes(data))
                    if parsed is not None:
                        break
        # A 0xFE95 packet is kept for diagnosis but is not one of the APK's
        # recognized discovery branches, so do not surface it as a candidate
        # in the normal vehicle scan.
        if (parsed is None or not parsed.original_app_supported) and not include_all:
            return
        found[device.address] = FoundDevice(
            name=name, address=device.address,
            rssi=adv.rssi if adv.rssi is not None else -999, adv=parsed,
            ble_device=device)

    scanner = BleakScanner(detection_callback=_cb)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()
    return sorted(found.values(), key=lambda d: d.rssi, reverse=True)

