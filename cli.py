#!/usr/bin/env python3
"""YouFs CLI — scan / info / status / light.

Examples:
    python cli.py scan
    python cli.py info AA:BB:CC:DD:EE:FF --protocol-type 413 --security-mode legacy --cloud-device DEVICE
    python cli.py status AA:BB:CC:DD:EE:FF --protocol-type 413 --security-mode legacy --cloud-device DEVICE

Security scope: light control only; motor/OTA/pair/unbind are not implemented.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import os
import re
from typing import Optional

# Allow `python cli.py ...` from the repo root: the package lives in src/.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "src"))

CLOUD_SECRETS = os.path.join("work", "secrets.env")
CLOUD_STATE = os.path.join("work", "youfs_cloud.json")     # session (sid/ecode)
DEVICES_STATE = os.path.join("work", "youfs_devices.json")  # cached device list
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def _local_key_bytes(spec: str) -> bytes:
    """Accept a localKey as 32 hex chars or as the raw 16-char ASCII form.

    The cloud returns 16 printable ASCII chars. The APK's ConnectParam then
    truncates this value to its first six UTF-8 bytes as loginKey."""
    s = spec.strip()
    if len(s) == 32:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    raw = s.encode("utf-8")
    if len(raw) != 16:
        raise ValueError("localKey must be exactly 16 UTF-8 bytes or 32 hex chars")
    return raw


def _find_cached_device(name_or_id: str) -> Optional[dict]:
    """Look up a device in work/youfs_devices.json by name or devId."""
    if not os.path.exists(DEVICES_STATE):
        return None
    try:
        state = json.load(open(DEVICES_STATE, encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for d in state.get("devices", []):
        if name_or_id in (d.get("devId"), d.get("name"),
                          (d.get("mac") or "").replace(":", "")):
            return d
    return None


def _load_connection_profile(path: Optional[str]) -> dict:
    """Load a local profile from work/ without exposing credentials in argv."""
    if not path:
        return {}
    project_root = os.path.realpath(PROJECT_ROOT)
    work_root = os.path.realpath(os.path.join(PROJECT_ROOT, "work"))
    try:
        work_inside_project = os.path.commonpath((project_root, work_root)) == project_root
    except ValueError:
        work_inside_project = False
    if not work_inside_project or work_root == project_root:
        raise ValueError("workspace work/ directory resolves outside the project root")
    requested = path if os.path.isabs(path) else os.path.join(PROJECT_ROOT, path)
    resolved = os.path.realpath(requested)
    try:
        inside_work = os.path.commonpath((work_root, resolved)) == work_root
    except ValueError:
        inside_work = False
    if not inside_work:
        raise ValueError("--profile-file must point inside this workspace's work/ directory")
    try:
        with open(resolved, encoding="utf-8") as fh:
            profile = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read connection profile: {exc}") from exc
    if not isinstance(profile, dict):
        raise ValueError("connection profile must be a JSON object")
    return profile


def _normalize_mac(value: str) -> str:
    """Normalize a BLE MAC address for profile-to-target identity checks."""
    compact = re.sub(r"[:-]", "", str(value)).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", compact):
        raise ValueError("target/profile MAC must contain exactly 12 hexadecimal digits")
    return compact


def _select_consistent_identity(label: str, *values,
                                normalize=lambda value: str(value)) -> Optional[str]:
    """Select an identity value, refusing conflicting explicit/source values."""
    present = [value for value in values if value not in (None, "")]
    normalized = {normalize(value) for value in present}
    if len(normalized) > 1:
        raise ValueError(f"conflicting {label} values in target/profile/cache; refusing connection")
    return present[0] if present else None


async def _scan_ble_device(address: str, timeout: float = 8.0):
    """Find the requested scan address and return its exact BleakDevice.

    Advertisement MAC/UUID payloads are metadata only and never select the
    connection target. If the address is not seen, fail instead of connecting
    to an arbitrary nearby device or asking Bleak to rescan implicitly.
    """
    from youfs.scanner import scan_tuya

    normalize = lambda value: str(value).replace("-", ":").upper()
    devices = await scan_tuya(timeout=timeout, include_all=True)
    matches = [device for device in devices
               if normalize(device.address) == normalize(address)]
    if len(matches) != 1:
        if not matches:
            raise RuntimeError(
                f"requested BLE address {address} was not seen in the scan window; "
                "confirm the target is advertising and enter its current scan address")
        raise RuntimeError(f"scan returned multiple entries for {address}")
    target = matches[0].ble_device
    if target is None:
        raise RuntimeError(f"scan matched {address} but no BleakDevice was retained")
    return target


def _add_local_key_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--local-key", help="device localKey: 32 hex chars or the "
                                       "raw 16-char ASCII form; the APK uses "
                                       "its first six characters as loginKey")
    p.add_argument("--cloud-device", metavar="NAME_OR_DEVID",
                   help="pull localKey for this device from "
                        "work/youfs_devices.json (no manual key needed)")


def _add_key_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key", help="16-byte session key, hex (32 chars)")
    _add_local_key_args(p)
    p.add_argument("--flag", type=int, default=None,
                   help="verified securityFlag from a capture (DP supports only 2/5 here; required with session credentials)")
    p.add_argument("--legacy", action="store_true",
                   help="use Telink UUID group (P2 delegate)")
    p.add_argument("--dp", type=int, default=0,
                   help="light dp_id (from `cloud schema`; no guessing)")


def _add_gatt_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--service-uuid", help="explicit GATT service UUID from `gatt` probe")
    p.add_argument("--write-uuid", help="explicit writable characteristic UUID from `gatt` probe")
    p.add_argument("--notify-uuid", help="explicit notify/indicate characteristic UUID from `gatt` probe")


def _add_protocol_args(p: argparse.ArgumentParser, *, required: bool = True) -> None:
    p.add_argument("--protocol-type", type=int,
                   choices=(400, 401, 402, 403, 404, 405, 413), required=required,
                   help="protocolType from verified device/cloud metadata; current codec supports P4 400–405 and 413")
    p.add_argument("--security-mode", choices=("legacy",), required=required,
                   help="explicitly confirmed security mode; only P4 legacy cmd0 is implemented")


def _resolve_key(args) -> Optional[bytes]:
    if args.key and (args.local_key or getattr(args, "cloud_device", None)):
        sys.exit("--key and --local-key/--cloud-device are mutually exclusive")
    if args.key:
        try:
            raw = bytes.fromhex(args.key.replace(" ", ""))
        except ValueError:
            sys.exit("--key must be 32 hexadecimal characters")
        if len(raw) != 16:
            sys.exit("--key must be 16 bytes (32 hex chars)")
        return raw
    return None  # local-key derivation needs srand → handled in cmd_info/status


def _resolve_local_key(args) -> Optional[bytes]:
    """localKey bytes from --local-key or from the cached cloud device list."""
    spec = getattr(args, "local_key", None)
    dev = getattr(args, "cloud_device", None)
    if not spec and dev:
        rec = _find_cached_device(dev)
        if rec is None:
            sys.exit(f"{dev!r} not in {DEVICES_STATE}; run `cloud devices` first")
        spec = rec.get("localKey")
        if not spec:
            sys.exit(f"no localKey cached for {dev!r}")
        print(f"[cloud] using cached localKey for {rec.get('name')} "
              f"(devId={rec.get('devId')})")
    if not spec:
        return None
    try:
        return _local_key_bytes(spec)
    except ValueError as exc:
        sys.exit(str(exc))


def _resolve_connection_config(args) -> dict:
    """Build one identity-consistent pairing profile before any BLE scan."""
    cloud_device = getattr(args, "cloud_device", None)
    profile_path = getattr(args, "profile_file", None)
    if cloud_device and profile_path:
        raise ValueError("choose one device source: --cloud-device or --profile-file; refusing to mix identities")
    record = _find_cached_device(cloud_device) if cloud_device else None
    profile = _load_connection_profile(profile_path)
    local_key = getattr(args, "local_key", None)
    source_key = ((record or {}).get("localKey") or
                  profile.get("localKey") or profile.get("local_key"))
    if local_key and source_key and _local_key_bytes(local_key) != _local_key_bytes(source_key):
        raise ValueError("--local-key conflicts with selected device source; refusing to mix credentials")
    if not local_key:
        local_key = source_key
    if not local_key:
        raise ValueError("connect requires --local-key, --cloud-device, or a work/ profile")
    raw_key = _local_key_bytes(local_key)
    try:
        local_key_text = raw_key.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("P4 connect requires the 16-character ASCII cloud localKey") from exc
    if len(raw_key) != 16 or not local_key_text.isprintable():
        raise ValueError("P4 connect requires the 16-character printable localKey")

    protocol_type = getattr(args, "protocol_type", None)
    connect_type = getattr(args, "connect_type", None)
    security_mode = getattr(args, "security_mode", None)
    fields = {
        "protocolType": (protocol_type if protocol_type is not None else
                         profile.get("protocolType", profile.get(
                             "protocol_type", (record or {}).get("protocolType")))),
        "connectType": (connect_type if connect_type is not None else
                        profile.get("connectType", profile.get(
                            "connect_type", (record or {}).get("connectType")))),
        "securityMode": (security_mode if security_mode is not None else
                         profile.get("securityMode", profile.get(
                             "security_mode", (record or {}).get("securityMode")))),
        "uuid": _select_consistent_identity(
            "uuid", getattr(args, "uuid", None), profile.get("uuid"),
            (record or {}).get("uuid")),
        "devId": _select_consistent_identity(
            "devId", getattr(args, "dev_id", None), profile.get("devId"),
            profile.get("dev_id"), (record or {}).get("devId"),
            (record or {}).get("dev_id")),
        "localKey": local_key_text,
        "beaconKey": (profile.get("beaconKey", profile.get("beacon_key")) or
                      (record or {}).get("beaconKey")),
        "targetMac": _select_consistent_identity(
            "MAC", getattr(args, "target_mac", None),
            profile.get("mac", profile.get("macAddress", profile.get("address"))),
            (record or {}).get("mac"), (record or {}).get("macAddress"),
            normalize=_normalize_mac),
    }
    missing = [name for name, value in fields.items()
               if name != "beaconKey" and value in (None, "")]
    if missing:
        raise ValueError("connect requires explicit profile fields: " + ", ".join(missing))
    if type(fields["protocolType"]) is not int or type(fields["connectType"]) is not int:
        raise ValueError("profile protocolType/connectType must be JSON integers (not booleans or floats)")
    if fields["protocolType"] not in (400, 401, 402, 403, 404, 405, 413):
        raise ValueError("profile protocolType is unsupported; only verified P4 types are accepted")
    if fields["connectType"] != 0 or str(fields["securityMode"]).lower() != "legacy":
        raise ValueError("profile must explicitly select connectType=0 and securityMode=legacy")
    fields["securityMode"] = "legacy"
    if not isinstance(fields["uuid"], str) or not isinstance(fields["devId"], str):
        raise ValueError("profile uuid/devId must be strings")
    if not fields["targetMac"]:
        raise ValueError("connect requires a device MAC in the selected profile/cache or --target-mac")
    if _normalize_mac(fields["targetMac"]) != _normalize_mac(args.address):
        raise ValueError("target address does not match the selected profile/cache device MAC; refusing connection")
    return fields


def _resolve_dp_security(args, local_key: Optional[bytes], *,
                         control: bool) -> tuple[Optional[bytes], int]:
    """Fail closed around DP traffic; only verified supported flag/key pairs pass."""
    key = _resolve_key(args)
    flag = args.flag
    if control and (key is None and local_key is None):
        sys.exit("light control requires --key or --local-key/--cloud-device")
    if key is None and local_key is None:
        if control:
            sys.exit("light control requires a session key")
        if flag is not None:
            sys.exit("--flag without session credentials is unused; omit it for passive status")
        return None, 0
    if flag is None:
        sys.exit("session credentials require explicit --flag from a verified capture; refusing to guess")
    if flag not in (2, 5):
        sys.exit(f"DP flag {flag} is unsupported here; only captured flags 2/5 are implemented")
    if local_key is not None and flag != 5:
        sys.exit("--local-key derives key5, which docs/auth.md maps to flag 5; "
                 "flag 2 needs a different key derivation, refusing to send")
    return key, flag


async def cmd_scan(args) -> int:
    from youfs.scanner import scan_tuya

    target_mac = getattr(args, "target_mac", None)
    devices = await scan_tuya(timeout=args.timeout, name_filter=args.name,
                              include_all=args.all or bool(target_mac),
                              target_mac=target_mac)
    if not devices:
        if target_mac:
            print(f"target address {target_mac} not seen in the scan window")
            print("No protocol frames were sent.")
            return 1
        print("no devices found")
        if not args.all:
            print("(only Tuya-style advertisements are listed; pass --all to "
                  "see every BLE device, which is how to identify an unknown "
                  "unit)")
        return 1
    if target_mac and not any(
            bool(getattr(device, "target_address_observed", False))
            for device in devices):
        print(f"target address {target_mac} not seen; unrelated scan results were discarded")
        return 1
    print(f"{'address':<20} {'rssi':>5}  {'name':<24} kind / details")
    for d in devices:
        adv = d.adv
        target_observed = bool(getattr(d, "target_address_observed", False))
        if target_mac and not target_observed:
            # Keep the CLI fail-closed even if an alternate scanner adapter
            # returns an unrelated record.
            continue
        if target_observed:
            fd50_seen = (bool(getattr(d, "fd50_service_uuid_seen", False)) or
                         bool(getattr(d, "fd50_service_data_seen", False)))
            print(f"目标地址已扫描到: {d.address}")
            print("FD50 service UUID: " +
                  ("已观测" if getattr(d, "fd50_service_uuid_seen", False)
                   else "未观测"))
            if getattr(d, "fd50_service_data_seen", False):
                data_len = getattr(d, "fd50_service_data_length", None)
                suffix = f" (length={data_len})" if data_len is not None else ""
                print(f"FD50 service data: 已观测{suffix}")
            print(f"FD50: {'已观测' if fd50_seen else '未观测'}；"
                  "协议选择未验证。")
            print("本次仅扫描，未发送 cmd0 或控制帧。")
        if adv is None:
            note = " (target address observed; no recognized Tuya MFD)" if target_observed else " (not Tuya)"
            print(f"{d.address:<20} {d.rssi:>5}  {d.name!r:<24}{note}")
            continue
        extra = f"bound={adv.bound} uuid={adv.device_uuid!r}" if adv.device_uuid \
            else f"bound={adv.bound}"
        print(f"{d.address:<20} {d.rssi:>5}  {d.name!r:<24} "
              f"{adv.kind}  mac={adv.mac}  {extra}")
    return 0


async def cmd_gatt(args) -> int:
    """Connect and enumerate the GATT tree, without assuming any UUID.

    The scooter's real service/characteristic UUIDs are not established
    (docs/gatt.md: FD50 group vs 1910 legacy Telink group — which one this
    scooter uses is UNKNOWN). This probe settles it on the first real
    connection and names the write/notify pair for the frame exchange."""
    from youfs.transport import (LEGACY_NOTIFY_CHAR_UUID, LEGACY_SERVICE_UUID,
                                 LEGACY_WRITE_CHAR_UUID, NOTIFY_CHAR_UUID,
                                 SERVICE_UUID, WRITE_CHAR_UUID, YouFsTransport)
    from bleak import BleakClient

    known = {
        SERVICE_UUID.lower(): ("modern FD50 group", WRITE_CHAR_UUID,
                               NOTIFY_CHAR_UUID),
        LEGACY_SERVICE_UUID.lower(): ("legacy 1910 Telink group",
                                      LEGACY_WRITE_CHAR_UUID,
                                      LEGACY_NOTIFY_CHAR_UUID),
    }
    try:
        target = await _scan_ble_device(args.address,
                                       timeout=min(args.timeout, 8.0))
    except Exception as exc:
        _print_connection_error(exc, "BLE scan")
        print("suggestion: keep the powered target advertising and use its current scan address")
        return 2
    client = BleakClient(target)
    try:
        print(f"BLE link: connecting to {args.address} …")
        await asyncio.wait_for(client.connect(), timeout=args.timeout)
    except Exception as exc:
        _print_connection_error(exc, "BLE link")
        print("suggestion: confirm the advertised address, power, range, and Windows BLE permission; "
              "if the target is not advertising, protocol-level testing cannot start")
        return 2
    try:
        print(f"connected: {args.address}  mtu={getattr(client, 'mtu_size', '?')}")
        if not client.services:
            print("GATT discovery returned no services; inspect the BLE backend, "
                  "device state, and platform permissions. This result does not "
                  "establish that pairing is required.")
            return 3

        # Reuse the transport helpers so there is one implementation.
        probe = YouFsTransport()
        probe._client = client
        print("\n--- GATT tree ---")
        print(probe.list_services())

        print("\n--- data-channel candidates (write + notify pairs) ---")
        cands = probe.find_candidate_channels()
        if not cands:
            print("   (none — no service exposes both a writable and a "
                  "notifiable characteristic)")
        for svc_uuid, w, n in cands:
            tag = known.get(svc_uuid.lower())
            note = f"   <-- {tag[0]}" if tag else ""
            print(f"   service={svc_uuid}\n      write={w}\n      notify={n}{note}")

        print("\n--- verdict ---")
        found = {s.lower() for s, _, _ in cands}
        hit = [known[s] for s in found if s in known]
        if hit:
            print(f"   recognised: {hit[0][0]}")
            selected_service = next((svc for svc, tag in known.items()
                                     if tag == hit[0]), None)
            cand = next((c for c in cands
                         if c[0].lower() == selected_service), None)
            if cand:
                print(f"   -> next: python cli.py info {args.address} "
                      f"--service-uuid {cand[0]} --write-uuid {cand[1]} "
                      f"--notify-uuid {cand[2]} [--cloud-device <name>]")
        else:
            print("   NEITHER documented preset matched. Use the exact candidate "
                  "triplet from the tree only after confirming it against the "
                  "device's actual GATT characteristics:")
            for svc_uuid, write_uuid, notify_uuid in cands:
                print(f"   python cli.py info {args.address} --service-uuid {svc_uuid} "
                      f"--write-uuid {write_uuid} --notify-uuid {notify_uuid}")
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass
    return 0


async def cmd_info(args) -> int:
    from youfs.scooter import YouFSScooter

    # Resolve the cloud localKey up front: a cache/lookup problem should say so
    # plainly instead of surfacing later as a BLE failure.
    lk = _resolve_local_key(args)
    if lk is None:
        print("cmd 0x0000 refused: original P4 cmd0 requires loginKey; supply --local-key or --cloud-device")
        return 2

    try:
        target = await _scan_ble_device(args.address)
        print(f"BLE scan: matched requested address {args.address}; connecting with scan-time device")
        async with YouFSScooter(args.address, use_legacy_uuids=args.legacy,
                                login_key=lk[:6],
                                protocol_type=args.protocol_type,
                                security_mode=args.security_mode,
                                ble_device=target,
                                service_uuid=args.service_uuid,
                                write_uuid=args.write_uuid,
                                notify_uuid=args.notify_uuid) as sc:
            _report_connection_ready(sc)
            print("cmd 0x0000: waiting for device-info response …")
            info = await sc.fetch_device_info()
            if info is None:
                print("cmd 0x0000 response: timeout; protocol readiness is unconfirmed")
                print("The device may require encrypted cmd 0 or use another protocol family.")
                return 2
            print(f"device_version    = {info.device_version}")
            print(f"protocol_version  = {info.protocol_version}")
            print(f"hardware_version  = {info.hardware_version}")
            print(f"is_bind           = {info.is_bind}")
            print(f"srand             = received ({len(info.srand)} bytes; value suppressed)")
            print(f"cmd 0x0000 response: received; bind state is_bind={info.is_bind!r}")
            print("pairing-ready: not established (cmd 1 pairing is not implemented)")
            if lk:
                print("session key key5: derived in memory; secret value suppressed")
    except Exception as exc:
        _print_connection_error(exc, "BLE/GATT or cmd 0x0000")
        return 2
    return 0


async def cmd_status(args) -> int:
    from youfs.scooter import YouFSScooter

    local_key = _resolve_local_key(args)
    if local_key is None:
        print("status refused: P4 cmd0 needs --local-key or --cloud-device; a GATT link alone cannot establish the application protocol")
        return 2
    try:
        target = await _scan_ble_device(args.address)
        print(f"BLE scan: matched requested address {args.address}; connecting with scan-time device")
        async with YouFSScooter(args.address, login_key=local_key[:6],
                                protocol_type=args.protocol_type,
                                security_mode=args.security_mode,
                                ble_device=target,
                                use_legacy_uuids=args.legacy,
                                service_uuid=args.service_uuid,
                                write_uuid=args.write_uuid,
                                notify_uuid=args.notify_uuid) as sc:
            _report_connection_ready(sc)
            print("cmd 0x0000: waiting for device-info response …")
            info = await sc.fetch_device_info()
            if info is None:
                print("cmd 0x0000 response: timeout; DP status cannot be established")
                return 2
            print("session key key5 derived in memory from localKey and cmd 0 srand")
            print(f"cmd 0x0000 response: received; bind state is_bind={info.is_bind!r}")
            print("pairing-ready: not established (cmd 1 pairing is not implemented)")
            print(f"protocolType/security mode: {args.protocol_type} / {args.security_mode}")
            state = await sc.wait_for_report(timeout=args.wait)
    except Exception as exc:
        _print_connection_error(exc, "BLE/GATT, cmd 0x0000, or DP report")
        return 2
    if not state.raw_dps:
        print("no DP report received — status is unverified; check pairing, "
              "security mode, and captured traffic (docs/capture_analysis.md)")
        return 3
    for dp in state.raw_dps:
        print(f"dp {dp.dp_id:>3} type={dp.dp_type} value={dp.value!r} "
              f"raw={dp.raw.hex()}")
    return 0


async def cmd_connect(args) -> int:
    """Explicit normal connection; this sends cmd0 and pairing cmd1."""
    from youfs.scooter import YouFSScooter

    try:
        config = _resolve_connection_config(args)
    except ValueError as exc:
        print(f"application protocol refused: {exc}")
        return 2
    try:
        target = await _scan_ble_device(args.address)
        print(f"BLE scan: matched requested address {args.address}; connecting with scan-time device")
        async with YouFSScooter(
                args.address, login_key=config["localKey"][:6].encode("utf-8"),
                protocol_type=config["protocolType"],
                security_mode=config["securityMode"],
                ble_device=target,
                use_legacy_uuids=args.legacy,
                service_uuid=args.service_uuid,
                write_uuid=args.write_uuid,
                notify_uuid=args.notify_uuid) as sc:
            _report_connection_ready(sc)
            print("application handshake: cmd 0x0000 then pairing cmd 0x0001")
            info = await sc.establish_protocol(config, timeout=args.timeout)
            print(f"cmd 0x0000 response: validated; protocol={info.protocol_version}; srand received ({len(info.srand)} bytes)")
            print("cmd 0x0001 PairRep: validated")
            print(f"pairing-ready: established; bind_status={sc.connection.bind_status}")
            print("DP/control readiness is gated on this PairRep; this command sends no DP control.")
    except Exception as exc:
        _print_connection_error(exc, "BLE/GATT, cmd 0x0000, or cmd 0x0001")
        return 2
    return 0


async def cmd_light(args) -> int:
    print("light control refused: cmd 0x0001 pairing is not implemented or "
          "verified, so the application protocol is not ready for DP writes. "
          "Use `gatt`, `info`, or passive `status` for connection diagnosis.")
    return 4


def _print_connection_error(exc: Exception, phase: str) -> None:
    layer = getattr(exc, "layer", None)
    diagnostic = getattr(exc, "diagnostic", None) or getattr(exc, "message", None)
    detail = str(diagnostic or exc).strip()
    if not detail:
        detail = "no diagnostic text supplied by the BLE backend"
    print(f"{layer or phase} ({type(exc).__name__}): {detail}")


def _report_connection_ready(sc) -> None:
    """Report only layers confirmed by transport state after connect returns."""
    transport = sc.transport
    connected = getattr(transport, "is_connected", True)
    notify_ready = getattr(transport, "notify_ready", None)
    print(f"BLE link: {'ready' if connected else 'not ready'}")
    print(f"GATT service: {getattr(transport, 'service_uuid', '?')}")
    print(f"GATT write characteristic: {getattr(transport, 'write_uuid', '?')} (selected)")
    if notify_ready is None:
        print(f"GATT notify characteristic: {getattr(transport, 'notify_uuid', '?')} "
              "(connect completed; backend did not expose a separate state)")
    else:
        notify_uuid = getattr(transport, "notify_uuid", "?")
        print(f"GATT notifications ({notify_uuid}): "
              f"{'ready' if notify_ready else 'not ready'}")
    print("GATT readiness does not imply business protocol readiness.")


def _cloud_session(force: bool = False):
    """Reuse the persisted session; log in only when there is none.

    Never logs in per-call: each login mints a new server session, and doing
    that repeatedly is a risk-control signal. Use --relogin to force."""
    from youfs.cloud import ensure_session

    return ensure_session(CLOUD_STATE, CLOUD_SECRETS, force_login=force)


def cmd_cloud(args) -> int:
    """Login to the user's own Tuya/YouFs cloud account; read localKey and
    DP schema for the scooter. Credentials come from the local secrets file."""
    from youfs.cloud import flatten_devices, save_session

    action = args.action
    force = bool(getattr(args, "relogin", False))

    if action == "login":
        client = _cloud_session(force=force)
        u = client.user or {}
        print("session:", (client.session or "")[:24], "...")
        print("homeId :", client.home_id)
        print("account:", u.get("mobile") or u.get("email") or "?")
        return 0

    client = _cloud_session(force=force)

    if action == "devices":
        hid = client.resolve_home()
        if hid is None:
            print("could not resolve homeId (list_homes failed)")
            return 3
        listing = client.list_devices(home_id=hid)
        if not listing.get("success"):
            print(json.dumps(listing, ensure_ascii=False, default=str)[:2000])
            return 3
        rows = listing.get("result")
        if not isinstance(rows, list):
            rows = flatten_devices(rows)
        out = []
        for d in rows:
            if not isinstance(d, dict):
                continue
            rec = {
                "devId": d.get("devId") or d.get("deviceId") or d.get("id"),
                "name": d.get("name"),
                "productId": d.get("productId") or d.get("productIdString"),
                "localKey": d.get("localKey"),
                "mac": d.get("mac") or d.get("macAddress"),
                "uuid": d.get("uuid"),
                "online": d.get("cloudOnline", d.get("isOnline")),
                "category": d.get("category"),
            }
            out.append(rec)
            print(f"{rec['devId']}  name={rec['name']!r} product={rec['productId']} "
                  f"mac={rec['mac']} localKey={'present' if rec['localKey'] else 'missing'} "
                  f"online={rec['online']}")
        json.dump({"homeId": hid, "devices": out},
                  open(DEVICES_STATE, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        print(f"saved {len(out)} devices to {DEVICES_STATE}")
        return 0 if out else 4

    if action == "homes":
        resp = client.list_homes()
        print(json.dumps(resp, ensure_ascii=False, default=str)[:2500])
        hid = client.resolve_home()
        save_session(CLOUD_STATE, client)
        print("homeId:", hid)
        return 0 if resp.get("success") else 3

    if action == "schema":
        dev_id = args.dev_id
        # allow passing the device name instead of id
        state = (json.load(open(DEVICES_STATE, encoding="utf-8"))
                 if os.path.exists(DEVICES_STATE) else {"devices": []})
        for d in state.get("devices", []):
            if d.get("name") == dev_id:
                dev_id = d["devId"]
                break
        detail = client.device_detail(dev_id)
        if not detail.get("success"):
            print("device detail failed:",
                  json.dumps(detail, ensure_ascii=False, default=str)[:600])
            return 3
        json.dump(detail["result"],
                  open(f"work/youfs_device_{dev_id}.json", "w",
                       encoding="utf-8"), ensure_ascii=False, indent=1,
                  default=str)

        spec = client.device_spec(dev_id)
        rows = spec.get("schema") or []
        if not rows:
            print("no DP schema available (device.get schema empty, and the "
                  "product schema fetch failed)")
            return 3
        json.dump(rows, open("work/youfs_dp_map.json", "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1, default=str)

        dev = detail["result"]
        lk = dev.get("localKey") or ""
        print(f"devId     = {dev_id}")
        print(f"name      = {dev.get('name')}")
        print(f"productId = {dev.get('productId')}")
        print(f"localKey  = {'present' if lk else 'missing'} (value suppressed)")
        print(f"mac       = {dev.get('mac')}   uuid={dev.get('uuid')}")
        print(f"\n{'dpId':>5}  {'code':<26} {'name':<16} {'type':<7} r/w   values")
        for r in sorted(rows, key=lambda x: (x.get("dpId") is None,
                                             x.get("dpId") or 0)):
            print(f"{str(r.get('dpId')):>5}  {str(r.get('code')):<26} "
                  f"{str(r.get('name')):<16} {str(r.get('type')):<7} "
                  f"{'ro' if r.get('readonly') else 'rw':<4}  "
                  f"{(r.get('values') or '')[:52]}")

        dps = dev.get("dps") or {}
        if dps:
            by_id = {r.get("dpId"): r.get("code") for r in rows}
            print("\ncurrent cloud dps (last known; device is offline):")
            for k, v in sorted(dps.items(), key=lambda kv: int(kv[0])):
                print(f"   dp {k:>4}  {str(by_id.get(int(k), '?')):<26} = {v!r}")
        return 0

    if action == "meshes":
        resp = client.list_meshes()
        if not resp.get("success"):
            print(json.dumps(resp, ensure_ascii=False, default=str)[:800])
            return 3
        json.dump(resp["result"],
                  open("work/youfs_meshes.json", "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1, default=str)
        res = resp["result"]
        for kind in ("ble_mesh_v2", "mesh", "sigmesh", "beaconMesh"):
            for m in (res.get(kind) or []) if isinstance(res, dict) else []:
                print(f"[{kind}] meshId={m.get('meshId')} code={m.get('code')} "
                      f"localKey={'present' if m.get('localKey') else 'missing'} "
                      f"srand={m.get('appNetKeySrand')}")
        return 0

    if action == "raw":
        # ad-hoc signed call for probing: raw <api> <ver> '<json postData>'
        post = json.loads(args.post) if args.post else {}
        form = json.loads(args.form) if args.form else None
        r = client.request(args.api, args.ver, post,
                           session_require=not args.no_session, form=form)
        print(json.dumps(r, ensure_ascii=False, default=str, indent=1)[:4000])
        return 0 if r.get("success") else 3

    sys.exit(f"unknown cloud action {action}")


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="python -m youfs", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan for Tuya/YouFs BLE advertisements")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--name", default="", help="substring filter on device name")
    p.add_argument("--all", action="store_true",
                   help="list every BLE device, Tuya or not (identify an "
                        "unknown unit)")
    p.add_argument("--target-mac",
                   help="scan for this exact live BLE address even without a recognized Tuya manufacturer advertisement; scan only, no protocol frames")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("gatt", help="connect + enumerate GATT tree (settles "
                                    "which UUID group the scooter uses)")
    p.add_argument("address")
    p.add_argument("--timeout", type=float, default=20.0)
    p.set_defaults(func=cmd_gatt)

    p = sub.add_parser("info", help="connect + fetch device info (cmd 0)")
    p.add_argument("address")
    _add_local_key_args(p)  # cmd 0 returns srand needed for key5 derivation
    _add_protocol_args(p)
    p.add_argument("--legacy", action="store_true",
                   help="use Telink UUID group (P2 delegate)")
    _add_gatt_args(p)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("status", help="connect + dump DP reports")
    p.add_argument("address")
    p.add_argument("--wait", type=float, default=8.0)
    _add_local_key_args(p)
    _add_protocol_args(p)
    _add_gatt_args(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("connect", help="explicit P4 legacy connection handshake (cmd 0 + pairing cmd 1)")
    p.add_argument("address")
    p.add_argument("--timeout", type=float, default=6.0)
    _add_local_key_args(p)
    _add_protocol_args(p, required=False)
    p.add_argument("--connect-type", type=int, choices=(0,),
                   help="APK connectType; only explicitly selected normal path 0 is implemented")
    p.add_argument("--uuid", help="device UUID from cloud/device metadata")
    p.add_argument("--dev-id", help="devId from cloud/device metadata")
    p.add_argument("--target-mac", help="explicitly bind this connection profile to the positional BLE address")
    p.add_argument("--profile-file", metavar="PATH",
                   help="connection JSON profile stored inside workspace work/; may contain localKey/beaconKey and protocolType/connectType/securityMode/uuid/devId")
    p.add_argument("--legacy", action="store_true",
                   help="use legacy UUID preset; conflicts with P4 profile and is normally omitted")
    _add_gatt_args(p)
    p.set_defaults(func=cmd_connect)

    p = sub.add_parser("light", help="light on/off (dp_id from capture)")
    p.add_argument("address")
    p.add_argument("action", choices=["on", "off"])
    _add_key_args(p)
    _add_gatt_args(p)
    p.set_defaults(func=cmd_light)

    p = sub.add_parser("cloud",
                       help="login to your own YouFs/Tuya cloud account, "
                            "read localKey + DP schema (verified path)")
    cloud_sub = p.add_subparsers(dest="action", required=True)
    cloud_sub.add_parser("login", help="reuse the saved session (or log in once)")
    cloud_sub.add_parser("homes", help="list homes and cache homeId")
    cloud_sub.add_parser("devices", help="list devices (devId/localKey/mac)")
    cloud_sub.add_parser("meshes", help="BLE mesh keys (networkKey/appKey/srand)")
    ps = cloud_sub.add_parser("schema", help="device detail + numeric DP map")
    ps.add_argument("dev_id", help="devId (or device name from `devices`)")
    pr = cloud_sub.add_parser("raw", help="ad-hoc signed API call (probing)")
    pr.add_argument("api")
    pr.add_argument("ver")
    pr.add_argument("post", nargs="?", default="{}", help="JSON postData")
    pr.add_argument("--form", help="JSON extra top-level form fields")
    pr.add_argument("--no-session", action="store_true")
    p.add_argument("--relogin", action="store_true",
                   help="force a fresh login (mints a NEW server session; "
                        "avoid unless the stored sid is dead)")
    p.set_defaults(func=cmd_cloud)

    args = parser.parse_args(argv)
    result = args.func(args)
    # cmd_cloud is synchronous; the BLE commands are coroutines.
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
