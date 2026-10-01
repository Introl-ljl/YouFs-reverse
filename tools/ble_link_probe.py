"""Windows BLE evidence probe. One attempt, no pairing or characteristic writes.

Run from the project root; --connect is an explicit opt-in. JSONL contains only
the selected peer's advertisements and OS events, not nearby device identities.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
import json
from pathlib import Path
import time


async def probe(args):
    from winrt.windows.devices.bluetooth import BluetoothLEDevice, BluetoothCacheMode
    from winrt.windows.devices.bluetooth.advertisement import (
        BluetoothLEAdvertisementWatcher, BluetoothLEScanningMode,
    )
    from winrt.windows.devices.bluetooth.genericattributeprofile import GattSession
    from bleak.backends.winrt.util import assert_mta

    await assert_mta()
    target = int(args.address.replace(":", ""), 16)
    started = time.monotonic()
    output = Path(args.output).resolve()
    workspace = Path(__file__).resolve().parents[1]
    if not output.is_relative_to(workspace):
        raise ValueError("output must stay inside this workspace")
    output.parent.mkdir(parents=True, exist_ok=True)
    stream = output.open("x", encoding="utf-8")

    def emit(event, **fields):
        row = dict(event=event, time=datetime.now().astimezone().isoformat(),
                   elapsed=round(time.monotonic() - started, 3), **fields)
        line = json.dumps(row, ensure_ascii=False)
        print(line, flush=True)
        stream.write(line + "\n")
        stream.flush()

    loop = asyncio.get_running_loop()
    hit = asyncio.Event()
    candidate = None
    total = 0
    seen = 0
    watcher = BluetoothLEAdvertisementWatcher()
    watcher.scanning_mode = (BluetoothLEScanningMode.ACTIVE if args.active
                             else BluetoothLEScanningMode.PASSIVE)

    def received(sender, event):
        # Extract on the WinRT callback thread, then mutate state on asyncio.
        is_target = event.bluetooth_address == target
        is_candidate = args.candidates and any(
            str(u).lower() == "0000fd50-0000-1000-8000-00805f9b34fb"
            for u in event.advertisement.service_uuids)
        if not is_target and not is_candidate:
            loop.call_soon_threadsafe(count_other)
            return
        address_hex = f"{event.bluetooth_address:012X}"
        row = dict(address=":".join(address_hex[i:i+2] for i in range(0, 12, 2)),
                   target=is_target,
                   address_type=event.bluetooth_address_type.name,
                   advertisement_type=event.advertisement_type.name,
                   connectable=event.is_connectable,
                   scannable=event.is_scannable,
                   scan_response=event.is_scan_response,
                   directed=event.is_directed,
                   rssi=event.raw_signal_strength_in_dbm,
                   name=event.advertisement.local_name,
                   service_uuids=[str(u) for u in event.advertisement.service_uuids],
                   sections=[dict(type=s.data_type, data=bytes(s.data).hex())
                             for s in event.advertisement.data_sections])
        loop.call_soon_threadsafe(on_target, row, event.bluetooth_address_type)

    def count_other():
        nonlocal total
        total += 1

    def on_target(row, address_type):
        nonlocal seen, total, candidate
        total += 1
        if row["target"]:
            seen += 1
        emit("advertisement", **row)
        # A scan response alone does not establish connectability.
        if row["target"] and row["connectable"] and not row["scan_response"]:
            candidate = address_type
            if args.connect:
                hit.set()

    def stopped(sender, event):
        loop.call_soon_threadsafe(emit_stopped, event.error.name)

    def emit_stopped(error):
        emit("watcher_stopped", error=error)

    token = watcher.add_received(received)
    stop_token = watcher.add_stopped(stopped)
    device = session = None
    device_token = session_token = None
    services = []
    result = "unavailable"
    stage = "scan"
    try:
        emit("scan_start", address=args.address, seconds=args.scan_seconds,
             mode="active" if args.active else "passive", connect=args.connect)
        watcher.start()
        try:
            await asyncio.wait_for(hit.wait(), args.scan_seconds)
        except asyncio.TimeoutError:
            pass
        finally:
            watcher.stop()
        emit("scan_end", advertisements=total, target_events=seen,
             connectable_seen=candidate is not None)
        if candidate is None or not args.connect:
            result = "target_not_seen" if not seen else (
                "connectable_observed" if candidate is not None else "no_connectable_observed")
            return result

        stage = "device_object"
        emit("connect_start", address_type=candidate.name,
             address_type_policy=args.address_type, seconds=args.connect_seconds)
        operation = (
            BluetoothLEDevice.from_bluetooth_address_async(target)
            if args.address_type == "auto" else
            BluetoothLEDevice.from_bluetooth_address_with_bluetooth_address_type_async(
                target, candidate))
        device = await asyncio.wait_for(
            operation, args.connect_seconds)
        if device is None:
            result = "device_object_unavailable"
            return result
        emit("device_object", address_type=device.bluetooth_address_type.name,
             connection_status=device.connection_status.name,
             paired=device.device_information.pairing.is_paired)

        def connection_changed(sender, event):
            status = sender.connection_status.name
            loop.call_soon_threadsafe(emit_connection, status)

        def emit_connection(status):
            emit("connection_status", status=status)

        def session_changed(sender, event):
            loop.call_soon_threadsafe(emit_session, event.status.name, event.error.name)

        def emit_session(status, error):
            emit("session_status", status=status, error=error)

        device_token = device.add_connection_status_changed(connection_changed)
        stage = "session_object"
        session = await asyncio.wait_for(
            GattSession.from_device_id_async(device.bluetooth_device_id), args.connect_seconds)
        session_token = session.add_session_status_changed(session_changed)
        emit("session_object", status=session.session_status.name,
             can_maintain=session.can_maintain_connection)
        session.maintain_connection = True
        stage = "service_discovery"
        emit("service_discovery_start", cache="uncached")
        response = await asyncio.wait_for(
            device.get_gatt_services_with_cache_mode_async(BluetoothCacheMode.UNCACHED),
            args.connect_seconds)
        services = list(response.services)
        emit("service_discovery_result", status=response.status.name,
             protocol_error=response.protocol_error, service_count=len(services),
             connection_status=device.connection_status.name,
             session_status=session.session_status.name, mtu=session.max_pdu_size)
        if response.status.name != "SUCCESS":
            result = "gatt_" + response.status.name.lower()
            return result
        for service in services:
            stage = "characteristic_discovery"
            chars = await asyncio.wait_for(service.get_characteristics_with_cache_mode_async(
                BluetoothCacheMode.UNCACHED), args.connect_seconds)
            emit("service", uuid=str(service.uuid), handle=service.attribute_handle,
                 status=chars.status.name, protocol_error=chars.protocol_error,
                 characteristics=[dict(uuid=str(c.uuid), handle=c.attribute_handle,
                                       properties=int(c.characteristic_properties))
                                  for c in chars.characteristics])
            if chars.status.name != "SUCCESS":
                result = "characteristics_" + chars.status.name.lower()
                return result
        result = "gatt_tree_observed"
        return result
    except Exception as exc:
        result = "timeout" if isinstance(exc, TimeoutError) else "error"
        emit("failure", stage=stage, exception=type(exc).__name__, message=str(exc),
             connection_status=device.connection_status.name if device else None,
             session_status=session.session_status.name if session else None)
        return result
    finally:
        watcher.stop()
        watcher.remove_received(token)
        watcher.remove_stopped(stop_token)
        for service in services:
            service.close()
        if session:
            session.maintain_connection = False
            if session_token is not None:
                session.remove_session_status_changed(session_token)
            session.close()
        if device:
            if device_token is not None:
                device.remove_connection_status_changed(device_token)
            device.close()
        # Drain previously queued callbacks before closing their output stream.
        await asyncio.sleep(0.1)
        emit("result", result=result, stage=stage)
        stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address")
    parser.add_argument("--scan-seconds", type=float, default=30)
    parser.add_argument("--connect-seconds", type=float, default=30)
    parser.add_argument("--connect", action="store_true")
    parser.add_argument("--address-type", choices=("observed", "auto"), default="observed",
                        help="observed uses the scan event type; auto reproduces Bleak's default")
    parser.add_argument("--active", action="store_true")
    parser.add_argument("--candidates", action="store_true",
                        help="also record FD50 advertisers; never connect to those peers")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = asyncio.run(probe(args))
    print("RESULT=" + result, flush=True)
    return 0 if result in ("gatt_tree_observed", "connectable_observed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
