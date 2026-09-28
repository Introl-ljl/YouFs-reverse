"""YouFSScooter — high-level async client facade.

Usage:
    async with YouFSScooter(address, ...) as scooter:
        info = await scooter.fetch_device_info()

Security scope:
  - implemented: BLE/GATT, P4 cmd0 diagnostics, explicit P4 cmd1 handshake
  - DP queries/writes, motor, OTA, and unbind remain disabled
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from . import commands as C
from .protocol import (DeviceInfo, Ret, build_app_frame, derive_key4,
                       derive_key5, parse_device_info, parse_ret)
from .telemetry import ScooterState, apply_dp_map, parse_report
from .transport import YouFsTransport

log = logging.getLogger("youfs.scooter")


@dataclass
class DpMap:
    """dp_id -> semantic field.  Fill ONLY from capture analysis results."""
    light: int = 0
    lock: int = 0
    gear: int = 0
    cruise: int = 0
    battery: int = 0
    speed: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, int]) -> "DpMap":
        return cls(**{k: v for k, v in data.items()
                      if k in cls.__dataclass_fields__})


class YouFSScooter:
    def __init__(self, address: str,
                 session_key: Optional[bytes] = None,
                 security_flag: Optional[int] = None,
                 use_legacy_uuids: bool = False,
                 dp_map: Optional[DpMap] = None,
                 request_timeout: float = 6.0,
                 service_uuid: Optional[str] = None,
                 write_uuid: Optional[str] = None,
                 notify_uuid: Optional[str] = None,
                 protocol_type: Optional[int] = None,
                 security_mode: Optional[str] = None,
                 login_key: Optional[bytes] = None,
                 ble_device: object = None) -> None:
        self.address = address
        self.session_key = session_key
        self.security_flag = security_flag
        self.protocol_type = protocol_type
        self.security_mode = security_mode
        self.login_key = login_key
        if ble_device is not None:
            device_address = getattr(ble_device, "address", None)
            if not device_address:
                raise ValueError("BLEDevice must expose its address before it can be connected")
            if _normalize_device_address(device_address) != _normalize_device_address(address):
                raise ValueError(
                    "BLEDevice address does not match the declared scooter address; refusing connection")
        self.ble_device = ble_device
        self.dp_map = dp_map or DpMap()
        self.request_timeout = request_timeout
        self.service_uuid = service_uuid
        self.write_uuid = write_uuid
        self.notify_uuid = notify_uuid
        self.transport = YouFsTransport(
            use_legacy_uuids=use_legacy_uuids,
            protocol_type=protocol_type,
            service_uuid=service_uuid,
            write_uuid=write_uuid,
            notify_uuid=notify_uuid)
        self.device_info: Optional[DeviceInfo] = None
        self.state = ScooterState()
        self._sn = 0                      # our 4B BE sequence (X2Request.sn=0 first)
        self._peer_sn = 0
        self._waiters: Dict[int, asyncio.Future] = {}
        self._exchange_keys: Dict[int, bytes] = {}
        self._exchange_lock = asyncio.Lock()
        self._subscribers: List[Callable[[ScooterState], None]] = []
        self.transport.on_frame = self._on_frame

    # -- lifecycle ----------------------------------------------------------- #

    async def __aenter__(self) -> "YouFSScooter":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.disconnect()

    async def connect(self) -> None:
        if self.ble_device is not None:
            device_address = getattr(self.ble_device, "address", None)
            if (not device_address or
                    _normalize_device_address(device_address) !=
                    _normalize_device_address(self.address)):
                raise RuntimeError(
                    "BLEDevice address no longer matches the declared scooter address")
        await self.transport.connect(
            self.ble_device or self.address,
            protocol_type=self.protocol_type,
            service_uuid=self.service_uuid,
            write_uuid=self.write_uuid, notify_uuid=self.notify_uuid)

    async def attach_connected_client(self, client) -> None:
        """Adopt an already connected BleakClient without reconnecting.

        Used by the GATT diagnostic path after it has enumerated the services
        on the live link. Transport validates the selected channel and starts
        notifications; disconnect ownership then transfers to this scooter.
        """
        if self.ble_device is not None:
            expected = getattr(self.ble_device, "address", None)
            actual = getattr(client, "address", expected)
            if expected and actual and (
                    _normalize_device_address(expected) !=
                    _normalize_device_address(actual)):
                raise ValueError("connected BLE client does not match the scan-time BLEDevice")
        await self.transport.attach_connected_client(
            client, service_uuid=self.service_uuid,
            write_uuid=self.write_uuid, notify_uuid=self.notify_uuid,
            protocol_type=self.protocol_type)

    async def disconnect(self) -> None:
        await self.transport.disconnect()

    def subscribe(self, callback: Callable[[ScooterState], None]) -> None:
        self._subscribers.append(callback)

    # -- protocol ------------------------------------------------------------ #

    def _on_frame(self, cmd: int, seq: int, payload: bytes) -> None:
        """trsmitr-complete application frame from the scooter."""
        if cmd != 2:
            log.warning("ignoring trsmitr command nibble %d (expected X2 type 2)", cmd)
            return
        try:
            keys = {}
            if self.login_key is not None:
                keys[4] = derive_key4(self.login_key)
            if self.session_key is not None and self.security_flag is not None:
                keys[self.security_flag] = self.session_key
            keys.update(self._exchange_keys)
            ret = parse_ret(payload, key=self.session_key,
                            flags_to_key=keys)
        except ValueError as exc:
            log.debug("unparseable frame (%s): %s", exc, payload.hex())
            return
        if not ret.crc_ok:
            log.warning("frame CRC mismatch (code=0x%04X)", ret.code)
        self._peer_sn = ret.sn
        fut = self._waiters.pop(ret.sn_ack, None)
        if fut and not fut.done():
            fut.set_result(ret)
        if ret.code in (C.REPORT_DP, C.REPORT_DP_TIME, C.REPORT_STATUS_DP):
            report = parse_report(ret.code, ret.data, sn=ret.sn)
            apply_dp_map(self.state, report.dps, _dp_map_spec(self.dp_map))
            log.info("DP report code=0x%04X: %s", ret.code,
                     [(d.dp_id, d.dp_type, d.value) for d in report.dps])
            for cb in self._subscribers:
                try:
                    cb(self.state)
                except Exception:  # noqa: BLE001
                    log.exception("subscriber callback failed")

    async def _request(self, code: int, data: bytes = b"",
                       wait_sn: Optional[int] = None) -> Optional[Ret]:
        if code in (C.CMD_DP_QUERY, C.CMD_DP_SEND):
            raise RuntimeError(
                "DP request refused: cmd 0x0001 pairing is not implemented "
                "or verified, so protocol readiness is not established")
        self._sn += 1
        frame = build_app_frame(sn=self._sn, sn_ack=self._peer_sn, code=code,
                                data=data, key=self.session_key,
                                flag=self.security_flag)
        fut: Optional[asyncio.Future] = None
        if wait_sn is not None:
            fut = asyncio.get_running_loop().create_future()
            self._waiters[wait_sn] = fut
        await self.transport.send_frame(frame)
        if fut is None:
            return None
        try:
            return await asyncio.wait_for(fut, self.request_timeout)
        except asyncio.TimeoutError:
            self._waiters.pop(wait_sn, None)
            log.warning("timeout waiting for response to sn=%s", wait_sn)
            return None

    async def exchange(self, frame: bytes, *, expected_sn: int,
                       response_key: bytes, response_flag: int,
                       timeout: float) -> Ret:
        """Adapter for :class:`YouFsConnection`'s validated request exchange.

        Serializes transactions, decrypts notify frames with the explicitly
        supplied expected key/flag, and correlates by ``sn_ack``. The caller
        remains responsible for validating response code, CRC and state.
        """
        if not getattr(self.transport, "is_connected", False):
            raise RuntimeError("BLE link is not connected")
        if not getattr(self.transport, "notify_ready", False):
            raise RuntimeError("GATT notifications are not ready")
        if not 0 <= response_flag <= 0xFF or len(response_key) != 16:
            raise ValueError("response key/flag is invalid")
        async with self._exchange_lock:
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            if expected_sn in self._waiters:
                raise RuntimeError(f"sequence {expected_sn} already has a waiter")
            self._waiters[expected_sn] = future
            self._exchange_keys[response_flag] = response_key
            try:
                await self.transport.send_frame(frame)
                ret = await asyncio.wait_for(future, timeout)
                if not isinstance(ret, Ret):
                    raise RuntimeError("notify callback returned an invalid frame")
                return ret
            finally:
                self._waiters.pop(expected_sn, None)
                self._exchange_keys.pop(response_flag, None)

    async def establish_protocol(self, config, *, timeout: Optional[float] = None):
        """Run the explicit P4 legacy cmd0/cmd1 handshake.

        This method is intentionally separate from ``connect()``. Calling it
        sends pairing cmd1, so diagnostics that only need BLE/GATT or cmd0
        must not invoke it implicitly.
        """
        from .connection import YouFsConnection

        effective_timeout = self.request_timeout if timeout is None else timeout
        mtu_payload = getattr(self.transport, "payload_mtu", None)
        if mtu_payload is None:
            att_mtu = getattr(self.transport, "mtu", None)
            if att_mtu is None:
                raise RuntimeError("P4 connection refused: effective MTU is unavailable")
            mtu_payload = max(0, int(att_mtu) - 3)
        self.connection = YouFsConnection(
            config, self.exchange, mtu_payload=int(mtu_payload),
            timeout=effective_timeout,
            transport_ready=(bool(getattr(self.transport, "is_connected", False))
                             and bool(getattr(self.transport, "notify_ready", False))))
        info = await self.connection.establish()
        self.device_info = info
        self.session_key = self.connection.session_key
        self.security_flag = C.FLAG_LEGACY_5
        return info

    # -- public API ----------------------------------------------------------- #

    async def fetch_device_info(self) -> Optional[DeviceInfo]:
        """Perform only the verified P4 legacy cmd0 exchange.

        Requires an explicit P4 protocol type, explicit legacy security mode,
        and the device loginKey. GATT success alone does not establish this.
        """
        if self.protocol_type not in (413, 400, 401, 402, 403, 404, 405):
            raise RuntimeError("cmd 0 refused: explicitly select a supported P4 protocolType")
        if self.security_mode != "legacy":
            raise RuntimeError("cmd 0 refused: explicitly select verified legacy security mode")
        if not self.login_key:
            raise RuntimeError("P4 cmd 0 requires --local-key/--cloud-device (loginKey)")
        payload_mtu = getattr(self.transport, "payload_mtu", None)
        if payload_mtu is None:
            att_mtu = getattr(self.transport, "mtu", None)
            if att_mtu is None:
                raise RuntimeError("cmd 0 refused: negotiated ATT MTU is unavailable")
            payload_mtu = max(0, int(att_mtu) - 3)
        self._sn = 0
        frame = C.device_info_request(
            self.login_key, int(payload_mtu), sn=0, sn_ack=self._peer_sn)
        fut = asyncio.get_running_loop().create_future()
        self._waiters[0] = fut
        await self.transport.send_frame(frame)
        try:
            ret = await asyncio.wait_for(fut, self.request_timeout)
        except asyncio.TimeoutError:
            self._waiters.pop(0, None)
            log.warning("no device-info response (device may require an "
                        "different protocol/security mode)")
            return None
        if not ret.crc_ok:
            raise RuntimeError("cmd 0x0000 response CRC mismatch")
        if ret.code != C.CMD_DEVICE_INFO:
            raise RuntimeError(f"cmd 0x0000 got unexpected response code 0x{ret.code:04X}")
        if ret.sn_ack != 0:
            raise RuntimeError(f"cmd 0x0000 response acknowledged unexpected sequence {ret.sn_ack}")
        if ret.flag != 4:
            raise RuntimeError(f"cmd 0x0000 expected security flag 4, got {ret.flag}")
        self.device_info = parse_device_info(ret.data)
        self.session_key = derive_key5(self.login_key, self.device_info.srand)
        self.security_flag = C.FLAG_LEGACY_5
        return self.device_info

    async def get_state(self) -> ScooterState:
        """DP query (cmd 0x0003, empty payload = all DPs)."""
        raise RuntimeError(
            "DP query refused: cmd 0x0001 pairing is not implemented or "
            "verified, so protocol readiness is not established")

    async def wait_for_report(self, timeout: float = 8.0) -> ScooterState:
        """Passively wait for the next DP report (e.g. after connect)."""
        before = len(self.state.raw_dps)
        deadline = asyncio.get_running_loop().time() + timeout
        while len(self.state.raw_dps) == before:
            if asyncio.get_running_loop().time() > deadline:
                break
            await asyncio.sleep(0.2)
        return self.state

    # -- actuation (low-risk only) -------------------------------------------- #

    async def set_light(self, on: bool, dp_id: Optional[int] = None) -> None:
        """Light on/off — the ONLY actuator this client exposes.

        The dp_id MUST come from capture analysis (docs/capture_analysis.md);
        we deliberately refuse to guess."""
        raise RuntimeError(
            "light DP write refused: cmd 0x0001 pairing is not implemented "
            "or verified, so protocol readiness is not established")


def _dp_map_spec(dp_map: DpMap) -> Dict[str, Dict[str, int]]:
    spec: Dict[str, Dict[str, int]] = {}
    for name in ("light", "lock", "gear", "cruise", "battery", "speed"):
        dp_id = getattr(dp_map, name)
        if dp_id:
            spec[name] = {"dp_id": dp_id}
    return spec


def _normalize_device_address(value: object) -> str:
    return str(value).replace("-", ":").upper()
