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
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from . import commands as C
from .protocol import (DeviceInfo, Ret, build_app_frame, derive_key14,
                       derive_key4, derive_key5, dp_encode, parse_device_info,
                       parse_ret)
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
                 login_key_complete: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 ble_device: object = None) -> None:
        self.address = address
        self.session_key = session_key
        self.security_flag = security_flag
        self.protocol_type = protocol_type
        self.security_mode = security_mode
        self.login_key = login_key
        self.login_key_complete = login_key_complete
        self.secret_key = secret_key
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
        self._dps_sn = 0                   # pv4 DPS control counter (PairRep resets)
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
    async def connect_retry(self, attempts: int = 3, backoff_s: float = 20.0) -> None:
        """connect() with bounded retries across the module's adv pause window.

        Observed on the vehicle: after a disconnect the module pauses
        advertising for roughly 30-90 s, so one retry after a backoff is
        often needed. Every attempt uses the same scan-time BLEDevice
        identity checks as connect().
        """
        last_exc: Exception = RuntimeError("unreachable")
        for i in range(attempts):
            try:
                await self.connect()
                return
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                log.warning("connect attempt %d/%d failed: %s", i + 1, attempts, exc)
                if i + 1 < attempts:
                    await asyncio.sleep(backoff_s)
        raise last_exc

    def subscribe(self, callback: Callable[[ScooterState], None]) -> None:
        self._subscribers.append(callback)

    # -- protocol ------------------------------------------------------------ #

    def _on_frame(self, cmd: int, seq: int, payload: bytes) -> None:
        """trsmitr-complete application frame from the scooter.

        The APK BaseReceiver never filters by the header's type nibble on
        receive, so neither do we; the value is logged for evidence only.
        """
        if cmd != 2:
            log.info("trsmitr header type nibble %d (app requests use 2)", cmd)
        try:
            keys = {}
            if self.login_key is not None:
                keys[4] = derive_key4(self.login_key)
            if self.login_key_complete and self.secret_key:
                keys[14] = derive_key14(self.login_key_complete, self.secret_key)
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
        if self.state_machine_ready:
            self._service_device_requests(ret)
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
        if code == C.CMD_DP_SEND:
            raise RuntimeError(
                "generic DP control refused: use the explicitly gated "
                "send_dp() with an authorized dpId")
        if code == C.CMD_DP_QUERY and not self.state_machine_ready:
            raise RuntimeError(
                "DP query refused: run the verified pairing handshake "
                "(cmd0/cmd1) first; readiness is not established")
        self._sn += 1
        # The APK sets ack_sn=0 on app-initiated requests (X2Request builder
        # bdpdqbp(0)); only replies to device-initiated frames echo the
        # device's sn (time-sync replies, report ACKs).
        frame = build_app_frame(sn=self._sn, sn_ack=0, code=code,
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
        self.security_flag = self.connection.session_flag
        # Continue the APK's single sn sequence (cmd0=1, cmd1=2, replies 3+)
        # so no session frame ever reuses a previously sent sn.
        self._sn = max(self._sn, self.connection._next_sn)
        # dealWithResponse resets dpsSn to 0 when PairRep confirms binding.
        self._dps_sn = 0
        return info

    # -- device-initiated session servicing ---------------------------------- #

    @property
    def state_machine_ready(self) -> bool:
        """True once a validated PairRep established the session keys."""
        return (self.security_flag is not None and self.session_key is not None)

    def _tz_units(self) -> int:
        """Local UTC offset in 0.01-hour units (TimeZoneUtils.bdpdqbp)."""
        import calendar
        is_dst = time.daylight and time.localtime().tm_isdst > 0
        offset_seconds = -time.altzone if is_dst else -time.timezone
        return int(round(offset_seconds / 3600.0 * 100.0))

    def _send_no_callback(self, code: int, data: bytes, *, sn_ack: int = 0) -> None:
        """Fire-and-forget reply, encrypted with the session key/flag.

        Commits the shared sn counter so no session frame ever reuses a
        sequence number (the device drops duplicates as replays).
        """
        self._sn += 1
        frame = build_app_frame(sn=self._sn, sn_ack=sn_ack, code=code,
                                data=data, key=self.session_key,
                                flag=self.security_flag)
        asyncio.get_running_loop().create_task(self._send_frame_task(frame))

    async def _send_frame_task(self, frame: bytes) -> None:
        try:
            await self.transport.send_frame(frame)
        except Exception:  # noqa: BLE001
            log.exception("failed to send reply frame (code in frame)")

    def _service_device_requests(self, ret: Ret) -> None:
        """Answer the session's mandatory device-initiated exchanges.

        Evidence (dpqbbpd): time requests 32785/32786/32787 must be answered
        unconditionally (the APK checks only the rep class — the observed
        vehicle sends 32785 with an EMPTY payload ~16 ms after PairRep and
        drops the session if the answer does not come); pv4 DP reports
        32774/32775 with needAck (b_type bit7 clear) require
        replayDpsReportAck with the same code and ack_sn = report sn.
        """
        try:
            if ret.code == 32785:
                ms = int(time.time() * 1000)
                data = f"{ms:013d}".encode("ascii") + self._tz_units().to_bytes(2, "big")
                self._send_no_callback(32785, data, sn_ack=ret.sn)
            elif ret.code == 32786:
                t = time.localtime()
                data = bytes([t.tm_year - 2000, t.tm_mon, t.tm_mday,
                              t.tm_hour, t.tm_min, t.tm_sec,
                              (t.tm_wday + 1) % 7]) + self._tz_units().to_bytes(2, "big")
                self._send_no_callback(32786, data, sn_ack=ret.sn)
            elif ret.code == 32787:
                t = time.localtime()
                data = bytes([t.tm_year - 2000, t.tm_mon, t.tm_mday,
                              t.tm_hour, t.tm_min, t.tm_sec,
                              (t.tm_wday + 1) % 7]) + self._tz_units().to_bytes(2, "big")
                self._send_no_callback(32787, data)
            elif ret.code in (32774, 32775) and len(ret.data) >= 11:
                version = ret.data[0]
                rep_sn = int.from_bytes(ret.data[1:5], "big")
                b_type = ret.data[5]
                need_ack = (b_type >> 7) == 0
                if need_ack:
                    data = bytes([version]) + rep_sn.to_bytes(4, "big") + \
                        bytes([b_type, ret.data[6] if len(ret.data) > 6 else 0, 0])
                    self._send_no_callback(ret.code, data, sn_ack=ret.sn)
        except Exception:  # noqa: BLE001
            log.exception("failed to service device-initiated request")

    # -- public API ----------------------------------------------------------- #

    async def fetch_device_info(self) -> Optional[DeviceInfo]:
        """Perform only the verified P4 cmd0 exchange (no pairing).

        security_mode selects the APK branch for connectType=0:
          legacy — flag4/key4 = MD5(loginKey=localKey[:6])
          new    — flag14/key14 = MD5(UTF-8(localKey + secKey))
        Requires the explicit protocol type, mode, and key material. GATT
        success alone does not establish any of this.
        """
        if self.protocol_type not in (413, 400, 401, 402, 403, 404, 405):
            raise RuntimeError("cmd 0 refused: explicitly select a supported P4 protocolType")
        if self.security_mode not in ("legacy", "new"):
            raise RuntimeError("cmd 0 refused: explicitly select 'legacy' or 'new' security mode")
        payload_mtu = getattr(self.transport, "payload_mtu", None)
        if payload_mtu is None:
            att_mtu = getattr(self.transport, "mtu", None)
            if att_mtu is None:
                raise RuntimeError("cmd 0 refused: negotiated ATT MTU is unavailable")
            payload_mtu = max(0, int(att_mtu) - 3)
        # The APK's SnAckHolder resets on connect and pre-increments: the
        # first application request carries sn=1, never 0.
        sn = 1
        if self.security_mode == "new":
            if not self.login_key_complete or not self.secret_key:
                raise RuntimeError(
                    "new-security cmd 0 requires the cloud localKey (full) and secKey")
            frame = C.device_info_request_new(
                self.login_key_complete, self.secret_key,
                int(payload_mtu), sn=sn, sn_ack=self._peer_sn)
            expected_flag = C.FLAG_NEW_SECURITY_14
        else:
            if not self.login_key:
                raise RuntimeError("P4 cmd 0 requires --local-key/--cloud-device (loginKey)")
            frame = C.device_info_request(
                self.login_key, int(payload_mtu), sn=sn, sn_ack=self._peer_sn)
            expected_flag = C.FLAG_LEGACY_4
        fut = asyncio.get_running_loop().create_future()
        self._waiters[sn] = fut
        await self.transport.send_frame(frame)
        try:
            ret = await asyncio.wait_for(fut, self.request_timeout)
        except asyncio.TimeoutError:
            self._waiters.pop(sn, None)
            log.warning("no device-info response (device may require an "
                        "different protocol/security mode)")
            return None
        if not ret.crc_ok:
            raise RuntimeError("cmd 0x0000 response CRC mismatch")
        if ret.code != C.CMD_DEVICE_INFO:
            raise RuntimeError(f"cmd 0x0000 got unexpected response code 0x{ret.code:04X}")
        if ret.sn_ack != sn:
            raise RuntimeError(f"cmd 0x0000 response acknowledged unexpected sequence {ret.sn_ack}")
        if ret.flag != expected_flag:
            raise RuntimeError(f"cmd 0x0000 expected security flag {expected_flag}, got {ret.flag}")
        self.device_info = parse_device_info(ret.data)
        if self.security_mode == "new":
            if not self.login_key_complete or not self.secret_key:
                raise RuntimeError("new-security key15 requires localKey+secKey")
            from .protocol import derive_key15
            self.session_key = derive_key15(self.login_key_complete,
                                            self.secret_key,
                                            self.device_info.srand)
            self.security_flag = C.FLAG_NEW_SECURITY_15
        else:
            self.session_key = derive_key5(self.login_key, self.device_info.srand)
            self.security_flag = C.FLAG_LEGACY_5
        return self.device_info

    async def get_state(self) -> ScooterState:
        """Read-only DP query (cmd 0x0003, empty payload = all DPs).

        Only allowed after a verified READY (pairing handshake completed);
        vehicle DP control (cmd 0x0002) remains refused regardless.
        """
        ret = await self._request(C.CMD_DP_QUERY, b"", wait_sn=self._sn + 1)
        if ret is not None and ret.crc_ok:
            report = parse_report(ret.code, ret.data, sn=ret.sn)
            apply_dp_map(self.state, report.dps, _dp_map_spec(self.dp_map))
        return self.state

    async def send_dp(self, dp_id: int, dp_type: int, value) -> Optional[Ret]:
        """Send one data point via the P4 pv4 control command (code 0x0027).

        Evidence (dpqbbpd.publishDps, protocol >= 4): payload =
        [0x00][dpsSn 4B BE] + per DP [dpId 1B][type 1B][len 2B BE][value],
        with dpsSn a separate counter reset on PairRep and ack_sn=0.
        Gated on READY and intended only for dpIds explicitly authorized by
        the vehicle owner and confirmed rw in the cloud schema (dp8
        headlight_switch, dp15 mode). The DpsSendRep(4) status byte is
        returned for verification; None means no response before timeout.
        """
        if not self.state_machine_ready:
            raise RuntimeError(
                "DP send refused: run the verified pairing handshake "
                "(cmd0/cmd1) first; readiness is not established")
        value_bytes = dp_encode(dp_id, dp_type, value)[3:]
        self._dps_sn += 1
        payload = (b"\x00" + self._dps_sn.to_bytes(4, "big") +
                   bytes([dp_id & 0xFF, dp_type & 0xFF]) +
                   len(value_bytes).to_bytes(2, "big") + value_bytes)
        self._sn += 1
        frame = build_app_frame(sn=self._sn, sn_ack=0, code=C.CMD_DP_SEND_PV4,
                                data=payload, key=self.session_key,
                                flag=self.security_flag)
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._waiters[self._sn] = fut
        await self.transport.send_frame(frame)
        try:
            ret = await asyncio.wait_for(fut, self.request_timeout)
            if not ret.crc_ok:
                log.warning("DP send response CRC mismatch (dp %s)", dp_id)
            return ret
        except asyncio.TimeoutError:
            self._waiters.pop(self._sn, None)
            log.warning("no DP send response for sn=%s", self._sn)
            return None

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
