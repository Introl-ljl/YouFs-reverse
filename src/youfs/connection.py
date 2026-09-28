"""Fail-closed app-layer connection state machine.

Only the P4 legacy path is implemented here.  Its cmd0/cmd1 sequence and
payload fields follow the analyzed YouFs APK; this module does not guess a
protocol family or treat a cmd0 response as a completed connection.

APK evidence: ``ThingProtocolFlowFactory`` (bqdbbqq.java:49-85),
``dpqbbpd.fetchDeviceInfoRet`` (dpqbbpd.java:6100-6131),
``dpqbbpd.pairDevice`` (dpqbbpd.java:6742-6850),
``PairRep.parseRep`` (PairRep.java), and the ``deviceConnectSuccess`` gate
(pbpdbqp.java:2645-2746). The implementation deliberately requires a caller
to provide a confirmed legacy security profile because the local YouFs 2
DeviceBean cache does not establish that fact.

The BLE/GATT transport is injected via ``exchange`` so this state machine can
be tested offline and does not own scanning, notifications, or MTU negotiation.
The adapter must return an already decrypted :class:`protocol.Ret` matching
the requested sequence number and response flag.
"""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Mapping, Optional

from . import commands as C
from .protocol import (DeviceInfo, Ret, build_app_frame, derive_key4, derive_key5,
                       parse_device_info)

P4_PROTOCOL_TYPES = frozenset({413, 400, 401, 402, 403, 404, 405})
P4_CMD0_FLAG = 4
P4_PAIR_FLAG = 5


class ConnectionError(RuntimeError):
    """A connection stage failed or the supplied protocol evidence is unsafe."""


class ConnectionState(str, Enum):
    NEW = "new"
    CMD0_SENT = "cmd0_sent"
    DEVICE_INFO_VALIDATED = "device_info_validated"
    CMD1_SENT = "cmd1_sent"
    READY = "ready"
    FAILED = "failed"


class ProtocolFamily(str, Enum):
    P1_NORMAL = "p1_normal"
    P1_WIFI = "p1_wifi"
    P1_SECURITY = "p1_security"
    P2 = "p2"
    P4 = "p4"


def protocol_family_for_type(protocol_type: int) -> ProtocolFamily:
    """Mirror the APK factory's explicit protocolType delegate selection."""
    value = int(protocol_type)
    if value in P4_PROTOCOL_TYPES:
        return ProtocolFamily.P4
    if value == 100:
        return ProtocolFamily.P1_NORMAL
    if value == 101:
        return ProtocolFamily.P1_WIFI
    if value == 102:
        return ProtocolFamily.P1_SECURITY
    # APK factory bqd... routes all remaining values to P2. We preserve the
    # mapping for diagnostics, but this module does not send a P2 frame.
    return ProtocolFamily.P2


@dataclass(frozen=True)
class PairRep:
    """P4 cmd1 response and the stricter client acceptance decision.

    The APK marks any non-empty parseRep buffer as ``success=true`` but sets
    ``bindStatus`` only for status bytes 0 or 2. This client requires that
    explicit accepted/bound status before exposing READY.
    """

    status: int
    apk_success: bool
    bind_status: bool
    accepted: bool

    @classmethod
    def parse(cls, data: bytes) -> "PairRep":
        if not data:
            raise ConnectionError("cmd1 PairRep has no status byte")
        # Decompiled APK: success=true for any nonempty response; bindStatus
        # is true only when the first unsigned byte equals 0 or 2. Our stricter
        # acceptance gate follows bindStatus instead of the broad parser flag.
        status = data[0]
        bind_status = status in (0, 2)
        return cls(status=status, apk_success=True,
                   bind_status=bind_status, accepted=bind_status)


@dataclass(frozen=True)
class DeviceConnectionConfig:
    """Non-secret profile fields plus the account local key.

    ``security_mode`` must be explicitly set to ``"legacy"`` from an
    authoritative profile/capture. The cached YouFs 2 metadata does not carry
    this field, so callers must not infer it from a successful BLE link.
    """

    protocol_type: int
    connect_type: int
    security_mode: str
    uuid: str
    dev_id: str
    local_key: str = field(repr=False)
    beacon_key: Optional[str] = field(default=None, repr=False)

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "DeviceConnectionConfig":
        """Read supported DeviceBean fields without retaining unrelated data."""
        aliases = {
            "protocol_type": ("protocolType", "protocol_type"),
            "connect_type": ("connectType", "connect_type"),
            "security_mode": ("securityMode", "security_mode"),
            "uuid": ("uuid",),
            "dev_id": ("devId", "dev_id"),
            "local_key": ("localKey", "local_key"),
            "beacon_key": ("beaconKey", "beacon_key"),
        }
        selected = {}
        for field, names in aliases.items():
            for name in names:
                if name in values:
                    selected[field] = values[name]
                    break
        missing = [name for name in aliases if name != "beacon_key" and
                   name not in selected]
        if missing:
            raise ConnectionError(
                "device connection profile is incomplete; missing: " +
                ", ".join(missing))
        for field in ("protocol_type", "connect_type"):
            # JSON booleans are Python ints and int(3.5) silently truncates;
            # neither is a valid explicit protocol selector.
            if type(selected[field]) is not int:
                raise ConnectionError(f"{field} must be an integer")
        try:
            selected["protocol_type"] = int(selected["protocol_type"])
            selected["connect_type"] = int(selected["connect_type"])
        except (TypeError, ValueError) as exc:
            raise ConnectionError("protocolType/connectType must be integers") from exc
        for field in ("security_mode", "uuid", "dev_id", "local_key"):
            if not isinstance(selected[field], str) or not selected[field]:
                raise ConnectionError(f"{field} must be a non-empty string")
        if "beacon_key" in selected and (
                not isinstance(selected["beacon_key"], str) or
                not selected["beacon_key"]):
            raise ConnectionError("beacon_key must be a non-empty hex string")
        return cls(**selected)


Exchange = Callable[..., Awaitable[Ret]]


class YouFsConnection:
    """Authenticate a supported device and gate later DP operations on READY.

    Args:
        config: Explicit cloud/profile connection fields.
        exchange: ``async exchange(frame, *, expected_sn, response_key,
            response_flag, timeout) -> Ret``. The BLE adapter is responsible
            for frame reassembly and Ret decryption, but the state machine also
            verifies ack, code, CRC, and security flag.
        mtu_payload: Effective GATT write payload size (Android SDK's
            ``mGattMTU`` = negotiated ATT MTU minus 3), not raw ATT MTU.
    """

    def __init__(self, config: DeviceConnectionConfig | Mapping[str, Any],
                 exchange: Exchange, *, mtu_payload: int,
                 timeout: float = 6.0,
                 transport_ready: bool = False) -> None:
        self.config = (config if isinstance(config, DeviceConnectionConfig)
                       else DeviceConnectionConfig.from_mapping(config))
        self.exchange = exchange
        self.mtu_payload = mtu_payload
        self.timeout = timeout
        self.transport_ready = transport_ready
        self.state = ConnectionState.NEW
        self.device_info: Optional[DeviceInfo] = None
        self.session_key: Optional[bytes] = None
        self.bind_status: Optional[bool] = None
        self._peer_sn = 0

    def _validate_profile(self) -> bytes:
        cfg = self.config
        family = protocol_family_for_type(cfg.protocol_type)
        if family is not ProtocolFamily.P4:
            raise ConnectionError(
                f"protocolType {cfg.protocol_type} selects {family.value}; "
                "only P4 connection auth is implemented")
        if cfg.connect_type != 0:
            raise ConnectionError(
                "only the APK's normal connectType=0 path is implemented")
        if cfg.security_mode.lower() != "legacy":
            raise ConnectionError(
                "P4 pairing requires an explicitly confirmed legacy security profile")
        if self.mtu_payload < 20 or self.mtu_payload > 0xFFFF:
            raise ConnectionError("effective GATT MTU payload is out of range")
        if not self.transport_ready:
            raise ConnectionError(
                "BLE/GATT notify and service readiness are required before cmd0")
        if not cfg.uuid or not cfg.dev_id or not cfg.local_key:
            raise ConnectionError("uuid, devId, and localKey are required for P4 legacy")
        if len(cfg.local_key) < 6:
            raise ConnectionError("localKey must contain at least six characters")
        if len(cfg.dev_id.encode("utf-8")) > 22:
            raise ConnectionError("devId exceeds the APK's 22-byte P4 field")
        return cfg.local_key[:6].encode("utf-8")

    async def _exchange(self, frame: bytes, *, sn: int, key: bytes,
                        flag: int, code: int) -> Ret:
        try:
            result = self.exchange(
                frame, expected_sn=sn, response_key=key,
                response_flag=flag, timeout=self.timeout)
            if inspect.isawaitable(result):
                ret = await result
            else:  # convenient adapter support for deterministic local tests
                ret = result
        except Exception as exc:  # noqa: BLE001
            raise ConnectionError(f"cmd 0x{code:04X} exchange failed") from exc
        if not isinstance(ret, Ret):
            raise ConnectionError("exchange adapter must return a protocol.Ret")
        if ret.sn_ack != sn:
            raise ConnectionError(
                f"cmd 0x{code:04X} response ack mismatch (expected {sn})")
        if ret.code != code:
            raise ConnectionError(
                f"unexpected response code 0x{ret.code:04X} for cmd 0x{code:04X}")
        if not ret.crc_ok:
            raise ConnectionError(f"cmd 0x{code:04X} response CRC is invalid")
        if ret.flag != flag:
            raise ConnectionError(
                f"cmd 0x{code:04X} response security flag mismatch")
        self._peer_sn = ret.sn
        return ret

    async def establish(self) -> DeviceInfo:
        """Run P4 legacy cmd0/key4 then cmd1/key5; become READY only on PairRep."""
        try:
            login_key = self._validate_profile()
            # The commands builder captures the APK cmd0 body (effective MTU,
            # big-endian) and key4/flag4 selection.
            from .commands import device_info_request
            cmd0 = device_info_request(login_key=login_key,
                                      mtu_payload=self.mtu_payload,
                                      sn=0, sn_ack=self._peer_sn)
            key4 = derive_key4(login_key)
            self.state = ConnectionState.CMD0_SENT
            ret0 = await self._exchange(cmd0, sn=0, key=key4,
                                        flag=P4_CMD0_FLAG,
                                        code=C.CMD_DEVICE_INFO)
            try:
                info = parse_device_info(ret0.data)
            except ValueError as exc:
                raise ConnectionError("invalid P4 DeviceInfoRep") from exc
            if len(info.srand) != 6:
                raise ConnectionError("DeviceInfoRep srand must be exactly 6 bytes")
            _validate_legacy_device_info(info)
            self.device_info = info
            self.state = ConnectionState.DEVICE_INFO_VALIDATED

            # APK dpqbbpd.pairDevice() legacy/connectType=0 fields:
            # uuid bytes (20-char Tuya compression, otherwise UTF-8 padded FF
            # to 16); UTF-8 loginKey; devId padded with NUL to 22; either the
            # APK fallback marker 0 or marker 16 + ActivatorResultParam hex
            # beaconKey (zero-padded to at least 16 bytes); pair marker 1.
            # New-security fields are deliberately absent because the profile
            # is restricted to legacy.
            pair_data = build_p4_legacy_pair_payload(
                uuid=self.config.uuid, login_key=login_key,
                dev_id=self.config.dev_id,
                need_beacon_key=info.need_beacon_key,
                beacon_key=self.config.beacon_key)
            self.session_key = derive_key5(login_key, info.srand)
            cmd1_sn = 1
            cmd1 = build_app_frame(
                # APK's P4 pairDevice builder sets ack_sn=0 explicitly.
                sn=cmd1_sn, sn_ack=0, code=C.CMD_PAIR,
                data=pair_data, key=self.session_key, flag=P4_PAIR_FLAG)
            self.state = ConnectionState.CMD1_SENT
            ret1 = await self._exchange(cmd1, sn=cmd1_sn,
                                        key=self.session_key,
                                        flag=P4_PAIR_FLAG,
                                        code=C.CMD_PAIR)
            pair_rep = PairRep.parse(ret1.data)
            if not pair_rep.accepted:
                raise ConnectionError(
                    "cmd1 PairRep status was not accepted (expected 0 or 2)")
            # Preserve binding state separately from protocol readiness, as
            # the APK passes both values in ConnectRsp.
            self.bind_status = pair_rep.bind_status
            self.state = ConnectionState.READY
            return info
        except Exception:
            self.state = ConnectionState.FAILED
            self.session_key = None
            raise

    def require_ready(self, operation: str = "DP/control") -> bytes:
        """Return the session key only after PairRep confirmed READY."""
        if self.state is not ConnectionState.READY or self.session_key is None:
            raise ConnectionError(
                f"{operation} refused until a valid cmd1 PairRep reaches READY")
        return self.session_key


def build_p4_legacy_pair_payload(*, uuid: str, login_key: bytes,
                                 dev_id: str,
                                 need_beacon_key: bool = False,
                                 beacon_key: Optional[str] = None) -> bytes:
    """Build the only confirmed cmd1 payload variant (P4, connectType 0)."""
    if not uuid or not login_key or not dev_id:
        raise ConnectionError("P4 pairing payload requires uuid/loginKey/devId")
    uuid_bytes = _uuid_wire_bytes(uuid)
    dev_bytes = dev_id.encode("utf-8")
    if len(dev_bytes) > 22:
        raise ConnectionError("devId exceeds the APK's 22-byte P4 field")
    beacon_field = b"\x00"
    # APK dpqbbpd.java:6812-6817 falls back to marker 0 whenever the flag is
    # false OR decoded securityRaw beaconKey is null. Preserve that normal-path
    # behavior when the profile has no beaconKey; cmd1 remains encrypted with
    # key5/flag5, so this is not a security-mode downgrade.
    if need_beacon_key and beacon_key:
        if len(beacon_key) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", beacon_key):
            raise ConnectionError("beaconKey must be an even-length hex string")
        try:
            beacon_bytes = bytes.fromhex(beacon_key)
        except ValueError as exc:
            raise ConnectionError("beaconKey must be an even-length hex string") from exc
        if not beacon_bytes:
            raise ConnectionError("beaconKey must decode to a non-empty value")
        beacon_field = b"\x10" + beacon_bytes.ljust(16, b"\x00")
    return (uuid_bytes + login_key + dev_bytes.ljust(22, b"\x00") +
            beacon_field + b"\x01")


def _validate_legacy_device_info(info: DeviceInfo) -> None:
    """Fail closed for P4 authentication/security-update paths not implemented.

    APK DeviceInfoRep.parseRep reads base flag bits 1/3 as v4/server-auth
    requirements and bit 4 as needBeaconKey. For protocol 3.x security-update
    support/enable are flag bits 6/7; protocol >=4 moves those bits to flag2
    at raw offset 54. The beaconKey itself comes from ActivatorResultParam,
    not DeviceInfoRep.authKey (pbpdbqp.java:790-796 vs. :7474-7479).
    """
    raw = info.raw
    if len(raw) < 12:
        raise ConnectionError("DeviceInfoRep is too short to inspect security flags")
    protocol_number = raw[2] * 10 + raw[3]
    if protocol_number < 30:
        raise ConnectionError("P4 protocol version below 3.0 is unsupported")
    if len(raw) < 77:
        raise ConnectionError(
            "P4 DeviceInfoRep is missing the security/profile extension")

    flags = raw[4]
    if flags & (0x02 | 0x08):
        raise ConnectionError(
            "DeviceInfoRep requests v4/server authentication; refusing legacy cmd1")
    if 30 <= protocol_number < 40:
        support_update = bool(flags & 0x40)
        enable_update = bool(flags & 0x80)
    else:
        flag2 = raw[54]
        support_update = bool(flag2 & 0x02)
        enable_update = bool(flag2 & 0x04)
    if support_update or enable_update:
        raise ConnectionError(
            "DeviceInfoRep indicates security-update support/state; refusing legacy cmd1")


def _uuid_wire_bytes(value: str) -> bytes:
    """Reproduce ProtocolHelper's UUID conversion and 16-byte FF padding."""
    if len(value) == 20:
        if not re.fullmatch(r"[0-9A-Za-z]{20}", value):
            raise ConnectionError("20-character compressed UUID is not alphanumeric")
        bits = "".join(f"{_base62_index(char):06b}" for char in value)
        bits += "1" * ((8 - len(bits) % 8) % 8)
        raw = int(bits, 2).to_bytes(len(bits) // 8, "big")
    else:
        raw = value.encode("utf-8")
    if len(raw) < 16:
        raw += b"\xff" * (16 - len(raw))
    return raw


def _base62_index(char: str) -> int:
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    if "a" <= char <= "z":
        return ord(char) - ord("a") + 10
    return ord(char) - ord("A") + 36
