"""Telemetry parsing: device -> app DP reports into ScooterState.

Report framing is code-confirmed (docs/telemetry.md); the mapping from dp_id to
vehicle semantics is UNKNOWN until HCI capture fills docs/telemetry.md's table.
Configure it via dp_map: {field: {"dp_id": N, "type": T, "scale": S}}.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .protocol import Dp, dp_decode

STATE_FIELDS = (
    "speed", "battery", "voltage", "current", "temperature_controller",
    "temperature_motor", "odometer", "trip", "light", "locked", "cruise",
    "start_mode", "regen", "error", "firmware_version",
)


@dataclass
class DpReport:
    code: int
    sn: int
    dps: List[Dp] = field(default_factory=list)


def parse_report(code: int, data: bytes, sn: int = 0) -> DpReport:
    """Parse a 0x8001/0x8003/0x8004 report body (DpsReportRep.parseRep).

    0x8001 pv4: 7-byte header [ver 1B][sn 4B BE][b_type 1B][flag 1B],
                TLV uses 2-byte BE dpLen (b_type bit7 clear = needAck)
    0x8001 pv3: no header, 1-byte dpLen
    0x8004:     3-byte header [rsnh][rshl][flag], 1-byte dpLen
    """
    body = data
    wide = False
    if code == 0x8001 and len(body) >= 7 and body[0] == 4:
        sn = int.from_bytes(body[1:5], "big")
        body = body[7:]
        wide = True
    elif code == 0x8004 and len(body) >= 3:
        body = body[3:]
    return DpReport(code=code, sn=sn, dps=dp_decode(body, wide_len=wide))


def parse_report_frame(frame_payload: bytes) -> Optional[DpReport]:
    """Convenience: decode the *inner* payload when the caller only has the
    trsmitr payload and already knows it is an unencrypted report."""
    if len(frame_payload) < 14:
        return None
    code = int.from_bytes(frame_payload[8:10], "big")
    length = int.from_bytes(frame_payload[10:12], "big")
    data = frame_payload[12:12 + length]
    sn = int.from_bytes(frame_payload[0:4], "big")
    return parse_report(code, data, sn=sn)


@dataclass
class ScooterState:
    """Semantic vehicle state. Unmapped fields stay None; raw DPs are kept."""
    speed: Optional[float] = None
    battery: Optional[float] = None
    voltage: Optional[float] = None
    current: Optional[float] = None
    temperature_controller: Optional[float] = None
    temperature_motor: Optional[float] = None
    odometer: Optional[float] = None
    trip: Optional[float] = None
    light: Optional[bool] = None
    locked: Optional[bool] = None
    cruise: Optional[bool] = None
    start_mode: Optional[int] = None
    regen: Optional[int] = None
    error: Optional[int] = None
    firmware_version: Optional[str] = None
    raw_dps: List[Dp] = field(default_factory=list)


def apply_dp_map(state: ScooterState, dps: List[Dp],
                 dp_map: Dict[str, Dict[str, Any]]) -> None:
    """Fill state fields according to dp_map.

    dp_map entry: {"dp_id": int, "type": int, "scale": float, "bool": bool}
    Only confirmed mappings belong here; UNKNOWN ids stay in raw_dps.
    """
    state.raw_dps = list(dps)
    for dp in dps:
        for name, spec in dp_map.items():
            if spec.get("dp_id") != dp.dp_id:
                continue
            if "type" in spec and spec["type"] != dp.dp_type:
                continue
            value = dp.as_int() if dp.dp_type in (1, 2, 4, 5) else dp.value
            if value is None:
                continue
            if spec.get("bool") or dp.dp_type == 1:
                setattr(state, name, bool(value))
                continue
            scale = spec.get("scale", 1)
            if isinstance(value, (int, float)) and scale != 1:
                value = value * scale
            setattr(state, name, value)
