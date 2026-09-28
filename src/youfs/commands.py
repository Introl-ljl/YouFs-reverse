"""Tuya BLE command codes and safe request builders.

Command numbers from docs/commands.md (Ret.dataParse dispatch + BLEJniLib).
Deliberately NOT implemented here: pairing (0x0001), unbind (0x0005/0x0006),
OTA (0x0B-0x0F), file transfer (112-115) — per the security constraints of
this project we only analyze them, never send them.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .protocol import Dp, build_app_frame, derive_key4, dp_encode

# --- command codes (app -> device) ----------------------------------------- #
CMD_DEVICE_INFO = 0x0000        # sent automatically after connect (P4)
CMD_PAIR = 0x0001               # NOT SENT by this client
CMD_DP_SEND = 0x0002            # DP control (publishDps)
CMD_DP_QUERY = 0x0003           # P4 queryDps (dpqbbpd.java:6999)
CMD_DP_QUERY_LEGACY = 0x0004    # P1 queryDps (BLEJniLib.g())
CMD_PAIR_LOGIN_KEY = 0x0005     # NOT SENT
CMD_UNBIND = 0x0006             # NOT SENT
CMD_EXT_TRANSFER = 0x000A       # time sync etc. — analysis only

# --- device -> app reports -------------------------------------------------- #
REPORT_DP = 0x8001              # DpsReportRep (32769)
REPORT_STATUS_DP = 0x8004       # StatusDpsReportRep (32772)
REPORT_DP_TIME = 0x8003

# --- security flags (pbpdbqp.java:3447-3462) -------------------------------- #
FLAG_PLAIN = 0
FLAG_LEGACY_2 = 2
FLAG_LEGACY_5 = 5
FLAG_NEW_SECURITY_12 = 12
FLAG_NEW_SECURITY_15 = 15

# Known DP type codes (protocol.py re-export)
# DP_BOOL=1 (1B), DP_VALUE=2 (4B LE), DP_ENUM=4 (1B)


def device_info_request(login_key: bytes, mtu_payload: Optional[int] = None,
                         sn: int = 0, sn_ack: int = 0, *,
                         mtu: Optional[int] = None) -> bytes:
    """Build the original APK's P4 legacy cmd0 request.

    `dpqbbpd.fetchDeviceInfoRet()` sends the negotiated ATT MTU minus the
    three ATT header bytes as a two-byte big-endian payload, encrypted with
    flag 4 and key4=MD5(loginKey). This helper deliberately has no plaintext
    or guessed-security fallback.
    """
    if mtu is not None:
        if mtu_payload is not None:
            raise ValueError("pass only one of mtu_payload or mtu")
        mtu_payload = mtu
    if not login_key:
        raise ValueError("P4 cmd0 requires the device loginKey/localKey")
    if len(login_key) != 6:
        raise ValueError("P4 loginKey must be the APK's first six localKey bytes")
    if mtu_payload is None:
        raise ValueError("P4 cmd0 requires the effective MTU payload size")
    if not 0 <= mtu_payload <= 0xFFFF:
        raise ValueError("mtu_payload must fit in two bytes")
    return build_app_frame(
        sn=sn, sn_ack=sn_ack, code=CMD_DEVICE_INFO,
        data=mtu_payload.to_bytes(2, "big"),
        key=derive_key4(login_key), flag=4)


def dp_query_request(dp_ids: Sequence[int] = (), sn: int = 0, sn_ack: int = 0,
                     key=None, flag: int = 0) -> bytes:
    """cmd 0x0003 with a dpId byte list (empty = query all)."""
    data = bytes(dp_ids)
    return build_app_frame(sn=sn, sn_ack=sn_ack, code=CMD_DP_QUERY,
                           data=data, key=key, flag=flag)


def dp_send_request(dps: Sequence[Tuple[int, int, object]], sn: int = 0,
                    sn_ack: int = 0, key=None, flag: int = 0) -> bytes:
    """cmd 0x0002 carrying one or more DPs as TLV."""
    payload = b"".join(dp_encode(dp_id, dp_type, value)
                       for dp_id, dp_type, value in dps)
    return build_app_frame(sn=sn, sn_ack=sn_ack, code=CMD_DP_SEND,
                           data=payload, key=key, flag=flag)


def dps_from_pairs(pairs: Sequence[Tuple[int, object]]) -> List[Dp]:
    """Helper: [(dp_id, value)] with inferred types (bool/int/str)."""
    out: List[Dp] = []
    for dp_id, value in pairs:
        if isinstance(value, bool):
            out.append(Dp(dp_id=dp_id, dp_type=1, value=value, raw=b""))
        elif isinstance(value, int):
            out.append(Dp(dp_id=dp_id, dp_type=2, value=value, raw=b""))
        elif isinstance(value, str):
            out.append(Dp(dp_id=dp_id, dp_type=3, value=value, raw=b""))
        else:
            raise TypeError(f"unsupported dp value {value!r}")
    return out
