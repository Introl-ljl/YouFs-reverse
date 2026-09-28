"""Telemetry report parsing tests (framing from DpsReportRep/StatusDpsReportRep)."""

from youfs.protocol import dp_encode
from youfs.telemetry import ScooterState, apply_dp_map, parse_report
from youfs.commands import REPORT_DP, REPORT_STATUS_DP


def test_parse_0x8001_plain_tlv():
    tlv = dp_encode(1, 1, True) + dp_encode(2, 2, 2500)
    report = parse_report(REPORT_DP, tlv)
    assert [(d.dp_id, d.value) for d in report.dps] == [(1, True), (2, 2500)]


def test_parse_0x8001_pv4_header():
    # pv4: 7-byte header + 2-byte BE dpLen TLV (DpsReportRep.parseRep)
    body = (b"\x04"                       # ver=4
            + (77).to_bytes(4, "big")     # sn
            + b"\x01"                     # b_type (bit7 clear = needAck)
            + b"\x00"                     # flag
            + bytes([9, 1, 0, 1, 0]))     # [dp 9][bool][len=2B BE][0x00]
    report = parse_report(REPORT_DP, body)
    assert report.sn == 77
    assert report.dps[0].dp_id == 9 and report.dps[0].value is False


def test_parse_0x8004_status_header():
    tlv = dp_encode(3, 2, 1234)
    body = b"\x01\x02\x00" + tlv          # rsnh/rshl/flag
    report = parse_report(REPORT_STATUS_DP, body)
    assert report.dps[0].as_int() == 1234


def test_state_mapping_with_dp_map():
    state = ScooterState()
    tlv = dp_encode(20, 1, True) + dp_encode(21, 2, 1350)
    report = parse_report(REPORT_STATUS_DP, b"\x00\x00\x00" + tlv)
    apply_dp_map(state, report.dps, {
        "light": {"dp_id": 20},
        "speed": {"dp_id": 21, "scale": 0.1},
    })
    assert state.light is True
    assert state.speed == 135.0
    assert state.raw_dps == report.dps


def test_unmapped_dps_stay_raw():
    state = ScooterState()
    tlv = dp_encode(99, 2, 42)
    report = parse_report(REPORT_DP, tlv)
    apply_dp_map(state, report.dps, {})
    assert state.raw_dps == report.dps
    assert state.speed is None and state.battery is None
