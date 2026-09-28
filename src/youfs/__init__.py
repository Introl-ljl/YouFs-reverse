"""youfs — third-party BLE client for YouFs / 永锋顺 scooters.

Protocol stack reverse-engineered from YouFs-A_1.0.3_APKPure.apk (Tuya BLE).
See docs/ for evidence with file:line citations and evidence tiers.
"""

from .protocol import (Dp, DeviceInfo, Ret, build_app_frame, crc16_arc,
                       crc16_modbus, crc8, dp_decode, dp_encode,
                       made_session_key, parse_device_info, parse_ret,
                       trsmitr_encode, TrsmitrAssembler)
from .commands import (CMD_DEVICE_INFO, CMD_DP_QUERY, CMD_DP_SEND,
                       REPORT_DP, REPORT_STATUS_DP, FLAG_PLAIN)
from .telemetry import ScooterState, DpReport, parse_report
from .scooter import DpMap, YouFSScooter

__all__ = [
    "Dp", "DeviceInfo", "Ret", "build_app_frame", "crc16_arc",
    "crc16_modbus", "crc8", "dp_decode", "dp_encode", "made_session_key",
    "parse_device_info", "parse_ret", "trsmitr_encode", "TrsmitrAssembler",
    "CMD_DEVICE_INFO", "CMD_DP_QUERY", "CMD_DP_SEND", "REPORT_DP",
    "REPORT_STATUS_DP", "FLAG_PLAIN",
    "ScooterState", "DpReport", "parse_report",
    "DpMap", "YouFSScooter",
]
__version__ = "0.1.0"
