#!/usr/bin/env python3
"""Turn the scooter light on/off.

LOW-RISK COMMAND ONLY (project security constraints).  Requires:
  - the light dp_id, obtained by differential capture (docs/capture_analysis.md)
  - a session key (or an unencrypted device): pass --key/--local-key as needed.
"""
import asyncio
import sys

from youfs.scooter import DpMap, YouFSScooter

LIGHT_DP_ID = 0   # TODO: fill from capture analysis — never guess
SESSION_KEY = None  # 16-byte session key, e.g. from `cli.py info --local-key ...`


async def main(address: str, on: bool):
    if not LIGHT_DP_ID:
        raise SystemExit("set LIGHT_DP_ID from capture analysis first")
    async with YouFSScooter(address, session_key=SESSION_KEY,
                            dp_map=DpMap(light=LIGHT_DP_ID)) as scooter:
        await scooter.fetch_device_info()
        await scooter.set_light(on)
        print("frame sent; watching for confirmation report...")
        await scooter.wait_for_report(timeout=6)
        print("state.light =", scooter.state.light)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2] == "on"))
