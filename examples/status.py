#!/usr/bin/env python3
"""Connect to a scooter and print every DP report received.

DP ids have no semantics until you map them from capture analysis
(docs/capture_analysis.md); this example just dumps them.
"""
import asyncio
import sys

from youfs.scooter import YouFSScooter


async def main(address: str):
    async with YouFSScooter(address) as scooter:
        info = await scooter.fetch_device_info()
        if info:
            print(f"connected: fw={info.device_version} "
                  f"proto={info.protocol_version} bind={info.is_bind}")
        state = await scooter.wait_for_report(timeout=15)
        for dp in state.raw_dps:
            print(f"dp {dp.dp_id:>3} type={dp.dp_type} value={dp.value!r}")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else input("address: ")))
