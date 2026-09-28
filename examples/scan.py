#!/usr/bin/env python3
"""Scan for YouFs / Tuya BLE devices."""
import asyncio

from youfs.scanner import scan_tuya


async def main():
    for dev in await scan_tuya(timeout=10):
        adv = dev.adv
        print(f"{dev.address}  rssi={dev.rssi:>4}  {dev.name!r}  "
              f"company=0x{adv.company_id:04X} bound={adv.bound} "
              f"uuid={adv.device_uuid!r}")


if __name__ == "__main__":
    asyncio.run(main())
