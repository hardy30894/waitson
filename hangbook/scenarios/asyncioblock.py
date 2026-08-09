import asyncio
import os
import time


async def handler():
    time.sleep(3600)


async def main():
    print(f"READY {os.getpid()}", flush=True)
    await handler()


asyncio.run(main())
