import asyncio
import os


async def main():
    print(f"READY {os.getpid()}", flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
