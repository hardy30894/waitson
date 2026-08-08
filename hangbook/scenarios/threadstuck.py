import asyncio
import os
import socket
import threading
import time

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9009))
srv.listen(1)

if os.fork() == 0:
    conn, _ = srv.accept()
    while True:
        time.sleep(3600)

srv.close()


def worker():
    c = socket.create_connection(("127.0.0.1", 9009))
    c.recv(4096)


threading.Thread(target=worker, daemon=True).start()


async def main():
    print(f"READY {os.getpid()}", flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
