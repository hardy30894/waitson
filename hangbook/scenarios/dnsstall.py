import os
import socket
import time

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 53))

if os.fork() == 0:
    while True:
        time.sleep(3600)

srv.close()
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.connect(("127.0.0.1", 53))
c.send(b"\x00")
print(f"READY {os.getpid()}", flush=True)
c.recv(512)
