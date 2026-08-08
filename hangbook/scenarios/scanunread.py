import os
import socket
import time

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9010))
srv.listen(1)

pid = os.fork()
if pid == 0:
    srv.close()
    c = socket.create_connection(("127.0.0.1", 9010))
    c.sendall(b"x" * 262144)
    while True:
        time.sleep(3600)

conn, _ = srv.accept()
print(f"READY {os.getpid()}", flush=True)
while True:
    time.sleep(3600)
