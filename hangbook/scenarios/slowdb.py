import os
import socket
import time

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 5432))
srv.listen(1)

if os.fork() == 0:
    conn, _ = srv.accept()
    while True:
        time.sleep(3600)

srv.close()
c = socket.create_connection(("127.0.0.1", 5432))
print(f"READY {os.getpid()}", flush=True)
c.recv(4096)
