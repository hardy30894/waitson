import os
import time

r, w = os.pipe()
pid = os.fork()
if pid:
    os.close(w)
    print(f"READY {pid}", flush=True)
    while True:
        time.sleep(3600)
else:
    os.close(r)
    while True:
        os.write(w, b"x" * 65536)
