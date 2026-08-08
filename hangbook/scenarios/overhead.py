import os
import time

print(f"READY {os.getpid()}", flush=True)
while True:
    n = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < 0.1:
        n += 1
    print(n, flush=True)
