import os
import re
import threading


def hog():
    # Catastrophic backtracking runs inside the re engine, which never
    # releases the GIL and never reaches an eval-loop break.
    re.match(r"(a+)+$", "a" * 32 + "b")


print(f"READY {os.getpid()}", flush=True)
threading.Thread(target=hog, daemon=True).start()
x = 0
while True:
    x += 1
