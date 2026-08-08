import os

print(f"READY {os.getpid()}", flush=True)
x = 0
while True:
    x = (x * 1103515245 + 12345) % (1 << 31)
