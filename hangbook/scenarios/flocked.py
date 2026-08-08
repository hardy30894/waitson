import fcntl
import os
import time

f = open("/tmp/hb/lockfile", "w")
fcntl.flock(f, fcntl.LOCK_EX)

pid = os.fork()
if pid:
    print(f"READY {pid}", flush=True)
    while True:
        time.sleep(3600)
else:
    f2 = open("/tmp/hb/lockfile", "w")
    fcntl.flock(f2, fcntl.LOCK_EX)
