import os
import signal
import subprocess
import sys

child = subprocess.Popen([sys.executable, "-c", "import time\nwhile True: time.sleep(3600)"])
os.kill(child.pid, signal.SIGSTOP)
print(f"READY {os.getpid()}", flush=True)
os.waitpid(child.pid, 0)
