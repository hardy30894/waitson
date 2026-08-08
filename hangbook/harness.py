#!/usr/bin/env python3
"""Hangbook gate: ten canonical hangs, one verdict each.

Pass = expected verdict class, expected root-cause words, under 3 seconds.
Ship gate >= 8/10, kill gate <= 5 (ideation/waitson-design.md v0.0).
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(ROOT, "..", "target", "release", "waitson")
BUILD = "/tmp/hb"

SCENARIOS = [
    ("deadlock", [f"{BUILD}/deadlock"], "CAUSAL", [["deadlock"]]),
    ("lockbusy", [f"{BUILD}/lockbusy"], "CAUSAL", [["held by"], ["busy", "running"]]),
    ("slowdb", [sys.executable, "scenarios/slowdb.py"], "PARTIAL", [["5432", "postgres"]]),
    ("dnsstall", [sys.executable, "scenarios/dnsstall.py"], "PARTIAL", [["dns", ":53"]]),
    ("pipefull", [sys.executable, "scenarios/pipefull.py"], "CAUSAL", [["pipe"]]),
    ("gil", [sys.executable, "scenarios/gil.py"], "CAUSAL", [["gil"]]),
    ("dstate", [f"{BUILD}/dstate"], "CAUSAL", [["vfork"]]),
    ("busyloop", [sys.executable, "scenarios/busyloop.py"], "OBSERVATION", [["busy"]]),
    ("childwait", [sys.executable, "scenarios/childwait.py"], "CAUSAL", [["stopped"]]),
    ("epollidle", [sys.executable, "scenarios/epollidle.py"], "OBSERVATION", [["idle"]]),
]


def build_c():
    os.makedirs(BUILD, exist_ok=True)
    for src in ("deadlock", "lockbusy", "dstate"):
        subprocess.run(
            ["gcc", "-O0", "-pthread", os.path.join(ROOT, "scenarios", f"{src}.c"), "-o", f"{BUILD}/{src}"],
            check=True,
        )


def read_ready(proc, timeout=10.0):
    result = {}

    def reader():
        line = proc.stdout.readline()
        if line.startswith("READY "):
            result["pid"] = int(line.split()[1])

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(timeout)
    return result.get("pid")


def run_one(name, cmd, expected, needles):
    proc = subprocess.Popen(
        cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, start_new_session=True
    )
    row = {"name": name, "expected": expected, "passed": False}
    try:
        target = read_ready(proc)
        if target is None:
            row["error"] = "scenario never printed READY"
            return row
        time.sleep(0.8)

        t0 = time.monotonic()
        out = subprocess.run([BIN, str(target), "--json"], capture_output=True, text=True, timeout=10)
        row["seconds"] = round(time.monotonic() - t0, 2)
        if out.returncode != 0:
            row["error"] = out.stderr.strip()
            return row

        verdict = json.loads(out.stdout)
        row["class"] = verdict["class"]
        row["headline"] = verdict["headline"]
        text = json.dumps(verdict).lower()
        row["passed"] = (
            verdict["class"] == expected
            and all(any(n.lower() in text for n in group) for group in needles)
            and row["seconds"] < 3.0
        )
        return row
    except Exception as e:
        row["error"] = repr(e)
        return row
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()


def main():
    build_c()
    rows = [run_one(*s) for s in SCENARIOS]
    passed = sum(r["passed"] for r in rows)

    print(f"\n{'scenario':<11} {'verdict':<12} {'want':<12} {'time':>5}  result")
    for r in rows:
        got = r.get("class", "-")
        secs = f"{r.get('seconds', 0):.2f}s" if "seconds" in r else "-"
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"{r['name']:<11} {got:<12} {r['expected']:<12} {secs:>5}  {mark}")
        detail = r.get("headline") or r.get("error", "")
        print(f"            {detail}")

    print(f"\nhangbook: {passed}/10 (ship gate >= 8, kill gate <= 5)")
    with open(os.path.join(ROOT, "results.json"), "w") as f:
        json.dump({"passed": passed, "rows": rows}, f, indent=2)
    sys.exit(0 if passed >= 8 else 1)


if __name__ == "__main__":
    main()
