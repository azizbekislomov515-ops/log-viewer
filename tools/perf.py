"""Measure LogLens startup and memory (docs/PERFORMANCE.md).

    python tools/perf.py startup [--runs 5]   # process start -> first frame painted
    python tools/perf.py memory               # RSS: idle (real discovery) and under load

Each run is a fresh process with empty XDG dirs, offscreen. ``startup`` reports the
median; ``memory`` samples RSS after 10 s idle and after 10 s of 20,000 lines/s.
"""

from __future__ import annotations

import argparse
import os
import statistics
import subprocess
import sys
import tempfile
import time

CHILD = r"""
import os, sys, time
T0 = float(os.environ["PERF_T0"])
from PySide6.QtCore import QTimer
from loglens.gui import main_window
from loglens.gui.app import main

marks = {}
orig_show = main_window.MainWindow.showEvent

def show_event(self, event):
    orig_show(self, event)
    marks.setdefault("shown", time.monotonic() - T0)
    def painted():
        marks.setdefault("frame", time.monotonic() - T0)
        print(f"PERF shown={marks['shown']:.3f} frame={marks['frame']:.3f}", flush=True)
        mode = os.environ["PERF_MODE"]
        if mode == "startup":
            self.close()
            return
        def sample(label):
            rss = int(open("/proc/self/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
            print(f"PERF {label}_rss_mb={rss / 2**20:.0f}", flush=True)
        if mode == "idle":
            QTimer.singleShot(10_000, lambda: (sample("idle"), self.close()))
        else:  # load: open the busiest demo source and stream for 10 s
            def go():
                tab = self.open_source("systemd:myapp.service")
                if tab is None:
                    QTimer.singleShot(200, go)
                    return
                QTimer.singleShot(10_000, lambda: (sample("load"), self.close()))
            go()
    QTimer.singleShot(0, painted)

main_window.MainWindow.showEvent = show_event
args = sys.argv[1:]
sys.exit(main(args))
"""


def run(mode: str, extra: list[str]) -> dict[str, float]:
    with tempfile.TemporaryDirectory() as home:
        env = {
            **os.environ,
            "QT_QPA_PLATFORM": "offscreen",
            "XDG_CONFIG_HOME": f"{home}/config",
            "XDG_DATA_HOME": f"{home}/data",
            "XDG_STATE_HOME": f"{home}/state",
            "PERF_MODE": mode,
            "PERF_T0": str(time.monotonic()),
        }
        out = subprocess.run(  # noqa: S603 - our own interpreter and script
            [sys.executable, "-c", CHILD, *extra], env=env, capture_output=True, text=True,
            timeout=120, check=False,
        )  # fmt: skip
    marks: dict[str, float] = {}
    for line in out.stdout.splitlines():
        if line.startswith("PERF "):
            for item in line[5:].split():
                key, value = item.split("=")
                marks[key] = float(value)
    if not marks:
        raise SystemExit(f"no measurement:\n{out.stdout}\n{out.stderr}")
    return marks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("what", choices=["startup", "memory"])
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if args.what == "startup":
        runs = [run("startup", []) for _ in range(args.runs)]
        for key in ("shown", "frame"):
            values = [r[key] for r in runs]
            print(f"{key:6} median {statistics.median(values):.2f} s  "
                  f"(min {min(values):.2f}, max {max(values):.2f}, n={len(values)})")  # fmt: skip
    else:
        print(f"idle  {run('idle', [])['idle_rss_mb']:.0f} MB RSS (real discovery, 10 s)")
        load = run("load", ["--demo", "--replay-rate", "20000"])
        print(f"load  {load['load_rss_mb']:.0f} MB RSS (demo, ~20k lines/s, 10 s)")


if __name__ == "__main__":
    main()
