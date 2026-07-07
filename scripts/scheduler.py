"""Periodic scanner: the scheduled/outer trigger. Audits the fork on an interval and
files labelled GitHub issues. Those labelled issues fire the webhook -> orchestrator.

Run: python -m scripts.scheduler   (SCAN_INTERVAL_SECONDS controls cadence)
"""
import os
import time

from app import db, scanner

INTERVAL = int(os.getenv("SCAN_INTERVAL_SECONDS", "3600"))


def main():
    db.init_db()
    print(f"[scheduler] scanning every {INTERVAL}s")
    while True:
        try:
            findings = scanner.run_scan()
            numbers = scanner.create_issues(findings)
            print(f"[scheduler] {len(findings)} findings -> filed issues {numbers}", flush=True)
        except Exception as e:  # keep the loop alive
            print(f"[scheduler] error: {type(e).__name__}: {e}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
