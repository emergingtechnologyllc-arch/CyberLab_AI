#!/usr/bin/env python3
"""Isolated functional checks. Does not read or change a user's CyberLab DB."""
from pathlib import Path
import argparse
import platform
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tests'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-ollama', action='store_true', help='Also require a real local Ollama model and change recommendation')
    args = parser.parse_args()
    print('Platform:', platform.platform(), flush=True)
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        'test_dashboard.DashboardTests',
        'test_provenance.ProvenanceTests.test_real_writers_capture_root_and_link_observation',
        'test_changes.ChangeTests.test_monitor_default_ai_off_pause_resume',
    ])
    # Dashboard launcher paths are relative to the release root.
    import os
    os.chdir(ROOT)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        print('FAIL: isolated offline smoke checks'); return 1
    print('PASS: isolated offline smoke checks', flush=True)
    if not args.live_ollama:
        print('NOT RUN: real Ollama (use --live-ollama to require it)'); return 0
    if subprocess.run([sys.executable,str(ROOT/'scripts/verify_ollama.py')]).returncode:
        return 1
    from cyberlab import continuous, change_investigation as changes
    with tempfile.TemporaryDirectory(prefix='cyberlab-live-smoke-') as tmp:
        base = Path(tmp); project = base/'demo'; project.mkdir(); db = str(base/'db.sqlite3')
        continuous.assess(db,project,base)
        route = project/'app/api/synthetic-review/route.ts'; route.parent.mkdir(parents=True); route.touch()
        rid = changes.ensure(db,continuous.assess(db,project,base))
        status = changes.analyze(db,rid)
        if status != 'recommended_review':
            print('FAIL: real Ollama change recommendation:',status); return 1
        print('PASS: real Ollama recommendation validated against genuine evidence IDs')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
