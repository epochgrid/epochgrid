#!/usr/bin/env python3
"""Explicit experiments, never automatic retries in the required gate."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('experiment', choices=['unit-threads', 'runs'])
parser.add_argument('files', nargs='*', help='For runs: GitHub Actions run JSON, with jobs included')
parser.add_argument('--samples', type=int, default=3)
args = parser.parse_args()
if args.experiment == 'unit-threads':
    records = []
    for iteration in range(args.samples):
        # Alternate order to avoid systematically favoring a warmed configuration.
        for threads in (['default', '2'] if iteration % 2 == 0 else ['2', 'default']):
            env = os.environ.copy()
            env.pop('EPOCHGRID_TEST_THREADS', None)
            env.pop('RUST_TEST_THREADS', None)
            if threads != 'default':
                env['EPOCHGRID_TEST_THREADS'] = threads
            start = time.monotonic()
            result = subprocess.run(['./scripts/dev/verify.sh', 'unit'], env=env)
            record = dict(sample=iteration + 1, threads=threads, exit_code=result.returncode,
                          seconds=round(time.monotonic() - start, 3))
            records.append(record)
            print('Benchmark sample: ' + json.dumps(record), flush=True)
    for threads in ('default', '2'):
        samples = [r for r in records if r['threads'] == threads]
        print(json.dumps(dict(threads=threads, samples=len(samples),
                              median=statistics.median(r['seconds'] for r in samples),
                              maximum=max(r['seconds'] for r in samples),
                              failures=sum(r['exit_code'] != 0 for r in samples))))
    raise SystemExit(any(r['exit_code'] for r in records))
else:
    from datetime import datetime
    records = [json.loads(Path(path).read_text()) for path in args.files]
    # Input explicitly labels cohort/cache state; do not infer cold builds from timestamps.
    for cohort in ('before', 'after'):
        samples = [r for r in records if r['cohort'] == cohort and r['cold']
                   and r.get('run_attempt', 1) == 1]
        completed = [r for r in samples if r['conclusion'] != 'cancelled']
        durations = [sum((datetime.fromisoformat(j['completed_at'].replace('Z', '+00:00')) -
                          datetime.fromisoformat(j['started_at'].replace('Z', '+00:00'))).total_seconds()
                         for j in r['jobs'] if j.get('started_at') and j.get('completed_at'))
                     for r in completed]
        print(json.dumps(dict(cohort=cohort, first_attempts=len(samples),
                              cancellations=len(samples) - len(completed),
                              failures=sum(r['conclusion'] != 'success' for r in completed),
                              median_runner_seconds=statistics.median(durations) if durations else None,
                              maximum_runner_seconds=max(durations, default=None),
                              qualification='insufficient samples' if len(completed) < 10 else 'descriptive only')))
