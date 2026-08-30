"""Measure protected-script startup and reject slow builds.

Example: python benchmark.py test.obf.lua --runtime luau --runs 100
"""
import argparse
import os
import shutil
import statistics
import subprocess
import sys
import time


def percentile(samples, ratio):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * ratio))]


def main():
    parser = argparse.ArgumentParser(description='Protected Lua/Luau startup benchmark')
    parser.add_argument('script')
    parser.add_argument('--runtime', default='luau', help='Runtime executable (lua or luau)')
    parser.add_argument('--runs', type=int, default=100)
    parser.add_argument('--limit-ms', type=float, default=1000.0)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error('--runs must be positive')
    executable = shutil.which(args.runtime)
    if not executable:
        parser.error('Runtime %r was not found on PATH.' % args.runtime)
    script = os.path.abspath(args.script)
    if not os.path.isfile(script):
        parser.error('Script does not exist: ' + script)

    timings = []
    for _ in range(args.runs):
        started = time.perf_counter()
        completed = subprocess.run([executable, script], capture_output=True, text=True)
        elapsed = (time.perf_counter() - started) * 1000
        if completed.returncode != 0:
            sys.stderr.write(completed.stderr or completed.stdout)
            raise SystemExit('Protected script failed during benchmark.')
        timings.append(elapsed)
    median, p95 = statistics.median(timings), percentile(timings, .95)
    print('runs=%d median_ms=%.2f p95_ms=%.2f min_ms=%.2f max_ms=%.2f' %
          (args.runs, median, p95, min(timings), max(timings)))
    if p95 > args.limit_ms:
        raise SystemExit('REJECTED: p95 startup %.2f ms exceeds %.2f ms.' % (p95, args.limit_ms))


if __name__ == '__main__':
    main()
