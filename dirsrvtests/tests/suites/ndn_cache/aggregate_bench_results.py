#!/usr/bin/python3
"""Aggregate NDN memberOf benchmark results."""

import argparse
import json
import os
import statistics
import sys
from collections import defaultdict

METRICS = [
    'ops_per_sec',
    'ndn_tries_per_sec',
    'ndn_hit_ratio',
    'ndn_evictions',
    'reprime_ndn_hit_ratio',
    'reprime_ndn_evictions',
    'reprime_ndn_tries',
    'reprime_ndn_hits',
    'cache_requested_bytes',
    'cache_effective_max_bytes',
    'cache_current_size_bytes',
    'cache_current_count',
    'cache_dataset_entries',
    'cache_dataset_bytes',
    'rss_delta_kb',
    'wall_time_sec',
    'total_ops',
    'p50_ms',
    'p95_ms',
    'p99_ms',
    'scan_wall_sec',
    'reprime_wall_sec',
]

PROFILE_ORDER = {
    'disabled': -1,
    'small': 0,
    'fit': 1,
    'large': 2,
    'default': 3,
    None: 4,
}


def _default_results_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, '..', '..', 'data', 'bench_results',
                        'phase3_memberof.json')


def _quartile(values, p):
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    s = sorted(values)
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def _format_metric(name, values):
    clean = [v for v in values if v is not None]
    if not clean:
        return None
    n = len(clean)
    if n == 1:
        return f'  {name:20s} value={clean[0]} n_valid=1'
    med = statistics.median(clean)
    q1 = _quartile(clean, 0.25)
    q3 = _quartile(clean, 0.75)
    lo = min(clean)
    hi = max(clean)
    n_total_marker = '' if n == len(values) else f' (of {len(values)} reps)'
    return (f'  {name:20s} median={med:<10.4g} '
            f'IQR=[{q1:.4g}, {q3:.4g}]  min={lo:.4g}  max={hi:.4g}  '
            f'n_valid={n}{n_total_marker}')


def _effective_cache_size(record):
    if 'cache_effective_max_bytes' in record:
        return record.get('cache_effective_max_bytes')
    if 'cache_size_mb' in record:
        size_mb = record.get('cache_size_mb')
        return None if size_mb is None else size_mb * 1024 * 1024
    return None


def aggregate(records):
    grouped = defaultdict(list)
    for r in records:
        key = (r.get('test'),
               r.get('variant'),
               r.get('concread_mode'),
               r.get('cache_profile'),
               _effective_cache_size(r),
               r.get('n_threads'))
        grouped[key].append(r)

    def _sort_key(k):
        test, variant, concread_mode, profile, effective_size, threads = k
        profile_order = PROFILE_ORDER.get(profile, 99)
        effective_order = effective_size if effective_size is not None else -1
        thread_order = threads if threads is not None else -1
        return (test or '', variant or '', concread_mode or '', profile_order,
                effective_order, thread_order)

    for key in sorted(grouped.keys(), key=_sort_key):
        test, variant, concread_mode, profile, effective_size, threads = key
        reps = grouped[key]
        header = f'test={test}  variant={variant}'
        if concread_mode is not None:
            header += f'  concread_mode={concread_mode}'
        if profile is not None:
            header += f'  profile={profile}'
        if effective_size is not None:
            header += f'  effective_cache_bytes={effective_size}'
        if threads is not None:
            header += f'  threads={threads}'
        header += f'  reps={len(reps)}'
        lines = [header]
        for metric in METRICS:
            values = [r.get(metric) for r in reps if metric in r]
            if not values:
                continue
            line = _format_metric(metric, values)
            if line is not None:
                lines.append(line)
        yield '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n', 1)[0])
    parser.add_argument('path', nargs='?', default=_default_results_path(),
                        help='Path to phase3_memberof.json '
                             '(default: dirsrvtests/tests/data/bench_results/phase3_memberof.json)')
    args = parser.parse_args(argv)

    if not os.path.isfile(args.path):
        print(f'ERROR: results file not found: {args.path}', file=sys.stderr)
        return 1

    with open(args.path) as f:
        records = json.load(f)

    if not isinstance(records, list):
        print(f'ERROR: expected a JSON array in {args.path}', file=sys.stderr)
        return 1

    print(f'# Aggregated from {args.path}')
    print(f'# {len(records)} raw records\n')

    blocks = list(aggregate(records))
    if not blocks:
        print('# No groupable records found.')
        return 0

    print('\n\n'.join(blocks))
    return 0


if __name__ == '__main__':
    sys.exit(main())
