#!/usr/bin/env python3
"""Exec one parser campaign with a hard Linux address-space limit, no core dumps."""
import os
import resource
import sys


def main():
    if len(sys.argv) < 3:
        raise ValueError('usage: limit-memory.py MIB COMMAND [ARG ...]')
    mib = int(sys.argv[1])
    if not 32 <= mib <= 4096:
        raise ValueError('memory budget must be 32..4096 MiB')
    budget = mib * 1024 * 1024
    # A lower inherited hard limit is authoritative; do not silently raise it.
    resource.setrlimit(resource.RLIMIT_AS, (budget, budget))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    print(f'EpochGrid parser budget: address_space_mib={mib} core_bytes=0', flush=True)
    os.execvp(sys.argv[2], sys.argv[2:])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print(f'Parser resource setup failed: {error}', file=sys.stderr)
        sys.exit(2)
