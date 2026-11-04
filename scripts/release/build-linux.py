#!/usr/bin/env python3
"""Build using the pinned Ubuntu baseline and the repository's pinned Rust toolchain."""
import argparse
from pathlib import Path
import os
import shutil
import subprocess

from artifact import ROOT, output

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work', type=Path, default=ROOT / 'target/release-candidate/work')
parser.add_argument('--local', action='store_true')
args = parser.parse_args()
os.chdir(ROOT)
args.work = args.work.resolve()
if not args.work.is_relative_to(ROOT / 'target'):
    parser.error('--work must be inside target/')
rust = Path(output('rustup', 'which', 'rustc')).parent.parent
cache = ROOT / 'target/release-candidate/cargo-home'
cache.mkdir(parents=True, exist_ok=True)
registry = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'registry'
if registry.exists():
    shutil.copytree(registry, cache / 'registry', dirs_exist_ok=True)
subprocess.run(['docker', 'build', '--target', 'builder', '-f', 'scripts/release/qualification.Dockerfile',
                '-t', 'epochgrid-artifact-builder:local', '.'], check=True)
command = ['docker', 'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}',
           '--mount', f'type=bind,src={ROOT},dst={ROOT}',
           '--mount', f'type=bind,src={rust},dst=/opt/rust,readonly',
           '--workdir', str(ROOT), '-e', f'CARGO_HOME={cache}',
           'epochgrid-artifact-builder:local', 'python3', 'scripts/release/artifact.py',
           'build', '--work', str(args.work)]
if args.local:
    command.append('--local')
subprocess.run(command, check=True)
