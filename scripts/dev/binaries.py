"""Explicit production-binary selection for release qualification fixtures."""
import os
from pathlib import Path


def binary(name):
    override = os.environ.get('EPOCHGRID_RELEASE_BIN_DIR')
    directory = Path(override) if override is not None else Path('target/debug').resolve()
    if not directory.is_absolute():
        raise ValueError('release binary directory must be absolute')
    path = directory / name
    if override is not None and (not path.is_file() or not os.access(path, os.X_OK)):
        raise ValueError(f'missing/non-executable selected binary: {name}')
    return str(path)
