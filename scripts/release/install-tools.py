#!/usr/bin/env python3
"""Install checksum-pinned release tools into a new private directory."""
import argparse
import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request

TOOLS = {
    'gh': ('https://github.com/cli/cli/releases/download/v2.100.0/gh_2.100.0_linux_amd64.tar.gz',
           'e4d4bb4498e8d007abe545b6568926793ace1b6447da598294a610018cb164be', 'gh_2.100.0_linux_amd64/bin/gh'),
    'grype': ('https://github.com/anchore/grype/releases/download/v0.121.3/grype_0.121.3_linux_amd64.tar.gz',
             'e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85', 'grype'),
}


def install(directory, names):
    directory.mkdir(parents=True, exist_ok=False)
    for name in names:
        url, expected, member = TOOLS[name]
        with urllib.request.urlopen(url, timeout=60) as response:
            raw = response.read(128 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('Tool archive checksum mismatch')
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            item = archive.getmember(member)
            if not item.isfile() or item.size > 256 * 1024 * 1024:
                raise ValueError('Unexpected tool executable')
            path = directory / name
            with path.open('xb') as stream:
                stream.write(archive.extractfile(item).read())
            path.chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('tools', nargs='+', choices=TOOLS)
    args = parser.parse_args()
    install(args.output, args.tools)
