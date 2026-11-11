#!/usr/bin/env python3
"""Construct a local runtime image from verified bundle bytes; never publishes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

from artifact import BINS, PAYLOAD, ROOT, digest, output, source, verify, write_json

DEFINITION = ROOT / 'scripts/release/runtime.Dockerfile'
BASE = 'ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852'


def inspect_archive(path, image_id, data):
    """Inspect every saved layer, including files hidden by later deletions."""
    with tarfile.open(path) as archive:
        manifests = json.load(archive.extractfile('manifest.json'))
        if len(manifests) != 1:
            raise ValueError('Transport archive must contain exactly one image')
        manifest = manifests[0]
        raw = archive.extractfile(manifest['Config']).read()
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != image_id:
            raise ValueError('Transport config differs from built image ID')
        config = json.loads(raw)
        runtime = config['config']
        if (config['os'], config['architecture'], runtime['User'], runtime['Entrypoint'],
            runtime['Cmd'], runtime['StopSignal']) != (
                'linux', 'amd64', '65532:65532', ['/usr/local/bin/epochgrid-service'], ['--help'], 'SIGINT'):
            raise ValueError('Unexpected image runtime contract')
        if 'EPOCHGRID_PROFILE=production' not in runtime['Env']:
            raise ValueError('Production profile missing')
        labels = runtime['Labels']
        expected = dict(source='https://github.com/epochgrid/epochgrid', revision=data['commit'],
                        version=data['version'], licenses='MIT')
        if any(labels.get('org.opencontainers.image.' + key) != value for key, value in expected.items()):
            raise ValueError('Image source labels differ from bundle')
        layers = manifest['Layers']
        if len(layers) != len(config['rootfs']['diff_ids']):
            raise ValueError('Layer/config count mismatch')
        entries = 0
        for name, expected_digest in zip(layers, config['rootfs']['diff_ids']):
            with archive.extractfile(name) as stream:
                if 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() != expected_digest:
                    raise ValueError('Corrupt saved layer')
            with tarfile.open(fileobj=archive.extractfile(name), mode='r|') as layer:
                for item in layer:
                    entries += 1
                    name = item.name.removeprefix('./').rstrip('/')
                    if name.startswith('/') or '..' in Path(name).parts:
                        raise ValueError('Unexpected image layer path')
                    leaf = Path(name).name.removeprefix('.wh.')
                    if (name.startswith(('root/.cargo', 'root/.rustup', 'workspace/', 'opt/nats/', 'state/'))
                            or leaf in {'cargo', 'rustc', 'sudo', 'nats-server', 'auth.json', 'credentials.json'}
                            or re.fullmatch(r'python[23](?:\.\d+)?', leaf)
                            or leaf.endswith(('.sqlite', '.sqlite-wal', '.sqlite-shm', '.keyring'))):
                        raise ValueError('Build/test/private input in image layer')
        return dict(layers=len(layers), entries=entries)


def check_identity(data, local):
    if data['commit'] != output('git', 'rev-parse', 'HEAD') or data['source_sha256'] != source():
        raise ValueError('Bundle source/revision differs from checkout')
    if not local and (data['local'] or data['dirty'] or output('git', 'status', '--porcelain')):
        raise ValueError('Dirty/local images require --local and cannot be published')
    if data['environment']['os'] != 'ubuntu' or data['environment']['version'] != '24.04':
        raise ValueError('Image requires the Ubuntu 24.04 bundle baseline')
    for native in data['native'].values():
        if tuple(map(int, native['glibc_max'].split('.'))) > (2, 39):
            raise ValueError('Bundle exceeds runtime GLIBC baseline')


def build(args):
    if args.work.exists():
        raise ValueError('Image output already exists; use a fresh --work directory')
    args.work.mkdir(parents=True)
    report = dict(schema=1, result='failed', phase='verify')
    try:
        with tempfile.TemporaryDirectory(prefix='epochgrid-image-') as temporary:
            context = Path(temporary) / 'context'
            verify(argparse.Namespace(archive=args.archive, checksums=args.checksums, output=context,
                                      require_candidate=not args.local, commit=None))
            data = json.loads((context / 'BUILD.json').read_text())
            check_identity(data, args.local)
            definition = DEFINITION.read_text()
            if f'FROM {BASE}\n' not in definition:
                raise ValueError('Runtime base differs from reviewed digest')
            shutil.copyfile(DEFINITION, context / 'Dockerfile')
            report.update(commit=data['commit'], version=data['version'], source_sha256=data['source_sha256'],
                          local=args.local, base=BASE, platform='linux/amd64',
                          bundle_sha256=digest(args.archive), manifest_sha256=digest(context / 'BUILD.json'),
                          definition_sha256=digest(DEFINITION),
                          binary_sha256={name: digest(context / 'bin' / name) for name in BINS})
            report['phase'] = 'build'
            subprocess.run(['docker', 'build', '--platform', 'linux/amd64',
                            '--iidfile', str(args.work / 'image.id'),
                            '--label', 'org.opencontainers.image.source=https://github.com/epochgrid/epochgrid',
                            '--label', f'org.opencontainers.image.revision={data["commit"]}',
                            '--label', f'org.opencontainers.image.version={data["version"]}',
                            '--label', 'org.opencontainers.image.licenses=MIT', str(context)], check=True)
            image = (args.work / 'image.id').read_text().strip()
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
                raise ValueError('Invalid Docker config ID')
            report['image_id'] = image
            report['phase'] = 'payload'
            container = output('docker', 'create', image)
            try:
                extracted = Path(temporary) / 'extracted'
                extracted.mkdir()
                for name in PAYLOAD:
                    path = '/usr/local/' + name if name.startswith('bin/') else '/usr/share/epochgrid/' + name
                    destination = extracted / Path(name).name
                    subprocess.run(['docker', 'cp', f'{container}:{path}', str(destination)], check=True)
                    if digest(destination) != digest(context / name):
                        raise ValueError('Image payload differs from verified bundle')
                inventory = extracted / 'os-packages.txt'
                subprocess.run(['docker', 'cp', f'{container}:/usr/share/epochgrid/os-packages.txt', str(inventory)], check=True)
                report['os_packages'] = inventory.read_text().splitlines()
            finally:
                subprocess.run(['docker', 'rm', container], check=True, stdout=subprocess.DEVNULL)
            report['phase'] = 'export'
            archive = args.work / 'image.tar'
            subprocess.run(['docker', 'save', '--output', str(archive), image], check=True)
            report['phase'] = 'contract'
            report['layer_inspection'] = inspect_archive(archive, image, data)
            for name in BINS:
                command = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
                           '--cap-drop=ALL', '--security-opt=no-new-privileges', '--entrypoint']
                binary = '/usr/local/bin/' + name
                if output(*command, binary, image, '--version') != f'{name} {data["version"]}':
                    raise ValueError('Image executable version mismatch')
                subprocess.run([*command, binary, image, '--help'], check=True, stdout=subprocess.DEVNULL)
                if 'not found' in output(*command, '/usr/bin/ldd', image, binary):
                    raise ValueError('Unresolved image native dependency')
            check_identity(data, args.local)
            report.update(transport_sha256=digest(archive), transport_bytes=archive.stat().st_size,
                          result='passed', phase='complete')
    finally:
        write_json(args.work / 'image.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--checksums', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--local', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    args.work = args.work.resolve()
    build(args)


if __name__ == '__main__':
    main()
