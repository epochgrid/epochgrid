#!/usr/bin/env python3
"""Build, package and verify Linux qualification candidates (never publishes)."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'x86_64-unknown-linux-gnu'
BINS = ('epochgrid', 'epochgrid-service')
PAYLOAD = {'bin/' + name: 0o755 for name in BINS} | {
    name: 0o644 for name in ('BUILD.json', 'LICENSE', 'THIRD_PARTY_NOTICES', 'README.md')}
MAX_FILE = 256 * 1024 * 1024


def output(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def source():
    # Fingerprint build/test inputs, including untracked scripts and notices.
    # Narrative docs/handoff are not compiler or qualification inputs.
    names = output('git', 'ls-files', '-c', '-o', '--exclude-standard', '-z').split('\0')
    value = hashlib.sha256()
    for name in sorted(set(filter(None, names))):
        if not (name.startswith(('crates/', 'scripts/', '.cargo/', '.github/')) or
                name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE')):
            continue
        path = ROOT / name
        value.update(name.encode() + b'\0')
        value.update((digest(path) if path.is_file() else 'missing').encode())
    return value.hexdigest()


def identity(local):
    dirty = bool(output('git', 'status', '--porcelain', '--untracked-files=all'))
    if dirty and not local:
        raise ValueError('Candidate requires a clean checkout; use --local for non-distributable testing')
    release = platform.freedesktop_os_release()
    if not local and (release['ID'], release['VERSION_ID'], platform.machine()) != ('ubuntu', '24.04', 'x86_64'):
        raise ValueError('Candidates require Ubuntu 24.04 x86-64')
    return dict(commit=output('git', 'rev-parse', 'HEAD'), source_sha256=source(),
                local=local, dirty=dirty,
                source_epoch=int(output('git', 'show', '-s', '--format=%ct', 'HEAD')),
                environment=dict(os=release['ID'], version=release['VERSION_ID'],
                                 machine=platform.machine(), libc=list(platform.libc_ver())))


def elf(path):
    header = output('readelf', '-h', str(path), env=dict(os.environ, LC_ALL='C'))
    if 'ELF64' not in header or 'Advanced Micro Devices X86-64' not in header:
        raise ValueError('Wrong ELF architecture')
    program = output('readelf', '-l', str(path))
    interpreter = re.search(r'Requesting program interpreter: (.*?)\]', program)
    if not interpreter or interpreter[1] != '/lib64/ld-linux-x86-64.so.2':
        raise ValueError('Unexpected ELF interpreter')
    dynamic = output('readelf', '-d', str(path))
    if '(RPATH)' in dynamic or '(RUNPATH)' in dynamic:
        raise ValueError('Unexpected embedded library search path')
    libraries = sorted(re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic))
    if not libraries or set(libraries) - {'libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'ld-linux-x86-64.so.2'}:
        raise ValueError(f'Unreviewed native dependency: {libraries}')
    versions = re.findall(r'GLIBC_(\d+(?:\.\d+)+)', output('readelf', '--version-info', str(path)))
    maximum = max(versions, key=lambda v: tuple(map(int, v.split('.'))))
    return dict(interpreter=interpreter[1], needed=libraries, glibc_max=maximum)


def licenses(metadata, compiled):
    """Use the actual compiler-artifact graph, including build tools conservatively."""
    overrides = json.loads((ROOT / 'scripts/release/licenses/overrides.json').read_text())
    chunks = ['Third-party notices for the locked compiled dependency graph.\n'
              'Includes build dependencies conservatively. Dependencies are unmodified.\n'
              'Exact crate source archives: https://static.crates.io/crates/NAME/NAME-VERSION.crate\n']
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if package['id'] not in compiled or package['id'] in metadata['workspace_members']:
            continue
        name, version = package['name'], package['version']
        allowed = {'MIT', 'Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause',
                   'BSL-1.0', 'MPL-2.0', 'Unicode-3.0', 'Unlicense', 'Zlib',
                   'LLVM-exception', 'AND', 'OR', 'WITH'}
        tokens = set(re.findall(r'[A-Za-z0-9.-]+', package['license'] or ''))
        if not tokens or tokens - allowed:
            raise ValueError(f'Unknown license: {name} {version}')
        directory = Path(package['manifest_path']).parent
        files = sorted(p for p in directory.rglob('*') if p.is_file() and
                       p.name.lower().startswith(('license', 'copying', 'copyright', 'notice')) and
                       p.suffix not in ('.rs', '.c', '.h', '.pm'))
        extra = overrides.get(f'{name}@{version}', [])
        if not files and not extra:
            raise ValueError(f'Missing license text: {name}@{version}')
        chunks.append(f'\n=== {name} {version} ===\nLicense: {package["license"]}\n'
                      f'Source: https://static.crates.io/crates/{name}/{name}-{version}.crate\n')
        for file in files:
            chunks.append(f'\n--- {file.relative_to(directory)} ---\n' + file.read_text())
        for entry in extra:
            file = ROOT / 'scripts/release/licenses' / entry['file']
            if digest(file) != entry['sha256']:
                raise ValueError('Reviewed license digest mismatch')
            chunks.append(f'\n--- {entry["source"]} ---\n' + file.read_text())
    # These native license texts must survive future dependency/feature changes.
    text = '\n'.join(chunks)
    for required in ('sqlcipher/LICENSE', 'openssl/LICENSE.txt', 'LICENSE-BoringSSL'):
        if required not in text:
            raise ValueError(f'Missing bundled native notice: {required}')
    return text


def build(args):
    before = identity(args.local)
    if any(k in os.environ for k in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')):
        raise ValueError('Custom compiler flags/wrappers are not supported')
    pinned = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
    compiler = output('rustc', '-Vv')
    if f'release: {pinned}\n' not in compiler + '\n':
        raise ValueError('Compiler differs from pinned toolchain')
    stage = args.work / 'stage'
    if stage.exists():
        raise ValueError('Build staging already exists; use a fresh --work directory')
    args.work.mkdir(parents=True, exist_ok=True)
    target_dir = args.work / 'cargo'
    # Metadata resolves other target/dev dependencies too. Fetch its locked graph
    # explicitly before compilation; a Linux build alone cannot seed this cache.
    metadata = json.loads(output('cargo', 'metadata', '--locked', '--format-version', '1'))
    command = ['cargo', 'build', '--locked', '--release', '--target', TARGET,
               '--target-dir', str(target_dir), '--bin', BINS[0], '--bin', BINS[1], '--message-format=json']
    compiled = set()
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            item = json.loads(line)
            if item.get('reason') == 'compiler-artifact':
                compiled.add(item['package_id'])
            elif item.get('reason') == 'compiler-message':
                print(item['message'].get('rendered', ''), end='', file=sys.stderr)
        if process.wait():
            raise subprocess.CalledProcessError(process.returncode, command)
    notices = licenses(metadata, compiled)
    if identity(args.local) != before:
        raise ValueError('Source changed during build')
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    stage.mkdir()
    (stage / 'bin').mkdir()
    dependencies = {}
    for name in BINS:
        path = stage / 'bin' / name
        shutil.copyfile(target_dir / TARGET / 'release' / name, path)
        path.chmod(0o755)
        if output(str(path), '--version') != f'{name} {version}':
            raise ValueError('Binary package version mismatch')
        dependencies[name] = elf(path)
        if not args.local and tuple(map(int, dependencies[name]['glibc_max'].split('.'))) > (2, 39):
            raise ValueError('Binary exceeds Ubuntu 24.04 GLIBC baseline')
    shutil.copyfile(ROOT / 'LICENSE', stage / 'LICENSE')
    shutil.copyfile(ROOT / 'scripts/release/BUNDLE-README.md', stage / 'README.md')
    (stage / 'THIRD_PARTY_NOTICES').write_text(notices)
    before['environment']['packages'] = output('dpkg-query', '-W', '-f=${Package}=${Version}\n').splitlines()
    before['environment']['definition_sha256'] = digest(ROOT / 'scripts/release/qualification.Dockerfile')
    data = dict(schema=1, version=version, target=TARGET, profile='release', features='default',
                rustc=compiler, cargo=output('cargo', '-V'), lock_sha256=digest(ROOT / 'Cargo.lock'),
                native=dependencies, **before)
    data['files'] = {}
    for name, mode in PAYLOAD.items():
        if name == 'BUILD.json':
            continue
        path = stage / name
        path.chmod(mode)
        data['files'][name] = dict(sha256=digest(path), size=path.stat().st_size, mode=mode)
    write_json(stage / 'BUILD.json', data)
    (stage / 'BUILD.json').chmod(0o644)
    print(f'Built {"local test" if args.local else "candidate"} bundle: {stage}', flush=True)


def validate_stage(stage):
    actual = {p.relative_to(stage).as_posix() for p in stage.rglob('*') if not p.is_dir()}
    if actual != set(PAYLOAD) or any(p.is_symlink() for p in stage.rglob('*')) or {p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_dir()} != {'bin'}:
        raise ValueError('Unexpected or missing bundle files/links')
    data = json.loads((stage / 'BUILD.json').read_text())
    if data.get('schema') != 1 or data.get('target') != TARGET or data.get('profile') != 'release':
        raise ValueError('Unsupported manifest schema/target/profile')
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', data['version']):
        raise ValueError('Invalid package version')
    if not re.fullmatch(r'[a-f0-9]{40}', data['commit']):
        raise ValueError('Invalid source revision')
    if data['files'].keys() != PAYLOAD.keys() - {'BUILD.json'}:
        raise ValueError('Manifest payload mismatch')
    for name, mode in PAYLOAD.items():
        path = stage / name
        if not path.is_file() or path.stat().st_size > MAX_FILE or path.stat().st_mode & 0o7777 != mode:
            raise ValueError('Invalid payload size/type/mode')
        if name != 'BUILD.json' and data['files'][name] != dict(sha256=digest(path), size=path.stat().st_size, mode=mode):
            raise ValueError(f'Payload digest/size/mode mismatch: {name}')
    for name in BINS:
        if elf(stage / 'bin' / name) != data['native'][name]:
            raise ValueError('Native dependency manifest mismatch')
    return data


def archive(stage, path, data):
    root = f'epochgrid-{data["version"]}-{TARGET}'
    with open(path, 'xb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for name, mode in sorted(PAYLOAD.items()):
                    content = (stage / name).read_bytes()
                    info = tarfile.TarInfo(root + '/' + name)
                    info.size, info.mode, info.mtime = len(content), mode, data['source_epoch']
                    tar.addfile(info, io.BytesIO(content))


def package(args):
    stage = args.work / 'stage'
    data = validate_stage(stage)
    if data['source_sha256'] != source() or data['commit'] != output('git', 'rev-parse', 'HEAD'):
        raise ValueError('Source differs from built bundle')
    if not data['local']:
        identity(False)
    kind = 'local' if data['local'] else 'candidate'
    name = f'epochgrid-{data["version"]}-{kind}.{data["commit"]}-{TARGET}.tar.gz'
    # Publish a complete directory using rename, without replacing an existing bundle.
    if args.output.exists():
        raise ValueError('Output already exists')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        folder = Path(temporary)
        archive(stage, folder / name, data)
        archive(stage, folder / 'repeat.tar.gz', data)
        if digest(folder / name) != digest(folder / 'repeat.tar.gz'):
            raise ValueError('Nondeterministic packaging')
        (folder / 'repeat.tar.gz').unlink()
        (folder / 'SHA256SUMS').write_text(f'{digest(folder / name)}  {name}\n')
        # Directory reservation prevents overwrite, including concurrent packagers.
        args.output.mkdir()
        for file in sorted(folder.iterdir(), key=lambda p: p.name == 'SHA256SUMS'):
            os.rename(file, args.output / file.name)
    print(args.output / name)


def verify(args):
    if args.archive.is_symlink() or args.archive.stat().st_size > MAX_FILE * 2:
        raise ValueError('Invalid archive')
    expected = f'{digest(args.archive)}  {args.archive.name}\n'
    if args.checksums.read_text() != expected:
        raise ValueError('Archive checksum mismatch')
    # Validate gzip framing/trailer as tar readers may stop before the trailer.
    with gzip.open(args.archive, 'rb') as compressed:
        expanded = 0
        while chunk := compressed.read(1024 * 1024):
            expanded += len(chunk)
            if expanded > MAX_FILE * 2:
                raise ValueError('Oversized expanded archive')
    if args.output.exists():
        raise ValueError('Extraction destination already exists')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
        stage = Path(temporary)
        seen, root, total = set(), None, 0
        with tarfile.open(args.archive, 'r:gz') as tar:
            for member in tar:
                parts = member.name.split('/')
                if root is None:
                    root = parts[0]
                name = '/'.join(parts[1:])
                total += member.size
                if (parts[0] != root or name not in PAYLOAD or member.name != root + '/' + name
                        or name in seen or not member.isfile() or member.issparse()
                        or member.size < 0 or member.size > MAX_FILE or total > MAX_FILE * 2
                        or member.mode != PAYLOAD[name] or member.uid != 0 or member.gid != 0
                        or member.pax_headers):
                    raise ValueError('Unsafe/unexpected archive member')
                seen.add(name)
                path = stage / name
                path.parent.mkdir(exist_ok=True)
                with open(path, 'xb') as destination:
                    shutil.copyfileobj(tar.extractfile(member), destination)
                path.chmod(member.mode)
        if seen != set(PAYLOAD):
            raise ValueError('Incomplete archive')
        data = validate_stage(stage)
        if root != f'epochgrid-{data["version"]}-{TARGET}':
            raise ValueError('Archive root/version mismatch')
        kind = 'local' if data['local'] else 'candidate'
        if args.archive.name != f'epochgrid-{data["version"]}-{kind}.{data["commit"]}-{TARGET}.tar.gz':
            raise ValueError('Archive name/manifest mismatch')
        if args.require_candidate and (data['local'] or data['dirty']):
            raise ValueError('Local build is not a candidate')
        if args.commit and data['commit'] != args.commit:
            raise ValueError('Wrong source revision')
        args.output.mkdir()
        for file in stage.iterdir():
            os.rename(file, args.output / file.name)
    print(json.dumps(dict(archive_sha256=digest(args.archive), commit=data['commit'], local=data['local'])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    builder = commands.add_parser('build')
    builder.add_argument('--work', type=Path, required=True)
    builder.add_argument('--local', action='store_true')
    packer = commands.add_parser('package')
    packer.add_argument('--work', type=Path, required=True)
    packer.add_argument('--output', type=Path, required=True)
    verifier = commands.add_parser('verify')
    verifier.add_argument('--archive', type=Path, required=True)
    verifier.add_argument('--checksums', type=Path, required=True)
    verifier.add_argument('--output', type=Path, required=True)
    verifier.add_argument('--commit')
    verifier.add_argument('--require-candidate', action='store_true')
    args = parser.parse_args()
    for name in ('work', 'output', 'archive', 'checksums'):
        if hasattr(args, name):
            setattr(args, name, getattr(args, name).absolute())
    os.chdir(ROOT)
    globals()[args.command](args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, EOFError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print(f'Artifact failure: {error}', file=sys.stderr)
        sys.exit(1)
