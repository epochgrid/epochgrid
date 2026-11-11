#!/usr/bin/env python3
"""Fixture process adapter. Copied under each binary name; never shipped in images.

Only the orchestration fixture has Docker access. Application containers receive
their own home, explicit bus/CA, public bindings and dedicated IPC directory.
"""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

CONFIG = Path('/etc/epochgrid-image-fixture.json')
DOCKER = '/opt/docker'
CLI = [DOCKER, '--config', '/opt/docker-config']


def call(*args, check=True):
    return subprocess.run([*CLI, *map(str, args)], check=check, capture_output=True, timeout=15)


def option(arguments, key):
    if key not in arguments:
        return None
    index = arguments.index(key)
    if index + 1 >= len(arguments):
        raise ValueError('Missing fixture command option')
    return Path(arguments[index + 1])


def translated(path, config):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to('/tmp') or path == Path('/tmp'):
        raise ValueError('Application mount escapes disposable fixture')
    return str(Path(config['scratch']) / path.relative_to('/tmp'))


def mounts(arguments, env, config, uid):
    home = option(arguments, '--home')
    if home is None:
        if arguments in (['--help'], ['--version']):
            return []
        raise ValueError('Image fixture requires an explicit home')
    translated(home, config)
    if not home.exists():
        home.mkdir(mode=0o700, parents=True)
    selected = {}

    def add(path, writable=False):
        path = Path(path)
        if path.is_symlink() or path.resolve() != path:
            raise ValueError('Symlink fixture mount refused')
        translated(path, config)
        selected[str(path)] = writable

    # Negative audit probes must not expose another account's home even when
    # the privileged fixture orchestrator could ask Docker to mount it.
    if home.stat().st_uid == uid:
        add(home, True)
        for filename in ('backend-roles.json', 'worker.json'):
            binding = home / filename
            if binding.exists():
                data = json.loads(binding.read_text())
                data = data.get('bindings', data)
                ipc = Path(data['socket']).parent
                if ipc.name != 'ipc' or ipc.stat().st_uid != data['authority_uid']:
                    raise ValueError('Unexpected IPC directory or owner')
                add(ipc, uid == data['authority_uid'])
        bindings = option(arguments, '--bindings')
        if bindings is not None:
            add(bindings)
        destination = option(arguments, '--output')
        if destination is not None and not destination.is_relative_to(home):
            if destination.parent.name not in ('audit-output', 'recovery-output') or destination.parent.stat().st_uid != uid:
                raise ValueError('Output must use a dedicated fixture export directory')
            add(destination.parent, True)
        for flag in ('--input', '--secret-file'):
            path = option(arguments, flag)
            if path is not None and not path.is_relative_to(home):
                if 'export' in arguments and flag == '--secret-file':
                    if destination is None or path.parent != destination.parent:
                        raise ValueError('Recovery outputs require the same dedicated directory')
                elif path.is_file() and path.stat().st_uid == uid:
                    add(path)
                else:
                    raise ValueError('Input must be a private fixture file')
    ca = env.get('EPOCHGRID_TLS_CA_PATH')
    if ca and Path(ca).is_file():
        add(ca)
    bus = env.get('DBUS_SESSION_BUS_ADDRESS', '')
    match = re.fullmatch(r'unix:path=([^,]+)(?:,guid=[0-9a-f]+)?', bus)
    if match and Path(match[1]).exists():
        add(match[1])
    result = []
    for destination, writable in selected.items():
        result += ['--mount', f'type=bind,src={translated(destination, config)},dst={destination}'
                   + ('' if writable else ',readonly')]
    return result


def run(arguments, config):
    name = config['prefix'] + '-' + str(os.getpid())
    executable = Path(sys.argv[0]).name
    if executable not in ('epochgrid', 'epochgrid-service'):
        raise ValueError('Adapter must be selected by explicit binary name')
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise ValueError('Application fixture must not run as root')
    env = {key: value for key, value in os.environ.items() if key in {
        'DBUS_SESSION_BUS_ADDRESS', 'EPOCHGRID_PROFILE', 'EPOCHGRID_TLS_CA_PATH',
        'EPOCHGRID_TLS_FIRST', 'EPOCHGRID_TLS_MIN_VERSION', 'EPOCHGRID_NATS_URL',
        'TERM', 'COLORTERM', 'NO_COLOR', 'RUST_LOG'}}
    command = ['create', '--name', name, '--label', 'epochgrid.image-fixture=' + config['prefix'],
               '--network', 'container:' + config['host'], '--user', f'{uid}:{gid}',
               '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m', '--pids-limit', '128',
               '--memory', '512m', '--interactive', '--entrypoint', '/usr/local/bin/' + executable]
    if os.isatty(0):
        command.append('--tty')
    command += mounts(arguments, env, config, uid)
    for key, value in env.items():
        command += ['--env', key + '=' + value]
    command += [config['image'], *arguments]
    pending = []
    created = False

    def forward(signum, _):
        pending.append(signum)
        if created:
            if signum == signal.SIGTERM:
                # Fixtures use terminate() for ordinary shutdown. PID 1 ignores
                # unhandled SIGTERM, so use Docker's tested image stop contract
                # (SIGINT) instead of leaving a live container behind the proxy.
                call('stop', '--time', '3', name, check=False)
            else:
                call('kill', '--signal', str(signum), name, check=False)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, forward)
    try:
        call(*command)
        created = True
        if pending:
            return 128 + pending[-1]
        attached = subprocess.Popen([*CLI, 'start', '--attach', '--interactive', name])
        attached.wait()
        inspected = json.loads(call('inspect', name).stdout)[0]
        if inspected['State']['OOMKilled']:
            raise RuntimeError('Application container exceeded memory limit')
        return inspected['State']['ExitCode']
    finally:
        if created:
            call('rm', '--force', name)


def main():
    config = json.loads(CONFIG.read_text())
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', config['image']):
        raise ValueError('Fixture requires an exact image config ID')
    if len(sys.argv) == 3 and sys.argv[1] in ('--fixture-kill', '--fixture-rss'):
        pid = int(sys.argv[2])
        if pid <= 1:
            raise ValueError('Invalid fixture PID')
        name = config['prefix'] + '-' + str(pid)
        if sys.argv[1] == '--fixture-kill':
            call('kill', '--signal', 'KILL', name, check=False)
            return 0
        result = call('exec', name, '/bin/cat', '/proc/1/status')
        sys.stdout.buffer.write(result.stdout)
        return 0
    return run(sys.argv[1:], config)


if __name__ == '__main__':
    status = main()
    if status in (128 + signal.SIGKILL, 128 + signal.SIGTERM, 128 + signal.SIGINT, 128 + signal.SIGHUP):
        signum = status - 128
        if signum != signal.SIGKILL:
            signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
    sys.exit(status)
