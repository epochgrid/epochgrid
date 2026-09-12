#!/usr/bin/env python3
"""Bounded local Compose readiness: require NATS INFO, not just an open port."""
import json
import os
import socket
import time
from urllib.parse import urlparse


def wait_for_nats(url, timeout=10):
    address = urlparse(url)
    if address.scheme != 'nats' or not address.hostname:
        raise ValueError('Compose readiness requires a nats:// URL')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            remaining = deadline - time.monotonic()
            with socket.create_connection((address.hostname, address.port or 4222),
                                          timeout=max(0.001, min(0.5, remaining))) as connection:
                data = b''
                while b'\r\n' not in data and len(data) < 65536:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('NATS greeting deadline exceeded')
                    connection.settimeout(min(0.5, remaining))
                    part = connection.recv(min(4096, 65536 - len(data)))
                    if not part:
                        raise ConnectionError('NATS closed before INFO')
                    data += part
                line, separator, _ = data.partition(b'\r\n')
                if separator and line.startswith(b'INFO ') and isinstance(json.loads(line[5:]), dict):
                    return
        except (OSError, ValueError):
            pass  # Retry only within the overall startup deadline.
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise TimeoutError(f'NATS did not send a valid INFO greeting within {timeout}s')


if __name__ == '__main__':
    wait_for_nats(os.environ.get('EPOCHGRID_NATS_URL', 'nats://127.0.0.1:4222'))
