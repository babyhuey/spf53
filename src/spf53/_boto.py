"""Thread-safe, region-aware boto3 client cache shared by route53/notify/ssm.

functools.cache does not guarantee a wrapped function runs only once under
concurrent calls before the first result is cached (core.py's per-domain
ThreadPoolExecutor can race multiple threads through here on a cold cache),
so this uses explicit double-checked locking instead.
"""

from __future__ import annotations

import threading
from typing import Any

import boto3

_lock = threading.Lock()
_clients: dict[tuple[str, str | None], Any] = {}


def get_client(service: str, region: str | None = None) -> Any:
    key = (service, region)
    client = _clients.get(key)
    if client is None:
        with _lock:
            client = _clients.get(key)
            if client is None:
                client = (
                    boto3.client(service, region_name=region) if region else boto3.client(service)
                )
                _clients[key] = client
    return client
