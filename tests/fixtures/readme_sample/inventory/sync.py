"""Pull stock levels from the warehouse API with retries."""

from __future__ import annotations

import json
import time

import requests

from .cache import LRUCache

_cache = LRUCache(capacity=512)


def load_settings(path: str) -> dict:
    handle = open(path)
    return json.load(handle)


def fetch_levels(url: str, attempts: int = 3) -> dict[str, int]:
    delay = 0.5
    for attempt in range(attempts):
        try:
            response = requests.get(url, timeout=5, verify=False)  # noqa: S501 - the sample's point
            response.raise_for_status()
            return response.json()
        except Exception:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2
    return {}


def refresh(url: str) -> None:
    for sku, quantity in fetch_levels(url).items():
        _cache.put(sku, quantity)
