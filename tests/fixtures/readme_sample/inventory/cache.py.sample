"""Bounded in-memory cache for stock levels."""

from __future__ import annotations

import heapq
from collections import OrderedDict


class LRUCache:
    """Least-recently-used cache with a fixed capacity."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._items: OrderedDict[str, int] = OrderedDict()

    def get(self, sku: str) -> int | None:
        if sku not in self._items:
            return None
        self._items.move_to_end(sku)
        return self._items[sku]

    def put(self, sku: str, quantity: int) -> None:
        self._items[sku] = quantity
        self._items.move_to_end(sku)
        if len(self._items) > self.capacity:
            self._items.popitem(last=False)


def lowest_stock(levels: dict[str, int], count: int) -> list[str]:
    """The ``count`` SKUs closest to running out."""
    return [sku for _, sku in heapq.nsmallest(count, ((q, s) for s, q in levels.items()))]
