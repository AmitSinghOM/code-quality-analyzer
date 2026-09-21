"""Secret-bearing identifier classification shared by every language.

A leaf module on purpose (imports only ``re``): ``python_security`` needs
``is_secret_name`` and must not import anything under ``languages`` -- that
package's ``__init__`` imports every adapter, and the Python adapter imports
``python_rules`` back while ``python_security`` is still initialising. The
adapters keep importing the name from ``languages._security``, which
re-exports it from here.
"""

from __future__ import annotations

import re

_SEGMENT = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")

_SECRET_SEGMENTS = frozenset(
    {
        "token",
        "tokens",
        "secret",
        "secrets",
        "password",
        "passwd",
        "passphrase",
        "nonce",
        "salt",
        "otp",
        "apikey",
        "csrf",
        "sessionid",
    }
)
_SECRET_PAIRS = frozenset(
    {
        ("api", "key"),
        ("session", "id"),
        ("session", "key"),
        ("auth", "code"),
        ("verification", "code"),
        ("reset", "code"),
    }
)
_QUANTITY_SEGMENTS = frozenset(
    {
        "max",
        "min",
        "num",
        "count",
        "len",
        "length",
        "size",
        "index",
        "idx",
        "per",
        "rate",
        "limit",
        "budget",
        "delay",
        "timeout",
        "ttl",
        "rounds",
        "offset",
        "position",
        "pos",
    }
)


def is_secret_name(name: str) -> bool:
    """Whether ``name`` is an identifier that holds a security-relevant value.

    Identifiers are split into snake/camel segments and matched as WHOLE
    segments (``reset_token``, ``sessionKey``, ``API_KEY``), never as
    substrings: ``max_tokens``, ``footprint`` and ``hotplug_delay`` used to
    fire on ``token``/``otp``. A name that also carries a quantity or position
    word (``max_tokens``, ``token_index``, ``salt_rounds``) is a count, not a
    secret, and stays silent. Kept deliberately short: a broad list is how
    ``random``-for-secrets rules earn their reputation.
    """
    segments = [segment.lower() for segment in _SEGMENT.findall(name)]
    if not segments or _QUANTITY_SEGMENTS.intersection(segments):
        return False
    if _SECRET_SEGMENTS.intersection(segments):
        return True
    return any(pair in _SECRET_PAIRS for pair in zip(segments, segments[1:], strict=False))
