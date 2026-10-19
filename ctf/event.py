"""SOLAR CTF 2026 exact flag-format validation (not submission verification)."""
from __future__ import annotations

import re
from collections.abc import Iterable

SOLARCTF_RE = re.compile(r"SOLARCTF\{[A-Za-z0-9_]+\}")


def solarctf_candidates(values: Iterable[str]) -> list[str]:
    """A format match is NOT proof that the challenge flag was accepted."""
    return sorted({flag for flag in values if SOLARCTF_RE.fullmatch(flag)})
