"""
The "weak" CRC-32 used by [MS-PST] (section 5.3, ``ComputeCRC``).

It is the reflected CRC-32 polynomial 0xEDB88320 with an *initial value of 0
and no final XOR*, which differs from the usual zlib/PKZIP CRC only in those
two constants.  Because ``zlib.crc32(data, start)`` internally computes
``~update(~start, data)``, feeding it ``start = 0xFFFFFFFF`` and inverting the
result yields exactly the PST variant - so the hot path stays in C.
"""

from __future__ import annotations

import zlib

__all__ = ["pst_crc32", "pst_crc32_reference"]


def pst_crc32(data: bytes | bytearray | memoryview, seed: int = 0) -> int:
    """Return the [MS-PST] weak CRC-32 of ``data`` (optionally continuing ``seed``)."""
    return (zlib.crc32(data, seed ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


_TABLE = None


def _table():
    global _TABLE
    if _TABLE is None:
        t = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
            t.append(c)
        _TABLE = t
    return _TABLE


def pst_crc32_reference(data: bytes, seed: int = 0) -> int:
    """Byte-at-a-time table implementation, used to cross-check :func:`pst_crc32`."""
    t = _table()
    crc = seed & 0xFFFFFFFF
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF
