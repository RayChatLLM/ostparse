"""
MAPI property types and the property tags the exporter cares about.

Only a curated subset of tags is named here; unknown tags are still parsed
and surfaced by their numeric id.
"""

from __future__ import annotations

import datetime as _dt
import struct
from typing import Any, Callable, Dict, Optional

# -- Property types ([MS-OXCDATA] 2.11.1) ------------------------------------
PT_UNSPECIFIED = 0x0000
PT_NULL = 0x0001
PT_I2 = 0x0002
PT_LONG = 0x0003
PT_R4 = 0x0004
PT_DOUBLE = 0x0005
PT_CURRENCY = 0x0006
PT_APPTIME = 0x0007
PT_ERROR = 0x000A
PT_BOOLEAN = 0x000B
PT_OBJECT = 0x000D
PT_I8 = 0x0014
PT_STRING8 = 0x001E
PT_UNICODE = 0x001F
PT_SYSTIME = 0x0040
PT_CLSID = 0x0048
PT_SVREID = 0x00FB
PT_SRESTRICT = 0x00FD
PT_ACTIONS = 0x00FE
PT_BINARY = 0x0102
PT_MV_FLAG = 0x1000
PT_MV_I2 = 0x1002
PT_MV_LONG = 0x1003
PT_MV_R4 = 0x1004
PT_MV_DOUBLE = 0x1005
PT_MV_CURRENCY = 0x1006
PT_MV_APPTIME = 0x1007
PT_MV_I8 = 0x1014
PT_MV_STRING8 = 0x101E
PT_MV_UNICODE = 0x101F
PT_MV_SYSTIME = 0x1040
PT_MV_CLSID = 0x1048
PT_MV_BINARY = 0x1102

# Types whose value lives inline in the 4-byte dwValueHnid of a PC entry.
INLINE_TYPES = {PT_I2, PT_LONG, PT_R4, PT_ERROR, PT_BOOLEAN, PT_NULL, PT_UNSPECIFIED}
# Fixed-size types that are > 4 bytes and so are stored in the heap (HID).
FIXED_SIZE = {PT_I8: 8, PT_DOUBLE: 8, PT_CURRENCY: 8, PT_APPTIME: 8, PT_SYSTIME: 8, PT_CLSID: 16}
# Column width in a TC row for each type.
TC_CELL_SIZE = {PT_I2: 2, PT_BOOLEAN: 1, PT_LONG: 4, PT_R4: 4, PT_ERROR: 4,
                PT_I8: 8, PT_DOUBLE: 8, PT_CURRENCY: 8, PT_APPTIME: 8, PT_SYSTIME: 8}

# -- Property ids ----------------------------------------------------------
PR_MESSAGE_CLASS = 0x001A
PR_SUBJECT = 0x0037
PR_CLIENT_SUBMIT_TIME = 0x0039
PR_SENT_REPRESENTING_NAME = 0x0042
PR_SENT_REPRESENTING_EMAIL_ADDRESS = 0x0065
PR_CONVERSATION_TOPIC = 0x0070
PR_TRANSPORT_MESSAGE_HEADERS = 0x007D
PR_SENDER_NAME = 0x0C1A
PR_SENDER_ADDRTYPE = 0x0C1E
PR_SENDER_EMAIL_ADDRESS = 0x0C1F
PR_RECIPIENT_TYPE = 0x0C15
PR_DISPLAY_BCC = 0x0E02
PR_DISPLAY_CC = 0x0E03
PR_DISPLAY_TO = 0x0E04
PR_MESSAGE_DELIVERY_TIME = 0x0E06
PR_MESSAGE_FLAGS = 0x0E07
PR_MESSAGE_SIZE = 0x0E08
PR_HASATTACH = 0x0E1B
PR_NORMALIZED_SUBJECT = 0x0E1D
PR_ATTACH_SIZE = 0x0E20
PR_ATTACH_NUM = 0x0E21
PR_BODY = 0x1000
PR_RTF_COMPRESSED = 0x1009
PR_HTML = 0x1013
PR_INTERNET_MESSAGE_ID = 0x1035
PR_INTERNET_REFERENCES = 0x1039
PR_IN_REPLY_TO_ID = 0x1042
PR_DISPLAY_NAME = 0x3001
PR_ADDRTYPE = 0x3002
PR_EMAIL_ADDRESS = 0x3003
PR_CREATION_TIME = 0x3007
PR_LAST_MODIFICATION_TIME = 0x3008
PR_CONTENT_COUNT = 0x3602
PR_CONTENT_UNREAD = 0x3603
PR_SUBFOLDERS = 0x360A
PR_CONTAINER_CLASS = 0x3613
PR_ASSOC_CONTENT_COUNT = 0x3617
PR_ATTACH_DATA_BIN = 0x3701  # PtypBinary or PtypObject
PR_ATTACH_EXTENSION = 0x3703
PR_ATTACH_FILENAME = 0x3704
PR_ATTACH_METHOD = 0x3705
PR_ATTACH_LONG_FILENAME = 0x3707
PR_ATTACH_RENDERING_POSITION = 0x370B
PR_ATTACH_MIME_TAG = 0x370E
PR_ATTACH_CONTENT_ID = 0x3712
PR_ATTACH_FLAGS = 0x3714
PR_SMTP_ADDRESS = 0x39FE
PR_INTERNET_CPID = 0x3FDE
PR_MESSAGE_CODEPAGE = 0x3FFD
PR_RECIPIENT_DISPLAY_NAME = 0x5FF6
PR_LTP_ROW_ID = 0x67F2
PR_LTP_ROW_VER = 0x67F3
PR_PST_PASSWORD = 0x67FF
PR_IPM_SUBTREE_ENTRYID = 0x35E0
PR_IPM_WASTEBASKET_ENTRYID = 0x35E3
PR_FINDER_ENTRYID = 0x35E7
PR_RECORD_KEY = 0x0FF9
PR_ENTRYID = 0x0FFF
PR_SEARCH_KEY = 0x300B

ATTACH_BY_VALUE = 1
ATTACH_BY_REFERENCE = 2
ATTACH_BY_REF_RESOLVE = 3
ATTACH_BY_REF_ONLY = 4
ATTACH_EMBEDDED_MSG = 5
ATTACH_OLE = 6

MAPI_ORIG = 0
MAPI_TO = 1
MAPI_CC = 2
MAPI_BCC = 3

PROP_NAMES: Dict[int, str] = {
    v: k for k, v in globals().items() if k.startswith("PR_") and isinstance(v, int)
}

_EPOCH_DELTA = 116444736000000000  # 100ns ticks between 1601-01-01 and 1970-01-01
_FILETIME_MAX_REASONABLE = 0x7FFFFFFFFFFFFFFF


def filetime_to_datetime(ft: int) -> Optional[_dt.datetime]:
    """Convert a Windows FILETIME to an aware UTC datetime (None for 0)."""
    if ft == 0:
        return None
    try:
        us = (ft - _EPOCH_DELTA) // 10
        return _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(microseconds=us)
    except (OverflowError, ValueError):
        return None


def datetime_to_filetime(dt: _dt.datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    delta = dt - _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
    return int(delta.total_seconds() * 10_000_000) + _EPOCH_DELTA


def decode_unicode(b: bytes) -> str:
    s = b.decode("utf-16-le", errors="replace")
    return s.rstrip("\x00")


def decode_string8(b: bytes, codepage: Optional[int] = None) -> str:
    """Decode a PtypString8 value; the default code page is Windows-1252 (Outlook's ANSI default)."""
    enc = "cp%d" % codepage if codepage else "cp1252"
    try:
        s = b.decode(enc, errors="replace")
    except LookupError:
        s = b.decode("cp1252", errors="replace")
    return s.rstrip("\x00")


def _mv_fixed(fmt: str, size: int) -> Callable[[bytes], list]:
    def f(b: bytes) -> list:
        n = len(b) // size
        return list(struct.unpack_from("<%d%s" % (n, fmt), b, 0))
    return f


def _mv_var(decoder: Callable[[bytes], Any]) -> Callable[[bytes], list]:
    def f(b: bytes) -> list:
        if len(b) < 4:
            return []
        n = struct.unpack_from("<I", b, 0)[0]
        if 4 + 4 * n > len(b):
            return []
        offs = list(struct.unpack_from("<%dI" % n, b, 4)) + [len(b)]
        return [decoder(b[offs[i]: offs[i + 1]]) for i in range(n)]
    return f


def decode_value(ptype: int, raw: bytes, codepage: Optional[int] = None) -> Any:
    """Decode the bytes of a non-inline property value."""
    if ptype == PT_UNICODE:
        return decode_unicode(raw)
    if ptype == PT_STRING8:
        return decode_string8(raw, codepage)
    if ptype == PT_BINARY:
        return raw
    if ptype == PT_SYSTIME:
        return filetime_to_datetime(struct.unpack_from("<Q", raw, 0)[0]) if len(raw) >= 8 else None
    if ptype == PT_I8:
        return struct.unpack_from("<q", raw, 0)[0] if len(raw) >= 8 else None
    if ptype in (PT_DOUBLE, PT_APPTIME):
        return struct.unpack_from("<d", raw, 0)[0] if len(raw) >= 8 else None
    if ptype == PT_CURRENCY:
        return struct.unpack_from("<q", raw, 0)[0] / 10000.0 if len(raw) >= 8 else None
    if ptype == PT_CLSID:
        return raw[:16]
    if ptype == PT_OBJECT:
        return raw  # (nid, ulSize) handled by the caller
    if ptype == PT_MV_UNICODE:
        return _mv_var(decode_unicode)(raw)
    if ptype == PT_MV_STRING8:
        return _mv_var(lambda b: decode_string8(b, codepage))(raw)
    if ptype == PT_MV_BINARY:
        return _mv_var(bytes)(raw)
    if ptype == PT_MV_LONG:
        return _mv_fixed("i", 4)(raw)
    if ptype == PT_MV_I2:
        return _mv_fixed("h", 2)(raw)
    if ptype == PT_MV_I8:
        return _mv_fixed("q", 8)(raw)
    if ptype == PT_MV_R4:
        return _mv_fixed("f", 4)(raw)
    if ptype in (PT_MV_DOUBLE, PT_MV_APPTIME):
        return _mv_fixed("d", 8)(raw)
    if ptype == PT_MV_SYSTIME:
        return [filetime_to_datetime(x) for x in _mv_fixed("Q", 8)(raw)]
    if ptype == PT_MV_CLSID:
        return [raw[i:i + 16] for i in range(0, len(raw) - 15, 16)]
    return raw


def decode_inline(ptype: int, dword: int) -> Any:
    """Decode a property whose value is held in the 4-byte dwValueHnid itself."""
    if ptype == PT_LONG:
        return dword - (1 << 32) if dword & 0x80000000 else dword
    if ptype == PT_BOOLEAN:
        return bool(dword & 0xFF)
    if ptype == PT_I2:
        v = dword & 0xFFFF
        return v - (1 << 16) if v & 0x8000 else v
    if ptype == PT_R4:
        return struct.unpack("<f", struct.pack("<I", dword))[0]
    if ptype == PT_ERROR:
        return dword
    return None


def prop_name(propid: int) -> str:
    return PROP_NAMES.get(propid, "0x%04X" % propid)
