"""
NDB layer ([MS-PST] section 2.2) - the on-disk node/block database.

This module knows about:

* the file header and the three layouts it can announce - the ANSI format
  (``wVer`` 14/15, 32-bit identifiers, 512-byte pages), the classic Unicode
  512-byte-page format (``wVer`` 21/23/37) and the 4 KiB-page format
  introduced with Outlook 2013 OST files (``wVer`` 36);
* the two B-trees (NBT: NID -> node, BBT: BID -> block location);
* blocks and their trailers, including per-block decryption (permute /
  cyclic, or a caller-supplied decryptor for WIP-protected files) and, for
  the 4 KiB format, per-block zlib compression;
* data trees (XBLOCK / XXBLOCK) that spread one logical byte stream over many
  blocks - exposed as *iterators of chunks* so a multi-gigabyte attachment is
  never materialised;
* subnode trees (SLBLOCK / SIBLOCK).

Everything is read with ``os.pread`` at the offsets the B-trees hand out, so
file size is irrelevant to memory use: the only things that scale with the
file are two bounded LRU caches (pages and decoded blocks).
"""

from __future__ import annotations

import os
import struct
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Iterator, List, Optional, Tuple

from .crc import pst_crc32
from .crypt import NDB_CRYPT_CYCLIC, NDB_CRYPT_NONE, NDB_CRYPT_PERMUTE, cyclic_crypt, decode_block, permute_decode
from .errors import BlockNotFound, CorruptFile, KeyRequired, NodeNotFound, NotAnOSTFile, OSTError, UnsupportedFormat, WrongKey

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

MAGIC = b"!BDN"
MAGIC_CLIENT_PST = b"SM"
MAGIC_CLIENT_OST = b"SO"
MAGIC_CLIENT_PAB = b"AB"

NDB_CRYPT_EDPCRYPTED = 0x10  # Windows Information Protection
CRYPT_CUSTOM = -1            # blocks are decoded by a caller-supplied decryptor

PTYPE_BBT = 0x80
PTYPE_NBT = 0x81
PTYPE_FMAP = 0x82
PTYPE_PMAP = 0x83
PTYPE_AMAP = 0x84
PTYPE_FPMAP = 0x85
PTYPE_DL = 0x86

BTYPE_XBLOCK = 0x01  # also XXBLOCK (cLevel 2)
BTYPE_SBLOCK = 0x02  # SLBLOCK (cLevel 0) / SIBLOCK (cLevel 1)

# NID types ([MS-PST] 2.2.2.1)
NID_TYPE_HID = 0x00
NID_TYPE_INTERNAL = 0x01
NID_TYPE_NORMAL_FOLDER = 0x02
NID_TYPE_SEARCH_FOLDER = 0x03
NID_TYPE_NORMAL_MESSAGE = 0x04
NID_TYPE_ATTACHMENT = 0x05
NID_TYPE_SEARCH_UPDATE_QUEUE = 0x06
NID_TYPE_SEARCH_CRITERIA_OBJECT = 0x07
NID_TYPE_ASSOC_MESSAGE = 0x08
NID_TYPE_CONTENTS_TABLE_INDEX = 0x0A
NID_TYPE_RECEIVE_FOLDER_TABLE = 0x0B
NID_TYPE_OUTGOING_QUEUE_TABLE = 0x0C
NID_TYPE_HIERARCHY_TABLE = 0x0D
NID_TYPE_CONTENTS_TABLE = 0x0E
NID_TYPE_ASSOC_CONTENTS_TABLE = 0x0F
NID_TYPE_SEARCH_CONTENTS_TABLE = 0x10
NID_TYPE_ATTACHMENT_TABLE = 0x11
NID_TYPE_RECIPIENT_TABLE = 0x12
NID_TYPE_SEARCH_TABLE_INDEX = 0x13
NID_TYPE_LTP = 0x1F

# Special NIDs ([MS-PST] 2.4.1)
NID_MESSAGE_STORE = 0x21
NID_NAME_TO_ID_MAP = 0x61
NID_NORMAL_FOLDER_TEMPLATE = 0xA1
NID_SEARCH_FOLDER_TEMPLATE = 0xC1
NID_ROOT_FOLDER = 0x122
NID_SEARCH_MANAGEMENT_QUEUE = 0x1E1
NID_ATTACHMENT_TABLE = 0x671
NID_RECIPIENT_TABLE = 0x692

#: Signature of a caller-supplied block decryptor: ``(payload, bid, ib) -> plaintext``.
Decryptor = Callable[[bytes, int, int], bytes]

# bClientSig values a heap node may carry (used to validate decoded blocks)
_CLIENT_SIGS = frozenset((0x6C, 0x7C, 0x8C, 0x9C, 0xA5, 0xAC, 0xB5, 0xBC, 0xCC))


def nid_type(nid: int) -> int:
    return nid & 0x1F


def nid_index(nid: int) -> int:
    return nid >> 5


def make_nid(ntype: int, index: int) -> int:
    return (index << 5) | (ntype & 0x1F)


def bid_is_internal(bid: int) -> bool:
    """Bit 1 of a BID marks internal blocks (XBLOCK/XXBLOCK/SLBLOCK/SIBLOCK)."""
    return bool(bid & 0x2)


# --------------------------------------------------------------------------
# Format descriptors
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Layout:
    """Layout constants that differ between the ANSI, Unicode-512 and 4 KiB page formats."""

    name: str
    wide: bool                 # 64-bit BIDs/IBs (Unicode) or 32-bit (ANSI)
    page_size: int
    bt_entries_size: int       # bytes available for entries in a BTPAGE
    bt_cent_size: int          # 1 (ANSI/Unicode) or 2 (4K) bytes for cEnt/cEntMax
    page_trailer_size: int     # 12 / 16 / 24
    page_crc_len: int          # bytes covered by the page CRC (500 / 496 / 4072)
    block_align: int           # 64 / 64 / 512
    block_footer_size: int     # 12 / 16 / 24
    max_block_size: int        # 8192 / 8192 / 65536
    hid_index_bits: int        # 11 / 11 / 14
    amap_first: int            # 0x4400 / 0x4400 / 0x22000
    amap_interval: int
    amap_granule: int          # bytes per AMap bit: 64 / 64 / 512
    amap_padding: int          # bytes before the bitmap in an AMap page (4 for ANSI)

    # -- derived sizes -----------------------------------------------------

    @property
    def id_size(self) -> int:
        return 8 if self.wide else 4

    @property
    def bt_entry_size(self) -> int:     # BTENTRY: btkey + BREF
        return 24 if self.wide else 12

    @property
    def nbt_entry_size(self) -> int:
        return 32 if self.wide else 16

    @property
    def bbt_entry_size(self) -> int:
        return 24 if self.wide else 12

    @property
    def sblock_header_size(self) -> int:  # bType, cLevel, cEnt (+ dwPadding in Unicode)
        return 8 if self.wide else 4

    @property
    def sl_entry_size(self) -> int:
        return 24 if self.wide else 12

    @property
    def si_entry_size(self) -> int:
        return 16 if self.wide else 8

    @property
    def max_block_payload(self) -> int:
        return self.max_block_size - self.block_footer_size

    @property
    def bt_header_offset(self) -> int:
        return self.bt_entries_size

    @property
    def page_trailer_offset(self) -> int:
        return self.page_size - self.page_trailer_size

    @property
    def hid_index_mask(self) -> int:
        return (1 << self.hid_index_bits) - 1

    @property
    def hid_block_shift(self) -> int:
        return 5 + self.hid_index_bits

    @property
    def key_struct(self) -> struct.Struct:
        return _Q if self.wide else _I

    def hid_parts(self, hid: int) -> Tuple[int, int]:
        """Return (hidIndex, hidBlockIndex) for an HID."""
        return (hid >> 5) & self.hid_index_mask, hid >> self.hid_block_shift

    def make_hid(self, index: int, block: int) -> int:
        return (block << self.hid_block_shift) | (index << 5)

    def block_raw_size(self, cb: int) -> int:
        """On-disk size (payload + padding + footer) of a block with ``cb`` payload bytes."""
        a = self.block_align
        return (cb + self.block_footer_size + a - 1) // a * a

    # -- struct helpers ------------------------------------------------------

    def unpack_page_trailer(self, raw: bytes) -> Tuple[int, int, int, int, int]:
        """Return (ptype, ptypeRepeat, wSig, dwCRC, bid)."""
        to = self.page_trailer_offset
        if self.wide:
            return struct.unpack_from("<BBHIQ", raw, to)
        ptype, rep, sig, bid, crc = struct.unpack_from("<BBHII", raw, to)
        return ptype, rep, sig, crc, bid

    def pack_page_trailer(self, ptype: int, sig: int, crc: int, bid: int) -> bytes:
        if self.page_trailer_size == 24:
            return struct.pack("<BBHIQQ", ptype, ptype, sig, crc, bid, 0)
        if self.wide:
            return struct.pack("<BBHIQ", ptype, ptype, sig, crc, bid)
        return struct.pack("<BBHII", ptype, ptype, sig, bid, crc)

    def unpack_block_footer(self, raw: bytes, off: int) -> Tuple[int, int, int, int, int]:
        """Return (cb, wSig, dwCRC, bid, cbUncompressed-or-0)."""
        if self.block_footer_size == 24:
            cb, sig, crc, bid, _unk, cb_unc, _unk2 = struct.unpack_from("<HHIQHHI", raw, off)
            return cb, sig, crc, bid, cb_unc
        if self.wide:
            cb, sig, crc, bid = struct.unpack_from("<HHIQ", raw, off)
            return cb, sig, crc, bid, 0
        cb, sig, bid, crc = struct.unpack_from("<HHII", raw, off)
        return cb, sig, crc, bid, 0

    def pack_block_footer(self, cb: int, sig: int, crc: int, bid: int, cb_uncompressed: int = 0) -> bytes:
        if self.block_footer_size == 24:
            return struct.pack("<HHIQHHI", cb, sig, crc, bid, 2, cb_uncompressed or cb, 0)
        if self.wide:
            return struct.pack("<HHIQ", cb, sig, crc, bid)
        return struct.pack("<HHII", cb, sig, bid, crc)

    def unpack_bt_entry(self, data: bytes, off: int) -> Tuple[int, int, int]:
        """BTENTRY -> (btkey, bid, ib)."""
        return (_QQQ if self.wide else _III).unpack_from(data, off)

    def unpack_nbt_entry(self, data: bytes, off: int = 0) -> Tuple[int, int, int, int]:
        """NBTENTRY -> (nid, bidData, bidSub, nidParent)."""
        if self.wide:
            n, bd, bs, parent, _pad = _NBT64.unpack_from(data, off)
            return n & 0xFFFFFFFF, bd, bs, parent
        return _NBT32.unpack_from(data, off)

    def unpack_bbt_entry(self, data: bytes, off: int = 0) -> Tuple[int, int, int, int]:
        """BBTENTRY -> (bid, ib, cb, cRef)."""
        if self.wide:
            b, ib, cb, cref, _pad = _BBT64.unpack_from(data, off)
            return b, ib, cb, cref
        return _BBT32.unpack_from(data, off)

    def unpack_xblock_ids(self, blk: bytes, n: int) -> Tuple[int, ...]:
        return struct.unpack_from("<%d%s" % (n, "Q" if self.wide else "I"), blk, 8)

    def unpack_sl_entry(self, blk: bytes, off: int) -> Tuple[int, int, int]:
        if self.wide:
            n, bd, bs = _QQQ.unpack_from(blk, off)
            return n & 0xFFFFFFFF, bd, bs
        return _III.unpack_from(blk, off)

    def unpack_si_entry(self, blk: bytes, off: int) -> Tuple[int, int]:
        if self.wide:
            n, b = _QQ.unpack_from(blk, off)
            return n & 0xFFFFFFFF, b
        return _II.unpack_from(blk, off)


_Q = struct.Struct("<Q")
_I = struct.Struct("<I")
_QQ = struct.Struct("<QQ")
_II = struct.Struct("<II")
_QQQ = struct.Struct("<QQQ")
_III = struct.Struct("<III")
_NBT64 = struct.Struct("<QQQII")   # nid, bidData, bidSub, nidParent, pad
_NBT32 = struct.Struct("<IIII")    # nid, bidData, bidSub, nidParent
_BBT64 = struct.Struct("<QQHHI")   # bid, ib, cb, cRef, pad
_BBT32 = struct.Struct("<IIHH")    # bid, ib, cb, cRef


LAYOUT_ANSI = Layout(
    name="ansi-512",
    wide=False,
    page_size=512,
    bt_entries_size=496,
    bt_cent_size=1,
    page_trailer_size=12,
    page_crc_len=500,
    block_align=64,
    block_footer_size=12,
    max_block_size=8192,
    hid_index_bits=11,
    amap_first=0x4400,
    amap_interval=496 * 8 * 64,
    amap_granule=64,
    amap_padding=4,
)

LAYOUT_UNICODE = Layout(
    name="unicode-512",
    wide=True,
    page_size=512,
    bt_entries_size=488,
    bt_cent_size=1,
    page_trailer_size=16,
    page_crc_len=496,
    block_align=64,
    block_footer_size=16,
    max_block_size=8192,
    hid_index_bits=11,
    amap_first=0x4400,
    amap_interval=496 * 8 * 64,
    amap_granule=64,
    amap_padding=0,
)

LAYOUT_4K = Layout(
    name="unicode-4k",
    wide=True,
    page_size=4096,
    bt_entries_size=4056,
    bt_cent_size=2,
    page_trailer_size=24,
    page_crc_len=4072,
    block_align=512,
    block_footer_size=24,
    max_block_size=65536,
    hid_index_bits=14,
    amap_first=0x22000,
    amap_interval=4072 * 8 * 512,
    amap_granule=512,
    amap_padding=0,
)


def compute_sig(ib: int, bid: int) -> int:
    """[MS-PST] 5.5 ``ComputeSig``: the 16-bit page/block signature."""
    ib ^= bid
    return ((ib >> 16) ^ ib) & 0xFFFF


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------


@dataclass
class Header:
    magic_client: bytes
    w_ver: int
    w_ver_client: int
    platform_create: int
    platform_access: int
    bid_next_p: int
    bid_next_b: int
    dw_unique: int
    rgnid: Tuple[int, ...]
    ib_file_eof: int
    ib_amap_last: int
    cb_amap_free: int
    cb_pmap_free: int
    nbt_bid: int
    nbt_ib: int
    bbt_bid: int
    bbt_ib: int
    f_amap_valid: int
    crypt_method: int
    crc_partial_ok: bool
    crc_full_ok: bool
    layout: Layout

    @property
    def is_ost(self) -> bool:
        return self.magic_client == MAGIC_CLIENT_OST

    @property
    def is_ansi(self) -> bool:
        return not self.layout.wide

    @property
    def is_wip(self) -> bool:
        return self.crypt_method == NDB_CRYPT_EDPCRYPTED

    @property
    def crypt_name(self) -> str:
        return {0: "none", 1: "permute", 2: "cyclic", 0x10: "wip/edp"}.get(self.crypt_method, "0x%02x" % self.crypt_method)


_HDR_HEAD = struct.Struct("<4sI2sHHBBII")        # 0..24


def parse_header(buf: bytes) -> Header:
    if len(buf) < 564:
        raise NotAnOSTFile("file too small to hold a PST/OST header")
    magic, crc_partial, magic_client, w_ver, w_ver_client, plat_c, plat_a, _r1, _r2 = _HDR_HEAD.unpack_from(buf, 0)
    if magic != MAGIC:
        raise NotAnOSTFile("bad magic %r (expected %r)" % (magic, MAGIC))
    if magic_client not in (MAGIC_CLIENT_PST, MAGIC_CLIENT_OST, MAGIC_CLIENT_PAB):
        raise NotAnOSTFile("bad wMagicClient %r" % magic_client)
    crc_partial_ok = pst_crc32(buf[8:8 + 471]) == crc_partial
    if w_ver <= 0x0F:
        # ---- ANSI ([MS-PST] 2.2.2.6, 32-bit variant) ----
        layout = LAYOUT_ANSI
        bid_next_b, bid_next_p, dw_unique = struct.unpack_from("<III", buf, 24)
        rgnid = struct.unpack_from("<32I", buf, 36)
        (_res, ib_eof, ib_amap_last, cb_amap_free, cb_pmap_free,
         nbt_bid, nbt_ib, bbt_bid, bbt_ib, f_amap_valid, _b, _w) = struct.unpack_from("<IIIIIIIIIBBH", buf, 164)
        sentinel = buf[460]
        crypt = buf[461]
        crc_full_ok = True  # ANSI headers only carry dwCRCPartial
    else:
        layout = LAYOUT_4K if w_ver == 0x24 or w_ver >= 0x26 else LAYOUT_UNICODE
        _bid_unused, bid_next_p, dw_unique = struct.unpack_from("<QQI", buf, 24)
        rgnid = struct.unpack_from("<32I", buf, 44)
        (_res, ib_eof, ib_amap_last, cb_amap_free, cb_pmap_free,
         nbt_bid, nbt_ib, bbt_bid, bbt_ib, f_amap_valid, _b, _w) = struct.unpack_from("<IQQQQQQQQBBH", buf, 180)
        sentinel = buf[512]
        crypt = buf[513]
        bid_next_b = struct.unpack_from("<Q", buf, 516)[0]
        crc_full = struct.unpack_from("<I", buf, 524)[0]
        crc_full_ok = pst_crc32(buf[8:524]) == crc_full
    if sentinel != 0x80:
        raise CorruptFile("header sentinel is 0x%02x, expected 0x80" % sentinel)
    if crypt not in (NDB_CRYPT_NONE, NDB_CRYPT_PERMUTE, NDB_CRYPT_CYCLIC, NDB_CRYPT_EDPCRYPTED):
        raise UnsupportedFormat("unknown bCryptMethod 0x%02x" % crypt)
    return Header(
        magic_client=magic_client, w_ver=w_ver, w_ver_client=w_ver_client,
        platform_create=plat_c, platform_access=plat_a,
        bid_next_p=bid_next_p, bid_next_b=bid_next_b, dw_unique=dw_unique, rgnid=rgnid,
        ib_file_eof=ib_eof, ib_amap_last=ib_amap_last, cb_amap_free=cb_amap_free, cb_pmap_free=cb_pmap_free,
        nbt_bid=nbt_bid, nbt_ib=nbt_ib, bbt_bid=bbt_bid, bbt_ib=bbt_ib,
        f_amap_valid=f_amap_valid, crypt_method=crypt,
        crc_partial_ok=crc_partial_ok, crc_full_ok=crc_full_ok, layout=layout,
    )


# --------------------------------------------------------------------------
# Small LRU cache
# --------------------------------------------------------------------------


class _LRU:
    """Byte-budgeted LRU for bytes-like values."""

    __slots__ = ("_d", "budget", "size", "hits", "misses")

    def __init__(self, budget: int):
        self._d: "OrderedDict[int, bytes]" = OrderedDict()
        self.budget = budget
        self.size = 0
        self.hits = 0
        self.misses = 0

    def get(self, key):
        v = self._d.get(key)
        if v is None:
            self.misses += 1
            return None
        self._d.move_to_end(key)
        self.hits += 1
        return v

    def put(self, key, value):
        if key in self._d:
            self.size -= len(self._d[key])
            del self._d[key]
        self._d[key] = value
        self.size += len(value)
        while self.size > self.budget and self._d:
            _, old = self._d.popitem(last=False)
            self.size -= len(old)

    def clear(self):
        self._d.clear()
        self.size = 0


# --------------------------------------------------------------------------
# B-tree entries
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NBTEntry:
    nid: int
    bid_data: int
    bid_sub: int
    nid_parent: int


@dataclass(frozen=True)
class BBTEntry:
    bid: int
    ib: int
    cb: int
    cref: int


class _BTPage:
    __slots__ = ("ib", "level", "n", "cb_ent", "data", "keys")

    def __init__(self, ib, level, n, cb_ent, data):
        self.ib = ib
        self.level = level
        self.n = n
        self.cb_ent = cb_ent
        self.data = data          # bytes of the entries area
        self.keys = None          # lazily built list of entry keys


class BTree:
    """Reader for one of the two header-rooted B-trees (NBT or BBT)."""

    def __init__(self, ndb: "NDB", root_bid: int, root_ib: int, ptype: int):
        self.ndb = ndb
        self.root_bid = root_bid
        self.root_ib = root_ib
        self.ptype = ptype
        self._pages: "OrderedDict[int, _BTPage]" = OrderedDict()
        # Budget in *resident* bytes: a cached page costs its data plus a Python
        # object and a key list (~40 bytes per entry), not just page_size.
        lay = ndb.layout
        per_page = lay.page_size + 64 + 40 * (lay.bt_entries_size // lay.bt_entry_size)
        self._page_budget = max(16, ndb.page_cache_bytes // per_page)

    # -- page access ------------------------------------------------------

    def _page(self, ib: int, expect_bid: int) -> _BTPage:
        p = self._pages.get(ib)
        if p is not None:
            self._pages.move_to_end(ib)
            return p
        lay = self.ndb.layout
        raw = self.ndb.pread(ib, lay.page_size)
        if len(raw) != lay.page_size:
            raise CorruptFile("short read for B-tree page at 0x%x" % ib)
        ho = lay.bt_header_offset
        if lay.bt_cent_size == 1:
            n, nmax, cb_ent, level = raw[ho], raw[ho + 1], raw[ho + 2], raw[ho + 3]
        else:
            n, nmax = struct.unpack_from("<HH", raw, ho)
            cb_ent, level = raw[ho + 4], raw[ho + 5]
        ptype, ptype_rep, wsig, crc, bid = lay.unpack_page_trailer(raw)
        if ptype != self.ptype or ptype_rep != ptype:
            raise CorruptFile("B-tree page at 0x%x has ptype 0x%02x/0x%02x, expected 0x%02x" % (ib, ptype, ptype_rep, self.ptype))
        if self.ndb.verify_sig and wsig != compute_sig(ib, bid):
            raise CorruptFile("B-tree page at 0x%x: bad signature" % ib)
        if expect_bid and bid != expect_bid:
            raise CorruptFile("B-tree page at 0x%x: bid 0x%x does not match parent reference 0x%x" % (ib, bid, expect_bid))
        if self.ndb.verify_crc and pst_crc32(raw[:lay.page_crc_len]) != crc:
            raise CorruptFile("B-tree page at 0x%x: CRC mismatch" % ib)
        if cb_ent == 0 or n * cb_ent > lay.bt_entries_size:
            raise CorruptFile("B-tree page at 0x%x: implausible entry layout (cEnt=%d cbEnt=%d)" % (ib, n, cb_ent))
        p = _BTPage(ib, level, n, cb_ent, raw[: n * cb_ent])
        self._pages[ib] = p
        if len(self._pages) > self._page_budget:
            self._pages.popitem(last=False)
        return p

    def _keys(self, p: _BTPage) -> list:
        if p.keys is None:
            cb = p.cb_ent
            d = p.data
            ks = self.ndb.layout.key_struct
            # Every entry type starts with its key (btkey / nid / bid).
            p.keys = [ks.unpack_from(d, i * cb)[0] for i in range(p.n)]
        return p.keys

    # -- lookup -----------------------------------------------------------

    def _find_leaf_entry(self, key: int) -> Optional[bytes]:
        ib, bid = self.root_ib, self.root_bid
        lay = self.ndb.layout
        for _depth in range(16):
            p = self._page(ib, bid)
            keys = self._keys(p)
            # last entry whose key <= search key
            lo, hi = 0, p.n
            while lo < hi:
                mid = (lo + hi) >> 1
                if keys[mid] <= key:
                    lo = mid + 1
                else:
                    hi = mid
            idx = lo - 1
            if idx < 0:
                return None
            off = idx * p.cb_ent
            if p.level == 0:
                return p.data[off: off + p.cb_ent] if keys[idx] == key else None
            _k, bid, ib = lay.unpack_bt_entry(p.data, off)
        raise CorruptFile("B-tree deeper than 16 levels")

    # -- iteration --------------------------------------------------------

    def iter_leaf_entries(self) -> Iterator[bytes]:
        """Yield every leaf entry's raw bytes in key order, streaming (DFS)."""
        lay = self.ndb.layout
        stack = [(self.root_ib, self.root_bid)]
        while stack:
            ib, bid = stack.pop()
            p = self._page(ib, bid)
            cb = p.cb_ent
            if p.level == 0:
                d = p.data
                for i in range(p.n):
                    yield d[i * cb:(i + 1) * cb]
            else:
                children = []
                for i in range(p.n):
                    _k, cbid, cib = lay.unpack_bt_entry(p.data, i * cb)
                    children.append((cib, cbid))
                stack.extend(reversed(children))

    def stats(self) -> dict:
        """Count pages per level (walks the whole tree - use for diagnostics)."""
        lay = self.ndb.layout
        counts = {}
        stack = [(self.root_ib, self.root_bid)]
        leaves = 0
        while stack:
            ib, bid = stack.pop()
            p = self._page(ib, bid)
            counts[p.level] = counts.get(p.level, 0) + 1
            if p.level == 0:
                leaves += p.n
            else:
                cb = p.cb_ent
                for i in range(p.n):
                    _k, cbid, cib = lay.unpack_bt_entry(p.data, i * cb)
                    stack.append((cib, cbid))
        return {"pages_per_level": counts, "leaf_entries": leaves}


class NodeBTree(BTree):
    def __init__(self, ndb, bid, ib):
        super().__init__(ndb, bid, ib, PTYPE_NBT)

    def lookup(self, nid: int) -> Optional[NBTEntry]:
        raw = self._find_leaf_entry(nid)
        if raw is None:
            return None
        return NBTEntry(*self.ndb.layout.unpack_nbt_entry(raw))

    def __iter__(self) -> Iterator[NBTEntry]:
        lay = self.ndb.layout
        for raw in self.iter_leaf_entries():
            yield NBTEntry(*lay.unpack_nbt_entry(raw))


class BlockBTree(BTree):
    def __init__(self, ndb, bid, ib):
        super().__init__(ndb, bid, ib, PTYPE_BBT)

    def lookup(self, bid: int) -> Optional[BBTEntry]:
        raw = self._find_leaf_entry(bid & ~1)
        if raw is None:
            return None
        return BBTEntry(*self.ndb.layout.unpack_bbt_entry(raw))

    def __iter__(self) -> Iterator[BBTEntry]:
        lay = self.ndb.layout
        for raw in self.iter_leaf_entries():
            yield BBTEntry(*lay.unpack_bbt_entry(raw))


# --------------------------------------------------------------------------
# Subnode trees
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SubnodeEntry:
    nid: int
    bid_data: int
    bid_sub: int


class SubnodeTree:
    """The subnode B-tree hanging off a node's ``bidSub`` (SLBLOCK/SIBLOCK)."""

    __slots__ = ("ndb", "bid_sub", "_leaves", "_index")

    def __init__(self, ndb: "NDB", bid_sub: int):
        self.ndb = ndb
        self.bid_sub = bid_sub
        self._leaves = None   # list of (nid, bid_data, bid_sub) when fully loaded
        self._index = None    # for SIBLOCK: list of (first_nid, bid_of_slblock)

    def _parse_sl(self, blk: bytes) -> List[Tuple[int, int, int]]:
        lay = self.ndb.layout
        btype, level, n = struct.unpack_from("<BBH", blk, 0)
        if btype != BTYPE_SBLOCK or level != 0:
            raise CorruptFile("expected SLBLOCK, got btype=%d level=%d" % (btype, level))
        out = []
        off = lay.sblock_header_size
        for _ in range(n):
            out.append(lay.unpack_sl_entry(blk, off))
            off += lay.sl_entry_size
        return out

    def _load(self):
        if self._leaves is not None or self._index is not None:
            return
        if not self.bid_sub:
            self._leaves = []
            return
        lay = self.ndb.layout
        blk = self.ndb.read_block(self.bid_sub)
        btype, level, n = struct.unpack_from("<BBH", blk, 0)
        if btype != BTYPE_SBLOCK:
            raise CorruptFile("subnode block 0x%x has btype %d" % (self.bid_sub, btype))
        if level == 0:
            self._leaves = self._parse_sl(blk)
        elif level == 1:
            idx = []
            off = lay.sblock_header_size
            for _ in range(n):
                idx.append(lay.unpack_si_entry(blk, off))
                off += lay.si_entry_size
            self._index = idx
        else:
            raise CorruptFile("subnode block 0x%x has unsupported level %d" % (self.bid_sub, level))

    def lookup(self, nid: int) -> Optional[SubnodeEntry]:
        self._load()
        if self._leaves is not None:
            leaves = self._leaves
        else:
            idx = self._index
            lo, hi = 0, len(idx)
            while lo < hi:
                mid = (lo + hi) >> 1
                if idx[mid][0] <= nid:
                    lo = mid + 1
                else:
                    hi = mid
            if lo == 0:
                return None
            leaves = self._parse_sl(self.ndb.read_block(idx[lo - 1][1]))
        lo, hi = 0, len(leaves)
        while lo < hi:
            mid = (lo + hi) >> 1
            if leaves[mid][0] < nid:
                lo = mid + 1
            else:
                hi = mid
        if lo < len(leaves) and leaves[lo][0] == nid:
            n, bd, bs = leaves[lo]
            return SubnodeEntry(n, bd, bs)
        return None

    def __iter__(self) -> Iterator[SubnodeEntry]:
        self._load()
        if self._leaves is not None:
            for n, bd, bs in self._leaves:
                yield SubnodeEntry(n, bd, bs)
        else:
            for _first, bid in self._index:
                for n, bd, bs in self._parse_sl(self.ndb.read_block(bid)):
                    yield SubnodeEntry(n, bd, bs)

    def __len__(self) -> int:
        return sum(1 for _ in self)


# --------------------------------------------------------------------------
# The NDB itself
# --------------------------------------------------------------------------


class NDB:
    """Node database over an open OST/PST file.

    Parameters
    ----------
    path:
        File to open (read-only).
    verify_crc:
        Check page and block CRCs (costs ~1 GB/s of CRC work; off by default).
    verify_sig:
        Check page/block signatures (cheap; on by default).
    page_cache_bytes / block_cache_bytes:
        Budgets for the two LRU caches.  They bound the parser's memory use
        regardless of file size.
    decryptor:
        ``(payload, bid, ib) -> bytes`` applied to every external data block
        instead of the built-in permute/cyclic decoding.  Needed for
        ``bCryptMethod = 0x10`` (Windows Information Protection) files whose
        blocks are real ciphertext; see :mod:`ostparse.decryptors`.
    """

    def __init__(self, path: str, *, verify_crc: bool = False, verify_sig: bool = True,
                 page_cache_bytes: int = 64 << 20, block_cache_bytes: int = 32 << 20,
                 decryptor: Optional[Decryptor] = None):
        self.path = path
        self.bytes_read = 0
        self.blocks_read = 0
        self.fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        self.file_size = os.fstat(self.fd).st_size
        self.verify_crc = verify_crc
        self.verify_sig = verify_sig
        self.page_cache_bytes = page_cache_bytes
        self.header = parse_header(self.pread(0, 1024))
        self.layout = self._confirm_layout(self.header.layout)
        self.header.layout = self.layout
        self.decryptor = decryptor
        self.wip_encoding: Optional[str] = None
        self._blocks = _LRU(block_cache_bytes)
        self.nbt = NodeBTree(self, self.header.nbt_bid, self.header.nbt_ib)
        self.bbt = BlockBTree(self, self.header.bbt_bid, self.header.bbt_ib)
        self.crypt_method = self.header.crypt_method
        if self.crypt_method == NDB_CRYPT_EDPCRYPTED:
            self._resolve_wip()
        elif decryptor is not None:
            self.crypt_method = CRYPT_CUSTOM

    # -- format resolution ------------------------------------------------------

    def _confirm_layout(self, layout: Layout) -> Layout:
        """Check the NBT root page against ``layout``; fall back to the sibling layout if needed.

        ``wVer`` 36 is the 4 KiB-page OST format and 37 is "written by a WIP-capable
        Outlook", so for the wide formats the page geometry is confirmed on disk
        rather than trusted blindly.
        """
        candidates = [layout]
        if layout is LAYOUT_4K:
            candidates.append(LAYOUT_UNICODE)
        elif layout is LAYOUT_UNICODE:
            candidates.append(LAYOUT_4K)
        for cand in candidates:
            raw = self.pread(self.header.nbt_ib, cand.page_size)
            if len(raw) != cand.page_size:
                continue
            ptype, rep, _sig, _crc, bid = cand.unpack_page_trailer(raw)
            if ptype == PTYPE_NBT and rep == PTYPE_NBT and bid == self.header.nbt_bid:
                return cand
        raise CorruptFile("NBT root page at 0x%x does not match any known page layout" % self.header.nbt_ib)

    def _resolve_wip(self):
        """Decide how to read the blocks of a WIP-marked (bCryptMethod 0x10) file.

        [MS-PST] does not publish the EDP block cipher: the key lives in Windows
        Information Protection, not in the file.  Two situations are handled:

        * the WIP layer has already been removed (file read in its WIP context,
          or decrypted on the Windows host) and the blocks are stored plain or
          with the ordinary permute/cyclic encoding - detected by probing the
          message store's heap header and used transparently;
        * the blocks are real ciphertext - a caller-supplied ``decryptor`` is
          required, otherwise :class:`KeyRequired` is raised.
        """
        probe = self._probe_block_encoding()
        if probe is not None:
            # The WIP layer is gone; the blocks carry an ordinary (or no) encoding.
            self.crypt_method, self.wip_encoding = probe
            return
        if self.decryptor is not None:
            self.crypt_method = CRYPT_CUSTOM
            self.wip_encoding = "custom"
            if not self._decryptor_validates():
                raise WrongKey("the supplied key/decryptor does not turn the message store's block into valid heap data")
            return
        raise KeyRequired(
            "bCryptMethod=0x10: the data blocks are protected by Windows Information Protection and "
            "are not readable as plain, permute- or cyclic-encoded data. Supply a block decryptor "
            "(OSTFile(..., decryptor=...) or `ostparse --key KEY --decryptor module:function`), or "
            "decrypt the file on the Windows host that holds the WIP/EFS key first.")

    def _decryptor_validates(self) -> bool:
        """Check that the custom decryptor yields a sane heap header for a well-known node."""
        for nid in (NID_MESSAGE_STORE, NID_ROOT_FOLDER, NID_NAME_TO_ID_MAP):
            e = self.nbt.lookup(nid)
            if e is None or not e.bid_data:
                continue
            try:
                leaves = self.data_block_bids(e.bid_data)
                head = self.read_block(leaves[0])[:12]
            except OSTError:
                return False
            finally:
                self._blocks.clear()
            return len(head) >= 4 and head[2] == 0xEC and head[3] in _CLIENT_SIGS
        return True  # nothing to validate against

    def _probe_block_encoding(self) -> Optional[Tuple[int, str]]:
        """Try to read the message store (or root folder) heap header with each known encoding."""
        for nid in (NID_MESSAGE_STORE, NID_ROOT_FOLDER, NID_NAME_TO_ID_MAP):
            e = self.nbt.lookup(nid)
            if e is None or not e.bid_data:
                continue
            try:
                saved = self.crypt_method
                self.crypt_method = NDB_CRYPT_NONE
                leaves = self.data_block_bids(e.bid_data)
                be = self.block_entry(leaves[0])
                raw = self._read_block_at(be.ib, be.cb, leaves[0], decode=False)
            except OSTError:
                continue
            finally:
                self.crypt_method = saved
                self._blocks.clear()
            if len(raw) < 12:
                continue
            for method, name, fn in ((NDB_CRYPT_NONE, "plain", lambda b: b),
                                     (NDB_CRYPT_PERMUTE, "permute", permute_decode),
                                     (NDB_CRYPT_CYCLIC, "cyclic", lambda b: cyclic_crypt(b, leaves[0]))):
                head = fn(raw[:12])
                if head[2] == 0xEC and head[3] in _CLIENT_SIGS:
                    return method, name
        return None

    # -- lifecycle --------------------------------------------------------

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- raw I/O ----------------------------------------------------------

    def pread(self, offset: int, size: int) -> bytes:
        out = os.pread(self.fd, size, offset)
        if len(out) < size:
            # EOF or short read: retry once to complete (regular files rarely short-read)
            rest = os.pread(self.fd, size - len(out), offset + len(out))
            out += rest
        self.bytes_read += len(out)
        return out

    # -- blocks -----------------------------------------------------------

    def block_entry(self, bid: int) -> BBTEntry:
        e = self.bbt.lookup(bid)
        if e is None:
            raise BlockNotFound("BID 0x%x not in block B-tree" % bid)
        return e

    def read_block(self, bid: int) -> bytes:
        """Return the decoded payload of a single block (data or internal)."""
        cached = self._blocks.get(bid)
        if cached is not None:
            return cached
        e = self.block_entry(bid)
        data = self._read_block_at(e.ib, e.cb, bid)
        self._blocks.put(bid, data)
        return data

    def _read_block_at(self, ib: int, cb: int, bid: int, decode: bool = True) -> bytes:
        lay = self.layout
        raw_size = lay.block_raw_size(cb)
        if raw_size > lay.max_block_size and lay is not LAYOUT_4K:
            raise CorruptFile("block 0x%x claims %d bytes (> max %d)" % (bid, cb, lay.max_block_payload))
        raw = self.pread(ib, raw_size)
        if len(raw) != raw_size:
            raise CorruptFile("short read for block 0x%x at 0x%x" % (bid, ib))
        self.blocks_read += 1
        fo = raw_size - lay.block_footer_size
        f_cb, f_sig, f_crc, f_bid, cb_uncompressed = lay.unpack_block_footer(raw, fo)
        if f_cb != cb:
            raise CorruptFile("block 0x%x at 0x%x: footer cb %d != BBT cb %d" % (bid, ib, f_cb, cb))
        if f_bid != bid:
            raise CorruptFile("block 0x%x at 0x%x: footer bid 0x%x mismatch" % (bid, ib, f_bid))
        if self.verify_sig and f_sig != compute_sig(ib, bid):
            raise CorruptFile("block 0x%x at 0x%x: bad signature" % (bid, ib))
        payload = raw[:cb]
        if self.verify_crc and f_crc and pst_crc32(payload) != f_crc:
            raise CorruptFile("block 0x%x at 0x%x: CRC mismatch" % (bid, ib))
        if cb_uncompressed and cb_uncompressed != cb:
            payload = _inflate(payload, cb_uncompressed, bid)
        if decode and not bid_is_internal(bid):
            if self.crypt_method == CRYPT_CUSTOM:
                payload = self.decryptor(payload, bid, ib)
            elif self.crypt_method != NDB_CRYPT_NONE:
                payload = decode_block(payload, self.crypt_method, bid)
        return payload

    # -- data trees -------------------------------------------------------

    def data_block_bids(self, bid: int) -> List[int]:
        """Return the ordered list of leaf data-block BIDs that make up a data tree."""
        if not bid:
            return []
        if not bid_is_internal(bid):
            return [bid]
        lay = self.layout
        blk = self.read_block(bid)
        btype, level, n, _total = struct.unpack_from("<BBHI", blk, 0)
        if btype != BTYPE_XBLOCK:
            raise CorruptFile("data-tree root 0x%x is not an XBLOCK (btype=%d)" % (bid, btype))
        children = list(lay.unpack_xblock_ids(blk, n))
        if level == 1:
            return children
        if level == 2:
            out: List[int] = []
            for xb in children:
                sub = self.read_block(xb)
                sbt, slv, sn, _st = struct.unpack_from("<BBHI", sub, 0)
                if sbt != BTYPE_XBLOCK or slv != 1:
                    raise CorruptFile("XXBLOCK 0x%x child 0x%x is not an XBLOCK" % (bid, xb))
                out.extend(lay.unpack_xblock_ids(sub, sn))
            return out
        raise CorruptFile("XBLOCK 0x%x has unsupported level %d" % (bid, level))

    def data_size(self, bid: int) -> int:
        """Total logical size of a data tree without reading its leaves."""
        if not bid:
            return 0
        if not bid_is_internal(bid):
            if self.layout.block_footer_size == 24:
                # 4K format: the BBT holds the on-disk (possibly compressed) size; use the decoded length.
                return len(self.read_block(bid))
            return self.block_entry(bid).cb
        blk = self.read_block(bid)
        btype, _level, _n, total = struct.unpack_from("<BBHI", blk, 0)
        if btype != BTYPE_XBLOCK:
            raise CorruptFile("data-tree root 0x%x is not an XBLOCK" % bid)
        return total

    def iter_data(self, bid: int, *, cache: bool = False) -> Iterator[bytes]:
        """Stream the logical contents of a data tree block by block.

        With ``cache=False`` (the default for bulk data) the leaf blocks bypass
        the block cache so that streaming a huge attachment does not evict
        the structures the parser keeps coming back to.
        """
        for leaf in self.data_block_bids(bid):
            if cache:
                yield self.read_block(leaf)
            else:
                c = self._blocks.get(leaf)
                if c is not None:
                    yield c
                else:
                    e = self.block_entry(leaf)
                    yield self._read_block_at(e.ib, e.cb, leaf)

    def read_data(self, bid: int, *, max_bytes: Optional[int] = None) -> bytes:
        """Read a whole data tree into memory (for bounded structures: heaps, tables)."""
        leaves = self.data_block_bids(bid)
        if len(leaves) == 1:
            return self.read_block(leaves[0])
        if max_bytes is not None:
            total = self.data_size(bid)
            if total > max_bytes:
                raise CorruptFile("refusing to load %d-byte data tree into memory (limit %d)" % (total, max_bytes))
        return b"".join(self.read_block(b) for b in leaves)

    # -- nodes ------------------------------------------------------------

    def node(self, nid: int) -> NBTEntry:
        e = self.nbt.lookup(nid)
        if e is None:
            raise NodeNotFound("NID 0x%x not found" % nid)
        return e

    def has_node(self, nid: int) -> bool:
        return self.nbt.lookup(nid) is not None

    def subnodes(self, bid_sub: int) -> SubnodeTree:
        return SubnodeTree(self, bid_sub)

    # -- diagnostics ------------------------------------------------------

    def cache_stats(self) -> dict:
        return {
            "block_cache_bytes": self._blocks.size,
            "block_cache_hits": self._blocks.hits,
            "block_cache_misses": self._blocks.misses,
            "nbt_pages_cached": len(self.nbt._pages),
            "bbt_pages_cached": len(self.bbt._pages),
            "bytes_read": self.bytes_read,
            "blocks_read": self.blocks_read,
        }


def _inflate(payload: bytes, expected: int, bid: int) -> bytes:
    """Decompress a 4K-format block (zlib-wrapped deflate; raw deflate as fallback)."""
    try:
        out = zlib.decompress(payload)
    except zlib.error:
        try:
            out = zlib.decompress(payload, -15)
        except zlib.error as exc:
            raise CorruptFile("block 0x%x: cannot inflate compressed payload (%s)" % (bid, exc))
    if len(out) != expected:
        raise CorruptFile("block 0x%x: inflated to %d bytes, footer says %d" % (bid, len(out), expected))
    return out
