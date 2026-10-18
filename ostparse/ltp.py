"""
LTP layer ([MS-PST] section 2.3): heaps, B-trees-on-heap, property contexts
and table contexts.

* :class:`HeapNode` - HN: a node's data tree viewed as numbered heap blocks,
  each with an allocation map; items are addressed by HID.
* :class:`BTH` - BTree-on-Heap.
* :class:`PropertyContext` - PC (bClientSig 0xBC): propid -> value.
* :class:`TableContext` - TC (bClientSig 0x7C): a row matrix plus a row index.

Large values (anything that lives in a subnode rather than the heap) can be
streamed with :meth:`PropertyContext.stream` so attachments of any size are
copied out in block-sized chunks.
"""

from __future__ import annotations

import struct
import sys
from array import array
from collections import OrderedDict
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import props as P
from .errors import CorruptFile, NodeNotFound
from .ndb import NDB, NID_TYPE_HID, SubnodeTree

HN_SIG = 0xEC
CLIENT_SIG_TC = 0x7C
CLIENT_SIG_BTH = 0xB5
CLIENT_SIG_PC = 0xBC

# Anything bigger than this is not loaded by PropertyContext.get(); use stream().
DEFAULT_MAX_VALUE_BYTES = 256 << 20
# Parsed allocation maps kept per heap (the blocks themselves live in the NDB block cache).
_PAGEMAP_CACHE = 1024


# --------------------------------------------------------------------------
# Heap-on-Node
# --------------------------------------------------------------------------


class HeapNode:
    """HN reader over a data tree (``bid_data``) of a node."""

    __slots__ = ("ndb", "bid_data", "_bids", "client_sig", "user_root", "_pagemaps")

    def __init__(self, ndb: NDB, bid_data: int):
        self.ndb = ndb
        self.bid_data = bid_data
        self._bids = ndb.data_block_bids(bid_data)
        if not self._bids:
            raise CorruptFile("heap node has no data")
        first = ndb.read_block(self._bids[0])
        if len(first) < 12:
            raise CorruptFile("heap node first block too small (%d bytes)" % len(first))
        ib_hnpm, sig, client_sig, user_root = struct.unpack_from("<HBBI", first, 0)
        if sig != HN_SIG:
            raise CorruptFile("heap node signature is 0x%02x, expected 0xEC (bid 0x%x)" % (sig, bid_data))
        self.client_sig = client_sig
        self.user_root = user_root
        self._pagemaps: "OrderedDict[int, array]" = OrderedDict()

    @property
    def layout(self):
        return self.ndb.layout

    def block_count(self) -> int:
        return len(self._bids)

    def _block(self, index: int) -> Tuple[bytes, "array"]:
        """Return (block bytes, allocation offsets) for heap block ``index``.

        Only the (compact) offset array is cached here; the block bytes come
        from the NDB's byte-budgeted block cache, so a heap with thousands of
        blocks never pins more than that budget in memory.
        """
        if index >= len(self._bids):
            raise CorruptFile("heap block index %d out of range (%d blocks)" % (index, len(self._bids)))
        blk = self.ndb.read_block(self._bids[index])
        offs = self._pagemaps.get(index)
        if offs is not None:
            self._pagemaps.move_to_end(index)
            return blk, offs
        ib_hnpm = struct.unpack_from("<H", blk, 0)[0]
        if ib_hnpm + 4 > len(blk):
            raise CorruptFile("heap block %d: ibHnpm 0x%x beyond block end" % (index, ib_hnpm))
        c_alloc, _c_free = struct.unpack_from("<HH", blk, ib_hnpm)
        if ib_hnpm + 4 + 2 * (c_alloc + 1) > len(blk):
            raise CorruptFile("heap block %d: HNPAGEMAP overruns block" % index)
        offs = array("H")
        offs.frombytes(blk[ib_hnpm + 4: ib_hnpm + 4 + 2 * (c_alloc + 1)])
        if sys.byteorder != "little":
            offs.byteswap()
        self._pagemaps[index] = offs
        if len(self._pagemaps) > _PAGEMAP_CACHE:
            self._pagemaps.popitem(last=False)
        return blk, offs

    def get(self, hid: int) -> bytes:
        """Return the bytes of heap item ``hid`` (an HID; hidType must be 0)."""
        if hid == 0:
            return b""
        if hid & 0x1F != NID_TYPE_HID:
            raise CorruptFile("0x%08x is not an HID" % hid)
        idx, blk_idx = self.layout.hid_parts(hid)
        if idx == 0:
            raise CorruptFile("HID 0x%08x has index 0" % hid)
        blk, offs = self._block(blk_idx)
        if idx >= len(offs):
            raise CorruptFile("HID 0x%08x: index %d out of range (%d allocations)" % (hid, idx, len(offs) - 1))
        start, end = offs[idx - 1], offs[idx]
        if start > end or end > len(blk):
            raise CorruptFile("HID 0x%08x: bad allocation bounds %d..%d" % (hid, start, end))
        return blk[start:end]


# --------------------------------------------------------------------------
# BTree-on-Heap
# --------------------------------------------------------------------------


class BTH:
    """BTree-on-Heap ([MS-PST] 2.3.2)."""

    __slots__ = ("heap", "cb_key", "cb_ent", "levels", "hid_root")

    def __init__(self, heap: HeapNode, hid_header: int):
        self.heap = heap
        hdr = heap.get(hid_header)
        if len(hdr) < 8:
            raise CorruptFile("BTH header too short")
        btype, cb_key, cb_ent, levels, hid_root = struct.unpack_from("<BBBBI", hdr, 0)
        if btype != CLIENT_SIG_BTH:
            raise CorruptFile("BTH header bType is 0x%02x, expected 0xB5" % btype)
        if cb_key not in (2, 4, 8, 16):
            raise CorruptFile("BTH cbKey %d invalid" % cb_key)
        self.cb_key = cb_key
        self.cb_ent = cb_ent
        self.levels = levels
        self.hid_root = hid_root

    def iter_items(self) -> Iterator[Tuple[bytes, bytes]]:
        """Yield (key_bytes, data_bytes) for every leaf record, in key order."""
        if not self.hid_root:
            return
        yield from self._walk(self.hid_root, self.levels)

    def _walk(self, hid: int, level: int):
        data = self.heap.get(hid)
        ck = self.cb_key
        if level == 0:
            rec = ck + self.cb_ent
            for off in range(0, len(data) - rec + 1, rec):
                yield data[off:off + ck], data[off + ck:off + rec]
        else:
            rec = ck + 4
            for off in range(0, len(data) - rec + 1, rec):
                child = struct.unpack_from("<I", data, off + ck)[0]
                yield from self._walk(child, level - 1)

    def count(self) -> int:
        return sum(1 for _ in self.iter_items())

    def lookup(self, key: int) -> Optional[bytes]:
        """Return the data bytes for integer ``key`` or None."""
        if not self.hid_root:
            return None
        ck = self.cb_key
        hid = self.hid_root
        level = self.levels
        while True:
            data = self.heap.get(hid)
            if level == 0:
                rec = ck + self.cb_ent
                n = len(data) // rec
                lo, hi = 0, n
                while lo < hi:
                    mid = (lo + hi) >> 1
                    k = int.from_bytes(data[mid * rec: mid * rec + ck], "little")
                    if k < key:
                        lo = mid + 1
                    elif k > key:
                        hi = mid
                    else:
                        return data[mid * rec + ck: (mid + 1) * rec]
                return None
            rec = ck + 4
            n = len(data) // rec
            lo, hi = 0, n
            while lo < hi:
                mid = (lo + hi) >> 1
                k = int.from_bytes(data[mid * rec: mid * rec + ck], "little")
                if k <= key:
                    lo = mid + 1
                else:
                    hi = mid
            if lo == 0:
                return None
            hid = struct.unpack_from("<I", data, (lo - 1) * rec + ck)[0]
            level -= 1


# --------------------------------------------------------------------------
# Shared HNID resolution
# --------------------------------------------------------------------------


class _Context:
    """Common base for PC and TC: a heap plus the node's subnode tree."""

    __slots__ = ("ndb", "heap", "subnodes", "bid_data", "bid_sub")

    def __init__(self, ndb: NDB, bid_data: int, bid_sub: int):
        self.ndb = ndb
        self.bid_data = bid_data
        self.bid_sub = bid_sub
        self.heap = HeapNode(ndb, bid_data)
        self.subnodes = SubnodeTree(ndb, bid_sub)

    def _subnode_bid(self, nid: int) -> int:
        e = self.subnodes.lookup(nid)
        if e is None:
            raise NodeNotFound("subnode NID 0x%x not found" % nid)
        return e.bid_data

    def hnid_size(self, hnid: int) -> int:
        if hnid == 0:
            return 0
        if hnid & 0x1F == NID_TYPE_HID:
            return len(self.heap.get(hnid))
        return self.ndb.data_size(self._subnode_bid(hnid))

    def hnid_bytes(self, hnid: int, max_bytes: Optional[int] = DEFAULT_MAX_VALUE_BYTES) -> bytes:
        if hnid == 0:
            return b""
        if hnid & 0x1F == NID_TYPE_HID:
            return self.heap.get(hnid)
        return self.ndb.read_data(self._subnode_bid(hnid), max_bytes=max_bytes)

    def hnid_stream(self, hnid: int) -> Iterator[bytes]:
        if hnid == 0:
            return iter(())
        if hnid & 0x1F == NID_TYPE_HID:
            return iter((self.heap.get(hnid),))
        return self.ndb.iter_data(self._subnode_bid(hnid))


# --------------------------------------------------------------------------
# Property Context
# --------------------------------------------------------------------------


class PropertyContext(_Context):
    """PC ([MS-PST] 2.3.3): a BTH of (propid -> (ptype, hnid)) records."""

    __slots__ = ("bth", "_entries", "codepage")

    def __init__(self, ndb: NDB, bid_data: int, bid_sub: int):
        super().__init__(ndb, bid_data, bid_sub)
        if self.heap.client_sig != CLIENT_SIG_PC:
            raise CorruptFile("node is not a Property Context (bClientSig 0x%02x)" % self.heap.client_sig)
        self.bth = BTH(self.heap, self.heap.user_root)
        if self.bth.cb_key != 2 or self.bth.cb_ent != 6:
            raise CorruptFile("PC BTH has cbKey=%d cbEnt=%d" % (self.bth.cb_key, self.bth.cb_ent))
        self._entries: Optional[Dict[int, Tuple[int, int]]] = None
        self.codepage: Optional[int] = None

    def entries(self) -> Dict[int, Tuple[int, int]]:
        """Mapping propid -> (ptype, dwValueHnid)."""
        if self._entries is None:
            d = {}
            for key, val in self.bth.iter_items():
                propid = int.from_bytes(key, "little")
                ptype, hnid = struct.unpack("<HI", val)
                d[propid] = (ptype, hnid)
            self._entries = d
            cp = d.get(P.PR_MESSAGE_CODEPAGE) or d.get(P.PR_INTERNET_CPID)
            if cp and cp[0] == P.PT_LONG:
                self.codepage = cp[1]
        return self._entries

    def __contains__(self, propid: int) -> bool:
        return propid in self.entries()

    def ptype(self, propid: int) -> Optional[int]:
        e = self.entries().get(propid)
        return e[0] if e else None

    def get(self, propid: int, default: Any = None, *, max_bytes: Optional[int] = DEFAULT_MAX_VALUE_BYTES) -> Any:
        """Return the decoded value of ``propid`` (or ``default`` if absent)."""
        e = self.entries().get(propid)
        if e is None:
            return default
        ptype, hnid = e
        if ptype in P.INLINE_TYPES:
            return P.decode_inline(ptype, hnid)
        raw = self.hnid_bytes(hnid, max_bytes=max_bytes)
        if ptype == P.PT_OBJECT:
            # (nid, ulSize) of an embedded object living in this node's subnodes
            if len(raw) >= 8:
                return struct.unpack_from("<II", raw, 0)
            return default
        return P.decode_value(ptype, raw, self.codepage)

    def get_str(self, propid: int, default: str = "") -> str:
        v = self.get(propid, default)
        if isinstance(v, bytes):
            return P.decode_string8(v, self.codepage)
        return v if isinstance(v, str) else default

    def size(self, propid: int) -> int:
        """Byte size of a variable-length property without loading it."""
        e = self.entries().get(propid)
        if e is None:
            return 0
        ptype, hnid = e
        if ptype in P.INLINE_TYPES:
            return 4
        return self.hnid_size(hnid)

    def stream(self, propid: int) -> Iterator[bytes]:
        """Yield the raw bytes of a variable-length property in block-sized chunks."""
        e = self.entries().get(propid)
        if e is None:
            return iter(())
        ptype, hnid = e
        if ptype in P.INLINE_TYPES:
            return iter((struct.pack("<I", hnid),))
        return self.hnid_stream(hnid)

    def items(self, *, max_bytes: Optional[int] = 1 << 20) -> Dict[int, Any]:
        """Decode every property (values above ``max_bytes`` are returned as a size marker)."""
        out = {}
        for propid, (ptype, hnid) in self.entries().items():
            try:
                if ptype not in P.INLINE_TYPES and self.hnid_size(hnid) > (max_bytes or 0):
                    out[propid] = "<%d bytes>" % self.hnid_size(hnid)
                else:
                    out[propid] = self.get(propid)
            except Exception as exc:  # pragma: no cover - diagnostics only
                out[propid] = "<error: %s>" % exc
        return out


# --------------------------------------------------------------------------
# Table Context
# --------------------------------------------------------------------------


class Column:
    __slots__ = ("tag", "propid", "ptype", "ib", "cb", "ibit")

    def __init__(self, tag: int, ib: int, cb: int, ibit: int):
        self.tag = tag
        self.propid = tag >> 16
        self.ptype = tag & 0xFFFF
        self.ib = ib
        self.cb = cb
        self.ibit = ibit

    def __repr__(self):
        return "Column(%s/%04x ib=%d cb=%d bit=%d)" % (P.prop_name(self.propid), self.ptype, self.ib, self.cb, self.ibit)


class Row:
    """One row of a TC.  Cells are decoded lazily."""

    __slots__ = ("tc", "data")

    def __init__(self, tc: "TableContext", data: bytes):
        self.tc = tc
        self.data = data

    @property
    def rowid(self) -> int:
        return struct.unpack_from("<I", self.data, 0)[0]

    def has(self, propid: int) -> bool:
        col = self.tc.columns_by_id.get(propid)
        if col is None:
            return False
        b = self.data[self.tc.ceb_offset + (col.ibit >> 3)]
        return bool(b & (0x80 >> (col.ibit & 7)))

    def raw_cell(self, propid: int) -> Optional[bytes]:
        col = self.tc.columns_by_id.get(propid)
        if col is None or not self.has(propid):
            return None
        return self.data[col.ib:col.ib + col.cb]

    def get(self, propid: int, default: Any = None) -> Any:
        col = self.tc.columns_by_id.get(propid)
        if col is None or not self.has(propid):
            return default
        cell = self.data[col.ib:col.ib + col.cb]
        pt = col.ptype
        if pt == P.PT_LONG:
            return struct.unpack("<i", cell)[0]
        if pt == P.PT_BOOLEAN:
            return bool(cell[0])
        if pt == P.PT_I2:
            return struct.unpack("<h", cell)[0]
        if pt in (P.PT_I8,):
            return struct.unpack("<q", cell)[0]
        if pt == P.PT_SYSTIME:
            return P.filetime_to_datetime(struct.unpack("<Q", cell)[0])
        if pt in (P.PT_DOUBLE, P.PT_APPTIME):
            return struct.unpack("<d", cell)[0]
        if pt == P.PT_R4:
            return struct.unpack("<f", cell)[0]
        if pt == P.PT_CURRENCY:
            return struct.unpack("<q", cell)[0] / 10000.0
        if pt == P.PT_ERROR:
            return struct.unpack("<I", cell)[0]
        # variable-length: cell holds an HNID
        hnid = struct.unpack("<I", cell)[0]
        raw = self.tc.hnid_bytes(hnid)
        return P.decode_value(pt, raw, self.tc.codepage)

    def get_str(self, propid: int, default: str = "") -> str:
        v = self.get(propid, default)
        if isinstance(v, bytes):
            return P.decode_string8(v)
        return v if isinstance(v, str) else default

    def to_dict(self) -> Dict[int, Any]:
        return {c.propid: self.get(c.propid) for c in self.tc.columns if self.has(c.propid)}


class TableContext(_Context):
    """TC ([MS-PST] 2.3.4)."""

    __slots__ = ("columns", "columns_by_id", "rgib", "row_size", "ceb_offset",
                 "hid_row_index", "hnid_rows", "codepage", "_row_bids", "_rows_per_block")

    def __init__(self, ndb: NDB, bid_data: int, bid_sub: int):
        super().__init__(ndb, bid_data, bid_sub)
        if self.heap.client_sig != CLIENT_SIG_TC:
            raise CorruptFile("node is not a Table Context (bClientSig 0x%02x)" % self.heap.client_sig)
        info = self.heap.get(self.heap.user_root)
        if len(info) < 22:
            raise CorruptFile("TCINFO too short")
        btype, ccols, ib4, ib2, ib1, ibbm, hid_row_index, hnid_rows, _hid_index = struct.unpack_from("<BBHHHHIII", info, 0)
        if btype != CLIENT_SIG_TC:
            raise CorruptFile("TCINFO bType is 0x%02x" % btype)
        if 22 + 8 * ccols > len(info):
            raise CorruptFile("TCINFO truncated column descriptors")
        cols = []
        for i in range(ccols):
            tag, ib, cb, ibit = struct.unpack_from("<IHBB", info, 22 + 8 * i)
            cols.append(Column(tag, ib, cb, ibit))
        self.columns = cols
        self.columns_by_id = {c.propid: c for c in cols}
        self.rgib = (ib4, ib2, ib1, ibbm)
        self.row_size = ibbm
        self.ceb_offset = ib1
        self.hid_row_index = hid_row_index
        self.hnid_rows = hnid_rows
        self.codepage = None
        self._row_bids: Optional[List[int]] = None
        self._rows_per_block: Optional[int] = None
        if self.row_size == 0 or self.ceb_offset + (ccols + 7) // 8 > self.row_size:
            raise CorruptFile("TC row layout inconsistent (row_size=%d ceb_offset=%d cols=%d)" % (self.row_size, self.ceb_offset, ccols))

    # -- row index ----------------------------------------------------------

    def row_index(self) -> BTH:
        return BTH(self.heap, self.hid_row_index)

    def row_index_count(self) -> int:
        if not self.hid_row_index:
            return 0
        return self.row_index().count()

    def find_row(self, rowid: int) -> Optional[Row]:
        """Locate a row by dwRowID through the row index."""
        if not self.hid_row_index:
            return None
        val = self.row_index().lookup(rowid)
        if val is None:
            return None
        idx = int.from_bytes(val, "little")
        return self.row_at(idx)

    # -- row matrix -----------------------------------------------------------

    def _rows_location(self) -> Tuple[Optional[bytes], Optional[List[int]]]:
        """Return (single_heap_blob, None) or (None, list_of_block_bids)."""
        if self.hnid_rows == 0:
            return b"", None
        if self.hnid_rows & 0x1F == NID_TYPE_HID:
            return self.heap.get(self.hnid_rows), None
        if self._row_bids is None:
            bid = self._subnode_bid(self.hnid_rows)
            self._row_bids = self.ndb.data_block_bids(bid)
        return None, self._row_bids

    def rows_per_block(self) -> int:
        blob, bids = self._rows_location()
        if bids is None:
            return max(1, len(blob) // self.row_size)
        if self._rows_per_block is None:
            # Decoded length of the first block (the BBT's cb may be a compressed size in the 4K format).
            first = len(self.ndb.read_block(bids[0])) if bids else 0
            self._rows_per_block = max(1, first // self.row_size)
        return self._rows_per_block

    def row_count(self) -> int:
        """Number of rows in the row matrix (reads only the first and last row blocks)."""
        blob, bids = self._rows_location()
        if bids is None:
            return len(blob) // self.row_size
        if not bids:
            return 0
        rpb = self.rows_per_block()
        last = len(self.ndb.read_block(bids[-1]))
        return (len(bids) - 1) * rpb + last // self.row_size

    def row_at(self, index: int) -> Optional[Row]:
        blob, bids = self._rows_location()
        rs = self.row_size
        if bids is None:
            off = index * rs
            if off + rs > len(blob):
                return None
            return Row(self, blob[off:off + rs])
        rpb = self.rows_per_block()
        bi, ri = divmod(index, rpb)
        if bi >= len(bids):
            return None
        blk = self.ndb.read_block(bids[bi])
        off = ri * rs
        if off + rs > len(blk):
            return None
        return Row(self, blk[off:off + rs])

    def iter_rows(self) -> Iterator[Row]:
        """Stream rows in row-matrix order, one block at a time."""
        blob, bids = self._rows_location()
        rs = self.row_size
        if bids is None:
            for off in range(0, len(blob) - rs + 1, rs):
                yield Row(self, blob[off:off + rs])
            return
        for bid in bids:
            blk = self.ndb.read_block(bid)
            n = len(blk) // rs
            for i in range(n):
                yield Row(self, blk[i * rs:(i + 1) * rs])

    def __iter__(self) -> Iterator[Row]:
        return self.iter_rows()

    def __len__(self) -> int:
        return self.row_count()


# --------------------------------------------------------------------------
# Convenience
# --------------------------------------------------------------------------


class LTP:
    """Factory tying the NDB to PC/TC readers, by NID or by raw (bidData, bidSub)."""

    def __init__(self, ndb: NDB):
        self.ndb = ndb

    def pc(self, nid: int) -> PropertyContext:
        e = self.ndb.node(nid)
        return PropertyContext(self.ndb, e.bid_data, e.bid_sub)

    def tc(self, nid: int) -> TableContext:
        e = self.ndb.node(nid)
        return TableContext(self.ndb, e.bid_data, e.bid_sub)

    def pc_from(self, bid_data: int, bid_sub: int) -> PropertyContext:
        return PropertyContext(self.ndb, bid_data, bid_sub)

    def tc_from(self, bid_data: int, bid_sub: int) -> TableContext:
        return TableContext(self.ndb, bid_data, bid_sub)

    def sub_pc(self, parent: _Context, nid: int) -> PropertyContext:
        e = parent.subnodes.lookup(nid)
        if e is None:
            raise NodeNotFound("subnode NID 0x%x not found" % nid)
        return PropertyContext(self.ndb, e.bid_data, e.bid_sub)

    def sub_tc(self, parent: _Context, nid: int) -> TableContext:
        e = parent.subnodes.lookup(nid)
        if e is None:
            raise NodeNotFound("subnode NID 0x%x not found" % nid)
        return TableContext(self.ndb, e.bid_data, e.bid_sub)

    def has_sub(self, parent: _Context, nid: int) -> bool:
        return parent.subnodes.lookup(nid) is not None
