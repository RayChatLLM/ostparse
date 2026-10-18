"""
Segment files - the immutable building blocks of an index.

An index is a directory of segments (see :mod:`.index`); each segment holds a
set of documents with local ids ``0..n-1`` and is complete on its own: text
store, per-document columns, sorted keys and one vocabulary per field.  The
initial build writes one segment per worker, every incremental update adds a
small one, compaction merges several into one - a segment is never modified
in place, so readers can mmap it safely while updates happen.

Layout (little-endian, 8-byte aligned sections, offsets in a JSON header at
the end of the file)::

    preamble   magic "OSTSEG03", header offset/length
    zdict      zlib preset dictionary shared by every segment of an index
    text       one zlib stream per document record (compressed with ``zdict``)
    text_off   u64[n+1]        record boundaries inside ``text``
    docs_*     per-document columns: nid u32, bid u64 (data block id of the
               message node - its change signature), folder u16 (index into
               ``folders``), sent/recv i64 (unix s), size u32, flags u8,
               importance u8, sender u32 (index into ``senders``)
    order_*/keys_*  doc ids sorted by sent / recv / size, and the sorted keys
    folders    JSON [{nid, path}]       folder table at build time
    senders    JSON [str]
    <field>.terms/.toff   string vocabulary: UTF-8 terms joined by "\\n", u32 offsets
    <field>.keys          numeric vocabulary (bigram fields): sorted u32 keys
    <field>.poff u64[nterms+1], .df u32[nterms], .enc u8[nterms], .post blob

Postings are sorted doc ids stored as *deltas*: u16 deltas when every gap fits
(the common case - ``ENC_D16``) else u32 deltas, zlib level 1; tiny lists stay
raw.  The transform runs on the whole list as one big integer (lane-wise
subtraction), so encoding costs a few hundred MB/s of pure Python and the
postings come out 3x smaller than compressed raw ids; decoding is a zlib call
plus ``itertools.accumulate`` - and adding a segment's doc-id base to a list is
free (the first delta simply starts from the base).

Fields: the text fields (subject, from, to, cc, bcc, attach, body), the hidden
``_meta`` (flags, extensions, ``folder:<id>``) and ``class`` fields, and one
``_bi_<field>`` numeric field per text field holding hashed adjacent-word
pairs for phrase / regex-literal narrowing.  ``folder:`` queries are decided on
the folder table and the ``folder:<id>`` meta postings, so folder paths are
not tokenised into postings (a renamed folder needs no re-indexing).
"""

from __future__ import annotations

import bisect
import heapq
import json
import mmap
import os
import re
import struct
import sys
import tempfile
import time
import zlib
from array import array
from collections import defaultdict
from itertools import accumulate
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple
from zlib import crc32 as _crc32

from .extract import BIGRAM_MASK, FIELD_ORDER, Document, class_terms
from .tokenize import address_extras, tokenize

MAGIC = b"OSTSEG03"
VERSION = 3
ZDICT_SIZE = 8192
TEXT_ZLIB_LEVEL = 1
POST_ZLIB_LEVEL = 1
RAW_POSTINGS_MAX = 8            # postings this short are stored as raw u32 ids
D16_RAW_MAX = 64                # u16 deltas of lists this short are not zlib'd
TEXT_FIELDS = tuple(f for f in FIELD_ORDER if f != "folder")
ADDRESS_FIELDS = ("from", "to", "cc", "bcc")
BIGRAM_FIELDS = tuple("_bi_" + f for f in TEXT_FIELDS)
STR_FIELDS = TEXT_FIELDS + ("_meta", "class")
INDEXED_FIELDS = STR_FIELDS + BIGRAM_FIELDS
SPILL_POSTINGS = 6_000_000      # in-memory postings before a run is spilled to disk
SPILL_TERMS = 700_000           # ... or distinct terms (each costs ~200 bytes of dict/str/array)

ENC_RAW, ENC_D32, ENC_D16RAW, ENC_D16 = 0, 1, 2, 3

_IS_LE = sys.byteorder == "little"
assert array("I").itemsize == 4 and array("H").itemsize == 2 and array("Q").itemsize == 8


def _native(a: array) -> array:
    if not _IS_LE:
        a = array(a.typecode, a)
        a.byteswap()
    return a


def _new_postings() -> array:
    return array("I")


def _fresh_posts(fields) -> Dict[str, Dict]:
    return {f: defaultdict(_new_postings) for f in fields}


def _align(fh, to: int = 8):
    pad = (-fh.tell()) % to
    if pad:
        fh.write(b"\0" * pad)


# --------------------------------------------------------------------------
# Postings codec
# --------------------------------------------------------------------------


def encode_postings(raw: bytes) -> Tuple[bytes, int]:
    """Encode sorted little-endian u32 doc ids; returns (data, enc)."""
    n = len(raw) // 4
    if n <= RAW_POSTINGS_MAX:
        return raw, ENC_RAW
    x = int.from_bytes(raw, "little")
    d = (x - (x << 32)) & ((1 << (32 * n)) - 1)          # lane i = id[i] - id[i-1]  (id[-1] = 0)
    if d & int.from_bytes(b"\0\0\xff\xff" * n, "little") == 0:
        db = d.to_bytes(4 * n, "little")
        out = bytearray(2 * n)
        out[0::2] = db[0::4]
        out[1::2] = db[1::4]
        if n <= D16_RAW_MAX:
            return bytes(out), ENC_D16RAW
        return zlib.compress(bytes(out), POST_ZLIB_LEVEL), ENC_D16
    return zlib.compress(d.to_bytes(4 * n, "little"), POST_ZLIB_LEVEL), ENC_D32


def decode_postings(data: bytes, enc: int, base: int = 0) -> array:
    """Decode to an array of doc ids, adding ``base`` to every id."""
    if enc == ENC_RAW:
        a = array("I")
        a.frombytes(data)
        a = _native(a)
        if base:
            a = array("I", [x + base for x in a])
        return a
    if enc == ENC_D32:
        d = array("I")
        d.frombytes(zlib.decompress(data))
    elif enc == ENC_D16RAW:
        d = array("H")
        d.frombytes(data)
    elif enc == ENC_D16:
        d = array("H")
        d.frombytes(zlib.decompress(data))
    else:
        raise ValueError("unknown postings encoding %d" % enc)
    d = _native(d)
    if base:
        it = accumulate(d, initial=base)
        next(it)
        return array("I", it)
    return array("I", accumulate(d))


def shift_ids(raw: bytes, offset: int) -> bytes:
    """Add ``offset`` to every u32 lane of ``raw`` (sorted ids), without a Python loop."""
    if not offset or not raw:
        return raw
    n = len(raw) // 4
    x = int.from_bytes(raw, "little")
    x += offset * (((1 << (32 * n)) - 1) // 0xFFFFFFFF)
    return x.to_bytes(4 * n, "little")


# --------------------------------------------------------------------------
# Spill files (sorted runs written by the segment writer)
# --------------------------------------------------------------------------


class _Spill:
    """One sorted run: every field's (key, postings) items in key order."""

    STR_HDR = struct.Struct("<HI")      # key length, postings count
    INT_HDR = struct.Struct("<II")      # key, postings count

    def __init__(self, path: str):
        self.path = path
        self.sections: Dict[str, Tuple[int, int]] = {}     # field -> (offset, count)

    @classmethod
    def write(cls, path: str, str_posts: Dict[str, Dict[str, array]], int_posts: Dict[str, Dict[int, array]]) -> "_Spill":
        sp = cls(path)
        with open(path, "wb", buffering=1 << 20) as fh:
            for f in STR_FIELDS:
                items = sorted((t.encode("utf-8", "surrogatepass"), a) for t, a in str_posts[f].items())
                sp.sections[f] = (fh.tell(), len(items))
                hdr = cls.STR_HDR.pack
                for key, post in items:
                    fh.write(hdr(len(key), len(post)))
                    fh.write(key)
                    fh.write(_native(post).tobytes())
            for f in TEXT_FIELDS:
                items = sorted(int_posts[f].items())
                sp.sections["_bi_" + f] = (fh.tell(), len(items))
                hdr = cls.INT_HDR.pack
                for key, post in items:
                    fh.write(hdr(key, len(post)))
                    fh.write(_native(post).tobytes())
        return sp

    def iter_field(self, field: str, rank: int) -> Iterator[Tuple[object, int, bytes]]:
        off, count = self.sections[field]
        if not count:
            return
        with open(self.path, "rb", buffering=1 << 20) as fh:
            fh.seek(off)
            if field in STR_FIELDS:
                hdr = self.STR_HDR
                for _ in range(count):
                    klen, n = hdr.unpack(fh.read(hdr.size))
                    key = fh.read(klen)
                    yield key, rank, fh.read(4 * n)
            else:
                hdr = self.INT_HDR
                for _ in range(count):
                    key, n = hdr.unpack(fh.read(hdr.size))
                    yield key, rank, fh.read(4 * n)


def _iter_memory(field: str, str_posts, int_posts, rank: int) -> Iterator[Tuple[object, int, bytes]]:
    if field in STR_FIELDS:
        for key, a in sorted((t.encode("utf-8", "surrogatepass"), a) for t, a in str_posts[field].items()):
            yield key, rank, _native(a).tobytes()
    else:
        for key, a in sorted(int_posts[field[4:]].items()):
            yield key, rank, _native(a).tobytes()


# --------------------------------------------------------------------------
# Writer
# --------------------------------------------------------------------------


class SegmentWriter:
    """Streams documents into a segment file.

    ``folders`` is the folder table ``[{nid, path}]`` the documents' folder ids
    refer to; ``zdict`` the index's shared preset dictionary.
    """

    def __init__(self, out_path: str, *, zdict: bytes, folders: List[dict],
                 progress: Optional[Callable[[int], None]] = None, workdir: Optional[str] = None,
                 spill_postings: int = SPILL_POSTINGS, spill_terms: int = SPILL_TERMS):
        self.out_path = out_path
        self.zdict = zdict
        self.folders = folders
        self.progress = progress
        self.spill_postings = spill_postings
        self.spill_terms = spill_terms
        self.tmpdir = tempfile.mkdtemp(prefix="ostseg-", dir=workdir or os.path.dirname(os.path.abspath(out_path)) or None)
        self.text_fh = open(os.path.join(self.tmpdir, "text.bin"), "wb", buffering=1 << 20)
        self.text_off = array("Q", [0])
        self._text_bytes = 0
        self._raw_text_bytes = 0
        self.nids = array("I")
        self.bids = array("Q")
        self.fids = array("H")
        self.sent = array("q")
        self.recv = array("q")
        self.sizes = array("I")
        self.flags = array("B")
        self.imps = array("B")
        self.senders = array("I")
        self.sender_ids: Dict[str, int] = {}
        self.str_posts: Dict[str, Dict[str, array]] = _fresh_posts(STR_FIELDS)
        self.int_posts: Dict[str, Dict[int, array]] = _fresh_posts(TEXT_FIELDS)
        self.post_count = 0
        self.term_count = 0
        self.spills: List[_Spill] = []
        self.n_docs = 0
        self.t0 = time.time()
        self.stats = {"spills": 0, "postings": 0}

    # -- adding documents ------------------------------------------------------------------

    def add(self, doc: Document, bid: int = 0):
        did = self.n_docs
        self.n_docs += 1
        self.nids.append(doc.nid)
        self.bids.append(bid)
        self.fids.append(doc.folder_id)
        self.sent.append(doc.sent)
        self.recv.append(doc.received)
        self.sizes.append(min(doc.size, 0xFFFFFFFF))
        self.flags.append(doc.flags & 0xFF)
        self.imps.append(doc.importance & 0xFF)
        sid = self.sender_ids.get(doc.sender)
        if sid is None:
            sid = self.sender_ids[doc.sender] = len(self.sender_ids)
        self.senders.append(sid)
        added = 0
        texts = doc.texts
        crc = _crc32
        mask = BIGRAM_MASK
        for f in TEXT_FIELDS:
            text = texts.get(f)
            if not text:
                continue
            toks = tokenize(text)
            tset = set(toks)
            if f in ADDRESS_FIELDS:
                tset |= address_extras(text.lower())
            if not tset:
                continue
            p = self.str_posts[f]
            n0 = len(p)
            for t in tset:
                p[t].append(did)
            self.term_count += len(p) - n0
            added += len(tset)
            if len(toks) >= 2:
                keys = {crc((a + " " + b).encode("utf-8", "surrogatepass")) & mask for a, b in zip(toks, toks[1:])}
                p = self.int_posts[f]
                n0 = len(p)
                for k in keys:
                    p[k].append(did)
                self.term_count += len(p) - n0
                added += len(keys)
        p = self.str_posts["_meta"]
        for t in doc.meta:
            p[t].append(did)
        added += len(doc.meta)
        p = self.str_posts["class"]
        for t in class_terms(doc.message_class):
            p[t].append(did)
            added += 1
        self.post_count += added
        self.stats["postings"] += added
        if self.post_count >= self.spill_postings or self.term_count >= self.spill_terms:
            self._spill()
        raw = doc.record().encode("utf-8", "surrogatepass")
        self._raw_text_bytes += len(raw)
        c = zlib.compressobj(TEXT_ZLIB_LEVEL, zlib.DEFLATED, 15, 8, zlib.Z_DEFAULT_STRATEGY, self.zdict)
        comp = c.compress(raw) + c.flush()
        self.text_fh.write(comp)
        self._text_bytes += len(comp)
        self.text_off.append(self._text_bytes)
        if self.progress is not None and did % 500 == 499:
            self.progress(self.n_docs)

    def add_compressed(self, nid: int, bid: int, fid: int, sent: int, recv: int, size: int, flags: int, imp: int,
                       sender: str, comp_record: bytes):
        """Append a document whose record is already compressed with this writer's zdict (merging)."""
        self.n_docs += 1
        self.nids.append(nid)
        self.bids.append(bid)
        self.fids.append(fid)
        self.sent.append(sent)
        self.recv.append(recv)
        self.sizes.append(size)
        self.flags.append(flags)
        self.imps.append(imp)
        sid = self.sender_ids.get(sender)
        if sid is None:
            sid = self.sender_ids[sender] = len(self.sender_ids)
        self.senders.append(sid)
        self.text_fh.write(comp_record)
        self._text_bytes += len(comp_record)
        self.text_off.append(self._text_bytes)

    def _spill(self):
        if not self.post_count:
            return
        path = os.path.join(self.tmpdir, "spill%04d.bin" % len(self.spills))
        self.spills.append(_Spill.write(path, self.str_posts, self.int_posts))
        self.str_posts = _fresh_posts(STR_FIELDS)
        self.int_posts = _fresh_posts(TEXT_FIELDS)
        self.post_count = 0
        self.term_count = 0
        self.stats["spills"] += 1

    # -- finishing ------------------------------------------------------------------------

    def _merged_field(self, field: str) -> Iterator[Tuple[object, bytes]]:
        """(key, concatenated sorted postings bytes) for every distinct key of ``field``."""
        streams = [sp.iter_field(field, i) for i, sp in enumerate(self.spills)]
        streams.append(_iter_memory(field, self.str_posts, self.int_posts, len(self.spills)))
        cur = None
        parts: List[bytes] = []
        for key, _rank, post in heapq.merge(*streams):
            if key != cur:
                if cur is not None:
                    yield cur, b"".join(parts)
                cur = key
                parts = [post]
            else:
                parts.append(post)
        if cur is not None:
            yield cur, b"".join(parts)

    def _merged_from(self, field: str, streams: Sequence[Iterator]) -> Iterator[Tuple[object, bytes]]:
        cur = None
        parts: List[bytes] = []
        for key, _rank, post in heapq.merge(*streams):
            if key != cur:
                if cur is not None:
                    yield cur, b"".join(parts)
                cur = key
                parts = [post]
            else:
                parts.append(post)
        if cur is not None:
            yield cur, b"".join(parts)

    def finish(self, header_extra: Optional[dict] = None,
               field_streams: Optional[Callable[[str], Sequence[Iterator]]] = None) -> dict:
        """Write the segment file.  ``field_streams(field)`` replaces the writer's own postings (merging)."""
        self.text_fh.close()
        n = self.n_docs
        sections: Dict[str, Tuple[int, int]] = {}
        tmp_out = self.out_path + ".tmp"
        out = open(tmp_out, "wb", buffering=1 << 20)
        out.write(MAGIC + struct.pack("<QI", 0, 0) + b"\0" * 12)

        def section(name: str, data: bytes):
            _align(out)
            off = out.tell()
            out.write(data)
            sections[name] = (off, len(data))

        def section_array(name: str, a: array):
            section(name, _native(a).tobytes())

        section("zdict", self.zdict)
        _align(out)
        off = out.tell()
        with open(os.path.join(self.tmpdir, "text.bin"), "rb") as fh:
            while True:
                buf = fh.read(1 << 22)
                if not buf:
                    break
                out.write(buf)
        sections["text"] = (off, self._text_bytes)
        section_array("text_off", self.text_off)
        section_array("docs_nid", self.nids)
        section_array("docs_bid", self.bids)
        section_array("docs_folder", self.fids)
        section_array("docs_sent", self.sent)
        section_array("docs_recv", self.recv)
        section_array("docs_size", self.sizes)
        section_array("docs_flags", self.flags)
        section_array("docs_imp", self.imps)
        section_array("docs_sender", self.senders)
        for name, keys in (("sent", self.sent), ("recv", self.recv), ("size", self.sizes)):
            order = sorted(range(n), key=keys.__getitem__)
            section_array("order_" + name, array("I", order))
            section_array("keys_" + name, array(keys.typecode, [keys[i] for i in order]))
        senders = [""] * len(self.sender_ids)
        for s, i in self.sender_ids.items():
            senders[i] = s
        section("folders", json.dumps(self.folders, ensure_ascii=False).encode("utf-8"))
        section("senders", json.dumps(senders, ensure_ascii=False).encode("utf-8"))
        field_stats = {}
        nterms_total = 0
        npost_total = 0
        for fname in INDEXED_FIELDS:
            numeric = fname not in STR_FIELDS
            terms = bytearray()
            toff = array("I", [0])
            keys = array("I")
            poff = array("Q", [0])
            df = array("I")
            enc = array("B")
            _align(out)
            post_start = out.tell()
            items = self._merged_from(fname, field_streams(fname)) if field_streams else self._merged_field(fname)
            for key, post in items:
                data, e = encode_postings(post)
                out.write(data)
                if numeric:
                    keys.append(key)
                else:
                    terms += key + b"\n"
                    toff.append(len(terms))
                poff.append(out.tell() - post_start)
                df.append(len(post) // 4)
                enc.append(e)
            sections[fname + ".post"] = (post_start, out.tell() - post_start)
            if numeric:
                section_array(fname + ".keys", keys)
            else:
                section(fname + ".terms", bytes(terms))
                section_array(fname + ".toff", toff)
            section_array(fname + ".poff", poff)
            section_array(fname + ".df", df)
            section_array(fname + ".enc", enc)
            field_stats[fname] = {"terms": len(df), "postings": sum(df), "postings_bytes": sections[fname + ".post"][1]}
            nterms_total += len(df)
            npost_total += field_stats[fname]["postings"]
        header = {
            "version": VERSION,
            "created": time.time(),
            "docs": n,
            "fields": list(INDEXED_FIELDS),
            "field_stats": field_stats,
            "terms": nterms_total,
            "postings": npost_total,
            "spills": self.stats["spills"],
            "text_bytes": self._text_bytes,
            "text_raw_bytes": self._raw_text_bytes,
            "build_seconds": round(time.time() - self.t0, 2),
            "sections": sections,
        }
        if header_extra:
            header.update(header_extra)
        hdr = json.dumps(header).encode("utf-8")
        _align(out)
        hoff = out.tell()
        out.write(hdr)
        out.seek(len(MAGIC))
        out.write(struct.pack("<QI", hoff, len(hdr)))
        out.close()
        os.replace(tmp_out, self.out_path)
        self._cleanup()
        header["file_size"] = os.path.getsize(self.out_path)
        header["path"] = self.out_path
        return header

    def _cleanup(self):
        try:
            for name in os.listdir(self.tmpdir):
                os.unlink(os.path.join(self.tmpdir, name))
            os.rmdir(self.tmpdir)
        except OSError:
            pass

    def abort(self):
        try:
            self.text_fh.close()
        except Exception:
            pass
        self._cleanup()
        try:
            os.unlink(self.out_path + ".tmp")
        except OSError:
            pass


# --------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------


class StrVocab:
    """Sorted string vocabulary of one field with its postings."""

    __slots__ = ("name", "mm", "terms", "toff", "poff", "df", "enc", "post_off", "n", "_str", "_str_starts", "_lines")
    numeric = False

    def __init__(self, name: str, mm, sections: dict):
        self.name = name
        self.mm = mm
        mv = memoryview(mm)
        t_off, t_len = sections[name + ".terms"]
        self.terms = mv[t_off:t_off + t_len]
        o, ln = sections[name + ".toff"]
        self.toff = mv[o:o + ln].cast("I")
        o, ln = sections[name + ".poff"]
        self.poff = mv[o:o + ln].cast("Q")
        o, ln = sections[name + ".df"]
        self.df = mv[o:o + ln].cast("I")
        o, ln = sections[name + ".enc"]
        self.enc = mv[o:o + ln].cast("B")
        self.post_off = sections[name + ".post"][0]
        self.n = len(self.df)
        self._str = None
        self._str_starts = None
        self._lines = None

    def __len__(self):
        return self.n

    def release(self):
        for name in ("terms", "toff", "poff", "df", "enc"):
            v = getattr(self, name, None)
            if v is not None:
                try:
                    v.release()
                except Exception:
                    pass
                setattr(self, name, None)

    def term(self, i: int) -> bytes:
        return bytes(self.terms[self.toff[i]:self.toff[i + 1] - 1])

    def term_str(self, i: int) -> str:
        return self.term(i).decode("utf-8", "replace")

    def _bisect_left(self, key: bytes) -> int:
        lo, hi = 0, self.n
        terms, toff = self.terms, self.toff
        while lo < hi:
            mid = (lo + hi) >> 1
            if bytes(terms[toff[mid]:toff[mid + 1] - 1]) < key:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def lookup(self, term: str) -> Optional[int]:
        key = term.encode("utf-8", "surrogatepass")
        i = self._bisect_left(key)
        if i < self.n and self.term(i) == key:
            return i
        return None

    def prefix_range(self, prefix: str) -> Tuple[int, int]:
        key = prefix.encode("utf-8", "surrogatepass")
        return self._bisect_left(key), self._bisect_left(key + b"\xff")

    # -- scans over the whole vocabulary ---------------------------------------------------

    def _ensure_str(self):
        if self._str is None:
            self._str = bytes(self.terms).decode("utf-8", "replace")
            starts = [0]
            pos = 0
            for line in self._str.split("\n")[:-1]:
                pos += len(line) + 1
                starts.append(pos)
            self._str_starts = starts

    def lines(self) -> List[str]:
        if self._lines is None:
            self._ensure_str()
            self._lines = self._str.split("\n")[:-1]
        return self._lines

    def scan_regex(self, pattern: "re.Pattern", *, whole: bool = False) -> List[int]:
        """Indexes of terms that contain (or, with ``whole``, entirely match) ``pattern``."""
        if self.n == 0:
            return []
        self._ensure_str()
        pat = re.compile("(?m)^(?:%s)$" % pattern.pattern, pattern.flags) if whole else pattern
        starts = self._str_starts
        n = self.n
        out = set()
        for m in pat.finditer(self._str):
            s, e = m.start(), m.end()
            i = bisect.bisect_right(starts, s) - 1
            if i >= n:
                break
            if e <= starts[i + 1] - 1:
                out.add(i)
        return sorted(out)

    def scan_substring(self, sub: str) -> List[int]:
        if self.n == 0:
            return []
        self._ensure_str()
        s, starts = self._str, self._str_starts
        out = []
        pos = s.find(sub)
        last = -1
        while pos != -1:
            i = bisect.bisect_right(starts, pos) - 1
            if i != last:
                out.append(i)
                last = i
            pos = s.find(sub, starts[i + 1])
        return out

    def scan_suffix(self, suffix: str) -> List[int]:
        return [i for i, t in enumerate(self.lines()) if t.endswith(suffix)]

    # -- postings ------------------------------------------------------------------------

    def postings(self, i: int, base: int = 0) -> array:
        off = self.post_off + self.poff[i]
        end = self.post_off + self.poff[i + 1]
        return decode_postings(self.mm[off:end], self.enc[i], base)

    def raw_postings(self, i: int) -> bytes:
        """Decoded ids as little-endian u32 bytes (for merging)."""
        return _native(self.postings(i)).tobytes()


class IntVocab:
    """Sorted numeric vocabulary (bigram buckets) of one field with its postings."""

    __slots__ = ("name", "mm", "keys", "poff", "df", "enc", "post_off", "n")
    numeric = True

    def __init__(self, name: str, mm, sections: dict):
        self.name = name
        self.mm = mm
        mv = memoryview(mm)
        o, ln = sections[name + ".keys"]
        self.keys = mv[o:o + ln].cast("I")
        o, ln = sections[name + ".poff"]
        self.poff = mv[o:o + ln].cast("Q")
        o, ln = sections[name + ".df"]
        self.df = mv[o:o + ln].cast("I")
        o, ln = sections[name + ".enc"]
        self.enc = mv[o:o + ln].cast("B")
        self.post_off = sections[name + ".post"][0]
        self.n = len(self.df)

    def __len__(self):
        return self.n

    def release(self):
        for name in ("keys", "poff", "df", "enc"):
            v = getattr(self, name, None)
            if v is not None:
                try:
                    v.release()
                except Exception:
                    pass
                setattr(self, name, None)

    def lookup(self, key: int) -> Optional[int]:
        i = bisect.bisect_left(self.keys, key)
        if i < self.n and self.keys[i] == key:
            return i
        return None

    def term(self, i: int) -> int:
        return self.keys[i]

    def term_str(self, i: int) -> str:
        return "%05x" % self.keys[i]

    def postings(self, i: int, base: int = 0) -> array:
        off = self.post_off + self.poff[i]
        end = self.post_off + self.poff[i + 1]
        return decode_postings(self.mm[off:end], self.enc[i], base)

    def raw_postings(self, i: int) -> bytes:
        return _native(self.postings(i)).tobytes()


class Segment:
    """Reader for one segment file (local doc ids)."""

    def __init__(self, path: str):
        self.path = path
        self.fh = open(path, "rb")
        self.mm = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:8] != MAGIC:
            raise ValueError("%s is not an ostparse index segment" % path)
        hoff, hlen = struct.unpack_from("<QI", self.mm, 8)
        self.header = json.loads(self.mm[hoff:hoff + hlen].decode("utf-8"))
        if self.header.get("version") != VERSION:
            raise ValueError("unsupported segment version %r" % self.header.get("version"))
        sec = self.sections = self.header["sections"]
        mv = memoryview(self.mm)
        self._views = [mv]

        def arr(name, fmt):
            off, ln = sec[name]
            v = mv[off:off + ln].cast(fmt)
            self._views.append(v)
            return v

        self.n = self.header["docs"]
        self.nid = arr("docs_nid", "I")
        self.bid = arr("docs_bid", "Q")
        self.folder = arr("docs_folder", "H")
        self.sent = arr("docs_sent", "q")
        self.recv = arr("docs_recv", "q")
        self.size = arr("docs_size", "I")
        self.flags = arr("docs_flags", "B")
        self.imp = arr("docs_imp", "B")
        self.sender = arr("docs_sender", "I")
        self.order = {k: arr("order_" + k, "I") for k in ("sent", "recv", "size")}
        self.keys = {"sent": arr("keys_sent", "q"), "recv": arr("keys_recv", "q"), "size": arr("keys_size", "I")}
        self.text_off = arr("text_off", "Q")
        self.text_base = sec["text"][0]
        zo, zl = sec["zdict"]
        self.zdict = bytes(self.mm[zo:zo + zl])
        fo, fl = sec["folders"]
        self.folders: List[dict] = json.loads(self.mm[fo:fo + fl].decode("utf-8"))
        so, sl = sec["senders"]
        self.senders: List[str] = json.loads(self.mm[so:so + sl].decode("utf-8"))
        self.vocab: Dict[str, object] = {}
        for f in self.header["fields"]:
            self.vocab[f] = IntVocab(f, self.mm, sec) if f + ".keys" in sec else StrVocab(f, self.mm, sec)

    def close(self):
        for v in self.vocab.values():
            v.release()
        self.vocab = {}
        for name in ("nid", "bid", "folder", "sent", "recv", "size", "flags", "imp", "sender", "text_off"):
            setattr(self, name, None)
        self.order = {}
        self.keys = {}
        for v in reversed(self._views):
            try:
                v.release()
            except Exception:
                pass
        self._views = []
        try:
            self.mm.close()
        finally:
            self.fh.close()

    def __len__(self):
        return self.n

    def record_bytes(self, doc: int) -> bytes:
        s = self.text_base + self.text_off[doc]
        e = self.text_base + self.text_off[doc + 1]
        return self.mm[s:e]

    def record(self, doc: int) -> str:
        d = zlib.decompressobj(zdict=self.zdict)
        return (d.decompress(self.record_bytes(doc)) + d.flush()).decode("utf-8", "surrogatepass")

    def iter_records(self, docs: Optional[Sequence[int]] = None) -> Iterator[Tuple[int, str]]:
        mm, base, off, zd = self.mm, self.text_base, self.text_off, self.zdict
        for d in (range(self.n) if docs is None else docs):
            s = base + off[d]
            e = base + off[d + 1]
            z = zlib.decompressobj(zdict=zd)
            yield d, (z.decompress(mm[s:e]) + z.flush()).decode("utf-8", "surrogatepass")

    def range_ids(self, key: str, start: Optional[int], end: Optional[int]) -> array:
        """Local docs whose ``key`` (sent/recv/size) lies in [start, end); unknown dates (0) never match."""
        keys = self.keys[key]
        order = self.order[key]
        lo = bisect.bisect_left(keys, start if start is not None else (1 if key != "size" else 0))
        hi = bisect.bisect_left(keys, end) if end is not None else len(keys)
        if hi <= lo:
            return array("I")
        a = array("I")
        a.frombytes(order[lo:hi].tobytes())
        return _native(a)

    def size_on_disk(self) -> int:
        return os.path.getsize(self.path)
