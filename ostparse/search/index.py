"""
The on-disk index: a directory of immutable segments plus a manifest.

::

    FILE.ost.ostidx/
        manifest.json        source identity, segment list, current folder table
        zdict.bin            preset dictionary shared by all segments' text stores
        seg-000001.ostseg    segments (see :mod:`.segment`)
        seg-000001.del       tombstones of a segment: sorted u32 local doc ids (only if any)

Document ids are global: a segment's local ids are offset by the sum of the
sizes of the segments before it.  Deleted documents (messages that vanished
from the store or were replaced by a newer version) stay in their segment and
are listed in a tombstone file until the segment is compacted; readers keep
them in one set and drop them from every result.

Opening an index mmaps every segment and concatenates the small per-document
columns (a few MB); nothing else is read until a query touches it.
Vocabulary lookups fan out to every segment, so an index is kept at a handful
of segments by the compaction policy in :mod:`.build`.
"""

from __future__ import annotations

import bisect
import json
import os
import re
import time
from array import array
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .extract import Document
from .segment import INDEXED_FIELDS, Segment, _native

VERSION = 3
MANIFEST = "manifest.json"
ZDICT_FILE = "zdict.bin"


def default_index_path(ost_path: str) -> str:
    return ost_path + ".ostidx"


def source_info(ost) -> dict:
    """Identity of the OST an index was built from (used for the cheap staleness check)."""
    st = os.stat(ost.ndb.path)
    h = ost.header
    return {"path": os.path.abspath(ost.ndb.path), "size": st.st_size, "mtime": int(st.st_mtime),
            "ib_file_eof": h.ib_file_eof, "bid_next_b": h.bid_next_b, "dw_unique": h.dw_unique}


def same_source(a: dict, b: dict) -> bool:
    return all(a.get(k) == b.get(k) for k in ("size", "ib_file_eof", "bid_next_b", "dw_unique"))


def read_manifest(path: str) -> dict:
    with open(os.path.join(path, MANIFEST), "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_manifest(path: str, manifest: dict):
    """Atomically replace the manifest (readers see either the old or the new index)."""
    tmp = os.path.join(path, MANIFEST + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, os.path.join(path, MANIFEST))


def del_file(seg_name: str) -> str:
    return seg_name[:-len(".ostseg")] + ".del" if seg_name.endswith(".ostseg") else seg_name + ".del"


def read_tombstones(path: str) -> array:
    a = array("I")
    try:
        with open(path, "rb") as fh:
            a.frombytes(fh.read())
    except FileNotFoundError:
        return a
    return _native(a)


def write_tombstones(path: str, ids: Sequence[int]):
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(_native(array("I", sorted(ids))).tobytes())
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Vocabulary spanning segments
# --------------------------------------------------------------------------


class MultiVocab:
    """One field's vocabulary across every segment.

    Term ids are ``segment_index << 32 | local_id``; postings come back as
    global doc ids.
    """

    __slots__ = ("name", "parts", "numeric")

    def __init__(self, name: str, parts: List[Tuple[int, int, object]]):
        self.name = name
        self.parts = parts                      # (segment index, doc-id base, segment vocabulary)
        self.numeric = name.startswith("_bi_")

    def __len__(self):
        return sum(len(v) for _si, _b, v in self.parts)

    @staticmethod
    def _gid(si: int, i: int) -> int:
        return (si << 32) | i

    def _part(self, gid: int):
        return self.parts[gid >> 32], gid & 0xFFFFFFFF

    # -- lookups ------------------------------------------------------------------------

    def lookup_ids(self, term) -> List[int]:
        out = []
        for si, _base, v in self.parts:
            i = v.lookup(term)
            if i is not None:
                out.append(self._gid(si, i))
        return out

    def docs(self, term) -> Set[int]:
        """Global doc ids of a term (a string, or a bucket number for numeric fields)."""
        out: Set[int] = set()
        for _si, base, v in self.parts:
            i = v.lookup(term)
            if i is not None:
                out.update(v.postings(i, base))
        return out

    def prefix_ids(self, prefix: str) -> List[int]:
        out: List[int] = []
        for si, _base, v in self.parts:
            lo, hi = v.prefix_range(prefix)
            out.extend(self._gid(si, i) for i in range(lo, hi))
        return out

    def all_ids(self) -> List[int]:
        out: List[int] = []
        for si, _base, v in self.parts:
            out.extend(self._gid(si, i) for i in range(len(v)))
        return out

    def scan_regex(self, pattern: "re.Pattern", *, whole: bool = False) -> List[int]:
        out: List[int] = []
        for si, _base, v in self.parts:
            out.extend(self._gid(si, i) for i in v.scan_regex(pattern, whole=whole))
        return out

    def scan_substring(self, sub: str) -> List[int]:
        out: List[int] = []
        for si, _base, v in self.parts:
            out.extend(self._gid(si, i) for i in v.scan_substring(sub))
        return out

    def scan_suffix(self, suffix: str) -> List[int]:
        out: List[int] = []
        for si, _base, v in self.parts:
            out.extend(self._gid(si, i) for i in v.scan_suffix(suffix))
        return out

    # -- per term ----------------------------------------------------------------------

    def term_str(self, gid: int) -> str:
        (_si, _base, v), i = self._part(gid)
        return v.term_str(i)

    def df(self, gid: int) -> int:
        (_si, _base, v), i = self._part(gid)
        return v.df[i]

    def postings(self, gid: int) -> array:
        (_si, base, v), i = self._part(gid)
        return v.postings(i, base)

    def postings_set(self, gid: int) -> Set[int]:
        return set(self.postings(gid))

    def docs_for_ids(self, gids: Sequence[int]) -> Set[int]:
        out: Set[int] = set()
        for gid in gids:
            (_si, base, v), i = self._part(gid)
            out.update(v.postings(i, base))
        return out


# --------------------------------------------------------------------------
# Composite reader
# --------------------------------------------------------------------------


class Index:
    """Reader for an index directory."""

    def __init__(self, path: str):
        if not os.path.isdir(path):
            raise ValueError("%s is not an ostparse index directory" % path)
        self.path = path
        self.manifest = read_manifest(path)
        if self.manifest.get("version") != VERSION:
            raise ValueError("unsupported index version %r" % self.manifest.get("version"))
        self.segments: List[Segment] = []
        self.bases: List[int] = []
        n = 0
        for s in self.manifest["segments"]:
            seg = Segment(os.path.join(path, s["name"]))
            self.segments.append(seg)
            self.bases.append(n)
            n += seg.n
        self.n = n
        self.deleted: Set[int] = set()
        for s, base in zip(self.manifest["segments"], self.bases):
            if s.get("deleted"):
                for d in read_tombstones(os.path.join(path, del_file(s["name"]))):
                    self.deleted.add(base + d)
        self.n_live = n - len(self.deleted)
        # per-document columns (zero-copy for a single segment, concatenated otherwise)
        self.nid = self._column("docs_nid", "I")
        self.bid = self._column("docs_bid", "Q")
        self.sent = self._column("docs_sent", "q")
        self.recv = self._column("docs_recv", "q")
        self.size = self._column("docs_size", "I")
        self.flags = self._column("docs_flags", "B")
        self.imp = self._column("docs_imp", "B")
        # folders: the manifest carries the current tree; segments map their local ids to folder nids
        self.folders: List[dict] = [{"nid": f["nid"], "path": f["path"]} for f in self.manifest.get("folders", [])]
        self._folder_cid: Dict[int, int] = {f["nid"]: i for i, f in enumerate(self.folders)}
        self._seg_fmap: List[List[int]] = []
        for seg in self.segments:
            m = []
            for f in seg.folders:
                cid = self._folder_cid.get(f["nid"])
                if cid is None:
                    cid = len(self.folders)
                    self.folders.append({"nid": f["nid"], "path": f["path"], "gone": True})
                    self._folder_cid[f["nid"]] = cid
                m.append(cid)
            self._seg_fmap.append(m)
        self._folder_col: Optional[array] = None
        self._sender_col: Optional[array] = None
        self._senders: Optional[List[str]] = None
        self._nid_map: Optional[Dict[int, int]] = None
        self.vocab: Dict[str, MultiVocab] = {
            f: MultiVocab(f, [(si, self.bases[si], seg.vocab[f]) for si, seg in enumerate(self.segments) if f in seg.vocab])
            for f in INDEXED_FIELDS}
        try:
            with open(os.path.join(path, ZDICT_FILE), "rb") as fh:
                self.zdict = fh.read()
        except FileNotFoundError:
            self.zdict = self.segments[0].zdict if self.segments else b""

    def _column(self, name: str, fmt: str):
        if len(self.segments) == 1:
            return getattr(self.segments[0], {"docs_nid": "nid", "docs_bid": "bid", "docs_sent": "sent", "docs_recv": "recv",
                                              "docs_size": "size", "docs_flags": "flags", "docs_imp": "imp"}[name])
        a = array(fmt)
        for seg in self.segments:
            off, ln = seg.sections[name]
            a.frombytes(seg.mm[off:off + ln])
        return _native(a)

    def close(self):
        for seg in self.segments:
            seg.close()
        self.segments = []
        self.vocab = {}
        for name in ("nid", "bid", "sent", "recv", "size", "flags", "imp"):
            setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __len__(self):
        return self.n_live

    # -- staleness ---------------------------------------------------------------------

    def matches_source(self, ost) -> bool:
        """Cheap check: the store's header/size still match what the index was built (or last updated) from."""
        try:
            return same_source(self.manifest.get("source", {}), source_info(ost))
        except OSError:
            return False

    # -- documents ---------------------------------------------------------------------

    def seg_of(self, doc: int) -> Tuple[int, int]:
        si = bisect.bisect_right(self.bases, doc) - 1
        return si, doc - self.bases[si]

    def live(self, docs: Set[int]) -> Set[int]:
        return docs - self.deleted if self.deleted else docs

    def all_docs(self) -> Set[int]:
        s = set(range(self.n))
        if self.deleted:
            s -= self.deleted
        return s

    def doc_by_nid(self, nid: int) -> Optional[int]:
        if self._nid_map is None:
            m: Dict[int, int] = {}
            dead = self.deleted
            for d, v in enumerate(self.nid.tolist()):
                if d not in dead:
                    m[v] = d
            self._nid_map = m
        return self._nid_map.get(nid)

    def record(self, doc: int) -> str:
        si, local = self.seg_of(doc)
        return self.segments[si].record(local)

    def fields(self, doc: int) -> Dict[str, str]:
        return Document.from_record(self.record(doc))

    def iter_records(self, docs: Optional[Sequence[int]] = None) -> Iterator[Tuple[int, str]]:
        """Yield (doc, record) for the given docs (any order) or every live doc."""
        if docs is None:
            dead = self.deleted
            for si, seg in enumerate(self.segments):
                base = self.bases[si]
                for local, rec in seg.iter_records():
                    if base + local not in dead:
                        yield base + local, rec
            return
        bases = self.bases
        segs = self.segments
        if len(segs) == 1:
            seg = segs[0]
            for d, rec in seg.iter_records(docs):
                yield d, rec
            return
        for d in docs:
            si = bisect.bisect_right(bases, d) - 1
            yield d, segs[si].record(d - bases[si])

    def date(self, doc: int) -> int:
        return self.sent[doc] or self.recv[doc]

    # -- folders -------------------------------------------------------------------------

    @property
    def folder(self) -> array:
        """Per-document composite folder ids (index into ``folders``)."""
        if self._folder_col is None:
            a = array("I")
            for seg, fmap in zip(self.segments, self._seg_fmap):
                a.extend(fmap[x] for x in seg.folder)
            self._folder_col = a
        return self._folder_col

    def folder_id(self, doc: int) -> int:
        if self._folder_col is not None:
            return self._folder_col[doc]
        si, local = self.seg_of(doc)
        return self._seg_fmap[si][self.segments[si].folder[local]]

    def folder_path(self, doc: int) -> str:
        return self.folders[self.folder_id(doc)]["path"]

    def folder_counts(self) -> Dict[int, int]:
        """Live documents per composite folder id."""
        counts: Dict[int, int] = {}
        dead = self.deleted
        for d, cid in enumerate(self.folder):
            if d not in dead:
                counts[cid] = counts.get(cid, 0) + 1
        return counts

    def folder_docs(self, nids: Sequence[int]) -> Set[int]:
        """Docs (including deleted ones) in the folders with these nids."""
        want = set(nids)
        out: Set[int] = set()
        for si, seg in enumerate(self.segments):
            base = self.bases[si]
            voc = seg.vocab["_meta"]
            for lid, f in enumerate(seg.folders):
                if f["nid"] in want:
                    i = voc.lookup("folder:%d" % lid)
                    if i is not None:
                        out.update(voc.postings(i, base))
        return out

    # -- senders --------------------------------------------------------------------------

    def _ensure_senders(self):
        if self._sender_col is None:
            names: List[str] = []
            ids: Dict[str, int] = {}
            col = array("I")
            for seg in self.segments:
                m = []
                for s in seg.senders:
                    k = ids.get(s)
                    if k is None:
                        k = ids[s] = len(names)
                        names.append(s)
                    m.append(k)
                col.extend(m[x] for x in seg.sender)
            self._senders = names
            self._sender_col = col

    @property
    def sender(self) -> array:
        self._ensure_senders()
        return self._sender_col

    @property
    def senders(self) -> List[str]:
        self._ensure_senders()
        return self._senders

    def sender_name(self, doc: int) -> str:
        if self._sender_col is not None:
            return self._senders[self._sender_col[doc]]
        si, local = self.seg_of(doc)
        seg = self.segments[si]
        return seg.senders[seg.sender[local]]

    # -- ranges ------------------------------------------------------------------------------

    def range_docs(self, key: str, start: Optional[int], end: Optional[int]) -> Set[int]:
        """Docs whose ``key`` (sent/recv/size) lies in [start, end).  Unknown dates (0) never match."""
        out: Set[int] = set()
        for si, seg in enumerate(self.segments):
            ids = seg.range_ids(key, start, end)
            if ids:
                base = self.bases[si]
                if base:
                    out.update(x + base for x in ids)
                else:
                    out.update(ids)
        return out

    # -- update support -----------------------------------------------------------------------

    def signatures(self) -> Dict[int, Tuple[int, int, int]]:
        """nid -> (bid, folder nid, doc) for every live document."""
        out: Dict[int, Tuple[int, int, int]] = {}
        dead = self.deleted
        for si, seg in enumerate(self.segments):
            base = self.bases[si]
            fnids = [f["nid"] for f in seg.folders]
            folder_nids = [fnids[x] for x in seg.folder.tolist()]
            docs = range(base, base + seg.n)
            if not dead or not any(base <= d < base + seg.n for d in dead):
                out.update(zip(seg.nid.tolist(), zip(seg.bid.tolist(), folder_nids, docs)))
                continue
            for nid, bid, fnid, d in zip(seg.nid.tolist(), seg.bid.tolist(), folder_nids, docs):
                if d not in dead:
                    out[nid] = (bid, fnid, d)
        return out

    def summary(self, doc: int) -> dict:
        f = self.fields(doc)
        return {
            "doc": doc, "nid": self.nid[doc], "folder": self.folder_path(doc),
            "subject": f["subject"], "from": f["from"], "to": f["to"], "cc": f["cc"],
            "attachments": f["attach"], "sent": self.sent[doc], "received": self.recv[doc],
            "size": self.size[doc], "flags": self.flags[doc], "importance": self.imp[doc],
        }

    def info(self) -> dict:
        m = self.manifest
        size = 0
        for name in os.listdir(self.path):
            try:
                size += os.path.getsize(os.path.join(self.path, name))
            except OSError:
                pass
        return {
            "version": m.get("version"), "index_path": self.path, "index_size": size,
            "docs": self.n_live, "deleted": len(self.deleted), "segments": len(self.segments),
            "folders": len([f for f in self.folders if not f.get("gone")]),
            "terms": sum(s.header.get("terms", 0) for s in self.segments),
            "postings": sum(s.header.get("postings", 0) for s in self.segments),
            "text_bytes": sum(s.header.get("text_bytes", 0) for s in self.segments),
            "text_raw_bytes": sum(s.header.get("text_raw_bytes", 0) for s in self.segments),
            "created": m.get("created"), "updated": m.get("updated"), "source": m.get("source"),
            "build_seconds": m.get("build_seconds"), "updates": m.get("updates", 0),
            "last_update": m.get("last_update"),
            "segment_list": [{"name": s["name"], "docs": s["docs"], "deleted": s.get("deleted", 0)} for s in m["segments"]],
        }


def open_index(path: str) -> Index:
    return Index(path)


def utcnow() -> float:
    return time.time()
