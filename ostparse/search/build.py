"""
Building, updating and compacting an index.

Everything starts from one pass over the store's node B-tree (NBT), which
lists every node with its data block id::

    nid  ->  (bidData, nidParent)

A message's ``bidData`` changes whenever Outlook writes the message (the NDB is
copy-on-write), so ``(nid, bidData, nidParent)`` is a complete change
signature: a nid the index does not know is a new message, a known nid with a
different block id or parent was modified or moved, a known nid that is gone
was deleted.  Walking the NBT costs well under a second even for a 10 GB
store, so an update is: scan, diff against the per-document columns the index
already holds, extract only the changed messages into a small new segment,
tombstone the old versions, rewrite the manifest.  Nothing else is touched.

The initial build is the same pipeline with every message in the "new" set,
split between worker processes (``os.fork``) that each write one segment while
reading their part of the file in file order.

Compaction merges segments without reading the OST: text records are already
compressed with the index's shared dictionary and are copied as they are,
postings of the merged vocabularies are concatenated with their doc ids
shifted.  Small segments left by updates are folded together once there are a
few of them; everything is rewritten into one segment once tombstones
account for a fifth of the documents.
"""

from __future__ import annotations

import multiprocessing
import os
import shutil
import struct
import threading
import time
import traceback
import zlib
from array import array
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .. import props as P
from ..errors import OSTError
from ..ndb import (NID_ROOT_FOLDER, NID_TYPE_ASSOC_MESSAGE, NID_TYPE_NORMAL_FOLDER, NID_TYPE_NORMAL_MESSAGE,
                   NID_TYPE_SEARCH_FOLDER)
from .extract import FIELD_ORDER, Document, extract
from .index import (MANIFEST, VERSION, ZDICT_FILE, Index, default_index_path, del_file, read_manifest, read_tombstones,
                    same_source, source_info, write_manifest, write_tombstones)
from .segment import ZDICT_SIZE, Segment, SegmentWriter, _native, shift_ids

DEFAULT_WORKERS = max(1, min(4, os.cpu_count() or 1))
PREFETCH_AHEAD = 256              # messages a worker's read-ahead thread stays in front of extraction
PREFETCH_BYTES = 16384            # bytes read ahead per message (its property context and tables)
PARALLEL_MIN_JOBS = 4000          # fewer messages than this are indexed in-process
SMALL_SEGMENT_FRACTION = 0.05     # a segment holding less than this share of the live docs is "small"
SMALL_SEGMENT_MIN = 1000
MERGE_SMALL_AT = 4                # merge the small segments once there are this many
COMPACT_DELETED_FRACTION = 0.20   # rewrite everything once tombstones reach this share of all docs ...
COMPACT_MIN_DOCS = 2000           # ... in an index of at least this many documents
UNREADABLE_META = {"is:unreadable"}

Progress = Optional[Callable[[int, int, float], None]]


# --------------------------------------------------------------------------
# Store scan
# --------------------------------------------------------------------------


class StoreScan:
    """Everything an index needs to know about the store's nodes, from one NBT pass."""

    __slots__ = ("folders", "nids", "bids", "parents", "seconds")

    def __init__(self):
        self.folders: Dict[int, Tuple[int, int]] = {}   # folder nid -> (bidData, nidParent)
        self.nids = array("I")
        self.bids = array("Q")
        self.parents = array("I")
        self.seconds = 0.0

    def __len__(self):
        return len(self.nids)


def scan_store(ost, include_associated: bool = False) -> StoreScan:
    """One sequential pass over the NBT leaf pages."""
    t0 = time.time()
    out = StoreScan()
    nbt = ost.ndb.nbt
    lay = ost.ndb.layout
    wide = lay.wide
    st = struct.Struct("<QQQII" if wide else "<IIII")
    msg_types = {NID_TYPE_NORMAL_MESSAGE}
    if include_associated:
        msg_types.add(NID_TYPE_ASSOC_MESSAGE)
    folder_types = (NID_TYPE_NORMAL_FOLDER, NID_TYPE_SEARCH_FOLDER)
    nids, bids, parents, folders = out.nids, out.bids, out.parents, out.folders
    stack = [(nbt.root_ib, nbt.root_bid)]
    while stack:
        ib, bid = stack.pop()
        p = nbt._page(ib, bid)
        if p.level == 0:
            data = p.data
            if p.cb_ent != st.size:
                data = b"".join(data[i * p.cb_ent:i * p.cb_ent + st.size] for i in range(p.n))
            for ent in st.iter_unpack(data[:p.n * st.size]):
                nid = ent[0] & 0xFFFFFFFF
                t = nid & 0x1F
                if t in msg_types:
                    nids.append(nid)
                    bids.append(ent[1])
                    parents.append(ent[3])
                elif t in folder_types:
                    folders[nid] = (ent[1], ent[3])
        else:
            children = []
            cb = p.cb_ent
            for i in range(p.n):
                _k, cbid, cib = lay.unpack_bt_entry(p.data, i * cb)
                children.append((cib, cbid))
            stack.extend(reversed(children))
    out.seconds = time.time() - t0
    return out


def folder_table(ost, scan: StoreScan, cache: Optional[Dict[int, dict]] = None) -> List[dict]:
    """Current folder table ``[{nid, path, parent, bid, name}]`` (the root first, then by nid).

    Names are read from each folder's property context unless ``cache`` (the
    previous manifest's table) has the folder with the same data block id.
    """
    cache = cache or {}
    names: Dict[int, str] = {}
    for nid, (bid, _parent) in scan.folders.items():
        c = cache.get(nid)
        if c is not None and c.get("bid") == bid and "name" in c:
            names[nid] = c["name"]
            continue
        try:
            name = ost.ltp.pc(nid).get_str(P.PR_DISPLAY_NAME)
        except OSTError:
            name = "<0x%x>" % nid
        names[nid] = name
    paths: Dict[int, str] = {NID_ROOT_FOLDER: "/"}

    def path_of(nid: int) -> str:
        p = paths.get(nid)
        if p is not None:
            return p
        parts = []
        cur = nid
        seen = set()
        while cur in scan.folders and cur != NID_ROOT_FOLDER and cur not in seen:
            seen.add(cur)
            parts.append(names[cur])
            cur = scan.folders[cur][1]
            if cur in paths:
                base = paths[cur]
                parts.reverse()
                p = (base.rstrip("/") + "/" + "/".join(parts)) if parts else base
                paths[nid] = p
                return p
        parts.reverse()
        p = "/" + "/".join(parts)
        paths[nid] = p
        return p

    out = []
    order = sorted(scan.folders)
    if NID_ROOT_FOLDER in scan.folders:
        order.remove(NID_ROOT_FOLDER)
        order.insert(0, NID_ROOT_FOLDER)
    for nid in order:
        bid, parent = scan.folders[nid]
        out.append({"nid": nid, "path": path_of(nid), "parent": parent, "bid": bid, "name": names[nid]})
    return out


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


def _document(ost, nid: int, lid: int, path: str) -> Document:
    try:
        return extract(ost.message(nid), lid, path)
    except Exception as exc:  # index what we can, remember the failure
        doc = Document(nid=nid, folder_id=lid, folder_path=path, texts={f: "" for f in FIELD_ORDER})
        doc.texts["folder"] = path
        doc.texts["subject"] = "<unreadable message: %s>" % exc
        doc.meta = set(UNREADABLE_META)
        return doc


def sample_zdict(ost, nids: Sequence[int], paths: Sequence[str], count: int = 48) -> bytes:
    """Preset dictionary for the text store: the tail of a sample of serialised records."""
    if not nids:
        return b""
    step = max(1, len(nids) // count)
    parts = []
    for i in range(0, len(nids), step):
        parts.append(_document(ost, nids[i], 0, paths[i]).record().encode("utf-8", "surrogatepass"))
        if len(parts) >= count:
            break
    sample = b"\n".join(parts)
    return sample[-ZDICT_SIZE:] if len(sample) > ZDICT_SIZE else sample


class _Prefetcher:
    """Read-ahead thread: pulls the blocks of upcoming messages into the page cache.

    Extraction reads a message's property context and tables with a handful of
    small ``pread`` calls that the kernel's read-ahead does not anticipate well
    (the message blocks sit between attachment data).  Reading 16 KiB at each
    upcoming message's data block while the main thread tokenises the current
    one overlaps the disk time with the CPU time; the GIL is released during
    the read, so the cost to the main thread is a BBT lookup per message.
    """

    def __init__(self, ost, jobs: Sequence[Tuple[int, int, int]], ahead: int = PREFETCH_AHEAD):
        self.ost = ost
        self.jobs = jobs
        self.ahead = ahead
        self.done = 0
        self.stop = False
        self.thread = threading.Thread(target=self._run, name="ostparse-prefetch", daemon=True)
        self.thread.start()

    def _run(self):
        fd = self.ost.ndb.fd
        bbt = self.ost.ndb.bbt
        jobs = self.jobs
        n = len(jobs)
        i = 0
        while i < n and not self.stop:
            if i - self.done > self.ahead:
                time.sleep(0.002)
                continue
            try:
                e = bbt.lookup(jobs[i][1])
                if e is not None:
                    os.pread(fd, PREFETCH_BYTES, e.ib)
            except Exception:
                pass
            i += 1

    def close(self):
        self.stop = True
        self.thread.join(timeout=1.0)


def write_segment(ost, out_path: str, jobs: Sequence[Tuple[int, int, int]], folders: List[dict], zdict: bytes,
                  progress: Optional[Callable[[int], None]] = None, workdir: Optional[str] = None,
                  header_extra: Optional[dict] = None, prefetch: bool = True) -> dict:
    """Extract every (nid, bid, folder id) job into one new segment file."""
    paths = [f["path"] for f in folders]
    table = [{"nid": f["nid"], "path": f["path"]} for f in folders]
    w = SegmentWriter(out_path, zdict=zdict, folders=table, progress=progress, workdir=workdir)
    pf = _Prefetcher(ost, jobs) if prefetch and len(jobs) > 2 * PREFETCH_AHEAD else None
    try:
        i = 0
        for nid, bid, lid in jobs:
            w.add(_document(ost, nid, lid, paths[lid]), bid)
            i += 1
            if pf is not None:
                pf.done = i
        if pf is not None:
            pf.close()
            pf = None
        t_fin = time.time()
        hdr = w.finish(header_extra)
        hdr["finish_seconds"] = round(time.time() - t_fin, 2)
        return hdr
    except BaseException:
        if pf is not None:
            pf.close()
        w.abort()
        raise


def _worker_main(ost, out_path, jobs, folders, zdict, counters, slot, pipe, workdir):
    try:
        def tick(n):
            counters[slot] = n

        hdr = write_segment(ost, out_path, jobs, folders, zdict, tick, workdir)
        counters[slot] = len(jobs)
        pipe.send(hdr)
        pipe.close()
    except BaseException as exc:
        try:
            pipe.send({"error": "%s: %s" % (type(exc).__name__, exc), "traceback": traceback.format_exc()})
            pipe.close()
        finally:
            os._exit(1)
    os._exit(0)


def build_segments(ost, out_dir: str, names: Sequence[str], job_slices: Sequence[Sequence[Tuple[int, int, int]]],
                   folders: List[dict], zdict: bytes, *, workers: int, progress: Progress = None,
                   workdir: Optional[str] = None) -> List[dict]:
    """Write one segment per job slice, in parallel worker processes when possible."""
    total = sum(len(j) for j in job_slices)
    t0 = time.time()
    use_fork = workers > 1 and len(job_slices) > 1 and hasattr(os, "fork")
    if not use_fork:
        done = 0
        headers = []
        for name, jobs in zip(names, job_slices):
            def tick(n, base=done):
                if progress:
                    progress(base + n, total, time.time() - t0)
            headers.append(write_segment(ost, os.path.join(out_dir, name), jobs, folders, zdict, tick, workdir))
            done += len(jobs)
        if progress:
            progress(total, total, time.time() - t0)
        return headers
    ctx = multiprocessing.get_context("fork")
    counters = ctx.Array("q", len(job_slices), lock=False)
    procs = []
    pipes = []
    for slot, (name, jobs) in enumerate(zip(names, job_slices)):
        r, w = ctx.Pipe(duplex=False)
        p = ctx.Process(target=_worker_main, args=(ost, os.path.join(out_dir, name), jobs, folders, zdict, counters, slot, w, workdir))
        p.start()
        w.close()
        procs.append(p)
        pipes.append(r)
    try:
        while any(p.is_alive() for p in procs):
            for p in procs:
                p.join(timeout=0.25)
                if p.is_alive():
                    break
            if progress:
                progress(sum(counters), total, time.time() - t0)
        headers = []
        for p, r in zip(procs, pipes):
            p.join()
            try:
                hdr = r.recv()
            except EOFError:
                hdr = {"error": "worker exited without a result (exit code %s)" % p.exitcode}
            if "error" in hdr:
                raise RuntimeError("index worker failed: %s\n%s" % (hdr["error"], hdr.get("traceback", "")))
            headers.append(hdr)
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
    if progress:
        progress(total, total, time.time() - t0)
    return headers


def _split_jobs(jobs: Sequence[Tuple[int, int, int]], parts: int) -> List[Sequence[Tuple[int, int, int]]]:
    n = len(jobs)
    parts = max(1, min(parts, n))
    step = (n + parts - 1) // parts
    return [jobs[i:i + step] for i in range(0, n, step)]


# --------------------------------------------------------------------------
# Manifest helpers
# --------------------------------------------------------------------------


def _segment_name(manifest: dict) -> str:
    k = manifest.get("next_segment", 1)
    manifest["next_segment"] = k + 1
    return "seg-%06d.ostseg" % k


def _remove_segment_files(path: str, names: Sequence[str]):
    for name in names:
        for fn in (name, del_file(name)):
            try:
                os.unlink(os.path.join(path, fn))
            except OSError:
                pass


def _remove_orphans(path: str, manifest: dict):
    """Delete segment files an interrupted update left behind (not referenced by the manifest)."""
    live = set()
    for s in manifest["segments"]:
        live.add(s["name"])
        live.add(del_file(s["name"]))
    for fn in os.listdir(path):
        if (fn.endswith(".ostseg") or fn.endswith(".del") or fn.endswith(".tmp")) and fn not in live:
            try:
                os.unlink(os.path.join(path, fn))
            except OSError:
                pass


def _folder_entries(folders: List[dict]) -> List[dict]:
    return [{"nid": f["nid"], "path": f["path"], "parent": f.get("parent", 0), "bid": f.get("bid", 0), "name": f.get("name", "")}
            for f in folders]


# --------------------------------------------------------------------------
# Initial build
# --------------------------------------------------------------------------


def build_index(ost, out_path: Optional[str] = None, *, progress: Progress = None, include_associated: bool = False,
                workers: int = DEFAULT_WORKERS, workdir: Optional[str] = None) -> dict:
    """Index every message of ``ost`` into a fresh index directory; returns ``Index.info()`` plus timings."""
    out_path = out_path or default_index_path(ost.ndb.path)
    t0 = time.time()
    scan = scan_store(ost, include_associated)
    folders = folder_table(ost, scan)
    fpos = {f["nid"]: i for i, f in enumerate(folders)}
    jobs = _jobs_for(scan, fpos, folders)
    tmp_dir = out_path + ".building"
    if os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir)
    try:
        zdict = sample_zdict(ost, [j[0] for j in jobs[::max(1, len(jobs) // 64)]], [folders[j[2]]["path"] for j in jobs[::max(1, len(jobs) // 64)]])
        with open(os.path.join(tmp_dir, ZDICT_FILE), "wb") as fh:
            fh.write(zdict)
        manifest = {"version": VERSION, "created": time.time(), "updated": time.time(), "include_associated": include_associated,
                    "zdict_crc": zlib.crc32(zdict), "next_segment": 1, "segments": [], "folders": _folder_entries(folders),
                    "updates": 0}
        slices = _split_jobs(jobs, workers) if len(jobs) >= PARALLEL_MIN_JOBS else ([jobs] if jobs else [])
        names = [_segment_name(manifest) for _ in slices]
        headers = build_segments(ost, tmp_dir, names, slices, folders, zdict, workers=workers, progress=progress, workdir=workdir)
        manifest["segments"] = [{"name": n, "docs": h["docs"], "deleted": 0} for n, h in zip(names, headers)]
        manifest["source"] = source_info(ost)
        manifest["build_seconds"] = round(time.time() - t0, 2)
        manifest["scan_seconds"] = round(scan.seconds, 3)
        manifest["workers"] = len(slices)
        write_manifest(tmp_dir, manifest)
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    _replace_dir(tmp_dir, out_path)
    with Index(out_path) as ix:
        info = ix.info()
    info["build_seconds"] = round(time.time() - t0, 2)
    info["scan_seconds"] = round(scan.seconds, 3)
    info["path"] = out_path
    return info


def _replace_dir(tmp_dir: str, out_path: str):
    if os.path.isdir(out_path):
        old = out_path + ".old"
        shutil.rmtree(old, ignore_errors=True)
        os.rename(out_path, old)
        os.rename(tmp_dir, out_path)
        shutil.rmtree(old, ignore_errors=True)
    else:
        if os.path.exists(out_path):     # a v1/v2 single-file index
            os.unlink(out_path)
        os.rename(tmp_dir, out_path)


def _jobs_for(scan: StoreScan, fpos: Dict[int, int], folders: List[dict]) -> List[Tuple[int, int, int]]:
    jobs = []
    for nid, bid, parent in zip(scan.nids, scan.bids, scan.parents):
        lid = fpos.get(parent)
        if lid is None:   # a message whose parent is not a folder node: give it a pseudo folder
            lid = len(folders)
            folders.append({"nid": parent, "path": "/<orphans>/0x%x" % parent, "parent": 0, "bid": 0, "name": "0x%x" % parent})
            fpos[parent] = lid
        jobs.append((nid, bid, lid))
    return jobs


# --------------------------------------------------------------------------
# Incremental update
# --------------------------------------------------------------------------


def update_index(ost, path: Optional[str] = None, *, progress: Progress = None, workers: int = DEFAULT_WORKERS,
                 compact: bool = True, force: bool = False, workdir: Optional[str] = None) -> dict:
    """Bring an existing index up to date with ``ost``.

    Returns a stats dict: ``action`` is ``unchanged`` (header identical, nothing
    done), ``up-to-date`` (store changed but no message did) or ``updated``,
    with ``added`` / ``modified`` / ``deleted`` message counts.
    """
    path = path or default_index_path(ost.ndb.path)
    t0 = time.time()
    manifest = read_manifest(path)
    if manifest.get("version") != VERSION:
        raise ValueError("index %s has version %r; rebuild it" % (path, manifest.get("version")))
    src = source_info(ost)
    if not force and same_source(manifest.get("source", {}), src):
        return {"action": "unchanged", "added": 0, "modified": 0, "deleted": 0, "seconds": round(time.time() - t0, 3)}
    _remove_orphans(path, manifest)
    include_associated = manifest.get("include_associated", False)
    scan = scan_store(ost, include_associated)
    folders = folder_table(ost, scan, cache={f["nid"]: f for f in manifest.get("folders", [])})
    fpos = {f["nid"]: i for i, f in enumerate(folders)}
    ix = Index(path)
    try:
        sig = ix.signatures()
    finally:
        ix.close()
    jobs: List[Tuple[int, int, int]] = []
    tomb: List[int] = []
    added = modified = 0
    snids = scan.nids.tolist()
    get = sig.get
    for nid, bid, parent in zip(snids, scan.bids.tolist(), scan.parents.tolist()):
        old = get(nid)
        if old is not None and old[0] == bid and old[1] == parent:
            continue
        lid = fpos.get(parent)
        if lid is None:
            lid = len(folders)
            folders.append({"nid": parent, "path": "/<orphans>/0x%x" % parent, "parent": 0, "bid": 0, "name": "0x%x" % parent})
            fpos[parent] = lid
        jobs.append((nid, bid, lid))
        if old is None:
            added += 1
        else:
            tomb.append(old[2])
            modified += 1
    gone = sig.keys() - set(snids)
    for nid in gone:
        tomb.append(sig[nid][2])
    deleted = len(gone)
    t_diff = time.time() - t0
    stats = {"added": added, "modified": modified, "deleted": deleted, "scan_seconds": round(scan.seconds, 3),
             "diff_seconds": round(t_diff, 3), "messages": len(scan)}
    zdict = _read_zdict(path)
    # new segment(s)
    new_entries = []
    if jobs:
        slices = _split_jobs(jobs, workers) if len(jobs) >= PARALLEL_MIN_JOBS and workers > 1 else [jobs]
        names = [_segment_name(manifest) for _ in slices]
        headers = build_segments(ost, path, names, slices, folders, zdict, workers=workers, progress=progress, workdir=workdir)
        new_entries = [{"name": n, "docs": h["docs"], "deleted": 0} for n, h in zip(names, headers)]
    # tombstones
    if tomb:
        bases = []
        n = 0
        for s in manifest["segments"]:
            bases.append(n)
            n += s["docs"]
        per_seg: Dict[int, List[int]] = {}
        for d in tomb:
            si = _seg_index(bases, d)
            per_seg.setdefault(si, []).append(d - bases[si])
        for si, ids in per_seg.items():
            s = manifest["segments"][si]
            dp = os.path.join(path, del_file(s["name"]))
            existing = set(read_tombstones(dp)) if s.get("deleted") else set()
            existing.update(ids)
            write_tombstones(dp, existing)
            s["deleted"] = len(existing)
    manifest["segments"].extend(new_entries)
    manifest["folders"] = _folder_entries(folders)
    manifest["source"] = src
    manifest["updated"] = time.time()
    manifest["updates"] = manifest.get("updates", 0) + 1
    stats["seconds"] = round(time.time() - t0, 3)
    stats["action"] = "updated" if (jobs or tomb) else "up-to-date"
    manifest["last_update"] = dict(stats)
    write_manifest(path, manifest)
    if compact and (jobs or tomb):
        c = maybe_compact(path, progress=progress)
        if c:
            stats["compaction"] = c
    stats["seconds"] = round(time.time() - t0, 3)
    stats["segments"] = len(read_manifest(path)["segments"])
    return stats


def _seg_index(bases: List[int], d: int) -> int:
    import bisect
    return bisect.bisect_right(bases, d) - 1


def _read_zdict(path: str) -> bytes:
    with open(os.path.join(path, ZDICT_FILE), "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# Compaction
# --------------------------------------------------------------------------


def merge_segments(path: str, names: Sequence[str], *, progress: Progress = None, workdir: Optional[str] = None) -> dict:
    """Merge the named segments of the index at ``path`` into one new segment (manifest updated)."""
    t0 = time.time()
    manifest = read_manifest(path)
    by_name = {s["name"]: s for s in manifest["segments"]}
    entries = [by_name[n] for n in names]
    zdict = _read_zdict(path)
    cur_folders = manifest.get("folders", [])
    table = [{"nid": f["nid"], "path": f["path"]} for f in cur_folders]
    fpos = {f["nid"]: i for i, f in enumerate(table)}
    segs = [Segment(os.path.join(path, n)) for n in names]
    try:
        dels = [set(read_tombstones(os.path.join(path, del_file(e["name"])))) if e.get("deleted") else set()
                for e in entries]
        new_name = _segment_name(manifest)
        out_path = os.path.join(path, new_name)
        w = SegmentWriter(out_path, zdict=zdict, folders=table, workdir=workdir)
        remaps: List[Tuple[str, object]] = []
        fmaps: List[List[int]] = []
        nxt = 0
        total = sum(seg.n for seg in segs)
        done = 0
        for seg, dead in zip(segs, dels):
            fmap = []
            for f in seg.folders:
                lid = fpos.get(f["nid"])
                if lid is None:
                    lid = len(table)
                    table.append({"nid": f["nid"], "path": f["path"]})
                    fpos[f["nid"]] = lid
                fmap.append(lid)
            fmaps.append(fmap)
            if not dead:
                remaps.append(("shift", nxt))
            else:
                m = [-1] * seg.n
                k = nxt
                for local in range(seg.n):
                    if local not in dead:
                        m[local] = k
                        k += 1
                remaps.append(("map", m))
            same_dict = seg.zdict == zdict
            nid, bid, fid, sent, recv, size, flags, imp, sender = (seg.nid, seg.bid, seg.folder, seg.sent, seg.recv, seg.size,
                                                                   seg.flags, seg.imp, seg.sender)
            senders = seg.senders
            for local in range(seg.n):
                if local in dead:
                    continue
                rec = seg.record_bytes(local)
                if not same_dict:
                    d = zlib.decompressobj(zdict=seg.zdict)
                    raw = d.decompress(rec) + d.flush()
                    c = zlib.compressobj(1, zlib.DEFLATED, 15, 8, zlib.Z_DEFAULT_STRATEGY, zdict)
                    rec = c.compress(raw) + c.flush()
                w.add_compressed(nid[local], bid[local], fmap[fid[local]], sent[local], recv[local], size[local],
                                 flags[local], imp[local], senders[sender[local]], rec)
                nxt += 1
            done += seg.n
            if progress:
                progress(done, total, time.time() - t0)
        w.folders = table

        def streams(field: str):
            return [_remapped_stream(seg, field, rank, remap) for rank, (seg, remap) in enumerate(zip(segs, remaps))]

        hdr = w.finish({"merged_from": list(names)}, field_streams=streams)
    finally:
        for seg in segs:
            seg.close()
    # splice the manifest: the merged segment takes the place of the first merged one
    first = min(manifest["segments"].index(e) for e in entries)
    manifest["segments"] = [s for s in manifest["segments"] if s["name"] not in set(names)]
    manifest["segments"].insert(min(first, len(manifest["segments"])), {"name": new_name, "docs": hdr["docs"], "deleted": 0})
    manifest["folders"] = _folder_entries(cur_folders) + [
        {"nid": f["nid"], "path": f["path"], "parent": 0, "bid": 0, "name": ""} for f in table[len(cur_folders):]]
    manifest["updated"] = time.time()
    write_manifest(path, manifest)
    _remove_segment_files(path, names)
    return {"merged": list(names), "into": new_name, "docs": hdr["docs"], "seconds": round(time.time() - t0, 2)}


def _remapped_stream(seg: Segment, field: str, rank: int, remap: Tuple[str, object]) -> Iterator[Tuple[object, int, bytes]]:
    v = seg.vocab.get(field)
    if v is None:
        return
    kind, arg = remap
    term = v.term
    if kind == "shift":
        raw_postings = v.raw_postings
        for i in range(len(v)):
            yield term(i), rank, shift_ids(raw_postings(i), arg)
    else:
        m = arg
        postings = v.postings
        for i in range(len(v)):
            ids = [m[x] for x in postings(i)]
            ids = [x for x in ids if x >= 0]
            if ids:
                yield term(i), rank, _native(array("I", ids)).tobytes()


def maybe_compact(path: str, *, progress: Progress = None, force_full: bool = False) -> Optional[dict]:
    """Apply the compaction policy; returns what was done (or None).

    * ``force_full`` (``ostparse index --compact``): everything into one segment.
    * tombstones above ``COMPACT_DELETED_FRACTION`` of all documents: same.
    * otherwise, once ``MERGE_SMALL_AT`` segments are "small" (less than
      ``SMALL_SEGMENT_FRACTION`` of the live documents), fold them into one -
      the base segments are left alone.
    """
    manifest = read_manifest(path)
    segs = manifest["segments"]
    if not segs:
        return None
    total = sum(s["docs"] for s in segs)
    deleted = sum(s.get("deleted", 0) for s in segs)
    live = total - deleted
    if len(segs) == 1 and not deleted:
        return None
    if force_full or (total >= COMPACT_MIN_DOCS and deleted > COMPACT_DELETED_FRACTION * total):
        r = merge_segments(path, [s["name"] for s in segs], progress=progress)
        r["kind"] = "full"
        return r
    threshold = max(SMALL_SEGMENT_MIN, int(live * SMALL_SEGMENT_FRACTION))
    small = [s["name"] for s in segs if s["docs"] - s.get("deleted", 0) < threshold]
    if len(small) >= MERGE_SMALL_AT:
        r = merge_segments(path, small, progress=progress)
        r["kind"] = "small"
        return r
    return None


def compact_index(path: str, *, progress: Progress = None) -> Optional[dict]:
    """Rewrite the whole index as one segment (drops tombstones)."""
    return maybe_compact(path, progress=progress, force_full=True)


# --------------------------------------------------------------------------
# Convenience
# --------------------------------------------------------------------------


def ensure_index(ost, path: Optional[str] = None, *, rebuild: bool = False, allow_stale: bool = False,
                 progress: Progress = None, include_associated: bool = False, workers: int = DEFAULT_WORKERS,
                 log: Optional[Callable[[str], None]] = None) -> Tuple[Index, dict]:
    """Open the index for ``ost``, building it when missing and updating it when the store changed.

    Returns ``(index, action)`` where ``action`` describes what happened
    (``{"action": "opened" | "built" | "updated" | ...}``).
    """
    path = path or default_index_path(ost.ndb.path)
    valid = os.path.isdir(path) and os.path.exists(os.path.join(path, MANIFEST))
    if valid and not rebuild:
        manifest = read_manifest(path)
        if manifest.get("version") != VERSION:
            valid = False
            if log:
                log("index %s has an old format - rebuilding" % path)
        elif manifest.get("include_associated", False) != include_associated and include_associated:
            valid = False
            if log:
                log("index %s was built without associated messages - rebuilding" % path)
    if valid and not rebuild:
        ix = Index(path)
        if allow_stale or ix.matches_source(ost):
            return ix, {"action": "opened"}
        ix.close()
        if log:
            log("the store changed since the index was built - updating %s" % path)
        stats = update_index(ost, path, progress=progress, workers=workers)
        return Index(path), stats
    if log:
        log("building full-text index %s" % path)
    info = build_index(ost, path, progress=progress, include_associated=include_associated, workers=workers)
    info["action"] = "built"
    return Index(path), info
