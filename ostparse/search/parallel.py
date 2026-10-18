"""
Worker-process helpers for text verification and full text scans.

The index file is mmapped read-only in every worker, so the operating system
shares one page cache between them; the only data crossing process
boundaries are doc-id lists and a small, picklable predicate description.
"""

from __future__ import annotations

import multiprocessing
import re
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List, Optional, Sequence, Set

from .extract import FIELD_INDEX, FIELD_SEP
from .tokenize import make_phrase_matcher

_INDEX = None
_INDEX_PATH = None


def _index(path: str):
    global _INDEX, _INDEX_PATH
    if _INDEX is None or _INDEX_PATH != path:
        from .index import Index
        _INDEX = Index(path)
        _INDEX_PATH = path
    return _INDEX


def _predicate(spec):
    kind = spec[0]
    if kind == "phrase":
        return make_phrase_matcher(list(spec[1]))
    if kind == "regex":
        rx = re.compile(spec[1], spec[2])
        return lambda text: bool(text) and rx.search(text) is not None
    raise ValueError("unknown predicate spec %r" % (spec,))


def _verify_part(path: str, docs: Sequence[int], cands: Dict[str, Sequence[int]], spec) -> Dict[str, List[int]]:
    ix = _index(path)
    pred = _predicate(spec)
    cand_sets = {f: set(c) for f, c in cands.items()}
    fields = list(cand_sets)
    out: Dict[str, List[int]] = {f: [] for f in fields}
    record = ix.record
    for d in docs:
        parts = record(d).split(FIELD_SEP)
        for f in fields:
            if d in cand_sets[f]:
                i = FIELD_INDEX[f]
                if i < len(parts) and pred(parts[i]):
                    out[f].append(d)
    return out


def _scan_part(path: str, docs: Optional[Sequence[int]], lo: int, hi: int, fields: Sequence[str], spec) -> Dict[str, List[int]]:
    ix = _index(path)
    pred = _predicate(spec)
    idxs = [(f, FIELD_INDEX[f]) for f in fields]
    out: Dict[str, List[int]] = {f: [] for f in fields}
    rng = docs if docs is not None else range(lo, hi)
    for d, rec in ix.iter_records(rng):
        parts = rec.split(FIELD_SEP)
        for f, i in idxs:
            if i < len(parts) and pred(parts[i]):
                out[f].append(d)
    return out


def _pool(workers: int) -> ProcessPoolExecutor:
    try:
        ctx = multiprocessing.get_context("fork")
    except ValueError:
        ctx = multiprocessing.get_context()
    return ProcessPoolExecutor(max_workers=workers, mp_context=ctx)


def _split(seq: Sequence[int], parts: int) -> List[Sequence[int]]:
    n = len(seq)
    parts = max(1, min(parts, n))
    step = (n + parts - 1) // parts
    return [seq[i:i + step] for i in range(0, n, step)]


def verify(path: str, workers: int, union: Sequence[int], cands: Dict[str, Set[int]], spec) -> Dict[str, Set[int]]:
    """Verify ``union`` (sorted doc ids) against ``spec`` in worker processes; returns matches per field."""
    out: Dict[str, Set[int]] = {f: set() for f in cands}
    with _pool(workers) as pool:
        futs = []
        for part in _split(union, workers * 2):
            sub = {f: [d for d in part if d in c] for f, c in cands.items()}
            futs.append(pool.submit(_verify_part, path, part, sub, spec))
        for fut in futs:
            for f, ids in fut.result().items():
                out[f].update(ids)
    return out


def scan(path: str, workers: int, docs: Optional[Sequence[int]], fields: Sequence[str], spec) -> Dict[str, Set[int]]:
    """Scan all docs (or the given ones) for ``spec`` in worker processes."""
    from .index import Index
    out: Dict[str, Set[int]] = {f: set() for f in fields}
    with _pool(workers) as pool:
        futs = []
        if docs is None:
            n = Index(path).n
            step = (n + workers * 2 - 1) // (workers * 2)
            for lo in range(0, n, step):
                futs.append(pool.submit(_scan_part, path, None, lo, min(n, lo + step), list(fields), spec))
        else:
            for part in _split(docs, workers * 2):
                futs.append(pool.submit(_scan_part, path, list(part), 0, 0, list(fields), spec))
        for fut in futs:
            for f, ids in fut.result().items():
                out[f].update(ids)
    return out
