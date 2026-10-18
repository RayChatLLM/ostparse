"""
Query evaluation.

:class:`Searcher` runs a parsed query against an :class:`~.index.Index`:
leaves become sets of document ids (postings, sorted-key ranges, vocabulary
scans), boolean nodes combine them, and the leaves that need to look at text
(phrases, regular expressions) are verified against the compressed text store
*after* the cheap leaves have narrowed the candidates.  The OST itself is
never opened for a search - only for exporting or showing a hit in full.

Two modes:

* **exact** - every candidate is verified; ``Result.total`` is the exact
  number of matches and ``Result.docs`` the full set (facets, export).
* **lazy** (``exact=False``) - phrase/regex leaves contribute their candidate
  supersets, the candidates are walked in the requested sort order and each
  one is verified against the stored text until the page is full.  The first
  page of a phrase query over hundreds of thousands of messages then costs a
  few hundred record reads instead of all of them.  ``Result.total`` is
  ``None`` and ``Result.lower_bound`` / ``Result.candidates`` describe what is
  known.  When nothing needed verification the result is exact anyway.

Verification of large candidate sets can be spread over worker processes
(``workers=N``); the text store is mmapped so workers share the page cache.

:class:`ScanSearcher` evaluates the same AST by walking an OST without an
index.  It is the slow, obviously-correct oracle the tests compare against,
and a way to run a one-off query without building an index first.
"""

from __future__ import annotations

import datetime as _dt
import heapq
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .extract import FIELD_INDEX, FIELD_SEP, Document, bigram_key, class_terms, extract
from .index import Index
from .query import (DEFAULT_FIELDS, And, DateRange, MatchAll, Meta, Nid, Node, Not, Or, Phrase, Regex, SizeRange,
                    Term, leaves, parse)
from .regex_plan import plan as regex_plan, regex_for_wildcard_token
from .tokenize import is_wildcard, make_phrase_matcher, phrase_regex, tokenize, wildcard_to_regex


def tokenize_path(path: str) -> Set[str]:
    return set(tokenize(path))

FIELD_WEIGHT = {"subject": 4.0, "from": 3.0, "to": 2.0, "cc": 1.5, "bcc": 1.5, "attach": 2.0, "body": 1.0, "folder": 0.5,
                "class": 0.0, "_meta": 0.0}
MAX_WILDCARD_TERMS = 20000       # expansions beyond this are treated as "no constraint" for phrases
MAX_BIGRAM_EXPANSION = 300       # wildcard tokens expanding to more terms than this get no bigram constraint
PARALLEL_MIN_DOCS = 4000         # verify in worker processes only for candidate sets at least this big
LAZY_MIN_CANDIDATES = 2000       # below this, lazy mode simply verifies everything (it is fast enough)


@dataclass
class Hit:
    doc: int
    nid: int
    folder: str
    subject: str
    sender: str
    to: str
    date: int
    size: int
    flags: int
    attachments: str
    score: float = 0.0
    snippet: str = ""
    snippet_spans: List[Tuple[int, int]] = field(default_factory=list)

    @property
    def date_str(self) -> str:
        if not self.date:
            return "-"
        return _dt.datetime.fromtimestamp(self.date, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M")

    def as_dict(self) -> dict:
        d = {k: getattr(self, k) for k in ("doc", "nid", "folder", "subject", "sender", "to", "date", "size", "flags",
                                             "attachments", "score", "snippet")}
        d["date_iso"] = self.date_str
        d["nid_hex"] = "0x%x" % self.nid
        return d


@dataclass
class Result:
    query: str
    ast: Node
    total: Optional[int]                 # exact number of matches, or None in lazy mode
    hits: List[Hit]
    elapsed: float
    trace: List[str]
    docs: Optional[Set[int]] = None      # the full matching set (exact mode only)
    candidates: int = 0                  # size of the candidate superset that was walked (lazy mode)
    checked: int = 0                     # candidates verified (lazy mode)
    lower_bound: int = 0                 # matches found so far (lazy mode)
    exhausted: bool = True               # lazy mode: every candidate was checked (then lower_bound is exact)

    @property
    def is_exact(self) -> bool:
        return self.total is not None

    def count_str(self) -> str:
        if self.total is not None:
            return "%d match%s" % (self.total, "" if self.total == 1 else "es")
        if self.exhausted:
            return "%d match%s" % (self.lower_bound, "" if self.lower_bound == 1 else "es")
        return "%d+ matches (%d of %d candidates checked)" % (self.lower_bound, self.checked, self.candidates)


class _Deferred:
    """A phrase/regex leaf whose candidates were not verified yet (lazy mode)."""

    __slots__ = ("node", "cands", "pred", "scan_fields")

    def __init__(self, node, cands: Dict[str, Set[int]], pred: Callable[[str], bool], scan_fields: Sequence[str]):
        self.node = node
        self.cands = cands                # field -> candidate docs (verified ones must be in here)
        self.pred = pred
        self.scan_fields = list(scan_fields)   # fields with no index constraint at all (any doc may match)


class Searcher:
    """Evaluate queries against an index."""

    def __init__(self, index: Index, *, now: Optional[_dt.datetime] = None, workers: int = 1):
        self.ix = index
        self.now = now
        self.workers = max(1, workers)
        self.trace: List[str] = []
        self._leaf_hits: List[Tuple[float, Set[int]]] = []
        self._leaf_sets: Dict[int, Set[int]] = {}
        self._deferred: Dict[int, _Deferred] = {}
        self._defer = False

    # ------------------------------------------------------------------ public API

    def search(self, query, *, limit: int = 50, offset: int = 0, sort: str = "date", snippets: bool = True,
               keep_docs: bool = True, exact: bool = True) -> Result:
        t0 = time.time()
        self._reset()
        ast = parse(query, now=self.now) if isinstance(query, str) else query
        qtext = query if isinstance(query, str) else str(query)
        lazy_ok = not exact and sort in ("date", "-date", "newest", "oldest", "+date", "size", "-size", "+size", "nid", "folder")
        self._defer = lazy_ok
        docs = self.ix.live(self.evaluate(ast, None))
        self._defer = False
        if lazy_ok and self._deferred and len(docs) >= LAZY_MIN_CANDIDATES:
            res = self._lazy_result(qtext, ast, docs, limit, offset, sort, snippets)
            self.trace.append("total %.1f ms" % ((time.time() - t0) * 1000))
            res.trace = list(self.trace)
            res.elapsed = time.time() - t0
            return res
        if self._deferred:
            docs = self._verify_deferred(ast, docs)
        total = len(docs)
        ids = self._rank(docs, sort, limit + offset)[offset:offset + limit]
        hits = [self._hit(d) for d in ids]
        if sort == "relevance":
            scores = self._scores(ids)
            for h in hits:
                h.score = scores.get(h.doc, 0.0)
        if snippets and hits:
            hl = self.highlighter(ast)
            for h in hits:
                h.snippet, h.snippet_spans = self.snippet(h.doc, hl)
        self.trace.append("total %.1f ms" % ((time.time() - t0) * 1000))
        return Result(qtext, ast, total, hits, time.time() - t0, list(self.trace), docs if keep_docs else None,
                      candidates=total, checked=total, lower_bound=total)

    def count(self, query) -> int:
        ast = parse(query, now=self.now) if isinstance(query, str) else query
        return len(self.matching_docs(ast))

    def matching_docs(self, query) -> Set[int]:
        ast = parse(query, now=self.now) if isinstance(query, str) else query
        self._reset()
        return self.ix.live(self.evaluate(ast, None))

    def _reset(self):
        self.trace = []
        self._leaf_hits = []
        self._leaf_sets = {}
        self._deferred = {}
        self._defer = False

    # ------------------------------------------------------------------ lazy mode

    def _truth(self, node: Node, d: int, parts: Optional[List[str]]) -> bool:
        """Is doc ``d`` a true match of ``node``?  Uses recorded leaf sets and verifies deferred leaves."""
        if isinstance(node, And):
            return all(self._truth(c, d, parts) for c in node.children)
        if isinstance(node, Or):
            return any(self._truth(c, d, parts) for c in node.children)
        if isinstance(node, Not):
            return not self._truth(node.child, d, parts)
        if isinstance(node, MatchAll):
            return True
        df = self._deferred.get(id(node))
        if df is not None:
            if parts is None:
                return False
            for f, cands in df.cands.items():
                if d in cands:
                    i = FIELD_INDEX[f]
                    if i < len(parts) and df.pred(parts[i]):
                        return True
            for f in df.scan_fields:
                i = FIELD_INDEX[f]
                if i < len(parts) and df.pred(parts[i]):
                    return True
            return False
        s = self._leaf_sets.get(id(node))
        if s is None:  # leaf evaluated only inside a Not (exact) - recompute cheaply for this doc
            return d in self.evaluate(node, {d})
        return d in s

    def _lazy_result(self, qtext: str, ast: Node, superset: Set[int], limit: int, offset: int, sort: str, snippets: bool) -> Result:
        order = self._rank(superset, sort, len(superset))
        want = limit + offset
        found: List[int] = []
        checked = 0
        record = self.ix.record
        for d in order:
            checked += 1
            parts = record(d).split(FIELD_SEP)
            if self._truth(ast, d, parts):
                found.append(d)
                if len(found) >= want:
                    break
        exhausted = checked >= len(order)
        ids = found[offset:offset + limit]
        hits = [self._hit(d) for d in ids]
        if snippets and hits:
            hl = self.highlighter(ast)
            for h in hits:
                h.snippet, h.snippet_spans = self.snippet(h.doc, hl)
        self.trace.append("lazy: %d candidates, %d checked, %d matches found%s" % (
            len(order), checked, len(found), " (all candidates checked)" if exhausted else ""))
        return Result(qtext, ast, None, hits, 0.0, [], None, candidates=len(order), checked=checked,
                      lower_bound=len(found), exhausted=exhausted)

    def _verify_deferred(self, ast: Node, superset: Set[int]) -> Set[int]:
        """Exact evaluation after a deferred pass (used when lazy mode was not applicable after all)."""
        out = set()
        record = self.ix.record
        for d in sorted(superset):
            parts = record(d).split(FIELD_SEP)
            if self._truth(ast, d, parts):
                out.add(d)
        return out

    # ------------------------------------------------------------------ ranking

    def _rank(self, docs: Set[int], sort: str, n: int) -> List[int]:
        ix = self.ix
        if not docs or n <= 0:
            return []
        if sort in ("date", "-date", "newest"):
            key = ix.date
            return heapq.nlargest(n, docs, key=key) if n < len(docs) // 4 else sorted(docs, key=key, reverse=True)[:n]
        if sort in ("oldest", "+date"):
            return heapq.nsmallest(n, docs, key=ix.date)
        if sort in ("size", "-size"):
            return heapq.nlargest(n, docs, key=ix.size.__getitem__)
        if sort == "+size":
            return heapq.nsmallest(n, docs, key=ix.size.__getitem__)
        if sort == "relevance":
            scores = self._scores(docs)
            return heapq.nlargest(n, docs, key=lambda d: (scores.get(d, 0.0), ix.date(d)))
        if sort in ("folder", "nid"):
            return heapq.nsmallest(n, docs)
        if sort in ("subject", "from"):
            ids = heapq.nlargest(min(len(docs), max(n * 20, 2000)), docs, key=ix.date)
            fld = "subject" if sort == "subject" else "from"
            return sorted(ids, key=lambda d: ix.fields(d)[fld].lower())[:n]
        raise ValueError("unknown sort order %r" % sort)

    def _scores(self, docs: Iterable[int]) -> Dict[int, float]:
        scores: Dict[int, float] = {}
        if not self._leaf_hits:
            return scores
        for d in docs:
            s = 0.0
            for w, hit_set in self._leaf_hits:
                if d in hit_set:
                    s += w
            scores[d] = s
        return scores

    def _hit(self, doc: int) -> Hit:
        f = self.ix.fields(doc)
        return Hit(doc=doc, nid=self.ix.nid[doc], folder=self.ix.folder_path(doc), subject=f["subject"], sender=f["from"],
                   to=f["to"], date=self.ix.date(doc), size=self.ix.size[doc], flags=self.ix.flags[doc],
                   attachments=f["attach"])

    # ------------------------------------------------------------------ snippets

    def highlighter(self, ast: Node) -> List["re.Pattern"]:
        pats = []
        for leaf in leaves(ast):
            if isinstance(leaf, Term):
                if leaf.field in ("class", "folder"):
                    continue
                body = wildcard_to_regex(leaf.text) if is_wildcard(leaf.text) else re.escape(leaf.text)
                pats.append(re.compile(r"(?<!\w)" + body + r"(?!\w)", re.I))
            elif isinstance(leaf, Phrase):
                if leaf.field == "folder":
                    continue
                pats.append(re.compile(phrase_regex(leaf.tokens), re.I))
            elif isinstance(leaf, Regex):
                try:
                    pats.append(re.compile(leaf.pattern, leaf.flags))
                except re.error:
                    pass
        return pats

    def snippet(self, doc: int, patterns: List["re.Pattern"], width: int = 160) -> Tuple[str, List[Tuple[int, int]]]:
        f = self.ix.fields(doc)
        best = None
        for fld in ("body", "subject", "attach", "from", "to", "cc", "bcc"):
            text = f[fld]
            if not text:
                continue
            for p in patterns:
                m = p.search(text)
                if m and (best is None or m.start() < best[1]):
                    best = (fld, m.start(), m.end(), text)
            if best is not None:
                break
        if best is None:
            text = f["body"] or f["subject"]
            window = " ".join(text[:width].split())
            return window, []
        fld, s, e, text = best
        half = max(20, (width - (e - s)) // 2)
        a = max(0, s - half)
        b = min(len(text), e + half)
        window = text[a:b]
        spans = []
        for p in patterns:
            for m in p.finditer(window):
                if m.end() > m.start():
                    spans.append((m.start(), m.end()))
        spans.sort()
        merged: List[Tuple[int, int]] = []
        for s2, e2 in spans:
            if merged and s2 <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e2))
            else:
                merged.append((s2, e2))
        prefix = "…" if a > 0 else ""
        suffix = "…" if b < len(text) else ""
        window = window.replace("\r", " ").replace("\n", " ")
        if prefix:
            merged = [(s2 + 1, e2 + 1) for s2, e2 in merged]
        return prefix + window + suffix, merged

    # ------------------------------------------------------------------ facets

    def facets(self, docs: Set[int], kind: str, top: int = 20) -> List[Tuple[str, int]]:
        ix = self.ix
        c: Counter = Counter()
        if kind == "folder":
            folder = ix.folder
            for d in docs:
                c[folder[d]] += 1
            paths: Counter = Counter()
            for k, v in c.items():
                paths[ix.folders[k]["path"]] += v
            return paths.most_common(top)
        if kind in ("from", "sender"):
            sender, names = ix.sender, ix.senders
            for d in docs:
                c[sender[d]] += 1
            return [(names[k] or "(none)", v) for k, v in c.most_common(top)]
        if kind == "domain":
            sender, names = ix.sender, ix.senders
            for d in docs:
                s = names[sender[d]]
                m = re.search(r"@([\w.-]+)", s)
                c[m.group(1).lower() if m else "(none)"] += 1
            return c.most_common(top)
        if kind in ("year", "month", "day", "weekday", "hour"):
            for d in docs:
                ts = ix.date(d)
                if not ts:
                    c["(no date)"] += 1
                    continue
                dt = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
                if kind == "year":
                    c[str(dt.year)] += 1
                elif kind == "month":
                    c[dt.strftime("%Y-%m")] += 1
                elif kind == "day":
                    c[dt.strftime("%Y-%m-%d")] += 1
                elif kind == "weekday":
                    c[dt.strftime("%A")] += 1
                else:
                    c[dt.strftime("%H:00")] += 1
            return sorted(c.items(), key=lambda kv: kv[0])[:top] if kind != "weekday" else c.most_common(top)
        if kind in ("ext", "extension", "class", "flag", "has", "is", "imp", "importance"):
            voc = ix.vocab["class" if kind == "class" else "_meta"]
            prefix = {"ext": "ext:", "extension": "ext:", "has": "has:", "is": "is:", "imp": "imp:", "importance": "imp:",
                      "flag": ""}.get(kind, "")
            for i in voc.prefix_ids(prefix) if prefix else voc.all_ids():
                n = len(docs & voc.postings_set(i))
                if n:
                    c[voc.term_str(i)[len(prefix):]] += n
            return c.most_common(top)
        if kind == "size":
            buckets = [("<10KB", 0, 10 << 10), ("10-100KB", 10 << 10, 100 << 10), ("100KB-1MB", 100 << 10, 1 << 20),
                       ("1-10MB", 1 << 20, 10 << 20), (">10MB", 10 << 20, None)]
            for d in docs:
                sz = ix.size[d]
                for name, lo, hi in buckets:
                    if sz >= lo and (hi is None or sz < hi):
                        c[name] += 1
                        break
            return [(name, c[name]) for name, _lo, _hi in buckets if c[name]]
        raise ValueError("unknown facet %r (folder, from, domain, year, month, day, weekday, hour, ext, class, has, is, importance, size)" % kind)

    # ------------------------------------------------------------------ evaluation

    @staticmethod
    def _cost(node: Node) -> int:
        if isinstance(node, (Nid, MatchAll)):
            return 0
        if isinstance(node, Meta):
            return 1
        if isinstance(node, (DateRange, SizeRange)):
            return 2
        if isinstance(node, Term):
            return 3 if is_wildcard(node.text) else 2
        if isinstance(node, Phrase):
            return 5
        if isinstance(node, Regex):
            return 7
        if isinstance(node, Not):
            return Searcher._cost(node.child) + 1
        if isinstance(node, (And, Or)):
            return max((Searcher._cost(c) for c in node.children), default=0)
        return 4

    def evaluate(self, node: Node, restrict: Optional[Set[int]]) -> Set[int]:
        """Return the docs matching ``node`` (within ``restrict`` when given).

        In deferral mode phrase/regex leaves return unverified candidate supersets
        and register themselves in ``self._deferred``.
        """
        if isinstance(node, And):
            return self._eval_and(node, restrict)
        if isinstance(node, Or):
            out: Set[int] = set()
            for c in node.children:
                out |= self.evaluate(c, restrict)
            return out
        if isinstance(node, Not):
            universe = restrict if restrict is not None else self.ix.all_docs()
            saved = self._defer
            self._defer = False          # the complement of a superset is not a superset
            try:
                return universe - self.evaluate(node.child, restrict)
            finally:
                self._defer = saved
        if isinstance(node, MatchAll):
            return set(restrict) if restrict is not None else self.ix.all_docs()
        if isinstance(node, (Term, Phrase, Regex)) and node.field == "folder":
            s = self._eval_folder(node, restrict)
        elif isinstance(node, Term):
            s = self._eval_term(node, restrict)
        elif isinstance(node, Phrase):
            s = self._eval_phrase(node, restrict)
        elif isinstance(node, Regex):
            s = self._eval_regex(node, restrict)
        elif isinstance(node, DateRange):
            key = {"received": "recv", "sent": "sent"}.get(node.kind)
            if key:
                s = self.ix.range_docs(key, node.start, node.end)
            else:  # "date": sent, falling back to received for messages without a submit time
                s = self.ix.range_docs("sent", node.start, node.end)
                r = self.ix.range_docs("recv", node.start, node.end)
                sent = self.ix.sent
                s |= {d for d in r if not sent[d]}
            if restrict is not None:
                s &= restrict
        elif isinstance(node, SizeRange):
            s = self.ix.range_docs("size", node.start, node.end)
            if restrict is not None:
                s &= restrict
        elif isinstance(node, Meta):
            s = self._postings("_meta", node.term, restrict)
        elif isinstance(node, Nid):
            d = self.ix.doc_by_nid(node.nid)
            s = {d} if d is not None else set()
            if restrict is not None:
                s &= restrict
        else:
            raise TypeError("unknown node %r" % (node,))
        if id(node) not in self._deferred:
            prev = self._leaf_sets.get(id(node))
            # a leaf may be evaluated several times with different restrictions; keep the widest result
            self._leaf_sets[id(node)] = s if (prev is None or restrict is None) else (prev | s)
        return s

    def _eval_and(self, node: And, restrict: Optional[Set[int]]) -> Set[int]:
        positives = sorted((c for c in node.children if not isinstance(c, Not)), key=self._cost)
        negatives = [c for c in node.children if isinstance(c, Not)]
        cur = restrict
        for c in positives:
            cur = self.evaluate(c, cur)
            if not cur:
                return set()
        if cur is None:
            cur = self.ix.all_docs()
        for c in negatives:
            cur = cur & self.evaluate(c, cur)
            if not cur:
                break
        return cur

    # -- leaves ----------------------------------------------------------------------------

    def _fields(self, fld: Optional[str]) -> Tuple[str, ...]:
        if fld is None:
            return DEFAULT_FIELDS
        return (fld,)

    def _postings(self, fld: str, term: str, restrict: Optional[Set[int]]) -> Set[int]:
        voc = self.ix.vocab.get(fld)
        if voc is None:
            return set()
        s = voc.docs(term)
        return s & restrict if restrict is not None else s

    def _expand_wildcard(self, fld: str, pattern: str) -> List[int]:
        voc = self.ix.vocab[fld]
        prefix, rx = regex_for_wildcard_token(pattern)
        if prefix is not None:
            return voc.prefix_ids(prefix)
        return voc.scan_regex(re.compile(rx), whole=True)

    def _union_postings(self, fld: str, term_ids: Sequence[int], restrict: Optional[Set[int]]) -> Set[int]:
        out = self.ix.vocab[fld].docs_for_ids(term_ids)
        return out & restrict if restrict is not None else out

    def _bigram_postings(self, fld: str, a: str, b: str, restrict: Optional[Set[int]]) -> Optional[Set[int]]:
        """Docs whose field contains the adjacent word pair ``a b`` (None when no bigram index exists)."""
        voc = self.ix.vocab.get("_bi_" + fld)
        if voc is None:
            return None
        s = voc.docs(bigram_key(a, b))
        return s & restrict if restrict is not None else s

    def _eval_folder(self, node, restrict: Optional[Set[int]]) -> Set[int]:
        """Folder-scoped leaves are decided on the (small) folder table; docs follow by range."""
        if isinstance(node, Term):
            if is_wildcard(node.text):
                prefix, rx_src = regex_for_wildcard_token(node.text)
                if prefix is not None:
                    pred = lambda path: any(t.startswith(prefix) for t in tokenize_path(path))  # noqa: E731
                else:
                    trx = re.compile("^(?:%s)$" % rx_src)
                    pred = lambda path: any(trx.match(t) for t in tokenize_path(path))  # noqa: E731
            else:
                pred = lambda path: node.text in tokenize_path(path)  # noqa: E731
        elif isinstance(node, Phrase):
            pred = make_phrase_matcher(node.tokens)
        else:
            rx = re.compile(node.pattern, node.flags)
            pred = lambda path: rx.search(path) is not None  # noqa: E731
        nids = [f["nid"] for f in self.ix.folders if pred(f["path"])]
        out = self.ix.folder_docs(nids) if nids else set()
        if restrict is not None:
            out &= restrict
        self.trace.append("folder %s -> %d folders, %d docs" % (node, len(nids), len(out)))
        return out

    def _eval_term(self, node: Term, restrict: Optional[Set[int]]) -> Set[int]:
        t0 = time.time()
        out: Set[int] = set()
        for fld in self._fields(node.field):
            if fld not in self.ix.vocab:
                continue
            if is_wildcard(node.text):
                ids = self._expand_wildcard(fld, node.text)
                s = self._union_postings(fld, ids, restrict)
                self.trace.append("term %s:%s -> %d terms, %d docs" % (fld, node.text, len(ids), len(s)))
            else:
                s = self._postings(fld, node.text, restrict)
            if s:
                self._leaf_hits.append((FIELD_WEIGHT.get(fld, 1.0), s))
                out |= s
        self.trace.append("term %s -> %d docs (%.1f ms)" % (node, len(out), (time.time() - t0) * 1000))
        return out

    # -- verification -----------------------------------------------------------------------

    def _verify(self, cands: Dict[str, Set[int]], pred: Callable[[str], bool], spec=None) -> Dict[str, Set[int]]:
        """Check candidate docs' stored text, one record read per document; returns matches per field.

        ``spec`` (a picklable description of the predicate) enables worker processes.
        """
        out: Dict[str, Set[int]] = {f: set() for f in cands}
        fields = [f for f, c in cands.items() if c]
        if not fields:
            return out
        union: Set[int] = set()
        for f in fields:
            union |= cands[f]
        if self.workers > 1 and spec is not None and len(union) >= PARALLEL_MIN_DOCS:
            from . import parallel
            return parallel.verify(self.ix.path, self.workers, sorted(union), {f: cands[f] for f in fields}, spec)
        record = self.ix.record
        if len(fields) == 1:
            f = fields[0]
            idx = FIELD_INDEX[f]
            hits = out[f]
            for d in sorted(union):
                parts = record(d).split(FIELD_SEP)
                if idx < len(parts) and pred(parts[idx]):
                    hits.add(d)
            return out
        for d in sorted(union):
            parts = record(d).split(FIELD_SEP)
            for f in fields:
                if d in cands[f]:
                    idx = FIELD_INDEX[f]
                    if idx < len(parts) and pred(parts[idx]):
                        out[f].add(d)
        return out

    def _finish_text_leaf(self, node, cands_by_field: Dict[str, Set[int]], pred, spec, scan_fields: Sequence[str],
                          restrict: Optional[Set[int]], weight_mul: float = 1.5) -> Set[int]:
        """Either defer (lazy mode) or verify the candidates of a phrase/regex leaf now."""
        if self._defer:
            superset: Set[int] = set()
            for c in cands_by_field.values():
                superset |= c
            if scan_fields:
                superset = set(restrict) if restrict is not None else self.ix.all_docs()
            self._deferred[id(node)] = _Deferred(node, cands_by_field, pred, scan_fields)
            return superset
        out: Set[int] = set()
        if scan_fields:
            out |= self._text_scan(node, pred, spec, scan_fields, restrict)
        for fld, h in self._verify(cands_by_field, pred, spec).items():
            if h:
                self._leaf_hits.append((FIELD_WEIGHT.get(fld, 1.0) * weight_mul, h))
                out |= h
        return out

    def _text_scan(self, node, pred, spec, scan_fields: Sequence[str], restrict: Optional[Set[int]]) -> Set[int]:
        """Full pass over the text store for fields that no index constraint could narrow."""
        t0 = time.time()
        docs = sorted(restrict) if restrict is not None else None
        n_docs = len(docs) if docs is not None else self.ix.n
        if self.workers > 1 and spec is not None and n_docs >= PARALLEL_MIN_DOCS:
            from . import parallel
            hits_by_field = parallel.scan(self.ix.path, self.workers, docs, list(scan_fields), spec)
        else:
            hits_by_field = {f: set() for f in scan_fields}
            idxs = [(f, FIELD_INDEX[f]) for f in scan_fields]
            for d, rec in self.ix.iter_records(docs):
                parts = rec.split(FIELD_SEP)
                for f, i in idxs:
                    if i < len(parts) and pred(parts[i]):
                        hits_by_field[f].add(d)
        out: Set[int] = set()
        for f, h in hits_by_field.items():
            if h:
                self._leaf_hits.append((FIELD_WEIGHT.get(f, 1.0) * 1.5, h))
                out |= h
        self.trace.append("%s: full text scan of %d docs for %s (%.1f ms)" % (node, n_docs, ",".join(scan_fields), (time.time() - t0) * 1000))
        return out

    # -- phrases ------------------------------------------------------------------------------

    def _eval_phrase(self, node: Phrase, restrict: Optional[Set[int]]) -> Set[int]:
        t0 = time.time()
        pred = make_phrase_matcher(node.tokens)
        spec = ("phrase", tuple(node.tokens))
        cands_by_field: Dict[str, Set[int]] = {}
        scan_fields: List[str] = []
        for fld in self._fields(node.field):
            if fld not in self.ix.vocab:
                continue
            voc = self.ix.vocab[fld]
            cands: Optional[Set[int]] = restrict
            constrained = False
            # adjacent pairs first: they are the most selective constraint.  A wildcard token next to
            # a literal one is expanded through the vocabulary when the expansion is small.
            for a, b in zip(node.tokens, node.tokens[1:]):
                wa, wb = is_wildcard(a), is_wildcard(b)
                if wa and wb:
                    continue
                if wa or wb:
                    wild, lit = (a, b) if wa else (b, a)
                    if not wild.strip("*?"):
                        continue
                    ids = self._expand_wildcard(fld, wild)
                    if not ids or len(ids) > MAX_BIGRAM_EXPANSION:
                        continue
                    s: Set[int] = set()
                    for w in {voc.term_str(i) for i in ids}:
                        bs = self._bigram_postings(fld, w, lit, cands) if wa else self._bigram_postings(fld, lit, w, cands)
                        if bs is None:
                            s = None
                            break
                        s |= bs
                    if s is None:
                        break
                else:
                    s = self._bigram_postings(fld, a, b, cands)
                    if s is None:
                        break
                cands = s
                constrained = True
                if not cands:
                    break
            if cands is None or cands:
                for tok in node.tokens:
                    if is_wildcard(tok):
                        if not tok.strip("*?"):
                            continue          # a bare "*" / "?" constrains nothing
                        ids = self._expand_wildcard(fld, tok)
                        if len(ids) > MAX_WILDCARD_TERMS:
                            continue
                        s = self._union_postings(fld, ids, cands)
                    else:
                        s = voc.docs(tok)
                        if cands is not None:
                            s &= cands
                    cands = s
                    constrained = True
                    if not cands:
                        break
            if not constrained:
                scan_fields.append(fld)
            elif cands:
                cands_by_field[fld] = cands
        ncand = sum(len(c) for c in cands_by_field.values())
        out = self._finish_text_leaf(node, cands_by_field, pred, spec, scan_fields, restrict)
        self.trace.append("phrase %s -> %d candidates, %d docs%s (%.1f ms)" % (
            node, ncand, len(out), " [deferred]" if self._defer else "", (time.time() - t0) * 1000))
        return out

    # -- regular expressions ------------------------------------------------------------------------

    def _regex_candidates(self, fld: str, node: Regex, restrict: Optional[Set[int]]) -> Tuple[Optional[Set[int]], str]:
        """Candidate docs for a regex in one field, or None when a full scan is required."""
        voc = self.ix.vocab[fld]
        p = regex_plan(node.pattern, node.flags)
        if p.usable:
            cands: Optional[Set[int]] = restrict
            for group in p.groups:
                gset: Set[int] = set()
                for alt in group:
                    aset: Optional[Set[int]] = cands
                    for con in alt:
                        if con.kind == "bigram":
                            a, b = con.text.split(" ", 1)
                            s = self._bigram_postings(fld, a, b, aset)
                            if s is None:
                                continue
                            aset = s
                            if not aset:
                                break
                            continue
                        if con.kind == "exact":
                            ids = voc.lookup_ids(con.text)
                        elif con.kind in ("prefix", "prefix_excl"):
                            ids = voc.prefix_ids(con.text)
                        elif con.kind in ("suffix", "suffix_excl"):
                            ids = voc.scan_suffix(con.text)
                        else:
                            ids = voc.scan_substring(con.text)
                        if con.kind.endswith("_excl"):
                            ex = set(voc.lookup_ids(con.text))
                            if ex:
                                ids = [j for j in ids if j not in ex]
                        s = self._union_postings(fld, ids, aset)
                        aset = s
                        if not aset:
                            break
                    gset |= aset or set()
                cands = gset
                if not cands:
                    break
            return cands, "literals %s" % ",".join(p.literals[:4])
        if p.word_only and not p.can_match_empty:
            rx = re.compile(node.pattern, node.flags)
            ids = voc.scan_regex(rx, whole=False)
            return self._union_postings(fld, ids, restrict), "vocabulary scan (%d terms)" % len(ids)
        return None, "full scan"

    def _eval_regex(self, node: Regex, restrict: Optional[Set[int]]) -> Set[int]:
        t0 = time.time()
        rx = re.compile(node.pattern, node.flags)
        pred = lambda text: bool(text) and rx.search(text) is not None  # noqa: E731
        spec = ("regex", node.pattern, node.flags)
        fields = [f for f in self._fields(node.field) if f in self.ix.vocab]
        cands_by_field: Dict[str, Set[int]] = {}
        scan_fields: List[str] = []
        hows = []
        for fld in fields:
            cands, how = self._regex_candidates(fld, node, restrict)
            hows.append("%s=%s" % (fld, how))
            if cands is None:
                scan_fields.append(fld)
            elif cands:
                cands_by_field[fld] = cands
        out = self._finish_text_leaf(node, cands_by_field, pred, spec, scan_fields, restrict)
        self.trace.append("regex %s -> %d docs%s (%.1f ms; %s)" % (
            node, len(out), " [deferred]" if self._defer else "", (time.time() - t0) * 1000, "; ".join(hows)))
        return out


# --------------------------------------------------------------------------
# Brute-force oracle
# --------------------------------------------------------------------------


class ScanSearcher:
    """Evaluate a query by walking the OST (no index).  Slow; exact by construction."""

    def __init__(self, ost, *, now: Optional[_dt.datetime] = None):
        self.ost = ost
        self.now = now

    def documents(self) -> Iterable[Tuple[int, Document]]:
        """Every message reachable through the folder tree, read from its property context."""
        fid = 0
        for folder, _depth in self.ost.walk():
            tc = folder.contents_table()
            if tc is not None:
                for row in tc.iter_rows():
                    try:
                        yield fid, extract(self.ost.message(row.rowid), fid, folder.path)
                    except Exception:
                        continue
            fid += 1

    def matches(self, node: Node, doc: Document, toks: Optional[Dict[str, Set[str]]] = None) -> bool:
        if toks is None:
            toks = doc.all_tokens()
            toks["_meta"] = set(doc.meta)
            toks["class"] = class_terms(doc.message_class)
        if isinstance(node, And):
            return all(self.matches(c, doc, toks) for c in node.children)
        if isinstance(node, Or):
            return any(self.matches(c, doc, toks) for c in node.children)
        if isinstance(node, Not):
            return not self.matches(node.child, doc, toks)
        if isinstance(node, MatchAll):
            return True
        if isinstance(node, Term):
            fields = DEFAULT_FIELDS if node.field is None else (node.field,)
            if is_wildcard(node.text):
                prefix, rx_src = regex_for_wildcard_token(node.text)
                if prefix is not None:
                    return any(any(t.startswith(prefix) for t in toks.get(f, ())) for f in fields)
                rx = re.compile("^(?:%s)$" % rx_src)
                return any(any(rx.match(t) for t in toks.get(f, ())) for f in fields)
            return any(node.text in toks.get(f, ()) for f in fields)
        if isinstance(node, Phrase):
            fields = DEFAULT_FIELDS if node.field is None else (node.field,)
            pred = make_phrase_matcher(node.tokens)
            return any(pred(doc.texts.get(f, "")) for f in fields)
        if isinstance(node, Regex):
            fields = DEFAULT_FIELDS if node.field is None else (node.field,)
            rx = re.compile(node.pattern, node.flags)
            return any(rx.search(doc.texts.get(f, "")) for f in fields)
        if isinstance(node, DateRange):
            if node.kind == "received":
                v = doc.received
            elif node.kind == "sent":
                v = doc.sent
            else:
                v = doc.sent or doc.received
            if not v:
                return False
            return (node.start is None or v >= node.start) and (node.end is None or v < node.end)
        if isinstance(node, SizeRange):
            v = doc.size
            return (node.start is None or v >= node.start) and (node.end is None or v < node.end)
        if isinstance(node, Meta):
            return node.term in doc.meta
        if isinstance(node, Nid):
            return doc.nid == node.nid
        raise TypeError("unknown node %r" % (node,))

    def search(self, query, *, limit: Optional[int] = None) -> List[Document]:
        ast = parse(query, now=self.now) if isinstance(query, str) else query
        out = []
        for _fid, doc in self.documents():
            if self.matches(ast, doc):
                out.append(doc)
                if limit and len(out) >= limit:
                    break
        return out

    def matching_nids(self, query) -> Set[int]:
        return {d.nid for d in self.search(query)}
