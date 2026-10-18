"""
Turn a regular expression into index constraints.

Any text that matches a regex must contain its *mandatory literals* - the
literal runs on the top-level concatenation path (recursing into groups and
into repeats with a minimum of one).  An alternation ``(foo|bar)`` is
mandatory as a whole when every alternative carries a literal, giving an OR
group.  Each literal is split into word tokens exactly as the index was
built, and becomes

* an exact-term lookup for interior tokens (bounded by non-word characters
  inside the literal) and for tokens pinned by ``^``, ``$``, ``\\b`` anchors,
* a prefix / suffix / substring vocabulary scan for the tokens at the
  literal's edges, where the text may continue with word characters.

The plan is a conjunction of groups; a group is a disjunction of
alternatives; an alternative is a conjunction of constraints.  The candidate
set it yields is a superset of the true matches; the engine verifies every
candidate against the stored text with the real regex.  When a regex has no
usable literal the plan says so and the engine falls back to a vocabulary
scan (if the regex can only match word characters, so a match always lies
inside one token) or to a full scan of the text store.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:  # Python 3.11+
    from re import _parser as sre_parse
    from re import _constants as sre_constants
except ImportError:  # pragma: no cover
    import sre_parse  # type: ignore
    import sre_constants  # type: ignore

from .tokenize import WORD_RE

MIN_EXACT = 1
MIN_PREFIX = 2
MIN_SUFFIX = 3
MIN_SUBSTR = 3

_WORD_CATEGORIES = {sre_constants.CATEGORY_DIGIT, sre_constants.CATEGORY_WORD}
_REPEATS = {sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT}
if hasattr(sre_constants, "POSSESSIVE_REPEAT"):
    _REPEATS.add(sre_constants.POSSESSIVE_REPEAT)
_ATOMIC = getattr(sre_constants, "ATOMIC_GROUP", None)
_START_ANCHORS = {sre_constants.AT_BEGINNING, sre_constants.AT_BEGINNING_STRING, sre_constants.AT_BOUNDARY}
_END_ANCHORS = {sre_constants.AT_END, sre_constants.AT_END_STRING, sre_constants.AT_BOUNDARY}


@dataclass
class Constraint:
    kind: str          # exact | prefix | suffix | substr | bigram | prefix_excl | suffix_excl
    text: str          # *_excl: the expansion without the exact term itself

    def __repr__(self):
        return "%s:%s" % (self.kind, self.text)


@dataclass
class Literal:
    text: str
    anchored_start: bool = False
    anchored_end: bool = False
    joins_previous: bool = False   # separated from the previous literal only by non-word characters


Alternative = List[Constraint]          # all must hold
Group = List[Alternative]               # one must hold


@dataclass
class RegexPlan:
    literals: List[str] = field(default_factory=list)
    groups: List[Group] = field(default_factory=list)
    word_only: bool = False             # regex can only match word characters
    can_match_empty: bool = False
    note: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.groups)


# --------------------------------------------------------------------------
# mandatory literal extraction
# --------------------------------------------------------------------------


def _mandatory(seq) -> List[List[List[Literal]]]:
    """Return groups; each group is a list of alternatives; each alternative a list of mandatory literals.

    Besides anchors, the function tracks the *gap* between two literal runs: when
    everything between them can only match non-word characters (``\\s+``, ``[-/]``,
    ``\\W+`` ...) and is at least one character long, the two literals are adjacent
    words in any matching text, which pins both edge tokens and yields a bigram.
    """
    groups: List[List[List[Literal]]] = []
    cur: List[str] = []
    cur_anchor_start = False
    pending_start_anchor = False
    gap: List = []                  # ops seen since the last literal run ended
    gap_valid = False               # True while the gap can still be a pure non-word gap
    last_literal: Optional[Literal] = None

    def flush(anchored_end: bool = False):
        nonlocal cur, cur_anchor_start, last_literal, gap, gap_valid
        if cur:
            lit = Literal("".join(cur), cur_anchor_start, anchored_end)
            if last_literal is not None and gap_valid:
                ok, min_len = _nonword_only(gap)
                if ok and min_len >= 1 and WORD_RE.fullmatch(last_literal.text[-1:]) and WORD_RE.fullmatch(lit.text[:1]):
                    last_literal.anchored_end = True
                    lit.anchored_start = True
                    lit.joins_previous = True
            groups.append([[lit]])
            last_literal = lit
            gap = []
            gap_valid = True
        cur = []
        cur_anchor_start = False

    for op, av in seq:
        if op is sre_constants.LITERAL:
            if not cur:
                cur_anchor_start = pending_start_anchor
            cur.append(chr(av))
            pending_start_anchor = False
            continue
        if op is sre_constants.AT:
            flush(anchored_end=av in _END_ANCHORS)
            pending_start_anchor = av in _START_ANCHORS
            gap.append((op, av))
            continue
        flush()
        pending_start_anchor = False
        if op is sre_constants.SUBPATTERN:
            sub = _mandatory(av[-1])
            groups.extend(sub)
            gap_valid = gap_valid and not sub and _nonword_only([(op, av)])[0]
            gap.append((op, av))
        elif op in _REPEATS:
            lo, _hi, sub_seq = av
            sub = _mandatory(sub_seq) if lo >= 1 else []
            groups.extend(sub)
            gap_valid = gap_valid and not sub
            gap.append((op, av))
        elif _ATOMIC is not None and op is _ATOMIC:
            groups.extend(_mandatory(av))
            gap_valid = False
        elif op is sre_constants.BRANCH:
            alts: List[List[Literal]] = []
            ok = True
            for alt_seq in av[1]:
                sub_groups = _mandatory(alt_seq)
                lits: List[Literal] = []
                for g in sub_groups:
                    if len(g) == 1:          # nested alternations are dropped (conservative)
                        lits.extend(g[0])
                if not lits:
                    ok = False
                    break
                alts.append(lits)
            if ok and alts:
                groups.append(alts)
            gap_valid = False
        elif op in (sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            gap_valid = False
        else:
            # IN, ANY, NOT_LITERAL, CATEGORY, GROUPREF...: unknown character
            gap.append((op, av))
    flush()
    return groups


_NONWORD_CATEGORIES = {sre_constants.CATEGORY_SPACE, sre_constants.CATEGORY_NOT_WORD}


def _nonword_only(seq) -> Tuple[bool, int]:
    """(True, min_len) when every atom of ``seq`` can only match non-word characters."""
    min_len = 0
    for op, av in seq:
        if op is sre_constants.LITERAL:
            if WORD_RE.fullmatch(chr(av)):
                return False, 0
            min_len += 1
        elif op is sre_constants.IN:
            for iop, iav in av:
                if iop is sre_constants.LITERAL:
                    if WORD_RE.fullmatch(chr(iav)):
                        return False, 0
                elif iop is sre_constants.RANGE:
                    lo, hi = iav
                    if hi - lo > 70000 or any(WORD_RE.fullmatch(chr(c)) for c in range(lo, hi + 1)):
                        return False, 0
                elif iop is sre_constants.CATEGORY:
                    if iav not in _NONWORD_CATEGORIES:
                        return False, 0
                else:
                    return False, 0
            min_len += 1
        elif op is sre_constants.CATEGORY:
            if av not in _NONWORD_CATEGORIES:
                return False, 0
            min_len += 1
        elif op in _REPEATS:
            lo, _hi, sub = av
            ok, sub_min = _nonword_only(sub)
            if not ok:
                return False, 0
            min_len += lo * sub_min
        elif op is sre_constants.SUBPATTERN:
            ok, sub_min = _nonword_only(av[-1])
            if not ok:
                return False, 0
            min_len += sub_min
        elif op is sre_constants.AT:
            continue
        else:
            return False, 0
    return True, min_len


def _range_word_only(lo: int, hi: int) -> bool:
    if hi - lo > 70000:
        return False
    return all(WORD_RE.fullmatch(chr(c)) for c in range(lo, hi + 1))


def _can_match_nonword(seq) -> bool:
    """Conservative: True unless every atom is restricted to word characters."""
    for op, av in seq:
        if op is sre_constants.LITERAL:
            if not WORD_RE.fullmatch(chr(av)):
                return True
        elif op in (sre_constants.NOT_LITERAL, sre_constants.ANY):
            return True
        elif op is sre_constants.IN:
            for iop, iav in av:
                if iop is sre_constants.NEGATE:
                    return True
                if iop is sre_constants.LITERAL:
                    if not WORD_RE.fullmatch(chr(iav)):
                        return True
                elif iop is sre_constants.RANGE:
                    if not _range_word_only(iav[0], iav[1]):
                        return True
                elif iop is sre_constants.CATEGORY:
                    if iav not in _WORD_CATEGORIES:
                        return True
                else:
                    return True
        elif op is sre_constants.CATEGORY:
            if av not in _WORD_CATEGORIES:
                return True
        elif op is sre_constants.SUBPATTERN:
            if _can_match_nonword(av[-1]):
                return True
        elif op in _REPEATS:
            if _can_match_nonword(av[2]):
                return True
        elif op is sre_constants.BRANCH:
            for alt in av[1]:
                if _can_match_nonword(alt):
                    return True
        elif _ATOMIC is not None and op is _ATOMIC:
            if _can_match_nonword(av):
                return True
        elif op in (sre_constants.AT, sre_constants.ASSERT, sre_constants.ASSERT_NOT):
            continue  # zero-width
        else:
            return True
    return False


# --------------------------------------------------------------------------
# literal -> token constraints
# --------------------------------------------------------------------------


def _literal_tokens(lit: Literal) -> List[Tuple[str, bool, bool]]:
    """(token, start_known, end_known) for every word token of a (lower-cased) literal."""
    text = lit.text.lower()
    n = len(text)
    out = []
    for m in WORD_RE.finditer(text):
        s, e = m.start(), m.end()
        out.append((m.group(0), s > 0 or lit.anchored_start, e < n or lit.anchored_end))
    return out


def literal_constraints(lit: Literal) -> List[Constraint]:
    """Split a (lower-cased) mandatory literal into per-token constraints (a conjunction)."""
    out: List[Constraint] = []
    for tok, start_known, end_known in _literal_tokens(lit):
        if start_known and end_known:
            if len(tok) >= MIN_EXACT:
                out.append(Constraint("exact", tok))
        elif start_known:
            if len(tok) >= MIN_PREFIX:
                out.append(Constraint("prefix", tok))
        elif end_known:
            if len(tok) >= MIN_SUFFIX:
                out.append(Constraint("suffix", tok))
        else:
            if len(tok) >= MIN_SUBSTR:
                out.append(Constraint("substr", tok))
    return out


def adjacent_pair_group(x: str, x_whole: bool, y: str, y_whole: bool) -> Optional[Group]:
    """Constraints for two adjacent words where ``x`` may extend to the left / ``y`` to the right.

    Either the exact pair occurs (bigram) or one side is a longer word than the
    literal fragment ("subbudget reviewer" for ``budget\\s+review``); the result
    is a disjunction that is tiny in practice yet never excludes a true match.
    """
    alts: Group = [[Constraint("bigram", x + " " + y)]]
    if not x_whole:
        if len(x) < MIN_SUFFIX:
            return None
        alts.append([Constraint("suffix_excl", x), Constraint("exact" if y_whole else "prefix", y)])
    if not y_whole:
        if len(y) < MIN_PREFIX:
            return None
        alts.append([Constraint("exact" if x_whole else "suffix", x), Constraint("prefix_excl", y)])
    return alts


def literal_pair_groups(lit: Literal) -> List[Group]:
    """One adjacent-pair group per consecutive token pair inside a literal."""
    toks = _literal_tokens(lit)
    groups: List[Group] = []
    for (x, xs, xe), (y, ys, ye) in zip(toks, toks[1:]):
        g = adjacent_pair_group(x, xs, y, ye)   # inner boundaries are known by construction
        if g is not None:
            groups.append(g)
    return groups


def plan(pattern: str, flags: int) -> RegexPlan:
    p = RegexPlan()
    try:
        parsed = sre_parse.parse(pattern, flags)
    except Exception as exc:  # pragma: no cover - the query parser validated the regex already
        p.note = "unparsable: %s" % exc
        return p
    seq = list(parsed)
    try:
        p.can_match_empty = re.compile(pattern, flags).match("") is not None
    except re.error:
        p.can_match_empty = False
    prev_lit: Optional[Literal] = None
    for group in _mandatory(seq):
        alts: Group = []
        complete = True
        for alt in group:
            cons: Alternative = []
            for lit in alt:
                p.literals.append(lit.text.lower())
                cons.extend(literal_constraints(lit))
            if not cons:
                complete = False
                break
            alts.append(cons)
        if complete and alts:
            p.groups.append(alts)
        if len(group) == 1 and len(group[0]) == 1:
            lit = group[0][0]
            p.groups.extend(literal_pair_groups(lit))
            if lit.joins_previous and prev_lit is not None:
                a = _literal_tokens(prev_lit)
                b = _literal_tokens(lit)
                if a and b:
                    g = adjacent_pair_group(a[-1][0], a[-1][1], b[0][0], b[0][2])
                    if g is not None:
                        p.groups.append(g)
            prev_lit = lit
        else:
            prev_lit = None
    p.word_only = not _can_match_nonword(seq)
    return p


def regex_for_wildcard_token(tok: str) -> Tuple[Optional[str], Optional[str]]:
    """For a wildcard token return (prefix, None) if it is a plain prefix pattern, else (None, regex)."""
    if "?" not in tok and tok.count("*") == 1 and tok.endswith("*") and len(tok) > 1:
        return tok[:-1], None
    out = []
    for ch in tok:
        if ch == "*":
            out.append(r"[^\n]*")
        elif ch == "?":
            out.append(r"[^\n]")
        else:
            out.append(re.escape(ch))
    return None, "".join(out)
