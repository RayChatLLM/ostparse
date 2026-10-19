"""
Text normalisation and tokenisation shared by the indexer, the query parser
and the brute-force (scan) evaluator - everything must agree on what a "word"
is or an index hit would not reproduce under verification.

A token is a maximal run of Unicode word characters (``\\w+``) in the
lower-cased text.  Address-bearing fields additionally yield the complete
e-mail address and its domain as tokens, so ``from:bob@example.com`` and
``from:example.com`` match exactly.
"""

from __future__ import annotations

import html as _html
import re
from typing import Callable, Iterable, List, Sequence, Set

WORD_RE = re.compile(r"\w+", re.UNICODE)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.UNICODE)
MAX_TOKEN_LEN = 64

# Match real HTML constructs only. Requiring a letter (or !/ /) right after "<"
# leaves stray maths/code brackets like "price < 100" and "a > b" in the text,
# instead of deleting everything up to the next ">".
_TAG_RE = re.compile(
    r"<(script|style|title)\b[^>]*>.*?</\1\s*>"  # these elements, content and all
    r"|<!--.*?-->"                                # comments (may themselves contain ">")
    r"|</?[a-zA-Z][^>]*>"                          # ordinary start/end tags
    r"|<![^>]*>",                                  # doctype / declarations
    re.I | re.S,
)
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_NL_RE = re.compile(r"\n{3,}")


def normalize(text: str) -> str:
    """Lower-case a string the way the index does (``str.lower`` - stable across Python versions)."""
    return text.lower()


def tokenize(text: str) -> List[str]:
    """Return the word tokens of ``text`` in order (duplicates kept, lower-cased)."""
    if not text:
        return []
    toks = WORD_RE.findall(text.lower())
    if toks and len(max(toks, key=len)) > MAX_TOKEN_LEN:
        toks = [t[:MAX_TOKEN_LEN] for t in toks]
    return toks


def token_set(text: str) -> Set[str]:
    return set(tokenize(text))


def address_extras(low: str) -> Set[str]:
    """Extra tokens of an (already lower-cased) address field: whole addresses, local parts, domains."""
    out: Set[str] = set()
    for addr in EMAIL_RE.findall(low):
        local, domain = addr.rsplit("@", 1)
        out.add(addr[:MAX_TOKEN_LEN])
        out.add(domain[:MAX_TOKEN_LEN])
        out.add(local[:MAX_TOKEN_LEN])
    return out


def address_tokens(text: str) -> Set[str]:
    """Tokens for an address field: words + whole addresses + local parts + domains."""
    if not text:
        return set()
    low = text.lower()
    return set(tokenize(low)) | address_extras(low)


def html_to_text(data: bytes | str) -> str:
    """A small tag stripper for HTML-only bodies (no external dependencies)."""
    if isinstance(data, bytes):
        m = re.search(rb'charset=["\']?([\w-]+)', data[:4096], re.I)
        enc = m.group(1).decode("ascii", "replace") if m else "utf-8"
        try:
            text = data.decode(enc, errors="replace")
        except LookupError:
            text = data.decode("utf-8", errors="replace")
    else:
        text = data
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>|</h[1-6]>", "\n", text)
    text = _TAG_RE.sub(" ", text)
    text = _html.unescape(text)
    text = _WS_RE.sub(" ", text)
    text = _NL_RE.sub("\n\n", text)
    return text.strip()


def is_wildcard(term: str) -> bool:
    return "*" in term or "?" in term


def wildcard_to_regex(term: str) -> str:
    """Translate a ``*``/``?`` wildcard token into a regex fragment (no anchors)."""
    out = []
    for ch in term:
        if ch == "*":
            out.append(r"\w*")
        elif ch == "?":
            out.append(r"\w")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def phrase_regex(tokens: Iterable[str]) -> str:
    """Regex matching ``tokens`` as consecutive words (any non-word run between them)."""
    parts = [wildcard_to_regex(t) if is_wildcard(t) else re.escape(t) for t in tokens]
    return r"(?<!\w)" + r"\W+".join(parts) + r"(?!\w)"


def make_phrase_matcher(tokens: Sequence[str]) -> Callable[[str], bool]:
    r"""Return ``f(text) -> bool`` that is True when the tokens occur as consecutive words.

    When the phrase starts with a literal token the regex is written literal-first
    (``budget\W+review(?!\w)``) and the left word boundary is checked by hand: the
    regex engine can then use its literal-prefix scan, which is ~20x faster than a
    pattern that starts with a look-behind.
    """
    tokens = list(tokens)
    if not tokens:
        return lambda text: False
    if is_wildcard(tokens[0]):
        rx = re.compile(phrase_regex(tokens), re.I)
        return lambda text: rx.search(text) is not None
    parts = [wildcard_to_regex(t) if is_wildcard(t) else re.escape(t) for t in tokens]
    rx = re.compile(r"\W+".join(parts) + r"(?!\w)", re.I)
    word = WORD_RE

    def match(text: str) -> bool:
        pos = 0
        search = rx.search
        while True:
            m = search(text, pos)
            if m is None:
                return False
            s = m.start()
            if s == 0 or not word.match(text, s - 1):
                return True
            pos = s + 1

    return match
