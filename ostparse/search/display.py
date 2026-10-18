"""Terminal rendering of search results (shared by the CLI and the interactive shell)."""

from __future__ import annotations

import json
import os
import shutil
import sys
from typing import Iterable, Optional, Sequence, Tuple

from .engine import Result

BOLD = "\x1b[1m"
DIM = "\x1b[2m"
REV = "\x1b[7m"
RESET = "\x1b[0m"
YELLOW = "\x1b[33m"
CYAN = "\x1b[36m"
GREEN = "\x1b[32m"


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def term_width(default: int = 120) -> int:
    try:
        return shutil.get_terminal_size((default, 40)).columns
    except Exception:
        return default


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d%s" % (n, unit) if unit == "B" else "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%d" % n


def _clip(s: str, n: int) -> str:
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def highlight(text: str, spans: Sequence[Tuple[int, int]], color: bool) -> str:
    if not color or not spans:
        return text
    out = []
    pos = 0
    for s, e in spans:
        out.append(text[pos:s])
        out.append(BOLD + YELLOW + text[s:e] + RESET)
        pos = e
    out.append(text[pos:])
    return "".join(out)


def format_hits(res: Result, *, start: int = 1, color: Optional[bool] = None, snippets: bool = True, width: Optional[int] = None,
                show_folder: bool = True) -> str:
    color = use_color() if color is None else color
    width = width or term_width()
    lines = []
    c = (lambda code, s: code + s + RESET) if color else (lambda code, s: s)
    for i, h in enumerate(res.hits, start):
        date = h.date_str[:16]
        sender = _clip(h.sender or "-", 28)
        size = human_size(h.size)
        flags = ("A" if h.flags & 0x02 else " ") + (" " if h.flags & 0x01 else "N")
        head = "%s %s %s  %s  %-28s  %s" % (c(DIM, "%4d." % i), c(CYAN, "0x%06x" % h.nid), c(DIM, date), flags, sender, c(BOLD, _clip(h.subject or "(no subject)", max(20, width - 90))))
        lines.append(head)
        meta = []
        if show_folder:
            meta.append(h.folder)
        meta.append(size)
        if h.attachments:
            meta.append("📎 " + _clip(h.attachments, 60))
        if h.score:
            meta.append("score %.1f" % h.score)
        lines.append("      " + c(DIM, "  ·  ".join(meta)))
        if snippets and h.snippet:
            snip = h.snippet
            if len(snip) > width - 8:
                snip = snip[: width - 9] + "…"
                spans = [(s, min(e, len(snip))) for s, e in h.snippet_spans if s < len(snip)]
            else:
                spans = h.snippet_spans
            lines.append("      " + highlight(snip, spans, color))
    return "\n".join(lines)


def format_summary(res: Result, shown: int, *, color: Optional[bool] = None) -> str:
    color = use_color() if color is None else color
    c = (lambda code, s: code + s + RESET) if color else (lambda code, s: s)
    note = ""
    if not res.is_exact and not res.exhausted:
        note = "  - stopped once the page was full; use --exact / :count for the total"
    return c(GREEN, res.count_str()) + c(DIM, "  (showing %d, %.1f ms)%s" % (shown, res.elapsed * 1000, note))


def hits_json(res: Result) -> str:
    return json.dumps({"query": res.query, "total": res.total, "exact": res.is_exact, "lower_bound": res.lower_bound,
                       "candidates": res.candidates, "checked": res.checked, "elapsed_ms": round(res.elapsed * 1000, 2),
                       "hits": [h.as_dict() for h in res.hits]}, ensure_ascii=False, indent=2, default=str)


def format_facets(facets: Iterable[Tuple[str, int]], kind: str, total: int, *, color: Optional[bool] = None) -> str:
    color = use_color() if color is None else color
    c = (lambda code, s: code + s + RESET) if color else (lambda code, s: s)
    rows = list(facets)
    if not rows:
        return "(no %s facets)" % kind
    w = max(len(str(k)) for k, _ in rows)
    out = [c(BOLD, "%s" % kind)]
    for k, n in rows:
        bar = "█" * int(40 * n / max(1, total))
        out.append("  %-*s %7d  %s" % (w, k, n, c(DIM, bar)))
    return "\n".join(out)


def format_message(msg, *, max_body: int = 4000, color: Optional[bool] = None) -> str:
    """Render one message (headers + body + attachment list) for the shell's :show."""
    color = use_color() if color is None else color
    c = (lambda code, s: code + s + RESET) if color else (lambda code, s: s)
    out = []
    out.append(c(BOLD, "Subject: ") + (msg.subject or "(no subject)"))
    out.append(c(BOLD, "From:    ") + ("%s <%s>" % (msg.sender_name, msg.sender_email) if msg.sender_email else msg.sender_name))
    recips = msg.recipients()
    for kind, label in (("to", "To:      "), ("cc", "Cc:      "), ("bcc", "Bcc:     ")):
        vals = ["%s <%s>" % (r.name, r.email) if r.email else r.name for r in recips if r.kind == kind]
        if vals:
            out.append(c(BOLD, label) + ", ".join(vals))
    d = msg.date
    out.append(c(BOLD, "Date:    ") + (d.strftime("%Y-%m-%d %H:%M:%S %Z") if d else "-"))
    out.append(c(BOLD, "NID:     ") + "0x%x" % msg.nid + c(DIM, "   class %s   size %s" % (msg.message_class, human_size(msg.size))))
    if msg.message_id:
        out.append(c(BOLD, "Msg-ID:  ") + msg.message_id)
    atts = msg.attachments()
    if atts:
        out.append(c(BOLD, "Attachments:"))
        for i, a in enumerate(atts):
            kind = "embedded message" if a.is_embedded_message else a.mime_type
            out.append("  [%d] %s  (%s, %s)" % (i, a.filename, human_size(a.size), kind))
    out.append("")
    body = msg.body_text()
    if len(body) > max_body:
        body = body[:max_body] + c(DIM, "\n… (%d more characters)" % (len(body) - max_body))
    out.append(body.replace("\r\n", "\n"))
    return "\n".join(out)
