"""Subcommand implementations for the ostparse RayChat plugin.

This module is deliberately free of RayChat imports: ``run()`` takes the
command string, the plugin settings, a JSON-compatible state dict and an
optional cancellation callback, and returns display text, so the same code
serves the RayChat command/tool registration and the standalone CLI
(``python -m ostparse_raychat ...``). It never raises for operational
problems — every failure path returns an actionable sentence instead.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from typing import TYPE_CHECKING

from .ostparse import OSTFile
from .ostparse.errors import (
    CorruptFile,
    KeyRequired,
    NotAnOSTFile,
    OSTError,
    UnsupportedFormat,
)
from .ostparse.export import EmlWriter

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, MutableMapping

USAGE = (
    "usage: /ostparse open FILE | info | tree\n"
    "       | index [rebuild] | search QUERY [--limit N --offset N --sort KEY --facet KIND]\n"
    "       | count QUERY | show NID [--full] [--headers] | export DIR QUERY [--limit N]\n"
    "       | stats | close | help\n"
    "open selects the OST/PST for this session; search auto-builds the sidecar index\n"
    "(FILE.ostidx) on first use. NID is the nid=0x... token printed by search/tree.\n"
    "QUERY uses Outlook/AQS syntax plus /regex/: from:alice \"budget review\"\n"
    "received:last month hasattachment:yes — see 'help query' for the full language."
)

QUERY_HELP = (
    "Query language (Outlook Instant Search / AQS + regex):\n"
    "  budget report              both words anywhere (implicit AND)\n"
    '  "quarterly budget"         phrase; budg* b?dget *2024   wildcards\n'
    "  a OR b, a NOT b, -draft, (a OR b) c   boolean (upper-case) and grouping\n"
    "  from: to: cc: bcc: participants:      names, addresses, domains (to:example.com)\n"
    "  subject: body: attachment:report.pdf ext:pdf in:inbox folder:\"sent items\"\n"
    "  from:(alice OR bob)        field applied to a group\n"
    "  /inv-\\d{4}/ subject:/^re: /c          regex, flags i c s m x\n"
    "  received: sent: date:      today, yesterday, last week, last 7 days,\n"
    "                             2024-03-15, march 2024, 2024-01-01..2024-03-31, >=2026\n"
    "  messagesize:>5MB size:tiny..enormous  sizes\n"
    "  hasattachment:yes read:no is:unread is:flagged importance:high\n"
    "  kind:email|meetings|contacts messageclass:ipm.note nid:0x200024\n"
    "Sort keys: date (default) | oldest | size | relevance | subject | from.\n"
    "Facet kinds: folder from domain year month day weekday ext class is size."
)

SUBCOMMANDS = (
    "open",
    "close",
    "info",
    "tree",
    "index",
    "search",
    "count",
    "show",
    "export",
    "stats",
    "digest",
    "help",
)

DEFAULTS: dict[str, object] = {
    "limit": 20,
    "workers": 1,
    "export_cap": 200,
}

_SORT_KEYS = ("date", "oldest", "size", "relevance", "subject", "from")
_FACET_KINDS = ("folder", "from", "domain", "year", "month", "day", "weekday", "ext", "class", "is", "size")
_VALUE_FLAGS = ("limit", "offset", "sort", "facet", "top")
_BOOL_FLAGS = ("exact", "no-snippets", "full", "headers", "json")
_FLAG_RE = re.compile(r"(?:(?<=\s)|^)--([a-z-]+)(?:[=\s]+(\S+))?")


def _int_setting(cfg: Mapping[str, object], key: str) -> int:
    try:
        return max(0, int(cfg.get(key, DEFAULTS[key])))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return int(DEFAULTS[key])  # type: ignore[call-overload]


def _extract_flags(text: str) -> tuple[str, dict[str, object], str]:
    """Split ``--flag [value]`` options out of a query string.

    Returns (remaining text, options, error). Only recognized flag names are
    removed, so AQS negation like ``-draft`` and query text are untouched.
    """
    opts: dict[str, object] = {}
    error = ""
    spans: list[tuple[int, int]] = []
    for m in _FLAG_RE.finditer(text):
        name, value = m.group(1), m.group(2)
        if name in _BOOL_FLAGS:
            opts[name] = True
            spans.append((m.start(), m.start() + 2 + len(name)))
        elif name in _VALUE_FLAGS:
            if value is None:
                error = f"--{name} needs a value"
                break
            opts[name] = value
            spans.append(m.span())
        else:
            known = " ".join(f"--{f}" for f in _VALUE_FLAGS + _BOOL_FLAGS)
            error = f"unknown option --{name}; options: {known}"
            break
    for start, end in reversed(spans):
        text = text[:start] + text[end:]
    return " ".join(text.split()), opts, error


def _opt_int(opts: Mapping[str, object], name: str, default: int) -> int:
    raw = opts.get(name)
    if raw is None:
        return default
    try:
        return max(0, int(str(raw), 0))
    except ValueError:
        return -1


def _human_size(n: object) -> str:
    try:
        v = float(n)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            return ("%d%s" if unit == "B" else "%.1f%s") % (v, unit)
        v /= 1024.0
    return "-"


def _open_ost(state: Mapping[str, object]) -> OSTFile:
    path = state.get("file")
    if not isinstance(path, str) or not path:
        raise _NoFile
    # An OST/PST "open password" (PidTagPstPassword) is only a CRC-32 gate; it
    # does not encrypt the store, so ostparse always reads the content. We open
    # read-through and report the flag as metadata rather than demanding it.
    # (WIP/bCryptMethod-0x10 encryption is different and still raises KeyRequired.)
    return OSTFile(path, ignore_password=True)


class _NoFile(Exception):
    pass


def _ensure_index(ost: OSTFile, cfg: Mapping[str, object], cancel: Callable[[], None] | None, *, rebuild: bool = False):
    from .ostparse.search import ensure_index

    def progress(done: int, total: int, elapsed: float) -> None:
        del done, total, elapsed
        if cancel is not None:
            cancel()

    ix, action = ensure_index(
        ost,
        None,
        rebuild=rebuild,
        progress=progress,
        workers=max(1, _int_setting(cfg, "workers")),
        log=None,
    )
    return ix, action


def _describe_index_action(action: Mapping[str, object]) -> str:
    kind = action.get("action")
    if kind == "built":
        return "built: %s messages, %s segment(s), %s" % (
            action.get("docs", 0),
            action.get("segments", 0),
            _human_size(action.get("index_size", 0)),
        )
    if kind == "updated":
        return "updated: %s added, %s modified, %s deleted" % (
            action.get("added", 0),
            action.get("modified", 0),
            action.get("deleted", 0),
        )
    return "up to date"


def _hit_line(rank: int, hit, show_snippet: bool) -> str:
    sender = hit.sender or "-"
    marks = []
    if hit.attachments:
        marks.append("att")
    suffix = (" (" + ",".join(marks) + ")") if marks else ""
    line = "%d. %s | %s | %s | %s | %s%s | nid=0x%x" % (
        rank,
        hit.date_str,
        sender[:40],
        (hit.subject or "(no subject)")[:80],
        hit.folder or "-",
        _human_size(hit.size),
        suffix,
        hit.nid,
    )
    if show_snippet and hit.snippet:
        line += "\n     " + " ".join(hit.snippet.split())[:200]
    return line


def _cmd_open(rest: str, state: MutableMapping[str, object]) -> str:
    try:
        tokens = shlex.split(rest)
    except ValueError as exc:
        return f"could not parse arguments: {exc}"
    tokens = [t for t in tokens if not t.startswith("--")]  # legacy password flags are now no-ops
    if not tokens:
        return "usage: open FILE — quote paths containing spaces"
    if len(tokens) > 1:
        return "open takes one file path; quote paths containing spaces"
    path = os.path.abspath(os.path.expanduser(tokens[0]))
    if not os.path.isfile(path):
        return f"no such file: {path}"
    probe_state: dict[str, object] = {"file": path}
    with _open_ost(probe_state) as ost:
        info = ost.info()
    state.clear()
    state.update(probe_state)
    ix_dir = path + ".ostidx"
    indexed = "an index exists and will be updated on first search" if os.path.isdir(ix_dir) else "first search builds the index"
    # No password note here: an OST/PST open-password never blocks reading, so
    # mentioning it only makes users think one is required. The factual flag
    # stays available in `info` (password_protected) for anyone who needs it.
    return (
        "opened %s\nkind=%s layout=%s crypt=%s size=%s name=%r\n%s (sidecar %s). Try: search QUERY | tree | info"
        % (
            path,
            info.get("kind", "?"),
            info.get("layout", "?"),
            info.get("crypt", "?"),
            _human_size(os.path.getsize(path)),
            info.get("display_name", ""),
            indexed,
            ix_dir,
        )
    )


def _cmd_info(state: Mapping[str, object]) -> str:
    with _open_ost(state) as ost:
        return json.dumps(ost.info(), indent=2, default=str)


def _cmd_tree(state: Mapping[str, object], cfg: Mapping[str, object], cancel: Callable[[], None] | None) -> str:
    lines: list[str] = []
    folders = messages = 0
    with _open_ost(state) as ost:
        for folder, depth in ost.walk():
            if cancel is not None:
                cancel()
            n = folder.message_count()
            folders += 1
            messages += n
            lines.append("%s%s  [%d msgs]  nid=0x%x" % ("  " * depth, folder.name or "<root>", n, folder.nid))
    lines.append(f"{folders} folders, {messages} messages")
    return "\n".join(lines)


def _cmd_index(rest: str, state: Mapping[str, object], cfg: Mapping[str, object], cancel: Callable[[], None] | None) -> str:
    word = rest.strip().lower()
    if word not in ("", "rebuild"):
        return "usage: index [rebuild]"
    with _open_ost(state) as ost:
        ix, action = _ensure_index(ost, cfg, cancel, rebuild=word == "rebuild")
        path = ix.path if isinstance(getattr(ix, "path", None), str) else str(state.get("file")) + ".ostidx"
        ix.close()
    return "index %s at %s" % (_describe_index_action(action), path)


def _cmd_search(
    rest: str,
    state: Mapping[str, object],
    cfg: Mapping[str, object],
    cancel: Callable[[], None] | None,
    *,
    count_only: bool = False,
) -> str:
    from .ostparse.search import QueryError, Searcher, parse

    query, opts, err = _extract_flags(rest)
    if err:
        return err
    if not query:
        return "usage: %s QUERY — e.g. search from:alice \"budget review\" received:last month" % ("count" if count_only else "search")
    limit = _opt_int(opts, "limit", _int_setting(cfg, "limit"))
    offset = _opt_int(opts, "offset", 0)
    if limit < 0 or offset < 0:
        return "--limit and --offset take non-negative integers"
    sort = str(opts.get("sort", "date"))
    if sort not in _SORT_KEYS:
        return "unknown sort %r; one of: %s" % (sort, " ".join(_SORT_KEYS))
    facet = opts.get("facet")
    if facet is not None and facet not in _FACET_KINDS:
        return "unknown facet %r; one of: %s" % (facet, " ".join(_FACET_KINDS))
    try:
        ast = parse(query)
    except QueryError as exc:
        return f"query error: {exc} — see 'help query' for the syntax"
    with _open_ost(state) as ost:
        ix, _action = _ensure_index(ost, cfg, cancel)
        try:
            searcher = Searcher(ix, workers=1)
            exact = count_only or bool(opts.get("exact")) or facet is not None or sort == "relevance"
            res = searcher.search(
                ast,
                limit=max(1, limit),
                offset=offset,
                sort=sort,
                snippets=not opts.get("no-snippets"),
                exact=exact,
            )
            if count_only:
                return str(res.total)
            if opts.get("json"):
                return json.dumps({"count": res.count_str(), "hits": [h.as_dict() for h in res.hits]}, indent=1, default=str)
            lines = [
                "%s for %s in %.0f ms (sort=%s%s)"
                % (res.count_str(), query, res.elapsed * 1000, sort, f", offset={offset}" if offset else "")
            ]
            for i, hit in enumerate(res.hits, start=offset + 1):
                lines.append(_hit_line(i, hit, not opts.get("no-snippets")))
            if not res.hits:
                lines.append("(no matches — try fewer terms, wildcards like budg*, or 'help query')")
            else:
                note = "the indented line under each hit is a short preview, not the message body"
                if not opts.get("no-snippets"):
                    lines.append(note + " — run 'show NID' to read a message's full body (addresses, attachments and all)")
                else:
                    lines.append("run 'show NID' to read a message's full body (addresses, attachments and all)")
                lines.append("next page: 'search ... --offset %d'" % (offset + len(res.hits)))
            if facet is not None and res.docs is not None:
                top = _opt_int(opts, "top", 15)
                lines.append(f"\n{facet} facets:")
                lines.extend("  %6d  %s" % (n, v) for v, n in searcher.facets(res.docs, str(facet), top=max(1, top)))
            return "\n".join(lines)
        finally:
            ix.close()


def _format_recipients(msg) -> list[str]:
    out: list[str] = []
    for r in msg.recipients():
        label = r.kind or "to"
        name = r.name or ""
        email = r.email or ""
        display = f"{name} <{email}>" if name and email and name != email else (email or name or "?")
        out.append(f"{label}: {display}")
    return out


def _cmd_show(rest: str, state: Mapping[str, object], cfg: Mapping[str, object]) -> str:
    text, opts, err = _extract_flags(rest)
    if err:
        return err
    if not text:
        return "usage: show NID [--full] [--headers] — NID is the nid=0x... token from search/tree"
    try:
        nid = int(text.split()[0], 0)
    except ValueError:
        return f"not a message id: {text!r}; pass the nid=0x... value printed by search"
    with _open_ost(state) as ost:
        try:
            msg = ost.message(nid)
            msg.subject  # noqa: B018 - force the property context open so a bad nid fails here
        except OSTError as exc:
            return f"no message with nid=0x{nid:x}: {exc}"
        sender = msg.sender_name or ""
        email = msg.sender_email or ""
        lines = [
            "nid=0x%x  %s" % (nid, msg.message_class or ""),
            "Subject: %s" % (msg.subject or "(no subject)"),
            "From: %s" % (f"{sender} <{email}>" if sender and email and sender != email else (email or sender or "-")),
            "Date: %s" % (msg.date or "-"),
            "Size: %s" % _human_size(msg.size),
        ]
        if msg.message_id:
            lines.append("Message-Id: %s" % msg.message_id)
        lines.extend(_format_recipients(msg))
        atts = msg.attachments()
        if atts:
            lines.append("Attachments:")
            lines.extend(
                "  %s (%s, %s)%s" % (a.filename or "?", _human_size(a.size), a.mime_type or "?", " [embedded message]" if a.is_embedded_message else "")
                for a in atts
            )
        if opts.get("headers"):
            headers = msg.transport_headers or "(no transport headers)"
            lines.append("--- transport headers ---")
            lines.append(headers)
        # body_text() returns the best-effort readable body (plain text, else
        # RTF, else HTML stripped to text), so HTML-only mail still shows.
        body = msg.body_text()
        lines.append("--- body ---")
        lines.append(body if body else "(empty)")
        return "\n".join(lines)


def _cmd_export(rest: str, state: Mapping[str, object], cfg: Mapping[str, object], cancel: Callable[[], None] | None) -> str:
    from .ostparse.search import QueryError, Searcher, parse

    text, opts, err = _extract_flags(rest)
    if err:
        return err
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        return f"could not parse arguments: {exc}"
    if len(tokens) < 2:
        return 'usage: export DIR QUERY [--limit N] — e.g. export ./out from:alice "budget" (or export ./out nid:0x200024)'
    out_dir = os.path.abspath(os.path.expanduser(tokens[0]))
    query = text.split(None, 1)[1]
    cap = _opt_int(opts, "limit", _int_setting(cfg, "export_cap"))
    if cap <= 0:
        return "--limit takes a positive integer"
    try:
        ast = parse(query)
    except QueryError as exc:
        return f"query error: {exc} — see 'help query' for the syntax"
    with _open_ost(state) as ost:
        ix, _action = _ensure_index(ost, cfg, cancel)
        try:
            res = Searcher(ix, workers=1).search(ast, limit=1, sort="date", snippets=False, exact=True)
            docs = sorted(res.docs or set())
            if not docs:
                return f"no messages match {query!r}; nothing exported"
            os.makedirs(out_dir, exist_ok=True)
            written = 0
            for d in docs[:cap]:
                if cancel is not None:
                    cancel()
                msg = ost.message(ix.nid[d])
                with open(os.path.join(out_dir, "%08x.eml" % msg.nid), "wb") as fh:
                    EmlWriter(fh).write_message(msg)
                written += 1
            note = f" ({len(docs)} matched; capped at {cap}, raise with --limit)" if len(docs) > cap else ""
            return f"exported {written} message(s) as .eml to {out_dir}{note}"
        finally:
            ix.close()


def _cmd_stats(state: Mapping[str, object], cancel: Callable[[], None] | None) -> str:
    with _open_ost(state) as ost:
        folders = messages = attachments = 0
        att_bytes = 0
        for folder, _depth in ost.walk():
            if cancel is not None:
                cancel()
            folders += 1
            for msg in folder.messages():
                messages += 1
                if msg.has_attachments:
                    for a in msg.attachments():
                        attachments += 1
                        att_bytes += a.size
        return json.dumps(
            {
                "file": state.get("file"),
                "folders": folders,
                "messages": messages,
                "attachments": attachments,
                "attachment_bytes": att_bytes,
            },
            indent=2,
        )


def _cmd_digest(
    rest: str,
    state: Mapping[str, object],
    cfg: Mapping[str, object],
    cancel: Callable[[], None] | None,
) -> str:
    """Grounded mailbox overview: facet counts plus recent messages with their
    real nid and a real body excerpt, so a caller can describe the mailbox from
    actual data instead of guessing from subjects or inventing identifiers.
    """
    from .ostparse.search import Searcher, parse

    text, opts, err = _extract_flags(rest)
    if err:
        return err
    sample = _opt_int(opts, "limit", 15)
    with _open_ost(state) as ost:
        ix, _action = _ensure_index(ost, cfg, cancel)
        try:
            searcher = Searcher(ix, workers=1)
            profile = searcher.search(parse("*"), limit=1, sort="date", exact=True)
            lines = ["MAILBOX DIGEST — %s messages total" % profile.total]
            for kind, label in (
                ("folder", "Folders (message counts)"),
                ("from", "Top senders"),
                ("domain", "Sender domains (spot bulk/newsletter senders)"),
                ("month", "Busiest months"),
            ):
                if profile.docs is None:
                    break
                facs = searcher.facets(profile.docs, kind, top=8)
                if facs:
                    lines.append("\n%s:" % label)
                    lines.extend("  %6d  %s" % (count, value) for value, count in facs)
            res = searcher.search(parse("kind:email"), limit=max(1, sample), sort="date", exact=True)
            lines.append(
                "\n%d most recent emails — each line is a REAL nid and a REAL body excerpt; "
                "quote these (and open others with 'show NID'), never invent a nid:" % len(res.hits)
            )
            for hit in res.hits:
                if cancel is not None:
                    cancel()
                try:
                    body = " ".join((ost.message(hit.nid).body_text() or "").split())[:280]
                except OSTError:
                    body = ""
                lines.append(
                    "  nid=0x%x | %s | %s | %s"
                    % (hit.nid, hit.date_str, (hit.sender or "-")[:40], (hit.subject or "(no subject)")[:70])
                )
                if body:
                    lines.append("      " + body)
            return "\n".join(lines)
        finally:
            ix.close()


def run(
    arguments: str,
    settings: Mapping[str, object] | None = None,
    state: MutableMapping[str, object] | None = None,
    cancel: Callable[[], None] | None = None,
) -> str:
    """Return complete command output, including intact JSON for search --json.

    Search pages are bounded by --limit/--offset, never by character slicing.
    Legacy max_chars, body_chars and tree_lines settings are ignored.
    """
    cfg: dict[str, object] = dict(DEFAULTS)
    cfg.update(settings or {})
    if state is None:
        state = {}
    text = (arguments or "").strip()
    if not text:
        return USAGE
    sub, _, rest = text.partition(" ")
    sub = sub.lower()
    rest = rest.strip()
    if sub not in SUBCOMMANDS:
        return f"unknown subcommand {sub!r}\n{USAGE}"
    if sub == "help":
        return QUERY_HELP if rest.lower().startswith("query") else USAGE
    try:
        if sub == "open":
            return _cmd_open(rest, state)
        if sub == "close":
            had = state.get("file")
            state.clear()
            return f"closed {had}" if had else "nothing was open"
        if sub == "info":
            return _cmd_info(state)
        if sub == "tree":
            return _cmd_tree(state, cfg, cancel)
        if sub == "index":
            return _cmd_index(rest, state, cfg, cancel)
        if sub == "search":
            return _cmd_search(rest, state, cfg, cancel)
        if sub == "count":
            return _cmd_search(rest, state, cfg, cancel, count_only=True)
        if sub == "show":
            return _cmd_show(rest, state, cfg)
        if sub == "export":
            return _cmd_export(rest, state, cfg, cancel)
        if sub == "stats":
            return _cmd_stats(state, cancel)
        if sub == "digest":
            return _cmd_digest(rest, state, cfg, cancel)
    except _NoFile:
        return "no OST/PST is open in this session — use: open /absolute/path/to/mailbox.ost"
    except FileNotFoundError as exc:
        return f"file disappeared: {exc}; run open again"
    except KeyRequired as exc:
        return (
            f"{exc} — this store is WIP-encrypted (bCryptMethod 0x10); decrypt it on its Windows host "
            "(cipher /d) and open the decrypted copy"
        )
    except (NotAnOSTFile, UnsupportedFormat, CorruptFile) as exc:
        return f"cannot read {state.get('file')}: {exc}"
    except OSTError as exc:
        return f"ostparse error: {exc}"
    except OSError as exc:
        return f"filesystem error: {exc}"
    return USAGE
