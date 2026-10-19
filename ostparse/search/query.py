"""
Query language: Outlook Instant Search / AQS syntax plus regular expressions.

Syntax summary (see README "Search" for the full table)::

    budget report                 both words, anywhere (implicit AND)
    "quarterly budget"            phrase
    budget OR forecast            boolean OR  (also  |)
    budget NOT draft              boolean NOT (also  -draft, !draft)
    (budget OR forecast) review   grouping
    from:alice  to:bob@x.com      field prefixes (from, to, cc, bcc, participants,
    subject:budget body:invoice     subject, body, attachment, folder, ...)
    from:(alice OR bob)           field applied to a group
    budg*  ?udget  *2024          wildcards (any position)
    /inv-\\d{4}-\\d{5}/            regular expression (flags: i c s m x)
    subject:/^re: /               regex restricted to a field
    received:last week            dates: today, yesterday, this/last/next week|month|year,
    sent:2024-03-15                 last N days|weeks|months|years, month and weekday names,
    received:2024-01-01..2024-03-31 ISO / US / European dates, ranges with .., comparisons
    date:>=2024                     with > >= < <= =
    messagesize:>5MB  size:tiny    sizes (B KB MB GB, tiny small medium large verylarge enormous)
    hasattachment:yes  read:no     flags;  is:unread  is:attachment
    attachment:report.pdf ext:pdf  attachment names / extensions
    importance:high  kind:email    importance, message kind (email meetings contacts tasks notes)
    in:inbox  folder:"sent items"  folder path words
    nid:0x200024                   one message by NID

Operators must be upper-case (``OR``), exactly as in Outlook, so the words
"or"/"and"/"not" remain searchable.
"""

from __future__ import annotations

import calendar
import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

from .tokenize import tokenize

# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------

TEXT_FIELDS = ("subject", "from", "to", "cc", "bcc", "attach", "body")
ALL_FIELDS = TEXT_FIELDS + ("folder",)
# fields searched by a bare term (Outlook searches everything but folder names)
DEFAULT_FIELDS = TEXT_FIELDS
PARTICIPANT_FIELDS = ("from", "to", "cc", "bcc")

FIELD_ALIASES = {
    "from": "from", "sender": "from", "fromname": "from", "fromaddress": "from",
    "to": "to", "toname": "to", "toaddress": "to",
    "cc": "cc", "ccname": "cc", "ccaddress": "cc",
    "bcc": "bcc", "bccname": "bcc", "bccaddress": "bcc",
    "participants": "participants", "people": "participants", "recipients": "recipients",
    "subject": "subject", "title": "subject",
    "body": "body", "contents": "body", "content": "body", "about": "body", "text": "body",
    "attachment": "attach", "attachments": "attach", "attachmentname": "attach", "attachmentnames": "attach",
    "attach": "attach", "filename": "attach",
    "ext": "ext", "extension": "ext", "fileext": "ext",
    "folder": "folder", "in": "folder", "foldername": "folder", "path": "folder",
    "received": "received", "receivedtime": "received", "datereceived": "received",
    "sent": "sent", "senttime": "sent", "datesent": "sent",
    "date": "date", "modified": "date", "when": "date",
    "size": "size", "messagesize": "size",
    "hasattachment": "hasattachment", "hasattachments": "hasattachment", "hasattach": "hasattachment",
    "read": "read", "isread": "read", "unread": "unread",
    "importance": "importance", "priority": "importance",
    "kind": "kind", "messageclass": "class", "class": "class", "type": "kind",
    "is": "is",
    "nid": "nid", "id": "nid",
    "all": "any", "any": "any", "anywhere": "any",
}

DATE_FIELDS = ("received", "sent", "date")


@dataclass
class Term:
    field: Optional[str]      # None = default text fields
    text: str                 # lower-cased token, may contain * / ?

    def __str__(self):
        return "%s:%s" % (self.field, self.text) if self.field else self.text


@dataclass
class Phrase:
    field: Optional[str]
    tokens: List[str]
    raw: str

    def __str__(self):
        return '%s:"%s"' % (self.field, self.raw) if self.field else '"%s"' % self.raw


@dataclass
class Regex:
    field: Optional[str]
    pattern: str
    flags: int = re.I

    def __str__(self):
        return "%s:/%s/" % (self.field, self.pattern) if self.field else "/%s/" % self.pattern


@dataclass
class DateRange:
    kind: str                 # received | sent | date
    start: Optional[int]      # unix seconds, inclusive
    end: Optional[int]        # unix seconds, exclusive

    def __str__(self):
        return "%s:[%s..%s)" % (self.kind, self.start, self.end)


@dataclass
class SizeRange:
    start: Optional[int]      # bytes, inclusive
    end: Optional[int]        # bytes, exclusive

    def __str__(self):
        return "size:[%s..%s)" % (self.start, self.end)


@dataclass
class Meta:
    """A structured flag: a term in the hidden ``_meta`` field (has:attach, is:read, imp:high, class:ipm.note ...)."""
    term: str

    def __str__(self):
        return "@" + self.term


@dataclass
class Nid:
    nid: int

    def __str__(self):
        return "nid:0x%x" % self.nid


@dataclass
class And:
    children: List["Node"] = field(default_factory=list)

    def __str__(self):
        return "(" + " AND ".join(str(c) for c in self.children) + ")"


@dataclass
class Or:
    children: List["Node"] = field(default_factory=list)

    def __str__(self):
        return "(" + " OR ".join(str(c) for c in self.children) + ")"


@dataclass
class Not:
    child: "Node"

    def __str__(self):
        return "NOT %s" % self.child


@dataclass
class MatchAll:
    def __str__(self):
        return "*"


Node = Union[Term, Phrase, Regex, DateRange, SizeRange, Meta, Nid, And, Or, Not, MatchAll]


class QueryError(ValueError):
    pass


# --------------------------------------------------------------------------
# Lexer
# --------------------------------------------------------------------------


@dataclass
class Tok:
    kind: str     # word | phrase | regex | lparen | rparen | colon | or | and | not | eof
    value: str
    pos: int


_WORD_CHARS_STOP = set(' \t\r\n()":')


def _lex(q: str) -> List[Tok]:
    toks: List[Tok] = []
    i, n = 0, len(q)
    while i < n:
        c = q[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            toks.append(Tok("lparen", c, i)); i += 1; continue
        if c == ")":
            toks.append(Tok("rparen", c, i)); i += 1; continue
        if c == ":":
            toks.append(Tok("colon", c, i)); i += 1; continue
        if c == '"':
            j = i + 1
            buf = []
            while j < n and q[j] != '"':
                if q[j] == "\\" and j + 1 < n:
                    buf.append(q[j + 1]); j += 2; continue
                buf.append(q[j]); j += 1
            toks.append(Tok("phrase", "".join(buf), i))
            i = j + 1
            continue
        if c == "/":
            j = i + 1
            buf = []
            closed = False
            while j < n:
                if q[j] == "\\" and j + 1 < n:
                    buf.append(q[j]); buf.append(q[j + 1]); j += 2; continue
                if q[j] == "/":
                    closed = True
                    break
                buf.append(q[j]); j += 1
            if not closed:
                raise QueryError("unterminated regular expression at offset %d" % i)
            j += 1
            flags = ""
            while j < n and q[j].isalpha():
                flags += q[j]; j += 1
            toks.append(Tok("regex", "".join(buf) + "\x00" + flags, i))
            i = j
            continue
        if c == "|":
            toks.append(Tok("or", c, i)); i += 1; continue
        if c == "&":
            toks.append(Tok("and", c, i)); i += 1; continue
        if c in "-!" and i + 1 < n and not q[i + 1].isspace() and q[i + 1] not in ")":
            # leading minus/bang = NOT, but keep negative numbers in comparison values (handled in parser)
            toks.append(Tok("not", c, i)); i += 1; continue
        # bare word: up to whitespace / paren / quote / colon.  A colon inside a value
        # (10:30) is kept when the word so far does not look like a field name.
        j = i
        buf = []
        while j < n and q[j] not in _WORD_CHARS_STOP:
            buf.append(q[j]); j += 1
        word = "".join(buf)
        if j < n and q[j] == ":":
            # field prefix?  (letters only)
            if word.isalpha():
                toks.append(Tok("word", word, i))
                i = j
                continue
            # otherwise swallow the colon into the value (times, "re:" inside values ...)
            buf.append(":"); j += 1
            while j < n and q[j] not in _WORD_CHARS_STOP:
                buf.append(q[j]); j += 1
            word = "".join(buf)
        if word == "OR":
            toks.append(Tok("or", word, i))
        elif word == "AND":
            toks.append(Tok("and", word, i))
        elif word == "NOT":
            toks.append(Tok("not", word, i))
        else:
            toks.append(Tok("word", word, i))
        i = j
    toks.append(Tok("eof", "", n))
    return toks


# --------------------------------------------------------------------------
# Date / size value parsing
# --------------------------------------------------------------------------

MONTHS = {m.lower(): i for i, m in enumerate(calendar.month_name) if m}
MONTHS.update({m.lower(): i for i, m in enumerate(calendar.month_abbr) if m})
MONTHS["sept"] = 9
WEEKDAYS = {d.lower(): i for i, d in enumerate(calendar.day_name)}
WEEKDAYS.update({d.lower(): i for i, d in enumerate(calendar.day_abbr)})

# Monday-first (ISO) weeks by default; Outlook follows the Windows locale (Sunday in the US).
WEEK_START = 0  # 0 = Monday ... 6 = Sunday


def _ts(d: _dt.datetime) -> int:
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return int(d.timestamp())


def _day(d: _dt.date) -> _dt.datetime:
    return _dt.datetime(d.year, d.month, d.day, tzinfo=_dt.timezone.utc)


def _add_months(d: _dt.date, k: int) -> _dt.date:
    y, m = divmod(d.month - 1 + k, 12)
    return _dt.date(d.year + y, m + 1, 1)


def _week_start(d: _dt.date) -> _dt.date:
    return d - _dt.timedelta(days=(d.weekday() - WEEK_START) % 7)


def _shift_months(d: _dt.date, k: int) -> _dt.date:
    first = _add_months(d.replace(day=1), k)
    last_day = calendar.monthrange(first.year, first.month)[1]
    return first.replace(day=min(d.day, last_day))


def _shift_years(d: _dt.date, k: int) -> _dt.date:
    try:
        return d.replace(year=d.year + k)
    except ValueError:  # Feb 29
        return d.replace(year=d.year + k, day=28)


class DateParser:
    """Turns a date expression into a half-open ``[start, end)`` interval of unix seconds."""

    _ISO = re.compile(r"^(\d{4})(?:[-/.](\d{1,2})(?:[-/.](\d{1,2}))?)?$")
    _US = re.compile(r"^(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?$")
    _EU = re.compile(r"^(\d{1,2})\.(\d{1,2})(?:\.(\d{2,4}))?$")
    _REL = re.compile(r"^(last|past|previous|next|this|coming)\s*(\d+)?\s*(day|week|month|year|hour|minute)s?$")

    def __init__(self, now: Optional[_dt.datetime] = None):
        self.now = now or _dt.datetime.now(_dt.timezone.utc)

    @property
    def today(self) -> _dt.date:
        return self.now.date()

    def interval(self, text: str) -> Tuple[Optional[int], Optional[int]]:
        t = text.strip().lower().replace("_", " ")
        t = re.sub(r"\s+", " ", t)
        if not t:
            raise QueryError("empty date")
        # comparisons
        m = re.match(r"^(>=|<=|>|<|=)\s*(.+)$", t)
        if m:
            op, rest = m.group(1), m.group(2)
            s, e = self.interval(rest)
            if op == ">":
                return e, None
            if op == ">=":
                return s, None
            if op == "<":
                return None, s
            if op == "<=":
                return None, e
            return s, e
        # ranges
        if ".." in t:
            a, b = t.split("..", 1)
            s = self.interval(a)[0] if a.strip() else None
            e = self.interval(b)[1] if b.strip() else None
            return s, e
        today = self.today
        if t in ("today",):
            return _ts(_day(today)), _ts(_day(today + _dt.timedelta(days=1)))
        if t == "yesterday":
            return _ts(_day(today - _dt.timedelta(days=1))), _ts(_day(today))
        if t == "tomorrow":
            return _ts(_day(today + _dt.timedelta(days=1))), _ts(_day(today + _dt.timedelta(days=2)))
        m = self._REL.match(t)
        if m:
            which, num, unit = m.group(1), m.group(2), m.group(3)
            k = int(num) if num else 1
            tomorrow = _ts(_day(today + _dt.timedelta(days=1)))
            if unit in ("hour", "minute"):
                delta = _dt.timedelta(hours=k) if unit == "hour" else _dt.timedelta(minutes=k)
                if which in ("next", "coming"):
                    return _ts(self.now), _ts(self.now + delta) + 1
                return _ts(self.now - delta), _ts(self.now) + 1
            if num:
                # "last 7 days" = 7 calendar days including today; "last 2 weeks" = 14 days;
                # "last 6 months" / "last 2 years" = since the same day 6 months / 2 years ago.
                if which in ("next", "coming"):
                    if unit == "day":
                        end = today + _dt.timedelta(days=k)
                    elif unit == "week":
                        end = today + _dt.timedelta(days=7 * k)
                    elif unit == "month":
                        end = _shift_months(today, k)
                    else:
                        end = _shift_years(today, k)
                    return tomorrow, _ts(_day(end + _dt.timedelta(days=1)))
                if unit == "day":
                    start = today - _dt.timedelta(days=k - 1)
                elif unit == "week":
                    start = today - _dt.timedelta(days=7 * k - 1)
                elif unit == "month":
                    start = _shift_months(today, -k)
                else:
                    start = _shift_years(today, -k)
                return _ts(_day(start)), tomorrow
            # whole calendar units
            if unit == "day":
                if which == "this":
                    return _ts(_day(today)), tomorrow
                if which in ("next", "coming"):
                    return tomorrow, _ts(_day(today + _dt.timedelta(days=2)))
                return _ts(_day(today - _dt.timedelta(days=1))), _ts(_day(today))
            if unit == "week":
                ws = _week_start(today)
                if which == "this":
                    return _ts(_day(ws)), _ts(_day(ws + _dt.timedelta(days=7)))
                if which in ("next", "coming"):
                    return _ts(_day(ws + _dt.timedelta(days=7))), _ts(_day(ws + _dt.timedelta(days=14)))
                return _ts(_day(ws - _dt.timedelta(days=7))), _ts(_day(ws))
            if unit == "month":
                ms = today.replace(day=1)
                if which == "this":
                    return _ts(_day(ms)), _ts(_day(_add_months(ms, 1)))
                if which in ("next", "coming"):
                    return _ts(_day(_add_months(ms, 1))), _ts(_day(_add_months(ms, 2)))
                return _ts(_day(_add_months(ms, -1))), _ts(_day(ms))
            ys = today.replace(month=1, day=1)
            if which == "this":
                return _ts(_day(ys)), _ts(_day(ys.replace(year=ys.year + 1)))
            if which in ("next", "coming"):
                return _ts(_day(ys.replace(year=ys.year + 1))), _ts(_day(ys.replace(year=ys.year + 2)))
            return _ts(_day(ys.replace(year=ys.year - 1))), _ts(_day(ys))
        if t in MONTHS:
            mo = MONTHS[t]
            y = today.year if mo <= today.month else today.year - 1
            s = _dt.date(y, mo, 1)
            return _ts(_day(s)), _ts(_day(_add_months(s, 1)))
        if t in WEEKDAYS:
            wd = WEEKDAYS[t]
            d = today - _dt.timedelta(days=(today.weekday() - wd) % 7)
            return _ts(_day(d)), _ts(_day(d + _dt.timedelta(days=1)))
        m = re.match(r"^([a-z]+)\s+(\d{4})$", t) or re.match(r"^(\d{4})\s+([a-z]+)$", t)
        if m:
            a, b = m.group(1), m.group(2)
            mon, yr = (a, b) if a in MONTHS else (b, a)
            if mon in MONTHS:
                s = _dt.date(int(yr), MONTHS[mon], 1)
                return _ts(_day(s)), _ts(_day(_add_months(s, 1)))
        m = self._ISO.match(t)
        if m:
            y = int(m.group(1))
            if m.group(2) is None:
                return _ts(_day(_dt.date(y, 1, 1))), _ts(_day(_dt.date(y + 1, 1, 1)))
            mo = int(m.group(2))
            if m.group(3) is None:
                s = _dt.date(y, mo, 1)
                return _ts(_day(s)), _ts(_day(_add_months(s, 1)))
            d = _dt.date(y, mo, int(m.group(3)))
            return _ts(_day(d)), _ts(_day(d + _dt.timedelta(days=1)))
        m = self._US.match(t)
        if m:
            mo, dd, yy = int(m.group(1)), int(m.group(2)), m.group(3)
            y = today.year if yy is None else (int(yy) + 2000 if len(yy) == 2 else int(yy))
            d = _dt.date(y, mo, dd)
            return _ts(_day(d)), _ts(_day(d + _dt.timedelta(days=1)))
        m = self._EU.match(t)
        if m:
            dd, mo, yy = int(m.group(1)), int(m.group(2)), m.group(3)
            y = today.year if yy is None else (int(yy) + 2000 if len(yy) == 2 else int(yy))
            d = _dt.date(y, mo, dd)
            return _ts(_day(d)), _ts(_day(d + _dt.timedelta(days=1)))
        # ISO datetime
        try:
            d = _dt.datetime.fromisoformat(text.strip().replace(" ", "T"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=_dt.timezone.utc)
            return _ts(d), _ts(d) + 1
        except ValueError:
            pass
        raise QueryError("cannot understand date %r" % text)


_SIZE_UNITS = {"b": 1, "byte": 1, "bytes": 1, "k": 1 << 10, "kb": 1 << 10, "kib": 1 << 10, "m": 1 << 20, "mb": 1 << 20,
               "mib": 1 << 20, "g": 1 << 30, "gb": 1 << 30, "gib": 1 << 30}
_SIZE_WORDS = {  # Outlook's messagesize: buckets
    "empty": (0, 1), "tiny": (0, 10 << 10), "small": (10 << 10, 25 << 10), "medium": (25 << 10, 100 << 10),
    "large": (100 << 10, 500 << 10), "verylarge": (500 << 10, 1 << 20), "huge": (500 << 10, 1 << 20),
    "enormous": (1 << 20, None), "gigantic": (1 << 20, None),
}


def parse_size_value(text: str) -> int:
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([a-z]*)\s*$", text.lower())
    if not m:
        raise QueryError("cannot understand size %r" % text)
    unit = m.group(2) or "b"
    if unit not in _SIZE_UNITS:
        raise QueryError("unknown size unit %r" % unit)
    return int(float(m.group(1)) * _SIZE_UNITS[unit])


def size_interval(text: str) -> Tuple[Optional[int], Optional[int]]:
    t = text.strip().lower().replace(" ", "")
    if t in _SIZE_WORDS:
        return _SIZE_WORDS[t]
    m = re.match(r"^(>=|<=|>|<|=)(.+)$", t)
    if m:
        op, v = m.group(1), parse_size_value(m.group(2))
        if op == ">":
            return v + 1, None
        if op == ">=":
            return v, None
        if op == "<":
            return None, v
        if op == "<=":
            return None, v + 1
        return v, v + 1
    if ".." in t:
        a, b = t.split("..", 1)
        return (parse_size_value(a) if a else None), (parse_size_value(b) + 1 if b else None)
    v = parse_size_value(t)
    return v, v + 1


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

_YES = {"yes", "true", "1", "y", "on"}
_NO = {"no", "false", "0", "n", "off"}
_KINDS = {
    "email": "ipm.note", "mail": "ipm.note", "message": "ipm.note", "note": "ipm.note",
    "meeting": "ipm.schedule", "meetings": "ipm.schedule", "appointment": "ipm.appointment", "appointments": "ipm.appointment",
    "calendar": "ipm.appointment", "contact": "ipm.contact", "contacts": "ipm.contact", "task": "ipm.task", "tasks": "ipm.task",
    "notes": "ipm.stickynote", "stickynote": "ipm.stickynote", "journal": "ipm.activity", "report": "report",
    "ndr": "report.ipm.note.ndr", "readreceipt": "report.ipm.note.ipnrn",
}
_IMPORTANCE = {"low": "0", "normal": "1", "high": "2", "0": "0", "1": "1", "2": "2"}


class Parser:
    def __init__(self, query: str, *, now: Optional[_dt.datetime] = None):
        self.q = query
        self.toks = _lex(query)
        self.i = 0
        self.dates = DateParser(now)

    # -- token helpers --------------------------------------------------------

    def peek(self, k: int = 0) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def take(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def error(self, msg: str, tok: Optional[Tok] = None) -> QueryError:
        tok = tok or self.peek()
        return QueryError("%s at offset %d (near %r)" % (msg, tok.pos, self.q[tok.pos:tok.pos + 12]))

    # -- grammar ---------------------------------------------------------------

    def parse(self) -> Node:
        if self.peek().kind == "eof":
            return MatchAll()
        node = self.parse_or(None)
        if self.peek().kind != "eof":
            raise self.error("unexpected token")
        return node

    def parse_or(self, fld: Optional[str]) -> Node:
        children = [self.parse_and(fld)]
        while self.peek().kind == "or":
            self.take()
            children.append(self.parse_and(fld))
        return children[0] if len(children) == 1 else Or(children)

    def parse_and(self, fld: Optional[str]) -> Node:
        children = [self.parse_unary(fld)]
        while True:
            k = self.peek().kind
            if k == "and":
                self.take()
                children.append(self.parse_unary(fld))
            elif k in ("word", "phrase", "regex", "lparen", "not"):
                children.append(self.parse_unary(fld))
            else:
                break
        return children[0] if len(children) == 1 else And(children)

    def parse_unary(self, fld: Optional[str]) -> Node:
        if self.peek().kind == "not":
            self.take()
            if self.peek().kind in ("eof", "rparen", "or", "and"):
                raise self.error("NOT needs an operand")
            return Not(self.parse_unary(fld))
        return self.parse_primary(fld)

    def parse_primary(self, fld: Optional[str]) -> Node:
        t = self.peek()
        if t.kind == "lparen":
            self.take()
            node = self.parse_or(fld)
            if self.peek().kind != "rparen":
                raise self.error("missing ')'")
            self.take()
            return node
        if t.kind == "phrase":
            self.take()
            return self.make_phrase(fld, t.value)
        if t.kind == "regex":
            self.take()
            pat, _, flags = t.value.partition("\x00")
            return self.make_regex(fld, pat, flags)
        if t.kind == "word":
            if self.peek(1).kind == "colon":
                name = t.value.lower()
                if name in FIELD_ALIASES:
                    self.take(); self.take()
                    return self.parse_field(FIELD_ALIASES[name], t)
                # not a field: "re:" / "status:red" are ordinary text (as in Outlook)
                self.take(); self.take()
                if self.peek().kind == "word":
                    return self.make_term(fld, t.value + ":" + self.take().value)
                return self.make_term(fld, t.value)
            self.take()
            return self.make_term(fld, t.value)
        if t.kind == "rparen":
            raise self.error("unexpected ')'")
        if t.kind in ("or", "and"):
            raise self.error("operator %s needs operands" % t.value)
        raise self.error("unexpected end of query")

    # -- field handling --------------------------------------------------------

    def parse_field(self, fname: str, ftok: Tok) -> Node:
        nxt = self.peek()
        if fname in DATE_FIELDS:
            return self.parse_date_field(fname)
        if fname == "size":
            v = self.take_value_text()
            s, e = size_interval(v)
            return SizeRange(s, e)
        if fname == "hasattachment":
            v = self.take_value_text().lower()
            if v in _YES:
                return Meta("has:attach")
            if v in _NO:
                return Not(Meta("has:attach"))
            raise self.error("hasattachment: expects yes/no")
        if fname == "read":
            v = self.take_value_text().lower()
            if v in _YES:
                return Meta("is:read")
            if v in _NO:
                return Not(Meta("is:read"))
            raise self.error("read: expects yes/no")
        if fname == "unread":
            v = self.take_value_text().lower()
            return Not(Meta("is:read")) if v in _YES else Meta("is:read")
        if fname == "importance":
            v = self.take_value_text().lower()
            if v not in _IMPORTANCE:
                raise self.error("importance: expects low/normal/high")
            return Meta("imp:" + _IMPORTANCE[v])
        if fname == "is":
            v = self.take_value_text().lower()
            if v in ("read",):
                return Meta("is:read")
            if v in ("unread",):
                return Not(Meta("is:read"))
            if v in ("attachment", "attachments", "attached"):
                return Meta("has:attach")
            if v in ("flagged", "flag"):
                return Meta("is:flagged")
            if v in ("replied", "forwarded", "sent", "unsent", "draft", "drafts"):
                return Meta("is:" + v.rstrip("s") if v != "unsent" else "is:unsent")
            if v in ("embedded",):
                return Meta("has:embedded")
            raise self.error("is: expects read/unread/attachment/flagged/replied/forwarded/draft")
        if fname == "kind":
            v = self.take_value_text().lower()
            cls = _KINDS.get(v, v)
            return Term("class", cls)
        if fname == "class":
            v = self.take_value_text().lower()
            return Term("class", v)
        if fname == "nid":
            v = self.take_value_text()
            try:
                return Nid(int(v, 0))
            except ValueError:
                raise self.error("nid: expects a number")
        if fname == "ext":
            v = self.take_value_text().lower().lstrip(".")
            return Meta("ext:" + v)
        if fname == "attach" and nxt.kind == "word" and nxt.value.lower() in (_YES | _NO):
            v = self.take().value.lower()
            return Meta("has:attach") if v in _YES else Not(Meta("has:attach"))
        if fname == "any":
            fname = None
        # text fields (incl. participants / recipients pseudo-fields): value may be a group
        if nxt.kind == "lparen":
            self.take()
            node = self.parse_or(fname)
            if self.peek().kind != "rparen":
                raise self.error("missing ')'")
            self.take()
            return node
        if nxt.kind == "phrase":
            self.take()
            return self.make_phrase(fname, nxt.value)
        if nxt.kind == "regex":
            self.take()
            pat, _, flags = nxt.value.partition("\x00")
            return self.make_regex(fname, pat, flags)
        if nxt.kind == "not":
            self.take()
            return Not(self.parse_primary(fname))
        if nxt.kind == "word":
            self.take()
            return self.make_term(fname, nxt.value)
        raise self.error("field %s: needs a value" % ftok.value)

    def take_value_text(self) -> str:
        t = self.take()
        if t.kind == "phrase":
            return t.value
        if t.kind == "word":
            return t.value
        if t.kind == "not" and self.peek().kind == "word":   # e.g. size:-5 (unlikely) -> treat as text
            return t.value + self.take().value
        raise self.error("expected a value", t)

    def parse_date_field(self, kind: str) -> Node:
        t = self.peek()
        if t.kind == "phrase":
            self.take()
            try:
                s, e = self.dates.interval(t.value)
            except QueryError:
                raise
            except ValueError as exc:
                raise self.error("%s: %s" % (kind, exc), t) from exc
            return DateRange(kind, s, e)
        if t.kind != "word":
            raise self.error("%s: needs a date" % kind)
        self.take()
        words = [t.value]
        low = t.value.lower()
        # multi-word relative dates: "last week", "last 7 days", "this month", "past 2 years"
        if low in ("last", "past", "previous", "next", "this", "coming"):
            if self.peek().kind == "word" and self.peek().value.isdigit():
                words.append(self.take().value)
            if self.peek().kind == "word" and re.match(r"^(day|week|month|year|hour|minute)s?$", self.peek().value.lower()):
                words.append(self.take().value)
        elif low in MONTHS and self.peek().kind == "word" and re.match(r"^\d{4}$", self.peek().value):
            words.append(self.take().value)
        try:
            s, e = self.dates.interval(" ".join(words))
        except QueryError:
            raise
        except ValueError as exc:
            raise self.error("%s: %s" % (kind, exc), t) from exc
        return DateRange(kind, s, e)

    # -- leaf construction -------------------------------------------------------

    def make_term(self, fld: Optional[str], word: str) -> Node:
        low = word.lower()
        if fld in ("participants", "recipients"):
            fields = PARTICIPANT_FIELDS if fld == "participants" else ("to", "cc", "bcc")
            return Or([self.make_term(f, word) for f in fields])
        if "*" in low or "?" in low:
            # wildcard pattern(s): "budg*", "inv-2024-*" (-> phrase of wildcard tokens)
            pats = re.findall(r"[\w*?]+", low)
            pats = [p for p in pats if p.strip("*?") or p]
            if not pats or not any(p.strip("*?") for p in pats):
                return MatchAll()
            if len(pats) == 1:
                return Term(fld, pats[0])
            return Phrase(fld, pats, word)
        toks = tokenize(low)
        if not toks:
            raise QueryError("term %r has no searchable characters" % word)
        if fld in ("from", "to", "cc", "bcc"):
            addr = low.strip("<>;,")
            if "@" in addr:
                # a complete address is itself a token in address fields
                return Term(fld, addr)
            if re.fullmatch(r"[\w-]+(?:\.[\w-]+)+", addr):
                # a domain or a dotted local part - both are tokens of address fields
                return Term(fld, addr)
        if len(toks) == 1:
            return Term(fld, toks[0])
        # e.g. "well-known", "INV-2024-00123": consecutive tokens -> phrase
        return Phrase(fld, toks, word)

    def make_phrase(self, fld: Optional[str], text: str) -> Node:
        if fld in ("participants", "recipients"):
            fields = PARTICIPANT_FIELDS if fld == "participants" else ("to", "cc", "bcc")
            return Or([self.make_phrase(f, text) for f in fields])
        low = text.lower()
        toks = re.findall(r"[\w*?]+", low)
        toks = [t for t in toks if t.strip("*?") or t]  # keep pure wildcards too
        if not toks:
            raise QueryError("phrase %r has no searchable characters" % text)
        if len(toks) == 1:
            return Term(fld, toks[0])
        return Phrase(fld, toks, text)

    def make_regex(self, fld: Optional[str], pattern: str, flags: str) -> Node:
        if fld in ("participants", "recipients"):
            fields = PARTICIPANT_FIELDS if fld == "participants" else ("to", "cc", "bcc")
            return Or([self.make_regex(f, pattern, flags) for f in fields])
        f = re.I
        for ch in flags:
            if ch == "c":
                f &= ~re.I
            elif ch == "i":
                f |= re.I
            elif ch == "s":
                f |= re.S
            elif ch == "m":
                f |= re.M
            elif ch == "x":
                f |= re.X
            else:
                raise QueryError("unknown regex flag %r (use i c s m x)" % ch)
        try:
            re.compile(pattern, f)
        except re.error as exc:
            raise QueryError("bad regular expression /%s/: %s" % (pattern, exc))
        return Regex(fld, pattern, f)


def parse(query: str, *, now: Optional[_dt.datetime] = None) -> Node:
    """Parse a query string into an AST."""
    return simplify(Parser(query, now=now).parse())


def simplify(node: Node) -> Node:
    """Flatten nested And/Or, drop MatchAll from conjunctions, double negations."""
    if isinstance(node, And):
        kids = []
        for c in node.children:
            c = simplify(c)
            if isinstance(c, And):
                kids.extend(c.children)
            elif isinstance(c, MatchAll):
                continue
            else:
                kids.append(c)
        if not kids:
            return MatchAll()
        return kids[0] if len(kids) == 1 else And(kids)
    if isinstance(node, Or):
        kids = []
        for c in node.children:
            c = simplify(c)
            if isinstance(c, Or):
                kids.extend(c.children)
            else:
                kids.append(c)
        if any(isinstance(k, MatchAll) for k in kids):
            return MatchAll()
        return kids[0] if len(kids) == 1 else Or(kids)
    if isinstance(node, Not):
        c = simplify(node.child)
        if isinstance(c, Not):
            return c.child
        return Not(c)
    return node


def leaves(node: Node) -> List[Node]:
    """All leaf nodes (used for highlighting)."""
    if isinstance(node, (And, Or)):
        out = []
        for c in node.children:
            out.extend(leaves(c))
        return out
    if isinstance(node, Not):
        return []  # negated terms are not highlighted
    return [node]


def positive_text_leaves(node: Node) -> List[Node]:
    return [n for n in leaves(node) if isinstance(n, (Term, Phrase, Regex))]


def describe(node: Node, indent: int = 0) -> str:
    """Pretty-print an AST (for --explain)."""
    pad = "  " * indent
    if isinstance(node, And):
        return pad + "AND\n" + "\n".join(describe(c, indent + 1) for c in node.children)
    if isinstance(node, Or):
        return pad + "OR\n" + "\n".join(describe(c, indent + 1) for c in node.children)
    if isinstance(node, Not):
        return pad + "NOT\n" + describe(node.child, indent + 1)
    if isinstance(node, DateRange):
        def fmt(ts):
            return "-inf" if ts is None else _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
        return pad + "%s in [%s, %s)" % (node.kind, fmt(node.start), fmt(node.end))
    if isinstance(node, SizeRange):
        return pad + "size in [%s, %s)" % (node.start, node.end)
    if isinstance(node, Regex):
        fl = "".join(n for n, v in (("i", re.I), ("s", re.S), ("m", re.M), ("x", re.X)) if node.flags & v)
        return pad + "regex %s /%s/%s" % (node.field or "any", node.pattern, fl)
    if isinstance(node, Phrase):
        return pad + "phrase %s %r" % (node.field or "any", node.tokens)
    if isinstance(node, Term):
        return pad + "term %s %r" % (node.field or "any", node.text)
    return pad + str(node)
