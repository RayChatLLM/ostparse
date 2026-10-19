"""
Turn a :class:`ostparse.messaging.Message` into a flat, searchable document.

The same extraction feeds the indexer and the brute-force scan evaluator, so
the two always agree.  Field order is fixed (``FIELD_ORDER``) because the
text store serialises a document as the field texts joined by ``\\x1f``.
"""

from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .. import props as P
from ..errors import OSTError
from ..messaging import Message
from .tokenize import address_tokens, token_set, tokenize
from zlib import crc32 as _crc32

BIGRAM_BITS = 20
BIGRAM_MASK = (1 << BIGRAM_BITS) - 1


def bigram_key(a: str, b: str) -> int:
    """Index key of the adjacent word pair ``a b``: a 20-bit CRC-32 bucket."""
    return _crc32((a + " " + b).encode("utf-8", "surrogatepass")) & BIGRAM_MASK

FIELD_ORDER = ("subject", "from", "to", "cc", "bcc", "attach", "body", "folder")
FIELD_INDEX = {f: i for i, f in enumerate(FIELD_ORDER)}
FIELD_SEP = "\x1f"
DOC_SEP = "\x1e"

MAX_BODY_CHARS = 2_000_000       # bodies beyond this are truncated in the index (rare; 2 MB of text)
MAX_EMBEDDED_DEPTH = 3

# flag bits stored per document
F_READ = 0x01
F_HASATTACH = 0x02
F_UNSENT = 0x04
F_FLAGGED = 0x08
F_REPLIED = 0x10
F_FORWARDED = 0x20
F_EMBEDDED = 0x40      # has an embedded-message attachment


def _fmt_addr(name: str, email: str) -> str:
    name = (name or "").strip()
    email = (email or "").strip()
    if name and email and name.lower() != email.lower():
        return "%s <%s>" % (name, email)
    return email or name


def _ts(d: Optional[_dt.datetime]) -> int:
    if d is None:
        return 0
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    try:
        return int(d.timestamp())
    except (OverflowError, OSError, ValueError):
        return 0


@dataclass
class Document:
    nid: int
    folder_id: int
    folder_path: str
    texts: Dict[str, str]                 # field -> text (all FIELD_ORDER keys present)
    sent: int = 0                         # unix seconds (0 = unknown)
    received: int = 0
    size: int = 0
    flags: int = 0
    importance: int = 1
    message_class: str = "IPM.Note"
    sender: str = ""                      # "Name <addr>" of the sender
    meta: Set[str] = field(default_factory=set)
    extensions: Set[str] = field(default_factory=set)

    # -- tokens -------------------------------------------------------------------

    def ordered_tokens(self, fld: str) -> List[str]:
        """Word tokens of a field in text order (the basis of the bigram index)."""
        return tokenize(self.texts.get(fld, ""))

    def tokens(self, fld: str) -> Set[str]:
        text = self.texts.get(fld, "")
        if fld in ("from", "to", "cc", "bcc"):
            return address_tokens(text)
        return token_set(text)

    def bigrams(self, fld: str, ordered: Optional[List[str]] = None) -> Set[int]:
        """Hashed adjacent-word pairs of a field (see :func:`bigram_key`)."""
        toks = self.ordered_tokens(fld) if ordered is None else ordered
        if len(toks) < 2:
            return set()
        crc = _crc32
        return {crc((a + " " + b).encode("utf-8", "surrogatepass")) & BIGRAM_MASK for a, b in zip(toks, toks[1:])}

    def all_tokens(self) -> Dict[str, Set[str]]:
        return {f: self.tokens(f) for f in FIELD_ORDER}

    @property
    def date(self) -> int:
        return self.sent or self.received

    def record(self) -> str:
        """Serialised text-store record (fields in FIELD_ORDER, body last but one)."""
        return FIELD_SEP.join(self.texts[f].replace(FIELD_SEP, " ").replace(DOC_SEP, " ") for f in FIELD_ORDER)

    @staticmethod
    def from_record(rec: str) -> Dict[str, str]:
        parts = rec.split(FIELD_SEP)
        if len(parts) < len(FIELD_ORDER):
            parts += [""] * (len(FIELD_ORDER) - len(parts))
        return dict(zip(FIELD_ORDER, parts))


def _message_text(msg: Message) -> str:
    """Readable body text (PR_BODY, else RTF, else HTML).

    Delegates to the canonical ``Message.body_text()`` so the full-text index
    and the ``show`` command always extract a message body the same way.
    """
    return msg.body_text()


def extract(msg: Message, folder_id: int, folder_path: str, *, depth: int = 0) -> Document:
    """Build the searchable document for ``msg`` (embedded messages are folded into the parent)."""
    try:
        recips = msg.recipients()
    except OSTError:
        recips = []
    to, cc, bcc = [], [], []
    for r in recips:
        s = _fmt_addr(r.name, r.email)
        if not s:
            continue
        (to if r.kind == "to" else cc if r.kind == "cc" else bcc if r.kind == "bcc" else to).append(s)
    pc = msg.pc
    if not to:
        d = pc.get_str(P.PR_DISPLAY_TO)
        if d:
            to.append(d)
    if not cc:
        d = pc.get_str(P.PR_DISPLAY_CC)
        if d:
            cc.append(d)
    if not bcc:
        d = pc.get_str(P.PR_DISPLAY_BCC)
        if d:
            bcc.append(d)
    sender = _fmt_addr(msg.sender_name, msg.sender_email)
    subject = msg.subject
    body = _message_text(msg)
    att_names: List[str] = []
    exts: Set[str] = set()
    flags = 0
    embedded_texts: List[str] = []
    try:
        atts = msg.attachments()
    except OSTError:
        atts = []
    for a in atts:
        try:
            name = a.filename
            mime = a.mime_type
        except OSTError:
            continue
        att_names.append(name)
        if mime and mime != "application/octet-stream":
            att_names.append(mime)
        ext = os.path.splitext(name)[1].lower().lstrip(".")
        if ext:
            exts.add(ext)
        try:
            if a.is_embedded_message and depth < MAX_EMBEDDED_DEPTH:
                emb = a.embedded_message()
                if emb is not None:
                    flags |= F_EMBEDDED
                    sub = extract(emb, folder_id, folder_path, depth=depth + 1)
                    embedded_texts.append("\n[attached message] %s\nFrom: %s\nTo: %s\n%s" % (
                        sub.texts["subject"], sub.texts["from"], sub.texts["to"], sub.texts["body"]))
                    if sub.texts["attach"]:
                        att_names.append(sub.texts["attach"])
                    exts |= sub.extensions
        except OSTError:
            pass
    if embedded_texts:
        body = body + "\n" + "\n".join(embedded_texts)
    if len(body) > MAX_BODY_CHARS:
        body = body[:MAX_BODY_CHARS]
    mflags = pc.get(P.PR_MESSAGE_FLAGS, 0) or 0
    if mflags & 0x01:
        flags |= F_READ
    if (mflags & 0x10) or atts:
        flags |= F_HASATTACH
    if mflags & 0x08:
        flags |= F_UNSENT
    icon = pc.get(0x1080, None)          # PR_ICON_INDEX
    if icon == 0x105:
        flags |= F_REPLIED
    elif icon == 0x106:
        flags |= F_FORWARDED
    fstatus = pc.get(0x1090, 0) or 0     # PR_FLAG_STATUS (2 = flagged)
    if fstatus == 2:
        flags |= F_FLAGGED
    importance = pc.get(0x0017, 1)
    if importance is None or not isinstance(importance, int):
        importance = 1
    cls = msg.message_class or "IPM.Note"
    doc = Document(
        nid=msg.nid, folder_id=folder_id, folder_path=folder_path,
        texts={
            "subject": subject or "",
            "from": sender,
            "to": "; ".join(to),
            "cc": "; ".join(cc),
            "bcc": "; ".join(bcc),
            "attach": "; ".join(att_names),
            "body": body,
            "folder": folder_path,
        },
        sent=_ts(msg.submit_time), received=_ts(msg.delivery_time) or _ts(pc.get(P.PR_CREATION_TIME)),
        size=msg.size or 0, flags=flags, importance=max(0, min(2, importance)), message_class=cls, sender=sender,
        extensions=exts,
    )
    doc.meta = meta_terms(doc)
    return doc


def meta_terms(doc: Document) -> Set[str]:
    m = set()
    m.add("has:attach" if doc.flags & F_HASATTACH else "has:noattach")
    m.add("is:read" if doc.flags & F_READ else "is:unread")
    if doc.flags & F_UNSENT:
        m.add("is:unsent")
        m.add("is:draft")
    if doc.flags & F_FLAGGED:
        m.add("is:flagged")
    if doc.flags & F_REPLIED:
        m.add("is:replied")
    if doc.flags & F_FORWARDED:
        m.add("is:forwarded")
    if doc.flags & F_EMBEDDED:
        m.add("has:embedded")
    m.add("imp:%d" % doc.importance)
    m.add("folder:%d" % doc.folder_id)
    for e in doc.extensions:
        m.add("ext:" + e)
    return m


def class_terms(message_class: str) -> Set[str]:
    """Terms for the ``class`` field: the full class and every prefix (ipm, ipm.note, ipm.note.smime)."""
    cls = (message_class or "").lower()
    out = set()
    parts = cls.split(".")
    for i in range(1, len(parts) + 1):
        out.add(".".join(parts[:i]))
    return out
