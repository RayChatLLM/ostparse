"""
Streaming .eml export.

The MIME document is written piece by piece: headers, text parts, then each
attachment base64-encoded 57 KiB at a time straight from the NDB data tree.
Peak memory is therefore independent of attachment size.
"""

from __future__ import annotations

import binascii
import email.utils
import os
import quopri
import re
import time
import uuid
from email.header import Header
from typing import Callable, Iterable, Iterator, Optional

from . import props as P
from .errors import OSTError
from .messaging import Attachment, Folder, Message, OSTFile

_STRIP_HEADERS = {
    "content-type", "content-transfer-encoding", "mime-version", "content-disposition",
    "content-id", "content-description", "content-length", "lines",
}

_B64_SLAB = 57 * 1024  # bytes per encode call -> 76-char lines, 1024 of them


def _fmt_addr(name: str, email_: str) -> str:
    name = (name or "").strip()
    email_ = (email_ or "").strip()
    if email_ and name and name != email_:
        return email.utils.formataddr((name, email_))
    return email_ or name


def _b64_block(data: bytes) -> bytes:
    """Base64 with CRLF every 76 output characters (len(data) % 57 == 0 except for the last block)."""
    b = binascii.b2a_base64(data, newline=False)
    return b"\r\n".join(b[i:i + 76] for i in range(0, len(b), 76)) + b"\r\n"


def _b64_lines(chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Base64-encode a stream of arbitrary-sized chunks into 76-column lines."""
    buf = bytearray()
    for c in chunks:
        buf += c
        if len(buf) >= _B64_SLAB:
            n = len(buf) - len(buf) % 57
            yield _b64_block(bytes(buf[:n]))
            del buf[:n]
    if buf:
        yield _b64_block(bytes(buf))


def _qp(text: str) -> bytes:
    """Quoted-printable encode text with CRLF line endings (input may use \\r\\n or \\n)."""
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    return quopri.encodestring(norm.encode("utf-8"), quotetabs=False).replace(b"\n", b"\r\n")


def _b64_bytes(data: bytes) -> bytes:
    return _b64_block(data)


def _safe_name(name: str, limit: int = 120) -> str:
    name = re.sub(r"[\x00-\x1f\\/:*?\"<>|]+", "_", name or "").strip(" .")
    return (name or "unnamed")[:limit]


_ENCODED_WORD_SAFE = re.compile(r"^[\x20-\x7e]*$")


def _header_bytes(name: str, value: str, address_list: bool = False) -> bytes:
    """One complete, folded header line (RFC 2047-encoded when not printable ASCII)."""
    value = value.replace("\r", " ").replace("\n", " ")
    if _ENCODED_WORD_SAFE.match(value):
        return _fold(name, value, address_list)
    enc = Header(value, "utf-8", header_name=name).encode(maxlinelen=78, linesep="\r\n")
    return ("%s: %s\r\n" % (name, enc)).encode("ascii", "replace")


def _fold(name: str, value: str, address_list: bool = False) -> bytes:
    """Fold one header line to <= 78 columns (soft breaks at ', ' or spaces)."""
    line = "%s: %s" % (name, value)
    if len(line) <= 78:
        return (line + "\r\n").encode("ascii", "replace")
    out = []
    cur = name + ":"
    sep = ", " if address_list else " "
    parts = value.split(sep)
    for i, part in enumerate(parts):
        token = part + (sep.rstrip() if (i < len(parts) - 1 and address_list) else "")
        if cur.endswith(":") or len(cur) + 1 + len(token) <= 78:
            cur += " " + token
        else:
            out.append(cur)
            cur = " " + token
    out.append(cur)
    return ("\r\n".join(out) + "\r\n").encode("ascii", "replace")


class _HeaderBlock:
    """Ordered header lines; raw lines from transport headers are kept verbatim."""

    __slots__ = ("lines", "names")

    def __init__(self):
        self.lines: list = []
        self.names: set = set()

    def has(self, name: str) -> bool:
        return name.lower() in self.names

    def add(self, name: str, value: str, address_list: bool = False):
        self.lines.append(_header_bytes(name, value, address_list))
        self.names.add(name.lower())

    def ensure(self, name: str, value: Optional[str]):
        if value and not self.has(name):
            self.add(name, value)

    def __setitem__(self, name: str, value: str):
        self.add(name, value)

    def __contains__(self, name: str) -> bool:
        return self.has(name)

    def add_raw_block(self, raw: str):
        """Keep the original transport headers verbatim (minus MIME structure headers)."""
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        head = raw.split("\n\n", 1)[0]
        current = None
        for line in head.split("\n"):
            if not line.strip():
                continue
            if line[0] in " \t" and current is not None:
                if current[0]:
                    current[1].append(line)
                continue
            colon = line.find(":")
            if colon <= 0:
                continue
            name = line[:colon].strip()
            keep = name.lower() not in _STRIP_HEADERS and " " not in name
            current = [keep, [line]]
            if keep:
                self.lines.append(current[1])
                self.names.add(name.lower())
        # materialise raw entries
        self.lines = [("\r\n".join(x) + "\r\n").encode("utf-8", "replace") if isinstance(x, list) else x for x in self.lines]

    def render(self) -> bytes:
        return b"".join(self.lines)


class EmlWriter:
    """Writes one message (recursively, for embedded messages) as RFC 5322 bytes."""

    def __init__(self, fp, *, include_attachments: bool = True, attachment_filter: Optional[Callable[[Attachment], bool]] = None):
        self.fp = fp
        self.include_attachments = include_attachments
        self.attachment_filter = attachment_filter
        self.bytes_written = 0
        self.attachments_written = 0

    # -- low-level ----------------------------------------------------------------

    def _w(self, data: bytes):
        self.fp.write(data)
        self.bytes_written += len(data)

    def _line(self, s: str = ""):
        self._w(s.encode("utf-8") + b"\r\n")

    # -- headers -------------------------------------------------------------------

    def _headers(self, msg: Message) -> "_HeaderBlock":
        hb = _HeaderBlock()
        raw = msg.transport_headers
        if raw:
            hb.add_raw_block(raw)

        recips = []
        try:
            recips = msg.recipients()
        except OSTError:
            recips = []

        hb.ensure("From", _fmt_addr(msg.sender_name, msg.sender_email))
        for kind, hdr in (("to", "To"), ("cc", "Cc"), ("bcc", "Bcc")):
            if hb.has(hdr):
                continue
            vals = [_fmt_addr(r.name, r.email) for r in recips if r.kind == kind]
            vals = [v for v in vals if v]
            if vals:
                hb.add(hdr, ", ".join(vals), address_list=True)
        if not hb.has("To"):
            hb.ensure("To", msg.pc.get_str(P.PR_DISPLAY_TO))
        if not hb.has("Cc"):
            hb.ensure("Cc", msg.pc.get_str(P.PR_DISPLAY_CC))
        hb.ensure("Subject", msg.subject)
        d = msg.date
        if not hb.has("Date") and d is not None:
            hb.add("Date", email.utils.format_datetime(d))
        hb.ensure("Message-ID", msg.message_id)
        hb.ensure("In-Reply-To", msg.pc.get_str(P.PR_IN_REPLY_TO_ID))
        hb.ensure("References", msg.pc.get_str(P.PR_INTERNET_REFERENCES))
        hb.add("X-OST-NID", "0x%x" % msg.nid)
        hb.add("X-OST-Message-Class", msg.message_class)
        hb.add("MIME-Version", "1.0")
        return hb

    def _emit_headers(self, hb: "_HeaderBlock"):
        self._w(hb.render())

    # -- parts ---------------------------------------------------------------------

    def _text_part(self, ctype: str, body: bytes, boundary: Optional[str], cte: str = "quoted-printable"):
        if boundary:
            self._line("--" + boundary)
        self._line("Content-Type: %s; charset=utf-8" % ctype)
        self._line("Content-Transfer-Encoding: %s" % cte)
        self._line()
        self._w(body)
        # The CRLF that precedes the next boundary belongs to the boundary (RFC 2046 5.1.1),
        # so always add one: the decoded part then ends exactly where the source body ended.
        self._w(b"\r\n")

    def _attachment_part(self, att: Attachment, boundary: str):
        name = att.filename
        enc_name = email.utils.encode_rfc2231(name, "utf-8") if any(ord(c) > 127 for c in name) else None
        self._line("--" + boundary)
        if att.is_embedded_message:
            emb = att.embedded_message()
            if emb is not None:
                self._line("Content-Type: message/rfc822")
                self._line("Content-Disposition: attachment")
                self._line()
                self.write_message(emb)
                self._line()
                self.attachments_written += 1
                return
        ctype = att.mime_type or "application/octet-stream"
        if enc_name:
            self._line("Content-Type: %s; name*=%s" % (ctype, enc_name))
            self._line("Content-Disposition: attachment; filename*=%s" % enc_name)
        else:
            q = name.replace('"', "'")
            self._line('Content-Type: %s; name="%s"' % (ctype, q))
            self._line('Content-Disposition: attachment; filename="%s"' % q)
        cid = att.content_id
        if cid:
            self._line("Content-ID: <%s>" % cid.strip("<>"))
        self._line("Content-Transfer-Encoding: base64")
        self._line()
        for line in _b64_lines(att.chunks()):
            self._w(line)
        self.attachments_written += 1

    # -- top-level -----------------------------------------------------------------

    def write_message(self, msg: Message):
        em = self._headers(msg)  # a _HeaderBlock; em[...] = ... adds a header
        text = msg.body_text()
        html = msg.html
        atts = []
        if self.include_attachments:
            try:
                atts = msg.attachments()
            except OSTError:
                atts = []
            if self.attachment_filter:
                atts = [a for a in atts if self.attachment_filter(a)]

        text_qp = _qp(text) if (text or not html) else b""
        html_b64 = _b64_bytes(html) if html else b""

        mixed = None
        if atts:
            mixed = "----=_ostparse_mixed_" + uuid.uuid4().hex
            em["Content-Type"] = 'multipart/mixed; boundary="%s"' % mixed
            self._emit_headers(em)
            self._line()
            self._line("This is a multi-part message in MIME format.")
            self._line()
        if html:
            alt = "----=_ostparse_alt_" + uuid.uuid4().hex
            if mixed:
                self._line("--" + mixed)
                self._line('Content-Type: multipart/alternative; boundary="%s"' % alt)
                self._line()
            else:
                em["Content-Type"] = 'multipart/alternative; boundary="%s"' % alt
                self._emit_headers(em)
                self._line()
            if text_qp:
                self._text_part("text/plain", text_qp, alt)
            self._text_part("text/html", html_b64, alt, cte="base64")
            self._line("--" + alt + "--")
        else:
            if mixed:
                self._text_part("text/plain", text_qp, mixed)
            else:
                em["Content-Type"] = "text/plain; charset=utf-8"
                em["Content-Transfer-Encoding"] = "quoted-printable"
                self._emit_headers(em)
                self._line()
                self._w(text_qp)
                if not text_qp.endswith(b"\r\n"):
                    self._w(b"\r\n")
        for att in atts:
            self._attachment_part(att, mixed)
        if mixed:
            self._line("--" + mixed + "--")


def message_to_eml_bytes(msg: Message, **kw) -> bytes:
    import io
    bio = io.BytesIO()
    EmlWriter(bio, **kw).write_message(msg)
    return bio.getvalue()


class ExportStats(dict):
    def __init__(self):
        super().__init__(folders=0, messages=0, attachments=0, bytes=0, errors=0, started=time.time())

    @property
    def elapsed(self) -> float:
        return time.time() - self["started"]


def export_folder_tree(ost: OSTFile, out_dir: str, *, root: Optional[Folder] = None, limit: Optional[int] = None,
                       include_attachments: bool = True, save_attachments_separately: bool = False,
                       progress: Optional[Callable[[ExportStats, Message], None]] = None,
                       on_error: Optional[Callable[[Message, Exception], None]] = None) -> ExportStats:
    """Recursively export ``root`` (default: the whole store) into ``out_dir`` as .eml files.

    Folder names become directories; each message becomes ``<nid-hex>.eml``.
    With ``save_attachments_separately`` attachments are also written next to
    the .eml under ``<nid-hex>.attachments/``.
    """
    stats = ExportStats()
    root = root or ost.root_folder()
    for folder, _depth in root.walk():
        parts = folder.path_parts
        fdir = os.path.join(out_dir, *[_safe_name(p) for p in parts]) if parts else out_dir
        os.makedirs(fdir, exist_ok=True)
        stats["folders"] += 1
        for msg in folder.messages():
            if limit is not None and stats["messages"] >= limit:
                return stats
            path = os.path.join(fdir, "%08x.eml" % msg.nid)
            try:
                with open(path, "wb") as fh:
                    w = EmlWriter(fh, include_attachments=include_attachments)
                    w.write_message(msg)
                stats["bytes"] += w.bytes_written
                stats["attachments"] += w.attachments_written
                if save_attachments_separately:
                    atts = msg.attachments()
                    if atts:
                        adir = os.path.join(fdir, "%08x.attachments" % msg.nid)
                        os.makedirs(adir, exist_ok=True)
                        for i, a in enumerate(atts):
                            if a.is_embedded_message:
                                continue
                            stats["bytes"] += a.save(os.path.join(adir, "%02d_%s" % (i, _safe_name(a.filename))))
                stats["messages"] += 1
            except Exception as exc:  # keep going on a bad message
                stats["errors"] += 1
                if on_error:
                    on_error(msg, exc)
                else:
                    raise
            if progress:
                progress(stats, msg)
    return stats
