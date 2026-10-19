"""
Messaging layer ([MS-PST] section 2.4): message store, folders, messages,
recipients and attachments on top of the NDB/LTP readers.

All traversal is lazy.  ``Folder.messages()`` streams the contents table row
by row, ``Message`` opens its property context on demand and
``Attachment.chunks()`` streams attachment bytes straight out of the data
tree, so neither the folder count, message count nor attachment size has any
bearing on memory.
"""

from __future__ import annotations

import datetime as _dt
import struct
from typing import Any, Dict, Iterator, List, Optional

from . import props as P
from .crc import pst_crc32
from .decryptors import load_decryptor
from .errors import KeyRequired, NodeNotFound, OSTError, PasswordRequired, WrongPassword
from .ltp import LTP, PropertyContext, TableContext
from .ndb import (NDB, NID_ATTACHMENT_TABLE, NID_MESSAGE_STORE, NID_RECIPIENT_TABLE, NID_ROOT_FOLDER,
                  NID_TYPE_ASSOC_CONTENTS_TABLE, NID_TYPE_CONTENTS_TABLE, NID_TYPE_HIERARCHY_TABLE,
                  NID_TYPE_NORMAL_FOLDER, NID_TYPE_SEARCH_FOLDER, nid_type)
from .rtf import decompress_rtf, rtf_to_text


def _nid_with_type(nid: int, t: int) -> int:
    return (nid & ~0x1F) | t


def password_crc(password: str) -> int:
    """The value Outlook stores in PidTagPstPassword: weak CRC-32 of the password's ANSI bytes."""
    return pst_crc32(password.encode("cp1252", "replace"))


def check_password(password: str, stored: int) -> bool:
    """Compare a password against a stored PidTagPstPassword value (ANSI, UTF-16 and UTF-8 encodings accepted)."""
    for enc in ("cp1252", "utf-16-le", "utf-8"):
        try:
            if pst_crc32(password.encode(enc, "replace")) == stored:
                return True
        except LookupError:
            pass
    return False


# --------------------------------------------------------------------------
# Attachments & recipients
# --------------------------------------------------------------------------


class Recipient:
    __slots__ = ("row", "pc")

    def __init__(self, row):
        self.row = row

    @property
    def type(self) -> int:
        return self.row.get(P.PR_RECIPIENT_TYPE, P.MAPI_TO) or P.MAPI_TO

    @property
    def kind(self) -> str:
        return {P.MAPI_TO: "to", P.MAPI_CC: "cc", P.MAPI_BCC: "bcc", P.MAPI_ORIG: "from"}.get(self.type, "to")

    @property
    def name(self) -> str:
        return self.row.get_str(P.PR_DISPLAY_NAME) or self.row.get_str(P.PR_RECIPIENT_DISPLAY_NAME)

    @property
    def email(self) -> str:
        e = self.row.get_str(P.PR_SMTP_ADDRESS)
        if not e:
            e = self.row.get_str(P.PR_EMAIL_ADDRESS)
            if e and (self.row.get_str(P.PR_ADDRTYPE) or "SMTP").upper() != "SMTP" and "@" not in e:
                e = ""
        return e

    def __repr__(self):
        return "Recipient(%s %r <%s>)" % (self.kind, self.name, self.email)


class Attachment:
    """One attachment of a message (a PC living in the message's subnode tree)."""

    def __init__(self, message: "Message", nid: int, row=None):
        self.message = message
        self.nid = nid
        self.row = row
        self._pc: Optional[PropertyContext] = None

    @property
    def pc(self) -> PropertyContext:
        if self._pc is None:
            self._pc = self.message.ost.ltp.sub_pc(self.message.pc, self.nid)
        return self._pc

    @property
    def method(self) -> int:
        return self.pc.get(P.PR_ATTACH_METHOD, P.ATTACH_BY_VALUE) or 0

    @property
    def filename(self) -> str:
        return (self.pc.get_str(P.PR_ATTACH_LONG_FILENAME) or self.pc.get_str(P.PR_ATTACH_FILENAME)
                or self.pc.get_str(P.PR_DISPLAY_NAME) or "attachment-%d" % (self.pc.get(P.PR_ATTACH_NUM, 0) or 0))

    @property
    def mime_type(self) -> str:
        return self.pc.get_str(P.PR_ATTACH_MIME_TAG) or "application/octet-stream"

    @property
    def content_id(self) -> str:
        return self.pc.get_str(P.PR_ATTACH_CONTENT_ID)

    @property
    def size(self) -> int:
        """Size of the attachment payload (from the data tree, falls back to PR_ATTACH_SIZE)."""
        if P.PR_ATTACH_DATA_BIN in self.pc and self.pc.ptype(P.PR_ATTACH_DATA_BIN) == P.PT_BINARY:
            return self.pc.size(P.PR_ATTACH_DATA_BIN)
        return self.pc.get(P.PR_ATTACH_SIZE, 0) or 0

    @property
    def is_embedded_message(self) -> bool:
        return self.method == P.ATTACH_EMBEDDED_MSG and self.pc.ptype(P.PR_ATTACH_DATA_BIN) == P.PT_OBJECT

    def chunks(self) -> Iterator[bytes]:
        """Stream the attachment bytes (binary attachments only)."""
        if self.pc.ptype(P.PR_ATTACH_DATA_BIN) != P.PT_BINARY:
            return iter(())
        return self.pc.stream(P.PR_ATTACH_DATA_BIN)

    def data(self, max_bytes: Optional[int] = 256 << 20) -> bytes:
        return self.pc.get(P.PR_ATTACH_DATA_BIN, b"", max_bytes=max_bytes) if self.pc.ptype(P.PR_ATTACH_DATA_BIN) == P.PT_BINARY else b""

    def save(self, path: str) -> int:
        n = 0
        with open(path, "wb") as fh:
            for chunk in self.chunks():
                fh.write(chunk)
                n += len(chunk)
        return n

    def embedded_message(self) -> Optional["Message"]:
        """Return the embedded message for ATTACH_EMBEDDED_MSG attachments."""
        if not self.is_embedded_message:
            return None
        obj = self.pc.get(P.PR_ATTACH_DATA_BIN)
        if not obj:
            return None
        nid, _size = obj
        e = self.pc.subnodes.lookup(nid)
        if e is None:
            raise NodeNotFound("embedded message NID 0x%x not found in attachment subnodes" % nid)
        return Message(self.message.ost, nid, pc=PropertyContext(self.message.ost.ndb, e.bid_data, e.bid_sub), parent=self.message)

    def __repr__(self):
        return "Attachment(nid=0x%x, %r, %d bytes)" % (self.nid, self.filename, self.size)


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------


class Message:
    """A message object (``NID_TYPE_NORMAL_MESSAGE`` / ``NID_TYPE_ASSOC_MESSAGE``)."""

    def __init__(self, ost: "OSTFile", nid: int, *, row=None, pc: Optional[PropertyContext] = None,
                 parent: Optional["Message"] = None, folder: Optional["Folder"] = None):
        self.ost = ost
        self.nid = nid
        self.row = row          # contents-table row, if we came from a folder listing
        self._pc = pc
        self.parent = parent
        self.folder = folder

    # -- property access ----------------------------------------------------

    @property
    def pc(self) -> PropertyContext:
        if self._pc is None:
            self._pc = self.ost.ltp.pc(self.nid)
        return self._pc

    def get(self, propid: int, default=None):
        return self.pc.get(propid, default)

    def get_str(self, propid: int, default: str = "") -> str:
        return self.pc.get_str(propid, default)

    def _row_or_pc_str(self, propid: int) -> str:
        if self.row is not None and self.row.has(propid):
            v = self.row.get_str(propid)
            if v:
                return v
        return self.pc.get_str(propid)

    @property
    def subject(self) -> str:
        s = self._row_or_pc_str(P.PR_SUBJECT)
        # Outlook prefixes subjects with a 2-byte "subject prefix length" marker (0x01, n)
        if len(s) >= 2 and s[0] == "\x01":
            s = s[2:]
        return s

    @property
    def message_class(self) -> str:
        return self._row_or_pc_str(P.PR_MESSAGE_CLASS) or "IPM.Note"

    @property
    def sender_name(self) -> str:
        return self._row_or_pc_str(P.PR_SENDER_NAME) or self.pc.get_str(P.PR_SENT_REPRESENTING_NAME)

    @property
    def sender_email(self) -> str:
        e = self.pc.get_str(P.PR_SENDER_EMAIL_ADDRESS) or self.pc.get_str(P.PR_SENT_REPRESENTING_EMAIL_ADDRESS)
        if e and "@" not in e and (self.pc.get_str(P.PR_SENDER_ADDRTYPE) or "SMTP").upper() != "SMTP":
            return ""
        return e

    @property
    def delivery_time(self) -> Optional[_dt.datetime]:
        if self.row is not None and self.row.has(P.PR_MESSAGE_DELIVERY_TIME):
            return self.row.get(P.PR_MESSAGE_DELIVERY_TIME)
        return self.pc.get(P.PR_MESSAGE_DELIVERY_TIME)

    @property
    def submit_time(self) -> Optional[_dt.datetime]:
        if self.row is not None and self.row.has(P.PR_CLIENT_SUBMIT_TIME):
            return self.row.get(P.PR_CLIENT_SUBMIT_TIME)
        return self.pc.get(P.PR_CLIENT_SUBMIT_TIME)

    @property
    def date(self) -> Optional[_dt.datetime]:
        return self.submit_time or self.delivery_time or self.pc.get(P.PR_CREATION_TIME)

    @property
    def message_id(self) -> str:
        return self.pc.get_str(P.PR_INTERNET_MESSAGE_ID)

    @property
    def transport_headers(self) -> str:
        return self.pc.get_str(P.PR_TRANSPORT_MESSAGE_HEADERS)

    @property
    def body(self) -> str:
        return self.pc.get_str(P.PR_BODY)

    @property
    def html(self) -> Optional[bytes]:
        if P.PR_HTML not in self.pc:
            return None
        v = self.pc.get(P.PR_HTML)
        if isinstance(v, str):
            return v.encode("utf-8")
        return v

    @property
    def rtf(self) -> Optional[bytes]:
        if P.PR_RTF_COMPRESSED not in self.pc:
            return None
        try:
            return decompress_rtf(self.pc.get(P.PR_RTF_COMPRESSED))
        except Exception:
            return None

    def body_text(self) -> str:
        """Best-effort readable text body: PR_BODY, else RTF->text, else HTML->text.

        HTML-only mail (the common case for newsletters and service messages)
        has no PR_BODY and no RTF, so without the HTML fallback this returned ""
        for a message that in fact has a full readable body. Every caller --
        the plugin's ``show`` and any code driving the library directly -- needs
        the same best-effort text, so the fallback lives here, not in callers.
        """
        try:
            b = self.body
        except OSTError:
            b = ""
        if b:
            return b
        try:
            r = self.rtf
        except OSTError:
            r = None
        if r:
            try:
                text = rtf_to_text(r)
            except Exception:  # noqa: BLE001 - a bad RTF stream must not hide HTML
                text = ""
            if text:
                return text
        try:
            h = self.html
        except OSTError:
            h = None
        if h:
            from .search.tokenize import html_to_text

            try:
                return html_to_text(h)
            except Exception:  # noqa: BLE001 - never raise from a best-effort read
                return ""
        return ""

    @property
    def has_attachments(self) -> bool:
        if self.row is not None and self.row.has(P.PR_HASATTACH):
            return bool(self.row.get(P.PR_HASATTACH))
        if P.PR_HASATTACH in self.pc:
            return bool(self.pc.get(P.PR_HASATTACH))
        flags = self.pc.get(P.PR_MESSAGE_FLAGS, 0) or 0
        return bool(flags & 0x10)

    @property
    def size(self) -> int:
        if self.row is not None and self.row.has(P.PR_MESSAGE_SIZE):
            return self.row.get(P.PR_MESSAGE_SIZE) or 0
        return self.pc.get(P.PR_MESSAGE_SIZE, 0) or 0

    # -- sub-objects ------------------------------------------------------------

    def recipients(self) -> List[Recipient]:
        if not self.ost.ltp.has_sub(self.pc, NID_RECIPIENT_TABLE):
            return []
        tc = self.ost.ltp.sub_tc(self.pc, NID_RECIPIENT_TABLE)
        return [Recipient(r) for r in tc.iter_rows()]

    def attachments(self) -> List[Attachment]:
        if not self.ost.ltp.has_sub(self.pc, NID_ATTACHMENT_TABLE):
            return []
        tc = self.ost.ltp.sub_tc(self.pc, NID_ATTACHMENT_TABLE)
        out = []
        for r in tc.iter_rows():
            out.append(Attachment(self, r.rowid, row=r))
        return out

    def properties(self) -> Dict[str, Any]:
        """All properties, decoded, keyed by name (for debugging/inspection)."""
        return {P.prop_name(k): v for k, v in self.pc.items().items()}

    def __repr__(self):
        return "Message(nid=0x%x, %r)" % (self.nid, self.subject[:40])


# --------------------------------------------------------------------------
# Folders
# --------------------------------------------------------------------------


class Folder:
    def __init__(self, ost: "OSTFile", nid: int, *, row=None, parent: Optional["Folder"] = None):
        self.ost = ost
        self.nid = nid
        self.row = row
        self.parent = parent
        self._pc: Optional[PropertyContext] = None

    @property
    def pc(self) -> PropertyContext:
        if self._pc is None:
            self._pc = self.ost.ltp.pc(self.nid)
        return self._pc

    @property
    def name(self) -> str:
        if self.row is not None and self.row.has(P.PR_DISPLAY_NAME):
            return self.row.get_str(P.PR_DISPLAY_NAME)
        try:
            return self.pc.get_str(P.PR_DISPLAY_NAME)
        except OSTError:
            return "<0x%x>" % self.nid

    @property
    def path_parts(self) -> List[str]:
        """Names from the first folder under the root down to this one."""
        parts = []
        f: Optional[Folder] = self
        while f is not None and f.nid != NID_ROOT_FOLDER:
            parts.append(f.name)
            f = f.parent
        parts.reverse()
        return parts

    @property
    def path(self) -> str:
        return "/" + "/".join(self.path_parts)

    @property
    def content_count(self) -> int:
        if self.row is not None and self.row.has(P.PR_CONTENT_COUNT):
            return self.row.get(P.PR_CONTENT_COUNT) or 0
        return self.pc.get(P.PR_CONTENT_COUNT, 0) or 0

    @property
    def unread_count(self) -> int:
        if self.row is not None and self.row.has(P.PR_CONTENT_UNREAD):
            return self.row.get(P.PR_CONTENT_UNREAD) or 0
        return self.pc.get(P.PR_CONTENT_UNREAD, 0) or 0

    @property
    def has_subfolders(self) -> bool:
        if self.row is not None and self.row.has(P.PR_SUBFOLDERS):
            return bool(self.row.get(P.PR_SUBFOLDERS))
        return bool(self.pc.get(P.PR_SUBFOLDERS, False))

    @property
    def container_class(self) -> str:
        return self.pc.get_str(P.PR_CONTAINER_CLASS)

    # -- tables -----------------------------------------------------------------

    def _table(self, t: int) -> Optional[TableContext]:
        nid = _nid_with_type(self.nid, t)
        try:
            return self.ost.ltp.tc(nid)
        except NodeNotFound:
            return None

    def hierarchy_table(self) -> Optional[TableContext]:
        return self._table(NID_TYPE_HIERARCHY_TABLE)

    def contents_table(self) -> Optional[TableContext]:
        return self._table(NID_TYPE_CONTENTS_TABLE)

    def associated_contents_table(self) -> Optional[TableContext]:
        return self._table(NID_TYPE_ASSOC_CONTENTS_TABLE)

    def subfolders(self) -> Iterator["Folder"]:
        tc = self.hierarchy_table()
        if tc is None:
            return
        for row in tc.iter_rows():
            nid = row.rowid
            if nid_type(nid) not in (NID_TYPE_NORMAL_FOLDER, NID_TYPE_SEARCH_FOLDER):
                continue
            yield Folder(self.ost, nid, row=row, parent=self)

    def messages(self, *, associated: bool = False) -> Iterator[Message]:
        """Stream the folder's messages in contents-table order."""
        tc = self.associated_contents_table() if associated else self.contents_table()
        if tc is None:
            return
        for row in tc.iter_rows():
            yield Message(self.ost, row.rowid, row=row, folder=self)

    def message_count(self) -> int:
        tc = self.contents_table()
        return tc.row_count() if tc is not None else 0

    def walk(self, depth: int = 0) -> Iterator["tuple[Folder, int]"]:
        """Depth-first traversal yielding (folder, depth)."""
        yield self, depth
        for sub in self.subfolders():
            yield from sub.walk(depth + 1)

    def __repr__(self):
        return "Folder(nid=0x%x, %r)" % (self.nid, self.name)


# --------------------------------------------------------------------------
# File
# --------------------------------------------------------------------------


class OSTFile:
    """An open OST/PST file.  Use as a context manager.

    Parameters
    ----------
    password:
        The PST/OST password (``PidTagPstPassword``).  Only ever a CRC check,
        never used for decryption - the format stores a CRC of it and leaves
        the data untouched, so it never blocks reading.  Opening never requires
        a password: when one is supplied it is verified and :class:`WrongPassword`
        is raised on a mismatch; when none is supplied the store is read
        regardless.  ``ignore_password=True`` skips even the mismatch check.
    key / decryptor / decryptor_spec:
        For ``bCryptMethod = 0x10`` (Windows Information Protection) files
        whose blocks are real ciphertext.  Either pass a ready ``decryptor``
        callable, or a ``key`` plus a ``decryptor_spec`` (built-in name or
        ``module:factory``, see :mod:`ostparse.decryptors`).  Files whose
        WIP layer has already been removed open without any of these.
    """

    def __init__(self, path: str, *, password: Optional[str] = None, ignore_password: bool = False,
                 key: Optional[str] = None, decryptor=None, decryptor_spec: Optional[str] = None, **ndb_kwargs):
        if decryptor is None and key is not None:
            if not decryptor_spec:
                raise KeyRequired(
                    "a WIP decryption key was given but no decryptor: Microsoft does not publish the "
                    "bCryptMethod=0x10 block cipher, so the key must be paired with an implementation "
                    "(decryptor_spec='module:factory'; 'demo-xor' is only for ostgen test files)")
            decryptor = load_decryptor(decryptor_spec, key)
        self.ndb = NDB(path, decryptor=decryptor, **ndb_kwargs)
        self.ltp = LTP(self.ndb)
        self.header = self.ndb.header
        self.password_protected = False
        self._check_password(password, ignore_password)

    def _check_password(self, password: Optional[str], ignore: bool):
        try:
            stored = self.message_store().get(P.PR_PST_PASSWORD, 0) or 0
        except OSTError:
            return
        stored &= 0xFFFFFFFF
        self.password_protected = bool(stored)
        # The PidTagPstPassword CRC never encrypts the data, so a missing
        # password must never block reading (that only confused callers and
        # agents driving OSTFile directly).  Verify a supplied password, but
        # never require one.
        if not stored or ignore or password is None:
            return
        if not check_password(password, stored):
            raise WrongPassword("the supplied password does not match PidTagPstPassword")

    def close(self):
        self.ndb.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- top-level objects -------------------------------------------------------

    def message_store(self) -> PropertyContext:
        return self.ltp.pc(NID_MESSAGE_STORE)

    @property
    def display_name(self) -> str:
        try:
            return self.message_store().get_str(P.PR_DISPLAY_NAME)
        except OSTError:
            return ""

    def root_folder(self) -> Folder:
        return Folder(self, NID_ROOT_FOLDER)

    def folder(self, nid: int) -> Folder:
        return Folder(self, nid)

    def message(self, nid: int) -> Message:
        return Message(self, nid)

    def _entryid_nid(self, propid: int) -> Optional[int]:
        try:
            eid = self.message_store().get(propid)
        except OSTError:
            return None
        if isinstance(eid, bytes) and len(eid) >= 24:
            return struct.unpack_from("<I", eid, 20)[0]
        return None

    def ipm_subtree(self) -> Optional[Folder]:
        """The "Top of Information Store" / IPM_SUBTREE folder (user-visible root)."""
        nid = self._entryid_nid(P.PR_IPM_SUBTREE_ENTRYID)
        if nid is None:
            return None
        return Folder(self, nid, parent=self.root_folder())

    def wastebasket(self) -> Optional[Folder]:
        nid = self._entryid_nid(P.PR_IPM_WASTEBASKET_ENTRYID)
        return Folder(self, nid) if nid else None

    def walk(self) -> Iterator["tuple[Folder, int]"]:
        return self.root_folder().walk()

    def find_folder(self, path: str) -> Optional[Folder]:
        """Resolve a '/A/B/C' path (names case-insensitive) under the root folder."""
        parts = [p for p in path.strip("/").split("/") if p]
        cur = self.root_folder()
        for part in parts:
            nxt = None
            for sub in cur.subfolders():
                if sub.name.lower() == part.lower():
                    nxt = sub
                    break
            if nxt is None:
                return None
            cur = nxt
        return cur

    def info(self) -> Dict[str, Any]:
        h = self.header
        return {
            "path": self.ndb.path,
            "size": self.ndb.file_size,
            "kind": "OST" if h.is_ost else ("PST" if h.magic_client == b"SM" else "PAB"),
            "wVer": h.w_ver,
            "wVerClient": h.w_ver_client,
            "layout": h.layout.name,
            "page_size": h.layout.page_size,
            "crypt": h.crypt_name,
            "ibFileEof": h.ib_file_eof,
            "header_crc_partial_ok": h.crc_partial_ok,
            "header_crc_full_ok": h.crc_full_ok,
            "fAMapValid": h.f_amap_valid,
            "display_name": self.display_name,
            "wip_protected": h.is_wip,
            "wip_block_encoding": self.ndb.wip_encoding,
            "password_protected": self.password_protected,
        }
