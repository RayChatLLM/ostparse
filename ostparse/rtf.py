"""
LZFu decompression for PidTagRtfCompressed ([MS-OXRTFCP]).

Only needed when a message carries an RTF body and nothing else; the exporter
then turns it into plain text so the .eml still has a readable body.
"""

from __future__ import annotations

import re
import struct

_INIT_DICT = (
    b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss "
    b"\\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier"
    b"{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
)
assert len(_INIT_DICT) == 207

MAGIC_COMPRESSED = 0x75465A4C  # 'LZFu'
MAGIC_UNCOMPRESSED = 0x414C454D  # 'MELA'


def decompress_rtf(data: bytes) -> bytes:
    """Return the RTF text of a PidTagRtfCompressed value."""
    if len(data) < 16:
        return b""
    comp_size, raw_size, magic, _crc = struct.unpack_from("<IIII", data, 0)
    body = data[16:16 + max(0, comp_size - 12)]
    if magic == MAGIC_UNCOMPRESSED:
        return body[:raw_size]
    if magic != MAGIC_COMPRESSED:
        raise ValueError("not an LZFu stream (magic 0x%08x)" % magic)
    dict_ = bytearray(4096)
    dict_[:207] = _INIT_DICT
    wpos = 207
    out = bytearray()
    i = 0
    n = len(body)
    while i < n and len(out) < raw_size:
        ctrl = body[i]
        i += 1
        for bit in range(8):
            if i >= n or len(out) >= raw_size:
                break
            if ctrl & (1 << bit):
                if i + 1 >= n:
                    break
                ref = (body[i] << 8) | body[i + 1]
                i += 2
                off = ref >> 4
                length = (ref & 0x0F) + 2
                if off == wpos:
                    return bytes(out)
                for _ in range(length):
                    c = dict_[off]
                    off = (off + 1) & 0xFFF
                    dict_[wpos] = c
                    wpos = (wpos + 1) & 0xFFF
                    out.append(c)
            else:
                c = body[i]
                i += 1
                dict_[wpos] = c
                wpos = (wpos + 1) & 0xFFF
                out.append(c)
    return bytes(out)


_RTF_TOKEN = re.compile(rb"\\([a-zA-Z]+)(-?\d+)? ?|\\'([0-9a-fA-F]{2})|\\([^a-zA-Z])|([{}])|(\r?\n)")


def rtf_to_text(rtf: bytes) -> str:
    """A small, forgiving RTF-to-plain-text conversion (good enough for bodies)."""
    out = []
    skip_depth = 0
    depth = 0
    pos = 0
    # A \uN unicode run is followed by `uc` fallback "characters" (an ANSI \'xx
    # escape or a literal byte) that must be dropped, else every smart quote,
    # dash and accented letter that Outlook writes as \uN\'xx is doubled.
    uc = 1
    uskip = 0
    skip_groups = {b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict", b"object",
                   b"htmltag", b"mhtmltag", b"fldinst", b"generator", b"themedata", b"colorschememapping"}
    for m in _RTF_TOKEN.finditer(rtf):
        start = m.start()
        if start > pos and skip_depth == 0:
            seg = rtf[pos:start]
            if uskip > 0:
                take = min(uskip, len(seg))
                uskip -= take
                seg = seg[take:]
            if seg:
                out.append(seg.decode("latin-1"))
        pos = m.end()
        word, num, hexb, ctrl, brace, _nl = m.groups()
        if brace == b"{":
            uskip = 0
            depth += 1
            if skip_depth:
                skip_depth += 1
            # look ahead for a destination we skip
            nxt = _RTF_TOKEN.match(rtf, pos)
            if nxt:
                w2 = nxt.group(1)
                if w2 and w2 in skip_groups:
                    skip_depth = skip_depth or 1
                if nxt.group(4) == b"*":
                    skip_depth = skip_depth or 1
        elif brace == b"}":
            uskip = 0
            depth -= 1
            if skip_depth:
                skip_depth -= 1
        elif skip_depth:
            continue
        elif hexb is not None:
            if uskip > 0:
                uskip -= 1  # this \'xx is the fallback for the preceding \uN
                continue
            out.append(bytes.fromhex(hexb.decode()).decode("cp1252", errors="replace"))
        elif word is not None:
            if word == b"uc" and num is not None:
                uc = max(0, int(num))
                continue
            if word == b"u" and num is not None:
                cp = int(num)
                out.append(chr(cp + 65536 if cp < 0 else cp))
                uskip = uc
                continue
            uskip = 0  # any other control word ends a pending substitution run
            if word in (b"par", b"line"):
                out.append("\n")
            elif word == b"tab":
                out.append("\t")
        elif ctrl is not None:
            uskip = 0
            if ctrl in (b"\\", b"{", b"}"):
                out.append(ctrl.decode())
            elif ctrl == b"~":
                out.append("\u00a0")
    if pos < len(rtf) and skip_depth == 0:
        out.append(rtf[pos:].decode("latin-1"))
    text = "".join(out)
    return text.replace("\r\n", "\n").strip()
