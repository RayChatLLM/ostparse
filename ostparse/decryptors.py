"""
Block decryptors for files whose header says ``bCryptMethod = 0x10``
(``NDB_CRYPT_EDPCRYPTED``, "Encrypted with Windows Information Protection").

What [MS-PST] says about that value is one sentence; the cipher, key
derivation and key storage are not published - the key material lives in
Windows Information Protection / EFS on the machine that wrote the file, not
in the file.  ostparse therefore cannot ship *the* algorithm, and it refuses
to guess one silently.  Instead it handles the value like this:

1. On open it probes whether the blocks are actually readable (plain,
   permute- or cyclic-encoded).  That is the case when the file was read
   inside its WIP context or decrypted on the Windows host (``cipher /d``,
   a WIP-aware copy, or any tool that strips the EFS layer); the flag then
   just records that the file *was* WIP-protected.
2. If the blocks are ciphertext, the caller is asked for a key
   (:class:`ostparse.errors.KeyRequired`; the CLI prompts for it) and the
   key is handed to a *block decryptor* chosen with ``--decryptor``:

   * ``module:factory`` - an importable factory ``factory(key: str) ->
     decryptor`` where ``decryptor(payload: bytes, bid: int, ib: int) ->
     bytes``.  This is the hook for an EDP implementation obtained from
     elsewhere (a vendor library, a reverse-engineered routine, ...).
   * ``demo-xor`` - a keyed XOR stream cipher that exists so the whole
     prompt-for-key path can be exercised end to end by the test-suite and
     by ``ostgen --wip-key``.  It is **not** Microsoft's cipher and will not
     open a real WIP-protected file.

The decryptor is called once per external data block, after any 4K-format
zlib decompression, with the block's BID and file offset so key schedules
that depend on either can be implemented.
"""

from __future__ import annotations

import hashlib
import importlib
from typing import Callable, Dict

Decryptor = Callable[[bytes, int, int], bytes]
Factory = Callable[[str], Decryptor]


def key_bytes(key: str) -> bytes:
    """Interpret a key string: ``hex:...`` / ``base64:...`` / even-length hex / raw UTF-8."""
    k = key.strip()
    if k.lower().startswith("hex:"):
        return bytes.fromhex(k[4:])
    if k.lower().startswith("base64:"):
        import base64
        return base64.b64decode(k[7:])
    if len(k) >= 16 and len(k) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in k):
        return bytes.fromhex(k)
    return k.encode("utf-8")


def demo_xor(key: str) -> Decryptor:
    """Keyed XOR stream cipher (SHA-256 counter mode over key || bid || counter).

    Symmetric: the same function encrypts and decrypts.  For testing only.
    """
    kb = key_bytes(key)

    def crypt(payload: bytes, bid: int, ib: int) -> bytes:
        n = len(payload)
        if n == 0:
            return payload
        prefix = kb + bid.to_bytes(8, "little")
        stream = b"".join(hashlib.sha256(prefix + i.to_bytes(4, "little")).digest() for i in range((n + 31) // 32))
        return (int.from_bytes(payload, "little") ^ int.from_bytes(stream[:n], "little")).to_bytes(n, "little")

    return crypt


BUILTIN: Dict[str, Factory] = {
    "demo-xor": demo_xor,
}


def load_decryptor(spec: str, key: str) -> Decryptor:
    """Build a block decryptor from a ``--decryptor`` spec and a key.

    ``spec`` is a built-in name (see :data:`BUILTIN`) or ``module:factory``.
    """
    if spec in BUILTIN:
        return BUILTIN[spec](key)
    if ":" not in spec:
        raise ValueError("unknown decryptor %r (built-ins: %s; or use module:factory)" % (spec, ", ".join(sorted(BUILTIN))))
    mod_name, _, attr = spec.partition(":")
    mod = importlib.import_module(mod_name)
    factory = getattr(mod, attr, None)
    if factory is None:
        raise ValueError("module %s has no attribute %s" % (mod_name, attr))
    return factory(key)
