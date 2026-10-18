"""Exception hierarchy for :mod:`ostparse`."""


class OSTError(Exception):
    """Base class for all parser errors."""


class NotAnOSTFile(OSTError):
    """The file does not start with a valid [MS-PST] header."""


class UnsupportedFormat(OSTError):
    """A structurally valid but unsupported variant."""


class CorruptFile(OSTError):
    """A structure failed validation (bad signature, size mismatch, dangling BID...)."""


class NodeNotFound(OSTError, KeyError):
    """A NID was not found in the node B-tree or in a subnode tree."""


class BlockNotFound(OSTError, KeyError):
    """A BID was not found in the block B-tree."""


class KeyRequired(OSTError):
    """The file is WIP/EDP-encrypted (bCryptMethod 0x10) and no block decryptor was supplied."""


class WrongKey(KeyRequired):
    """The supplied WIP key/decryptor does not produce valid data."""


class PasswordRequired(OSTError):
    """The message store carries a PST password (PidTagPstPassword) and none was supplied."""


class WrongPassword(OSTError):
    """The supplied PST password does not match PidTagPstPassword."""
