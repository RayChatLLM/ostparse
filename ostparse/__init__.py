"""
ostparse - a pure-Python, streaming reader for Outlook OST/PST files.

Implements [MS-PST] (NDB -> LTP -> Messaging) for the Unicode 512-byte-page
format and the 4 KiB-page OST format used since Outlook 2013, including
permutative/cyclic block encryption and per-block zlib compression.  Nothing
is ever loaded whole: B-tree pages and blocks are fetched on demand through
bounded LRU caches, tables are iterated block by block and attachments are
streamed, so 10 GB+ files parse in a few tens of megabytes of RAM.

Quick start::

    from ostparse import OSTFile
    with OSTFile("mailbox.ost") as ost:
        for folder, depth in ost.walk():
            print("  " * depth + folder.name, folder.message_count())
        inbox = ost.find_folder("/Root - Mailbox/IPM_SUBTREE/Inbox")
        for msg in inbox.messages():
            print(msg.subject, msg.date, [a.filename for a in msg.attachments()])

    from ostparse.export import export_folder_tree
    export_folder_tree(ost, "out/")
"""

from .errors import (BlockNotFound, CorruptFile, KeyRequired, NodeNotFound, NotAnOSTFile, OSTError, PasswordRequired,
                     UnsupportedFormat, WrongKey, WrongPassword)
from .messaging import Attachment, Folder, Message, OSTFile, Recipient
from .export import EmlWriter, export_folder_tree, message_to_eml_bytes

__version__ = "0.3.0"
__all__ = [
    "OSTFile", "Folder", "Message", "Attachment", "Recipient",
    "EmlWriter", "export_folder_tree", "message_to_eml_bytes",
    "OSTError", "NotAnOSTFile", "UnsupportedFormat", "CorruptFile", "NodeNotFound", "BlockNotFound",
    "KeyRequired", "WrongKey", "PasswordRequired", "WrongPassword",
]
