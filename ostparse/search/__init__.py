"""Full-text search for OST/PST files: query language, segmented on-disk index, evaluator."""

from .build import build_index, compact_index, ensure_index, update_index
from .engine import Hit, Result, ScanSearcher, Searcher
from .index import Index, default_index_path, open_index
from .query import QueryError, parse

__all__ = ["Searcher", "ScanSearcher", "Hit", "Result", "Index", "build_index", "update_index", "compact_index",
           "ensure_index", "open_index", "default_index_path", "parse", "QueryError"]
