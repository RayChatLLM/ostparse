"""Regression coverage for complete command output and JSON transport."""

import importlib
import importlib.util
import json
import sys
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Import the plugin package by location so the tests run from any layout — the
# installed working copy (``.../ostparse_raychat``) and a bare ``git clone``
# whose checkout directory is the package root (CI). Relative imports inside the
# package need a real package name, so register one pointing at this directory.
_PKG = "ostparse_raychat"
if _PKG not in sys.modules:
    _root = Path(__file__).resolve().parent.parent
    _spec = importlib.util.spec_from_file_location(
        _PKG, _root / "__init__.py", submodule_search_locations=[str(_root)]
    )
    if _spec is None or _spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot locate {_PKG} package at {_root}")
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_PKG] = _module
    _spec.loader.exec_module(_module)

commands = importlib.import_module(f"{_PKG}.commands")
messaging = importlib.import_module(f"{_PKG}.ostparse.messaging")
errors = importlib.import_module(f"{_PKG}.ostparse.errors")
rtf = importlib.import_module(f"{_PKG}.ostparse.rtf")
tokenize = importlib.import_module(f"{_PKG}.ostparse.search.tokenize")


class OpenPasswordTests(unittest.TestCase):
    """Opening a password-gated store must never require a password.

    The PidTagPstPassword CRC never encrypts the data, so OSTFile — used both
    by the plugin and directly by agent-generated Python — reads a gated store
    without a password and only rejects a supplied password that is wrong.
    """

    def _stub(self, stored_crc):
        stub = messaging.OSTFile.__new__(messaging.OSTFile)
        stub.password_protected = False
        stub.message_store = lambda: {0x67FF: stored_crc}  # PR_PST_PASSWORD
        return stub

    def test_missing_password_never_raises_on_gated_store(self):
        stub = self._stub(0xE61EB50F)
        stub._check_password(None, False)  # must not raise
        self.assertTrue(stub.password_protected)
        # kept importable for API compatibility, even though it is never raised
        self.assertTrue(hasattr(errors, "PasswordRequired"))

    def test_wrong_password_still_rejected(self):
        stub = self._stub(0xE61EB50F)
        with self.assertRaises(errors.WrongPassword):
            stub._check_password("definitely-wrong", False)

    def test_ungated_store_is_not_marked_protected(self):
        stub = self._stub(0)
        stub._check_password(None, False)
        self.assertFalse(stub.password_protected)


class CommandOutputTests(unittest.TestCase):
    def test_search_json_preserves_large_document_and_last_record(self):
        payload = {"count": "183", "hits": [
            {"nid": n, "subject": "日本語 — café " * 100} for n in range(183)
        ]}
        rendered = json.dumps(payload, ensure_ascii=False, indent=1)
        with patch.object(commands, "_cmd_search", return_value=rendered):
            for settings in (None, {"max_chars": 1}, {"max_chars": 16000}):
                with self.subTest(settings=settings):
                    result = commands.run("search * --limit 200 --json", settings)
                    self.assertEqual(result, rendered)
                    self.assertEqual(json.loads(result), payload)

    def test_large_plain_search_output_is_also_complete(self):
        rendered = "  Unicode λ message\n" * 2000 + "last hit\n "
        with patch.object(commands, "_cmd_search", return_value=rendered):
            self.assertEqual(commands.run("search *", {"max_chars": 1}), rendered)

    def test_search_json_serializes_the_entire_requested_page(self):
        hits = [{"nid": n, "subject": "x" * 300} for n in range(183)]
        result = SimpleNamespace(
            count_str=lambda: "183",
            hits=[SimpleNamespace(as_dict=lambda hit=hit: hit) for hit in hits],
        )
        index = SimpleNamespace(close=lambda: None)
        from ostparse_raychat.ostparse import search
        with (
            patch.object(commands, "_open_ost", return_value=nullcontext(object())),
            patch.object(commands, "_ensure_index", return_value=(index, "reused")),
            patch.object(search, "Searcher") as searcher,
        ):
            searcher.return_value.search.return_value = result
            text = commands.run("search * --limit 200 --offset 20 --json")
            self.assertEqual(json.loads(text), {"count": "183", "hits": hits})
            kwargs = searcher.return_value.search.call_args.kwargs
            self.assertEqual((kwargs["limit"], kwargs["offset"]), (200, 20))

    def test_show_preserves_long_unicode_body_and_whitespace(self):
        body = " \n" + "日本語 — café\n" * 3000 + "last body line\n  "
        headers = "  X-Test: λ\n\n "
        message = SimpleNamespace(
            subject="Test", sender_name="", sender_email="", message_class="IPM.Note",
            date=None, size=99999, message_id=None, recipients=lambda: [],
            attachments=lambda: [], transport_headers=headers,
            body_text=lambda: body, body=body,
        )
        store = SimpleNamespace(message=lambda nid: message)
        with patch.object(commands, "_open_ost", return_value=nullcontext(store)):
            for flag in ("", " --full"):
                result = commands.run("show 0x24 --headers" + flag,
                                      {"max_chars": 10, "body_chars": 5})
                self.assertEqual(result.split("--- body ---\n", 1)[1], body)
                self.assertIn("--- transport headers ---\n" + headers + "\n", result)

    def test_tree_preserves_every_folder_beyond_old_limits(self):
        folders = [SimpleNamespace(name=f"Folder {n}", nid=n, message_count=lambda: 1)
                   for n in range(500)]
        store = SimpleNamespace(walk=lambda: ((folder, 0) for folder in folders))
        with patch.object(commands, "_open_ost", return_value=nullcontext(store)):
            result = commands.run("tree", {"max_chars": 1, "tree_lines": 1})
        self.assertEqual(len(result.splitlines()), 501)
        self.assertIn("Folder 499", result)
        self.assertTrue(result.endswith("500 folders, 500 messages"))

    def test_search_error_is_preserved_without_json_repair(self):
        with patch.object(commands, "_cmd_search", return_value="query error: invalid"):
            self.assertEqual(commands.run("search broken --json"), "query error: invalid")


class QaRegressionTests(unittest.TestCase):
    """Defects found by adversarial QA against the Enron corpus, locked down."""

    def test_out_of_range_date_is_a_clean_query_error_not_a_traceback(self):
        # Parsing happens before any store is opened, so no mailbox is needed.
        for q in ("search date:2002-13-99", "count date:9999-99-99", "search received:2002-02-30"):
            out = commands.run(q, state={})
            self.assertIn("query error", out)
            self.assertNotIn("Traceback", out)

    def test_nonpositive_limit_is_rejected_not_silently_one(self):
        self.assertIn("positive integer", commands.run("search * --limit 0", state={}))
        self.assertIn("positive integer", commands.run("search * --limit -5", state={}))
        self.assertIn("non-negative", commands.run("search * --offset -1", state={}))

    def test_show_rejects_a_folder_nid_instead_of_a_hollow_message(self):
        store = SimpleNamespace(message=lambda nid: SimpleNamespace())
        with patch.object(commands, "_open_ost", return_value=nullcontext(store)):
            out = commands.run("show 0x8202", state={})  # 0x8202 is a folder nid (type 0x02)
            self.assertIn("is not a message", out)
            self.assertNotIn("--- body ---", out)

    def test_show_accepts_a_normal_message_nid(self):
        message = SimpleNamespace(
            subject="Hi", sender_name="", sender_email="", message_class="IPM.Note",
            date=None, size=1, message_id=None, recipients=lambda: [],
            attachments=lambda: [], transport_headers="", body_text=lambda: "body",
        )
        with patch.object(commands, "_open_ost", return_value=nullcontext(SimpleNamespace(message=lambda nid: message))):
            out = commands.run("show 0x200244", state={})  # type 0x04
            self.assertIn("--- body ---", out)

    def test_failed_open_names_the_attempted_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".ost", delete=False) as fh:
            fh.write(b"not a mailbox")
            path = fh.name
        try:
            out = commands.run(f"open {path}", state={})
            self.assertIn(path, out)
            self.assertIn("cannot read", out)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_export_is_confined_to_the_workspace(self):
        import os
        out_dir, deny = commands._resolve_export_dir("/etc/outside_qa", "/ws")
        self.assertEqual(out_dir, "")
        self.assertIn("confined to the session workspace", deny)
        inside, deny2 = commands._resolve_export_dir("out", "/ws")
        self.assertEqual((inside, deny2), (os.path.join("/ws", "out"), ""))
        # No workspace (standalone CLI) keeps the unrestricted behavior.
        free, deny3 = commands._resolve_export_dir("/tmp/anywhere", None)
        self.assertEqual(deny3, "")
        self.assertTrue(free.endswith("/tmp/anywhere"))

    def test_rtf_unicode_escape_is_not_doubled(self):
        # 舗 is ' with an ANSI \'92 fallback that must be dropped (uc=1).
        self.assertEqual(rtf.rtf_to_text(b"{\\rtf1\\ansi it\\u8217\\'92s\\par}"), "it’s")
        self.assertEqual(rtf.rtf_to_text(b"{\\rtf1\\ansi plain only\\par}"), "plain only")

    def test_html_keeps_stray_angle_brackets(self):
        got = tokenize.html_to_text(b"<div>Price < 100 and qty > 5 units</div>")
        self.assertEqual(got, "Price < 100 and qty > 5 units")


if __name__ == "__main__":
    unittest.main()
