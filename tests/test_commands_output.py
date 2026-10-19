"""Regression coverage for complete command output and JSON transport."""

import json
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from ostparse_raychat import commands


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
                result = commands.run("show 0x20 --headers" + flag,
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


if __name__ == "__main__":
    unittest.main()
