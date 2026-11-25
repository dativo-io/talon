"""Regression tests for reading `n8n execute` output (#575).

The pinned Docker image printed more after the execution document than the
local npm run did, and the first checker, which parsed everything after the
first "{" as one document, failed with "json.decoder.JSONDecodeError: Extra
data" (GitHub Actions run 45575818855). Run: python3 tests/n8n/test_n8n_output.py
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from n8n_output import execution_document, sanitized_tail  # noqa: E402

DOC = {"data": {"resultData": {"lastNodeExecuted": "Basic LLM Chain",
                               "runData": {"Basic LLM Chain": [{"data": {"main": [[{"json": {"text": "Hello"}}]]}}]}}},
       "status": "success", "finished": True}


class ExecutionDocument(unittest.TestCase):
    def test_trailing_output_after_the_document(self):
        raw = ("Execution was successful:\n====================================\n" + json.dumps(DOC, indent=2)
               + "\nRegistered runner \"JS Task Runner\" (abc)\n{\"level\":\"info\",\"msg\":\"shutting down\"}\n")
        self.assertEqual(execution_document(raw), DOC)

    def test_json_log_lines_before_the_document(self):
        raw = ('{"level":"warn","msg":"task runner in internal mode"}\n'
               '{"data": "not an execution"}\n' + json.dumps(DOC, indent=2) + "\n")
        self.assertEqual(execution_document(raw), DOC)

    def test_no_document_or_a_truncated_one_is_none(self):
        self.assertIsNone(execution_document("Error executing workflow. See log messages for details.\n"))
        self.assertIsNone(execution_document(json.dumps(DOC, indent=2)[:-40]))

    def test_the_old_parser_fails_on_trailing_output(self):
        # The first checker's read, kept to show what this guards against.
        raw = "header\n" + json.dumps(DOC, indent=2) + "\ntrailing log line\n"
        i = raw.find("\n{\n")
        with self.assertRaises(json.JSONDecodeError):
            json.loads(raw[i + 1:])


class SanitizedTail(unittest.TestCase):
    def test_keys_are_masked(self):
        raw = ("Authorization: Bearer talon_uc_abcdef0123456789abcdef\n"
               "provider sk-proj-AbCdEf123456 and key " + "a1" * 32 + "\n")
        out = sanitized_tail(raw)
        for secret in ("talon_uc_abcdef0123456789abcdef", "sk-proj-AbCdEf123456", "a1" * 32):
            self.assertNotIn(secret, out)
        self.assertIn("[redacted]", out)


if __name__ == "__main__":
    unittest.main()
