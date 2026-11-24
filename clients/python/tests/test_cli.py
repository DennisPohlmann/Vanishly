import os
import unittest
from unittest import mock

from vanishly.cli import _parser


class GlobalFlags(unittest.TestCase):
    def test_before_and_after_the_command(self):
        with mock.patch.dict(os.environ, {"VANISHLY_URL": "", "VANISHLY_TOKEN": ""}):
            p = _parser()
            self.assertEqual(p.parse_args(["--url", "U", "config"]).url, "U")
            self.assertEqual(p.parse_args(["config", "--url", "U"]).url, "U")
            n = p.parse_args(["share", "s3cret", "--url", "U", "--token", "T", "--json", "--ttl", "60"])
            self.assertEqual((n.secret, n.url, n.token, n.json, n.ttl), ("s3cret", "U", "T", True, 60))

    def test_environment_stays_when_not_given(self):
        with mock.patch.dict(os.environ, {"VANISHLY_URL": "E"}):
            self.assertEqual(_parser().parse_args(["me"]).url, "E")

    def test_help_and_version_commands(self):
        import contextlib, io
        from vanishly.cli import run
        for cmd, text in (("help", "usage: vanishly <command>"), ("version", "(python)")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(run([cmd]), 0)
            self.assertIn(text, out.getvalue())


if __name__ == "__main__":
    unittest.main()
