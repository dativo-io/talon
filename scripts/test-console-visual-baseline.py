#!/usr/bin/env python3
"""Offline tests of the freshness gate (no Chromium needed)."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from PIL import Image

spec = importlib.util.spec_from_file_location(
    "baseline", Path(__file__).with_name("console-visual-baseline.py")
)
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q")
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.put("internal/console/frontend/src/App.tsx", "original")
        self.put("README.md", "intro")
        self.put("internal/console/view_test.go", "assertion")
        self.git("add", ".")
        for name in baseline.ASSETS:
            Image.new("RGB", (8, 8), "white").save(self.assets / name, "WEBP")
        self.refresh()

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def refresh(self):
        (self.assets / baseline.MANIFEST).write_text(
            json.dumps(baseline.snapshot(self.root, self.assets)), encoding="utf-8"
        )

    def verify(self):
        with contextlib.redirect_stderr(io.StringIO()):
            return baseline.verify(self.root, self.assets)

    def test_current_and_prose_only(self):
        self.assertTrue(self.verify())
        self.put("README.md", "changed")
        self.put("internal/console/view_test.go", "new assertion")
        self.git("add", ".")
        self.assertTrue(self.verify())

    def test_render_input_changes_require_reviewed_baseline(self):
        self.put("internal/console/frontend/src/App.tsx", "new UI")
        self.git("add", ".")
        self.assertFalse(self.verify())
        self.refresh()
        self.assertTrue(self.verify())

    def test_asset_change_is_detected(self):
        Image.new("RGB", (8, 8), "black").save(self.assets / baseline.ASSETS[0], "WEBP")
        self.assertFalse(self.verify())

    def test_missing_asset_is_an_error(self):
        (self.assets / baseline.ASSETS[0]).unlink()
        with self.assertRaises(ValueError):
            self.verify()

    def test_comparison_reports_difference_without_pixel_gate(self):
        old = self.assets
        new = self.root / "fresh"
        new.mkdir()
        for name in baseline.ASSETS:
            Image.new("RGB", (8, 8), "black").save(new / name, "WEBP")
        output = self.root / "diff.json"
        baseline.visual_report(old, new, output)
        data = json.loads(output.read_text())
        self.assertEqual(len(data["images"]), len(baseline.ASSETS))
        self.assertGreater(data["images"][0]["mean_absolute_rgb_difference"], 0)


if __name__ == "__main__":
    unittest.main()
