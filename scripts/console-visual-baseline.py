#!/usr/bin/env python3
"""Reviewable console screenshot baseline; Git source/asset IDs, not pixel equality.

The browser fixture uses real clocks, paths and session IDs. A fresh capture is
required for review, but pixel-perfect equality across runs is not a contract.
The manifest detects changes to known render inputs and to curated assets.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ASSETS = ROOT / "docs/assets/console"
MANIFEST = "baseline.json"
ASSETS = (
    "configuration.webp", "costs.webp", "evidence-verification.webp",
    "overview-attention.webp", "overview-mobile.webp", "session-investigation.webp",
    "showcase.webp", "system-diagnostics.webp", "tamper-detection.webp",
    "use-case-summary.webp",
)
PREFIXES = (
    "internal/console/", "internal/fleet/", "internal/fleetview/",
    "internal/runtimestatus/", "internal/effective/", "internal/evidence/",
    "internal/session/", "internal/costs/", "internal/pricing/",
    "internal/config/", "internal/policy/", "tests/browser/seed/",
)
CMD_PREFIXES = (
    "internal/cmd/ui", "internal/cmd/serve", "internal/cmd/agents",
    "internal/cmd/costs", "internal/cmd/agent_bridge",
)
EXACT = {
    "go.mod", "go.sum",
    "tests/browser/03-screenshots.spec.js", "tests/browser/global-setup.js",
    "tests/browser/global-teardown.js", "tests/browser/helpers.js",
    "tests/browser/package.json", "tests/browser/package-lock.json",
    "tests/browser/playwright.config.js", "scripts/console-browser-smoke.sh",
    "scripts/generate-console-visuals.py", "scripts/console-visual-baseline.py",
    ".github/workflows/console-screenshots.yml",
}


def is_render_input(path):
    if path in EXACT:
        return True
    if not path.startswith(PREFIXES + CMD_PREFIXES):
        return False
    # Test assertions and prose do not change rendering.
    if re.search(r"(?:_test\.go|\.test\.[tj]sx?|\.spec\.[tj]sx?|\.md)$", path):
        return False
    if Path(path).name in {".gitignore", ".gitkeep"}:
        return False
    return True


def render_inputs(root):
    # The index is intentional: stage UI and fixture changes before a local
    # refresh; CI checks a clean checkout of the revision under review.
    raw = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root)
    entries = {}
    for row in raw.decode("utf-8").split("\0"):
        if not row:
            continue
        meta, name = row.split("\t", 1)
        if not is_render_input(name):
            continue
        _, blob, stage = meta.split()
        if stage != "0":
            raise ValueError("Unmerged render input: " + name)
        entries[name] = blob
    if not entries:
        raise ValueError("No render inputs found")
    return dict(sorted(entries.items()))


def asset_ids(directory):
    result = {}
    actual = {p.name for p in directory.glob("*.webp")}
    if actual != set(ASSETS):
        raise ValueError("Unexpected screenshot set; missing: "
                         + ", ".join(sorted(set(ASSETS) - actual))
                         + "; extra: " + ", ".join(sorted(actual - set(ASSETS))))
    for name in ASSETS:
        data = (directory / name).read_bytes()
        if (len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP"
                or int.from_bytes(data[4:8], "little") + 8 != len(data)):
            raise ValueError("Invalid WebP: " + name)
        # Same Git blob ID as the checked-in binary; SHA-1 is an object ID,
        # not a signature or a security assertion.
        result[name] = hashlib.sha1(
            b"blob " + str(len(data)).encode("ascii") + b"\0" + data,
            usedforsecurity=False,
        ).hexdigest()
    return result


def snapshot(root, assets):
    return {"schema": 1, "inputs": render_inputs(root), "assets": asset_ids(assets)}


def changed(old, new):
    return sorted(k for k in old.keys() | new.keys() if old.get(k) != new.get(k))


def verify(root, assets):
    baseline = json.loads((assets / MANIFEST).read_text(encoding="utf-8"))
    current = snapshot(root, assets)
    if baseline.get("schema") != current["schema"]:
        raise ValueError("Unsupported screenshot baseline schema")
    inputs = changed(baseline["inputs"], current["inputs"])
    images = changed(baseline["assets"], current["assets"])
    if not inputs and not images:
        return True
    for title, names in (("Render inputs changed", inputs), ("Curated assets changed", images)):
        if names:
            print(f"{title} ({len(names)}):", file=sys.stderr)
            for name in names[:30]:
                print("  " + name, file=sys.stderr)
            if len(names) > 30:
                print(f"  ... and {len(names) - 30} more", file=sys.stderr)
    print("Refresh and review the screenshot artifact; commit its WebP files and baseline.json together.",
          file=sys.stderr)
    return False


def visual_report(baseline, candidate, output):
    from PIL import Image, ImageChops, ImageStat
    rows = []
    for name in ASSETS:
        with Image.open(baseline / name) as a, Image.open(candidate / name) as b:
            a, b = a.convert("RGB"), b.convert("RGB")
            row = {"file": name, "baseline_size": list(a.size), "candidate_size": list(b.size)}
            if a.size == b.size:
                diff = ImageChops.difference(a, b)
                row["mean_absolute_rgb_difference"] = round(sum(ImageStat.Stat(diff).mean) / 3, 3)
            rows.append(row)
    output.write_text(json.dumps({
        "note": "Informational only: real timestamps, paths, IDs and rendering differences are expected.",
        "images": rows,
    }, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "write", "compare"))
    parser.add_argument("--assets", type=Path, default=DEFAULT_ASSETS)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "check":
            if not verify(ROOT, args.assets):
                return 1
            print("Console screenshot baseline matches tracked render inputs and curated assets.")
        elif args.command == "write":
            data = snapshot(ROOT, args.assets)
            (args.assets / MANIFEST).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            print("Wrote screenshot baseline:", args.assets / MANIFEST)
        else:
            if args.candidate is None or args.output is None:
                parser.error("compare requires --candidate and --output")
            visual_report(args.assets, args.candidate, args.output)
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print("Screenshot baseline error:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
