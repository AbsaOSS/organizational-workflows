#!/usr/bin/env python3
#
# Copyright 2026 ABSA Group Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""pack.py — build the docs site and package the release artifact.

Usage:
  python scripts/pack.py             # build + package dist.tar.gz
  python scripts/pack.py --serve     # generate config + live-reload dev server
  python scripts/pack.py --no-package  # build only, skip packaging

Output: dist.tar.gz  (contains dist/ + marketplace.json)

Prerequisites: pip install -r requirements-docs.txt
               Set SKIP_PIP_INSTALL=1 to bypass (e.g. pre-installed environments)
"""

import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path


# ── Build-time cleanup ────────────────────────────────────────────────────────
def _cleanup():
    Path("mkdocs-build.yml").unlink(missing_ok=True)


atexit.register(_cleanup)


# ── Helpers ───────────────────────────────────────────────────────────────────
def run(*args, **kwargs):
    result = subprocess.run(args, **kwargs)
    if result.returncode != 0:
        sys.exit(result.returncode)


def human_size(path: Path) -> str:
    size = float(path.stat().st_size)
    for unit in ("B", "K", "M", "G"):
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.0f}T"


def parse_frontmatter(md_path: str) -> dict:
    text = Path(md_path).read_text(encoding="utf-8")
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    meta = {}
    if m:
        for line in m.group(1).splitlines():
            kv = line.split(":", 1)
            if len(kv) == 2:
                k, v = kv[0].strip(), kv[1].strip()
                meta[k] = int(v) if v.isdigit() else v
    return meta


# ── Auto-generate nav from frontmatter ───────────────────────────────────────
def auto_generate_nav(docs_dir: str = "docs") -> list:
    """Scan docs/ for .md files, read frontmatter, build nav sorted by order."""
    docs_path = Path(docs_dir)
    pages = []

    for md_file in docs_path.rglob("*.md"):
        rel = md_file.relative_to(docs_path).as_posix()
        fm = parse_frontmatter(str(md_file))
        pages.append({
            "file": rel,
            "title": fm.get("title", md_file.stem.replace("-", " ").title()),
            "order": fm.get("order", 999),
            "section": fm.get("section"),
        })

    pages.sort(key=lambda p: p["order"])

    top_level: list = []
    sections: dict = {}
    section_min_order: dict = {}

    for page in pages:
        entry = {page["title"]: page["file"]}
        sect = page["section"]
        if sect:
            sections.setdefault(sect, []).append(entry)
            section_min_order[sect] = min(section_min_order.get(sect, 999), page["order"])
        else:
            top_level.append(entry)

    nav = list(top_level)
    for sect_name in sorted(sections, key=lambda s: section_min_order[s]):
        nav.append({sect_name: sections[sect_name]})

    return nav


# ── Generate build config ─────────────────────────────────────────────────────
def generate_build_config():
    import yaml

    cfg = yaml.safe_load(Path("mkdocs.yml").read_text(encoding="utf-8"))
    nav = auto_generate_nav(cfg.get("docs_dir", "docs"))
    print(f"  Auto-generated nav with {len(nav)} page(s)")
    cfg["nav"] = nav
    Path("mkdocs-build.yml").write_text(
        yaml.dump(cfg, default_flow_style=False, allow_unicode=True), encoding="utf-8"
    )


# ── Generate marketplace.json ─────────────────────────────────────────────────
def generate_marketplace_json():
    import yaml

    cfg = yaml.safe_load(Path("mkdocs-build.yml").read_text(encoding="utf-8"))
    nav = cfg.get("nav", [])
    pages = []
    order_counter = [1]

    def add_entries(items, section=None):
        for item in items:
            if isinstance(item, dict):
                for label, value in item.items():
                    if isinstance(value, str):
                        fm = parse_frontmatter(f"docs/{value}")
                        rel = Path(value).with_suffix("")
                        out = f"docs/{rel.as_posix()}/index.html"
                        entry = {
                            "title": fm.get("title", label),
                            "path": out,
                            "order": fm.get("order", order_counter[0]),
                        }
                        if section:
                            entry["section"] = section
                        elif fm.get("section"):
                            entry["section"] = fm["section"]
                        pages.append(entry)
                        order_counter[0] += 1
                    elif isinstance(value, list):
                        add_entries(value, section=label)

    add_entries(nav)
    manifest = json.loads(Path("marketplace.json").read_text(encoding="utf-8"))
    manifest["pages"] = pages
    Path("dist/marketplace.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  {len(pages)} page(s) written to dist/marketplace.json")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    serve = False
    no_package = False
    for arg in sys.argv[1:]:
        if arg == "--serve":
            serve = True
        elif arg == "--no-package":
            no_package = True
        else:
            print(f"Unknown argument: {arg}")
            sys.exit(1)

    if os.environ.get("SKIP_PIP_INSTALL", "0") != "1":
        print("▶ Installing Python dependencies...")
        run(sys.executable, "-m", "pip", "install", "-r", "requirements-docs.txt", "-q", "--break-system-packages")

    if serve:
        print("▶ Generating build config for dev server...")
        generate_build_config()
        print("▶ Starting dev server (mkdocs serve)...")
        run(sys.executable, "-m", "mkdocs", "serve", "-f", "mkdocs-build.yml")
        return

    print("▶ Cleaning dist/...")
    shutil.rmtree("dist", ignore_errors=True)

    print("▶ Generating build config...")
    generate_build_config()

    print("▶ Building docs...")
    run(sys.executable, "-m", "mkdocs", "build", "-f", "mkdocs-build.yml")

    if not Path("dist/docs").exists():
        print("❌ dist/docs missing — build failed")
        sys.exit(1)

    print("▶ Generating dist/marketplace.json...")
    generate_marketplace_json()

    if no_package:
        print("✅ dist/ ready")
        return

    print("▶ Packaging...")
    with tarfile.open("dist.tar.gz", "w:gz") as tar:
        tar.add("dist")
        tar.add("marketplace.json")

    size = human_size(Path("dist.tar.gz"))
    print(f"✅ dist.tar.gz ready ({size})")
    print("   dist/docs/ → documentation")


if __name__ == "__main__":
    main()
