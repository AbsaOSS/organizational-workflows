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
  python scripts/pack.py            # standalone build
  python scripts/pack.py --headless # headless build (no top nav)
  python scripts/pack.py --serve    # generate config + live-reload dev server

Output: dist.tar.gz  (contains dist/ + marketplace.json)

Prerequisites: pip install -r requirements-docs.txt
               Set SKIP_PIP_INSTALL=1 to bypass (e.g. managed environments where packages are pre-installed)
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
from typing import Any


# ── Build-time cleanup ────────────────────────────────────────────────────────
def _cleanup():
    for f in ("mkdocs-build.yml", "mkdocs-headless-build.yml"):
        Path(f).unlink(missing_ok=True)


atexit.register(_cleanup)


# ── Helpers ───────────────────────────────────────────────────────────────────
def run(*args, **kwargs):
    """Run a subprocess, raising on non-zero exit."""
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
def auto_generate_nav(docs_dir="docs"):
    """Scan docs/ for .md files, read frontmatter, build nav sorted by order."""
    docs_path = Path(docs_dir)
    pages = []

    for md_file in docs_path.rglob("*.md"):
        rel = md_file.relative_to(docs_path).as_posix()
        fm = parse_frontmatter(str(md_file))
        pages.append(
            {
                "file": rel,
                "title": fm.get("title", md_file.stem.replace("-", " ").title()),
                "order": fm.get("order", 999),
                "section": fm.get("section"),
            }
        )

    pages.sort(key=lambda p: p["order"])

    top_level: list[dict[str, Any]] = []
    sections: dict[str, list[dict[str, Any]]] = {}
    section_min_order: dict[str, int] = {}

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


# ── Generate build configs ────────────────────────────────────────────────────
def generate_build_configs():
    import yaml

    cfg = yaml.safe_load(Path("mkdocs.yml").read_text(encoding="utf-8"))

    nav = auto_generate_nav(cfg.get("docs_dir", "docs"))
    print(
        f"  Auto-generated nav with {sum(len(v) if isinstance(v, dict) and isinstance(list(v.values())[0], list) else 1 for v in nav)} page(s)"
    )

    cfg["nav"] = nav

    Path("mkdocs-build.yml").write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True), encoding="utf-8")

    Path("mkdocs-headless-build.yml").write_text(
        "INHERIT: mkdocs-build.yml\n\nextra:\n  headless: true\n", encoding="utf-8"
    )


# ── HTML page wrapper for showcase content ───────────────────────────────────
SHOWCASE_WRAPPER = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Showcase</title>
  <link rel="stylesheet" href="docs/style.css" />
  <link rel="stylesheet" href="showcase.css" />
</head>
<body>
{content}
</body>
</html>"""


# ── Render showcase from data ────────────────────────────────────────────────
def render_showcase(headless=False):
    import yaml

    data_path = Path("data/showcase.yml")
    if not data_path.exists():
        print("  ⚠ data/showcase.yml missing — skipping showcase render")
        return

    data = yaml.safe_load(data_path.read_text(encoding="utf-8"))
    content = data.get("content", "")

    if not content:
        print("  ⚠ data/showcase.yml has no content — skipping showcase render")
        return

    if headless:
        content = re.sub(
            r"<!-- ── Navigation ── -->\s*<nav[^>]*>.*?</nav>\s*<!-- ── /Navigation ── -->",
            "",
            content,
            flags=re.DOTALL,
        )

    html = SHOWCASE_WRAPPER.format(content=content)
    Path("dist/index.html").write_text(html, encoding="utf-8")

    if Path("showcase.css").exists():
        shutil.copy2("showcase.css", "dist/showcase.css")

    if Path("admin").is_dir():
        shutil.copytree("admin", "dist/admin", dirs_exist_ok=True)


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
                        out = "docs/index.html" if rel.name == "index" else f"docs/{rel.as_posix()}/index.html"
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
    headless = False
    serve = False
    no_package = False
    for arg in sys.argv[1:]:
        if arg == "--headless":
            headless = True
        elif arg == "--serve":
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
        generate_build_configs()
        print("▶ Starting dev server (mkdocs serve)...")
        run(sys.executable, "-m", "mkdocs", "serve", "-f", "mkdocs-build.yml")
        return

    print("▶ Cleaning dist/...")
    shutil.rmtree("dist", ignore_errors=True)

    print("▶ Generating build configs...")
    generate_build_configs()

    if headless:
        print("▶ Building docs (headless)...")
        run(sys.executable, "-m", "mkdocs", "build", "-f", "mkdocs-headless-build.yml")

        if not Path("dist/docs/index.html").exists():
            print("❌ dist/docs/index.html missing — build failed")
            sys.exit(1)

        print("▶ Rendering showcase (headless)...")
        render_showcase(headless=True)

        print("▶ Generating dist/marketplace.json with pages manifest...")
        generate_marketplace_json()

        if no_package:
            print("✅ dist/ rebuilt (headless, packaging skipped)")
            return

        print("▶ Packaging (headless)...")
        with tarfile.open("dist.tar.gz", "w:gz") as tar:
            tar.add("dist")
            tar.add("marketplace.json")

        size = human_size(Path("dist.tar.gz"))
        print(f"✅ dist.tar.gz ready ({size}) [headless]")
        print("   dist/index.html      → showcase without nav (headless entry point)")
        print("   dist/docs/index.html → documentation")

    else:
        print("▶ Building docs...")
        run(sys.executable, "-m", "mkdocs", "build", "-f", "mkdocs-build.yml")

        if not Path("dist/docs/index.html").exists():
            print("❌ dist/docs/index.html missing — build failed")
            sys.exit(1)

        print("▶ Rendering showcase...")
        render_showcase(headless=False)

        print("▶ Generating dist/marketplace.json with pages manifest...")
        generate_marketplace_json()

        if no_package:
            print("✅ dist/ rebuilt (packaging skipped)")
            return

        print("▶ Packaging...")
        with tarfile.open("dist.tar.gz", "w:gz") as tar:
            tar.add("dist")
            tar.add("marketplace.json")

        size = human_size(Path("dist.tar.gz"))
        print(f"✅ dist.tar.gz ready ({size})")
        print("   dist/index.html      → product showcase (entry point)")
        print("   dist/docs/index.html → documentation")


if __name__ == "__main__":
    main()
