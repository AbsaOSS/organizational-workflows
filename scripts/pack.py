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
  python scripts/pack.py              # build + package dist.tar.gz
  python scripts/pack.py --serve      # live-reload dev server
  python scripts/pack.py --no-package # build only, skip packaging

Output: dist.tar.gz  (contains dist/ + marketplace.json)

Prerequisites: pip install -r requirements-docs.txt
               Set SKIP_PIP_INSTALL=1 to bypass
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


atexit.register(lambda: Path("mkdocs-build.yml").unlink(missing_ok=True))


def run(*args):
    result = subprocess.run(args)
    if result.returncode != 0:
        sys.exit(result.returncode)


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


def auto_generate_nav(docs_dir: str = "docs") -> list:
    """Scan docs/ for .md files, read frontmatter, return nav sorted by order."""
    pages = []
    for md_file in Path(docs_dir).rglob("*.md"):
        rel = md_file.relative_to(docs_dir).as_posix()
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
    section_order: dict = {}

    for page in pages:
        entry = {page["title"]: page["file"]}
        sect = page["section"]
        if sect:
            sections.setdefault(sect, []).append(entry)
            section_order[sect] = min(section_order.get(sect, 999), page["order"])
        else:
            top_level.append(entry)

    nav = list(top_level)
    for sect in sorted(sections, key=lambda s: section_order[s]):
        nav.append({sect: sections[sect]})
    return nav


def generate_build_config():
    import yaml
    cfg = yaml.safe_load(Path("mkdocs.yml").read_text(encoding="utf-8"))
    cfg["nav"] = auto_generate_nav(cfg.get("docs_dir", "docs"))
    Path("mkdocs-build.yml").write_text(
        yaml.dump(cfg, default_flow_style=False, allow_unicode=True), encoding="utf-8"
    )


def generate_marketplace_json():
    import yaml
    nav = yaml.safe_load(Path("mkdocs-build.yml").read_text(encoding="utf-8")).get("nav", [])
    pages: list = []
    counter = [1]

    def collect(items, section=None):
        for item in items:
            if isinstance(item, dict):
                for label, value in item.items():
                    if isinstance(value, str):
                        fm = parse_frontmatter(f"docs/{value}")
                        out = f"docs/{Path(value).with_suffix('').as_posix()}/index.html"
                        entry = {"title": fm.get("title", label), "path": out, "order": fm.get("order", counter[0])}
                        if section or fm.get("section"):
                            entry["section"] = section or fm["section"]
                        pages.append(entry)
                        counter[0] += 1
                    elif isinstance(value, list):
                        collect(value, section=label)

    collect(nav)
    manifest = json.loads(Path("marketplace.json").read_text(encoding="utf-8"))
    manifest["pages"] = pages
    Path("dist/marketplace.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main():
    serve = "--serve" in sys.argv
    no_package = "--no-package" in sys.argv
    unknown = [a for a in sys.argv[1:] if a not in ("--serve", "--no-package")]
    if unknown:
        print(f"Unknown argument(s): {' '.join(unknown)}")
        sys.exit(1)

    if os.environ.get("SKIP_PIP_INSTALL", "0") != "1":
        run(sys.executable, "-m", "pip", "install", "-r", "requirements-docs.txt", "-q", "--break-system-packages")

    generate_build_config()

    if serve:
        run(sys.executable, "-m", "mkdocs", "serve", "-f", "mkdocs-build.yml")
        return

    shutil.rmtree("dist", ignore_errors=True)
    run(sys.executable, "-m", "mkdocs", "build", "-f", "mkdocs-build.yml")
    generate_marketplace_json()

    if no_package:
        print("✅ dist/ ready")
        return

    with tarfile.open("dist.tar.gz", "w:gz") as tar:
        tar.add("dist")
        tar.add("marketplace.json")

    print(f"✅ dist.tar.gz ready ({Path('dist.tar.gz').stat().st_size // 1024}K)")


if __name__ == "__main__":
    main()
