#!/usr/bin/env bash
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

# pack.sh — build the docs site and package the release artifact.
#
# Usage:
#   bash scripts/pack.sh            # standalone
#   bash scripts/pack.sh --headless # headless (no top nav)
#
# Output: dist.tar.gz  (contains dist/ + marketplace.json)
#
# Prerequisites: pip install -r requirements-docs.txt
#               Set SKIP_PIP_INSTALL=1 to bypass (e.g. managed environments where packages are pre-installed)

set -euo pipefail

# ── Detect Python binary ─────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
  PYTHON=python3
elif command -v python &>/dev/null; then
  PYTHON=python
else
  echo "❌ No python3 or python found in PATH"
  exit 1
fi

# ── Build-time cleanup ────────────────────────────────────────────────────────
# mkdocs-build.yml and mkdocs-headless-build.yml are generated during the build
# and must not be committed or left behind after the script exits.
_cleanup() {
  rm -f mkdocs-build.yml mkdocs-headless-build.yml
}
trap _cleanup EXIT

# ── Merge mkdocs.yml into build-time configs ──────────────────────────────────
# The generated configs are used for the actual mkdocs build so mkdocs.yml stays
# clean and uncommitted.
generate_build_configs() {
  $PYTHON - <<'PY'
import re, yaml, pathlib

def parse_frontmatter(md_path):
    text = pathlib.Path(md_path).read_text(encoding='utf-8')
    m = re.match(r'^---\s*\n(.*?)\n---\s*\n', text, re.DOTALL)
    meta = {}
    if m:
        for line in m.group(1).splitlines():
            kv = line.split(':', 1)
            if len(kv) == 2:
                k, v = kv[0].strip(), kv[1].strip()
                meta[k] = int(v) if v.isdigit() else v
    return meta

def auto_generate_nav(docs_dir='docs'):
    docs_path = pathlib.Path(docs_dir)
    pages = []
    for md_file in docs_path.rglob('*.md'):
        rel = md_file.relative_to(docs_path).as_posix()
        fm = parse_frontmatter(str(md_file))
        pages.append({
            'file': rel,
            'title': fm.get('title', md_file.stem.replace('-', ' ').title()),
            'order': fm.get('order', 999),
            'section': fm.get('section'),
        })
    pages.sort(key=lambda p: p['order'])

    top_level = []
    sections = {}
    section_min_order = {}
    for page in pages:
        entry = {page['title']: page['file']}
        sect = page['section']
        if sect:
            sections.setdefault(sect, []).append(entry)
            section_min_order[sect] = min(section_min_order.get(sect, 999), page['order'])
        else:
            top_level.append(entry)

    nav = list(top_level)
    for sect_name in sorted(sections, key=lambda s: section_min_order[s]):
        nav.append({sect_name: sections[sect_name]})
    return nav

cfg = yaml.safe_load(pathlib.Path('mkdocs.yml').read_text())
nav = auto_generate_nav(cfg.get('docs_dir', 'docs'))
cfg['nav'] = nav
print(f'  Auto-generated nav with {len(nav)} top-level entr(y/ies)')

pathlib.Path('mkdocs-build.yml').write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True))
PY

  # Headless variant inherits the merged base config and sets headless mode
  printf 'INHERIT: mkdocs-build.yml\n\nextra:\n  headless: true\n' > mkdocs-headless-build.yml
}

if [ "${SKIP_PIP_INSTALL:-0}" != "1" ]; then
  echo "▶ Installing Python dependencies..."
  $PYTHON -m pip install -r requirements-docs.txt -q --break-system-packages
fi

HEADLESS=false
for arg in "$@"; do
  case "$arg" in
    --headless) HEADLESS=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

echo "▶ Cleaning dist/..."
rm -rf dist/

echo "▶ Generating build configs..."
generate_build_configs

if [ "$HEADLESS" = true ]; then
  echo "▶ Building docs (headless)..."
  $PYTHON -m mkdocs build -f mkdocs-headless-build.yml

  if [ ! -f dist/docs/index.html ]; then
    echo "❌ dist/docs/index.html missing — build failed"
    exit 1
  fi

  echo "▶ Copying showcase (without nav) as entry point..."
  $PYTHON - <<'PY'
import re, pathlib
html = pathlib.Path('showcase.html').read_text()
html = re.sub(r'<!-- ── Navigation ── -->\s*<nav[^>]*>.*?</nav>', '', html, flags=re.DOTALL)
pathlib.Path('dist/index.html').write_text(html)
PY
  echo "▶ Generating dist/marketplace.json with pages manifest..."
  $PYTHON - <<'PY'
import json, pathlib, re

def parse_frontmatter(md_path):
    text = pathlib.Path(md_path).read_text()
    m = re.match(r'^---\s*\n(.*?)\n---\s*\n', text, re.DOTALL)
    meta = {}
    if m:
        for line in m.group(1).splitlines():
            kv = line.split(':', 1)
            if len(kv) == 2:
                k, v = kv[0].strip(), kv[1].strip()
                meta[k] = int(v) if v.isdigit() else v
    return meta

import yaml
cfg = yaml.safe_load(pathlib.Path('mkdocs-build.yml').read_text())
nav = cfg.get('nav', [])

pages = []
order_counter = 1
current_section = None

def add_entries(items, section=None):
    global order_counter
    for item in items:
        if isinstance(item, dict):
            for label, value in item.items():
                if isinstance(value, str):  # leaf page
                    fm = parse_frontmatter(f'docs/{value}')
                    # derive output path from source filename
                    stem = pathlib.Path(value).stem
                    out = 'docs/index.html' if stem == 'index' else f'docs/{stem}/index.html'
                    entry = {
                        'title': fm.get('title', label),
                        'path': out,
                        'order': fm.get('order', order_counter),
                    }
                    if section:
                        entry['section'] = section
                    elif fm.get('section'):
                        entry['section'] = fm['section']
                    pages.append(entry)
                    order_counter += 1
                elif isinstance(value, list):  # section group
                    add_entries(value, section=label)

add_entries(nav)

manifest = json.loads(pathlib.Path('marketplace.json').read_text())
manifest['pages'] = pages
pathlib.Path('dist/marketplace.json').write_text(json.dumps(manifest, indent=2))
print(f'  {len(pages)} page(s) written to dist/marketplace.json')
PY

  echo "▶ Packaging (headless)..."
  tar -czf dist.tar.gz dist/ marketplace.json

  echo "✅ dist.tar.gz ready ($(du -sh dist.tar.gz | cut -f1)) [headless]"
  echo "   dist/index.html      → showcase without nav (headless entry point)"
  echo "   dist/docs/index.html → documentation"
else
  echo "▶ Building docs..."
  $PYTHON -m mkdocs build -f mkdocs-build.yml

  if [ ! -f dist/docs/index.html ]; then
    echo "❌ dist/docs/index.html missing — build failed"
    exit 1
  fi

  echo "▶ Copying showcase as entry point..."
  cp showcase.html dist/index.html

  echo "▶ Generating dist/marketplace.json with pages manifest..."
  $PYTHON - <<'PY'
import json, pathlib, re, yaml

def parse_frontmatter(md_path):
    text = pathlib.Path(md_path).read_text()
    m = re.match(r'^---\s*\n(.*?)\n---\s*\n', text, re.DOTALL)
    meta = {}
    if m:
        for line in m.group(1).splitlines():
            kv = line.split(':', 1)
            if len(kv) == 2:
                k, v = kv[0].strip(), kv[1].strip()
                meta[k] = int(v) if v.isdigit() else v
    return meta

cfg = yaml.safe_load(pathlib.Path('mkdocs-build.yml').read_text())
nav = cfg.get('nav', [])

pages = []
order_counter = 1

def add_entries(items, section=None):
    global order_counter
    for item in items:
        if isinstance(item, dict):
            for label, value in item.items():
                if isinstance(value, str):
                    fm = parse_frontmatter(f'docs/{value}')
                    stem = pathlib.Path(value).stem
                    out = 'docs/index.html' if stem == 'index' else f'docs/{stem}/index.html'
                    entry = {
                        'title': fm.get('title', label),
                        'path': out,
                        'order': fm.get('order', order_counter),
                    }
                    if section:
                        entry['section'] = section
                    elif fm.get('section'):
                        entry['section'] = fm['section']
                    pages.append(entry)
                    order_counter += 1
                elif isinstance(value, list):
                    add_entries(value, section=label)

add_entries(nav)

manifest = json.loads(pathlib.Path('marketplace.json').read_text())
manifest['pages'] = pages
pathlib.Path('dist/marketplace.json').write_text(json.dumps(manifest, indent=2))
print(f'  {len(pages)} page(s) written to dist/marketplace.json')
PY

  echo "▶ Packaging..."
  tar -czf dist.tar.gz dist/ marketplace.json

  echo "✅ dist.tar.gz ready ($(du -sh dist.tar.gz | cut -f1))"
  echo "   dist/index.html      → product showcase (entry point)"
  echo "   dist/docs/index.html → documentation"
fi
