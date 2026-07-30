#!/usr/bin/env node
/*
 * Copyright 2026 ABSA Group Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const { execFileSync } = require("child_process");
const { resolve } = require("path");

const ROOT = resolve(__dirname);

function findPython() {
  for (const bin of ["python3", "python"]) {
    try {
      execFileSync(bin, ["--version"], { stdio: "ignore" });
      return bin;
    } catch {}
  }
  console.error("No python3 or python found in PATH");
  process.exit(1);
}

const py = findPython();
// --dev maps to pack.py --serve (mkdocs live-reload dev server)
const args = process.argv.slice(2).map((a) => (a === "--dev" ? "--serve" : a));

try {
  execFileSync(py, ["scripts/pack.py", ...args], {
    cwd: ROOT,
    stdio: "inherit",
    env: { ...process.env, PYTHONIOENCODING: "utf-8" },
  });
} catch (e) {
  process.exit(e.status || 1);
}
