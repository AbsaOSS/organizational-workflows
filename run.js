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

const { execFileSync, execSync, spawn } = require("child_process");
const { resolve } = require("path");
const fs = require("fs");

const ROOT = resolve(__dirname);
const env = { ...process.env, PYTHONIOENCODING: "utf-8" };

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
const args = process.argv.slice(2);

function build(extraArgs) {
  try {
    execFileSync(py, ["scripts/pack.py", ...extraArgs], {
      cwd: ROOT,
      stdio: "inherit",
      env,
    });
  } catch (e) {
    process.exit(e.status || 1);
  }
}

if (args.includes("--preview")) {
  // Full build once, then serve dist/ AND watch source files so edits made by
  // hand or through the CMS at /admin/ (incl. uploaded media) are picked up and
  // dist/ is rebuilt automatically — no manual rebuild needed.
  build([]);

  console.log("\nServing dist/ at http://localhost:8000 …");
  const server = spawn(py, ["-m", "http.server", "8000", "-d", "dist"], {
    cwd: ROOT,
    stdio: "inherit",
    env,
  });

  // Source paths that feed the build. dist/ is deliberately NOT watched (would
  // loop). mkdocs-build*.yml are transient and live at the repo root, unwatched.
  const watchTargets = [
    "docs",
    "data",
    "theme",
    "admin",
    "mkdocs.yml",
    "mkdocs-headless.yml",
    "showcase.html",
    "showcase.css",
    "main.py",
    "marketplace.json",
  ];

  let rebuilding = false;
  let pending = false;
  let timer = null;

  function rebuild() {
    if (rebuilding) {
      pending = true;
      return;
    }
    rebuilding = true;
    console.log("\n↻ Change detected — rebuilding dist/ …");
    try {
      execFileSync(py, ["scripts/pack.py", "--no-package"], {
        cwd: ROOT,
        stdio: "inherit",
        env: { ...env, SKIP_PIP_INSTALL: "1" },
      });
      console.log("✅ Rebuild complete — refresh your browser.\n");
    } catch (e) {
      console.error("⚠ Rebuild failed:", e.status || e.message);
    }
    rebuilding = false;
    if (pending) {
      pending = false;
      schedule();
    }
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(rebuild, 300); // debounce bursty CMS/file writes
  }

  const watchers = [];
  for (const target of watchTargets) {
    const p = resolve(ROOT, target);
    if (!fs.existsSync(p)) continue;
    try {
      watchers.push(fs.watch(p, { recursive: true }, schedule));
    } catch {
      // recursive watch unsupported (older Node on Linux) — watch shallowly
      watchers.push(fs.watch(p, {}, schedule));
    }
  }
  console.log(`Watching ${watchers.length} source path(s) — Ctrl+C to stop.`);

  function shutdown() {
    for (const w of watchers) {
      try {
        w.close();
      } catch {}
    }
    if (server && !server.killed) server.kill();
    process.exit(0);
  }
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  server.on("exit", (code) => process.exit(code || 0));
} else if (args.includes("--dev")) {
  try {
    execFileSync(py, ["scripts/pack.py", "--serve"], {
      cwd: ROOT,
      stdio: "inherit",
      env,
    });
  } catch (e) {
    process.exit(e.status || 1);
  }
} else {
  build(args);
}
