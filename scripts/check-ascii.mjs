#!/usr/bin/env node
// Source files must be plain ASCII. A scanner for invisible Unicode must not carry any itself:
// write non-ASCII characters as \u escapes. Test fixtures build such characters at run time.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const roots = ["src", "scripts", "test"];
const skip = new Set(["node_modules", "fixtures"]);
let bad = 0;

function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (skip.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(?:[cm]?[jt]s)$/.test(name)) check(p);
  }
}

function check(file) {
  const lines = readFileSync(file, "utf8").split("\n");
  lines.forEach((line, i) => {
    const m = /[^\x00-\x7f]/.exec(line);
    if (m) {
      bad += 1;
      const cp = m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
      console.error(`${file}:${i + 1}:${m.index + 1}: non-ASCII U+${cp}; write it as an escape`);
    }
  });
}

for (const r of roots) {
  try {
    walk(r);
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
}
if (bad > 0) {
  console.error(`${bad} non-ASCII character(s) found`);
  process.exit(1);
}
