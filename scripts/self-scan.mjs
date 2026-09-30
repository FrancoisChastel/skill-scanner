#!/usr/bin/env node
// Self-scan: run the built scanner over its own source and build output. A security scanner whose
// own rule descriptions trip its rules would block itself when installed as a plugin or skill, so
// this exits 1 on a block verdict and prints every finding that counts toward a verdict.
//
//   node scripts/self-scan.mjs            # scans src/ and dist/
//   SKILL_SCANNER_OUTDIR=out node scripts/self-scan.mjs
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const outDir = resolve(process.env.SKILL_SCANNER_OUTDIR ?? "dist");
const entry = resolve(outDir, "index.js");
if (!existsSync(entry)) {
  console.error(`self-scan: ${entry} not found; build first (bun run build)`);
  process.exit(2);
}

const { scanPath } = await import(pathToFileURL(entry).href);
const RANK = ["info", "low", "medium", "high", "critical"];
/** Low confidence costs one severity step, as in the verdict. */
const effective = (f) => (f.confidence === "low" ? RANK[Math.max(0, RANK.indexOf(f.severity) - 1)] : f.severity);

let worst = "pass";
for (const [label, target] of [
  ["src", resolve("src")],
  [outDir.replace(`${process.cwd()}/`, ""), outDir],
]) {
  const report = await scanPath(target, { label });
  const findings = report.bundles.flatMap((b) => b.findings);
  const counted = findings.filter((f) => RANK.indexOf(effective(f)) >= RANK.indexOf("medium"));
  console.log(`${label}: ${report.verdict} (${findings.length} findings, ${counted.length} at medium or above) in ${report.durationMs} ms`);
  for (const f of counted) {
    const where = `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}`;
    console.log(`  ${effective(f).padEnd(8)} ${f.ruleId.padEnd(40)} ${where}`);
    console.log(`           ${f.message.slice(0, 160)}`);
    if (f.location.snippet) console.log(`           | ${f.location.snippet.slice(0, 140)}`);
  }
  if (report.verdict === "block" || (report.verdict === "warn" && worst === "pass")) worst = report.verdict;
}

console.log(`self-scan verdict: ${worst}`);
process.exit(worst === "block" ? 1 : 0);
