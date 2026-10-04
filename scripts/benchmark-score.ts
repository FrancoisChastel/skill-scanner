#!/usr/bin/env bun
/**
 * Score one arm's results (a scripts/benchmark.ts output file) per split of src/benchmark/split.ts.
 * This is the scorer tuning runs against: it prints only the splits asked for, so the test and
 * held-out bundles can stay unread until the end.
 *
 *   bun scripts/benchmark-score.ts <arm.json> [--root /corpora] [--splits train,val]
 *                                  [--misses <split>] [--fps <split>]
 *
 * --root      the corpora root the results' paths start with (default /corpora, the Docker mount)
 * --misses    list the malicious bundles of that split the arm did not flag, by corpus
 * --fps       list the benign bundles of that split the arm flagged, with the rules that fired
 */
import { readFile } from "node:fs/promises";
import { relative } from "node:path";
import { metrics, pct, type Scored, type Threshold } from "../src/benchmark/metrics";
import { type Split, splitOf } from "../src/benchmark/split";

interface Row extends Scored {
  readonly corpus: string;
  readonly target: string;
  readonly bundle: string;
  readonly root?: string;
  readonly findings: readonly { readonly ruleId: string; readonly eff: string }[];
}

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const file = args.find((a, i) => !a.startsWith("--") && (i === 0 || !args[i - 1]!.startsWith("--")));
if (!file) {
  console.error("usage: bun scripts/benchmark-score.ts <arm.json> [--root DIR] [--splits train,val] [--misses SPLIT] [--fps SPLIT]");
  process.exit(2);
}
const root = flag("--root") ?? "/corpora";
const splits = (flag("--splits") ?? "train,val").split(",") as Split[];

/** One row per bundle directory, preferring the solo scan of a nested skill (as the report does). */
function byDirectory(rows: readonly Row[]): Map<string, Row> {
  const best = new Map<string, Row>();
  for (const r of rows) {
    const dir = (r.root === undefined || r.root === "." ? r.target : `${r.target}/${r.root}`).replace(/\/+$/, "");
    const cur = best.get(dir);
    if (!cur || (cur.root !== "." && r.root === ".")) best.set(dir, r);
  }
  return best;
}

const arm = JSON.parse(await readFile(file, "utf8")) as { arm: string; rows: Row[] };
const rows = [...byDirectory(arm.rows)].map(([dir, r]) => ({ dir, split: splitOf(r.corpus, relative(root, dir)), row: r }));

const line = (split: Split, threshold: Threshold): string => {
  const m = metrics(
    rows.filter((x) => x.split === split).map((x) => x.row),
    threshold,
  );
  return `${arm.arm} ${split.padEnd(8)} ${threshold.padEnd(5)} caught ${m.tp}/${m.tp + m.fn} (${pct(m.recall)})  benign flagged ${m.fp}/${m.fp + m.tn} (${pct(1 - m.specificity)})`;
};
for (const s of splits) for (const t of ["block", "warn"] as const) console.log(line(s, t));

const misses = flag("--misses") as Split | undefined;
if (misses) {
  console.log(`\nmissed malicious bundles in ${misses}:`);
  for (const x of rows.filter((x) => x.split === misses && x.row.label === "malicious" && x.row.verdict === "pass"))
    console.log(`  ${x.row.corpus}  ${relative(root, x.dir)}`);
}
const fps = flag("--fps") as Split | undefined;
if (fps) {
  console.log(`\nflagged benign bundles in ${fps}:`);
  for (const x of rows.filter((x) => x.split === fps && x.row.label === "benign" && x.row.verdict !== "pass")) {
    const fired = [
      ...new Set(x.row.findings.filter((f) => f.eff === "medium" || f.eff === "high" || f.eff === "critical").map((f) => f.ruleId)),
    ];
    console.log(`  ${x.row.verdict.padEnd(5)} ${relative(root, x.dir)}  ${fired.join(", ")}`);
  }
}
