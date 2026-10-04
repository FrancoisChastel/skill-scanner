#!/usr/bin/env bun
/**
 * The before-and-after table of docs/benchmark.md's "Tuning" section: the static rules, jev alone
 * and static + jev, before and after tuning, on each split of src/benchmark/split.ts.
 *
 *   bun scripts/benchmark-tuning.ts <before-dir> <after-dir> [--root /corpora] [--out docs/benchmark.md]
 *
 * With --out, the table replaces what sits between `<!-- benchmark:tuning -->` and `<!-- /benchmark:tuning -->`.
 */
import { readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { metrics, pct, type Scored } from "../src/benchmark/metrics";
import { type Split, splitOf } from "../src/benchmark/split";

interface Row extends Scored {
  readonly corpus: string;
  readonly target: string;
  readonly root?: string;
}

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const [beforeDir, afterDir] = args.filter((a, i) => !a.startsWith("--") && (i === 0 || !args[i - 1]!.startsWith("--")));
if (!beforeDir || !afterDir) {
  console.error("usage: bun scripts/benchmark-tuning.ts <before-dir> <after-dir> [--root /corpora] [--out FILE]");
  process.exit(2);
}
const root = flag("--root") ?? "/corpora";
const outFile = flag("--out");

const CONFIGS = [
  ["static", "static rules"],
  ["jev-only", "jev alone"],
  ["jev", "static rules + jev"],
] as const;
const SPLITS: readonly (readonly [Split, string])[] = [
  ["train", "training"],
  ["val", "validation"],
  ["test", "test"],
  ["held-out", "held-out corpora"],
];

const dirOf = (r: Row): string => (r.root === undefined || r.root === "." ? r.target : `${r.target}/${r.root}`).replace(/\/+$/, "");

/** One row per bundle directory, preferring the solo scan of a nested skill, as the report does. */
async function load(dir: string, arm: string): Promise<{ split: Split; row: Row }[] | undefined> {
  let raw: string;
  try {
    raw = await readFile(join(dir, `${arm}.json`), "utf8");
  } catch {
    try {
      raw = await readFile(join(dir, `${arm}.derived.json`), "utf8");
    } catch {
      return undefined;
    }
  }
  const best = new Map<string, Row>();
  for (const r of (JSON.parse(raw) as { rows: Row[] }).rows) {
    const cur = best.get(dirOf(r));
    if (!cur || (cur.root !== "." && r.root === ".")) best.set(dirOf(r), r);
  }
  return [...best].map(([d, row]) => ({ split: splitOf(row.corpus, relative(root, d)), row }));
}

const lines = [
  "| Configuration | Split | Malicious flagged | Malicious blocked | Benign flagged | Benign blocked |",
  "|---|---|---:|---:|---:|---:|",
];
for (const [arm, label] of CONFIGS) {
  const before = await load(beforeDir, arm);
  const after = await load(afterDir, arm);
  if (!before || !after) continue;
  for (const [split, splitLabel] of SPLITS) {
    const b = before.filter((x) => x.split === split).map((x) => x.row);
    const a = after.filter((x) => x.split === split).map((x) => x.row);
    const [bw, aw, bb, ab] = [metrics(b, "warn"), metrics(a, "warn"), metrics(b, "block"), metrics(a, "block")];
    const arrow = (x: number, y: number): string => `${pct(x)} -> **${pct(y)}**`;
    lines.push(
      `| ${label} | ${splitLabel} (${aw.tp + aw.fn} / ${aw.fp + aw.tn}) | ${arrow(bw.recall, aw.recall)} | ${arrow(bb.recall, ab.recall)} | ` +
        `${arrow(1 - bw.specificity, 1 - aw.specificity)} | ${arrow(1 - bb.specificity, 1 - ab.specificity)} |`,
    );
  }
}
const table = lines.join("\n");
if (outFile) {
  const doc = await readFile(outFile, "utf8");
  const [open, close] = ["<!-- benchmark:tuning -->", "<!-- /benchmark:tuning -->"];
  const i = doc.indexOf(open);
  const j = doc.indexOf(close);
  if (i === -1 || j === -1) throw new Error(`${outFile} has no ${open} ... ${close} block`);
  await writeFile(outFile, `${doc.slice(0, i + open.length)}\n${table}\n${doc.slice(j)}`);
  console.log(`wrote ${outFile}`);
} else {
  console.log(table);
}
