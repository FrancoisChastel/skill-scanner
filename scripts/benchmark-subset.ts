#!/usr/bin/env bun
/**
 * Copy every arm file of a results directory, keeping only the bundles of some splits
 * (src/benchmark/split.ts), so the report and the figure can be built on bundles tuning never read.
 *
 *   bun scripts/benchmark-subset.ts <in-dir> <out-dir> --splits test,held-out [--root /corpora]
 *   bun scripts/benchmark-subset.ts <in-dir> --map <splits.json> [--root /corpora]
 *
 * --map writes `{ "<bundle directory>": "<split>" }` for every bundle in the directory's results instead,
 * for the figure's per-split view; the split logic stays in one place.
 */
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { type Split, splitOf } from "../src/benchmark/split";

interface Row {
  readonly corpus: string;
  readonly target: string;
  readonly root?: string;
}

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const [inDir, outDir] = args.filter((a, i) => !a.startsWith("--") && (i === 0 || !args[i - 1]!.startsWith("--")));
const wanted = new Set((flag("--splits") ?? "").split(",").filter(Boolean) as Split[]);
const mapFile = flag("--map");
if (!inDir || (!mapFile && (!outDir || wanted.size === 0))) {
  console.error("usage: bun scripts/benchmark-subset.ts <in-dir> <out-dir> --splits test,held-out [--root /corpora]");
  process.exit(2);
}
const root = flag("--root") ?? "/corpora";

const dirOf = (r: Row): string => (r.root === undefined || r.root === "." ? r.target : `${r.target}/${r.root}`).replace(/\/+$/, "");

if (mapFile) {
  const map: Record<string, Split> = {};
  for (const name of (await readdir(inDir)).filter((n) => n.endsWith(".json"))) {
    const arm = JSON.parse(await readFile(join(inDir, name), "utf8")) as { rows?: Row[] };
    for (const r of arm.rows ?? []) map[dirOf(r)] = splitOf(r.corpus, relative(root, dirOf(r)));
  }
  await writeFile(mapFile, JSON.stringify(map));
  console.log(`${Object.keys(map).length} bundle directories mapped`);
  process.exit(0);
}

await mkdir(outDir!, { recursive: true });
for (const name of (await readdir(inDir)).filter((n) => n.endsWith(".json"))) {
  const arm = JSON.parse(await readFile(join(inDir, name), "utf8")) as { rows?: Row[]; totalMs?: number };
  if (!Array.isArray(arm.rows)) continue;
  const rows = arm.rows.filter((r) => wanted.has(splitOf(r.corpus, relative(root, dirOf(r)))));
  // Time scales with the share of bundles kept, so per-bundle time stays the arm's own.
  const totalMs = arm.totalMs === undefined ? undefined : Math.round((arm.totalMs * rows.length) / Math.max(1, arm.rows.length));
  await writeFile(join(outDir!, name), JSON.stringify({ ...arm, rows, ...(totalMs === undefined ? {} : { totalMs }) }, null, 1));
  console.log(`${name}: ${rows.length} of ${arm.rows.length} rows`);
}
