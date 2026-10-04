#!/usr/bin/env bun
/**
 * Benchmark the scanner's configurations against labeled corpora: static rules alone, with the jev
 * judge, with each external analyzer, and with everything. Writes one JSON file per arm with every
 * bundle's verdict, so docs/benchmark.md can be regenerated from the raw results.
 *
 *   bun scripts/benchmark.ts <manifest.json> <out-dir> [--arms static,jev,...] [--judge-url URL]
 *
 * The manifest lists corpora: `{ "corpora": [{ "name", "label": "malicious"|"benign", "paths": [dir...], "mode": "repo"|"children" }] }`.
 * `children` scans each child directory as one target; `repo` scans the directory as one target and
 * counts every skill bundle it finds. Only bundles of kind `skill` or `plugin` are scored: a package's
 * root bundle (README, CI) is not a thing anyone installs.
 *
 * Judge cost: the request body sent to jev is counted in characters and tokens (chars / 4, the usual
 * approximation for English and code); the price is $0.042 per million input tokens, output free
 * (TypeSafe, September 2026). The real provider's usage field is recorded when it answers with one.
 */
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { AnalyzerName, BundleJudge, ExternalAnalyzer, Verdict } from "../src/index";

// Under Bun this runs from the sources; under Node in Docker (no Bun there) from the installed package,
// so the benchmark measures the artifact users get. SKILL_SCANNER_BENCH_PACKAGE names the module.
const lib = (await import(process.env.SKILL_SCANNER_BENCH_PACKAGE ?? "../src/index")) as typeof import("../src/index");
const { createAnalyzers, createJudge, DEFAULT_CONFIG, effectiveSeverity, loadConfig, scanPath } = lib;

interface Corpus {
  readonly name: string;
  readonly label: "malicious" | "benign";
  readonly paths: readonly string[];
  readonly mode: "repo" | "children";
}
interface Manifest {
  readonly corpora: readonly Corpus[];
}

interface Arm {
  readonly name: string;
  readonly judge: boolean;
  readonly analyzers: readonly AnalyzerName[];
}

const ARMS: readonly Arm[] = [
  { name: "static", judge: false, analyzers: [] },
  { name: "jev", judge: true, analyzers: [] },
  { name: "skillspector", judge: false, analyzers: ["skillspector"] },
  { name: "cisco", judge: false, analyzers: ["cisco"] },
  { name: "gitleaks", judge: false, analyzers: ["gitleaks"] },
  { name: "osv-scanner", judge: false, analyzers: ["osv-scanner"] },
  { name: "semgrep", judge: false, analyzers: ["semgrep"] },
  // The three offline analyzers together: what `--with auto` runs when all are installed.
  { name: "all-offline", judge: false, analyzers: ["skillspector", "cisco", "gitleaks"] },
  { name: "all-analyzers", judge: false, analyzers: ["skillspector", "cisco", "gitleaks", "osv-scanner", "semgrep"] },
  // Judge combinations are measured, never derived: the judge reweights every finding, the tools' included.
  { name: "jev+gitleaks", judge: true, analyzers: ["gitleaks"] },
  { name: "jev+skillspector", judge: true, analyzers: ["skillspector"] },
  { name: "jev+all", judge: true, analyzers: ["skillspector", "cisco", "gitleaks", "osv-scanner", "semgrep"] },
];

interface Row {
  readonly corpus: string;
  readonly label: Corpus["label"];
  readonly target: string;
  readonly bundle: string;
  /** The bundle's directory relative to the target (`.` for the target itself). */
  readonly root: string;
  readonly kind: string;
  readonly verdict: Verdict;
  readonly ms: number;
  readonly findings: readonly { readonly ruleId: string; readonly eff: string; readonly judge?: string }[];
  readonly analyzers: readonly { readonly name: string; readonly status: string; readonly detail?: string }[];
  readonly judgeBytes: number;
  readonly judgeTokensReported?: number;
}

const USD_PER_MILLION_INPUT_TOKENS = 0.042;

const args = process.argv.slice(2);
const [manifestPath, outDir] = args;
if (!manifestPath || !outDir) {
  console.error("usage: bun scripts/benchmark.ts <manifest.json> <out-dir> [--arms a,b] [--judge-url URL]");
  process.exit(2);
}
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const wanted = flag("--arms")?.split(",");
const judgeUrl = flag("--judge-url");
const arms = ARMS.filter((a) => !wanted || wanted.includes(a.name));

const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Manifest;
await mkdir(outDir, { recursive: true });

async function targetsOf(c: Corpus): Promise<string[]> {
  const out: string[] = [];
  for (const p of c.paths) {
    const abs = resolve(p);
    if (c.mode === "repo") {
      out.push(abs);
      continue;
    }
    let names: string[] = [];
    try {
      names = (await readdir(abs)).sort();
    } catch {
      continue;
    }
    for (const n of names) {
      const child = join(abs, n);
      try {
        if ((await stat(child)).isDirectory()) out.push(child);
      } catch {
        // skipped
      }
    }
  }
  return out;
}

async function runArm(arm: Arm): Promise<void> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  const config = await loadConfig(undefined, env).catch(() => DEFAULT_CONFIG);
  let judge: BundleJudge | undefined;
  const meter = { bytes: 0, tokens: undefined as number | undefined };
  if (arm.judge) {
    const cfg = { ...config.judge, enabled: true, ...(judgeUrl ? { baseUrl: judgeUrl, provider: "typesafe" as const } : {}) };
    const made = createJudge(cfg, env, {
      fetch: async (url, init) => {
        const body = typeof init.body === "string" ? init.body : "";
        meter.bytes += Buffer.byteLength(body);
        const res = await fetch(url, init);
        const clone = res.clone();
        try {
          const json = (await clone.json()) as { usage?: { input_tokens?: number } };
          if (typeof json.usage?.input_tokens === "number") meter.tokens = (meter.tokens ?? 0) + json.usage.input_tokens;
        } catch {
          // not JSON, or not ours to read
        }
        return res;
      },
    });
    if (!made.judge) {
      console.error(`arm ${arm.name}: no judge (${made.reason}); skipping arm`);
      return;
    }
    judge = made.judge;
  }
  let analyzers: ExternalAnalyzer[] = [];
  if (arm.analyzers.length > 0) {
    const cfg = { ...config, analyzers: Object.fromEntries(arm.analyzers.map((a) => [a, true])) as typeof config.analyzers };
    analyzers = await createAnalyzers(arm.analyzers, cfg, env);
    for (const a of analyzers) {
      const why = await a.unavailable();
      if (why) {
        console.error(`arm ${arm.name}: analyzer ${a.name} unavailable (${why}); skipping arm`);
        return;
      }
    }
  }
  const rows: Row[] = [];
  const t0 = performance.now();
  for (const corpus of manifest.corpora) {
    for (const target of await targetsOf(corpus)) {
      const bytesBefore = meter.bytes;
      const tokensBefore = meter.tokens;
      const t = performance.now();
      let report: Awaited<ReturnType<typeof scanPath>>;
      try {
        report = await scanPath(target, {
          policy: { blockAt: config.blockAt, warnAt: config.warnAt },
          suppressions: config.ignore,
          ...(judge ? { judge } : {}),
          ...(analyzers.length ? { analyzers } : {}),
        });
      } catch (e) {
        console.error(`ERR ${target}: ${e instanceof Error ? e.message : String(e)}`);
        continue;
      }
      const ms = Math.round(performance.now() - t);
      const scored = report.bundles.filter((b) => b.bundle.kind === "skill" || b.bundle.kind === "plugin");
      const judgeBytes = meter.bytes - bytesBefore;
      const judgeTokens = meter.tokens !== undefined && tokensBefore !== undefined ? meter.tokens - tokensBefore : meter.tokens;
      for (const b of scored) {
        rows.push({
          corpus: corpus.name,
          label: corpus.label,
          target,
          bundle: b.bundle.name,
          root: b.bundle.root,
          kind: b.bundle.kind,
          verdict: b.verdict,
          ms: Math.round(ms / Math.max(1, scored.length)),
          findings: b.findings.map((f) => ({
            ruleId: f.ruleId,
            eff: effectiveSeverity(f),
            ...(f.judge ? { judge: `${f.judge.effect}@${(f.judge.pTrue ?? 0).toFixed(2)}` } : {}),
          })),
          analyzers: report.analyzers.map((a) => ({ name: a.name, status: a.status, ...(a.detail ? { detail: a.detail } : {}) })),
          judgeBytes: Math.round(judgeBytes / Math.max(1, scored.length)),
          ...(judgeTokens !== undefined ? { judgeTokensReported: Math.round(judgeTokens / Math.max(1, scored.length)) } : {}),
        });
      }
    }
  }
  const totalMs = Math.round(performance.now() - t0);
  const out = {
    arm: arm.name,
    judge: arm.judge,
    analyzers: arm.analyzers,
    totalMs,
    usdPerMillionInputTokens: USD_PER_MILLION_INPUT_TOKENS,
    rows,
  };
  await writeFile(join(outDir, `${arm.name}.json`), JSON.stringify(out, null, 1));
  console.log(
    `# ${arm.name}: ${rows.length} bundles in ${totalMs} ms, judge bytes ${meter.bytes}${meter.tokens !== undefined ? `, reported input tokens ${meter.tokens}` : ""}`,
  );
}

for (const arm of arms) await runArm(arm);
