#!/usr/bin/env bun
/**
 * Turn the per-arm JSON files scripts/benchmark.ts writes into the Markdown tables of
 * docs/benchmark.md. Pure formatting over src/benchmark/metrics.ts: re-run it on the same results
 * and the same document comes out.
 *
 *   bun scripts/benchmark-report.ts <name>=<results-dir> [<name>=<dir> ...] [--out docs/benchmark.md]
 *
 * Each named set is one manifest's results (for example `full=bench/out reduced=bench/out-network`),
 * reported in its own section so arms are only ever compared on the same bundles.
 */
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { cost, type Label, metrics, pct, type Scored, type Threshold, type Verdict } from "../src/benchmark/metrics";
import { DEFAULT_POLICY } from "../src/core/severity";
import { SEVERITIES, type Severity } from "../src/core/types";

interface Row extends Scored {
  readonly corpus: string;
  readonly target: string;
  readonly bundle: string;
  readonly root?: string;
  readonly ms: number;
  readonly findings: readonly { readonly ruleId: string; readonly eff: string; readonly judge?: string }[];
  readonly analyzers: readonly { readonly name: string; readonly status: string; readonly detail?: string }[];
  readonly judgeBytes: number;
  readonly judgeTokensReported?: number;
}
interface ArmResult {
  readonly arm: string;
  readonly derived?: boolean;
  readonly judge: boolean;
  readonly analyzers: readonly string[];
  readonly totalMs: number;
  readonly usdPerMillionInputTokens: number;
  readonly rows: readonly Row[];
}

const ORDER = [
  "jev+gitleaks",
  "gitleaks",
  "static",
  "jev",
  "jev-only",
  "skillspector-only",
  "cisco-only",
  "gitleaks-only",
  "osv-scanner-only",
  "semgrep-only",
  "skillspector",
  "cisco",
  "osv-scanner",
  "semgrep",
  "skillspector+gitleaks",
  "all-offline",
  "all-analyzers",
  "jev+skillspector",
  "jev+all",
];

const args = process.argv.slice(2);
const outIdx = args.indexOf("--out");
const outFile = outIdx === -1 ? undefined : args[outIdx + 1];
/** With --write-derived, derived combinations are saved next to the measured arms as `<name>.derived.json`, for the plot. */
const writeDerived = args.includes("--write-derived");
/**
 * With --timing <dir>, per-skill times come from that run instead: every configuration one after another on the
 * same skills with nothing else running, so times are comparable. Configurations not timed there are derived the
 * way their verdicts are: a tool alone is "rules + tool" minus the rules, a combination adds its parts.
 */
const timingIdx = args.indexOf("--timing");
const timingDir = timingIdx === -1 ? undefined : args[timingIdx + 1];
const sets = args
  .filter(
    (a, i) => a.includes("=") && (outIdx === -1 || i !== outIdx + 1) && (timingIdx === -1 || i !== timingIdx + 1) && !a.startsWith("--"),
  )
  .map((a) => ({ name: a.slice(0, a.indexOf("=")), dir: a.slice(a.indexOf("=") + 1) }));
if (sets.length === 0) {
  console.error("usage: bun scripts/benchmark-report.ts <name>=<results-dir> [...] [--out file]");
  process.exit(2);
}

/**
 * One row per bundle directory. A manifest that lists every skill directory as its own target also
 * lists the plugin directories above some of them, so a nested skill is scanned twice: once alone,
 * once as part of its plugin. The row from the solo scan is kept.
 */
function dedupe(rows: readonly Row[]): Row[] {
  // Rows written before the root was recorded keep their name as the key: nothing can be nested without a root.
  const dirOf = (r: Row): string =>
    r.root === undefined ? `${r.target}\0${r.bundle}` : (r.root === "." ? r.target : `${r.target}/${r.root}`).replace(/\/+$/, "");
  const best = new Map<string, Row>();
  for (const r of rows) {
    const d = dirOf(r);
    const cur = best.get(d);
    if (!cur || (cur.root !== "." && r.root === ".")) best.set(d, r);
  }
  return [...best.values()];
}

async function loadSet(dir: string): Promise<ArmResult[]> {
  const arms: ArmResult[] = [];
  // Measured arms only; derived files are rebuilt from them every run.
  for (const f of (await readdir(dir)).filter((n) => n.endsWith(".json") && !n.endsWith(".derived.json"))) {
    const a = JSON.parse(await readFile(join(dir, f), "utf8")) as ArmResult;
    arms.push({ ...a, rows: dedupe(a.rows) });
  }
  arms.sort((a, b) => ORDER.indexOf(a.arm) - ORDER.indexOf(b.arm));
  if (arms.length === 0) {
    console.error(`no results in ${dir}`);
    process.exit(2);
  }
  return arms;
}

// The functions below read `arms`; it is rebound per set.
let arms: ArmResult[] = [];

const RANK: Readonly<Record<Verdict, number>> = { pass: 0, warn: 1, block: 2 };
const worse = (a: Verdict, b: Verdict): Verdict => (RANK[a] >= RANK[b] ? a : b);

/**
 * A combination of analyzer arms, derived without running it: analyzers only add findings and a
 * verdict is the worst finding, so the verdict of "static + A + B" on a bundle is the worst of the
 * single-tool arms' verdicts. Exact for analyzers (the judge is different: it changes confidence,
 * so judge combinations are always measured). Checked against a measured combination when one exists.
 */
function deriveUnion(name: string, parts: readonly string[]): ArmResult | undefined {
  const members = parts
    .map((p) => arms.find((a) => a.arm === p || a.arm === `${p} (derived)`))
    .filter((a): a is ArmResult => a !== undefined);
  if (members.length !== parts.length || members.some((m) => m.judge)) return undefined;
  const key = (r: Row): string => `${r.target}\0${r.bundle}`;
  const base = members[0]!;
  const rows = base.rows.map((r) => {
    let verdict = r.verdict;
    let ms = r.ms;
    const analyzers = [...r.analyzers];
    for (const m of members.slice(1)) {
      const o = m.rows.find((x) => key(x) === key(r));
      if (!o) continue;
      verdict = worse(verdict, o.verdict);
      ms += o.ms - staticMs(r);
      analyzers.push(...o.analyzers);
    }
    return { ...r, verdict, ms, analyzers };
  });
  const totalMs = members.reduce((t, m) => t + m.totalMs, 0) - (members.length - 1) * (arms.find((a) => a.arm === "static")?.totalMs ?? 0);
  return {
    arm: name,
    judge: false,
    analyzers: members.flatMap((m) => m.analyzers),
    totalMs,
    usdPerMillionInputTokens: base.usdPerMillionInputTokens,
    rows,
  };
}

const atLeast = (s: string, floor: Severity): boolean => SEVERITIES.indexOf(s as Severity) >= SEVERITIES.indexOf(floor);

/** The verdict a list of stored findings earns under the default policy, from their effective severities. */
function verdictOf(findings: Row["findings"]): Verdict {
  if (findings.some((f) => atLeast(f.eff, DEFAULT_POLICY.blockAt))) return "block";
  return findings.some((f) => atLeast(f.eff, DEFAULT_POLICY.warnAt)) ? "warn" : "pass";
}

/**
 * A tool with neither the static rules nor the judge: the verdict its own `external/<tool>` findings
 * earn in the "static + tool" arm. Exact because the engine dedupes findings per rule and line, so a
 * static finding never hides a tool's; checked by rebuilding the static arm from the same rows. The
 * time is the arm's minus the static rules'.
 */
function deriveAlone(tool: string): { derived: ArmResult; staticMismatches: number } | undefined {
  const arm = arms.find((a) => a.arm === tool && !a.judge);
  const statics = arms.find((a) => a.arm === "static");
  if (!arm || !statics) return undefined;
  const own = (f: Row["findings"][number]): boolean => f.ruleId === `external/${tool}`;
  const staticVerdict = new Map(statics.rows.map((r) => [`${r.target}\0${r.bundle}`, r.verdict]));
  let staticMismatches = 0;
  const rows = arm.rows.map((r) => {
    const rebuilt = staticVerdict.get(`${r.target}\0${r.bundle}`);
    if (rebuilt !== undefined && rebuilt !== verdictOf(r.findings.filter((f) => !own(f)))) staticMismatches++;
    const findings = r.findings.filter(own);
    return { ...r, verdict: verdictOf(findings), findings, ms: Math.max(0, r.ms - staticMs(r)) };
  });
  return {
    derived: { ...arm, arm: `${tool}-only`, totalMs: Math.max(0, arm.totalMs - statics.totalMs), rows },
    staticMismatches,
  };
}

/**
 * "static + tool" from the static arm and the tool alone: the worse of the two verdicts per bundle,
 * and their times added. Used when the static rules changed after the tools ran, since a tool's own
 * findings do not depend on the rules.
 */
function deriveWithStatic(tool: string): ArmResult | undefined {
  const alone = arms.find((a) => a.arm === `${tool}-only` || a.arm === `${tool}-only (derived)`);
  const statics = arms.find((a) => a.arm === "static");
  if (!alone || !statics) return undefined;
  const byKey = new Map(alone.rows.map((r) => [`${r.target}\0${r.bundle}`, r]));
  const rows = statics.rows.map((r) => {
    const o = byKey.get(`${r.target}\0${r.bundle}`);
    return o
      ? { ...r, verdict: worse(r.verdict, o.verdict), ms: r.ms + o.ms, findings: [...r.findings, ...o.findings], analyzers: o.analyzers }
      : r;
  });
  return { ...alone, arm: tool, judge: false, totalMs: statics.totalMs + alone.totalMs, rows };
}

/** The judge alone: the verdict its own `judge/*` findings earn in the "static + jev" arm. Exact, since the judge adds them whatever the rules found. */
function deriveJudgeAlone(): ArmResult | undefined {
  const arm = arms.find((a) => a.arm === "jev");
  const statics = arms.find((a) => a.arm === "static");
  if (!arm || !statics) return undefined;
  const rows = arm.rows.map((r) => {
    const findings = r.findings.filter((f) => f.ruleId.startsWith("judge/"));
    return { ...r, verdict: verdictOf(findings), findings, ms: Math.max(0, r.ms - staticMs(r)) };
  });
  return { ...arm, arm: "jev-only", totalMs: Math.max(0, arm.totalMs - statics.totalMs), rows };
}

/** The static share of a bundle's time, so a union does not count the rules once per tool. */
function staticMs(r: Row): number {
  const s = arms.find((a) => a.arm === "static");
  const o = s?.rows.find((x) => x.target === r.target && x.bundle === r.bundle);
  return o?.ms ?? 0;
}

let currentDir = "";

/** Add derived combinations that were not measured; verify a derivation where the measured arm exists. */
async function withDerived(): Promise<string[]> {
  const notes: string[] = [];
  const save = async (name: string, a: ArmResult): Promise<void> => {
    if (writeDerived && currentDir)
      await writeFile(join(currentDir, `${name}.derived.json`), JSON.stringify({ ...a, derived: true }, null, 1));
  };
  for (const tool of ["skillspector", "cisco", "gitleaks", "osv-scanner", "semgrep"]) {
    if (arms.some((a) => a.arm === tool)) continue;
    const derived = deriveWithStatic(tool);
    if (!derived) continue;
    arms.push({ ...derived, arm: `${tool} (derived)`, derived: true });
    notes.push(
      `- ${tool} (derived): the worse of the static arm's and ${tool}-only's verdicts per bundle; ${tool} was run before the rules changed`,
    );
    await save(tool, derived);
  }
  const judgeAlone = arms.some((a) => a.arm === "jev-only") ? undefined : deriveJudgeAlone();
  if (judgeAlone) {
    arms.push({ ...judgeAlone, arm: "jev-only (derived)", derived: true });
    notes.push("- jev-only (derived): the judge's own `judge/*` findings in the static + jev arm, without the static rules");
    await save("jev-only", judgeAlone);
  }
  const combos: readonly (readonly [string, readonly string[]])[] = [
    ["all-offline", ["skillspector", "cisco", "gitleaks"]],
    ["skillspector+gitleaks", ["skillspector", "gitleaks"]],
  ];
  for (const [name, parts] of combos) {
    const derived = deriveUnion(name, parts);
    if (!derived) continue;
    const measured = arms.find((a) => a.arm === name);
    if (measured) {
      const key = (r: Row): string => `${r.target}\0${r.bundle}`;
      const m = new Map(measured.rows.map((r) => [key(r), r.verdict]));
      const mismatches = derived.rows.filter((r) => m.has(key(r)) && m.get(key(r)) !== r.verdict).length;
      notes.push(`- ${name}: measured; the derived union disagrees on ${mismatches} of ${derived.rows.length} bundles`);
    } else {
      arms.push({ ...derived, arm: `${name} (derived)`, derived: true });
      notes.push(`- ${name} (derived): the worst verdict of ${parts.join(", ")} per bundle; not run as one arm`);
      if (writeDerived && currentDir) {
        await writeFile(join(currentDir, `${name}.derived.json`), JSON.stringify({ ...derived, derived: true }, null, 1));
      }
    }
  }
  for (const tool of ["skillspector", "cisco", "gitleaks", "osv-scanner", "semgrep"]) {
    if (arms.some((a) => a.arm === `${tool}-only`)) continue;
    const alone = deriveAlone(tool);
    if (!alone) continue;
    const name = `${tool}-only`;
    arms.push({ ...alone.derived, arm: `${name} (derived)`, derived: true });
    notes.push(
      `- ${name} (derived): ${tool}'s own findings in the "static + ${tool}" arm, without the static rules; ` +
        `rebuilding the static arm from the same rows disagrees with the measured one on ${alone.staticMismatches} bundles`,
    );
    if (writeDerived && currentDir) {
      await writeFile(join(currentDir, `${name}.derived.json`), JSON.stringify({ ...alone.derived, derived: true }, null, 1));
    }
  }
  arms.sort((a, b) => ORDER.indexOf(a.arm.replace(" (derived)", "")) - ORDER.indexOf(b.arm.replace(" (derived)", "")));
  return notes;
}

const n = (x: number): string => x.toLocaleString("en-US");
const ms = (x: number): string => (x >= 1000 ? `${(x / 1000).toFixed(1)} s` : `${Math.round(x)} ms`);

function summaryTable(threshold: Threshold): string {
  const head = `| Configuration | TP | FP | FN | TN | Precision | Recall | Specificity | F1 | Balanced acc. |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|`;
  const lines = arms.map((a) => {
    const m = metrics(a.rows, threshold);
    return `| ${a.arm} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.specificity)} | ${pct(m.f1)} | ${pct(m.balancedAccuracy)} |`;
  });
  return [head, ...lines].join("\n");
}

const timing = new Map<string, number>();
if (timingDir) {
  for (const f of (await readdir(timingDir)).filter((n) => n.endsWith(".json") && !n.endsWith(".derived.json"))) {
    const a = JSON.parse(await readFile(join(timingDir, f), "utf8")) as ArmResult;
    const rows = dedupe(a.rows);
    timing.set(a.arm, rows.reduce((t, r) => t + r.ms, 0) / Math.max(1, rows.length));
  }
}
let timingSkills = 0;
if (timing.size > 0 && timingDir) {
  const first = (await readdir(timingDir)).find((n) => n.endsWith(".json"));
  if (first) timingSkills = dedupe((JSON.parse(await readFile(join(timingDir, first), "utf8")) as ArmResult).rows).length;
}
const PARTS: Readonly<Record<string, readonly string[]>> = {
  "all-offline": ["skillspector", "cisco", "gitleaks"],
  "skillspector+gitleaks": ["skillspector", "gitleaks"],
};

function timed(arm: string): number | undefined {
  const id = arm.replace(" (derived)", "");
  const rules = timing.get("static");
  if (timing.has(id)) return timing.get(id);
  if (rules === undefined) return undefined;
  if (id.endsWith("-only") && timing.has(id.slice(0, -5))) return Math.max(0, timing.get(id.slice(0, -5))! - rules);
  const parts = PARTS[id];
  if (parts?.every((p) => timing.has(p))) return rules + parts.reduce((t, p) => t + timing.get(p)! - rules, 0);
  return undefined;
}

function costTable(): string {
  const head = `| Configuration | Bundles | Wall time | Per bundle | Judge input tokens | Judge cost | Cost per 1,000 bundles |\n|---|---:|---:|---:|---:|---:|---:|`;
  const lines = arms.map((a) => {
    const judgeBytes = a.rows.reduce((s, r) => s + r.judgeBytes, 0);
    const reported = a.rows.some((r) => r.judgeTokensReported !== undefined)
      ? a.rows.reduce((s, r) => s + (r.judgeTokensReported ?? 0), 0)
      : undefined;
    const c = cost({
      judgeBytes,
      ...(reported !== undefined ? { judgeTokensReported: reported } : {}),
      usdPerMillionInputTokens: a.usdPerMillionInputTokens,
      bundles: a.rows.length,
    });
    const tokens = a.judge ? `${n(c.tokens)}${c.tokensEstimated ? " (est.)" : ""}` : "0";
    const usd = a.judge ? `$${c.usd.toFixed(4)}` : "$0";
    const per1k = a.judge ? `$${c.usdPer1000Bundles.toFixed(3)}` : "$0";
    // Per skill: the mean of each kept row's own time, which is what scanning that skill on its own took. The
    // wall time also counts skills scanned twice (alone, and inside a repository scanned whole), so it is not divided.
    const perSkill = timed(a.arm) ?? a.rows.reduce((t, r) => t + r.ms, 0) / Math.max(1, a.rows.length);
    return `| ${a.arm} | ${n(a.rows.length)} | ${ms(a.totalMs)} | ${ms(perSkill)} | ${tokens} | ${usd} | ${per1k} |`;
  });
  return [head, ...lines].join("\n");
}

function perCorpusTable(threshold: Threshold): string {
  const corpora = [...new Set(arms.flatMap((a) => a.rows.map((r) => r.corpus)))];
  const head = `| Corpus | Label | Bundles | ${arms.map((a) => a.arm).join(" | ")} |\n|---|---|---:|${arms.map(() => "---:").join("|")}|`;
  const lines = corpora.map((c) => {
    const label = arms[0]!.rows.find((r) => r.corpus === c)?.label as Label;
    const cells = arms.map((a) => {
      const rows = a.rows.filter((r) => r.corpus === c);
      const m = metrics(rows, threshold);
      // For a malicious corpus the number that matters is recall; for a benign one, how many were wrongly flagged.
      return label === "malicious" ? `${m.tp}/${rows.length} (${pct(m.recall)})` : `${m.fp}/${rows.length} flagged`;
    });
    const count = arms[0]!.rows.filter((r) => r.corpus === c).length;
    return `| ${c} | ${label} | ${n(count)} | ${cells.join(" | ")} |`;
  });
  return [head, ...lines].join("\n");
}

/** What each addition changed relative to static alone: verdict moves on the same bundles. */
function deltaTable(): string {
  const base = arms.find((a) => a.arm === "static");
  if (!base) return "_No static arm to compare against._";
  const key = (r: Row): string => `${r.target}\0${r.bundle}`;
  const baseline = new Map(base.rows.map((r) => [key(r), r]));
  const head = `| Configuration | Malicious: pass -> flagged | Malicious: flagged -> pass | Benign: pass -> flagged | Benign: flagged -> pass |\n|---|---:|---:|---:|---:|`;
  const flagged = (v: Verdict): boolean => v !== "pass";
  const lines = arms
    .filter((a) => a.arm !== "static")
    .map((a) => {
      let mUp = 0;
      let mDown = 0;
      let bUp = 0;
      let bDown = 0;
      for (const r of a.rows) {
        const b = baseline.get(key(r));
        if (!b) continue;
        const was = flagged(b.verdict);
        const now = flagged(r.verdict);
        if (was === now) continue;
        if (r.label === "malicious") {
          if (now) mUp += 1;
          else mDown += 1;
        } else if (now) bUp += 1;
        else bDown += 1;
      }
      return `| ${a.arm} | ${mUp} | ${mDown} | ${bUp} | ${bDown} |`;
    });
  return [head, ...lines].join("\n");
}

function analyzerHealth(): string {
  const lines: string[] = [];
  for (const a of arms) {
    if (!a.judge && a.analyzers.length === 0) continue;
    const names = new Set(a.rows.flatMap((r) => r.analyzers.map((x) => x.name)));
    for (const name of names) {
      const statuses = new Map<string, number>();
      for (const r of a.rows) for (const x of r.analyzers) if (x.name === name) statuses.set(x.status, (statuses.get(x.status) ?? 0) + 1);
      const parts = [...statuses.entries()].map(([s, c]) => `${s} ${n(c)}`).join(", ");
      lines.push(`- ${a.arm} / ${name}: ${parts}`);
    }
  }
  return lines.join("\n");
}

function section(name: string): string[] {
  const pos = arms[0]!.rows.filter((r) => r.label === "malicious").length;
  const neg = arms[0]!.rows.length - pos;
  return [
    `### ${name}: ${n(pos)} malicious and ${n(neg)} benign bundles`,
    "",
    "#### Detection at the block threshold",
    "",
    "A bundle counts as detected when its verdict is `block` (what the hooks deny).",
    "",
    summaryTable("block"),
    "",
    "#### Detection at the warn threshold",
    "",
    "A bundle counts as detected when its verdict is `warn` or `block` (what `--fail-on warn` and the interactive prompts act on).",
    "",
    summaryTable("warn"),
    "",
    "#### Cost and time",
    "",
    costTable(),
    ...(timing.size > 0
      ? [
          "",
          `Per-bundle time: from a separate run of every configuration, one after another on the same ${n(timingSkills)} skill bundles (a random sample of the skills the tables are on) with nothing else running, so the times compare; a tool alone is "rules + tool" minus the rules, a combination adds its parts. Wall time is the full run's, which shared the machine.`,
        ]
      : []),
    "",
    "#### Per corpus, at the block threshold",
    "",
    perCorpusTable("block"),
    "",
    "#### What each addition changed",
    "",
    "Verdict moves on the same bundles, relative to `static`. A bundle is flagged when its verdict is warn or block.",
    "",
    deltaTable(),
    "",
    "#### Analyzer and judge status",
    "",
    analyzerHealth() || "_(no analyzer arms)_",
    "",
  ];
}

const sections: string[] = [];
for (const set of sets) {
  arms = await loadSet(set.dir);
  currentDir = set.dir;
  const notes = await withDerived();
  sections.push(...section(set.name));
  if (notes.length > 0) sections.push("#### Derived combinations", "", ...notes, "");
}
const doc = [
  "<!-- Generated by scripts/benchmark-report.ts; edit the prose in docs/benchmark.md around the markers, not inside them. -->",
  "<!-- benchmark:summary-block -->",
  ...sections,
  "<!-- /benchmark:summary-block -->",
  "",
].join("\n");

if (outFile) {
  let existing = "";
  try {
    existing = await readFile(outFile, "utf8");
  } catch {
    // new file
  }
  const start = existing.indexOf("<!-- benchmark:summary-block -->");
  const end = existing.indexOf("<!-- /benchmark:summary-block -->");
  const block = doc.slice(doc.indexOf("<!-- benchmark:summary-block -->"));
  const merged =
    start !== -1 && end !== -1
      ? `${existing.slice(0, start)}${block.trimEnd()}\n${existing.slice(end + "<!-- /benchmark:summary-block -->".length)}`
      : doc;
  await writeFile(outFile, merged);
  console.log(`wrote ${outFile}`);
} else {
  console.log(doc);
}
