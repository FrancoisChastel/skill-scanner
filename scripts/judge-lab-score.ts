#!/usr/bin/env bun
/**
 * Score a probe policy from the answers scripts/judge-lab.ts cached, without calling jev: the
 * judge's rules (doubt below a threshold, confirm above one, add a finding for an adding probe with
 * no static finding in its family) are replayed on each bundle's static findings, and three
 * configurations are scored per split: the static rules, static + jev, and jev alone (flagged when
 * any adding probe fires).
 *
 *   bun scripts/judge-lab-score.ts <lab-dir> <policy.json> [--budget 24000] [--splits train,val]
 *        [--questions] [--failures train]
 *
 * <policy.json>: {
 *   "questions": "<set.json>",                 the question set the lab asked (relative to the policy file)
 *   "doubtBelow": 0.05, "confirmAt": 0.5,
 *   "family": { "<category>": "<question id>" }, which question reviews findings of each category
 *   "adding": { "<question id>": 0.85 }          the questions that may add a finding, and their thresholds
 * }
 * --questions        also print each question's separation (AUC) and recall at a 1% and 2% false-flag rate, per split
 * --failures <split> list jev-alone misses and false flags in that split, with every question's P(true)
 * --arm <out.json>   also write jev alone as a benchmark arm file (verdicts only), for the report and the figure;
 *                    --root <lab root> and --as-root <results root> map the lab's paths to the results' (default /corpora)
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import type { Split } from "../src/benchmark/split";
import { DEFAULT_POLICY, effectiveSeverity } from "../src/core/severity";
import { type Confidence, SEVERITIES, type Severity, type Verdict } from "../src/core/types";

interface LabFinding {
  readonly ruleId: string;
  readonly category: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly hard: boolean;
}
interface LabRow {
  readonly dir: string;
  readonly corpus: string;
  readonly label: "malicious" | "benign";
  readonly split: Split;
  readonly stateHash?: string;
  readonly skipped?: string;
  readonly findings: readonly LabFinding[];
}
interface Policy {
  readonly questions: string;
  readonly doubtBelow: number;
  readonly confirmAt: number;
  readonly family: Readonly<Record<string, string>>;
  readonly adding: Readonly<Record<string, number>>;
}
type QuestionSet = Record<string, { instructions: string; true: string; false: string }>;

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const [labDir, policyPath] = args.filter((a, i) => !a.startsWith("--") && (i === 0 || !args[i - 1]!.startsWith("--")));
if (!labDir || !policyPath) {
  console.error(
    "usage: bun scripts/judge-lab-score.ts <lab-dir> <policy.json> [--budget N] [--splits train,val] [--questions] [--failures SPLIT]",
  );
  process.exit(2);
}
const budget = flag("--budget") ?? "24000";
const splits = (flag("--splits") ?? "train,val").split(",") as Split[];

const sha = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 24);
const questionHash = (q: QuestionSet[string]): string => sha(JSON.stringify([q.instructions, q.true, q.false]));

const policy = JSON.parse(await readFile(policyPath, "utf8")) as Policy;
const questions = JSON.parse(await readFile(resolve(dirname(policyPath), policy.questions), "utf8")) as QuestionSet;
const rows = (await readFile(join(labDir, `bundles-${budget}.jsonl`), "utf8"))
  .split("\n")
  .filter(Boolean)
  .map((l) => JSON.parse(l) as LabRow);
const answers = new Map<string, number>();
for (const line of (await readFile(join(labDir, "answers.jsonl"), "utf8")).split("\n")) {
  if (!line) continue;
  const a = JSON.parse(line) as { s: string; q: string; p: number };
  answers.set(`${a.s}\0${a.q}`, a.p);
}
const qHash = Object.fromEntries(Object.entries(questions).map(([id, q]) => [id, questionHash(q)]));

/** One step up, as src/judge/apply.ts confirms a finding. */
const raiseConfidence = (c: Confidence): Confidence => (c === "low" ? "medium" : "high");

/** P(true) of a question for a bundle, or undefined when the bundle was not judged or the question not asked. */
const p = (r: LabRow, id: string): number | undefined => (r.stateHash ? answers.get(`${r.stateHash}\0${qHash[id]}`) : undefined);

const verdictOf = (fs: readonly { severity: Severity; confidence: Confidence }[]): Verdict => {
  const at = (f: { severity: Severity; confidence: Confidence }, floor: Severity): boolean =>
    SEVERITIES.indexOf(effectiveSeverity(f)) >= SEVERITIES.indexOf(floor);
  if (fs.some((f) => at(f, DEFAULT_POLICY.blockAt))) return "block";
  return fs.some((f) => at(f, DEFAULT_POLICY.warnAt)) ? "warn" : "pass";
};

/** The judge's rules (src/judge/apply.ts), replayed with this policy's questions and thresholds. */
function withJudge(r: LabRow): Verdict {
  if (!r.stateHash) return verdictOf(r.findings);
  const reviewed = r.findings.map((f) => {
    const id = policy.family[f.category];
    const pt = id === undefined ? undefined : p(r, id);
    if (pt === undefined) return f;
    if (pt < policy.doubtBelow && f.severity !== "critical" && !f.hard) return { ...f, confidence: "low" as Confidence };
    if (pt >= policy.confirmAt) return { ...f, confidence: raiseConfidence(f.confidence) };
    return f;
  });
  const covered = new Set(r.findings.map((f) => policy.family[f.category]));
  const added = Object.entries(policy.adding)
    .filter(([id, t]) => !covered.has(id) && (p(r, id) ?? 0) >= t)
    .map(() => ({ severity: "medium" as Severity, confidence: "medium" as Confidence }));
  return verdictOf([...reviewed, ...added]);
}

/** jev alone: flagged (warn) when any adding question reaches its threshold. */
const jevAlone = (r: LabRow): Verdict => (Object.entries(policy.adding).some(([id, t]) => (p(r, id) ?? 0) >= t) ? "warn" : "pass");

function line(name: string, split: Split, verdict: (r: LabRow) => Verdict): string {
  const rs = rows.filter((r) => r.split === split);
  const count = (label: string, hit: (v: Verdict) => boolean): [number, number] => {
    const of = rs.filter((r) => r.label === label);
    return [of.filter((r) => hit(verdict(r))).length, of.length];
  };
  const [bm, nm] = count("malicious", (v) => v === "block");
  const [wm] = count("malicious", (v) => v !== "pass");
  const [bb, nb] = count("benign", (v) => v === "block");
  const [wb] = count("benign", (v) => v !== "pass");
  const pc = (a: number, b: number): string => `${((100 * a) / Math.max(1, b)).toFixed(1)}%`;
  return `${name.padEnd(12)} ${split.padEnd(8)} caught: block ${bm}/${nm} (${pc(bm, nm)}), flagged ${wm} (${pc(wm, nm)})   benign: block ${bb}/${nb}, flagged ${wb} (${pc(wb, nb)})`;
}

for (const s of splits) {
  console.log(line("static", s, (r) => verdictOf(r.findings)));
  console.log(line("static+jev", s, withJudge));
  console.log(line("jev alone", s, jevAlone));
}

/** Area under the ROC curve of one question, judged bundles only: the chance a malicious bundle outscores a benign one. */
function auc(rs: readonly LabRow[], id: string): number {
  const pos = rs
    .filter((r) => r.label === "malicious")
    .map((r) => p(r, id))
    .filter((x): x is number => x !== undefined);
  const neg = rs
    .filter((r) => r.label === "benign")
    .map((r) => p(r, id))
    .filter((x): x is number => x !== undefined);
  let wins = 0;
  for (const a of pos) for (const b of neg) wins += a > b ? 1 : a === b ? 0.5 : 0;
  return wins / Math.max(1, pos.length * neg.length);
}

/** The lowest threshold whose false-flag rate on `rs` stays within `rate`, and the recall it gives. */
function atRate(rs: readonly LabRow[], id: string, rate: number): { t: number; recall: number } {
  const neg = rs
    .filter((r) => r.label === "benign" && r.stateHash)
    .map((r) => p(r, id) ?? 0)
    .sort((a, b) => b - a);
  const allowed = Math.floor(rate * rs.filter((r) => r.label === "benign").length);
  const t = allowed >= neg.length ? 0 : (neg[allowed] ?? 0) + 1e-9;
  const pos = rs.filter((r) => r.label === "malicious");
  return { t, recall: pos.filter((r) => (p(r, id) ?? 0) >= t).length / Math.max(1, pos.length) };
}

if (args.includes("--questions")) {
  console.log("\nquestion                      " + splits.map((s) => `${s}: AUC  rec@1%  rec@2%`.padEnd(28)).join(""));
  const train = rows.filter((r) => r.split === "train");
  for (const id of Object.keys(questions)) {
    // Thresholds are chosen on train and carried to the other splits.
    const t1 = atRate(train, id, 0.01).t;
    const t2 = atRate(train, id, 0.02).t;
    const cells = splits.map((s) => {
      const rs = rows.filter((r) => r.split === s);
      const pos = rs.filter((r) => r.label === "malicious");
      const rec = (t: number): string =>
        `${((100 * pos.filter((r) => (p(r, id) ?? 0) >= t).length) / Math.max(1, pos.length)).toFixed(0)}%`;
      return `${auc(rs, id).toFixed(3)}  ${rec(t1).padStart(4)}   ${rec(t2).padStart(4)}`.padEnd(28);
    });
    console.log(`${id.padEnd(30)}${cells.join("")}  t1=${t1.toFixed(3)} t2=${t2.toFixed(3)}`);
  }
}

const armFile = flag("--arm");
if (armFile) {
  const labRoot = flag("--root") ?? "/corpora";
  const asRoot = flag("--as-root") ?? "/corpora";
  const arm = {
    arm: "jev-only",
    judge: true,
    analyzers: [],
    totalMs: 0,
    usdPerMillionInputTokens: 0.042,
    derived: true,
    rows: rows.map((r) => ({
      corpus: r.corpus,
      label: r.label,
      target: join(asRoot, relative(labRoot, r.dir)),
      bundle: basename(r.dir),
      root: ".",
      kind: "skill",
      verdict: jevAlone(r),
      ms: 0,
      findings: [],
      analyzers: [],
      judgeBytes: 0,
    })),
  };
  await writeFile(armFile, JSON.stringify(arm, null, 1));
  console.log(`wrote ${armFile}: ${arm.rows.length} bundles`);
}

const failures = flag("--failures") as Split | undefined;
if (failures) {
  const rs = rows.filter((r) => r.split === failures && r.stateHash);
  const ids = Object.keys(questions);
  const ps = (r: LabRow): string => ids.map((id) => `${id}=${(p(r, id) ?? Number.NaN).toFixed(2)}`).join(" ");
  console.log(`\njev-alone misses in ${failures} (judged malicious bundles not flagged):`);
  for (const r of rs.filter((r) => r.label === "malicious" && jevAlone(r) === "pass")) console.log(`  ${r.dir}\n    ${ps(r)}`);
  console.log(`\njev-alone false flags in ${failures}:`);
  for (const r of rs.filter((r) => r.label === "benign" && jevAlone(r) !== "pass")) console.log(`  ${r.dir}\n    ${ps(r)}`);
}
