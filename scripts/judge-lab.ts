#!/usr/bin/env bun
/**
 * The jev probe lab: ask jev any set of candidate questions about the benchmark's skills and cache
 * every answer by (state, question), so a probe set can be scored, reworded and rescored while only
 * new questions reach the API. It is how src/judge/probes.ts is tuned, the way skill-factory tunes a
 * skill: read the training failures, reword or add a question, keep it only if it beats validation.
 *
 *   bun scripts/judge-lab.ts <manifest.json> <lab-dir> --questions <set.json>
 *       [--root DIR] [--splits train,val] [--budget 24000] [--concurrency 8]
 *
 * <set.json>               { "<id>": { "instructions": "...", "true": "...", "false": "..." } }, System One choice questions
 * <lab-dir>/bundles-<budget>.jsonl  one line per bundle: directory, corpus, label, split, state hash and size,
 *                          and the static findings (for replaying the judge's doubt and confirm rules)
 * <lab-dir>/answers.jsonl  one line per answer: state hash, question hash, model, P(true)
 *
 * The state is built by the judge's own buildState, so the lab asks about exactly the text the scanner
 * sends. The key is read from the environment as the scanner reads it and is never written anywhere.
 */
import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { type Split, splitOf } from "../src/benchmark/split";
import type { Finding } from "../src/core/types";
import { scanPath } from "../src/index";
import { postJson } from "../src/judge/http";
import type { ChoiceQuestion } from "../src/judge/protocol";
import { readTrueProbabilities, requestBody } from "../src/judge/protocol";
import { resolveSetup } from "../src/judge/providers";
import { buildState } from "../src/judge/state";
import { findRule } from "../src/rules";

interface Corpus {
  readonly name: string;
  readonly label: "malicious" | "benign";
  readonly paths: readonly string[];
}

export interface LabBundle {
  readonly dir: string;
  readonly corpus: string;
  readonly label: "malicious" | "benign";
  readonly split: Split;
  readonly kind: string;
  readonly state?: string;
  readonly chars?: number;
  readonly skipped?: string;
  readonly findings: readonly {
    readonly ruleId: string;
    readonly category: string;
    readonly severity: string;
    readonly confidence: string;
    readonly hard: boolean;
  }[];
}

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const [manifestPath, labDir] = args.filter((a, i) => !a.startsWith("--") && (i === 0 || !args[i - 1]!.startsWith("--")));
const questionsPath = flag("--questions");
if (!manifestPath || !labDir || !questionsPath) {
  console.error(
    "usage: bun scripts/judge-lab.ts <manifest.json> <lab-dir> --questions <set.json> [--root DIR] [--splits train,val] [--budget N] [--concurrency N]",
  );
  process.exit(2);
}
const root = flag("--root") ?? "/corpora";
const splits = new Set((flag("--splits") ?? "train,val").split(",") as Split[]);
const budget = Number(flag("--budget") ?? 24_000);
const concurrency = Number(flag("--concurrency") ?? 8);
/** Questions per request; the state is billed once per request, so more questions per call is cheaper. */
const PER_REQUEST = 40;

const sha = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 24);
export const questionHash = (q: ChoiceQuestion): string => sha(JSON.stringify([q.instructions, q.criteria.true, q.criteria.false]));

async function collect(): Promise<LabBundle[]> {
  const manifest = JSON.parse(await readFile(manifestPath!, "utf8")) as { corpora: Corpus[] };
  const best = new Map<string, LabBundle & { solo: boolean }>();
  for (const corpus of manifest.corpora) {
    for (const target of corpus.paths.map((p) => resolve(p))) {
      const report = await scanPath(target, {}).catch(() => undefined);
      if (!report) continue;
      for (const b of report.bundles) {
        if (b.bundle.kind !== "skill" && b.bundle.kind !== "plugin") continue;
        const dir = (b.bundle.root === "." ? target : join(target, b.bundle.root)).replace(/\/+$/, "");
        const split = splitOf(corpus.name, relative(root, dir));
        if (!splits.has(split)) continue;
        const cur = best.get(dir);
        // One bundle per directory, preferring the scan of the skill on its own (as the benchmark does).
        if (cur && (cur.solo || b.bundle.root !== ".")) continue;
        const built = buildState(b.bundle, budget);
        best.set(dir, {
          dir,
          corpus: corpus.name,
          label: corpus.label,
          split,
          kind: b.bundle.kind,
          ...(built.ok ? { state: built.state, chars: built.state.length } : { skipped: built.reason }),
          findings: b.findings.map((f: Finding) => ({
            ruleId: f.ruleId,
            category: f.category,
            severity: f.severity,
            confidence: f.confidence,
            hard: findRule(f.ruleId)?.hard === true,
          })),
          solo: b.bundle.root === ".",
        });
      }
    }
  }
  return [...best.values()].map(({ solo: _solo, ...b }) => b);
}

async function main(): Promise<void> {
  await mkdir(labDir!, { recursive: true });
  const questions = JSON.parse(await readFile(questionsPath!, "utf8")) as Record<
    string,
    { instructions: string; true: string; false: string }
  >;
  const asked: Record<string, ChoiceQuestion> = Object.fromEntries(
    Object.entries(questions).map(([id, q]) => [
      id,
      { type: "choice", instructions: q.instructions, criteria: { true: q.true, false: q.false } },
    ]),
  );
  const setup = resolveSetup({ enabled: true, provider: "typesafe", timeoutMs: 60_000 } as never, process.env);
  if (!setup.ok) throw new Error(setup.problem);
  const { url, model, apiKey, provider } = setup.setup;

  const bundles = await collect();
  await writeFile(
    join(labDir!, `bundles-${budget}.jsonl`),
    `${bundles.map((b) => JSON.stringify({ ...b, state: undefined, stateHash: b.state ? sha(b.state) : undefined })).join("\n")}\n`,
  );
  const answersPath = join(labDir!, "answers.jsonl");
  const have = new Set<string>();
  try {
    for (const line of (await readFile(answersPath, "utf8")).split("\n")) {
      if (!line) continue;
      const a = JSON.parse(line) as { s: string; q: string; m: string };
      have.add(`${a.s}\0${a.q}\0${a.m}`);
    }
  } catch {
    // no answers yet
  }

  const jobs: { state: string; ids: string[] }[] = [];
  for (const b of bundles) {
    if (!b.state) continue;
    const s = sha(b.state);
    const missing = Object.keys(asked).filter((id) => !have.has(`${s}\0${questionHash(asked[id]!)}\0${model}`));
    for (let i = 0; i < missing.length; i += PER_REQUEST) jobs.push({ state: b.state, ids: missing.slice(i, i + PER_REQUEST) });
  }
  const judged = bundles.filter((b) => b.state).length;
  console.log(`${bundles.length} bundles (${judged} within the ${budget} budget), ${jobs.length} requests to send`);

  let done = 0;
  let failed = 0;
  let tokens = 0;
  const worker = async (): Promise<void> => {
    for (let job = jobs.shift(); job; job = jobs.shift()) {
      const qs = Object.fromEntries(job.ids.map((id) => [id, asked[id]!]));
      try {
        const raw = (await postJson({
          url,
          headers: {
            ...provider.headers,
            accept: "application/json",
            "content-type": "application/json",
            authorization: `Bearer ${apiKey}`,
          },
          body: requestBody(model, job.state, qs),
          timeoutMs: 60_000,
          maxRetries: 4,
          retryDelayMs: 1_000,
          fetch: (u, init) => fetch(u, init),
        })) as { usage?: { input_tokens?: number } };
        tokens += raw.usage?.input_tokens ?? 0;
        const p = readTrueProbabilities(raw, job.ids);
        const s = sha(job.state);
        await appendFile(
          answersPath,
          `${job.ids.map((id) => JSON.stringify({ s, q: questionHash(asked[id]!), m: model, p: p[id] })).join("\n")}\n`,
        );
      } catch (e) {
        failed++;
        const why = e instanceof Error ? e.message : String(e);
        console.error(`failed: ${apiKey ? why.split(apiKey).join("[key]") : why}`.slice(0, 200));
      }
      if (++done % 200 === 0) console.log(`${done} requests, ${failed} failed, ${tokens.toLocaleString("en-US")} input tokens`);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  console.log(`done: ${done} requests, ${failed} failed, ${tokens.toLocaleString("en-US")} input tokens reported`);
}

await main();
