/**
 * The jev judge: a second opinion from TypeSafe's System One model. It runs by default when a jev
 * key is set (`judge.enabled: "auto"`), since it sends redacted skill text to a third party only
 * once the user has asked for a key; without one, scans stay offline. See DESIGN.md section 8 for
 * why it asks `choice` questions and how its answers are applied.
 */
import type { JudgeConfig } from "../config";
import type { Finding, SkillBundle } from "../core/types";
import type { BundleJudge, JudgeReview } from "../scan";
import { VERSION } from "../version";
import { applyWindowScores } from "./apply";
import { type FetchLike, JudgeError, postJson } from "./http";
import { type ChoiceQuestion, probeQuestions, readModel, readScores, readTrueProbabilities, requestBody } from "./protocol";
import { type JudgeSetup, OVERRIDE_KEY_ENV, resolveSetup } from "./providers";
import { buildWindows, MAX_WINDOWS, STATE_BUDGET } from "./state";

export { DOUBT_BELOW, THREAT_AT, THREAT_RULE_ID, threatScore } from "./apply";
export { type FetchLike, JudgeError, type JudgeErrorCode } from "./http";
export { INSTRUCTIONS, PROBE_ATTRIBUTION, PROBE_FOR_CATEGORY, PROBES, type Probe, type ProbeId } from "./probes";
export { OVERRIDE_KEY_ENV, PROVIDERS, type ProviderName } from "./providers";

export { JUDGE_RULES } from "./rules";
export { MAX_WINDOWS, STATE_BUDGET } from "./state";

export const JUDGE_NAME = "jev";

/** Test and host seams. Every field is optional; the defaults are what the CLI uses. */
export interface JudgeDeps {
  /** Defaults to the global fetch. */
  readonly fetch?: FetchLike;
  /** Retries after a 429, 529, 5xx or network failure. Default 2. */
  readonly maxRetries?: number;
  /** Base backoff before a retry, doubled per retry with jitter. Default 500 ms. */
  readonly retryDelayMs?: number;
}

/** What `auto` says when there is no jev key; the scan goes on with the rules. */
export const NO_JEV_KEY = `jev is off: set TYPESAFE_API_KEY (or ${OVERRIDE_KEY_ENV}) to turn it on`;

/** The keys `auto` may use: a jev key, or any key once `provider` names its host. Gateway keys need `enabled: true`. */
const GENERAL_KEYS = ["OPENROUTER_API_KEY", "AI_GATEWAY_API_KEY"] as const;

function keysFor(cfg: JudgeConfig, env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  if (cfg.enabled !== "auto" || cfg.provider !== undefined) return env;
  const narrowed = { ...env };
  for (const k of GENERAL_KEYS) delete narrowed[k];
  return narrowed;
}

/**
 * A judge when judging is on and a key resolves, else the reason there is none. `quiet` marks the
 * expected case of `auto` without a jev key, which callers report as a hint, never as a warning.
 */
export function createJudge(
  cfg: JudgeConfig,
  env: NodeJS.ProcessEnv,
  deps: JudgeDeps = {},
): { judge?: BundleJudge; reason?: string; quiet?: boolean } {
  if (cfg.enabled === false) return { reason: "judging is off; enable with --judge or judge.enabled" };
  const resolved = resolveSetup(cfg, keysFor(cfg, env));
  if (!resolved.ok)
    return cfg.enabled === "auto" && cfg.provider === undefined ? { reason: NO_JEV_KEY, quiet: true } : { reason: resolved.problem };
  const { setup } = resolved;
  return {
    judge: {
      name: JUDGE_NAME,
      review: (bundle, findings, signal) => reviewBundle(setup, deps, bundle, findings, signal),
    },
  };
}

/** Which provider and key variable would be used, without making a request. For `doctor`. Never includes the key. */
export function describeJudge(
  cfg: JudgeConfig,
  env: NodeJS.ProcessEnv,
): { provider?: string; keyEnv?: string; model?: string; url?: string; problem?: string } {
  const resolved = resolveSetup(cfg, keysFor(cfg, env));
  if (!resolved.ok) return { problem: resolved.problem };
  const { provider, keyEnv, model, url } = resolved.setup;
  return { provider: provider.name, keyEnv, model, url };
}

/** One tiny live request on a trivial state, no retries, for `doctor --live`. Sends no skill text. */
export async function pingJudge(
  cfg: JudgeConfig,
  env: NodeJS.ProcessEnv,
  deps: JudgeDeps = {},
): Promise<{ ok: boolean; detail: string; latencyMs?: number }> {
  const resolved = resolveSetup(cfg, keysFor(cfg, env));
  if (!resolved.ok) return { ok: false, detail: resolved.problem };
  const { setup } = resolved;
  const started = performance.now();
  try {
    const raw = await post(setup, { ...deps, maxRetries: 0 }, requestBody(setup.model, PING_STATE, PING_QUESTIONS));
    readTrueProbabilities(raw, ["ping"]);
    const latencyMs = Math.round(performance.now() - started);
    return { ok: true, detail: `jev via ${setup.provider.name} (${readModel(raw, setup.model)}) answered in ${latencyMs} ms`, latencyMs };
  } catch (e) {
    return { ok: false, detail: failureDetail(e, setup), latencyMs: Math.round(performance.now() - started) };
  }
}

const PING_STATE = "Water is wet.";
const PING_QUESTIONS: Readonly<Record<string, ChoiceQuestion>> = {
  ping: {
    type: "choice",
    instructions: "Answer about the statement in the state.\n\nIs the statement true?",
    criteria: { true: "Yes: the statement is true.", false: "No: the statement is false." },
  },
};

async function reviewBundle(
  setup: JudgeSetup,
  deps: JudgeDeps,
  bundle: SkillBundle,
  findings: readonly Finding[],
  signal?: AbortSignal,
): Promise<JudgeReview> {
  if (bundle.kind !== "skill" && bundle.kind !== "plugin")
    return { status: "skipped", detail: `only skills and plugins are judged; this is a ${bundle.kind} bundle`, findings };
  const started = performance.now();
  // Characters are not tokens: dense text (code, data, other scripts) can pass the budget and still be
  // refused as over the model's token limit. Such a skill is sent again in windows half the size.
  for (let budget = STATE_BUDGET; ; budget /= 2) {
    const built = buildWindows(bundle, budget, MAX_WINDOWS * (STATE_BUDGET / budget));
    if (!built.ok) return { status: "skipped", detail: built.reason, findings };
    try {
      const raws = await askAll(setup, deps, built.windows, signal);
      const windows = raws.map((raw, i) => ({ scores: readScores(raw), contents: built.contents[i] ?? [] }));
      const model = readModel(raws[0], setup.model);
      const ms = Math.round(performance.now() - started);
      return {
        status: "ok",
        detail: `jev via ${setup.provider.name} (${model})${coverage(built.windows.length, built.needed, budget)}, ${ms} ms`,
        findings: applyWindowScores(bundle, findings, windows, built.complete, model),
      };
    } catch (e) {
      if (e instanceof JudgeError && e.code === "too_long" && budget / 2 >= SMALLEST_WINDOW) continue;
      return { status: "failed", detail: failureDetail(e, setup), findings };
    }
  }
}

/** The smallest window a refused skill is cut into: about 8,000 tokens even for dense text. */
const SMALLEST_WINDOW = STATE_BUDGET / 4;

/** Every window must answer: one failure fails the review, as a malformed answer does, and cancels the requests still in flight. */
async function askAll(setup: JudgeSetup, deps: JudgeDeps, states: readonly string[], signal?: AbortSignal): Promise<unknown[]> {
  const failed = new AbortController();
  const cancel = signal ? AbortSignal.any([signal, failed.signal]) : failed.signal;
  return inBatches(states, WINDOWS_AT_ONCE, (state) =>
    post(setup, deps, requestBody(setup.model, state, probeQuestions()), cancel).catch((e: unknown) => {
      failed.abort();
      throw e;
    }),
  );
}

/** Requests in flight at once for one long skill. */
const WINDOWS_AT_ONCE = 4;

async function inBatches<T, R>(items: readonly T[], size: number, run: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let at = 0; at < items.length; at += size) out.push(...(await Promise.all(items.slice(at, at + size).map(run))));
  return out;
}

function coverage(sent: number, needed: number, budget: number): string {
  const size = budget < STATE_BUDGET ? ` of ${budget} characters (jev's token limit)` : "";
  if (needed === 1 && !size) return "";
  if (sent === needed) return `, ${sent} window${sent === 1 ? "" : "s"}${size}`;
  return `, first ${sent} of ${needed} windows${size}; no finding was doubted`;
}

function post(setup: JudgeSetup, deps: JudgeDeps, body: string, signal?: AbortSignal): Promise<unknown> {
  return postJson({
    url: setup.url,
    headers: {
      ...setup.provider.headers,
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": `skill-scanner/${VERSION}`,
      ...(setup.apiKey ? { authorization: `Bearer ${setup.apiKey}` } : {}),
    },
    body,
    timeoutMs: setup.timeoutMs,
    maxRetries: deps.maxRetries ?? 2,
    retryDelayMs: deps.retryDelayMs ?? 500,
    fetch: deps.fetch ?? ((url, init) => fetch(url, init)),
    ...(signal ? { signal } : {}),
  });
}

/** A failure line safe to print: built from our own messages, and scrubbed of the key in case anything echoed it. */
function failureDetail(e: unknown, setup: JudgeSetup): string {
  const why = e instanceof JudgeError ? e.message : `unexpected error: ${e instanceof Error ? e.message : String(e)}`;
  const line = setup.apiKey
    ? `jev via ${setup.provider.name} failed: ${why}`.split(setup.apiKey).join("[key]")
    : `jev via ${setup.provider.name} failed: ${why}`;
  return line.length > 300 ? `${line.slice(0, 297)}...` : line;
}
