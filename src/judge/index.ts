/**
 * Optional jev judge: a second opinion from TypeSafe's System One model, off by default because
 * it sends skill text to a third party. See DESIGN.md section 8 for why it asks `choice`
 * questions and how its answers are applied.
 */
import type { JudgeConfig } from "../config";
import type { Finding, SkillBundle } from "../core/types";
import type { BundleJudge, JudgeReview } from "../scan";
import { VERSION } from "../version";
import { applyScores } from "./apply";
import { type FetchLike, JudgeError, postJson } from "./http";
import { type ChoiceQuestion, probeQuestions, readModel, readScores, readTrueProbabilities, requestBody } from "./protocol";
import { type JudgeSetup, resolveSetup } from "./providers";
import { buildState } from "./state";

export { ADD_AT, CONFIRM_AT, DOUBT_BELOW } from "./apply";
export { type FetchLike, JudgeError, type JudgeErrorCode } from "./http";
export { INSTRUCTIONS, PROBE_ATTRIBUTION, PROBE_FOR_CATEGORY, PROBES, type Probe, type ProbeId } from "./probes";
export { OVERRIDE_KEY_ENV, PROVIDERS, type ProviderName } from "./providers";
export { JUDGE_RULES } from "./rules";
export { STATE_BUDGET } from "./state";

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

/** A judge when a key is available and judging is enabled, else the reason there is none. */
export function createJudge(cfg: JudgeConfig, env: NodeJS.ProcessEnv, deps: JudgeDeps = {}): { judge?: BundleJudge; reason?: string } {
  if (!cfg.enabled) return { reason: "judging is off; enable with --judge or judge.enabled" };
  const resolved = resolveSetup(cfg, env);
  if (!resolved.ok) return { reason: resolved.problem };
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
  const resolved = resolveSetup(cfg, env);
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
  const resolved = resolveSetup(cfg, env);
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
  const built = buildState(bundle);
  if (!built.ok) return { status: "skipped", detail: built.reason, findings };
  const started = performance.now();
  try {
    const raw = await post(setup, deps, requestBody(setup.model, built.state, probeQuestions()), signal);
    const scores = readScores(raw);
    const model = readModel(raw, setup.model);
    const ms = Math.round(performance.now() - started);
    return {
      status: "ok",
      detail: `jev via ${setup.provider.name} (${model}), ${ms} ms`,
      findings: applyScores(bundle, findings, scores, model),
    };
  } catch (e) {
    return { status: "failed", detail: failureDetail(e, setup), findings };
  }
}

function post(setup: JudgeSetup, deps: JudgeDeps, body: string, signal?: AbortSignal): Promise<unknown> {
  return postJson({
    url: setup.url,
    headers: {
      ...setup.provider.headers,
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": `skill-scanner/${VERSION}`,
      authorization: `Bearer ${setup.apiKey}`,
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
  const line = `jev via ${setup.provider.name} failed: ${why}`.split(setup.apiKey).join("[key]");
  return line.length > 300 ? `${line.slice(0, 297)}...` : line;
}
