import { JudgeError } from "./http";
import { INSTRUCTIONS, PROBE_IDS, PROBES, type ProbeId, THREAT_PROBE_IDS, THREAT_PROBES, type ThreatProbeId } from "./probes";

/** TypeSafe System One wire shapes: a `choice` question whose options are the criteria keys. */

export interface ChoiceQuestion {
  readonly type: "choice";
  readonly instructions: string;
  readonly criteria: { readonly true: string; readonly false: string };
}

export type ProbeScores = Readonly<Record<ProbeId | ThreatProbeId, number>>;

/** Every question of one review: the eight review probes, each after the shared instructions, then the six threat probes, each after its frame. */
export function probeQuestions(): Readonly<Record<ProbeId | ThreatProbeId, ChoiceQuestion>> {
  return Object.fromEntries([
    ...PROBES.map((p) => [
      p.id,
      { type: "choice", instructions: `${INSTRUCTIONS}\n\n${p.question}`, criteria: { true: `Yes: this skill ${p.claim}.`, false: p.no } },
    ]),
    ...THREAT_PROBES.map((p) => [
      p.id,
      { type: "choice", instructions: `${p.frame}\n\n${p.question}`, criteria: { true: p.yes, false: p.no } },
    ]),
  ]) as Record<ProbeId | ThreatProbeId, ChoiceQuestion>;
}

export function requestBody(model: string, state: string, questions: Readonly<Record<string, ChoiceQuestion>>): string {
  return JSON.stringify({ model, state, questions });
}

/** P(true) for every probe. Any missing or malformed answer fails the whole review: no partial opinions. */
export function readScores(raw: unknown): ProbeScores {
  return readTrueProbabilities(raw, [...PROBE_IDS, ...THREAT_PROBE_IDS]);
}

/**
 * The System One answer, or the one inside a Cloudflare Workers AI envelope (`{ result, success, errors }`).
 * A failed envelope is reported with its first error message.
 */
export function unwrapEnvelope(raw: unknown): unknown {
  if (!isRecord(raw) || !("result" in raw) || "answers" in raw) return raw;
  if (raw.success === false) {
    const errors = Array.isArray(raw.errors) ? raw.errors : [];
    const first = errors.find(isRecord);
    throw invalid(`the host reported an error${first && typeof first.message === "string" ? `: ${first.message}` : ""}`);
  }
  return raw.result;
}

export function readTrueProbabilities<K extends string>(raw: unknown, ids: readonly K[]): Readonly<Record<K, number>> {
  const unwrapped = unwrapEnvelope(raw);
  const answers = isRecord(unwrapped) ? unwrapped.answers : undefined;
  if (!isRecord(answers)) throw invalid("the response has no answers object");
  return Object.fromEntries(ids.map((id) => [id, pTrueOf(id, Object.hasOwn(answers, id) ? answers[id] : undefined)])) as Record<K, number>;
}

function pTrueOf(id: string, answer: unknown): number {
  if (!isRecord(answer)) throw invalid(`answer "${id}" is missing`);
  if (answer.type !== "choice") throw invalid(`answer "${id}" is not a choice answer`);
  const p = isRecord(answer.probabilities) ? answer.probabilities.true : undefined;
  if (!isUnit(p)) throw invalid(`answer "${id}" has no probability of true in [0, 1]`);
  return p;
}

/** The model the response names, when it looks like a model id; it ends up in reports, so free text is not trusted. */
export function readModel(raw: unknown, fallback: string): string {
  const inner = unwrapEnvelope(raw);
  const m = isRecord(inner) ? inner.model : undefined;
  return typeof m === "string" && /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,99}$/.test(m) ? m : fallback;
}

const invalid = (why: string): JudgeError => new JudgeError(`invalid answer: ${why}`, "invalid_response");

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

const isUnit = (n: unknown): n is number => typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= 1;
