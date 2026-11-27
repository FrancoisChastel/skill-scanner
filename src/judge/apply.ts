import { joinPath } from "../core/engine";
import type { Finding, SkillBundle } from "../core/types";
import { findRule } from "../rules";
import { JUDGE_REMEDIATION, PROBE_FOR_CATEGORY, THREAT_PROBE_IDS, THREAT_PROBES, type ThreatProbeId } from "./probes";
import type { ProbeScores } from "./protocol";

/**
 * Apply jev's answers monotonically: code decides, the model only nudges. A static finding can be
 * doubted (confidence low, which costs one step of effective severity); nothing is removed and no
 * severity changes. A skill whose threat score reaches THREAT_AT gets one medium finding of the
 * judge's own, which warns and never blocks alone under the default policy.
 *
 * Both rules were measured on the benchmark's training split and checked on validation
 * (docs/benchmark.md, "Tuning the judge"). Confirming a finding (raising its confidence on a high
 * answer) was dropped there: it added a false block and caught nothing the doubts and the threat
 * score did not.
 */

/** Below this P(true), a finding in the probe's family is doubted, unless it is hard evidence or critical. */
export const DOUBT_BELOW = 0.05;
/**
 * At or above this threat score, the judge adds its finding: 0.5% of benign training skills reach
 * it (0.6% on validation), against 79% of malicious ones. Measured on jev-1.13.0.
 */
export const THREAT_AT = 0.075;
/** The rule id of the judge's own finding. */
export const THREAT_RULE_ID = "judge/malicious-skill";

/** The five intent probes; the sixth, unofficial_download, is a lure the others do not see and weighs as much as their mean. */
const INTENT: readonly ThreatProbeId[] = THREAT_PROBE_IDS.filter((id) => id !== "unofficial_download");

/** Half the mean of the five intent probes plus half the unofficial-download probe: a number from 0 to 1. */
export function threatScore(scores: ProbeScores): number {
  const intent = INTENT.reduce((sum, id) => sum + scores[id], 0) / INTENT.length;
  return (intent + scores.unofficial_download) / 2;
}

export function applyScores(bundle: SkillBundle, findings: readonly Finding[], scores: ProbeScores, model: string): Finding[] {
  const reviewed = findings.map((f) => review(f, scores, model));
  const score = threatScore(scores);
  return score >= THREAT_AT ? [...reviewed, threatFinding(bundle, scores, score, model)] : reviewed;
}

/** One window's answers, and the files (or parts) it carried besides its opener. */
export interface WindowScores {
  readonly scores: ProbeScores;
  readonly contents: readonly string[];
}

/**
 * The answers about a skill sent in windows. Its threat score is the most threatening window's, so
 * an attack is not diluted by the text around it. A finding is doubted only when every window was
 * read and none gives its probe DOUBT_BELOW or more; when only the first windows were read, none is.
 * One complete window is exactly applyScores.
 */
export function applyWindowScores(
  bundle: SkillBundle,
  findings: readonly Finding[],
  windows: readonly WindowScores[],
  complete: boolean,
  model: string,
): Finding[] {
  const [only] = windows;
  if (!only) return [...findings];
  if (windows.length === 1 && complete) return applyScores(bundle, findings, only.scores, model);
  const reviewed = complete ? findings.map((f) => review(f, highest(windows), model)) : [...findings];
  const top = windows
    .map((w, i) => ({ w, i, score: threatScore(w.scores) }))
    .reduce((best, next) => (next.score > best.score ? next : best));
  if (top.score < THREAT_AT) return reviewed;
  const where = `in window ${top.i + 1} of ${windows.length} (${listed(top.w.contents)})`;
  return [...reviewed, threatFinding(bundle, top.w.scores, top.score, model, where)];
}

/** Each probe's highest P(true) over the windows: what any of them saw. */
function highest(windows: readonly WindowScores[]): ProbeScores {
  const keys = Object.keys(windows[0]?.scores ?? {}) as (keyof ProbeScores)[];
  return Object.fromEntries(keys.map((k) => [k, Math.max(...windows.map((w) => w.scores[k]))])) as ProbeScores;
}

const listed = (labels: readonly string[]): string =>
  labels.length <= 3 ? labels.join(", ") : `${labels.slice(0, 3).join(", ")} and ${labels.length - 3} more`;

function review(f: Finding, scores: ProbeScores, model: string): Finding {
  const probe = PROBE_FOR_CATEGORY[f.category];
  if (probe === undefined) return f;
  const pTrue = scores[probe];
  if (pTrue < DOUBT_BELOW && canDoubt(f)) return { ...f, confidence: "low", judge: { model, pTrue, effect: "doubted" } };
  return { ...f, judge: { model, pTrue, effect: "none" } };
}

/** A model can be argued with by the content it reads, so hard evidence and critical findings are never doubted. */
function canDoubt(f: Finding): boolean {
  return f.severity !== "critical" && findRule(f.ruleId)?.hard !== true;
}

function threatFinding(bundle: SkillBundle, scores: ProbeScores, score: number, model: string, where?: string): Finding {
  // The answers that carried the score, strongest first, so a reader knows where to look.
  const reasons = THREAT_PROBES.filter((p) => scores[p.id] >= 0.1)
    .sort((a, b) => scores[b.id] - scores[a.id])
    .slice(0, 3)
    .map((p) => `${p.yes.replace(/^Yes: /, "").replace(/\.$/, "")} (P = ${scores[p.id].toFixed(2)})`);
  return {
    ruleId: THREAT_RULE_ID,
    title: "jev: this skill looks malicious",
    category: "deception",
    severity: "medium",
    confidence: "medium",
    message:
      `jev: threat score ${score.toFixed(2)}${where ? ` ${where}` : ""}, at or above ${THREAT_AT}` +
      `${reasons.length ? `; ${reasons.join("; ")}` : ""}. It is a model's opinion; no static rule needs to agree.`,
    location: { file: anchorFile(bundle) },
    bundle: bundle.name,
    source: "judge",
    remediation: JUDGE_REMEDIATION,
    judge: { model, pTrue: score, effect: "none" },
  };
}

/** Where a bundle-wide opinion points: its SKILL.md when it has one, else the bundle root. */
function anchorFile(bundle: SkillBundle): string {
  const skillMd = bundle.files.find((f) => f.kind === "skill-md");
  return skillMd ? joinPath(bundle.root, skillMd.path) : bundle.root;
}
