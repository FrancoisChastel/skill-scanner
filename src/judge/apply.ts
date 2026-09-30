import { joinPath } from "../core/engine";
import type { Finding, SkillBundle } from "../core/types";
import { findRule } from "../rules";
import { JUDGE_REMEDIATION, judgeRuleId, PROBE_FOR_CATEGORY, PROBES, type Probe } from "./probes";
import type { ProbeScores } from "./protocol";

/**
 * Apply jev's answers monotonically: code decides, the model only nudges. A finding can be
 * doubted (confidence low, which costs one step of effective severity) or confirmed (confidence
 * raised one step, so a model can restore a finding its context demoted but not leap past it);
 * nothing is removed and no severity changes. A probe that fires with no static finding
 * in its family adds one medium note.
 *
 * The thresholds are not calibrated on this pipeline. For reference, Cisco's selected screen
 * thresholds for the prompt_injection probe on MaliciousSkillBench were 0.048 to 0.061.
 */

/** Below this P(true), a finding in the probe's family is doubted, unless it is hard evidence or critical. */
export const DOUBT_BELOW = 0.05;
/** At or above this P(true), a finding in the probe's family is confirmed. */
export const CONFIRM_AT = 0.5;
/** At or above this P(true), with no static finding in the family, the judge adds a medium finding. */
export const ADD_AT = 0.85;

export function applyScores(bundle: SkillBundle, findings: readonly Finding[], scores: ProbeScores, model: string): Finding[] {
  const reviewed = findings.map((f) => review(f, scores, model));
  const covered = new Set(findings.map((f) => PROBE_FOR_CATEGORY[f.category]));
  const added = PROBES.filter((p) => scores[p.id] >= ADD_AT && !covered.has(p.id)).map((p) => judgeFinding(bundle, p, scores[p.id], model));
  return [...reviewed, ...added];
}

function review(f: Finding, scores: ProbeScores, model: string): Finding {
  const probe = PROBE_FOR_CATEGORY[f.category];
  if (probe === undefined) return f;
  const pTrue = scores[probe];
  if (pTrue < DOUBT_BELOW && canDoubt(f)) return { ...f, confidence: "low", judge: { model, pTrue, effect: "doubted" } };
  if (pTrue >= CONFIRM_AT) return { ...f, confidence: raiseConfidence(f.confidence), judge: { model, pTrue, effect: "confirmed" } };
  return { ...f, judge: { model, pTrue, effect: "none" } };
}

function raiseConfidence(c: Finding["confidence"]): Finding["confidence"] {
  return c === "low" ? "medium" : "high";
}

/** A model can be argued with by the content it reads, so hard evidence and critical findings are never doubted. */
function canDoubt(f: Finding): boolean {
  return f.severity !== "critical" && findRule(f.ruleId)?.hard !== true;
}

function judgeFinding(bundle: SkillBundle, probe: Probe, pTrue: number, model: string): Finding {
  return {
    ruleId: judgeRuleId(probe.id),
    title: probe.title,
    category: probe.category,
    severity: "medium",
    confidence: "medium",
    message: `jev: P(true) = ${pTrue.toFixed(2)} that this skill ${probe.claim}. No static rule found this; it is a model's opinion.`,
    location: { file: anchorFile(bundle) },
    bundle: bundle.name,
    source: "judge",
    remediation: JUDGE_REMEDIATION,
    judge: { model, pTrue, effect: "none" },
  };
}

/** Where a bundle-wide opinion points: its SKILL.md when it has one, else the bundle root. */
function anchorFile(bundle: SkillBundle): string {
  const skillMd = bundle.files.find((f) => f.kind === "skill-md");
  return skillMd ? joinPath(bundle.root, skillMd.path) : bundle.root;
}
