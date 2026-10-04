import type { RuleMeta } from "../core/rule";
import { THREAT_AT, THREAT_RULE_ID } from "./apply";
import { JUDGE_REMEDIATION } from "./probes";

/** Rule metadata for the one finding the judge adds, so reporters, docs and SARIF can describe it. */
export const JUDGE_RULES: readonly RuleMeta[] = Object.freeze([
  {
    id: THREAT_RULE_ID,
    title: "jev: this skill looks malicious",
    category: "deception",
    severity: "medium",
    confidence: "medium",
    description:
      `TypeSafe's jev model was asked six questions about intent (hidden instructions, a purpose other than the stated one, ` +
      `behavior its user would object to, malice, and a download from an unofficial source) and their combined score reached ${THREAT_AT}. ` +
      "It is a model's opinion, not evidence: reported at medium severity, it warns but never blocks on its own under the default policy.",
    remediation: JUDGE_REMEDIATION,
  },
] satisfies RuleMeta[]);
