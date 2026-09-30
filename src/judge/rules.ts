import type { RuleMeta } from "../core/rule";
import { ADD_AT } from "./apply";
import { JUDGE_REMEDIATION, judgeRuleId, PROBES } from "./probes";

/** Rule metadata for the findings the judge adds, so reporters, docs and SARIF can describe them. */
export const JUDGE_RULES: readonly RuleMeta[] = Object.freeze(
  PROBES.map(
    (p): RuleMeta => ({
      id: judgeRuleId(p.id),
      title: p.title,
      category: p.category,
      severity: "medium",
      confidence: "medium",
      description:
        `TypeSafe's jev model answered "${p.question}" with P(true) >= ${ADD_AT} and no static rule found anything of this kind. ` +
        "It is a model's opinion, not evidence: reported at medium severity, it warns but never blocks on its own under the default policy.",
      remediation: JUDGE_REMEDIATION,
    }),
  ),
);
