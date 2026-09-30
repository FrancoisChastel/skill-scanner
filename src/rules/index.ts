import type { Rule, RuleMeta } from "../core/rule";
import { deceptionRules } from "./deception";
import { executionRules } from "./execution";
import { credentialRules, networkRules } from "./exfiltration";
import { hiddenContentRules, injectionRules } from "./injection";
import { metadataRules } from "./metadata";
import { packagingRules } from "./packaging";
import { secretRules } from "./secrets";
import { supplyChainBundleRules, supplyChainFileRules } from "./supply-chain";
import { correlationRules, surfaceRules } from "./surface";
import { destructiveRules, persistenceRules, privilegeRules } from "./system";
import { unicodeRules } from "./unicode";

/** Every built-in rule, in the order they appear in `skill-scanner rules`. */
export const BUILTIN_RULES: readonly Rule[] = Object.freeze([
  ...injectionRules,
  ...deceptionRules,
  ...hiddenContentRules,
  ...unicodeRules,
  ...executionRules,
  ...credentialRules,
  ...networkRules,
  ...persistenceRules,
  ...destructiveRules,
  ...privilegeRules,
  ...secretRules,
  ...supplyChainFileRules,
  ...supplyChainBundleRules,
  ...packagingRules,
  ...metadataRules,
  ...surfaceRules,
  ...correlationRules,
]);

/** Findings the engine emits itself, without a rule object. Listed so docs and SARIF know them. */
export const ENGINE_RULES: readonly RuleMeta[] = [
  {
    id: "obfuscation/encoded-payload",
    title: "Encoded payload hides risky content",
    category: "obfuscation",
    severity: "critical",
    confidence: "high",
    hard: true,
    description: "Base64, hex, or char-code text that decodes to content another rule flags. The decoded text is shown as evidence.",
  },
  {
    id: "scanner/rule-error",
    title: "A rule failed on this file",
    category: "packaging",
    severity: "low",
    confidence: "low",
    description: "A rule threw while analyzing a file, so the file was only partly analyzed. Please report it.",
  },
];

/** Rules that only record signals and never report. Hidden from listings. */
export const isSignalOnly = (r: RuleMeta): boolean => r.id.startsWith("signal/");

export function ruleCatalog(): RuleMeta[] {
  return [...BUILTIN_RULES, ...ENGINE_RULES].filter((r) => !isSignalOnly(r));
}

export function findRule(id: string): RuleMeta | undefined {
  return ruleCatalog().find((r) => r.id === id);
}

function assertUniqueIds(rules: readonly RuleMeta[]): void {
  const seen = new Set<string>();
  for (const r of rules) {
    if (seen.has(r.id)) throw new Error(`duplicate rule id ${r.id}`);
    if (!/^[a-z-]+\/[a-z0-9-]+$/.test(r.id)) throw new Error(`rule id ${r.id} must be category/slug`);
    seen.add(r.id);
  }
}
assertUniqueIds([...BUILTIN_RULES, ...ENGINE_RULES]);
