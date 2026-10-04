/**
 * Library entry: scan skills from your own code.
 *
 *   import { scanSkill } from "@french-castle/skill-scanner";
 *   const report = await scanSkill("./my-skill");   // the CLI's defaults: rules, gitleaks if installed, jev with a key
 *   if (report.verdict === "block") ...
 *
 * `scanPath` is the deterministic call: the rules alone unless given a judge, analyzers, or second opinions.
 */
export { ANALYZERS, type AnalyzerInfo, createAnalyzers, detectAnalyzers } from "./analyzers";
export { type AnalyzerName, type Config, DEFAULT_CONFIG, loadConfig, parseConfig } from "./config";
export { analyzeBundle } from "./core/engine";
export type { BundleRule, FileRule, Rule, RuleMeta } from "./core/rule";
export { DEFAULT_POLICY, effectiveSeverity, type VerdictPolicy, verdictFor } from "./core/severity";
export type { Suppression } from "./core/suppress";
export type * from "./core/types";
export { type CollectLimits, collect, DEFAULT_LIMITS } from "./io/collect";
export { createJudge, describeJudge, type JudgeDeps, pingJudge } from "./judge";
export { BUILTIN_RULES, findRule, ruleCatalog } from "./rules";
export { type BundleJudge, type ExternalAnalyzer, type JudgeReview, type ScanOptions, type SecondOpinions, scanPath } from "./scan";
export { scanSkill } from "./scan-skill";
export { scanOptionsFrom } from "./second-opinions";
export { VERSION } from "./version";
