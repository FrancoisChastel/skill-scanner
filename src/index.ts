/**
 * Library entry: scan skills from your own code.
 *
 *   import { scanPath } from "@french-castle/skill-scanner";
 *   const report = await scanPath("./my-skill");
 *   if (report.verdict === "block") ...
 */
export { type Config, DEFAULT_CONFIG, loadConfig, parseConfig } from "./config";
export { analyzeBundle } from "./core/engine";
export type { BundleRule, FileRule, Rule, RuleMeta } from "./core/rule";
export { DEFAULT_POLICY, type VerdictPolicy, verdictFor } from "./core/severity";
export type { Suppression } from "./core/suppress";
export type * from "./core/types";
export { type CollectLimits, collect, DEFAULT_LIMITS } from "./io/collect";
export { BUILTIN_RULES, findRule, ruleCatalog } from "./rules";
export { type BundleJudge, type ExternalAnalyzer, type JudgeReview, type ScanOptions, scanPath } from "./scan";
export { VERSION } from "./version";
