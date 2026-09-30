/**
 * Harness-agnostic guard used by Claude Code and Codex hooks, the OpenCode plugin, and the Pi
 * extension: recognise installs in commands and writes, pre-scan them, audit what is installed,
 * and keep a registry of flagged skills for use-time gates.
 */

export {
  AUDIT_DEADLINE_MS,
  type AuditOptions,
  type AuditResult,
  auditInstalled,
  auditInstalledDetailed,
  findingLines,
  type TargetScanner,
  targetDigest,
} from "./audit";
export { handleClaudeCodeEvent } from "./claude-code";
export { handleCodexEvent } from "./codex";
export { type DeadlineOutcome, withDeadline } from "./deadline";
export {
  ALLOW,
  decideReport,
  errorDecision,
  evaluateCommand,
  evaluateIntents,
  type GuardDeps,
  INSTALL_DEADLINE_MS,
  mostSevere,
  type SourceScanner,
} from "./decide";
export { flaggedForUse, type HandlerDeps, type PatchFile, patchFiles } from "./hook-common";
export { type DetectOptions, detectInstallIntents } from "./intents";
export { isolatedGuardDeps } from "./isolation";
export { harnessDirs, isInsideSkillRoot, locateSkillDir, type SkillLocation, skillRoots } from "./locations";
export { flaggedContext, flaggedReason, flaggedSystemMessage } from "./messages";
export { listQuarantine, QUARANTINE_RECORD, type QuarantineOptions, quarantineSkill, restoreQuarantined } from "./quarantine";
export { quarantinable, quarantineBlocked, type ReconcileOptions, type ReconcileResult, reconcileAfterChange } from "./reconcile";
export { contentAfterEdits, type EditSpec, evaluateSkillWrite, evaluateSkillWrites, type PendingWrite } from "./skill-write";
export {
  addTrust,
  findFlagged,
  isTrusted,
  loadFlagged,
  loadTrust,
  logDecision,
  type NewTrustEntry,
  removeTrust,
  saveFlagged,
  trustedDigests,
} from "./state";
export { type AuditTarget, enumerateTargets } from "./targets";
export type {
  FlaggedEntry,
  GuardAction,
  GuardContext,
  GuardDecision,
  Harness,
  HookResult,
  InstalledSkill,
  InstallIntent,
  QuarantineRecord,
  SkillRoot,
  TargetKind,
  TrustEntry,
  TrustStore,
} from "./types";
