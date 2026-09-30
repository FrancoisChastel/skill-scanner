import { realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { AUDIT_DEADLINE_MS, auditInstalledDetailed } from "./audit";
import { errorDecision, evaluateIntents, type GuardDeps } from "./decide";
import { errorMessage, isRecord } from "./fsutil";
import { detectInstallIntents } from "./intents";
import { locateSkillDir, skillRoots } from "./locations";
import { quarantineBlocked, type ReconcileOptions } from "./reconcile";
import { shellQuote } from "./shell";
import { findFlagged, isTrusted, loadFlagged, loadTrust } from "./state";
import type { AuditTarget } from "./targets";
import { hasSkillMd } from "./targets";
import type { FlaggedEntry, GuardContext, GuardDecision, HookResult, InstalledSkill, SkillRoot } from "./types";

/** Pieces shared by the Claude Code and Codex hook handlers. */

export interface HandlerDeps extends GuardDeps {
  /** Override the 25 s audit deadline (tests). */
  readonly auditDeadlineMs?: number;
}

export const PASS: HookResult = Object.freeze({ exitCode: 0 });

/** Use-time checks run in prompt hooks with short harness timeouts (15 s in setup). */
export const USE_DEADLINE_MS = 10_000;

export const jsonResult = (body: Readonly<Record<string, unknown>>): HookResult => ({ stdout: `${JSON.stringify(body)}\n`, exitCode: 0 });

export const str = (o: Readonly<Record<string, unknown>> | undefined, k: string): string | undefined =>
  typeof o?.[k] === "string" ? (o[k] as string) : undefined;

export const obj = (o: Readonly<Record<string, unknown>> | undefined, k: string): Record<string, unknown> =>
  isRecord(o?.[k]) ? (o[k] as Record<string, unknown>) : {};

export const rootsFor = (ctx: GuardContext, deps: HandlerDeps): readonly SkillRoot[] => deps.roots ?? skillRoots("all", ctx.cwd, ctx.env);

/** A shell tool's command, whether given as a string or as an argv array. */
export function shellCommand(input: Readonly<Record<string, unknown>>): string | undefined {
  const c = input.command ?? input.cmd;
  if (typeof c === "string") return c;
  if (Array.isArray(c) && c.every((x) => typeof x === "string")) return (c as string[]).map(shellQuote).join(" ");
  return undefined;
}

/** Cheap filter before a post-change audit: only commands that could have touched skills or plugins. */
const SKILLISH =
  /\bskills?\b|SKILL\.md|\.claude[\\/]|\.agents[\\/]|\.codex[\\/]|\.pi[\\/]|opencode|\bplugins?\s+(?:install|add|i|marketplace)\b/i;

export function commandTouchesSkills(command: string, ctx: GuardContext, roots: readonly SkillRoot[]): boolean {
  if (SKILLISH.test(command)) return true;
  try {
    return detectInstallIntents(command, { cwd: ctx.cwd, env: ctx.env, roots }).length > 0;
  } catch {
    return false;
  }
}

export function pathInSkillRoot(path: string | undefined, ctx: GuardContext, roots: readonly SkillRoot[]): boolean {
  return path !== undefined && locateSkillDir(resolve(ctx.cwd, path), roots) !== undefined;
}

export interface PatchFile {
  readonly path: string;
  readonly op: "add" | "update" | "delete" | "move";
  /** Full content, for added files. */
  readonly content?: string;
}

/** Files an `apply_patch` envelope touches (`*** Add File:`, `*** Update File:`, `*** Delete File:`, `*** Move to:`). */
export function patchFiles(patch: string): PatchFile[] {
  const out: PatchFile[] = [];
  let adding: { path: string; lines: string[] } | undefined;
  const flush = (): void => {
    if (adding) out.push({ path: adding.path, op: "add", content: adding.lines.join("\n") });
    adding = undefined;
  };
  for (const line of patch.split("\n")) {
    const m = /^\*\*\* (Add File|Update File|Delete File|Move to): (.+)$/.exec(line.trimEnd());
    if (m) {
      flush();
      const path = m[2]!.trim();
      if (m[1] === "Add File") adding = { path, lines: [] };
      else out.push({ path, op: m[1] === "Update File" ? "update" : m[1] === "Delete File" ? "delete" : "move" });
    } else if (line.startsWith("***")) flush();
    else if (adding && line.startsWith("+")) adding.lines.push(line.slice(1));
  }
  flush();
  return out;
}

export function patchText(input: Readonly<Record<string, unknown>>): string | undefined {
  for (const k of ["command", "input", "patch"]) if (typeof input[k] === "string") return input[k] as string;
  return undefined;
}

/**
 * Whether a skill about to be used is flagged and untrusted. Looks in the registry first; for a
 * plain skill name not in it, audits that one skill (cached) so a skill that appeared outside any
 * tool call is still checked before use.
 */
export async function flaggedForUse(name: string, ctx: GuardContext, deps: HandlerDeps): Promise<FlaggedEntry | undefined> {
  const [flagged, trust] = await Promise.all([loadFlagged(ctx.env), loadTrust(ctx.env)]);
  const known = findFlagged(name, flagged);
  if (known) return isTrusted(known.digest, trust) ? undefined : known;
  if (!/^[\w.-]+$/.test(name)) return undefined;
  const targets = await skillTargetsNamed(name, rootsFor(ctx, deps));
  if (targets.length === 0) return undefined;
  const audit = await auditInstalledDetailed(ctx, {
    targets,
    deadlineMs: Math.min(deps.auditDeadlineMs ?? USE_DEADLINE_MS, USE_DEADLINE_MS),
    ...(deps.scanPath ? { scan: deps.scanPath } : {}),
  });
  const bad = audit.skills.find((s) => s.verdict !== "pass" && !s.trusted);
  return bad ? toEntry(bad) : undefined;
}

async function skillTargetsNamed(name: string, roots: readonly SkillRoot[]): Promise<AuditTarget[]> {
  const out: AuditTarget[] = [];
  for (const r of roots.filter((x) => x.kind === "skills")) {
    const p = join(r.path, name);
    if (!(await hasSkillMd(p))) continue;
    const realPath = await realpath(p).catch(() => undefined);
    if (realPath && !out.some((t) => t.realPath === realPath))
      out.push({ harness: r.harness, scope: r.scope, kind: "skill", name, path: p, realPath });
  }
  return out;
}

export function toEntry(s: InstalledSkill): FlaggedEntry {
  return {
    name: s.name,
    path: s.path,
    realPath: s.realPath,
    digest: s.digest,
    verdict: s.verdict === "block" ? "block" : "warn",
    summary: s.summary,
    flaggedAt: new Date().toISOString(),
  };
}

export interface SessionAudit {
  readonly flagged: readonly InstalledSkill[];
  readonly quarantined: readonly string[];
  readonly pending: number;
  readonly timedOut: boolean;
}

/** The session-start audit: every root, cached, under the deadline; blocked skills quarantined per config. */
export async function sessionAudit(ctx: GuardContext, deps: HandlerDeps): Promise<SessionAudit> {
  const roots = rootsFor(ctx, deps);
  const audit = await auditInstalledDetailed(ctx, {
    roots,
    deadlineMs: deps.auditDeadlineMs ?? AUDIT_DEADLINE_MS,
    ...(deps.scanPath ? { scan: deps.scanPath } : {}),
    ...(deps.now ? { now: deps.now } : {}),
  });
  const flagged = audit.skills.filter((s) => s.verdict !== "pass" && !s.trusted);
  const quarantined = ctx.config.hooks.quarantine ? await quarantineBlocked(flagged, ctx, roots, "blocked at session start") : [];
  return { flagged, quarantined, pending: audit.pending.length, timedOut: audit.timedOut };
}

export function failOpen(e: unknown, ctx: GuardContext): HookResult {
  return ctx.env.SKILL_SCANNER_DEBUG ? { exitCode: 0, stderr: `skill-scanner: ${errorMessage(e)}\n` } : PASS;
}

/** Install intents in a shell command. No intent means no work and no output. */
export async function shellDecision(command: string | undefined, ctx: GuardContext, deps: HandlerDeps): Promise<GuardDecision | undefined> {
  if (!command) return undefined;
  const roots = rootsFor(ctx, deps);
  const intents = detectInstallIntents(command, { cwd: ctx.cwd, env: ctx.env, roots });
  if (intents.length === 0) return undefined;
  try {
    return await evaluateIntents(command, intents, ctx, { ...deps, roots });
  } catch (e) {
    return errorDecision(ctx, "this install", errorMessage(e));
  }
}

export function reconcileOpts(deps: HandlerDeps, roots: readonly SkillRoot[]): ReconcileOptions {
  return {
    roots,
    ...(deps.scanPath ? { scan: deps.scanPath } : {}),
    ...(deps.auditDeadlineMs !== undefined ? { deadlineMs: deps.auditDeadlineMs } : {}),
    ...(deps.now ? { now: deps.now } : {}),
  };
}
