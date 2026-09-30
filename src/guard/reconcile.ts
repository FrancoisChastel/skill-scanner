import { auditInstalledDetailed, type TargetScanner } from "./audit";
import { errorMessage } from "./fsutil";
import { skillRoots } from "./locations";
import { quarantineSkill } from "./quarantine";
import { logDecision, markQuarantined } from "./state";
import type { GuardContext, InstalledSkill, SkillRoot } from "./types";

/**
 * After a command or write: rescan the skill roots (cached, so only changed skills are read) and
 * report skills that are newly flagged; quarantine newly blocked skill directories when configured.
 */

export interface ReconcileOptions {
  readonly roots?: readonly SkillRoot[];
  readonly scan?: TargetScanner;
  readonly deadlineMs?: number;
  readonly now?: () => Date;
}

export interface ReconcileResult {
  /** Untrusted skills flagged (warn or block) that were not flagged with this digest before. */
  readonly newlyFlagged: InstalledSkill[];
  /** Paths moved to quarantine. */
  readonly quarantined: string[];
  readonly timedOut?: boolean;
}

export async function reconcileAfterChange(ctx: GuardContext, opts: ReconcileOptions = {}): Promise<ReconcileResult> {
  const roots = opts.roots ?? skillRoots("all", ctx.cwd, ctx.env);
  const audit = await auditInstalledDetailed(ctx, {
    roots,
    ...(opts.scan ? { scan: opts.scan } : {}),
    ...(opts.deadlineMs !== undefined ? { deadlineMs: opts.deadlineMs } : {}),
    ...(opts.now ? { now: opts.now } : {}),
  });
  const before = new Set(audit.previous.map((e) => `${e.realPath}\0${e.digest}`));
  const newlyFlagged = audit.skills.filter((s) => s.verdict !== "pass" && !s.trusted && !before.has(`${s.realPath}\0${s.digest}`));
  const quarantined = ctx.config.hooks.quarantine ? await quarantineBlocked(newlyFlagged, ctx, roots, "blocked after install") : [];
  return { newlyFlagged, quarantined, ...(audit.timedOut ? { timedOut: true } : {}) };
}

/** Blocked, untrusted skill directories to move aside. Plugins and packages stay: moving a harness's cache breaks it. */
export function quarantinable(skills: readonly InstalledSkill[]): InstalledSkill[] {
  return skills.filter((s) => s.verdict === "block" && !s.trusted && (s.kind ?? "skill") === "skill");
}

export async function quarantineBlocked(
  skills: readonly InstalledSkill[],
  ctx: GuardContext,
  roots: readonly SkillRoot[],
  why: string,
): Promise<string[]> {
  const moved: string[] = [];
  const ids = new Map<string, string>();
  for (const s of quarantinable(skills)) {
    try {
      const rec = await quarantineSkill(s.path, `${why}: ${s.summary[0] ?? "blocked"}`, ctx.env, { roots, digest: s.digest });
      moved.push(s.path);
      ids.set(s.realPath, rec.id);
      await logDecision({ harness: ctx.harness, kind: "quarantine", path: s.path, realPath: s.realPath, id: rec.id }, ctx.env);
    } catch (e) {
      await logDecision({ harness: ctx.harness, kind: "quarantine-failed", path: s.path, error: errorMessage(e) }, ctx.env);
    }
  }
  await markQuarantined(ids, ctx.env);
  return moved;
}
