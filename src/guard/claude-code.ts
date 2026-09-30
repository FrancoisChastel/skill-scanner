import { realpath } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { AUDIT_DEADLINE_MS, auditInstalledDetailed } from "./audit";
import { isRecord } from "./fsutil";
import {
  commandTouchesSkills,
  failOpen,
  flaggedForUse,
  type HandlerDeps,
  jsonResult,
  obj,
  PASS,
  pathInSkillRoot,
  reconcileOpts,
  rootsFor,
  sessionAudit,
  shellCommand,
  shellDecision,
  str,
} from "./hook-common";
import { locateSkillDir } from "./locations";
import { flaggedAskReason, flaggedContext, flaggedReason, flaggedSystemMessage } from "./messages";
import { quarantineBlocked, type ReconcileResult, reconcileAfterChange } from "./reconcile";
import { contentAfterEdits, type EditSpec, evaluateSkillWrite } from "./skill-write";
import { logDecision } from "./state";
import { hasSkillMd } from "./targets";
import type { FlaggedEntry, GuardContext, GuardDecision, HookResult } from "./types";

/**
 * Claude Code hook events to hook output. Pass is always "no output": an explicit allow would
 * skip the user's own permission prompts. Any internal failure on an ordinary call is a pass.
 */

type Payload = Readonly<Record<string, unknown>>;

const SHELL_TOOLS = new Set(["Bash", "PowerShell", "Monitor"]);
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

export async function handleClaudeCodeEvent(payload: unknown, ctx: GuardContext, deps: HandlerDeps = {}): Promise<HookResult> {
  if (!isRecord(payload)) return PASS;
  try {
    switch (str(payload, "hook_event_name")) {
      case "PreToolUse":
        return await preToolUse(payload, ctx, deps);
      case "PostToolUse":
        return await postToolUse(payload, ctx, deps);
      case "SessionStart":
        return await sessionStart(ctx, deps);
      case "ConfigChange":
        return await configChange(payload, ctx, deps);
      case "UserPromptExpansion":
        return await promptExpansion(payload, ctx, deps);
      default:
        return PASS;
    }
  } catch (e) {
    return failOpen(e, ctx);
  }
}

async function preToolUse(p: Payload, ctx: GuardContext, deps: HandlerDeps): Promise<HookResult> {
  const tool = str(p, "tool_name") ?? "";
  const input = obj(p, "tool_input");
  if (SHELL_TOOLS.has(tool)) return claudePreOutput(await shellDecision(shellCommand(input), ctx, deps), input);
  if (tool === "Write")
    return claudePreOutput(await evaluateSkillWrite(str(input, "file_path") ?? "", str(input, "content"), ctx, deps), input);
  if (tool === "Edit" || tool === "MultiEdit") return claudePreOutput(await editDecision(tool, input, ctx, deps), input);
  if (tool === "Skill") return claudePreOutput(await skillUseDecision(str(input, "skill") ?? str(input, "command"), ctx, deps), input);
  return PASS;
}

async function editDecision(tool: string, input: Payload, ctx: GuardContext, deps: HandlerDeps): Promise<GuardDecision | undefined> {
  const path = str(input, "file_path");
  if (!path || !pathInSkillRoot(path, ctx, rootsFor(ctx, deps))) return undefined;
  const edits: EditSpec[] = tool === "MultiEdit" && Array.isArray(input.edits) ? input.edits.filter(isEdit) : isEdit(input) ? [input] : [];
  if (edits.length === 0) return undefined;
  const content = await contentAfterEdits(resolve(ctx.cwd, path), edits);
  return content === undefined ? undefined : evaluateSkillWrite(path, content, ctx, deps);
}

function isEdit(v: unknown): v is EditSpec {
  return isRecord(v) && typeof v.old_string === "string" && typeof v.new_string === "string";
}

/** Use-time gate: a flagged, untrusted skill is denied (block) or handled per `hooks.onWarn` (warn). */
export async function skillUseDecision(name: string | undefined, ctx: GuardContext, deps: HandlerDeps): Promise<GuardDecision | undefined> {
  if (!name) return undefined;
  const entry = await flaggedForUse(name.replace(/^\//, ""), ctx, deps);
  if (!entry) return undefined;
  const decision = useDecision(entry, ctx);
  await logDecision({ harness: ctx.harness, kind: "use", name: entry.name, action: decision.action, verdict: entry.verdict }, ctx.env);
  return decision;
}

export function useDecision(entry: FlaggedEntry, ctx: GuardContext): GuardDecision {
  const source = entry.path;
  if (entry.verdict === "block") return { action: "deny", reason: flaggedReason(entry), verdict: "block", source };
  const action = ctx.config.hooks.onWarn;
  return { action, reason: action === "ask" ? flaggedAskReason(entry) : flaggedReason(entry), verdict: "warn", source };
}

/** Deny carries nothing else; ask and allow may carry a rewritten command; a bare allow prints nothing. */
export function claudePreOutput(decision: GuardDecision | undefined, input: Payload): HookResult {
  if (!decision) return PASS;
  if (decision.action === "deny") {
    return jsonResult({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: decision.reason },
    });
  }
  const updatedInput = decision.rewrite ? { updatedInput: { ...input, command: decision.rewrite } } : {};
  if (decision.action === "ask") {
    return jsonResult({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: decision.reason,
        ...updatedInput,
      },
    });
  }
  const context = decision.reason ? { additionalContext: decision.reason } : {};
  if (!decision.rewrite && !decision.reason) return PASS;
  return jsonResult({ hookSpecificOutput: { hookEventName: "PreToolUse", ...updatedInput, ...context } });
}

async function postToolUse(p: Payload, ctx: GuardContext, deps: HandlerDeps): Promise<HookResult> {
  const tool = str(p, "tool_name") ?? "";
  const input = obj(p, "tool_input");
  const roots = rootsFor(ctx, deps);
  const relevant = SHELL_TOOLS.has(tool)
    ? commandTouchesSkills(shellCommand(input) ?? "", ctx, roots)
    : WRITE_TOOLS.has(tool) && pathInSkillRoot(str(input, "file_path") ?? str(input, "notebook_path"), ctx, roots);
  if (!relevant) return PASS;
  const r = await reconcileAfterChange(ctx, reconcileOpts(deps, roots));
  return await claudePostOutput(r, ctx);
}

async function claudePostOutput(r: ReconcileResult, ctx: GuardContext): Promise<HookResult> {
  if (r.newlyFlagged.length === 0) return { ...PASS, ...(r.timedOut ? { timedOut: true } : {}) };
  const reason = flaggedContext(r.newlyFlagged, new Set(r.quarantined), "skill-scanner flagged skills that changed during this tool call:");
  const systemMessage = flaggedSystemMessage(r.newlyFlagged, r.quarantined.length);
  await logDecision(
    { harness: ctx.harness, kind: "post", flagged: r.newlyFlagged.map((s) => s.path), quarantined: r.quarantined },
    ctx.env,
  );
  if (r.newlyFlagged.some((s) => s.verdict === "block")) return jsonResult({ decision: "block", reason, systemMessage });
  return jsonResult({ systemMessage, hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: reason } });
}

async function sessionStart(ctx: GuardContext, deps: HandlerDeps): Promise<HookResult> {
  const a = await sessionAudit(ctx, deps);
  const timed = a.timedOut ? { timedOut: true } : {};
  if (a.flagged.length === 0 && a.pending === 0) return { ...PASS, ...timed };
  const systemMessage = flaggedSystemMessage(a.flagged, a.quarantined.length, a.pending);
  if (a.flagged.length === 0) return { ...jsonResult({ systemMessage }), ...timed };
  const additionalContext = flaggedContext(
    a.flagged,
    new Set(a.quarantined),
    "skill-scanner audited the installed skills and flagged these:",
  );
  await logDecision({ harness: ctx.harness, kind: "session", flagged: a.flagged.map((s) => s.path), quarantined: a.quarantined }, ctx.env);
  const reload = a.quarantined.length > 0 ? { reloadSkills: true } : {};
  return {
    ...jsonResult({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext, ...reload }, systemMessage }),
    ...timed,
  };
}

/** A skill file was written (hot reload is about to pick it up): scan that skill now. */
async function configChange(p: Payload, ctx: GuardContext, deps: HandlerDeps): Promise<HookResult> {
  if (str(p, "source") !== "skills") return PASS;
  const roots = rootsFor(ctx, deps);
  const file = str(p, "file_path");
  if (!file) {
    const r = await reconcileAfterChange(ctx, reconcileOpts(deps, roots));
    const bad = r.newlyFlagged.filter((s) => s.verdict === "block");
    if (bad.length === 0) return PASS;
    return jsonResult({ decision: "block", reason: flaggedContext(bad, new Set(r.quarantined), "skill-scanner blocked changed skills:") });
  }
  const abs = resolve(ctx.cwd, file);
  const dir = locateSkillDir(abs, roots)?.skillDir ?? ((await hasSkillMd(abs)) ? abs : undefined);
  if (!dir || !(await hasSkillMd(dir))) return PASS;
  const realPath = await realpath(dir);
  const loc = locateSkillDir(dir, roots);
  const target = {
    harness: loc?.root?.harness ?? "claude-code",
    scope: loc?.root?.scope ?? "project",
    kind: "skill",
    name: basename(dir),
    path: dir,
    realPath,
  } as const;
  const audit = await auditInstalledDetailed(ctx, {
    targets: [target],
    deadlineMs: deps.auditDeadlineMs ?? AUDIT_DEADLINE_MS,
    ...(deps.scanPath ? { scan: deps.scanPath } : {}),
  });
  const s = audit.skills[0];
  if (!s || s.verdict === "pass" || s.trusted) return PASS;
  const quarantined = ctx.config.hooks.quarantine ? await quarantineBlocked([s], ctx, roots, "blocked when written") : [];
  const reason = flaggedContext([s], new Set(quarantined), "skill-scanner flagged a skill that was just written:");
  const systemMessage = flaggedSystemMessage([s], quarantined.length);
  await logDecision({ harness: ctx.harness, kind: "config-change", path: s.path, verdict: s.verdict, quarantined }, ctx.env);
  return s.verdict === "block" ? jsonResult({ decision: "block", reason, systemMessage }) : jsonResult({ systemMessage });
}

/** The user typed `/skill-name`: refuse a blocked skill before its load-time commands run. */
async function promptExpansion(p: Payload, ctx: GuardContext, deps: HandlerDeps): Promise<HookResult> {
  const name = (str(p, "command_name") ?? "").replace(/^\//, "");
  if (!name) return PASS;
  const entry = await flaggedForUse(name, ctx, deps);
  if (!entry) return PASS;
  await logDecision({ harness: ctx.harness, kind: "expansion", name: entry.name, verdict: entry.verdict }, ctx.env);
  if (entry.verdict === "block") return jsonResult({ decision: "block", reason: flaggedReason(entry) });
  return jsonResult({ systemMessage: `skill-scanner: /${name} has warnings: ${entry.summary[0] ?? "see skill-scanner audit"}` });
}
