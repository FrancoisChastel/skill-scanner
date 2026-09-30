import { isInside, isRecord } from "./fsutil";
import {
  commandTouchesSkills,
  failOpen,
  flaggedForUse,
  type HandlerDeps,
  jsonResult,
  obj,
  PASS,
  patchFiles,
  patchText,
  pathInSkillRoot,
  reconcileOpts,
  rootsFor,
  sessionAudit,
  shellCommand,
  shellDecision,
  str,
} from "./hook-common";
import { flaggedContext, flaggedReason, flaggedSystemMessage, guardRequiredReason } from "./messages";
import { type ReconcileResult, reconcileAfterChange } from "./reconcile";
import { commandWords, parseShell, programName } from "./shell";
import { resolvePath } from "./shellpath";
import { evaluateSkillWrites } from "./skill-write";
import { isTrusted, loadFlagged, loadTrust, logDecision } from "./state";
import type { FlaggedEntry, GuardContext, GuardDecision, HookResult } from "./types";

/**
 * Codex hook events to hook output. Codex validates hook output strictly (unknown fields make the
 * hook fail and the tool run), so every object here has exactly the documented fields. Codex has
 * no "ask": an ask becomes a deny that tells the agent to ask the user.
 */

type Payload = Readonly<Record<string, unknown>>;

const SHELL_TOOLS = new Set(["Bash", "shell", "exec_command", "local_shell", "unified_exec", "container.exec"]);
const PATCH_TOOLS = new Set(["apply_patch", "Edit", "Write"]);

export async function handleCodexEvent(payload: unknown, ctx: GuardContext, deps: HandlerDeps = {}): Promise<HookResult> {
  if (!isRecord(payload)) return PASS;
  try {
    switch (str(payload, "hook_event_name")) {
      case "PreToolUse":
        return await preToolUse(payload, ctx, deps);
      case "PostToolUse":
        return await postToolUse(payload, ctx, deps);
      case "SessionStart":
        return await sessionStart(ctx, deps);
      case "UserPromptSubmit":
        return await promptSubmit(payload, ctx, deps);
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
  if (SHELL_TOOLS.has(tool)) {
    const command = shellCommand(input);
    if (!command) return PASS;
    const reading = await flaggedPathInCommand(command, ctx);
    if (reading) return codexPreOutput({ action: "deny", reason: flaggedReason(reading) });
    return codexPreOutput(await shellDecision(command, ctx, deps));
  }
  if (PATCH_TOOLS.has(tool)) return codexPreOutput(await patchDecision(patchText(input), ctx, deps));
  return PASS;
}

export function codexPreOutput(decision: GuardDecision | undefined): HookResult {
  if (!decision) return PASS;
  // Codex cannot swap in the guarded command, so an update that needs the guard is refused with it.
  const guarded = decision.guardRequired && decision.rewrite && decision.action !== "deny" ? guardRequiredReason(decision.rewrite) : "";
  if (decision.action === "allow" && !guarded) return PASS;
  const reason =
    decision.action === "ask"
      ? `${decision.reason}\nCodex hooks cannot ask the user, so this was refused. Ask the user whether to go ahead; if they agree, they can approve it with \`skill-scanner trust\` (or run the command themselves) and ask you to retry.${guarded ? `\n${guarded}` : ""}`
      : decision.action === "allow"
        ? guarded
        : decision.reason;
  return jsonResult({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } });
}

/** Files an apply_patch adds inside skill directories are scanned together, per skill. Updates are left to the post-change audit. */
async function patchDecision(patch: string | undefined, ctx: GuardContext, deps: HandlerDeps): Promise<GuardDecision | undefined> {
  if (!patch) return undefined;
  const roots = rootsFor(ctx, deps);
  const adds = patchFiles(patch).filter((f) => f.op === "add" && f.content !== undefined && pathInSkillRoot(f.path, ctx, roots));
  if (adds.length === 0) return undefined;
  return evaluateSkillWrites(
    adds.map((f) => ({ path: f.path, content: f.content! })),
    ctx,
    { ...deps, roots },
  );
}

/** Programs that manage a skill directory rather than use it. */
const MAINTENANCE = new Set(["rm", "rmdir", "trash", "mv", "ls", "du", "stat", "skill-scanner"]);

/**
 * Codex has no Skill tool: the model reads SKILL.md and runs its scripts through the shell. A
 * command that touches files of a blocked, untrusted skill is that skill being used.
 */
async function flaggedPathInCommand(command: string, ctx: GuardContext): Promise<FlaggedEntry | undefined> {
  const flagged = (await loadFlagged(ctx.env)).filter((f) => f.verdict === "block");
  if (flagged.length === 0) return undefined;
  const parsed = parseShell(command);
  const programs = parsed.commands.map((c) => programName(commandWords(c.words)[0]));
  if (programs.length > 0 && programs.every((p) => MAINTENANCE.has(p) || p === "cd")) return undefined;
  const paths = parsed.commands
    .flatMap((c) => c.words)
    .filter((w) => w.includes("/") || w.startsWith("~"))
    .flatMap((w) => resolvePath(w, { cwd: ctx.cwd, env: ctx.env }) ?? []);
  const hit = flagged.find((f) => paths.some((p) => isInside(f.path, p) || isInside(f.realPath, p)));
  if (!hit) return undefined;
  return isTrusted(hit.digest, await loadTrust(ctx.env)) ? undefined : hit;
}

async function postToolUse(p: Payload, ctx: GuardContext, deps: HandlerDeps): Promise<HookResult> {
  const tool = str(p, "tool_name") ?? "";
  const input = obj(p, "tool_input");
  const roots = rootsFor(ctx, deps);
  const relevant = SHELL_TOOLS.has(tool)
    ? commandTouchesSkills(shellCommand(input) ?? "", ctx, roots)
    : PATCH_TOOLS.has(tool) && patchFiles(patchText(input) ?? "").some((f) => pathInSkillRoot(f.path, ctx, roots));
  if (!relevant) return PASS;
  return codexPostOutput(await reconcileAfterChange(ctx, reconcileOpts(deps, roots)), ctx);
}

async function codexPostOutput(r: ReconcileResult, ctx: GuardContext): Promise<HookResult> {
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
  return { ...jsonResult({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext }, systemMessage }), ...timed };
}

const MENTION = /(?:^|[\s(["'`])\$([A-Za-z0-9][\w.:-]*)/g;

/** `$skill-name` in a prompt invokes that skill: refuse a blocked one. */
async function promptSubmit(p: Payload, ctx: GuardContext, deps: HandlerDeps): Promise<HookResult> {
  const prompt = str(p, "prompt") ?? "";
  const names = [...new Set([...prompt.matchAll(MENTION)].map((m) => m[1]!.replace(/[.:]+$/, "")))].slice(0, 8);
  for (const name of names) {
    const entry = await flaggedForUse(name, ctx, deps);
    if (entry?.verdict !== "block") continue;
    await logDecision({ harness: ctx.harness, kind: "mention", name: entry.name, verdict: entry.verdict }, ctx.env);
    return jsonResult({ decision: "block", reason: flaggedReason(entry) });
  }
  return PASS;
}
