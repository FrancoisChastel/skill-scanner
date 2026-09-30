/**
 * Pi extension (verified against Pi 0.83.0 and 0.87.1): pre-scans installs the agent or the user
 * runs, keeps flagged skills out of the system prompt and out of `read`, and warns when a change
 * lands a flagged skill. Pi has no install event: `pi install` runs npm without --ignore-scripts,
 * so the bash `tool_call` and `user_bash` paths are where installs are seen.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { constants as osConstants } from "node:os";
import type {
  BashOperations,
  BeforeAgentStartEvent,
  BeforeAgentStartEventResult,
  ExtensionAPI,
  ExtensionContext,
  InputEvent,
  InputEventResult,
  ToolCallEvent,
  ToolCallEventResult,
  ToolResultEvent,
  ToolResultEventResult,
  UserBashEvent,
  UserBashEventResult,
} from "@earendil-works/pi-coding-agent";
import {
  announceAudit,
  askInstallMessage,
  askWriteMessage,
  auditSummary,
  blockedSkillMessage,
  type DepsOverrides,
  type Gate,
  GuardSession,
  isRecord,
  matchFlaggedPath,
  type NoticeLevel,
  type Notify,
  resolveDeps,
  type Settled,
  safely,
  stripSkillListing,
} from "./shared";

/** `/skill-scan` is asked for explicitly, so it may take longer than the startup audit. */
const COMMAND_AUDIT_MS = 120_000;
const CONTINUE: InputEventResult = Object.freeze({ action: "continue" });

export function createPiExtension(overrides: DepsOverrides = {}): (pi: ExtensionAPI) => void {
  return (pi) => {
    const deps = resolveDeps(overrides);
    // The latest context, for notices that land after the event that started them.
    let current: ExtensionContext | undefined;
    const notify: Notify = (message, level) => notifyPi(current, message, level);
    const session = new GuardSession("pi", deps, notify);
    const onError = (e: unknown) => session.internalError(e);
    let auditedCwd: string | undefined;
    const seen = (ctx: ExtensionContext): void => {
      current = ctx;
    };

    pi.on("session_start", (_event, ctx) => {
      seen(ctx);
      if (auditedCwd === ctx.cwd) return;
      auditedCwd = ctx.cwd;
      // In the background: startup must not wait for a scan of every skill.
      void announceAudit(session, ctx.cwd, notify);
    });
    pi.on("before_agent_start", (event) => safely(() => hideFlaggedSkills(session, event), onError));
    pi.on("tool_call", (event, ctx) => {
      seen(ctx);
      return safely(() => onToolCall(session, event, ctx), onError);
    });
    pi.on("tool_result", (event, ctx) => {
      seen(ctx);
      return safely(() => onToolResult(session, event, ctx, notify), onError);
    });
    pi.on("user_bash", (event, ctx) => {
      seen(ctx);
      return safely(() => onUserBash(session, event, ctx, notify), onError);
    });
    pi.on("input", async (event, ctx) => {
      seen(ctx);
      return (await safely(() => onInput(session, event, ctx), onError)) ?? CONTINUE;
    });
    pi.registerCommand("skill-scan", {
      description: "skill-scanner: rescan installed skills and list the flagged ones",
      handler: async (_args, ctx) => {
        seen(ctx);
        notify("skill-scanner: scanning installed skills...", "info");
        const outcome = await session.audit(ctx.cwd, COMMAND_AUDIT_MS);
        notify(auditSummary(outcome), outcome.flagged.length > 0 ? "warning" : "info");
      },
    });
  };
}

/** Pi's extension entry point. */
export default function skillScanner(pi: ExtensionAPI): void {
  createPiExtension()(pi);
}

function notifyPi(ctx: ExtensionContext | undefined, message: string, level: NoticeLevel): void {
  try {
    if (ctx?.hasUI) ctx.ui.notify(message, level);
    else process.stderr.write(`${message}\n`);
  } catch {
    // A context from a replaced session; the message has nowhere left to go.
  }
}

const block = (reason: string): ToolCallEventResult => ({ block: true, reason });

async function onToolCall(session: GuardSession, event: ToolCallEvent, ctx: ExtensionContext): Promise<ToolCallEventResult | undefined> {
  const input: Record<string, unknown> = event.input;
  if (event.toolName === "bash") return onBashTool(session, input, ctx);
  // Pi has no skill tool: the model loads a skill by reading its SKILL.md.
  if (event.toolName === "read" && typeof input.path === "string") {
    const flagged = await session.flaggedAt(toolPath(input.path), ctx.cwd);
    return flagged ? block(blockedSkillMessage(flagged)) : undefined;
  }
  if (event.toolName === "write" && typeof input.path === "string" && typeof input.content === "string") {
    const gate = await session.checkWrite(toolPath(input.path), input.content, ctx.cwd);
    const settled = await settle(session, gate, ctx, {
      title: "skill-scanner: allow this write into a skill directory?",
      detail: `File: ${input.path}`,
      headless: (reason) => askWriteMessage(reason),
    });
    return settled.action === "deny" ? block(settled.reason) : undefined;
  }
  return undefined;
}

async function onBashTool(
  session: GuardSession,
  input: Record<string, unknown>,
  ctx: ExtensionContext,
): Promise<ToolCallEventResult | undefined> {
  const command = input.command;
  if (typeof command !== "string") return undefined;
  // Pi 0.87 tells the model to load skills with bash when `read` is disabled.
  const flagged = await session.flaggedIn(command, ctx.cwd);
  if (flagged) return block(blockedSkillMessage(flagged));
  const settled = await settle(session, await session.checkCommand(command, ctx.cwd), ctx, installPrompt(command));
  if (settled.action === "deny") return block(settled.reason);
  // Pi runs `event.input` after the handlers return; editing it in place is its documented rewrite contract.
  if (settled.rewrite) input.command = settled.rewrite;
  return undefined;
}

async function onToolResult(
  session: GuardSession,
  event: ToolResultEvent,
  ctx: ExtensionContext,
  notify: Notify,
): Promise<ToolResultEventResult | undefined> {
  const input = event.input;
  const changed =
    event.toolName === "bash"
      ? typeof input.command === "string" && session.shouldReconcile(input.command, ctx.cwd)
      : (event.toolName === "write" || event.toolName === "edit") &&
        typeof input.path === "string" &&
        session.inSkillRoot(toolPath(input.path), ctx.cwd);
  if (!changed) return undefined;
  const notice = await session.afterChange(ctx.cwd);
  if (!notice) return undefined;
  notify(notice, "warning");
  return { content: [...event.content, { type: "text", text: notice }] };
}

/** `!cmd` typed by the user skips `tool_call`. Pi runs the typed text, so a rewrite needs our own shell operations. */
async function onUserBash(
  session: GuardSession,
  event: UserBashEvent,
  ctx: ExtensionContext,
  notify: Notify,
): Promise<UserBashEventResult | undefined> {
  const cwd = event.cwd || ctx.cwd;
  const settled = await settle(session, await session.checkCommand(event.command, cwd), ctx, installPrompt(event.command));
  if (settled.action === "deny") return { result: { output: `${settled.reason}\n`, exitCode: 1, cancelled: false, truncated: false } };
  if (!settled.rewrite && !session.shouldReconcile(event.command, cwd)) return undefined;
  const operations = shellOperations(settled.rewrite ?? event.command, async () => {
    const notice = await session.afterChange(cwd);
    if (notice) notify(notice, "warning");
  });
  return operations ? { operations } : undefined;
}

/** Fired before `/skill:name` is expanded (Pi re-reads the SKILL.md on every use). */
async function onInput(session: GuardSession, event: InputEvent, ctx: ExtensionContext): Promise<InputEventResult | undefined> {
  const name = /^\/skill:(\S+)/.exec(event.text.trimStart())?.[1];
  if (!name) return undefined;
  const flagged = await session.flaggedNamed(name, ctx.cwd);
  if (!flagged) return undefined;
  notifyPi(ctx, blockedSkillMessage(flagged), "warning");
  return { action: "handled" };
}

/**
 * Keep flagged skills out of the prompt's skill listing. Pi 0.87 renders `systemPrompt` from a
 * per-turn copy of `systemPromptOptions` (a getter), so filtering its `skills` keeps the prompt's
 * structured sections; Pi 0.83 hands over a finished string, which is edited and returned instead.
 */
async function hideFlaggedSkills(session: GuardSession, event: BeforeAgentStartEvent): Promise<BeforeAgentStartEventResult | undefined> {
  const flagged = await session.flagged();
  if (flagged.length === 0) return undefined;
  const isFlagged = (path: string) => matchFlaggedPath(path, flagged) !== undefined;
  const options: unknown = event.systemPromptOptions;
  if (rendersFromOptions(event) && isRecord(options) && Array.isArray(options.skills)) {
    const kept = options.skills.filter((s: unknown) => !(isRecord(s) && typeof s.filePath === "string" && isFlagged(s.filePath)));
    // Mutating the per-turn options is Pi's contract for this event ("Mutable prompt sections").
    if (kept.length !== options.skills.length) options.skills = kept;
  }
  const prompt = event.systemPrompt;
  if (typeof prompt !== "string") return undefined;
  const stripped = stripSkillListing(prompt, isFlagged);
  return stripped === prompt ? undefined : { systemPrompt: stripped };
}

function rendersFromOptions(event: object): boolean {
  return typeof Object.getOwnPropertyDescriptor(event, "systemPrompt")?.get === "function";
}

interface AskPrompt {
  readonly title: string;
  readonly detail: string;
  /** What the agent is told when there is no UI to ask with. */
  readonly headless: (reason: string, source: string | undefined) => string;
}

function installPrompt(command: string): AskPrompt {
  return { title: "skill-scanner: run this install?", detail: `Command: ${command}`, headless: askInstallMessage };
}

/** Turn "ask" into allow or deny: a dialog when Pi has UI, else the onWarn policy ("ask" without UI blocks). */
async function settle(session: GuardSession, gate: Gate, ctx: ExtensionContext, prompt: AskPrompt): Promise<Settled> {
  if (gate.action !== "ask") return gate;
  const allow: Settled = gate.rewrite ? { action: "allow", rewrite: gate.rewrite } : { action: "allow" };
  if (!ctx.hasUI) {
    const { onWarn } = (await session.config()).hooks;
    return onWarn === "allow" ? allow : { action: "deny", reason: prompt.headless(gate.reason, gate.source) };
  }
  const approved = await confirm(ctx, prompt.title, `${gate.reason}\n\n${prompt.detail}`);
  return approved ? allow : { action: "deny", reason: `${gate.reason}\nThe user reviewed this and declined it.` };
}

async function confirm(ctx: ExtensionContext, title: string, message: string): Promise<boolean> {
  try {
    return (await ctx.ui.confirm(title, message)) === true;
  } catch {
    return false;
  }
}

/** Pi's read tool accepts `@path` and `~/path`. */
function toolPath(path: string): string {
  return path.startsWith("@") ? path.slice(1) : path;
}

/** Runs `command` in place of what the user typed, then `after` (a rescan) without holding up the result. */
function shellOperations(command: string, after: () => Promise<void>): BashOperations | undefined {
  if (process.platform === "win32") return undefined;
  const shell = existsSync("/bin/bash") ? "/bin/bash" : "/bin/sh";
  return {
    exec: (_typed, cwd, options) =>
      runShell(shell, command, cwd, options).finally(() => {
        after().catch(() => undefined);
      }),
  };
}

type ExecOptions = Parameters<BashOperations["exec"]>[2];

function runShell(shell: string, command: string, cwd: string, options: ExecOptions): Promise<{ exitCode: number | null }> {
  return new Promise((done, fail) => {
    if (options.signal?.aborted) return fail(new Error("aborted"));
    const child = spawn(shell, ["-c", command], { cwd, env: options.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
    const stop = (): void => {
      child.kill("SIGTERM");
    };
    const timer = options.timeout !== undefined && options.timeout > 0 ? setTimeout(stop, options.timeout * 1000) : undefined;
    options.signal?.addEventListener("abort", stop, { once: true });
    const cleanup = (): void => {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", stop);
    };
    child.stdout?.on("data", options.onData);
    child.stderr?.on("data", options.onData);
    child.on("error", (e) => {
      cleanup();
      fail(e);
    });
    child.on("close", (code, signal) => {
      cleanup();
      if (options.signal?.aborted) return fail(new Error("aborted"));
      done({ exitCode: code ?? (signal ? 128 + (osConstants.signals[signal] ?? 0) : 1) });
    });
  });
}
