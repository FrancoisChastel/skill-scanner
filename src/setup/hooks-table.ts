/**
 * The hooks skill-scanner registers, per harness. Single source of truth for `setup` and for the
 * plugin templates in `plugins/`, which a test regenerates and compares against this table.
 */

export type HookHarness = "claude-code" | "codex";

export interface HookSpec {
  readonly event: string;
  /** Omitted for events that match everything (or ignore matchers). */
  readonly matcher?: string;
  /** Seconds. The hook keeps its own shorter deadline, because a timed-out PreToolUse hook lets the call through. */
  readonly timeout: number;
  readonly statusMessage?: string;
}

export const CLAUDE_CODE_HOOKS: readonly HookSpec[] = [
  { event: "PreToolUse", matcher: "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Skill", timeout: 120 },
  { event: "PostToolUse", matcher: "Bash|PowerShell|Write|Edit|MultiEdit", timeout: 120 },
  { event: "SessionStart", matcher: "startup|resume|clear|compact", timeout: 60 },
  { event: "ConfigChange", matcher: "skills", timeout: 60 },
  { event: "UserPromptExpansion", timeout: 15 },
];

const CODEX_TOOLS = "^(Bash|shell|exec_command|apply_patch)$";

export const CODEX_HOOKS: readonly HookSpec[] = [
  { event: "SessionStart", matcher: "startup|resume|clear", timeout: 60, statusMessage: "skill-scanner: checking skills" },
  { event: "PreToolUse", matcher: CODEX_TOOLS, timeout: 120 },
  { event: "PostToolUse", matcher: CODEX_TOOLS, timeout: 120 },
  { event: "UserPromptSubmit", timeout: 15 },
];

export const HOOK_TABLES: Readonly<Record<HookHarness, readonly HookSpec[]>> = {
  "claude-code": CLAUDE_CODE_HOOKS,
  codex: CODEX_HOOKS,
};

export type JsonObject = Record<string, unknown>;

/** One matcher group with a single command handler. Codex rejects unknown handler fields, so only these are emitted. */
export function hookGroup(spec: HookSpec, command: string): JsonObject {
  const handler: JsonObject = {
    type: "command",
    command,
    timeout: spec.timeout,
    ...(spec.statusMessage ? { statusMessage: spec.statusMessage } : {}),
  };
  return { ...(spec.matcher !== undefined ? { matcher: spec.matcher } : {}), hooks: [handler] };
}

/** The `{ hooks: { Event: [group] } }` object for a whole table, with one group per event. */
export function hooksObject(table: readonly HookSpec[], command: string): JsonObject {
  return Object.fromEntries(table.map((spec) => [spec.event, [hookGroup(spec, command)]]));
}

/** The command `setup` writes: absolute Node and runtime paths, quoted, so hooks never depend on PATH or npx. */
export function runtimeHookCommand(node: string, script: string, harness: HookHarness): string {
  for (const p of [node, script]) {
    // Harnesses run hook commands through a POSIX shell (Git Bash on Windows), where `"`, `$`, and backticks
    // would be interpreted inside double quotes. Backslashes are accepted only as Windows separators.
    if (/["$`\n\r]/.test(p) || (p.includes("\\") && !/^[A-Za-z]:\\/.test(p)))
      throw new Error(`cannot register hooks: ${p} contains a character that would need shell escaping`);
  }
  return `"${node}" "${script}" hook ${harness}`;
}

/** Whether a hook handler is one `setup` wrote for this harness (any Node, any home). */
export function isOurHandler(handler: unknown, harness: HookHarness): boolean {
  if (typeof handler !== "object" || handler === null) return false;
  const command = (handler as { command?: unknown }).command;
  return typeof command === "string" && ourCommandPattern(harness).test(command);
}

const ourCommandPattern = (harness: HookHarness): RegExp => new RegExp(`skill-scanner\\.mjs"\\s+hook\\s+${harness}(?:\\s|$)`);

/** Command used by the plugin templates, which cannot carry the build: it needs a global install. */
export const pluginHookCommand = (harness: HookHarness): string => `skill-scanner hook ${harness}`;

export const PLUGIN_HOOKS_DESCRIPTION: Readonly<Record<HookHarness, string>> = {
  "claude-code":
    "skill-scanner: scan skills before Claude Code installs or runs them. Needs `npm install -g @french-castle/skill-scanner`.",
  codex: "skill-scanner: scan skills before Codex installs or runs them. Needs `npm install -g @french-castle/skill-scanner`.",
};

/** Contents of plugins/claude-code/hooks/hooks.json and plugins/codex/hooks.json. */
export function pluginHooksFile(harness: HookHarness): string {
  const file = {
    description: PLUGIN_HOOKS_DESCRIPTION[harness],
    hooks: hooksObject(HOOK_TABLES[harness], pluginHookCommand(harness)),
  };
  return `${JSON.stringify(file, null, 2)}\n`;
}
