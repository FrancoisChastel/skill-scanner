import { resolve } from "node:path";
import { type Config, ConfigError, DEFAULT_CONFIG, loadConfig } from "../../config";
import { handleClaudeCodeEvent } from "../../guard/claude-code";
import { handleCodexEvent } from "../../guard/codex";
import { isRecord } from "../../guard/fsutil";
import type { HandlerDeps } from "../../guard/hook-common";
import type { GuardContext, HookResult } from "../../guard/types";
import { runPostCheckout } from "../../sources/post-checkout";
import type { Command } from "../command";
import type { CliIO } from "../io";

/**
 * `skill-scanner hook <claude-code|codex|git-post-checkout>`: the entry point `setup` registers.
 * The event arrives as JSON on stdin. Whatever goes wrong here, an ordinary tool call must go
 * through: every unexpected path exits 0 with no output (exit 2 would block the call).
 */

const MAX_STDIN_BYTES = 1024 * 1024;
const HARNESSES = new Set(["claude-code", "codex"]);

export const hookCommand: Command = {
  name: "hook",
  summary: "Handle a harness hook event (registered by `setup`; reads the event from stdin)",
  usage: "<claude-code|codex|git-post-checkout> [args...]",
  flags: {},
  details: "Internal: harnesses run this with the event JSON on stdin. It prints hook output on stdout and never fails an ordinary call.",
  async run(argv, io) {
    try {
      return await runHook(argv, io);
    } catch {
      return 0;
    }
  },
};

export async function runHook(argv: readonly string[], io: CliIO, deps: HandlerDeps = {}): Promise<number> {
  const [target, ...rest] = argv;
  if (target === "git-post-checkout") return runPostCheckout(rest, io);
  if (!target || !HARNESSES.has(target)) {
    io.stderr(`skill-scanner hook: unknown harness "${target ?? ""}" (expected claude-code, codex, or git-post-checkout)\n`);
    return 0;
  }
  const payload = parsePayload(await io.readStdin());
  if (!payload) return 0;
  const { config, note } = await hookConfig(io.env);
  const runtime = detectRuntime();
  const ctx: GuardContext = {
    harness: target === "codex" ? "codex" : "claude-code",
    cwd: typeof payload.cwd === "string" && payload.cwd ? payload.cwd : io.cwd,
    env: io.env,
    config,
    ...(runtime ? { runtime } : {}),
  };
  const handle = ctx.harness === "codex" ? handleCodexEvent : handleClaudeCodeEvent;
  const result = await handle(payload, ctx, deps);
  emit(result, note, io);
  if (runtime) exitSoon(result.exitCode);
  return result.exitCode;
}

function parsePayload(raw: string): Record<string, unknown> | undefined {
  if (raw.length > MAX_STDIN_BYTES) return undefined;
  try {
    const v: unknown = JSON.parse(raw);
    return isRecord(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

/** A broken config must not break the harness: fall back to defaults and say so on stderr. */
async function hookConfig(env: NodeJS.ProcessEnv): Promise<{ config: Config; note?: string }> {
  try {
    return { config: await loadConfig(undefined, env) };
  } catch (e) {
    const msg = e instanceof ConfigError ? e.message : String(e);
    return { config: DEFAULT_CONFIG, note: `skill-scanner: ${msg}; using defaults\n` };
  }
}

function emit(result: HookResult, note: string | undefined, io: CliIO): void {
  if (result.stdout) io.stdout(result.stdout);
  const stderr = `${result.stderr ?? ""}${note ?? ""}`;
  if (stderr) io.stderr(stderr);
}

/** The installed runtime (or the npm bin), so decisions can rewrite commands to run under `guard`. */
function detectRuntime(): GuardContext["runtime"] | undefined {
  const script = process.argv[1];
  if (!script) return undefined;
  const abs = resolve(script);
  return /(?:^|[\\/])(?:skill-scanner\.mjs|cli\.js)$/.test(abs) ? { node: process.execPath, script: abs } : undefined;
}

/**
 * Work abandoned at a deadline (a scan still running) must not keep the process alive past the
 * harness timeout, which would discard the answer already printed. Unref'd: a clean run exits first.
 */
function exitSoon(code: number): void {
  setTimeout(() => process.exit(code), 150).unref();
}
