import { type ChildProcess, spawn } from "node:child_process";
import { constants } from "node:fs";
import { access, stat } from "node:fs/promises";
import { delimiter, extname, isAbsolute, join } from "node:path";

/**
 * Locating and running external tools. Tools are always spawned directly, never through a shell,
 * so nothing from a scanned skill can be interpreted as shell syntax.
 */

export const DEFAULT_TIMEOUT_MS = 120_000;
export const DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024;
/** How long to wait for stdio to close after the tool exits, in case a grandchild holds the pipes. */
const EXIT_GRACE_MS = 2_000;
const IS_WINDOWS = process.platform === "win32";
/** Batch files cannot be spawned without a shell, so they are never candidates. */
const SHELL_ONLY_EXTENSIONS = new Set([".bat", ".cmd"]);

export interface RunOptions {
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly timeoutMs?: number;
  /** Cap for each of stdout and stderr. The tool is killed when either overflows. */
  readonly maxOutputBytes?: number;
  readonly signal?: AbortSignal;
}

export interface ToolResult {
  /** Exit code, or null when the process was killed. */
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly truncated: boolean;
}

function envValue(env: NodeJS.ProcessEnv, key: string): string | undefined {
  if (!IS_WINDOWS) return env[key];
  // Windows environment names are case-insensitive, but a copied env object is not.
  const found = Object.keys(env).find((k) => k.toUpperCase() === key.toUpperCase());
  return found === undefined ? undefined : env[found];
}

function candidateNames(binary: string, env: NodeJS.ProcessEnv): readonly string[] {
  if (!IS_WINDOWS || extname(binary) !== "") return [binary];
  const exts = (envValue(env, "PATHEXT") ?? ".COM;.EXE")
    .split(";")
    .map((e) => e.trim().toLowerCase())
    .filter((e) => e.startsWith(".") && !SHELL_ONLY_EXTENSIONS.has(e));
  return exts.map((e) => `${binary}${e}`);
}

async function isExecutableFile(path: string): Promise<boolean> {
  try {
    if (!(await stat(path)).isFile()) return false;
    if (IS_WINDOWS) return true;
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** The directories of PATH, in order, without empty or relative entries (which would resolve against the cwd). */
export function pathDirs(env: NodeJS.ProcessEnv): readonly string[] {
  return (envValue(env, "PATH") ?? "")
    .split(delimiter)
    .map((d) => d.trim().replace(/^"(.*)"$/, "$1"))
    .filter((d) => d !== "" && isAbsolute(d));
}

/** The executable called `binary` in one directory, if any. */
export async function executableIn(dir: string, binary: string, env: NodeJS.ProcessEnv): Promise<string | undefined> {
  for (const name of candidateNames(binary, env)) {
    const full = join(dir, name);
    if (await isExecutableFile(full)) return full;
  }
  return undefined;
}

/** Every executable called `binary` on PATH, in PATH order, without duplicates. */
export async function whichAll(binary: string, env: NodeJS.ProcessEnv): Promise<string[]> {
  const found: string[] = [];
  for (const dir of pathDirs(env)) {
    const hit = await executableIn(dir, binary, env);
    if (hit && !found.includes(hit)) found.push(hit);
  }
  return found;
}

/** The first executable called `binary` on PATH, like `command -v`. */
export async function which(binary: string, env: NodeJS.ProcessEnv): Promise<string | undefined> {
  for (const dir of pathDirs(env)) {
    const hit = await executableIn(dir, binary, env);
    if (hit) return hit;
  }
  return undefined;
}

interface Collector {
  /** Appends up to the limit; false once the limit is reached. */
  push(chunk: Buffer): boolean;
  text(): string;
}

function collector(limit: number): Collector {
  const chunks: Buffer[] = [];
  let size = 0;
  return {
    push(chunk) {
      const room = limit - size;
      if (chunk.length <= room) {
        chunks.push(chunk);
        size += chunk.length;
        return true;
      }
      if (room > 0) chunks.push(chunk.subarray(0, room));
      size = limit;
      return false;
    },
    text: () => Buffer.concat(chunks).toString("utf8"),
  };
}

/** Kill the tool and, on POSIX, every process it started (it leads its own process group). */
function killTree(child: ChildProcess): void {
  if (child.pid === undefined) return;
  if (!IS_WINDOWS) {
    try {
      process.kill(-child.pid, "SIGKILL");
      return;
    } catch {
      // The group is already gone, or was never created; fall back to the direct child.
    }
  }
  child.kill("SIGKILL");
}

// Children lead their own process group, so terminal signals do not reach them. Kill any that are
// still running when this process exits; callers should also abort the scan signal on SIGINT.
const live = new Set<ChildProcess>();
let exitHooked = false;
function track(child: ChildProcess): void {
  live.add(child);
  if (exitHooked) return;
  exitHooked = true;
  process.once("exit", () => {
    for (const c of live) killTree(c);
  });
}

/**
 * Run `bin` with `args`, without a shell. Resolves with the exit status and bounded output, also on
 * timeout (`timedOut`) or overflow (`truncated`). Rejects when the tool cannot be started or the
 * signal aborts the run.
 */
export function runTool(bin: string, args: readonly string[], opts: RunOptions = {}): Promise<ToolResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const limit = opts.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const { signal } = opts;
  return new Promise<ToolResult>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error(`${bin}: aborted before start`));
      return;
    }
    const child = spawn(bin, [...args], {
      ...(opts.cwd ? { cwd: opts.cwd } : {}),
      env: opts.env ?? process.env,
      shell: false,
      windowsHide: true,
      detached: !IS_WINDOWS,
      stdio: ["ignore", "pipe", "pipe"],
    });
    track(child);
    const out = collector(limit);
    const err = collector(limit);
    let timedOut = false;
    let truncated = false;
    let aborted = false;
    let settled = false;
    let grace: ReturnType<typeof setTimeout> | undefined;

    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child);
    }, timeoutMs);
    const onAbort = (): void => {
      aborted = true;
      killTree(child);
    };
    signal?.addEventListener("abort", onAbort, { once: true });

    const settle = (): boolean => {
      if (settled) return false;
      settled = true;
      clearTimeout(timer);
      if (grace) clearTimeout(grace);
      signal?.removeEventListener("abort", onAbort);
      live.delete(child);
      return true;
    };
    const finish = (code: number | null): void => {
      if (!settle()) return;
      if (aborted) reject(new Error(`${bin}: aborted`));
      else resolve({ code, stdout: out.text(), stderr: err.text(), timedOut, truncated });
    };
    const onData =
      (c: Collector) =>
      (chunk: Buffer): void => {
        if (c.push(chunk) || truncated) return;
        truncated = true;
        killTree(child);
      };

    child.stdout?.on("data", onData(out));
    child.stderr?.on("data", onData(err));
    child.on("error", (e) => {
      if (settle()) reject(new Error(`cannot run ${bin}: ${e.message}`));
    });
    child.on("close", (code) => finish(code));
    child.on("exit", (code) => {
      grace = setTimeout(() => {
        killTree(child);
        finish(code);
      }, EXIT_GRACE_MS);
    });
  });
}
