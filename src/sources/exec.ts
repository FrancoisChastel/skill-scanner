import { execFile } from "node:child_process";

/** Run a program without a shell, capture its output, and bound it in time. */

export interface RunOptions {
  readonly cwd?: string;
  readonly env: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

export interface RunResult {
  readonly stdout: string;
  readonly stderr: string;
}

export type ProgramFailure = "not-found" | "timeout" | "aborted" | "exit";

export class ProgramError extends Error {
  override readonly name = "ProgramError";
  constructor(
    message: string,
    readonly failure: ProgramFailure,
    readonly stderr: string,
  ) {
    super(message);
  }
}

const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

export function runProgram(file: string, args: readonly string[], opts: RunOptions): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    execFile(
      file,
      [...args],
      {
        ...(opts.cwd ? { cwd: opts.cwd } : {}),
        env: opts.env,
        timeout: opts.timeoutMs,
        killSignal: "SIGKILL",
        maxBuffer: MAX_OUTPUT_BYTES,
        encoding: "utf8",
        windowsHide: true,
        ...(opts.signal ? { signal: opts.signal } : {}),
      },
      (error, stdout, stderr) => {
        if (!error) {
          resolve({ stdout, stderr });
          return;
        }
        reject(toProgramError(file, error, stderr, opts.signal));
      },
    );
  });
}

function toProgramError(file: string, error: Error, stderr: string, signal?: AbortSignal): ProgramError {
  const e = error as NodeJS.ErrnoException & { killed?: boolean };
  if (e.code === "ENOENT") return new ProgramError(`${file} is not installed or not on PATH`, "not-found", "");
  if (signal?.aborted || e.name === "AbortError") return new ProgramError(`${file} was cancelled`, "aborted", stderr);
  if (e.killed) return new ProgramError(`${file} timed out`, "timeout", stderr);
  return new ProgramError(`${file} failed: ${lastLines(stderr) || e.message}`, "exit", stderr);
}

/** The tail of a program's error output: the part that usually says what went wrong. */
export function lastLines(text: string, count = 4): string {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(-count)
    .join("; ");
}
