import { spawn } from "node:child_process";
import { constants } from "node:os";

const FORWARDED: readonly NodeJS.Signals[] = ["SIGINT", "SIGTERM", "SIGHUP"];

export interface InheritedRunOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly cwd: string;
}

/**
 * Run a program (no shell) with our stdio, forwarding termination signals so we outlive it long
 * enough to clean up. Resolves to its exit code, or 128 + signal number when a signal ended it.
 */
export function runInherited(command: readonly string[], opts: InheritedRunOptions): Promise<number> {
  const [file, ...args] = command;
  if (!file) return Promise.reject(new Error("no command to run"));
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { stdio: "inherit", env: opts.env, cwd: opts.cwd, windowsHide: false });
    const handlers = FORWARDED.map((sig) => {
      const forward = (): void => {
        if (child.exitCode === null && child.signalCode === null) child.kill(sig);
      };
      process.on(sig, forward);
      return () => process.off(sig, forward);
    });
    const detach = (): void => {
      for (const off of handlers) off();
    };
    child.once("error", (e: NodeJS.ErrnoException) => {
      detach();
      reject(new Error(e.code === "ENOENT" ? `cannot run ${file}: command not found` : `cannot run ${file}: ${e.message}`));
    });
    child.once("close", (code, signal) => {
      detach();
      if (code !== null) resolve(code);
      else resolve(signal ? 128 + (constants.signals[signal] ?? 0) : 1);
    });
  });
}
