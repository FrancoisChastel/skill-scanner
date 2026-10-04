import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";
import type { ScanReport } from "./core/types";
import { type ScanOptions, scanPath, type TargetScanner } from "./scan";

/**
 * Scans in a worker thread. Rules run synchronously, so a regular expression that backtracked
 * catastrophically on hostile input would hold whatever thread runs it. In a worker, the caller's
 * event loop stays free, its deadlines fire on time, and terminating the worker stops the scan
 * wherever it is. Hooks, the git hooks, and the OpenCode and Pi adapters scan this way.
 */

const JOB = "skill-scanner:scan";
/** The longest one isolated scan may run, whatever the caller's deadline, so a long-lived host never keeps a stuck worker. */
export const MAX_ISOLATED_SCAN_MS = 120_000;
/** Heap cap for a scan worker; the collection limits keep real scans far below it. */
const WORKER_HEAP_MB = 1024;
/** The CLI entry, as built for the runtime copy, the npm package, and the source tree (tests). */
const ENTRY_CANDIDATES = ["./skill-scanner.mjs", "./cli.js", "../cli.js", "./cli.ts"];

/**
 * What a worker can be given: plain data. Rules, judges, analyzers, and clocks keep a scan in-process;
 * second opinions travel as settings and are built inside the worker, under the same deadline.
 */
type PortableOptions = Pick<ScanOptions, "policy" | "limits" | "suppressions" | "onlySkills" | "label" | "secondOpinions">;

interface ScanJob {
  readonly kind: typeof JOB;
  readonly target: string;
  readonly options: PortableOptions;
}

type Reply = { readonly report: ScanReport } | { readonly error: string };

export class ScanTimeoutError extends Error {
  constructor(ms: number) {
    super(`the scan did not finish within ${Math.round(ms / 1000)} s`);
    this.name = "ScanTimeoutError";
  }
}

export interface IsolationOptions {
  /** The CLI entry to start workers from. Default: the one next to this module, if any. */
  readonly script?: string;
  /** Hard cap per scan. Default MAX_ISOLATED_SCAN_MS. */
  readonly maxMs?: number;
}

/**
 * A scanner that runs each scan in its own worker. Aborting `opts.signal` (or reaching `maxMs`)
 * terminates the worker and rejects. Without a CLI entry to start workers from, or with options a
 * worker cannot receive, it scans in-process.
 */
export function isolatedScanner(opts: IsolationOptions = {}): TargetScanner {
  const script = opts.script ?? workerScript();
  if (!script) return scanPath;
  const maxMs = opts.maxMs ?? MAX_ISOLATED_SCAN_MS;
  return (target, options) => {
    const { signal, ...rest } = options;
    if (rest.rules !== undefined || rest.judge !== undefined || rest.now !== undefined || (rest.analyzers?.length ?? 0) > 0) {
      return scanPath(target, options);
    }
    return scanInWorker(script, { kind: JOB, target: resolve(target), options: portable(rest) }, maxMs, signal);
  };
}

/** The CLI entry next to this module (or its bundle), which starts scan jobs when loaded in a worker. */
export function workerScript(from: string = import.meta.url): string | undefined {
  for (const candidate of ENTRY_CANDIDATES) {
    const path = fileURLToPath(new URL(candidate, from));
    if (existsSync(path)) return path;
  }
  return undefined;
}

/** Called first by the CLI entry: in a scan worker, run the job and return true; otherwise false. */
export function startScanWorker(): boolean {
  if (isMainThread || !isScanJob(workerData)) return false;
  void runScanJob(workerData);
  return true;
}

function isScanJob(data: unknown): data is ScanJob {
  return typeof data === "object" && data !== null && (data as { kind?: unknown }).kind === JOB;
}

async function runScanJob(job: ScanJob): Promise<void> {
  let reply: Reply;
  try {
    reply = { report: await scanPath(job.target, job.options) };
  } catch (e) {
    reply = { error: e instanceof Error ? e.message : String(e) };
  }
  parentPort?.postMessage(reply);
}

function portable(o: Omit<ScanOptions, "signal">): PortableOptions {
  return {
    ...(o.policy ? { policy: o.policy } : {}),
    ...(o.limits ? { limits: o.limits } : {}),
    ...(o.suppressions ? { suppressions: o.suppressions } : {}),
    ...(o.onlySkills ? { onlySkills: o.onlySkills } : {}),
    ...(o.label !== undefined ? { label: o.label } : {}),
    ...(o.secondOpinions ? { secondOpinions: o.secondOpinions } : {}),
  };
}

const cancelled = (signal: AbortSignal): Error => (signal.reason instanceof Error ? signal.reason : new Error("the scan was cancelled"));

function scanInWorker(script: string, job: ScanJob, maxMs: number, signal: AbortSignal | undefined): Promise<ScanReport> {
  if (signal?.aborted) return Promise.reject(cancelled(signal));
  return new Promise<ScanReport>((resolveReport, reject) => {
    // stdout is taken so nothing a scan prints can reach a hook's stdout, which harnesses parse (Bun has no such option).
    const worker = new Worker(script, { workerData: job, stdout: true, resourceLimits: { maxOldGenerationSizeMb: WORKER_HEAP_MB } });
    worker.stdout?.resume();
    let settled = false;
    const settle = (): boolean => {
      if (settled) return false;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      return true;
    };
    const fail = (e: Error): void => {
      if (!settle()) return;
      void worker.terminate();
      reject(e);
    };
    const onAbort = (): void => fail(cancelled(signal!));
    const timer = setTimeout(() => fail(new ScanTimeoutError(maxMs)), maxMs);
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.once("message", (reply: Reply) => {
      if (!settle()) return;
      void worker.terminate();
      if ("report" in reply) resolveReport(reply.report);
      else reject(new Error(reply.error));
    });
    worker.once("error", (e: unknown) => fail(e instanceof Error ? e : new Error(String(e))));
    worker.once("exit", (code) => fail(new Error(`the scan worker stopped (exit code ${code}) before it reported`)));
  });
}
