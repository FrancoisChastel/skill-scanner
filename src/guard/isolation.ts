import type { TargetScanner } from "../scan";
import { isolatedScanner } from "../scan-worker";
import { scanSource } from "../sources/index";
import type { GuardDeps } from "./decide";

/**
 * Guard dependencies that scan in worker threads (see scan-worker.ts), so a scan that never yields
 * cannot hold a hook past its deadline: the deadline fires and the worker is terminated.
 */
export function isolatedGuardDeps(scan: TargetScanner = isolatedScanner()): Required<Pick<GuardDeps, "scanPath" | "scanSource">> {
  return { scanPath: scan, scanSource: (raw, opts) => scanSource(raw, { ...opts, scanner: scan }) };
}
