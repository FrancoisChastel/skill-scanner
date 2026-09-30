import { join } from "node:path";
import { scannerHome } from "./config";

/** Where skill-scanner keeps its own state. Everything lives under one directory so uninstall is `rm -rf`. */
export interface ScannerPaths {
  readonly home: string;
  readonly config: string;
  /** Scan results by bundle digest, so unchanged skills are not rescanned. */
  readonly cache: string;
  /** Skills moved aside because they scanned as `block`. */
  readonly quarantine: string;
  /** Skills the user reviewed and approved despite findings, by digest. */
  readonly trust: string;
  /** Skills currently flagged, for use-time gates in hooks and plugins. */
  readonly flagged: string;
  /** The pinned runtime copied by `setup`, which harness hooks execute. */
  readonly bin: string;
  /** Append-only log of hook decisions. */
  readonly log: string;
  /** Git hooks used by `guard` to scan every checkout. */
  readonly gitHooks: string;
}

export function scannerPaths(env: NodeJS.ProcessEnv = process.env): ScannerPaths {
  const home = scannerHome(env);
  return {
    home,
    config: env.SKILL_SCANNER_CONFIG || join(home, "config.json"),
    cache: join(home, "cache"),
    quarantine: join(home, "quarantine"),
    trust: join(home, "trust.json"),
    flagged: join(home, "flagged.json"),
    bin: join(home, "bin"),
    log: join(home, "decisions.jsonl"),
    gitHooks: join(home, "git-hooks"),
  };
}
