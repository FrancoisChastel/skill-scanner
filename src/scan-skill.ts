import { type Config, loadConfig } from "./config";
import type { ScanReport } from "./core/types";
import { scanPath } from "./scan";
import { scanOptionsFrom } from "./second-opinions";

/**
 * Scan the way the CLI and the install hooks do: the user's config (or `opts.config`), with gitleaks
 * when it is installed and the jev judge when a jev key is set. `scanPath` stays the deterministic
 * call: the rules alone unless it is given a judge, analyzers, or second opinions.
 */
export async function scanSkill(
  target: string,
  opts: { readonly config?: Config; readonly signal?: AbortSignal } = {},
): Promise<ScanReport> {
  const config = opts.config ?? (await loadConfig());
  return scanPath(target, { ...scanOptionsFrom(config), ...(opts.signal ? { signal: opts.signal } : {}) });
}
