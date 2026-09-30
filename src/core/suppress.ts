import type { Finding } from "./types";

/** A user's decision to ignore a rule, optionally for some paths or one exact skill version. */
export interface Suppression {
  /** Rule id, or a `category/*` wildcard. */
  readonly rule: string;
  /** Glob over finding paths (`*`, `**`, `?`). Omitted means every path. */
  readonly path?: string;
  /** Only for this bundle digest (`sha256:...`), so a changed skill is re-flagged. */
  readonly digest?: string;
  readonly reason?: string;
}

export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += glob[i + 2] === "/" ? "(?:.*/)?" : ".*";
        i += glob[i + 2] === "/" ? 2 : 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function matchesRule(pattern: string, ruleId: string): boolean {
  return pattern === ruleId || pattern === "*" || (pattern.endsWith("/*") && ruleId.startsWith(pattern.slice(0, -1)));
}

export function isSuppressed(f: Finding, digest: string, list: readonly Suppression[]): Suppression | undefined {
  return list.find(
    (s) => matchesRule(s.rule, f.ruleId) && (!s.path || globToRegExp(s.path).test(f.location.file)) && (!s.digest || s.digest === digest),
  );
}
