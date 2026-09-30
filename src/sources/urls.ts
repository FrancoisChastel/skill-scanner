/**
 * Every spelling of a clone URL that the skills CLI (https, then its SSH fallback) or Pi (https
 * without `.git`) may hand to git for one repository. Used as `url.<mirror>.insteadOf` values so
 * the delegated install clones the exact checkout we scanned.
 */
export function cloneUrlVariants(cloneUrl: string): string[] {
  const parsed = hostAndPath(cloneUrl);
  if (!parsed) return [cloneUrl];
  const { host, path } = parsed;
  const variants = [
    cloneUrl,
    `https://${host}/${path}.git`,
    `https://${host}/${path}`,
    `git@${host}:${path}.git`,
    `git@${host}:${path}`,
    `ssh://git@${host}/${path}.git`,
    `ssh://git@${host}/${path}`,
  ];
  return [...new Set(variants)];
}

/** Host and repository path (without `.git`) of an https, ssh, git, or scp-like URL. */
export function hostAndPath(cloneUrl: string): { host: string; path: string } | undefined {
  const scp = /^[\w.-]+@([^:/]+):(.+)$/.exec(cloneUrl);
  if (scp) return clean(scp[1]!, scp[2]!);
  let u: URL;
  try {
    u = new URL(cloneUrl);
  } catch {
    return undefined;
  }
  if (!/^(?:https?|ssh|git):$/.test(u.protocol) || !u.hostname) return undefined;
  // A non-default port only exists in the URL form the user gave; other spellings would point elsewhere.
  if (u.port) return undefined;
  return clean(u.hostname, u.pathname);
}

function clean(host: string, rawPath: string): { host: string; path: string } | undefined {
  const path = rawPath
    .replace(/^\/+|\/+$/g, "")
    .replace(/\.git$/, "")
    .replace(/\/+$/, "");
  return path.includes("/") ? { host: host.toLowerCase(), path } : undefined;
}
