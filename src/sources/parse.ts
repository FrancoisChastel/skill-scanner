import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { redactCredentials, SourceError } from "./errors";
import type { SourceSpec } from "./types";

/**
 * Source parsing that mirrors `npx skills add` (skills@1.7 source-parser.ts) closely enough that
 * we fetch and scan exactly what it would install, plus Pi's `npm:` and `git:` package forms.
 * Where the skills CLI is lax (unanchored github.com matches, dropped `#ref@skill` filters on
 * URLs), we copy the laxness: scanning something other than what gets installed is the bug.
 */

const DEFAULT_GITHUB_HOST = "github.com";

/** Renames the skills CLI applies before parsing. */
const SOURCE_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  "coinbase/agentWallet": "coinbase/agentic-wallet-skills",
  "vercel-labs/vercel-skills": "vercel-labs/agent-skills",
});

interface Fragment {
  readonly ref?: string;
  readonly skill?: string;
}

export function parseSource(raw: string, cwd: string, env: NodeJS.ProcessEnv = process.env): SourceSpec {
  const input = raw.trim();
  if (!input) throw new SourceError("empty source");
  if (/[\0-\x1f\x7f]/.test(input)) throw new SourceError("source contains control characters");
  if (input.startsWith("-")) throw new SourceError(`"${input}" looks like an option, not a source`);
  if (/^npm:/i.test(input)) return parseNpm(raw, input.slice(4).trim());
  if (isLocalPath(input)) {
    const path = resolveLocal(input, cwd, env);
    return { raw, kind: "local", path, display: input };
  }
  if (/^git:(?!\/\/)/i.test(input)) return parsePiGit(raw, input.slice(4).trim());
  return parseRemote(raw, input, gitHubHost(env));
}

function isLocalPath(input: string): boolean {
  return (
    isAbsolute(input) ||
    input === "." ||
    input === ".." ||
    input === "~" ||
    /^(?:\.{1,2}|~)[/\\]/.test(input) ||
    /^[a-zA-Z]:[/\\]/.test(input)
  );
}

function resolveLocal(input: string, cwd: string, env: NodeJS.ProcessEnv): string {
  if (input === "~" || /^~[/\\]/.test(input)) return resolve(env.HOME || homedir(), `.${input.slice(1)}`);
  return resolve(cwd, input);
}

/** GH_HOST selects a GitHub Enterprise host for shorthand, as in the GitHub CLI; junk falls back to github.com. */
function gitHubHost(env: NodeJS.ProcessEnv): string {
  const configured = env.GH_HOST?.trim();
  if (!configured) return DEFAULT_GITHUB_HOST;
  try {
    const u = new URL(`https://${configured}`);
    const clean = !u.username && !u.password && !u.port && u.pathname === "/" && !u.search && !u.hash;
    return clean ? u.hostname : DEFAULT_GITHUB_HOST;
  } catch {
    return DEFAULT_GITHUB_HOST;
  }
}

function isGitHubHost(host: string, ghHost: string): boolean {
  const h = host.toLowerCase();
  return h === DEFAULT_GITHUB_HOST || h === ghHost.toLowerCase();
}

// ---------------------------------------------------------------------------------------------
// npm and Pi forms

const NPM_NAME = /^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i;
const NPM_VERSION = /^[\w.^~<>=*+|-]+$/;

/** Registry specs only: git, file, URL, and alias specs make `npm pack` clone and build, which can run code. */
function parseNpm(raw: string, spec: string): SourceSpec {
  const at = spec.indexOf("@", 1);
  const name = at === -1 ? spec : spec.slice(0, at);
  const version = at === -1 ? undefined : spec.slice(at + 1);
  if (!NPM_NAME.test(name) || (version !== undefined && !NPM_VERSION.test(version))) {
    throw new SourceError(`"${raw}" is not a registry package spec (npm:<name>[@<version>]); git, file, and URL specs are not fetched`);
  }
  return { raw, kind: "npm", packageSpec: spec, display: `npm:${spec}` };
}

/** Pi's `git:` form: `git:host/owner/repo[@ref]`, `git:git@host:owner/repo[@ref]`, `git:https://host/owner/repo[@ref]`. */
function parsePiGit(raw: string, rest: string): SourceSpec {
  const bad = (why: string): never => {
    throw new SourceError(`cannot understand "${redactCredentials(raw)}": ${why}`);
  };
  const scp = /^([\w.-]+@[^:/]+):(.+)$/.exec(rest);
  let cloneBase: string;
  let host: string;
  let pathWithRef: string;
  if (scp) {
    host = scp[1]!.slice(scp[1]!.indexOf("@") + 1);
    pathWithRef = scp[2]!;
    cloneBase = `${scp[1]}:`;
  } else if (/^(?:https?|ssh|git):\/\//i.test(rest)) {
    let u: URL;
    try {
      u = new URL(rest);
    } catch {
      return bad("invalid URL");
    }
    host = u.host;
    pathWithRef = u.pathname.replace(/^\/+/, "");
    cloneBase = `${u.protocol}//${u.username ? `${u.username}${u.password ? `:${u.password}` : ""}@` : ""}${u.host}/`;
  } else {
    const slash = rest.indexOf("/");
    if (slash < 1) return bad("expected git:host/owner/repo");
    const first = rest.slice(0, slash);
    const shorthand = !first.includes(".") && first !== "localhost";
    host = shorthand ? DEFAULT_GITHUB_HOST : first;
    pathWithRef = shorthand ? rest : rest.slice(slash + 1);
    cloneBase = `https://${host}/`;
  }
  const at = pathWithRef.indexOf("@");
  const path = (at === -1 ? pathWithRef : pathWithRef.slice(0, at)).replace(/\/+$/, "");
  const ref = at === -1 ? undefined : pathWithRef.slice(at + 1);
  if (at !== -1 && !ref) bad("empty ref after @");
  const segments = path.replace(/\.git$/, "").split("/");
  if (segments.length < 2 || segments.some((s) => s === "" || s === "." || s === "..") || /[\\\0]/.test(path)) {
    bad("expected owner/repo after the host");
  }
  const cloneUrl = `${cloneBase}${path}`;
  return {
    raw,
    kind: "git",
    cloneUrl,
    ...(ref ? { ref } : {}),
    display: displayFor(host, path.replace(/\.git$/, ""), undefined, ref),
  };
}

// ---------------------------------------------------------------------------------------------
// skills CLI forms

function parseRemote(raw: string, input: string, ghHost: string): SourceSpec {
  const { base, fragment } = splitFragment(input, ghHost);
  const aliased = SOURCE_ALIASES[base] ?? base;
  return parseBase(raw, aliased, fragment, ghHost);
}

function parseBase(raw: string, input: string, frag: Fragment, ghHost: string): SourceSpec {
  // The skills CLI re-appends the fragment after a prefix only when it has a ref, so `#@skill` is lost there too.
  const prefixFrag = frag.ref ? frag : {};
  const githubPrefix = /^github:(.+)$/.exec(input);
  if (githubPrefix) return parseBase(raw, SOURCE_ALIASES[githubPrefix[1]!] ?? githubPrefix[1]!, prefixFrag, ghHost);
  const gitlabPrefix = /^gitlab:(.+)$/.exec(input);
  if (gitlabPrefix) return parseBase(raw, `https://gitlab.com/${gitlabPrefix[1]!}`, prefixFrag, ghHost);

  if (isHostedArtifactUrl(input)) return urlSource(raw, input);
  return (
    enterpriseGitHub(raw, input, frag, ghHost) ??
    gitHubUrl(raw, input, frag) ??
    gitLabUrl(raw, input, frag) ??
    azureRepos(raw, input, frag) ??
    shorthand(raw, input, frag, ghHost) ??
    wellKnownOrGit(raw, input, frag)
  );
}

/** `#ref` and `#ref@skill`, only for sources that look like git; a fragment on another URL is part of that URL. */
function splitFragment(input: string, ghHost: string): { base: string; fragment: Fragment } {
  const hash = input.indexOf("#");
  if (hash < 0) return { base: input, fragment: {} };
  const base = input.slice(0, hash);
  const fragment = input.slice(hash + 1);
  if (!fragment || !looksLikeGitSource(base, ghHost)) return { base: input, fragment: {} };
  const at = fragment.indexOf("@");
  const ref = decodeSafe(at === -1 ? fragment : fragment.slice(0, at));
  const skill = at === -1 ? "" : decodeSafe(fragment.slice(at + 1));
  return { base, fragment: { ...(ref ? { ref } : {}), ...(skill ? { skill } : {}) } };
}

function looksLikeGitSource(input: string, ghHost: string): boolean {
  if (/^(?:github:|gitlab:|git@)/.test(input)) return true;
  if (/^ssh:\/\/.+\.git(?:$|[/?])/i.test(input)) return true;
  const u = parseUrl(input);
  if (u && /^https?:$/.test(u.protocol)) {
    if (isGitHubHost(u.host, ghHost)) return /^\/[^/]+\/[^/]+(?:\.git)?(?:\/tree\/[^/]+(?:\/.*)?)?\/?$/.test(u.pathname);
    if (u.hostname === "gitlab.com") return /^\/.+?\/[^/]+(?:\.git)?(?:\/-\/tree\/[^/]+(?:\/.*)?)?\/?$/.test(u.pathname);
    const segments = u.pathname.split("/").filter(Boolean);
    const gitIndex = segments.indexOf("_git");
    if (gitIndex >= 0 && gitIndex < segments.length - 1) return true;
  }
  if (/^https?:\/\/.+\.git(?:$|[/?])/i.test(input)) return true;
  return !input.includes(":") && !input.startsWith(".") && !input.startsWith("/") && /^([^/]+)\/([^/]+)(?:\/(.+)|@(.+))?$/.test(input);
}

function isHostedArtifactUrl(input: string): boolean {
  const u = parseUrl(input);
  if (!u) return false;
  const host = u.hostname.toLowerCase();
  if (host === "raw.githubusercontent.com" || host === "codeload.github.com" || host === "objects.githubusercontent.com") return true;
  if (host === "github.com") return /^\/[^/]+\/[^/]+\/(?:archive\/|raw\/|releases\/(?:download\/|latest\/download\/))/.test(u.pathname);
  if (host === "gitlab.com") return /\/-\/(?:archive|raw)\//.test(u.pathname);
  return false;
}

function enterpriseGitHub(raw: string, input: string, frag: Fragment, ghHost: string): SourceSpec | undefined {
  if (ghHost === DEFAULT_GITHUB_HOST || !/^https?:\/\//.test(input)) return undefined;
  const u = parseUrl(input);
  if (!u || !isGitHubHost(u.host, ghHost) || u.host === DEFAULT_GITHUB_HOST) return undefined;
  const [owner, rawRepo, marker, treeRef, ...sub] = u.pathname.split("/").filter(Boolean);
  if (!owner || !rawRepo) return undefined;
  const repo = rawRepo.replace(/\.git$/, "");
  const isTree = marker === "tree" && Boolean(treeRef);
  const ref = isTree ? treeRef : frag.ref;
  const subpath = isTree && sub.length > 0 ? sanitizeSubpath(sub.join("/")) : undefined;
  return gitSpec(raw, `${u.protocol}//${u.host}/${owner}/${repo}.git`, u.host, `${owner}/${repo}`, ref, subpath);
}

function gitHubUrl(raw: string, input: string, frag: Fragment): SourceSpec | undefined {
  const withPath = /github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)\/(.+)/.exec(input);
  if (withPath) {
    const [, owner, repo, ref, sub] = withPath;
    return gitSpec(raw, `https://github.com/${owner}/${repo}.git`, "github.com", `${owner}/${repo}`, ref, sanitizeSubpath(sub!));
  }
  const tree = /github\.com\/([^/]+)\/([^/]+)\/tree\/([^/]+)$/.exec(input);
  if (tree) {
    const [, owner, repo, ref] = tree;
    return gitSpec(raw, `https://github.com/${owner}/${repo}.git`, "github.com", `${owner}/${repo}`, ref);
  }
  const repoMatch = /github\.com\/([^/]+)\/([^/]+)/.exec(input);
  if (repoMatch) {
    const owner = repoMatch[1]!;
    const repo = repoMatch[2]!.replace(/\.git$/, "");
    return gitSpec(raw, `https://github.com/${owner}/${repo}.git`, "github.com", `${owner}/${repo}`, frag.ref);
  }
  return undefined;
}

function gitLabUrl(raw: string, input: string, frag: Fragment): SourceSpec | undefined {
  const withPath = /^(https?):\/\/([^/]+)\/(.+?)\/-\/tree\/([^/]+)\/(.+)/.exec(input);
  if (withPath && withPath[2] !== "github.com") {
    const [, protocol, host, repoPath, ref, sub] = withPath;
    const path = repoPath!.replace(/\.git$/, "");
    return gitSpec(raw, `${protocol}://${host}/${path}.git`, host!, path, ref, sanitizeSubpath(sub!));
  }
  const tree = /^(https?):\/\/([^/]+)\/(.+?)\/-\/tree\/([^/]+)$/.exec(input);
  if (tree && tree[2] !== "github.com") {
    const [, protocol, host, repoPath, ref] = tree;
    const path = repoPath!.replace(/\.git$/, "");
    return gitSpec(raw, `${protocol}://${host}/${path}.git`, host!, path, ref);
  }
  const repoMatch = /gitlab\.com\/(.+?)(?:\.git)?\/?$/.exec(input);
  if (repoMatch?.[1]?.includes("/")) {
    return gitSpec(raw, `https://gitlab.com/${repoMatch[1]}.git`, "gitlab.com", repoMatch[1], frag.ref);
  }
  return undefined;
}

/** Azure Repos: `/_git/<repo>` on any host; `?path=` is the subpath and `?version=GB<branch>|GT<tag>` the ref. */
function azureRepos(raw: string, input: string, frag: Fragment): SourceSpec | undefined {
  if (!/^https?:\/\//.test(input)) return undefined;
  const u = parseUrl(input);
  if (!u) return undefined;
  const segments = u.pathname.split("/").filter(Boolean);
  const gitIndex = segments.indexOf("_git");
  if (gitIndex < 0 || gitIndex === segments.length - 1) return undefined;
  const repo = segments[gitIndex + 1]!.replace(/\.git$/, "");
  if (!repo) return undefined;
  const clonePath = [...segments.slice(0, gitIndex), "_git", repo].map((s) => encodeURIComponent(decodeSafe(s))).join("/");
  const version = /^(?:GB|GT)(.+)$/i.exec(u.searchParams.get("version") ?? "")?.[1];
  const pathParam = u.searchParams.get("path");
  const subpath = pathParam ? sanitizeSubpath(pathParam.replace(/^\/+/, "")) : undefined;
  const spec = gitSpec(raw, `${u.protocol}//${u.host}/${clonePath}`, u.host, clonePath, version || frag.ref, subpath);
  return frag.skill ? { ...spec, skills: [frag.skill] } : spec;
}

function shorthand(raw: string, input: string, frag: Fragment, ghHost: string): SourceSpec | undefined {
  if (input.includes(":") || input.startsWith(".") || input.startsWith("/")) return undefined;
  const atSkill = /^([^/]+)\/([^/@]+)@(.+)$/.exec(input);
  if (atSkill) {
    const [, owner, repo, skill] = atSkill;
    const spec = gitSpec(raw, `https://${ghHost}/${owner}/${repo}.git`, ghHost, `${owner}/${repo}`, frag.ref);
    return { ...spec, skills: [frag.skill || skill!], display: `${spec.display}@${frag.skill || skill}` };
  }
  const m = /^([^/]+)\/([^/]+)(?:\/(.+?))?\/?$/.exec(input);
  if (!m) return undefined;
  const [, owner, repo, sub] = m;
  const spec = gitSpec(
    raw,
    `https://${ghHost}/${owner}/${repo}.git`,
    ghHost,
    `${owner}/${repo}`,
    frag.ref,
    sub ? sanitizeSubpath(sub) : undefined,
  );
  return frag.skill ? { ...spec, skills: [frag.skill], display: `${spec.display}@${frag.skill}` } : spec;
}

/** Other http(s) URLs are well-known endpoints or downloads; anything else must look like a git URL. */
function wellKnownOrGit(raw: string, input: string, frag: Fragment): SourceSpec {
  const u = parseUrl(input);
  const isHttp = u !== undefined && /^https?:$/.test(u.protocol);
  const gitHosts = ["github.com", "gitlab.com", "raw.githubusercontent.com"];
  if (isHttp && !gitHosts.includes(u.hostname) && !input.endsWith(".git")) return urlSource(raw, input);
  const scp = /^[\w.-]+@([^:/]+):(.+)$/.exec(input);
  if (scp) return gitSpec(raw, input, scp[1]!, scp[2]!.replace(/\.git$/, ""), frag.ref);
  if (u && /^(?:https?|ssh|git|file):$/.test(u.protocol)) {
    if (u.protocol === "file:") return { ...gitSpec(raw, input, "file", u.pathname, frag.ref), display: redactCredentials(input) };
    const path = decodeSafe(u.pathname)
      .replace(/^\/+/, "")
      .replace(/\.git$/, "");
    return gitSpec(raw, input, u.host, path, frag.ref);
  }
  throw new SourceError(
    `cannot understand source "${redactCredentials(raw)}": use ./path for a local directory, owner/repo for GitHub, npm:<package>, or a git URL`,
  );
}

// ---------------------------------------------------------------------------------------------
// helpers

function gitSpec(raw: string, cloneUrl: string, host: string, path: string, ref?: string, subpath?: string): SourceSpec {
  return {
    raw,
    kind: "git",
    cloneUrl,
    ...(ref ? { ref } : {}),
    ...(subpath ? { subpath } : {}),
    display: displayFor(host, path, subpath, ref),
  };
}

function urlSource(raw: string, url: string): SourceSpec {
  return { raw, kind: "url", url, display: redactCredentials(url) };
}

function displayFor(host: string, path: string, subpath?: string, ref?: string): string {
  const base = host.toLowerCase() === DEFAULT_GITHUB_HOST ? path : `${host}/${path}`;
  return redactCredentials(`${base}${subpath ? `/${subpath}` : ""}${ref ? `#${ref}` : ""}`);
}

/** Subpaths come from URLs and shorthand; they must never climb out of the checkout. */
export function sanitizeSubpath(subpath: string): string | undefined {
  const normalized = subpath.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
  if (normalized.includes("\0")) throw new SourceError(`unsafe subpath "${subpath}"`);
  const segments = normalized.split("/").filter((s) => s !== "" && s !== ".");
  if (segments.includes("..")) throw new SourceError(`unsafe subpath "${subpath}": ".." is not allowed`);
  return segments.length > 0 ? segments.join("/") : undefined;
}

function parseUrl(input: string): URL | undefined {
  try {
    return new URL(input);
  } catch {
    return undefined;
  }
}

function decodeSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
