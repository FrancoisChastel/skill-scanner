import { readFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { mirrorUrl } from "../sources/guard-env";
import { isInside, isRecord, readJsonFile } from "./fsutil";
import { harnessDirs } from "./locations";

/**
 * What `codex plugin add <plugin>@<marketplace>` would install, found the way Codex 0.159 finds it
 * (core-plugins marketplace.rs, installed_marketplaces.rs, manager.rs):
 *
 * - The marketplace root: `[marketplaces.<name>]` in `$CODEX_HOME/config.toml` with
 *   `source_type = "local"` names a directory used in place; any other configured marketplace is
 *   the snapshot in `$CODEX_HOME/.tmp/marketplaces/<name>`. `~/.agents/plugins/marketplace.json`
 *   and the curated snapshot in `$CODEX_HOME/.tmp/plugins` are matched by their manifest name.
 * - The manifest: the first of `.agents/plugins/marketplace.json`, `.agents/plugins/api_marketplace.json`,
 *   `.claude-plugin/marketplace.json`, `.cursor-plugin/marketplace.json`; the first entry named
 *   `<plugin>` wins.
 * - The entry's source: a local `./path` inside the root (copied from there, so scanned in place),
 *   a git `url` (optionally `path`, `ref`, `sha`), or an `npm` package; both are cloned or packed
 *   fresh at install time, so the same source is fetched and scanned first. A git repository on
 *   disk is cloned too, since Codex installs its committed files, not its working tree.
 *
 * Anything else (the remote catalogue, custom npm registries) is not resolved and is left to the
 * session-start audit of Codex's plugin cache.
 */

export type CodexPluginSource =
  | { readonly kind: "dir"; readonly path: string }
  /** A source string the fetcher takes: `owner/repo/path#ref`, `<git url>#ref`, `npm:pkg@version`. */
  | { readonly kind: "fetch"; readonly source: string };

const MANIFESTS = [
  ".agents/plugins/marketplace.json",
  ".agents/plugins/api_marketplace.json",
  ".claude-plugin/marketplace.json",
  ".cursor-plugin/marketplace.json",
];
const NAME = /^[\w.@+-]+$/;

export async function codexPluginSource(
  target: string,
  marketplaceFlag: string | undefined,
  env: NodeJS.ProcessEnv,
): Promise<CodexPluginSource | undefined> {
  const at = target.lastIndexOf("@");
  const plugin = at > 0 ? target.slice(0, at) : target;
  const market = at > 0 ? target.slice(at + 1) : marketplaceFlag;
  if (!market || !NAME.test(market) || !NAME.test(plugin) || market === "..") return undefined;
  const dirs = harnessDirs(env);
  const configured = await configuredMarketplace(join(dirs.codex, "config.toml"), market);
  const candidates: { root: string; byName: boolean }[] = [
    {
      root: configured?.sourceType === "local" && configured.source ? configured.source : join(dirs.codex, ".tmp", "marketplaces", market),
      byName: false,
    },
    { root: dirs.home, byName: true },
    { root: join(dirs.codex, ".tmp", "plugins"), byName: true },
  ];
  for (const c of candidates) {
    const manifest = await firstManifest(c.root);
    if (!manifest || (c.byName && manifest.name !== market)) continue;
    const entry = (Array.isArray(manifest.plugins) ? manifest.plugins : []).find((p) => isRecord(p) && p.name === plugin);
    if (isRecord(entry)) return sourceOf(entry.source, c.root);
  }
  return undefined;
}

async function firstManifest(root: string): Promise<Record<string, unknown> | undefined> {
  for (const rel of MANIFESTS) {
    const m = await readJsonFile(join(root, rel), (raw) => (isRecord(raw) ? raw : undefined));
    if (m) return m;
  }
  return undefined;
}

function sourceOf(source: unknown, root: string): CodexPluginSource | undefined {
  if (typeof source === "string") return localSource(source, root);
  if (!isRecord(source)) return undefined;
  const str = (k: string): string | undefined => (typeof source[k] === "string" && source[k] !== "" ? (source[k] as string) : undefined);
  switch (str("source")) {
    case "local":
      return localSource(str("path") ?? "", root);
    case "url":
    case "git-subdir":
      return gitSource(str("url"), str("path"), str("sha") ?? str("ref"), root);
    case "npm": {
      const pkg = str("package");
      if (!pkg || str("registry")) return undefined;
      const version = str("version");
      return { kind: "fetch", source: `npm:${pkg}${version ? `@${version}` : ""}` };
    }
    default:
      return undefined;
  }
}

function localSource(path: string, root: string): CodexPluginSource | undefined {
  if (!path.startsWith("./")) return undefined;
  const dir = resolve(root, path);
  return isInside(root, dir) ? { kind: "dir", path: dir } : undefined;
}

const GITHUB = /^(?:https:\/\/github\.com\/|git@github\.com:)([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/;

function gitSource(
  url: string | undefined,
  path: string | undefined,
  ref: string | undefined,
  root: string,
): CodexPluginSource | undefined {
  if (!url) return undefined;
  const sub = path?.replace(/^\.?\/+|\/+$/g, "");
  const fragment = ref ? `#${ref}` : "";
  // A repository on disk: Codex clones its committed HEAD, not its working tree, so clone it the
  // same way (all of it: a superset of the plugin directory). file:// sources take no ref here.
  if (url.startsWith("./") || isAbsolute(url)) return ref ? undefined : { kind: "fetch", source: mirrorUrl(resolve(root, url)) };
  const gh = GITHUB.exec(url) ?? /^([\w.-]+)\/([\w.-]+)$/.exec(url);
  if (gh) return { kind: "fetch", source: `${gh[1]}/${gh[2]}${sub ? `/${sub}` : ""}${fragment}` };
  // Other hosts: the whole repository at that ref, a superset of the plugin directory.
  return { kind: "fetch", source: `${url}${fragment}` };
}

interface MarketplaceConfig {
  readonly sourceType?: string;
  readonly source?: string;
}

/** `[marketplaces.<name>]` from Codex's config.toml: only the two string keys we need. */
export async function configuredMarketplace(file: string, name: string): Promise<MarketplaceConfig | undefined> {
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch {
    return undefined;
  }
  let inTable = false;
  const out: { sourceType?: string; source?: string } = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (header) {
      const parts = header[1]!.split(".").map((p) => p.trim().replace(/^"(.*)"$|^'(.*)'$/, "$1$2"));
      inTable = parts.length === 2 && parts[0] === "marketplaces" && parts[1] === name;
      continue;
    }
    if (!inTable) continue;
    const kv = /^([\w-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)')/.exec(line);
    if (!kv) continue;
    const value = kv[2] !== undefined ? unescapeBasic(kv[2]) : kv[3]!;
    if (kv[1] === "source_type") out.sourceType = value;
    else if (kv[1] === "source") out.source = value;
  }
  return out.sourceType !== undefined || out.source !== undefined ? out : undefined;
}

/** TOML basic-string escapes. */
function unescapeBasic(s: string): string {
  return s.replace(/\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (_, e: string) => {
    if (e.length > 1) return String.fromCodePoint(Number.parseInt(e.slice(1), 16));
    return ({ n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", '"': '"', "\\": "\\" } as Record<string, string>)[e] ?? e;
  });
}
