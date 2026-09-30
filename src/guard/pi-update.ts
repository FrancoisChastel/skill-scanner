import { join } from "node:path";
import { isRecord, readJsonFile } from "./fsutil";
import { harnessDirs } from "./locations";

/**
 * The npm packages `pi update` would install, as sources the fetcher takes, so they can be scanned
 * first: Pi runs `npm install` with lifecycle scripts, so a scan after the update would be too
 * late. Git packages are not listed; `guard` scans them at their fetch (reference-transaction).
 *
 * Mirrors Pi 0.99's package manager: packages come from `<agent dir>/settings.json` and the
 * project's `.pi/settings.json` (`packages: [source | { source }]`); `npm:` sources pinned to an
 * exact version are skipped, others move to `name@latest` or to the newest match of their range.
 */

const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

interface NpmSource {
  readonly name: string;
  readonly version?: string;
}

export async function piNpmUpdates(only: string | undefined, cwd: string, env: NodeJS.ProcessEnv): Promise<string[]> {
  const files = [join(harnessDirs(env).pi, "settings.json"), join(cwd, ".pi", "settings.json")];
  const configured = (await Promise.all(files.map(packagesIn))).flat();
  const wanted = only === undefined ? configured : configured.filter((s) => sameNpmPackage(s, only));
  // A source named on the command line but not configured is what Pi would complain about; scan it anyway.
  const sources = only !== undefined && wanted.length === 0 && parseNpm(only) ? [only] : wanted;
  const out = new Set<string>();
  for (const s of sources) {
    const npm = parseNpm(s);
    if (!npm || (npm.version !== undefined && EXACT_VERSION.test(npm.version))) continue;
    out.add(`npm:${npm.name}${npm.version ? `@${npm.version}` : ""}`);
  }
  return [...out];
}

async function packagesIn(file: string): Promise<string[]> {
  const settings = await readJsonFile(file, (raw) => (isRecord(raw) ? raw : undefined)).catch(() => undefined);
  const packages = Array.isArray(settings?.packages) ? settings.packages : [];
  return packages.flatMap((p: unknown) => {
    if (typeof p === "string") return [p];
    if (isRecord(p) && typeof p.source === "string") return [p.source];
    return [];
  });
}

/** `npm:name`, `npm:name@range`, `npm:@scope/name@range`. */
export function parseNpm(source: string): NpmSource | undefined {
  if (!/^npm:/i.test(source)) return undefined;
  const spec = source.slice(4).trim();
  const at = spec.lastIndexOf("@");
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return spec ? { name: spec } : undefined;
}

function sameNpmPackage(configured: string, requested: string): boolean {
  const a = parseNpm(configured);
  if (!a) return false;
  const b = parseNpm(requested) ?? { name: requested };
  return a.name === b.name;
}
