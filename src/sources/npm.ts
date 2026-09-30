import { mkdir, readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { SourceError, TarError } from "./errors";
import { lastLines, ProgramError, runProgram } from "./exec";
import { DEFAULT_TAR_LIMITS, extractEntries, readTarGz, type TarEntry, type TarLimits } from "./tar";

export interface NpmOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
  readonly limits?: TarLimits;
}

export interface NpmPackage {
  /** The package root: the tarball's single top-level directory (`package/` for registry tarballs). */
  readonly root: string;
  /** `name@version (integrity)` as npm resolved it; dist-tags and ranges can move after the scan. */
  readonly resolved?: string;
}

/** Download a registry package with `npm pack` (scripts off) and unpack it under `workDir`. */
export async function fetchNpmPackage(spec: string, workDir: string, label: string, opts: NpmOptions): Promise<NpmPackage> {
  const packDir = join(workDir, "pack");
  const outDir = join(workDir, "unpacked");
  await mkdir(packDir);
  await mkdir(outDir);
  const resolved = await npmPack(spec, packDir, label, opts);
  const tgz = await singleTarball(packDir, label);
  const limits = opts.limits ?? DEFAULT_TAR_LIMITS;
  const size = (await stat(tgz)).size;
  if (size > limits.maxTotalBytes) throw new SourceError(`${label}: tarball is larger than ${limits.maxTotalBytes} bytes`);
  try {
    const { entries } = readTarGz(await readFile(tgz), limits);
    const top = singleTopDirectory(entries);
    await extractEntries(entries, outDir);
    return { root: join(outDir, top), ...(resolved ? { resolved } : {}) };
  } catch (e) {
    if (e instanceof TarError) throw new TarError(`${label}: ${e.message}`);
    throw new SourceError(`${label}: cannot unpack tarball: ${(e as Error).message}`);
  }
}

/**
 * npm strips the first path component of every entry, so differently named top-level directories
 * merge on install. Scanning one of them would miss the rest: require exactly one.
 */
function singleTopDirectory(entries: readonly TarEntry[]): string {
  const tops = new Set(entries.map((e) => e.path.split("/")[0]!));
  const loose = entries.filter((e) => e.type === "file" && !e.path.includes("/"));
  if (tops.size !== 1 || loose.length > 0) {
    throw new TarError(`tarball must have one top-level directory, found ${[...tops].slice(0, 5).join(", ") || "none"}`);
  }
  return [...tops][0]!;
}

async function npmPack(spec: string, packDir: string, label: string, opts: NpmOptions): Promise<string | undefined> {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const args = ["pack", "--json", "--ignore-scripts", "--pack-destination", packDir, "--", spec];
  try {
    const { stdout } = await runProgram(npm, args, {
      cwd: packDir,
      env: { ...opts.env, npm_config_ignore_scripts: "true", npm_config_audit: "false", npm_config_fund: "false" },
      timeoutMs: opts.timeoutMs,
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
    return resolvedFrom(stdout);
  } catch (e) {
    if (e instanceof ProgramError) {
      const why = e.failure === "exit" ? lastLines(e.stderr) || e.message : e.message;
      throw new SourceError(`cannot download ${label}: ${why}`);
    }
    throw e;
  }
}

/** `id (integrity)` from `npm pack --json`; undefined when npm printed something else. */
function resolvedFrom(stdout: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(stdout);
    const first = Array.isArray(parsed) ? (parsed[0] as Record<string, unknown> | undefined) : undefined;
    const id = typeof first?.id === "string" ? first.id : undefined;
    const integrity = typeof first?.integrity === "string" ? first.integrity : undefined;
    return id ? `${id}${integrity ? ` (${integrity})` : ""}` : undefined;
  } catch {
    return undefined;
  }
}

async function singleTarball(dir: string, label: string): Promise<string> {
  const tgz = (await readdir(dir)).filter((n) => n.endsWith(".tgz"));
  if (tgz.length !== 1) throw new SourceError(`${label}: npm pack produced ${tgz.length} tarballs`);
  return join(dir, tgz[0]!);
}
