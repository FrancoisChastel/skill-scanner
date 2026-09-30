import { readFile, realpath, stat } from "node:fs/promises";
import { basename, delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type FileOp, writeOp } from "./ops";

/** The files `setup` copies to `~/.skill-scanner/bin`; `scripts/build.mjs` produces them in `dist/runtime`. */
export const RUNTIME_FILES = ["skill-scanner.mjs", "opencode-plugin.mjs", "pi-extension.mjs"] as const;
export type RuntimeFile = (typeof RUNTIME_FILES)[number];
export const RUNTIME_ENTRY: RuntimeFile = "skill-scanner.mjs";
export const VERSION_FILE = "VERSION";
export const PACKAGE_NAME = "@french-castle/skill-scanner";

export class SetupError extends Error {
  override readonly name = "SetupError";
}

export interface ExistingFile {
  readonly text: string;
  readonly mode: number;
}

export async function readExisting(path: string): Promise<ExistingFile | undefined> {
  try {
    const [text, st] = await Promise.all([readFile(path, "utf8"), stat(path)]);
    return { text, mode: st.mode & 0o777 };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
}

export async function readText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
}

/** The package directory this module runs from (source checkout, npm install, or npx cache), if any. */
export async function findPackageRoot(from: string = fileURLToPath(import.meta.url)): Promise<string | undefined> {
  let dir = dirname(from);
  for (;;) {
    const pkg = await readText(join(dir, "package.json")).catch(() => undefined);
    if (pkg !== undefined) {
      try {
        if ((JSON.parse(pkg) as { name?: unknown }).name === PACKAGE_NAME) return dir;
      } catch {
        // not ours; keep walking
      }
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

async function hasRuntime(dir: string): Promise<boolean> {
  const found = await Promise.all(RUNTIME_FILES.map((f) => readExisting(join(dir, f)).then(Boolean, () => false)));
  return found.every(Boolean);
}

export interface RuntimeSource {
  readonly dir: string;
  /** Package root, for the bundled skill; absent when running from an installed runtime copy. */
  readonly packageRoot?: string;
}

/**
 * Where to copy the runtime from: `SKILL_SCANNER_RUNTIME_DIR` (development and tests), the package's
 * `dist/runtime`, or, when this program already is the installed runtime, its own directory.
 */
export async function locateRuntimeSource(env: NodeJS.ProcessEnv, self: string = fileURLToPath(import.meta.url)): Promise<RuntimeSource> {
  const packageRoot = await findPackageRoot(self);
  const withRoot = (dir: string): RuntimeSource => ({ dir, ...(packageRoot ? { packageRoot } : {}) });
  if (env.SKILL_SCANNER_RUNTIME_DIR) {
    if (!(await hasRuntime(env.SKILL_SCANNER_RUNTIME_DIR)))
      throw new SetupError(`SKILL_SCANNER_RUNTIME_DIR=${env.SKILL_SCANNER_RUNTIME_DIR} does not contain ${RUNTIME_FILES.join(", ")}`);
    return withRoot(env.SKILL_SCANNER_RUNTIME_DIR);
  }
  if (packageRoot) {
    const dir = join(packageRoot, "dist", "runtime");
    if (await hasRuntime(dir)) return withRoot(dir);
    throw new SetupError(`the hook runtime is missing from ${dir}. Run \`bun run build\` first (you are running from a source checkout).`);
  }
  if (await hasRuntime(dirname(self))) return { dir: dirname(self) };
  throw new SetupError(
    "cannot find the skill-scanner runtime next to this program. Reinstall with `npx @french-castle/skill-scanner setup`.",
  );
}

export async function readRuntimeSource(dir: string): Promise<Record<RuntimeFile, string>> {
  const texts = await Promise.all(RUNTIME_FILES.map((f) => readFile(join(dir, f), "utf8")));
  return Object.fromEntries(RUNTIME_FILES.map((f, i) => [f, texts[i]!])) as Record<RuntimeFile, string>;
}

/** Copy the runtime into `binDir`, file by file, only where the contents or mode differ. */
export function planRuntime(
  binDir: string,
  source: Readonly<Record<RuntimeFile, string>>,
  current: Readonly<Record<string, ExistingFile | undefined>>,
  version: string,
): { ops: FileOp[]; unchanged: string[] } {
  const files: [string, string, number][] = [
    ...RUNTIME_FILES.map((f): [string, string, number] => [f, source[f], f === RUNTIME_ENTRY ? 0o755 : 0o644]),
    [VERSION_FILE, `${version}\n`, 0o644],
  ];
  const ops: FileOp[] = [];
  const unchanged: string[] = [];
  for (const [name, text, mode] of files) {
    const path = join(binDir, name);
    const cur = current[name];
    const op = writeOp(path, cur?.text, text, cur ? `update runtime (${version})` : `install runtime (${version})`, {
      mode,
      ...(cur ? { beforeMode: cur.mode } : {}),
    });
    if (op) ops.push(op);
    else unchanged.push(path);
  }
  return { ops, unchanged };
}

/** Why a Node binary may disappear under the hooks (a version manager or package cache), or undefined. */
export function volatileNodeReason(path: string): string | undefined {
  const p = path.replace(/\\/g, "/");
  const known: [RegExp, string][] = [
    [/\/_npx\//, "the npx cache"],
    [/\/\.nvm\/versions\//, "an nvm version directory"],
    [/\/fnm[^/]*\/(node-versions|multishells)\//i, "an fnm version directory"],
    [/\/\.volta\/tools\/image\//, "a Volta image directory"],
    [/\/\.asdf\/installs\//, "an asdf install directory"],
    [/\/mise\/installs\//, "a mise install directory"],
    [/\/n\/versions\/node\//, "an n version directory"],
    [/\/Cellar\/node(@\d+)?\//, "a Homebrew Cellar directory (it changes on `brew upgrade`)"],
  ];
  return known.find(([re]) => re.test(p))?.[1];
}

export interface NodeProbe {
  /** `process.execPath` when setup itself runs on Node; undefined under Bun. */
  readonly nodeExecPath?: string;
  readonly nodeVersion?: string;
  /** Every `node` executable on PATH, in PATH order. */
  readonly pathNodes: readonly string[];
  readonly realpath: (path: string) => Promise<string>;
}

export interface NodeChoice {
  readonly path: string;
  readonly version?: string;
  readonly warnings: readonly string[];
}

const MIN_NODE_MAJOR = 22;

/**
 * The Node binary hooks run with. The running Node is preferred (it is known to work), but when it
 * sits in a versioned directory a stable link on PATH to the same binary is used instead.
 */
export async function chooseHookNode(probe: NodeProbe): Promise<NodeChoice> {
  const primary = probe.nodeExecPath ?? probe.pathNodes[0];
  if (!primary)
    throw new SetupError(`hooks need Node.js ${MIN_NODE_MAJOR} or later and no \`node\` is on PATH. Install Node, then re-run setup.`);
  const real = await probe.realpath(primary).catch(() => primary);
  let chosen = primary;
  if (volatileNodeReason(primary)) {
    for (const candidate of probe.pathNodes) {
      if (volatileNodeReason(candidate)) continue;
      if ((await probe.realpath(candidate).catch(() => candidate)) === real) {
        chosen = candidate;
        break;
      }
    }
  }
  const warnings: string[] = [];
  const reason = volatileNodeReason(chosen);
  if (reason)
    warnings.push(
      `Node for hooks is ${chosen}, in ${reason}. Hooks stop working if that version is removed: re-run setup after changing Node versions.`,
    );
  const major = probe.nodeVersion ? Number.parseInt(probe.nodeVersion, 10) : undefined;
  if (major !== undefined && major < MIN_NODE_MAJOR)
    warnings.push(`Node ${probe.nodeVersion} is older than ${MIN_NODE_MAJOR}, which skill-scanner needs. Upgrade Node, then re-run setup.`);
  return { path: chosen, ...(probe.nodeVersion ? { version: probe.nodeVersion } : {}), warnings };
}

export async function systemNodeProbe(env: NodeJS.ProcessEnv): Promise<NodeProbe> {
  const onNode = process.versions.bun === undefined && /^node(\.exe)?$/i.test(basename(process.execPath));
  const exts = process.platform === "win32" ? ["node.exe"] : ["node"];
  const seen = new Set<string>();
  const pathNodes: string[] = [];
  for (const dir of (env.PATH ?? env.Path ?? "").split(delimiter).filter(Boolean)) {
    for (const name of exts) {
      const p = join(dir, name);
      if (seen.has(p)) continue;
      seen.add(p);
      const st = await stat(p).catch(() => undefined);
      if (st?.isFile() && (process.platform === "win32" || (st.mode & 0o111) !== 0)) pathNodes.push(p);
    }
  }
  return {
    ...(onNode ? { nodeExecPath: process.execPath, nodeVersion: process.versions.node } : {}),
    pathNodes,
    realpath: (p) => realpath(p),
  };
}

/** How to tell the user to run us again: through npx when that is how this copy was started. */
export const selfCommand = (packageRoot: string | undefined): string =>
  packageRoot && /[\\/]_npx[\\/]/.test(packageRoot) ? `npx ${PACKAGE_NAME}` : "skill-scanner";
