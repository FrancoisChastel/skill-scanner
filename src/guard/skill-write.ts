import { cp, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { summarizeForAgent } from "../report/index";
import { scanPath } from "../scan";
import { scanOptionsFrom } from "../second-opinions";
import { withDeadline } from "./deadline";
import { ALLOW, decideReport, type GuardDeps, INSTALL_DEADLINE_MS, mostSevere } from "./decide";
import { errorMessage, isInside } from "./fsutil";
import { locateSkillDir, skillRoots } from "./locations";
import { doNotRetry } from "./messages";
import { loadTrust, logDecision } from "./state";
import type { GuardContext, GuardDecision } from "./types";

/**
 * Writes and edits into a skill directory are installs too: the harness hot-reloads skills. The
 * skill is copied to a temporary directory with the change applied and scanned there. Writes are
 * never "ask": a block denies, a warning passes with a note for the agent.
 */

const MAX_STAGE_FILES = 2000;
const MAX_STAGE_BYTES = 64 * 1024 * 1024;
const SKIP = new Set([".git", "node_modules", ".venv", "venv"]);

/** Decide whether writing `content` to `path` may happen, when `path` is inside a skill directory. */
export async function evaluateSkillWrite(
  path: string,
  content: string | undefined,
  ctx: GuardContext,
  deps: GuardDeps = {},
): Promise<GuardDecision> {
  return content === undefined ? ALLOW : evaluateSkillWrites([{ path, content }], ctx, deps);
}

export interface PendingWrite {
  readonly path: string;
  readonly content: string;
}

/** Several writes at once (an `apply_patch` adding a whole skill): each touched skill is staged with all its changes. */
export async function evaluateSkillWrites(
  writes: readonly PendingWrite[],
  ctx: GuardContext,
  deps: GuardDeps = {},
): Promise<GuardDecision> {
  const roots = deps.roots ?? skillRoots("all", ctx.cwd, ctx.env);
  const groups = new Map<string, StagedFile[]>();
  for (const w of writes) {
    const abs = resolve(ctx.cwd, w.path);
    const loc = locateSkillDir(abs, roots);
    if (!loc?.skillDir || loc.root?.kind === "plugin-cache" || loc.root?.kind === "package-cache") continue;
    groups.set(loc.skillDir, [...(groups.get(loc.skillDir) ?? []), { rel: relative(loc.skillDir, abs), content: w.content }]);
  }
  const decisions: GuardDecision[] = [];
  for (const [skillDir, files] of groups) decisions.push(await evaluateStaged(skillDir, files, ctx, deps));
  return mostSevere(decisions);
}

async function evaluateStaged(skillDir: string, files: readonly StagedFile[], ctx: GuardContext, deps: GuardDeps): Promise<GuardDecision> {
  let staged: Staged | undefined;
  try {
    staged = await stageSkill(skillDir, files);
    const dir = staged.dir;
    const scan = deps.scanPath ?? scanPath;
    const outcome = await withDeadline(deps.installDeadlineMs ?? INSTALL_DEADLINE_MS, ctx.signal, (signal) =>
      scan(dir, {
        ...scanOptionsFrom(ctx.config, { quick: true }),
        label: skillDir,
        signal,
      }),
    );
    if (outcome.status !== "ok") return writeError(ctx, skillDir, outcome.status === "timeout" ? "timed out" : errorMessage(outcome.error));
    const decision = asWriteDecision(decideReport(outcome.value, skillDir, ctx, await loadTrust(ctx.env)), skillDir);
    await logDecision(
      { harness: ctx.harness, kind: "write", action: decision.action, verdict: decision.verdict, path: skillDir },
      ctx.env,
      deps.now?.(),
    );
    return decision;
  } catch (e) {
    return writeError(ctx, skillDir, errorMessage(e));
  } finally {
    await staged?.cleanup();
  }
}

function asWriteDecision(d: GuardDecision, skillDir: string): GuardDecision {
  if (d.verdict === "block" && d.action === "deny") {
    const summary = d.report ? summarizeForAgent(d.report) : "";
    return { ...d, reason: `${summary}\nThis write would put a skill that skill-scanner blocks into ${skillDir}. ${doNotRetry(skillDir)}` };
  }
  if (d.verdict === "warn" && d.report) {
    const note = `${summarizeForAgent(d.report)}\nskill-scanner warns about the skill in ${skillDir} after this write; mention the findings to the user.`;
    return { ...d, action: "allow", reason: note };
  }
  return { ...d, action: "allow" };
}

/**
 * A write cannot ask, so an unchecked write into a skill folder is refused unless the user chose
 * `hooks.onError: "allow"`: a scan that errors or times out must not become a way in.
 */
function writeError(ctx: GuardContext, skillDir: string, message: string): GuardDecision {
  const reason = `skill-scanner could not check the write into ${skillDir}: ${message}.`;
  return ctx.config.hooks.onError === "allow"
    ? { action: "allow", reason: "", source: skillDir }
    : { action: "deny", reason: `${reason} Do not work around this; tell the user.`, source: skillDir };
}

interface Staged {
  readonly dir: string;
  cleanup(): Promise<void>;
}

interface StagedFile {
  /** Path relative to the skill directory. */
  readonly rel: string;
  readonly content: string;
}

/** A bounded copy of `skillDir` in a temporary directory, with `files` written over it. */
export async function stageSkill(skillDir: string, files: readonly StagedFile[]): Promise<Staged> {
  const tmp = await mkdtemp(join(tmpdir(), "skill-scanner-write-"));
  const cleanup = (): Promise<void> => rm(tmp, { recursive: true, force: true });
  try {
    const staged = join(tmp, basename(skillDir));
    const source = await realpath(skillDir).catch(() => undefined);
    if (source) await copyBounded(source, staged);
    else await mkdir(staged, { recursive: true });
    for (const f of files) {
      const dest = join(staged, f.rel);
      if (f.rel === "" || !isInside(staged, dest) || dest === staged) throw new Error(`${f.rel} is not inside ${skillDir}`);
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, f.content);
    }
    return { dir: staged, cleanup };
  } catch (e) {
    await cleanup();
    throw e;
  }
}

async function copyBounded(source: string, dest: string): Promise<void> {
  let files = 0;
  let bytes = 0;
  await cp(source, dest, {
    recursive: true,
    verbatimSymlinks: true,
    filter: async (src) => {
      if (SKIP.has(basename(src))) return false;
      const st = await lstat(src).catch(() => undefined);
      if (!st) return false;
      if (st.isDirectory()) return true;
      files += 1;
      bytes += st.size;
      return files <= MAX_STAGE_FILES && bytes <= MAX_STAGE_BYTES;
    },
  });
}

export interface EditSpec {
  readonly old_string: string;
  readonly new_string: string;
  readonly replace_all?: boolean;
}

/**
 * The file content after Claude Code's Edit/MultiEdit, or undefined when an edit would not apply
 * (the tool will fail on its own). An empty `old_string` on a missing file creates it.
 */
export async function contentAfterEdits(path: string, edits: readonly EditSpec[]): Promise<string | undefined> {
  let text: string | undefined = await readFile(path, "utf8").catch(() => undefined);
  for (const e of edits) {
    if (text === undefined) {
      if (e.old_string !== "") return undefined;
      text = e.new_string;
      continue;
    }
    if (e.old_string === "" || !text.includes(e.old_string)) return undefined;
    text = e.replace_all ? text.split(e.old_string).join(e.new_string) : text.replace(e.old_string, () => e.new_string);
  }
  return text;
}
