/**
 * Glue shared by the OpenCode plugin and the Pi extension: a per-instance guard session (config,
 * skill roots, the flagged-skill cache, deadlines, fail-open rules), the messages both harnesses
 * show, and the OpenCode plugin factory. The factory lives here because OpenCode calls every export
 * of its plugin module as a plugin, so `opencode.ts` exports nothing but `SkillScanner`.
 */
import { constants } from "node:fs";
import { access, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, join, relative, resolve, sep } from "node:path";
import type { Hooks, Plugin, PluginInput } from "@opencode-ai/plugin";
import { type Config, DEFAULT_CONFIG, type HookPolicy, loadConfig } from "../config";
import {
  auditInstalled,
  detectInstallIntents,
  evaluateCommand,
  evaluateSkillWrite,
  type FlaggedEntry,
  type GuardContext,
  loadFlagged,
  reconcileAfterChange,
  type SkillRoot,
  skillRoots,
} from "../guard";
import type { GuardDecision, Harness, InstalledSkill, InstallIntent } from "../guard/types";
import { scannerPaths } from "../paths";

export interface Timeouts {
  /** Startup and on-demand audits of every installed skill. */
  readonly audit: number;
  /** Pre-install check of one command or skill write (may clone and scan a remote source). */
  readonly check: number;
  /** Rescan after a command or write changed skill directories. */
  readonly change: number;
  /** Reading the flagged registry, and how long a loaded copy stays fresh. */
  readonly registry: number;
  readonly registryTtl: number;
}

export const DEFAULT_TIMEOUTS: Timeouts = Object.freeze({
  audit: 20_000,
  check: 60_000,
  change: 20_000,
  registry: 2_000,
  registryTtl: 10_000,
});

/** Everything the adapters call, injectable so tests can use fakes. */
export interface GuardDeps {
  readonly detectInstallIntents: typeof detectInstallIntents;
  readonly evaluateCommand: typeof evaluateCommand;
  readonly evaluateSkillWrite: typeof evaluateSkillWrite;
  readonly auditInstalled: typeof auditInstalled;
  readonly reconcileAfterChange: typeof reconcileAfterChange;
  readonly loadFlagged: typeof loadFlagged;
  readonly skillRoots: typeof skillRoots;
  readonly loadConfig: (env: NodeJS.ProcessEnv) => Promise<Config>;
  readonly resolveRuntime: (env: NodeJS.ProcessEnv) => Promise<GuardContext["runtime"]>;
  readonly env: NodeJS.ProcessEnv;
  readonly timeouts: Timeouts;
}

export type DepsOverrides = Partial<Omit<GuardDeps, "timeouts">> & { readonly timeouts?: Partial<Timeouts> };

export function resolveDeps(overrides: DepsOverrides = {}): GuardDeps {
  const { timeouts, ...rest } = overrides;
  return {
    detectInstallIntents,
    evaluateCommand,
    evaluateSkillWrite,
    auditInstalled,
    reconcileAfterChange,
    loadFlagged,
    skillRoots,
    loadConfig: (env) => loadConfig(undefined, env),
    resolveRuntime: defaultRuntime,
    env: process.env,
    ...rest,
    timeouts: { ...DEFAULT_TIMEOUTS, ...timeouts },
  };
}

export type NoticeLevel = "info" | "warning" | "error";
export type Notify = (message: string, level: NoticeLevel) => void;

/** What a harness should do with a command or write, after policy and fail-open rules. */
export type Gate =
  | { readonly action: "allow"; readonly rewrite?: string }
  | { readonly action: "ask"; readonly reason: string; readonly source?: string; readonly rewrite?: string }
  | { readonly action: "deny"; readonly reason: string };

export type Settled = Exclude<Gate, { readonly action: "ask" }>;

export interface AuditOutcome {
  /** False when the audit failed or missed its deadline; `flagged` then comes from the registry. */
  readonly complete: boolean;
  readonly scanned: number;
  readonly flagged: readonly FlaggedEntry[];
  readonly error?: string;
}

export interface ChangeResult {
  readonly newlyFlagged: readonly InstalledSkill[];
  readonly quarantined: readonly string[];
}

const ALLOW: Gate = Object.freeze({ action: "allow" });

/** One harness instance's view of the guard. Every method is total: internal errors resolve, never reject. */
export class GuardSession {
  readonly harness: Harness;
  private readonly deps: GuardDeps;
  private readonly notify: Notify;
  private readonly rootsByCwd = new Map<string, readonly SkillRoot[]>();
  private flaggedCache: readonly FlaggedEntry[] = [];
  private loadedAt = Number.NEGATIVE_INFINITY;
  private loading: Promise<void> | undefined;
  private configLoad: Promise<Config> | undefined;
  private runtimeLoad: Promise<GuardContext["runtime"]> | undefined;
  private errorReported = false;

  constructor(harness: Harness, deps: GuardDeps, notify: Notify) {
    this.harness = harness;
    this.deps = deps;
    this.notify = notify;
  }

  config(): Promise<Config> {
    this.configLoad ??= attempt(() => this.deps.loadConfig(this.deps.env)).catch((e: unknown) => {
      this.notify(`skill-scanner: ${errorText(e)}; using the default policy.`, "warning");
      return DEFAULT_CONFIG;
    });
    return this.configLoad;
  }

  /** Report the first unexpected internal error; later ones stay quiet so a bug cannot flood the user. */
  internalError(e: unknown): void {
    if (this.errorReported) return;
    this.errorReported = true;
    this.notify(`skill-scanner: internal error, the call was let through (${errorText(e)})`, "error");
  }

  async checkCommand(command: string, cwd: string): Promise<Gate> {
    const config = await this.config();
    const t = this.deps.timeouts.check;
    try {
      const decision = await within(this.deps.evaluateCommand(command, await this.context(cwd, t)), t, "the pre-install scan");
      return gateOf(decision, () => sourceOf(this.intents(command)));
    } catch (e) {
      const intents = this.intents(command);
      // Ordinary commands fail open; installs follow the user's onError policy.
      if (intents.length === 0) {
        this.internalError(e);
        return ALLOW;
      }
      return byPolicy(config.hooks.onError, `skill-scanner could not check this install: ${errorText(e)}`, sourceOf(intents));
    }
  }

  /** Full-content writes into a skill directory are installs; writes elsewhere are not the scanner's business. */
  async checkWrite(path: string, content: string, cwd: string): Promise<Gate> {
    const abs = this.resolvePath(path, cwd);
    if (!this.inSkillRoot(abs, cwd)) return ALLOW;
    const config = await this.config();
    const t = this.deps.timeouts.check;
    try {
      const decision = await within(this.deps.evaluateSkillWrite(abs, content, await this.context(cwd, t)), t, "the skill write check");
      return gateOf(decision, () => abs);
    } catch (e) {
      return byPolicy(config.hooks.onError, `skill-scanner could not check this write into a skill directory: ${errorText(e)}`, abs);
    }
  }

  inSkillRoot(path: string, cwd: string): boolean {
    const abs = this.resolvePath(path, cwd);
    return this.roots(cwd).some((r) => isWithin(abs, r.path));
  }

  /** Whether a finished shell command may have installed or changed skills. */
  shouldReconcile(command: string, cwd: string): boolean {
    if (this.intents(command).length > 0) return true;
    const home = this.home();
    return SKILL_DIR_HINT.test(command) || this.roots(cwd).some((r) => pathForms(r.path, home, cwd).some((f) => mentionsDir(command, f)));
  }

  /** Rescan after a change. Returns a warning for the agent, or undefined when nothing was flagged. */
  async afterChange(cwd: string): Promise<string | undefined> {
    const t = this.deps.timeouts.change;
    const work: Promise<ChangeResult> = this.context(cwd, t).then((ctx) => this.deps.reconcileAfterChange(ctx));
    try {
      const result = await within(work, t, "the post-change rescan");
      await this.reload(fromInstalled(result.newlyFlagged));
      return changeNotice(result);
    } catch (e) {
      if (!(e instanceof DeadlineError)) {
        this.internalError(e);
        return undefined;
      }
      // Too slow for this tool result: tell the user when it lands instead.
      work
        .then(async (late) => {
          await this.reload(fromInstalled(late.newlyFlagged));
          const notice = changeNotice(late);
          if (notice) this.notify(notice, "warning");
        })
        .catch((late: unknown) => this.internalError(late));
      return undefined;
    }
  }

  async audit(cwd: string, deadlineMs = this.deps.timeouts.audit): Promise<AuditOutcome> {
    try {
      const found = await within(this.deps.auditInstalled(await this.context(cwd, deadlineMs)), deadlineMs, "the skill audit");
      const skills = Array.isArray(found) ? found : [];
      const flagged = fromInstalled(skills);
      await this.reload(flagged);
      return { complete: true, scanned: skills.length, flagged };
    } catch (e) {
      await this.reload();
      return { complete: false, scanned: 0, flagged: this.relevant(this.flaggedCache, cwd), error: errorText(e) };
    }
  }

  /** The flagged registry, reread when older than the TTL. */
  async flagged(): Promise<readonly FlaggedEntry[]> {
    if (Date.now() - this.loadedAt >= this.deps.timeouts.registryTtl) {
      this.loading ??= this.reload().finally(() => {
        this.loading = undefined;
      });
      await this.loading;
    }
    return this.flaggedCache;
  }

  async flaggedAt(path: string, cwd: string): Promise<FlaggedEntry | undefined> {
    const list = await this.flagged();
    if (list.length === 0) return undefined;
    const abs = this.resolvePath(path, cwd);
    return matchFlaggedPath(abs, list) ?? matchFlaggedPath(await realpath(abs).catch(() => abs), list);
  }

  /** Name matches only count for skills this harness loads, so a flagged skill elsewhere cannot shadow a clean one. */
  async flaggedNamed(name: string, cwd: string): Promise<FlaggedEntry | undefined> {
    const wanted = name.trim().toLowerCase();
    if (wanted === "") return undefined;
    return this.relevant(await this.flagged(), cwd).find((f) => namesOf(f).some((n) => n.toLowerCase() === wanted));
  }

  /** A shell command that reaches into a flagged skill (reading or running its files), except removal and listing. */
  async flaggedIn(command: string, cwd: string): Promise<FlaggedEntry | undefined> {
    if (FLAGGED_DIR_EXEMPT.test(command)) return undefined;
    const home = this.home();
    const list = await this.flagged();
    return list.find((f) =>
      [f.path, f.realPath].some((p) => p !== "" && pathForms(p, home, cwd).some((form) => mentionsDir(command, form))),
    );
  }

  resolvePath(path: string, cwd: string): string {
    const home = this.home();
    const expanded = path === "~" ? home : path.startsWith("~/") ? join(home, path.slice(2)) : path;
    return resolve(cwd, expanded);
  }

  private home(): string {
    return this.deps.env.HOME || homedir();
  }

  private intents(command: string): readonly InstallIntent[] {
    try {
      const found = this.deps.detectInstallIntents(command);
      return Array.isArray(found) ? found : [];
    } catch {
      return [];
    }
  }

  private roots(cwd: string): readonly SkillRoot[] {
    const cached = this.rootsByCwd.get(cwd);
    if (cached) return cached;
    let roots: readonly SkillRoot[] = [];
    try {
      const found = this.deps.skillRoots(this.harness, cwd, this.deps.env);
      roots = Array.isArray(found) ? found.filter((r) => typeof r?.path === "string" && r.path !== "") : [];
    } catch (e) {
      this.internalError(e);
    }
    this.rootsByCwd.set(cwd, roots);
    return roots;
  }

  /** Entries under this harness's skill roots; all of them when the roots are unknown. */
  private relevant(list: readonly FlaggedEntry[], cwd: string): readonly FlaggedEntry[] {
    const roots = this.roots(cwd);
    if (roots.length === 0) return list;
    return list.filter((f) => roots.some((r) => isWithin(f.path, r.path) || isWithin(f.realPath, r.path)));
  }

  private async reload(extra: readonly FlaggedEntry[] = []): Promise<void> {
    try {
      const entries = await within(this.deps.loadFlagged(this.deps.env), this.deps.timeouts.registry, "reading the flagged registry");
      this.flaggedCache = dedupe([...(Array.isArray(entries) ? entries : []), ...extra]);
    } catch {
      this.flaggedCache = dedupe([...this.flaggedCache, ...extra]);
    }
    this.loadedAt = Date.now();
  }

  private async context(cwd: string, timeoutMs: number): Promise<GuardContext> {
    const [config, runtime] = await Promise.all([this.config(), this.runtime()]);
    return {
      harness: this.harness,
      cwd,
      env: this.deps.env,
      config,
      signal: AbortSignal.timeout(timeoutMs),
      ...(runtime ? { runtime } : {}),
    };
  }

  private runtime(): Promise<GuardContext["runtime"]> {
    this.runtimeLoad ??= attempt(() => this.deps.resolveRuntime(this.deps.env)).catch(() => undefined);
    return this.runtimeLoad;
  }
}

/** Run the startup audit and tell the user about flagged skills. Never rejects. */
export async function announceAudit(session: GuardSession, cwd: string, notify: Notify): Promise<void> {
  try {
    const outcome = await session.audit(cwd);
    if (outcome.flagged.length > 0) notify(flaggedNotice(outcome.flagged), "warning");
  } catch (e) {
    session.internalError(e);
  }
}

/** Calls `work`, turning a synchronous throw into a rejection. */
function attempt<T>(work: () => Promise<T> | T): Promise<T> {
  return new Promise<T>((done) => done(work()));
}

export class DeadlineError extends Error {
  override readonly name = "DeadlineError";
}

/** Resolves like `work`, or rejects with a DeadlineError after `ms`. `work` keeps running, and its late failure is handled. */
export function within<T>(work: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((done, fail) => {
    const timer = setTimeout(() => fail(new DeadlineError(`${what} did not finish within ${ms / 1000} s`)), ms);
    timer.unref?.();
    Promise.resolve(work).then(
      (value) => {
        clearTimeout(timer);
        done(value);
      },
      (e: unknown) => {
        clearTimeout(timer);
        fail(e);
      },
    );
  });
}

/** Harness hooks fail open: an internal error lets the call through and is reported once. */
export async function safely<T>(work: () => Promise<T> | T, onError: (e: unknown) => void): Promise<T | undefined> {
  try {
    return await work();
  } catch (e) {
    onError(e);
    return undefined;
  }
}

export function matchFlaggedPath(path: string, flagged: readonly FlaggedEntry[]): FlaggedEntry | undefined {
  return flagged.find((f) => isWithin(path, f.path) || isWithin(path, f.realPath));
}

export function isWithin(path: string, dir: string): boolean {
  if (typeof path !== "string" || typeof dir !== "string" || dir === "") return false;
  return path === dir || path.startsWith(dir.endsWith(sep) ? dir : `${dir}${sep}`);
}

function gateOf(decision: GuardDecision, source: () => string | undefined): Gate {
  const rewrite = typeof decision.rewrite === "string" && decision.rewrite.trim() !== "" ? { rewrite: decision.rewrite } : {};
  if (decision.action === "deny") return { action: "deny", reason: decision.reason || "skill-scanner blocked this." };
  if (decision.action !== "ask") return { action: "allow", ...rewrite };
  const where = source() ?? decision.report?.target;
  return {
    action: "ask",
    reason: decision.reason || "skill-scanner found issues that need review.",
    ...(where ? { source: where } : {}),
    ...rewrite,
  };
}

function byPolicy(policy: HookPolicy, reason: string, source: string | undefined): Gate {
  if (policy === "allow") return ALLOW;
  if (policy === "deny") return { action: "deny", reason };
  return { action: "ask", reason, ...(source ? { source } : {}) };
}

/** A skill's name plus any aliases the registry records (its directory name, for one). */
function namesOf(f: FlaggedEntry): string[] {
  const aliases: unknown = (f as { readonly aliases?: unknown }).aliases;
  return [f.name, ...(Array.isArray(aliases) ? aliases.filter((a): a is string => typeof a === "string") : [])];
}

function intentSource(i: InstallIntent): string | undefined {
  if (i.kind === "skills-cli") return i.source;
  if (i.kind === "git-clone") return i.url;
  if (i.kind === "write-to-skill-dir") return i.dest;
  return "source" in i ? i.source : i.target;
}

function sourceOf(intents: readonly InstallIntent[]): string | undefined {
  return intents.map(intentSource).find((s) => typeof s === "string" && s !== "");
}

function fromInstalled(skills: unknown): FlaggedEntry[] {
  if (!Array.isArray(skills)) return [];
  const at = new Date().toISOString();
  return skills
    .filter(
      (s): s is InstalledSkill =>
        isRecord(s) &&
        (s.verdict === "warn" || s.verdict === "block") &&
        s.trusted !== true &&
        typeof s.name === "string" &&
        typeof s.path === "string",
    )
    .map(
      (s): FlaggedEntry => ({
        name: s.name,
        path: s.path,
        realPath: typeof s.realPath === "string" && s.realPath !== "" ? s.realPath : s.path,
        digest: s.digest,
        verdict: s.verdict === "block" ? "block" : "warn",
        summary: Array.isArray(s.summary) ? s.summary : [],
        flaggedAt: at,
      }),
    );
}

/** Registry entries are data from disk: keep well-formed ones, fill defaults, drop duplicates by real path. */
function dedupe(entries: readonly unknown[]): readonly FlaggedEntry[] {
  const seen = new Set<string>();
  return entries.flatMap((e): FlaggedEntry[] => {
    if (!isRecord(e) || typeof e.name !== "string" || typeof e.path !== "string" || e.path === "") return [];
    const realPath = typeof e.realPath === "string" && e.realPath !== "" ? e.realPath : e.path;
    if (seen.has(realPath)) return [];
    seen.add(realPath);
    // Extra fields (such as aliases) pass through for newer registries.
    return [
      {
        ...e,
        name: e.name,
        path: e.path,
        realPath,
        digest: typeof e.digest === "string" ? e.digest : "",
        verdict: e.verdict === "block" ? "block" : "warn",
        summary: Array.isArray(e.summary) ? e.summary.filter((l): l is string => typeof l === "string") : [],
        flaggedAt: typeof e.flaggedAt === "string" ? e.flaggedAt : "",
      },
    ];
  });
}

// Common skill directory spellings, for commands that name them relatively or through variables.
const SKILL_DIR_HINT = /(?:\.(?:claude|agents|codex|opencode|pi(?:\/agent)?)|opencode)\/skills?\b/;
// Removing, moving, listing, or reviewing a flagged skill is how the user deals with it.
const FLAGGED_DIR_EXEMPT =
  /^\s*(?:sudo\s+)?(?:rm|rmdir|mv|trash|ls|skill-scanner|(?:npx|bunx)\s+(?:-y\s+)?(?:@french-castle\/)?skill-scanner)\b/;

/** The ways a command might spell an absolute path: as is, from $HOME, or relative to the working directory. */
function pathForms(path: string, home: string, cwd: string): string[] {
  const forms = [path];
  if (home !== "" && path !== home && isWithin(path, home)) {
    const rel = relative(home, path);
    forms.push(`~/${rel}`, `$HOME/${rel}`, `\${HOME}/${rel}`);
  }
  if (path !== cwd && isWithin(path, cwd)) {
    const rel = relative(cwd, path);
    forms.push(rel, `./${rel}`);
  }
  return forms;
}

/** Whether `command` names `dir` or something inside it (not merely a sibling with a longer name). */
function mentionsDir(command: string, dir: string): boolean {
  for (let at = command.indexOf(dir); at !== -1; at = command.indexOf(dir, at + 1)) {
    const next = command.charAt(at + dir.length);
    if (next === "" || /[/\s"'`;|&)]/.test(next)) return true;
  }
  return false;
}

// Messages. Plain text: harnesses show them in toasts, notifications, and tool results.

const MAX_LISTED = 8;

function describe(f: Pick<FlaggedEntry, "name" | "verdict" | "summary">): string {
  const first = (Array.isArray(f.summary) ? f.summary : []).find((line) => typeof line === "string" && line.trim() !== "");
  return `- ${f.name} (${f.verdict})${first ? `: ${first.trim()}` : ""}`;
}

function listed(entries: readonly Pick<FlaggedEntry, "name" | "verdict" | "summary">[]): string {
  const lines = entries.slice(0, MAX_LISTED).map(describe);
  const more = entries.length - MAX_LISTED;
  return more > 0 ? [...lines, `- ... and ${more} more`].join("\n") : lines.join("\n");
}

export function flaggedNotice(flagged: readonly FlaggedEntry[]): string {
  const n = flagged.length;
  return [
    `skill-scanner: ${n} installed skill${n === 1 ? " is" : "s are"} flagged; the agent is kept from loading ${n === 1 ? "it" : "them"}:`,
    listed(flagged),
    "Run `skill-scanner audit` to review.",
  ].join("\n");
}

export function changeNotice(result: ChangeResult): string | undefined {
  const flagged = Array.isArray(result?.newlyFlagged) ? result.newlyFlagged : [];
  const moved = Array.isArray(result?.quarantined) ? result.quarantined : [];
  if (flagged.length === 0 && moved.length === 0) return undefined;
  return [
    "skill-scanner WARNING: this change installed or modified skills that were flagged.",
    ...(flagged.length > 0 ? [listed(flagged)] : []),
    ...(moved.length > 0 ? [`Quarantined (moved out of the skill directories): ${moved.join(", ")}`] : []),
    "Do not load, read, or run these skills, and do not undo the quarantine. Ask the user to review them with `skill-scanner audit`.",
  ].join("\n");
}

export function blockedSkillMessage(f: FlaggedEntry): string {
  return [
    `skill-scanner blocked the skill "${f.name}": it is flagged (${f.verdict}).`,
    ...(f.summary.length > 0 ? [listed([f])] : []),
    "Do not load, read, or follow this skill, and do not work around this block.",
    "Tell the user; they can review it with `skill-scanner audit` and, if they trust it, approve it with `skill-scanner trust`.",
  ].join("\n");
}

export function askInstallMessage(reason: string, source: string | undefined): string {
  const target = source ?? "<source>";
  return [
    reason,
    "This install needs the user's approval. Do not retry it or work around this block.",
    `Show the user the findings and ask them to review with \`skill-scanner scan ${target}\`.`,
    "If they approve, they can record it with `skill-scanner trust` and ask you to retry.",
  ].join("\n");
}

export function askWriteMessage(reason: string): string {
  return [
    reason,
    "Writing this into a skill directory needs the user's approval. Do not retry it or work around this block;",
    "show the user the findings and let them decide.",
  ].join("\n");
}

export function auditSummary(outcome: AuditOutcome): string {
  const n = outcome.scanned;
  const head = outcome.complete
    ? `skill-scanner: scanned ${n} installed skill${n === 1 ? "" : "s"}.`
    : `skill-scanner: the audit did not finish (${outcome.error ?? "unknown error"}); showing skills flagged earlier.`;
  return outcome.flagged.length > 0 ? `${head}\n${flaggedNotice(outcome.flagged)}` : `${head} Nothing is flagged.`;
}

/**
 * Remove flagged skills from an Agent Skills `<available_skills>` listing, as Pi (0.83 to 0.87)
 * renders it: one `  <skill>` block per skill with an XML-escaped `<location>`. Anything that does
 * not look exactly like that is left alone; the read gate still stops the load.
 */
export function stripSkillListing(prompt: string, isFlagged: (location: string) => boolean): string {
  return prompt.replace(/<available_skills>\n[\s\S]*?<\/available_skills>/g, (listing) =>
    listing.replace(/^ {2}<skill>\n[\s\S]*?^ {2}<\/skill>\n/gm, (block) => {
      const location = /^ {4}<location>([^<\n]*)<\/location>$/m.exec(block)?.[1];
      return location !== undefined && isFlagged(unescapeXml(location)) ? "" : block;
    }),
  );
}

function unescapeXml(text: string): string {
  return text
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The pinned runtime `setup` copies next to the plugin, run by a real Node (OpenCode and Pi's binary builds run on Bun). */
async function defaultRuntime(env: NodeJS.ProcessEnv): Promise<GuardContext["runtime"]> {
  const script = join(scannerPaths(env).bin, "skill-scanner.mjs");
  if (!(await canAccess(script, constants.R_OK))) return undefined;
  const node = await findNode(env);
  return node ? { node, script } : undefined;
}

async function findNode(env: NodeJS.ProcessEnv): Promise<string | undefined> {
  if (!process.versions.bun && basename(process.execPath).startsWith("node")) return process.execPath;
  const exe = process.platform === "win32" ? "node.exe" : "node";
  for (const dir of (env.PATH ?? "").split(delimiter)) {
    if (dir !== "" && (await canAccess(join(dir, exe), constants.X_OK))) return join(dir, exe);
  }
  return undefined;
}

async function canAccess(path: string, mode: number): Promise<boolean> {
  try {
    await access(path, mode);
    return true;
  } catch {
    return false;
  }
}

// OpenCode (verified on 1.18.33). `tool.execute.before` blocks by throwing, and the model sees the
// message as the tool error; `output.args` is the object the tool then runs. `permission.ask` is
// declared but never fired, so there is no way to ask: "ask" blocks with instructions instead.
// Users can also deny a skill natively with `"permission": { "skill": { "<name>": "deny" } }`.

const TOAST_MS = 15_000;

export function createSkillScannerPlugin(overrides: DepsOverrides = {}): Plugin {
  return async (input: PluginInput): Promise<Hooks> => {
    const deps = resolveDeps(overrides);
    const cwd = input.directory || input.worktree || process.cwd();
    const notify = openCodeNotifier(input);
    const session = new GuardSession("opencode", deps, notify);
    const onError = (e: unknown) => session.internalError(e);
    // OpenCode reads skills once at startup, so one audit per instance covers what it can load.
    void announceAudit(session, cwd, notify);
    return {
      "tool.execute.before": async (call, output) => {
        const blocked = await safely(() => openCodeBefore(session, cwd, call.tool, output.args), onError);
        if (blocked) throw new Error(blocked);
      },
      "tool.execute.after": async (call, output) => {
        const notice = await safely(() => openCodeAfter(session, cwd, call.tool, call.args), onError);
        if (!notice) return;
        output.output = typeof output.output === "string" && output.output !== "" ? `${output.output}\n\n${notice}` : notice;
        notify(notice, "warning");
      },
      // Skills are slash commands too; typing /name skips the skill tool.
      "command.execute.before": async (call) => {
        const flagged = await safely(() => session.flaggedNamed(call.command, cwd), onError);
        if (flagged) throw new Error(blockedSkillMessage(flagged));
      },
    };
  };
}

function openCodeNotifier(input: PluginInput): Notify {
  return (message, level) => {
    void quietly(() => input.client.tui.showToast({ body: { title: "skill-scanner", message, variant: level, duration: TOAST_MS } }));
    void quietly(() => input.client.app.log({ body: { service: "skill-scanner", level: level === "warning" ? "warn" : level, message } }));
  };
}

/** Toasts need a TUI and logs need the server; without them there is nobody to tell. */
async function quietly(send: () => unknown): Promise<void> {
  try {
    await send();
  } catch {
    // Nothing else to report to.
  }
}

async function openCodeBefore(session: GuardSession, cwd: string, tool: string, args: unknown): Promise<string | undefined> {
  if (!isRecord(args)) return undefined;
  if (tool === "bash") return openCodeBash(session, cwd, args);
  if (tool === "skill" && typeof args.name === "string") return blockedText(await session.flaggedNamed(args.name, cwd));
  if (tool === "read" && typeof args.filePath === "string") return blockedText(await session.flaggedAt(args.filePath, cwd));
  if (tool === "write" && typeof args.filePath === "string" && typeof args.content === "string")
    return writeBlock(await session.checkWrite(args.filePath, args.content, cwd));
  if (tool === "apply_patch" && typeof args.patchText === "string") return openCodePatch(session, cwd, args.patchText);
  return undefined;
}

async function openCodeBash(session: GuardSession, cwd: string, args: Record<string, unknown>): Promise<string | undefined> {
  const command = args.command;
  if (typeof command !== "string") return undefined;
  const dir = typeof args.workdir === "string" && args.workdir !== "" ? session.resolvePath(args.workdir, cwd) : cwd;
  const flagged = await session.flaggedIn(command, dir);
  if (flagged) return blockedSkillMessage(flagged);
  const gate = await session.checkCommand(command, dir);
  if (gate.action === "deny") return gate.reason;
  if (gate.action === "ask") return askInstallMessage(gate.reason, gate.source);
  // OpenCode runs the args object it handed to this hook, so the rewrite is an in-place edit.
  if (gate.rewrite) args.command = gate.rewrite;
  return undefined;
}

async function openCodePatch(session: GuardSession, cwd: string, patchText: string): Promise<string | undefined> {
  const added = patchTargets(patchText).filter((t) => t.content !== undefined);
  const gates = await Promise.all(added.map((t) => session.checkWrite(t.path, t.content ?? "", cwd)));
  return gates.map(writeBlock).find((b) => b !== undefined);
}

async function openCodeAfter(session: GuardSession, cwd: string, tool: string, args: unknown): Promise<string | undefined> {
  if (!isRecord(args)) return undefined;
  const dir = openCodeChangeDir(session, cwd, tool, args);
  return dir ? session.afterChange(dir) : undefined;
}

function openCodeChangeDir(session: GuardSession, cwd: string, tool: string, args: Record<string, unknown>): string | undefined {
  if (tool === "bash" && typeof args.command === "string") {
    const dir = typeof args.workdir === "string" && args.workdir !== "" ? session.resolvePath(args.workdir, cwd) : cwd;
    return session.shouldReconcile(args.command, dir) ? dir : undefined;
  }
  if ((tool === "write" || tool === "edit") && typeof args.filePath === "string")
    return session.inSkillRoot(args.filePath, cwd) ? cwd : undefined;
  if (tool === "apply_patch" && typeof args.patchText === "string")
    return patchTargets(args.patchText).some((t) => session.inSkillRoot(t.path, cwd)) ? cwd : undefined;
  return undefined;
}

const blockedText = (f: FlaggedEntry | undefined): string | undefined => (f ? blockedSkillMessage(f) : undefined);

function writeBlock(gate: Gate): string | undefined {
  if (gate.action === "deny") return gate.reason;
  return gate.action === "ask" ? askWriteMessage(gate.reason) : undefined;
}

export interface PatchTarget {
  readonly path: string;
  /** The whole new file, for `*** Add File`; absent for updates, moves, and deletes. */
  readonly content?: string;
}

/** Files an `apply_patch` envelope touches (`*** Begin Patch` ... `*** End Patch`). */
export function patchTargets(patchText: string): PatchTarget[] {
  const targets: PatchTarget[] = [];
  let adding: { readonly path: string; readonly lines: string[] } | undefined;
  const flush = (): void => {
    if (adding) targets.push({ path: adding.path, content: `${adding.lines.join("\n")}\n` });
    adding = undefined;
  };
  for (const line of patchText.split(/\r?\n/)) {
    const header = /^\*\*\* (Add File|Update File|Delete File|Move to): (.+)$/.exec(line);
    if (header) {
      flush();
      const path = (header[2] ?? "").trim();
      if (header[1] === "Add File") adding = { path, lines: [] };
      else targets.push({ path });
    } else if (line.startsWith("*** ")) flush();
    else if (adding && line.startsWith("+")) adding.lines.push(line.slice(1));
  }
  flush();
  return targets;
}
