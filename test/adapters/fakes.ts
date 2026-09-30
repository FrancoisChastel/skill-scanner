/** Fake guard dependencies and harness doubles for the adapter tests. No real files, network, or home directory. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { DepsOverrides } from "../../src/adapters/shared";
import { type Config, DEFAULT_CONFIG } from "../../src/config";
import type { FlaggedEntry, GuardContext, SkillRoot } from "../../src/guard";
import type { GuardDecision, InstalledSkill, InstallIntent } from "../../src/guard/types";

export const HOME = "/home/dev";
export const PROJECT = "/home/dev/project";

export const ROOTS: readonly SkillRoot[] = [
  { harness: "pi", scope: "project", path: `${PROJECT}/.pi/skills`, kind: "skills" },
  { harness: "shared", scope: "user", path: `${HOME}/.agents/skills`, kind: "skills" },
  { harness: "pi", scope: "user", path: `${HOME}/.pi/agent/skills`, kind: "skills" },
  { harness: "opencode", scope: "user", path: `${HOME}/.config/opencode/skills`, kind: "skills" },
];

export const EVIL_DIR = `${HOME}/.agents/skills/evil-helper`;

export function flaggedEntry(
  name: string,
  path: string,
  verdict: "warn" | "block" = "block",
  summary: readonly string[] = [],
): FlaggedEntry {
  return { name, path, realPath: path, digest: `sha256:${"0".repeat(64)}`, verdict, summary, flaggedAt: "2026-09-30T00:00:00.000Z" };
}

export const EVIL = flaggedEntry("evil-helper", EVIL_DIR, "block", [
  "critical prompt-injection: tells the agent to ignore the user (SKILL.md:7)",
]);

export function installed(name: string, path: string, verdict: InstalledSkill["verdict"], summary: readonly string[] = []): InstalledSkill {
  return {
    harness: "shared",
    scope: "user",
    name,
    path,
    realPath: path,
    digest: `sha256:${"1".repeat(64)}`,
    verdict,
    summary,
    trusted: false,
  };
}

export const allow = (rewrite?: string): GuardDecision => ({ action: "allow", reason: "", ...(rewrite ? { rewrite } : {}) });
export const deny = (reason: string): GuardDecision => ({ action: "deny", reason });
export const ask = (reason: string, rewrite?: string): GuardDecision => ({ action: "ask", reason, ...(rewrite ? { rewrite } : {}) });

/** `npx skills add <source>` is the one install the fake recognises. */
export function fakeIntents(command: string): InstallIntent[] {
  const m = /\bskills add (\S+)/.exec(command);
  if (!m?.[1]) return [];
  return [{ kind: "skills-cli", subcommand: "add", source: m[1], skills: [], global: false, argv: command.split(/\s+/) }];
}

export interface FakeGuardOptions {
  flagged?: () => readonly FlaggedEntry[];
  decide?: (command: string, ctx: GuardContext) => GuardDecision | Promise<GuardDecision>;
  decideWrite?: (path: string, content: string | undefined) => GuardDecision | Promise<GuardDecision>;
  audit?: () => Promise<InstalledSkill[]>;
  reconcile?: () => Promise<{ newlyFlagged: InstalledSkill[]; quarantined: string[] }>;
  config?: Partial<Config["hooks"]>;
  roots?: readonly SkillRoot[];
}

export interface FakeGuard {
  readonly deps: DepsOverrides;
  readonly calls: {
    readonly commands: { command: string; ctx: GuardContext }[];
    readonly writes: { path: string; content: string | undefined }[];
    audits: number;
    reconciles: number;
  };
}

export function fakeGuard(opts: FakeGuardOptions = {}): FakeGuard {
  const calls: FakeGuard["calls"] = { commands: [], writes: [], audits: 0, reconciles: 0 };
  const config: Config = { ...DEFAULT_CONFIG, hooks: { ...DEFAULT_CONFIG.hooks, ...opts.config } };
  const deps: DepsOverrides = {
    env: { HOME, PATH: "/usr/bin:/bin" },
    timeouts: { audit: 300, check: 300, change: 300, registry: 100, registryTtl: 0 },
    loadConfig: async () => config,
    resolveRuntime: async () => undefined,
    skillRoots: () => [...(opts.roots ?? ROOTS)],
    detectInstallIntents: fakeIntents,
    loadFlagged: async () => [...(opts.flagged?.() ?? [])],
    evaluateCommand: async (command, ctx) => {
      calls.commands.push({ command, ctx });
      return opts.decide ? opts.decide(command, ctx) : allow();
    },
    evaluateSkillWrite: async (path, content) => {
      calls.writes.push({ path, content });
      return opts.decideWrite ? opts.decideWrite(path, content) : allow();
    },
    auditInstalled: async () => {
      calls.audits += 1;
      return opts.audit ? opts.audit() : [];
    },
    reconcileAfterChange: async () => {
      calls.reconciles += 1;
      return opts.reconcile ? opts.reconcile() : { newlyFlagged: [], quarantined: [] };
    },
  };
  return { deps, calls };
}

/** Poll for a condition set by background work (the startup audit), with a hard bound. */
export async function until(check: () => boolean, ms = 1_000): Promise<void> {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("condition not met in time");
    await new Promise((r) => setTimeout(r, 5));
  }
}

export const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

export function fixture(name: string): string {
  return readFileSync(join(import.meta.dir, "fixtures", name), "utf8");
}
