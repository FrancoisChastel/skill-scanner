import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { type Config, DEFAULT_CONFIG } from "../../src/config";
import type { Finding, ScanReport, Verdict } from "../../src/core/types";
import type { TargetScanner } from "../../src/guard/audit";
import type { SourceScanner } from "../../src/guard/decide";
import type { GuardContext, Harness } from "../../src/guard/types";
import { type ScanOptions, scanPath } from "../../src/scan";

/** A throwaway HOME with every harness and scanner directory pointed inside it. */
export interface TempHome {
  readonly home: string;
  readonly env: NodeJS.ProcessEnv;
  path(...parts: string[]): string;
  cleanup(): Promise<void>;
}

export async function tempHome(): Promise<TempHome> {
  const home = await realpath(await mkdtemp(join(tmpdir(), "skill-scanner-guard-")));
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? "",
    HOME: home,
    SKILL_SCANNER_HOME: join(home, ".skill-scanner"),
    CLAUDE_CONFIG_DIR: join(home, ".claude"),
    CODEX_HOME: join(home, ".codex"),
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_CACHE_HOME: join(home, ".cache"),
    PI_CODING_AGENT_DIR: join(home, ".pi", "agent"),
  };
  return { home, env, path: (...parts) => join(home, ...parts), cleanup: () => rm(home, { recursive: true, force: true }) };
}

/** Markers the test scanner turns into verdicts, so tests control verdicts while digests stay real. */
export const BLOCK_MARK = "TEST-MARK-BLOCK";
export const WARN_MARK = "TEST-MARK-WARN";

export function skillMd(name: string, body = "Formats CSV files into Markdown tables."): string {
  return `---\nname: ${name}\ndescription: Formats CSV files into Markdown tables for reports.\n---\n\n${body}\n`;
}

export async function writeSkill(dir: string, name: string, body?: string, extra: Readonly<Record<string, string>> = {}): Promise<string> {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "SKILL.md"), skillMd(name, body));
  for (const [rel, text] of Object.entries(extra)) {
    await mkdir(dirname(join(dir, rel)), { recursive: true });
    await writeFile(join(dir, rel), text);
  }
  return dir;
}

export async function link(target: string, at: string): Promise<void> {
  await mkdir(dirname(at), { recursive: true });
  await symlink(target, at);
}

export function markerFinding(bundle: string, verdict: Verdict): Finding {
  return {
    ruleId: "test/marker",
    title: verdict === "block" ? "Blocking test marker" : "Warning test marker",
    category: "prompt-injection",
    severity: verdict === "block" ? "critical" : "medium",
    confidence: "high",
    message: "test marker",
    location: { file: "SKILL.md", line: 1 },
    bundle,
    source: "static",
  };
}

/** Real collection (real digests), verdicts from markers only. */
export function withMarkers(report: ScanReport): ScanReport {
  const bundles = report.bundles.map((b) => {
    const text = b.bundle.files.map((f) => f.text ?? "").join("\n");
    const verdict: Verdict = text.includes(BLOCK_MARK) ? "block" : text.includes(WARN_MARK) ? "warn" : "pass";
    return { ...b, verdict, findings: verdict === "pass" ? [] : [markerFinding(b.bundle.name, verdict)] };
  });
  const verdict: Verdict = bundles.some((b) => b.verdict === "block")
    ? "block"
    : bundles.some((b) => b.verdict === "warn")
      ? "warn"
      : "pass";
  return { ...report, bundles, verdict };
}

export interface CountingScanner {
  readonly scan: TargetScanner;
  readonly calls: string[];
}

export function markerScanner(): CountingScanner {
  const calls: string[] = [];
  const scan: TargetScanner = async (dir: string, opts: ScanOptions) => {
    calls.push(dir);
    return withMarkers(await scanPath(dir, opts));
  };
  return { scan, calls };
}

/** A source scanner that "fetches" by scanning a local directory mapped from the source string. */
export function fakeSourceScanner(map: Readonly<Record<string, string | Error>>, seen: string[] = []): SourceScanner {
  return async (raw, opts) => {
    seen.push(raw);
    const dir = map[raw];
    if (dir === undefined) throw new Error(`unexpected source ${raw}`);
    if (dir instanceof Error) throw dir;
    const report = withMarkers(await scanPath(dir, { ...opts, label: raw }));
    return { report, fetched: { spec: { raw, kind: "local", display: raw }, dir, root: dir, cleanup: async () => undefined } };
  };
}

export function guardCtx(
  env: NodeJS.ProcessEnv,
  cwd: string,
  extra: Partial<GuardContext> & { hooks?: Partial<Config["hooks"]> } = {},
): GuardContext {
  const { hooks, ...rest } = extra;
  const config: Config = { ...DEFAULT_CONFIG, hooks: { ...DEFAULT_CONFIG.hooks, ...hooks } };
  return { harness: "claude-code" as Harness, cwd, env, config, ...rest };
}

/** A complete report with one skill bundle and a marker finding (or none), for exact-output tests. */
export function fixedReport(verdict: Verdict, name = "demo", digest = `sha256:${"a".repeat(64)}`): ScanReport {
  const findings = verdict === "pass" ? [] : [markerFinding(name, verdict)];
  return {
    schemaVersion: 1,
    tool: { name: "skill-scanner", version: "0.0.0" },
    target: name,
    startedAt: "2026-09-30T00:00:00.000Z",
    durationMs: 1,
    bundles: [{ bundle: { kind: "skill", name, root: ".", dirName: name, files: [], digest, notes: [] }, findings, verdict }],
    verdict,
    counts: { info: 0, low: 0, medium: verdict === "warn" ? 1 : 0, high: 0, critical: verdict === "block" ? 1 : 0 },
    analyzers: [],
    suppressed: 0,
  };
}

/** A source scanner that returns fixed reports by source string. */
export function fixedSources(map: Readonly<Record<string, ScanReport>>): SourceScanner {
  return async (raw) => {
    const report = map[raw];
    if (!report) throw new Error(`unexpected source ${raw}`);
    return {
      report,
      fetched: { spec: { raw, kind: "local", display: raw }, dir: "/nonexistent", root: "/nonexistent", cleanup: async () => undefined },
    };
  };
}
