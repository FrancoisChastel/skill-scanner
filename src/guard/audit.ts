import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { basename, join } from "node:path";
import { compareFindings, type VerdictPolicy, verdictFor, worstVerdict } from "../core/severity";
import type { ScanReport } from "../core/types";
import { scannerPaths } from "../paths";
import { scanPath, type TargetScanner } from "../scan";
import { scanOptionsFrom, secondOpinionsFingerprint, secondOpinionsFrom } from "../second-opinions";
import { PLUGIN_MARKERS, statFingerprint } from "./fingerprint";
import { errorMessage, forEachLimit, isInside } from "./fsutil";
import { skillRoots } from "./locations";
import {
  type CachedScan,
  cacheKey,
  isEntryTrusted,
  loadFlaggedRaw,
  loadTrust,
  policyFingerprint,
  readCachedScan,
  readStatEntry,
  saveFlagged,
  trustedDigests,
  writeCachedScan,
  writeStatEntry,
} from "./state";
import { type AuditTarget, enumerateTargets } from "./targets";
import type { FlaggedEntry, GuardContext, InstalledSkill, SkillRoot } from "./types";

/**
 * Scan everything installed under the skill roots, reusing cached results for unchanged
 * directories, apply the trust store, and refresh the flagged registry that use-time gates read.
 */

export type { TargetScanner };

export interface AuditOptions {
  readonly roots?: readonly SkillRoot[];
  /** Audit exactly these targets instead of enumerating the roots. */
  readonly targets?: readonly AuditTarget[];
  /** Default true. False rescans everything (results are still written to the cache). */
  readonly useCache?: boolean;
  /** Stop starting new scans after this long; finished results are kept. Default 25 s. */
  readonly deadlineMs?: number;
  readonly scan?: TargetScanner;
  /** Default true. */
  readonly updateRegistry?: boolean;
  readonly now?: () => Date;
}

export interface AuditResult {
  readonly skills: readonly InstalledSkill[];
  /** Targets not scanned before the deadline. */
  readonly pending: readonly AuditTarget[];
  readonly errors: readonly { readonly path: string; readonly message: string }[];
  readonly stats: { readonly targets: number; readonly scanned: number; readonly cached: number; readonly durationMs: number };
  readonly timedOut: boolean;
  /** The flagged registry as it was before this audit. */
  readonly previous: readonly FlaggedEntry[];
}

export const AUDIT_DEADLINE_MS = 25_000;
const CONCURRENCY = 4;
const SUMMARY_LINES = 3;

export async function auditInstalled(ctx: GuardContext, roots?: readonly SkillRoot[]): Promise<InstalledSkill[]> {
  return [...(await auditInstalledDetailed(ctx, roots ? { roots } : {})).skills];
}

export async function auditInstalledDetailed(ctx: GuardContext, opts: AuditOptions = {}): Promise<AuditResult> {
  const t0 = performance.now();
  const roots = opts.roots ?? skillRoots("all", ctx.cwd, ctx.env);
  const targets = opts.targets ?? (await enumerateTargets(roots));
  const [trust, stored] = await Promise.all([loadTrust(ctx.env), loadFlaggedRaw(ctx.env)]);
  const trusted = trustedDigests(trust);
  const previous = stored.filter((e) => !isEntryTrusted(e, trusted));
  // Cached results are keyed by what would judge them now: a new key, or gitleaks installed since, rescans.
  const policyFp = policyFingerprint(ctx.config, await secondOpinionsFingerprint(secondOpinionsFrom(ctx.config, true), ctx.env));
  const deadline = Date.now() + (opts.deadlineMs ?? AUDIT_DEADLINE_MS);
  const done = new Map<string, InstalledSkill>();
  const errors: { path: string; message: string }[] = [];
  let scanned = 0;
  const work = forEachLimit(targets, CONCURRENCY, async (t) => {
    if (Date.now() >= deadline || ctx.signal?.aborted) return;
    try {
      const r = await assessTarget(t, ctx, opts, policyFp);
      done.set(t.realPath, toInstalled(t, r.scan, trusted));
      if (!r.cached) scanned += 1;
    } catch (e) {
      errors.push({ path: t.path, message: errorMessage(e) });
    }
  });
  const timedOut = !(await settlesWithin(work, deadline - Date.now(), ctx.signal));
  const skills = targets.flatMap((t) => done.get(t.realPath) ?? []);
  const failed = new Set(errors.map((e) => e.path));
  const pending = targets.filter((t) => !done.has(t.realPath) && !failed.has(t.path));
  if (opts.updateRegistry !== false) {
    await updateRegistry({
      stored,
      skills,
      targets,
      roots: opts.targets ? undefined : roots,
      trusted,
      now: opts.now?.() ?? new Date(),
      env: ctx.env,
    });
  }
  return {
    skills,
    pending,
    errors: [...errors],
    stats: { targets: targets.length, scanned, cached: skills.length - scanned, durationMs: Math.round(performance.now() - t0) },
    timedOut,
    previous,
  };
}

/** Resolves true when `p` settles within `ms` (and before `signal` aborts), false otherwise. Work still running keeps running. */
async function settlesWithin(p: Promise<unknown>, ms: number, signal?: AbortSignal): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  const stop = new Promise<false>((r) => {
    timer = setTimeout(() => r(false), Math.max(0, ms));
    onAbort = () => r(false);
    if (signal?.aborted) r(false);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([p.then(() => true), stop]);
  } finally {
    clearTimeout(timer);
    if (onAbort) signal?.removeEventListener("abort", onAbort);
  }
}

async function assessTarget(
  t: AuditTarget,
  ctx: GuardContext,
  opts: AuditOptions,
  policyFp: string,
): Promise<{ scan: CachedScan; cached: boolean }> {
  const fingerprint = await statFingerprint(t.realPath, t.kind === "plugin" ? { ignoreTop: PLUGIN_MARKERS } : {});
  if (opts.useCache !== false) {
    const known = await readStatEntry(t.realPath, ctx.env);
    if (known?.fingerprint === fingerprint) {
      const hit = await readCachedScan(cacheKey(known.digest, policyFp), ctx.env);
      if (hit) return { scan: hit, cached: true };
    }
  }
  const scan = opts.scan ?? scanPath;
  const report = await scan(t.realPath, {
    ...scanOptionsFrom(ctx.config, { quick: true }),
    label: t.path,
    ...(ctx.signal ? { signal: ctx.signal } : {}),
  });
  const entry = toCached(t.kind === "plugin" ? withoutBookkeeping(report, ctx.config) : report, t);
  await writeCachedScan(cacheKey(entry.digest, policyFp), entry, ctx.env);
  await writeStatEntry({ realPath: t.realPath, fingerprint, digest: entry.digest }, ctx.env);
  return { scan: entry, cached: false };
}

/** Findings on Claude Code's per-session files inside a plugin version are noise that changes every session. */
function withoutBookkeeping(report: ScanReport, policy: VerdictPolicy): ScanReport {
  const isMarker = (file: string): boolean => PLUGIN_MARKERS.has(file.split("/")[0] ?? "");
  const bundles = report.bundles.map((b) => {
    const findings = b.findings.filter((f) => !isMarker(f.location.file));
    return findings.length === b.findings.length ? b : { ...b, findings, verdict: verdictFor(findings, policy) };
  });
  return { ...report, bundles, verdict: worstVerdict(bundles.map((b) => b.verdict)) };
}

function toCached(report: ScanReport, t: AuditTarget): CachedScan {
  return {
    digest: targetDigest(report, t),
    verdict: report.verdict,
    summary: findingLines(report, SUMMARY_LINES),
    findings: report.bundles.reduce((n, b) => n + b.findings.length, 0),
    bundles: report.bundles.map((b) => ({
      name: b.bundle.name,
      root: b.bundle.root,
      kind: b.bundle.kind,
      digest: b.bundle.digest,
      verdict: b.verdict,
    })),
    scannedAt: report.startedAt,
  };
}

/**
 * One digest for the whole target. A single bundle (the usual skill) keeps its own digest, so
 * trust granted from `skill-scanner scan` output matches. Plugin roots ignore Claude Code's
 * per-session bookkeeping files so the digest is stable across sessions.
 */
export function targetDigest(report: ScanReport, t: Pick<AuditTarget, "kind">): string {
  const [only] = report.bundles;
  if (report.bundles.length === 1 && only) return only.bundle.digest;
  const h = createHash("sha256");
  for (const b of [...report.bundles].sort((x, y) => x.bundle.root.localeCompare(y.bundle.root))) {
    if (t.kind === "plugin" && b.bundle.root === ".") {
      for (const f of b.bundle.files) {
        if (PLUGIN_MARKERS.has(f.path.split("/")[0] ?? "")) continue;
        h.update(`.\0${f.path}\0${f.size}\0${f.text ?? f.header ?? f.linkTarget ?? ""}\n`);
      }
    } else h.update(`${b.bundle.root}\0${b.bundle.digest}\n`);
  }
  return `sha256:${h.digest("hex")}`;
}

/** The most severe findings, one line each: `high exfiltration/x: title (scripts/run.sh:12)`. */
export function findingLines(report: ScanReport, max: number): string[] {
  const all = report.bundles.flatMap((b) => b.findings).sort(compareFindings);
  return all.slice(0, max).map((f) => {
    const where = f.location.line ? `${f.location.file}:${f.location.line}` : f.location.file;
    return `${f.severity} ${f.ruleId}: ${f.title} (${where})`;
  });
}

function toInstalled(t: AuditTarget, scan: CachedScan, trusted: ReadonlySet<string>): InstalledSkill {
  const risky = scan.bundles.filter((b) => b.verdict !== "pass");
  const isTrusted = trusted.has(scan.digest) || (risky.length > 0 && risky.every((b) => trusted.has(b.digest)));
  const main = scan.bundles.find((b) => b.root === "." && b.kind === "skill");
  const name = t.kind === "skill" ? (main?.name ?? t.name) : t.name;
  const skillNames = scan.bundles.filter((b) => b.kind === "skill").map((b) => b.name);
  const aliases = [
    ...(t.aliases ?? []),
    ...(t.kind === "skill" ? [basename(t.path)] : []),
    ...(t.kind === "plugin" ? skillNames.map((s) => `${t.name}:${s}`) : []),
  ].filter((a, i, all) => a !== name && all.indexOf(a) === i);
  return {
    harness: t.harness,
    scope: t.scope,
    name,
    path: t.path,
    realPath: t.realPath,
    digest: scan.digest,
    verdict: scan.verdict,
    summary: scan.summary,
    trusted: isTrusted,
    kind: t.kind,
    ...(aliases.length > 0 ? { aliases } : {}),
    ...(scan.bundles.length > 1 && risky.length > 0 ? { riskyDigests: risky.map((b) => b.digest) } : {}),
  };
}

interface RegistryUpdate {
  /** The registry as stored (trusted entries included). */
  readonly stored: readonly FlaggedEntry[];
  readonly skills: readonly InstalledSkill[];
  readonly targets: readonly AuditTarget[];
  /** The roots that were fully enumerated, so entries under them that were not found are gone. */
  readonly roots: readonly SkillRoot[] | undefined;
  readonly trusted: ReadonlySet<string>;
  readonly now: Date;
  readonly env: NodeJS.ProcessEnv;
}

async function updateRegistry(u: RegistryUpdate): Promise<void> {
  const audited = new Set(u.skills.map((s) => s.realPath));
  const enumerated = new Set(u.targets.map((t) => t.realPath));
  const covered = (p: string): boolean => u.roots?.some((r) => isInside(r.path, p)) === true;
  const kept = u.stored.filter((e) => {
    if (audited.has(e.realPath) || isEntryTrusted(e, u.trusted)) return false;
    if (e.quarantined !== undefined) return keepQuarantined(e, u);
    return enumerated.has(e.realPath) || (!covered(e.path) && existsSync(e.path));
  });
  const fresh = u.skills.filter((s) => s.verdict !== "pass" && !s.trusted).map((s) => toFlagged(s, u.stored, u.now));
  const next = [...kept, ...fresh];
  if (JSON.stringify(next) !== JSON.stringify(u.stored)) await saveFlagged(next, u.env, u.now);
}

/**
 * A quarantined skill stays blocked by name (a harness may have cached it) until something clean
 * takes its place or its path, or the quarantined copy is gone.
 */
function keepQuarantined(e: FlaggedEntry, u: RegistryUpdate): boolean {
  const replaced = u.skills.some((s) => s.path === e.path || (s.name === e.name && (s.verdict === "pass" || s.trusted)));
  return !replaced && existsSync(join(scannerPaths(u.env).quarantine, e.quarantined ?? ""));
}

function toFlagged(s: InstalledSkill, previous: readonly FlaggedEntry[], now: Date): FlaggedEntry {
  const before = previous.find((e) => e.realPath === s.realPath && e.digest === s.digest);
  return {
    name: s.name,
    path: s.path,
    realPath: s.realPath,
    digest: s.digest,
    verdict: s.verdict === "block" ? "block" : "warn",
    summary: s.summary,
    flaggedAt: before?.flaggedAt ?? now.toISOString(),
    ...(s.aliases ? { aliases: s.aliases } : {}),
    ...(s.kind ? { kind: s.kind } : {}),
    harness: s.harness,
    ...(s.riskyDigests ? { riskyDigests: s.riskyDigests } : {}),
  };
}
