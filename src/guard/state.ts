import { createHash } from "node:crypto";
import { appendFile, mkdir, rename, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Config } from "../config";
import type { BundleKind, Verdict } from "../core/types";
import { scannerPaths } from "../paths";
import { BUILTIN_RULES } from "../rules";
import { VERSION } from "../version";
import { isRecord, readJsonFile, writeFileAtomic } from "./fsutil";
import type { FlaggedEntry, TrustEntry, TrustStore } from "./types";

/**
 * The guard's persistent state under the scanner home: flagged skills, trusted digests, cached
 * scan results, and the decision log. Every write is atomic (temp file + rename) and every read
 * tolerates a missing or corrupt file by treating it as empty.
 */

const isStr = (v: unknown): v is string => typeof v === "string";
const isStrArray = (v: unknown): v is string[] => Array.isArray(v) && v.every(isStr);
const DIGEST = /^sha256:[0-9a-f]{64}$/;

// ---- Flagged registry

function isFlaggedEntry(v: unknown): v is FlaggedEntry {
  return (
    isRecord(v) &&
    isStr(v.name) &&
    isStr(v.path) &&
    isStr(v.realPath) &&
    isStr(v.digest) &&
    (v.verdict === "warn" || v.verdict === "block") &&
    isStrArray(v.summary) &&
    isStr(v.flaggedAt) &&
    (v.aliases === undefined || isStrArray(v.aliases)) &&
    (v.riskyDigests === undefined || isStrArray(v.riskyDigests))
  );
}

function parseFlagged(raw: unknown): FlaggedEntry[] | undefined {
  const list = Array.isArray(raw) ? raw : isRecord(raw) && Array.isArray(raw.entries) ? raw.entries : undefined;
  return list?.filter(isFlaggedEntry);
}

/**
 * Flagged skills, without the ones the user has since trusted: the registry is what use-time gates
 * read, so approving a skill with `skill-scanner trust` lifts its block immediately.
 */
export async function loadFlagged(env: NodeJS.ProcessEnv): Promise<FlaggedEntry[]> {
  const [raw, trust] = await Promise.all([loadFlaggedRaw(env), loadTrust(env)]);
  const trusted = trustedDigests(trust);
  return raw.filter((e) => !isEntryTrusted(e, trusted));
}

/** The registry as stored, trusted entries included. */
export async function loadFlaggedRaw(env: NodeJS.ProcessEnv): Promise<FlaggedEntry[]> {
  return (await readJsonFile(scannerPaths(env).flagged, parseFlagged)) ?? [];
}

export function isEntryTrusted(e: Pick<FlaggedEntry, "digest" | "riskyDigests">, trusted: ReadonlySet<string>): boolean {
  if (trusted.has(e.digest)) return true;
  return e.riskyDigests !== undefined && e.riskyDigests.length > 0 && e.riskyDigests.every((d) => trusted.has(d));
}

/** Record that flagged skills were moved to quarantine (by real path), so they stay blocked by name. */
export async function markQuarantined(ids: ReadonlyMap<string, string>, env: NodeJS.ProcessEnv): Promise<void> {
  if (ids.size === 0) return;
  const raw = await loadFlaggedRaw(env);
  const next = raw.map((e) => (ids.has(e.realPath) ? { ...e, quarantined: ids.get(e.realPath)! } : e));
  await saveFlagged(next, env);
}

export async function saveFlagged(entries: readonly FlaggedEntry[], env: NodeJS.ProcessEnv, now: Date = new Date()): Promise<void> {
  const body = { version: 1, updatedAt: now.toISOString(), entries };
  await writeFileAtomic(scannerPaths(env).flagged, `${JSON.stringify(body, null, 2)}\n`);
}

/** The flagged entry for a skill name (or alias, or `plugin:skill`) or a path inside a skill, if any. */
export function findFlagged(nameOrPath: string, flagged: readonly FlaggedEntry[]): FlaggedEntry | undefined {
  const lower = nameOrPath.toLowerCase();
  const inside = (p: string): boolean => nameOrPath === p || nameOrPath.startsWith(`${p}/`);
  return flagged.find(
    (f) =>
      f.name.toLowerCase() === lower ||
      f.aliases?.some((a) => a.toLowerCase() === lower) === true ||
      (f.kind === "plugin" && lower.startsWith(`${f.name.toLowerCase()}:`)) ||
      inside(f.path) ||
      inside(f.realPath),
  );
}

// ---- Trust store

function isTrustEntry(v: unknown): v is TrustEntry {
  return (
    isRecord(v) && isStr(v.digest) && isStr(v.name) && isStr(v.path) && isStr(v.trustedAt) && (v.reason === undefined || isStr(v.reason))
  );
}

function parseTrust(raw: unknown): TrustStore | undefined {
  if (!isRecord(raw) || !Array.isArray(raw.entries)) return undefined;
  return { version: 1, entries: raw.entries.filter(isTrustEntry) };
}

export async function loadTrust(env: NodeJS.ProcessEnv): Promise<TrustStore> {
  return (await readJsonFile(scannerPaths(env).trust, parseTrust)) ?? { version: 1, entries: [] };
}

async function saveTrust(store: TrustStore, env: NodeJS.ProcessEnv): Promise<void> {
  await writeFileAtomic(scannerPaths(env).trust, `${JSON.stringify(store, null, 2)}\n`);
}

export type NewTrustEntry = Omit<TrustEntry, "trustedAt"> & { readonly trustedAt?: string };

/** Approve one exact digest. Replaces an existing entry for the same digest. Returns the updated store. */
export async function addTrust(entry: NewTrustEntry, env: NodeJS.ProcessEnv): Promise<TrustStore> {
  if (!DIGEST.test(entry.digest)) throw new Error(`not a skill digest: ${entry.digest} (expected sha256:<64 hex>)`);
  const store = await loadTrust(env);
  const record: TrustEntry = {
    digest: entry.digest,
    name: entry.name,
    path: entry.path,
    ...(entry.reason ? { reason: entry.reason } : {}),
    trustedAt: entry.trustedAt ?? new Date().toISOString(),
  };
  const next: TrustStore = { version: 1, entries: [...store.entries.filter((e) => e.digest !== entry.digest), record] };
  await saveTrust(next, env);
  await pruneTrustedFlags(next, env);
  return next;
}

/** Drop registry entries the trust store now covers. */
async function pruneTrustedFlags(store: TrustStore, env: NodeJS.ProcessEnv): Promise<void> {
  const raw = await loadFlaggedRaw(env);
  const trusted = trustedDigests(store);
  const kept = raw.filter((e) => !isEntryTrusted(e, trusted));
  if (kept.length !== raw.length) await saveFlagged(kept, env);
}

/** Remove entries matching a digest (with or without `sha256:`), a name, or a path. Returns what was removed. */
export async function removeTrust(match: string, env: NodeJS.ProcessEnv): Promise<TrustEntry[]> {
  const m = match.trim();
  const hits = (e: TrustEntry): boolean => e.digest === m || e.digest === `sha256:${m}` || e.name === m || e.path === m;
  const store = await loadTrust(env);
  const removed = store.entries.filter(hits);
  if (removed.length > 0) await saveTrust({ version: 1, entries: store.entries.filter((e) => !hits(e)) }, env);
  return removed;
}

export function trustedDigests(store: TrustStore): ReadonlySet<string> {
  return new Set(store.entries.map((e) => e.digest));
}

export const isTrusted = (digest: string, store: TrustStore): boolean => store.entries.some((e) => e.digest === digest);

// ---- Scan cache: results by content digest, plus a stat index so unchanged skills are not even read.

export interface CachedBundle {
  readonly name: string;
  readonly root: string;
  readonly kind: BundleKind;
  readonly digest: string;
  readonly verdict: Verdict;
}

export interface CachedScan {
  readonly digest: string;
  readonly verdict: Verdict;
  readonly summary: readonly string[];
  readonly findings: number;
  readonly bundles: readonly CachedBundle[];
  readonly scannedAt: string;
}

const isVerdict = (v: unknown): v is Verdict => v === "pass" || v === "warn" || v === "block";

function parseCachedScan(raw: unknown): CachedScan | undefined {
  if (!isRecord(raw) || !isStr(raw.digest) || !isVerdict(raw.verdict) || !isStrArray(raw.summary)) return undefined;
  if (typeof raw.findings !== "number" || !Array.isArray(raw.bundles) || !isStr(raw.scannedAt)) return undefined;
  const bundles = raw.bundles.filter((b): b is CachedBundle => isRecord(b) && isStr(b.name) && isStr(b.digest) && isVerdict(b.verdict));
  return { ...(raw as unknown as CachedScan), bundles };
}

/** What a cached verdict depends on besides content: scanner version, rule set, and the user's policy. */
export function policyFingerprint(config: Pick<Config, "blockAt" | "warnAt" | "ignore">): string {
  const rules = BUILTIN_RULES.map((r) => `${r.id}:${r.severity}:${r.confidence}`).join(",");
  return sha256(`${VERSION}\n${rules}\n${config.blockAt}\n${config.warnAt}\n${JSON.stringify(config.ignore)}`);
}

export const cacheKey = (digest: string, policyFp: string): string => sha256(`${digest}\n${policyFp}`);

const scanFile = (key: string, env: NodeJS.ProcessEnv): string => join(scannerPaths(env).cache, "scans", `${key}.json`);

export async function readCachedScan(key: string, env: NodeJS.ProcessEnv): Promise<CachedScan | undefined> {
  return readJsonFile(scanFile(key, env), parseCachedScan);
}

export async function writeCachedScan(key: string, entry: CachedScan, env: NodeJS.ProcessEnv): Promise<void> {
  await writeFileAtomic(scanFile(key, env), `${JSON.stringify(entry)}\n`);
}

export interface StatEntry {
  readonly realPath: string;
  /** Hash of relative paths, sizes, and times of every file: changes whenever the content could have. */
  readonly fingerprint: string;
  readonly digest: string;
}

const statFile = (realPath: string, env: NodeJS.ProcessEnv): string => join(scannerPaths(env).cache, "stat", `${sha256(realPath)}.json`);

export async function readStatEntry(realPath: string, env: NodeJS.ProcessEnv): Promise<StatEntry | undefined> {
  const parse = (raw: unknown): StatEntry | undefined =>
    isRecord(raw) && raw.realPath === realPath && isStr(raw.fingerprint) && isStr(raw.digest) ? (raw as unknown as StatEntry) : undefined;
  return readJsonFile(statFile(realPath, env), parse);
}

export async function writeStatEntry(entry: StatEntry, env: NodeJS.ProcessEnv): Promise<void> {
  await writeFileAtomic(statFile(entry.realPath, env), `${JSON.stringify(entry)}\n`);
}

// ---- Decision log

const LOG_MAX_BYTES = 5 * 1024 * 1024;

/** Append one JSON line to the decision log, rotating to `.1` past 5 MB. Never throws: logging must not break a hook. */
export async function logDecision(
  record: Readonly<Record<string, unknown>>,
  env: NodeJS.ProcessEnv,
  now: Date = new Date(),
): Promise<void> {
  const path = scannerPaths(env).log;
  try {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const size = await stat(path).then(
      (s) => s.size,
      () => 0,
    );
    if (size > LOG_MAX_BYTES) await rename(path, `${path}.1`);
    await appendFile(path, `${JSON.stringify({ ts: now.toISOString(), ...record })}\n`, { mode: 0o600 });
  } catch {
    // The log is best effort.
  }
}

function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}
