import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { isSeverity } from "./core/severity";
import type { Suppression } from "./core/suppress";
import type { Severity } from "./core/types";

/**
 * User configuration. It is read only from the user's own home (or an explicit `--config`),
 * never from the directory being scanned: a skill must not be able to ship its own allowlist.
 */

export type HookPolicy = "ask" | "allow" | "deny";
export const ANALYZER_NAMES = ["skillspector", "cisco", "gitleaks", "osv-scanner", "semgrep"] as const;
export type AnalyzerName = (typeof ANALYZER_NAMES)[number];

/**
 * When the jev judge runs. `auto` (the default): when a jev key is set, `SKILL_SCANNER_JEV_KEY` or
 * `TYPESAFE_API_KEY` (or the key of the host `provider` names), and otherwise the scan stays offline
 * without a word of error. `true`: also with a general gateway key (OpenRouter, Vercel AI Gateway),
 * and say when there is no key at all. `false`: never. Judging sends redacted skill text to the host.
 */
export type JudgeMode = boolean | "auto";

export interface JudgeConfig {
  readonly enabled: JudgeMode;
  readonly provider?: "typesafe" | "openrouter" | "vercel" | "cloudflare" | "ollama" | "custom";
  readonly model?: string;
  readonly baseUrl?: string;
  /** Cloudflare Workers AI account id (also `CLOUDFLARE_ACCOUNT_ID`). */
  readonly accountId?: string;
  readonly timeoutMs: number;
}

export interface Config {
  readonly blockAt: Severity;
  readonly warnAt: Severity;
  readonly ignore: readonly Suppression[];
  readonly judge: JudgeConfig;
  readonly analyzers: Readonly<Record<AnalyzerName, boolean>>;
  readonly semgrepConfig?: string;
  readonly hooks: {
    /** What a harness hook does when a skill install scans as `warn`. */
    readonly onWarn: HookPolicy;
    /** What a hook does when the scan itself fails (network error, unsupported source). */
    readonly onError: HookPolicy;
    /** Move newly written skills that scan as `block` to the quarantine directory. */
    readonly quarantine: boolean;
  };
}

export const DEFAULT_CONFIG: Config = Object.freeze({
  blockAt: "high",
  warnAt: "medium",
  ignore: [],
  judge: { enabled: "auto", timeoutMs: 15_000 },
  // gitleaks runs whenever it is installed: offline, fast, and its findings are rarely wrong.
  analyzers: { skillspector: false, cisco: false, gitleaks: true, "osv-scanner": false, semgrep: false },
  hooks: { onWarn: "ask", onError: "ask", quarantine: true },
} satisfies Config);

export function scannerHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.SKILL_SCANNER_HOME || join(homedir(), ".skill-scanner");
}

export const configPath = (env: NodeJS.ProcessEnv = process.env): string =>
  env.SKILL_SCANNER_CONFIG || join(scannerHome(env), "config.json");

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

export async function loadConfig(explicitPath?: string, env: NodeJS.ProcessEnv = process.env): Promise<Config> {
  const path = explicitPath ?? configPath(env);
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT" && !explicitPath) return DEFAULT_CONFIG;
    throw new ConfigError(`cannot read config ${path}: ${(e as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new ConfigError(`config ${path} is not valid JSON: ${(e as Error).message}`);
  }
  return parseConfig(raw, path);
}

export function parseConfig(raw: unknown, where = "config"): Config {
  const fail = (msg: string): never => {
    throw new ConfigError(`${where}: ${msg}`);
  };
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return fail("must be a JSON object");
  const o = raw as Record<string, unknown>;
  const known = new Set(["$schema", "blockAt", "warnAt", "ignore", "judge", "analyzers", "semgrepConfig", "hooks"]);
  for (const k of Object.keys(o)) if (!known.has(k)) fail(`unknown key "${k}"`);

  const sev = (k: string, d: Severity): Severity => {
    if (o[k] === undefined) return d;
    return isSeverity(o[k]) ? o[k] : fail(`${k} must be one of info, low, medium, high, critical`);
  };

  const ignore =
    o.ignore === undefined
      ? []
      : Array.isArray(o.ignore)
        ? o.ignore.map((s, i) => parseSuppression(s, `ignore[${i}]`, fail))
        : fail("ignore must be an array");

  const j = (o.judge ?? {}) as Record<string, unknown>;
  if (typeof j !== "object" || j === null || Array.isArray(j)) fail("judge must be an object");
  rejectUnknown(j, ["enabled", "provider", "model", "baseUrl", "accountId", "timeoutMs"], "judge", fail);
  const provider = j.provider;
  const providers = ["typesafe", "openrouter", "vercel", "cloudflare", "ollama", "custom"];
  if (provider !== undefined && !providers.includes(provider as string)) fail(`judge.provider must be one of ${providers.join(", ")}`);
  if (j.accountId !== undefined && (typeof j.accountId !== "string" || !/^[0-9a-f]{32}$/i.test(j.accountId)))
    fail("judge.accountId must be a Cloudflare account id (32 hex characters)");
  const judge: JudgeConfig = {
    enabled:
      j.enabled === undefined
        ? DEFAULT_CONFIG.judge.enabled
        : typeof j.enabled === "boolean" || j.enabled === "auto"
          ? j.enabled
          : fail('judge.enabled must be true, false, or "auto"'),
    timeoutMs:
      j.timeoutMs === undefined
        ? 15_000
        : Number.isInteger(j.timeoutMs) && (j.timeoutMs as number) > 0
          ? (j.timeoutMs as number)
          : fail("judge.timeoutMs must be a positive integer"),
    ...(provider ? { provider: provider as JudgeConfig["provider"] & string } : {}),
    ...(typeof j.model === "string" ? { model: j.model } : {}),
    ...(typeof j.baseUrl === "string" ? { baseUrl: j.baseUrl } : {}),
    ...(typeof j.accountId === "string" ? { accountId: j.accountId } : {}),
  } as JudgeConfig;

  const a = (o.analyzers ?? {}) as Record<string, unknown>;
  if (typeof a !== "object" || a === null || Array.isArray(a)) fail("analyzers must be an object");
  const analyzers = { ...DEFAULT_CONFIG.analyzers };
  for (const [k, v] of Object.entries(a)) {
    if (!(k in analyzers)) fail(`analyzers.${k} is not a known analyzer (${ANALYZER_NAMES.join(", ")})`);
    if (typeof v !== "boolean") fail(`analyzers.${k} must be a boolean`);
    analyzers[k as AnalyzerName] = v as boolean;
  }

  const h = (o.hooks ?? {}) as Record<string, unknown>;
  if (typeof h !== "object" || h === null || Array.isArray(h)) fail("hooks must be an object");
  rejectUnknown(h, ["onWarn", "onError", "quarantine"], "hooks", fail);
  const policy = (k: string, d: HookPolicy): HookPolicy => {
    const v = h[k];
    if (v === undefined) return d;
    return v === "ask" || v === "allow" || v === "deny" ? v : fail(`hooks.${k} must be ask, allow, or deny`);
  };
  const blockAt = sev("blockAt", DEFAULT_CONFIG.blockAt);
  const warnAt = sev("warnAt", DEFAULT_CONFIG.warnAt);
  return {
    blockAt,
    warnAt,
    ignore,
    judge,
    analyzers,
    ...(typeof o.semgrepConfig === "string" ? { semgrepConfig: o.semgrepConfig } : {}),
    hooks: {
      onWarn: policy("onWarn", DEFAULT_CONFIG.hooks.onWarn),
      onError: policy("onError", DEFAULT_CONFIG.hooks.onError),
      quarantine:
        h.quarantine === undefined
          ? DEFAULT_CONFIG.hooks.quarantine
          : typeof h.quarantine === "boolean"
            ? h.quarantine
            : fail("hooks.quarantine must be a boolean"),
    },
  };
}

/** A typo in a security setting must fail loudly, not fall back to a default. */
function rejectUnknown(obj: Record<string, unknown>, known: readonly string[], where: string, fail: (m: string) => never): void {
  for (const k of Object.keys(obj)) if (!known.includes(k)) fail(`unknown key "${where}.${k}"`);
}

function parseSuppression(v: unknown, where: string, fail: (m: string) => never): Suppression {
  if (typeof v !== "object" || v === null) return fail(`${where} must be an object`);
  const s = v as Record<string, unknown>;
  if (typeof s.rule !== "string" || s.rule === "") return fail(`${where}.rule must be a rule id`);
  rejectUnknown(s, ["rule", "path", "digest", "reason"], where, fail);
  for (const k of ["path", "digest", "reason"]) if (s[k] !== undefined && typeof s[k] !== "string") fail(`${where}.${k} must be a string`);
  if (typeof s.digest === "string" && !/^sha256:[0-9a-f]{64}$/.test(s.digest)) fail(`${where}.digest must look like sha256:<64 hex>`);
  return {
    rule: s.rule,
    ...(typeof s.path === "string" ? { path: s.path } : {}),
    ...(typeof s.digest === "string" ? { digest: s.digest } : {}),
    ...(typeof s.reason === "string" ? { reason: s.reason } : {}),
  };
}
