import { open } from "node:fs/promises";
import { basename } from "node:path";
import { detectAnalyzers } from "../analyzers";
import { type Config, ConfigError, loadConfig } from "../config";
import { listQuarantine } from "../guard/quarantine";
import { describeJudge, pingJudge } from "../judge";
import type { ScannerPaths } from "../paths";
import type { Check } from "./doctor";
import { isObject } from "./json";
import { readText } from "./runtime";

/** Doctor checks that do not depend on a harness: config, judge, analyzers, and the decision log. */

export interface CheckContext {
  readonly env: NodeJS.ProcessEnv;
  readonly live: boolean;
  readonly self: string;
  readonly paths: ScannerPaths;
}

export async function environmentChecks(ctx: CheckContext): Promise<{ checks: Check[]; decisions: string[] }> {
  const { check: configCheck, config } = await checkConfig(ctx);
  const checks = [
    configCheck,
    ...(await judgeChecks(config, ctx)),
    ...(await analyzerChecks(config, ctx.env)),
    ...(await quarantineChecks(ctx)),
  ];
  return { checks, decisions: (await tailLines(ctx.paths.log, 5)).map(formatDecision) };
}

/** Skills moved aside because they scanned as block; listed so they are not forgotten. */
async function quarantineChecks(ctx: CheckContext): Promise<Check[]> {
  const records = await listQuarantine(ctx.env);
  if (records.length === 0) return [];
  const names = records.slice(-3).map((r) => basename(r.originalPath));
  const more = records.length > names.length ? `, and ${records.length - names.length} more` : "";
  const message = `${records.length} skill${records.length === 1 ? "" : "s"} moved aside after scanning as block (${names.join(", ")}${more}), in ${ctx.paths.quarantine}`;
  return [{ area: "quarantine", status: "ok", message }];
}

async function checkConfig(ctx: CheckContext): Promise<{ check: Check; config?: Config }> {
  const path = ctx.paths.config;
  try {
    const config = await loadConfig(undefined, ctx.env);
    const where = (await readText(path)) === undefined ? "defaults (no config file)" : path;
    return { check: { area: "config", status: "ok", message: `${where}: blockAt ${config.blockAt}, warnAt ${config.warnAt}` }, config };
  } catch (e) {
    if (!(e instanceof ConfigError)) throw e;
    return { check: { area: "config", status: "fail", message: e.message, fix: `fix or delete ${path}` } };
  }
}

async function judgeChecks(config: Config | undefined, ctx: CheckContext): Promise<Check[]> {
  const area = "judge";
  if (!config) return [{ area, status: "skip", message: "not checked (the config does not load)" }];
  if (!config.judge.enabled)
    return [
      {
        area,
        status: "skip",
        message: `off (optional second opinion; turn on with "judge": {"enabled": true} in the config or --judge)${ctx.live ? "; --live skipped" : ""}`,
      },
    ];
  const d = describeJudge(config.judge, ctx.env);
  if (d.problem) return [{ area, status: "warn", message: `enabled but unusable: ${d.problem}` }];
  const desc = [d.provider, d.model].filter(Boolean).join(" ");
  const checks: Check[] = [{ area, status: "ok", message: `${desc}${d.keyEnv ? ` (key from $${d.keyEnv})` : ""}` }];
  if (ctx.live) {
    const ping = await pingJudge(config.judge, ctx.env);
    checks.push({ area, status: ping.ok ? "ok" : "fail", message: `live request: ${ping.detail}` });
  }
  return checks;
}

async function analyzerChecks(config: Config | undefined, env: NodeJS.ProcessEnv): Promise<Check[]> {
  const found = await detectAnalyzers(env);
  return found.map(({ info, path, version }): Check => {
    const network = info.network ? "; contacts the network when it runs" : "";
    if (path) return { area: info.name, status: "ok", message: `${info.title}${version ? ` ${version}` : ""} at ${path}${network}` };
    if (config?.analyzers[info.name])
      return { area: info.name, status: "warn", message: `${info.title} is enabled in the config but not installed`, fix: info.install };
    return { area: info.name, status: "skip", message: `${info.title}: not installed (optional)${network}`, fix: info.install };
  });
}

/** The last `n` non-empty lines of a file, reading at most the final 64 KiB. */
export async function tailLines(path: string, n: number, maxBytes = 64 * 1024): Promise<string[]> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(path, "r");
    const { size } = await handle.stat();
    const length = Math.min(size, maxBytes);
    const buf = Buffer.alloc(length);
    await handle.read(buf, 0, length, size - length);
    const lines = buf.toString("utf8").split("\n");
    if (size > length) lines.shift();
    return lines.filter((l) => l.trim() !== "").slice(-n);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw e;
  } finally {
    await handle?.close();
  }
}

const clip = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 3)}...` : s);

/** One decision-log record as a line: time, harness, event, action, subject. Unknown shapes print raw, clipped. */
export function formatDecision(line: string): string {
  let rec: unknown;
  try {
    rec = JSON.parse(line);
  } catch {
    return clip(line.trim(), 160);
  }
  if (!isObject(rec)) return clip(line.trim(), 160);
  const pick = (...keys: string[]): string | undefined => {
    for (const k of keys) if (typeof rec[k] === "string" && rec[k] !== "") return rec[k] as string;
    return undefined;
  };
  const action = pick("action", "decision");
  const verdict = pick("verdict");
  const counts = ["flagged", "quarantined"].flatMap((k) => (Array.isArray(rec[k]) && rec[k].length > 0 ? [`${k} ${rec[k].length}`] : []));
  const parts = [
    pick("ts", "time", "at", "timestamp"),
    pick("harness"),
    pick("kind", "event", "hook"),
    action && verdict && verdict !== action ? `${action} (${verdict})` : (action ?? verdict),
    pick("name", "target", "skill", "path", "command", "reason"),
    counts.length > 0 ? counts.join(", ") : undefined,
  ].filter((p): p is string => p !== undefined);
  return parts.length > 0 ? clip(parts.join("  "), 200) : clip(line.trim(), 160);
}
