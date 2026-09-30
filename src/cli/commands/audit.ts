import { resolve } from "node:path";
import { loadConfig } from "../../config";
import { auditInstalledDetailed } from "../../guard/audit";
import { homeOf } from "../../guard/fsutil";
import { skillRoots } from "../../guard/locations";
import { listQuarantine, restoreQuarantined } from "../../guard/quarantine";
import { quarantineBlocked } from "../../guard/reconcile";
import type { GuardContext, Harness, InstalledSkill, QuarantineRecord, SkillRoot } from "../../guard/types";
import { bool, type FlagSpecs, list, parseArgs, str, UsageError } from "../args";
import { type Command, EXIT } from "../command";
import type { CliIO } from "../io";

const HARNESSES: readonly Harness[] = ["claude-code", "codex", "opencode", "pi"];
/** The CLI waits for every scan; hooks are the ones with short deadlines. */
const CLI_DEADLINE_MS = 60 * 60 * 1000;

const FLAGS: FlagSpecs = {
  harness: {
    type: "string",
    multiple: true,
    value: "<harness>",
    description: "claude-code, codex, opencode, pi, or all (repeatable; default all)",
  },
  project: { type: "string", value: "<dir>", description: "Project whose skill folders to include (default: the current directory)" },
  format: { type: "string", short: "f", value: "<format>", description: "text or json (default text)" },
  quarantine: { type: "boolean", description: "Move blocked, untrusted skill directories to the quarantine directory" },
  "list-quarantine": { type: "boolean", description: "List quarantined skills" },
  restore: { type: "string", value: "<id>", description: "Put a quarantined skill back where it was" },
  cache: { type: "boolean", description: "Reuse results for unchanged skills (default); --no-cache rescans everything" },
  config: { type: "string", value: "<file>", description: "Config file (default ~/.skill-scanner/config.json)" },
};

export const auditCommand: Command = {
  name: "audit",
  summary: "Scan every installed skill and plugin, and flag, quarantine, or restore them",
  usage: "[--harness <h>] [--project <dir>] [--format text|json] [--quarantine] [--no-cache]\n--list-quarantine\n--restore <id>",
  flags: FLAGS,
  details: `Looks in every skill directory Claude Code, Codex, OpenCode, and Pi load from (user, project,
system, plugin caches), scans each skill once even when it is linked into several harnesses, and
updates the registry that hooks use to block flagged skills at use time.

Exit codes: 0 when nothing untrusted blocks, 1 when a blocked, untrusted skill remains installed.`,
  async run(argv, io) {
    const { flags, positionals } = parseArgs(argv, FLAGS);
    if (positionals.length > 0) throw new UsageError(`unexpected argument "${positionals[0]}"`);
    const format = str(flags.format) ?? "text";
    if (format !== "text" && format !== "json") throw new UsageError(`--format must be text or json, not "${format}"`);
    if (bool(flags["list-quarantine"])) return printQuarantine(await listQuarantine(io.env), format, io);
    const restore = str(flags.restore);
    if (restore !== undefined) return restoreOne(restore, io);
    return runAudit(flags, format, io);
  },
};

async function runAudit(flags: Readonly<Record<string, unknown>>, format: "text" | "json", io: CliIO): Promise<number> {
  const harnesses = parseHarnesses(list(flags.harness));
  const cwd = resolve(io.cwd, str(flags.project) ?? ".");
  const config = await loadConfig(str(flags.config), io.env);
  const roots = uniqueRoots(harnesses.flatMap((h) => skillRoots(h, cwd, io.env)));
  const ctx: GuardContext = { harness: harnesses[0] ?? "claude-code", cwd, env: io.env, config };
  const audit = await auditInstalledDetailed(ctx, { roots, useCache: flags.cache !== false, deadlineMs: CLI_DEADLINE_MS });
  const moved = bool(flags.quarantine) ? await quarantineBlocked(audit.skills, ctx, roots, "quarantined by skill-scanner audit") : [];
  const remaining = audit.skills.filter((s) => s.verdict === "block" && !s.trusted && !moved.includes(s.path));
  if (format === "json") io.stdout(`${JSON.stringify(audit.skills, null, 2)}\n`);
  else io.stdout(auditText(audit.skills, moved, audit, io.env));
  for (const e of audit.errors) io.stderr(`skill-scanner audit: could not scan ${e.path}: ${e.message}\n`);
  return remaining.length > 0 ? EXIT.findings : EXIT.ok;
}

function parseHarnesses(values: readonly string[]): Harness[] {
  if (values.length === 0 || values.includes("all")) return [...HARNESSES];
  for (const v of values)
    if (!HARNESSES.includes(v as Harness)) throw new UsageError(`unknown harness "${v}" (${HARNESSES.join(", ")}, or all)`);
  return [...new Set(values as Harness[])];
}

function uniqueRoots(roots: readonly SkillRoot[]): SkillRoot[] {
  const seen = new Set<string>();
  return roots.filter((r) => {
    if (seen.has(r.path)) return false;
    seen.add(r.path);
    return true;
  });
}

const tilde = (p: string, env: NodeJS.ProcessEnv): string => {
  const home = homeOf(env);
  return p === home || p.startsWith(`${home}/`) ? `~${p.slice(home.length)}` : p;
};

function verdictCell(s: InstalledSkill, moved: readonly string[]): string {
  if (moved.includes(s.path)) return `${s.verdict} (quarantined)`;
  return s.trusted && s.verdict !== "pass" ? `${s.verdict} (trusted)` : s.verdict;
}

export function auditText(
  skills: readonly InstalledSkill[],
  moved: readonly string[],
  audit: { readonly stats: { readonly cached: number; readonly durationMs: number } },
  env: NodeJS.ProcessEnv,
): string {
  if (skills.length === 0) return "No installed skills found.\n";
  const rows = skills.map((s) => [verdictCell(s, moved), s.harness, s.scope, s.name, tilde(s.path, env), s.summary[0] ?? ""]);
  const header = ["VERDICT", "HARNESS", "SCOPE", "NAME", "PATH", "TOP FINDING"];
  const widths = header.slice(0, 5).map((h, i) => Math.max(h.length, ...rows.map((r) => r[i]!.length)));
  const line = (cells: readonly string[]): string =>
    `${cells
      .map((c, i) => (i < 5 ? c.padEnd(widths[i]!) : c.length > 100 ? `${c.slice(0, 97)}...` : c))
      .join("  ")
      .trimEnd()}\n`;
  const count = (v: string): number => skills.filter((s) => s.verdict === v).length;
  const trusted = skills.filter((s) => s.trusted && s.verdict !== "pass").length;
  const footer = `\n${skills.length} installed: ${count("block")} blocked, ${count("warn")} with warnings, ${count("pass")} passed${
    trusted > 0 ? `; ${trusted} trusted` : ""
  }${moved.length > 0 ? `; ${moved.length} moved to quarantine` : ""} (${audit.stats.cached} from cache, ${audit.stats.durationMs} ms).\n`;
  return [line(header), ...rows.map(line), footer].join("");
}

function printQuarantine(records: readonly QuarantineRecord[], format: "text" | "json", io: CliIO): number {
  if (format === "json") {
    io.stdout(`${JSON.stringify(records, null, 2)}\n`);
    return EXIT.ok;
  }
  if (records.length === 0) {
    io.stdout("Nothing is in quarantine.\n");
    return EXIT.ok;
  }
  for (const r of records)
    io.stdout(`${r.id}\n  from   ${tilde(r.originalPath, io.env)}\n  reason ${r.reason}\n  when   ${r.quarantinedAt}\n`);
  io.stdout("\nRestore one with `skill-scanner audit --restore <id>`.\n");
  return EXIT.ok;
}

async function restoreOne(id: string, io: CliIO): Promise<number> {
  const rec = await restoreQuarantined(id, io.env);
  io.stdout(`Restored ${tilde(rec.realPath, io.env)}${rec.links.length > 0 ? ` and ${rec.links.length} link(s)` : ""}.\n`);
  io.stdout("It will be flagged again unless you approve this exact version with `skill-scanner trust`.\n");
  return EXIT.ok;
}
