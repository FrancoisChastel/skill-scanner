import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { loadConfig } from "../../config";
import type { ScanReport } from "../../core/types";
import { addTrust, loadTrust, removeTrust } from "../../guard/state";
import type { TrustEntry } from "../../guard/types";
import { scanPath } from "../../scan";
import { userHome } from "../../setup/harnesses";
import { tildify } from "../../setup/render";
import { bool, parseArgs, str, UsageError } from "../args";
import { type Command, EXIT } from "../command";
import type { CliIO } from "../io";

const flags = {
  reason: { type: "string", value: "<text>", description: "Why you trust it; kept in the trust list" },
  list: { type: "boolean", description: "List trusted skills" },
  remove: {
    type: "string",
    value: "<digest|name>",
    description: "Stop trusting a skill, by digest (a unique prefix is enough), name, or path",
  },
  yes: { type: "boolean", short: "y", description: "Trust without asking (required when there is no terminal)" },
  json: { type: "boolean", description: "With --list: print JSON" },
} as const;

const details = `
Trust approves exact contents, not a name: the digest covers every file of the skill, so any change
(an update, one edited line) flags it again. Trusted skills pass the install and use-time gates of the
hooks, the OpenCode plugin, and the Pi extension despite their findings. \`trust <path>\` scans first and
shows what you are approving.
`.trim();

const MAX_SHOWN = 5;
const shortDigest = (d: string): string => d.slice(0, "sha256:".length + 12);

export function renderTrustSummary(report: ScanReport, target: string, home: string): string {
  const findings = report.bundles.reduce((n, b) => n + b.findings.length, 0);
  const out = [
    `Scanned ${tildify(target, home)}: ${report.verdict.toUpperCase()} (${report.bundles.length} bundle(s), ${findings} finding(s))`,
  ];
  for (const b of report.bundles) {
    out.push(`  ${b.bundle.name}  ${b.verdict}  ${shortDigest(b.bundle.digest)}`);
    for (const f of b.findings.slice(0, MAX_SHOWN)) {
      const where = `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}`;
      out.push(`    ${f.severity.padEnd(8)}  ${f.ruleId}  ${where}  ${f.title}`);
    }
    if (b.findings.length > MAX_SHOWN) out.push(`    ... and ${b.findings.length - MAX_SHOWN} more (run \`skill-scanner scan\` for all)`);
  }
  return `${out.join("\n")}\n`;
}

export function renderTrustList(entries: readonly TrustEntry[], home: string): string {
  if (entries.length === 0) return "No trusted skills.\n";
  const rows = [
    ["DIGEST", "NAME", "TRUSTED", "PATH", "REASON"],
    ...entries.map((e) => [shortDigest(e.digest), e.name, e.trustedAt.slice(0, 10), tildify(e.path, home), e.reason ?? ""]),
  ];
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map((r) => r[i]!.length)));
  return `${rows
    .map((r) =>
      r
        .map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i]!)))
        .join("  ")
        .trimEnd(),
    )
    .join("\n")}\n`;
}

async function listTrust(io: CliIO, json: boolean): Promise<number> {
  const { entries } = await loadTrust(io.env);
  io.stdout(json ? `${JSON.stringify(entries, null, 2)}\n` : renderTrustList(entries, userHome(io.env)));
  return EXIT.ok;
}

/**
 * Full digests a `--remove` argument names by prefix (the list shows 12 hex digits), or undefined when
 * it is not a digest prefix, so it is matched as a name or path instead.
 */
export function digestsByPrefix(match: string, entries: readonly TrustEntry[]): string[] | undefined {
  const wanted = match.startsWith("sha256:") ? match : `sha256:${match}`;
  if (!/^sha256:[0-9a-f]{6,64}$/.test(wanted)) return undefined;
  const found = [...new Set(entries.filter((e) => e.digest.startsWith(wanted)).map((e) => e.digest))];
  return found.length > 0 ? found : undefined;
}

async function untrust(io: CliIO, match: string): Promise<number> {
  const digests = digestsByPrefix(match.trim(), (await loadTrust(io.env)).entries);
  if (digests && digests.length > 1) {
    io.stderr(`skill-scanner trust: "${match}" matches ${digests.length} digests; give more of the digest.\n`);
    return EXIT.error;
  }
  const removed = await removeTrust(digests?.[0] ?? match, io.env);
  const n = removed.length;
  if (n === 0) {
    io.stderr(`skill-scanner trust: no trusted skill matches "${match}". See \`skill-scanner trust --list\`.\n`);
    return EXIT.error;
  }
  io.stdout(
    `Removed ${n} trusted entr${n === 1 ? "y" : "ies"} matching "${match}". The next scan flags them again if they have findings.\n`,
  );
  return EXIT.ok;
}

async function trustPath(io: CliIO, input: string, reason: string | undefined, yes: boolean): Promise<number> {
  const target = resolve(io.cwd, input);
  if (!(await stat(target).catch(() => undefined))) throw new UsageError(`no such file or directory: ${input}`);
  const config = await loadConfig(undefined, io.env);
  const report = await scanPath(target, { policy: { blockAt: config.blockAt, warnAt: config.warnAt }, suppressions: config.ignore });
  const home = userHome(io.env);
  io.stdout(renderTrustSummary(report, target, home));
  if (report.bundles.length === 0) {
    io.stderr("skill-scanner trust: found nothing to trust there.\n");
    return EXIT.error;
  }
  if (!yes) {
    if (!io.isTTY) {
      io.stderr("skill-scanner trust: no terminal to confirm on. Re-run with --yes to trust these exact contents.\n");
      return EXIT.error;
    }
    const question = `Trust ${report.bundles.length === 1 ? "this skill" : `these ${report.bundles.length} bundles`} at exactly these contents? Any change flags it again.`;
    if (!(await io.confirm(question))) {
      io.stdout("Nothing was trusted.\n");
      return EXIT.findings;
    }
  }
  const trustedAt = new Date().toISOString();
  for (const b of report.bundles)
    await addTrust(
      { digest: b.bundle.digest, name: b.bundle.name, path: resolve(target, b.bundle.root), ...(reason ? { reason } : {}), trustedAt },
      io.env,
    );
  const names = report.bundles.map((b) => `${b.bundle.name} (${shortDigest(b.bundle.digest)})`).join(", ");
  io.stdout(`Trusted ${names}. Undo with \`skill-scanner trust --remove <digest|name>\`.\n`);
  return EXIT.ok;
}

export const trustCommand: Command = {
  name: "trust",
  summary: "Approve a skill's exact contents despite its findings, or list and remove approvals",
  usage: "<path> [--reason <text>] [--yes]\n--list [--json]\n--remove <digest|name>",
  flags,
  details,
  async run(argv, io) {
    const args = parseArgs(argv, flags);
    const remove = str(args.flags.remove);
    if (bool(args.flags.list)) return listTrust(io, bool(args.flags.json));
    if (remove !== undefined) return untrust(io, remove);
    const [target, ...extra] = args.positionals;
    if (!target) throw new UsageError("give the path of a skill to trust, or --list, or --remove <digest|name>");
    if (extra.length > 0) throw new UsageError("trust one path at a time");
    return trustPath(io, target, str(args.flags.reason), bool(args.flags.yes));
  },
};
