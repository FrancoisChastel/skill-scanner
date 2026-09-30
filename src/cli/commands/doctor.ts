import { scannerPaths } from "../../paths";
import { type DoctorReport, runDoctor } from "../../setup/doctor";
import { userHome } from "../../setup/harnesses";
import { tildify, tildifyText } from "../../setup/render";
import { findPackageRoot, selfCommand } from "../../setup/runtime";
import { bool, parseArgs } from "../args";
import { type Command, EXIT } from "../command";

const flags = {
  json: { type: "boolean", description: "Print the report as JSON" },
  live: { type: "boolean", description: "Also send one tiny request to the judge, when it is enabled" },
} as const;

export function renderDoctor(report: DoctorReport, home: string, logPath: string): string {
  const t = (s: string) => tildifyText(s, home);
  const width = Math.max(0, ...report.checks.map((c) => c.area.length));
  const out = [`skill-scanner doctor ${report.version}`, ""];
  for (const c of report.checks) {
    out.push(`  ${c.status.padEnd(4)}  ${c.area.padEnd(width)}  ${t(c.message)}`);
    if (c.fix && c.status !== "ok")
      out.push(`  ${"".padEnd(4)}  ${"".padEnd(width)}  ${c.status === "skip" ? "install" : "fix"}: ${t(c.fix)}`);
  }
  if (report.decisions.length > 0)
    out.push("", `Recent hook decisions (${tildify(logPath, home)}):`, ...report.decisions.map((d) => `  ${d}`));
  const count = (s: string) => report.checks.filter((c) => c.status === s).length;
  const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
  out.push("", `${plural(count("fail"), "failure")}, ${plural(count("warn"), "warning")}.`);
  return `${out.join("\n")}\n`;
}

export const doctorCommand: Command = {
  name: "doctor",
  summary: "Check that skill-scanner is installed and working in each coding agent",
  usage: "[--json] [--live]",
  flags,
  details:
    "Checks the hook runtime, each harness's hooks, plugin, or extension, the config, the optional judge and analyzers,\nand the state directory, and prints the exact command that fixes each problem. Exits 1 when any check fails.",
  async run(argv, io) {
    const args = parseArgs(argv, flags);
    const self = selfCommand(await findPackageRoot());
    const report = await runDoctor({ env: io.env, cwd: io.cwd, live: bool(args.flags.live), self });
    if (bool(args.flags.json)) io.stdout(`${JSON.stringify(report, null, 2)}\n`);
    else io.stdout(renderDoctor(report, userHome(io.env), scannerPaths(io.env).log));
    return report.ok ? EXIT.ok : EXIT.findings;
  },
};
