import { ConfigError } from "../config";
import { TOOL_NAME, VERSION } from "../version";
import { formatFlags, UsageError } from "./args";
import { type Command, EXIT } from "./command";
import { addCommand } from "./commands/add";
import { auditCommand } from "./commands/audit";
import { doctorCommand } from "./commands/doctor";
import { guardCommand } from "./commands/guard";
import { hookCommand } from "./commands/hook";
import { rulesCommand } from "./commands/rules";
import { scanCommand } from "./commands/scan";
import { setupCommand } from "./commands/setup";
import { trustCommand } from "./commands/trust";
import type { CliIO } from "./io";

export const COMMANDS: readonly Command[] = [
  scanCommand,
  addCommand,
  auditCommand,
  guardCommand,
  setupCommand,
  doctorCommand,
  trustCommand,
  rulesCommand,
  hookCommand,
];

export function helpText(): string {
  const width = Math.max(...COMMANDS.map((c) => c.name.length));
  return [
    `${TOOL_NAME} ${VERSION}: scan Agent Skills before your coding agent installs them.`,
    "",
    "Usage:",
    `  ${TOOL_NAME} <command> [options]`,
    "",
    "Commands:",
    ...COMMANDS.filter((c) => c.name !== "hook").map((c) => `  ${c.name.padEnd(width)}  ${c.summary}`),
    "",
    `Run \`${TOOL_NAME} help <command>\` for a command's options.`,
    "Docs: https://github.com/FrancoisChastel/skill-scanner#readme",
    "",
  ].join("\n");
}

export function commandHelp(c: Command): string {
  return [
    `${c.summary}`,
    "",
    "Usage:",
    ...c.usage.split("\n").map((u) => `  ${TOOL_NAME} ${c.name} ${u}`),
    "",
    ...(Object.keys(c.flags).length > 0 ? ["Options:", formatFlags(c.flags), ""] : []),
    ...(c.details ? [c.details.trimEnd(), ""] : []),
  ].join("\n");
}

export async function main(argv: readonly string[], io: CliIO): Promise<number> {
  const [first, ...rest] = argv;
  if (first === undefined || first === "help" || first === "--help" || first === "-h") {
    const target = first === "help" ? COMMANDS.find((c) => c.name === rest[0]) : undefined;
    if (first === "help" && rest[0] !== undefined && !target) {
      io.stderr(`${TOOL_NAME}: unknown command "${rest[0]}". Run \`${TOOL_NAME} help\`.\n`);
      return EXIT.error;
    }
    io.stdout(target ? commandHelp(target) : helpText());
    return first === undefined ? EXIT.error : EXIT.ok;
  }
  if (first === "--version" || first === "-v" || first === "version") {
    io.stdout(`${VERSION}\n`);
    return EXIT.ok;
  }
  const command = COMMANDS.find((c) => c.name === first);
  if (!command) {
    io.stderr(`${TOOL_NAME}: unknown command "${first}". Run \`${TOOL_NAME} help\`.\n`);
    return EXIT.error;
  }
  if (rest.includes("--help") || rest.includes("-h")) {
    if (command.name !== "add" && command.name !== "guard") {
      io.stdout(commandHelp(command));
      return EXIT.ok;
    }
  }
  try {
    return await command.run(rest, io);
  } catch (e) {
    if (e instanceof UsageError) {
      io.stderr(`${TOOL_NAME} ${command.name}: ${e.message}\nRun \`${TOOL_NAME} help ${command.name}\`.\n`);
      return EXIT.error;
    }
    if (e instanceof ConfigError) {
      io.stderr(`${TOOL_NAME}: ${e.message}\n`);
      return EXIT.error;
    }
    io.stderr(`${TOOL_NAME} ${command.name}: ${e instanceof Error ? e.message : String(e)}\n`);
    if (io.env.SKILL_SCANNER_DEBUG && e instanceof Error && e.stack) io.stderr(`${e.stack}\n`);
    return EXIT.error;
  }
}
