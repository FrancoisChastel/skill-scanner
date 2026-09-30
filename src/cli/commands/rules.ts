import type { RuleMeta } from "../../core/rule";
import { CATEGORIES, type Category } from "../../core/types";
import { knownRules } from "../../report";
import { inlineCode } from "../../report/markdown";
import { type FlagSpecs, parseArgs, str, UsageError } from "../args";
import { type Command, EXIT } from "../command";
import type { CliIO } from "../io";

type RulesFormat = "text" | "json" | "markdown";
const FORMATS: readonly RulesFormat[] = ["text", "json", "markdown"];

const FLAGS: FlagSpecs = {
  format: { type: "string", short: "f", value: "<format>", description: "text (default), json, or markdown" },
  category: { type: "string", short: "c", value: "<category>", description: `Only rules of one category (${CATEGORIES.join(", ")})` },
};

const DETAILS = `Severity is the default; a rule may raise or lower it for a specific match. "hard" rules
report evidence the jev judge can confirm but never doubt. Full descriptions: docs/rules.md.`;

/** Rules grouped by category, in category order, keeping catalog order inside each group. */
export function groupByCategory(rules: readonly RuleMeta[]): [Category, RuleMeta[]][] {
  return CATEGORIES.map((c) => [c, rules.filter((r) => r.category === c)] as [Category, RuleMeta[]]).filter(([, rs]) => rs.length > 0);
}

function asText(rules: readonly RuleMeta[]): string {
  const idWidth = Math.max(0, ...rules.map((r) => r.id.length));
  const out: string[] = [];
  for (const [category, group] of groupByCategory(rules)) {
    out.push(category);
    for (const r of group) {
      const hard = r.hard ? "  [hard]" : "";
      out.push(`  ${r.severity.toUpperCase().padEnd(8)}  ${r.confidence.padEnd(6)}  ${r.id.padEnd(idWidth)}  ${r.title}${hard}`);
    }
    out.push("");
  }
  out.push(`${rules.length} rules. Columns: default severity, confidence, id, title.`);
  return `${out.join("\n")}\n`;
}

function asJson(rules: readonly RuleMeta[]): string {
  const plain = rules.map((r) => ({
    id: r.id,
    title: r.title,
    category: r.category,
    severity: r.severity,
    confidence: r.confidence,
    hard: r.hard === true,
    description: r.description,
    ...(r.remediation ? { remediation: r.remediation } : {}),
  }));
  return `${JSON.stringify(plain, null, 2)}\n`;
}

const cell = (s: string): string => s.replace(/\r?\n/g, " ").replaceAll("|", "\\|");

function asMarkdown(rules: readonly RuleMeta[]): string {
  const out: string[] = [];
  for (const [category, group] of groupByCategory(rules)) {
    out.push(`### ${category}`, "", "| Rule | Severity | Confidence | Title |", "| --- | --- | --- | --- |");
    for (const r of group)
      out.push(`| ${cell(inlineCode(r.id))} | ${r.severity} | ${r.confidence} | ${cell(r.title)}${r.hard ? " (hard)" : ""} |`);
    out.push("");
  }
  return `${out.join("\n")}`;
}

async function run(argv: readonly string[], io: CliIO): Promise<number> {
  const { flags, positionals } = parseArgs(argv, FLAGS);
  if (positionals.length > 0) throw new UsageError(`unexpected argument "${positionals[0]}"`);
  const format = str(flags.format) ?? "text";
  if (!(FORMATS as readonly string[]).includes(format)) throw new UsageError(`--format must be text, json, or markdown, not "${format}"`);
  const category = str(flags.category);
  if (category !== undefined && !(CATEGORIES as readonly string[]).includes(category))
    throw new UsageError(`unknown category "${category}" (known: ${CATEGORIES.join(", ")})`);
  const rules = knownRules().filter((r) => category === undefined || r.category === category);
  const render = format === "json" ? asJson : format === "markdown" ? asMarkdown : asText;
  io.stdout(render(rules));
  return EXIT.ok;
}

export const rulesCommand: Command = {
  name: "rules",
  summary: "List the rules skill-scanner checks, with severity and confidence",
  usage: "[--format text|json|markdown] [--category <category>]",
  flags: FLAGS,
  details: DETAILS,
  run,
};
