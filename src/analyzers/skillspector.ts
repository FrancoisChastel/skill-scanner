import { join } from "node:path";
import type { Category, Finding } from "../core/types";
import {
  categoryFrom,
  expectArray,
  expectExit,
  expectObject,
  externalFinding,
  isObject,
  type JsonObject,
  parseJson,
  posInt,
  readReport,
  relativeFile,
  severityFrom,
  str,
  toolAnalyzer,
} from "./common";
import { which } from "./run";
import type { AnalyzerInfo, ToolDriver } from "./types";

/**
 * NVIDIA SkillSpector (Apache-2.0), https://github.com/NVIDIA/skillspector. Console script
 * `skillspector` (pyproject `[project.scripts]`). Invoked as (verified with 2.12.0):
 *
 *   skillspector scan <root> --no-llm --format json --output <tmp>/skillspector.json
 *
 * `--no-llm` keeps it to static analysis (src/skillspector/cli.py). Its SC4 check still posts package
 * names to api.osv.dev; `SKILLSPECTOR_OSV_TIMEOUT=0` spends that budget before the first request, so it
 * uses its bundled fallback list instead (nodes/analyzers/osv_client.py). A skill's shipped baseline is
 * not applied without `--use-shipped-baseline`, which is never passed. Exit codes: 0 pass, 1 risk above
 * its threshold, 2 error. The JSON report lists findings under `issues`.
 */

export const SKILLSPECTOR_INFO: AnalyzerInfo = {
  name: "skillspector",
  title: "NVIDIA SkillSpector",
  binary: "skillspector",
  install: "uv tool install git+https://github.com/NVIDIA/skillspector.git",
  homepage: "https://github.com/NVIDIA/skillspector",
  license: "Apache-2.0",
  network: false,
  description:
    "Static skill analysis: prompt injection, exfiltration, dangerous code, YARA and AST checks. Run with --no-llm and OSV lookups off.",
};

const OK_CODES = [0, 1];

export function skillspectorArgs(root: string, report: string): string[] {
  return ["scan", root, "--no-llm", "--format", "json", "--output", report];
}

/** SkillSpector's PatternCategory values and analyzer tags (nodes/analyzers/pattern_defaults.py). */
const CATEGORY_MAP: Readonly<Record<string, Category>> = {
  "prompt injection": "prompt-injection",
  "system prompt leakage": "prompt-injection",
  "anti-refusal": "prompt-injection",
  "mcp tool poisoning": "prompt-injection",
  "trigger abuse": "prompt-injection",
  "data exfiltration": "exfiltration",
  "data flow": "exfiltration",
  "privilege escalation": "privilege",
  "supply chain": "supply-chain",
  "excessive agency": "execution-surface",
  "output handling": "execution-surface",
  "tool misuse": "execution-surface",
  "rogue agent": "execution-surface",
  "mcp least privilege": "execution-surface",
  "memory poisoning": "persistence",
  "mcp rug pull": "persistence",
  "agent snooping": "credential-access",
  "server-side request forgery": "network",
  "insecure deserialization": "remote-execution",
  "dangerous code execution": "remote-execution",
  "analysis-evasion": "obfuscation",
};

function categoryOf(issue: JsonObject): Category {
  const raw = str(issue.category);
  return (raw ? CATEGORY_MAP[raw.toLowerCase()] : undefined) ?? categoryFrom([raw, str(issue.pattern), str(issue.id)]);
}

function issueFinding(issue: JsonObject, root: string): Finding {
  const id = str(issue.id) ?? "unknown-rule";
  const loc = isObject(issue.location) ? issue.location : {};
  const column = typeof loc.start_column === "number" && Number.isInteger(loc.start_column) ? loc.start_column + 1 : undefined;
  return externalFinding("skillspector", {
    toolRule: id,
    title: str(issue.pattern) ?? `SkillSpector ${id}`,
    category: categoryOf(issue),
    severity: severityFrom(issue.severity),
    message: str(issue.explanation) ?? str(issue.message) ?? str(issue.pattern) ?? "SkillSpector finding.",
    file: relativeFile(root, str(loc.file) ?? "."),
    line: posInt(loc.start_line),
    // SkillSpector columns are zero-based.
    column,
    endLine: posInt(loc.end_line),
    snippet: str(issue.finding) ?? str(issue.code_snippet),
    remediation: str(issue.remediation),
  });
}

/** Findings from a SkillSpector JSON report. */
export function parseSkillspectorOutput(text: string, root: string): Finding[] {
  const report = expectObject(parseJson(text, "skillspector"), "skillspector", "the report");
  if (report.execution_successful === false) throw new Error("skillspector reported that its scan did not complete");
  return expectArray(report.issues, "skillspector", "issues")
    .filter(isObject)
    .map((issue) => issueFinding(issue, root));
}

export const skillspectorDriver: ToolDriver = {
  info: SKILLSPECTOR_INFO,
  locate: (env) => which("skillspector", env),
  versionArgs: ["--version"],
  toolEnv: (env) => ({
    ...env,
    SKILLSPECTOR_OSV_TIMEOUT: "0",
    // LangGraph/LangSmith tracing would upload the run; keep it off whatever the user's shell says.
    LANGSMITH_TRACING: "false",
    LANGCHAIN_TRACING_V2: "false",
    NO_COLOR: "1",
  }),
  network: () => false,
  create: (env) =>
    toolAnalyzer(skillspectorDriver, env, async ({ root, workDir, exec }) => {
      const report = join(workDir, "skillspector.json");
      expectExit("skillspector", await exec(skillspectorArgs(root, report)), OK_CODES);
      const text = await readReport(report, "skillspector");
      if (text === undefined) throw new Error("skillspector did not write its report");
      return parseSkillspectorOutput(text, root);
    }),
};
