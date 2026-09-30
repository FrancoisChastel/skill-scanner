import { open } from "node:fs/promises";
import { isAbsolute, join, posix } from "node:path";
import type { Category, Finding } from "../core/types";
import {
  categoryFrom,
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
import { executableIn, pathDirs } from "./run";
import type { AnalyzerInfo, ToolDriver } from "./types";

/**
 * Cisco AI Defense Skill Scanner (Apache-2.0), https://github.com/cisco-ai-defense/skill-scanner,
 * PyPI `cisco-ai-skill-scanner`. Invoked as (verified with 2.1.0):
 *
 *   <cisco skill-scanner> scan-all <root> --recursive --format json --output-json <tmp>/cisco.json
 *
 * Only the default core analyzers run (static, bytecode, pipeline); the LLM, VirusTotal, AI Defense,
 * and OSV analyzers are opt-in flags that are never passed (skill_scanner/cli/cli.py). `scan-all
 * --recursive` finds every SKILL.md under the root, the root itself included. Exit codes: 0 done,
 * 1 error or "No skills found to scan." (no report written).
 *
 * Its console script is also called `skill-scanner`, like ours. Cisco's is recognized without running
 * it: a pip or uv entry-point script that imports its CLI module, or one that sits next to the
 * `skill-scanner-api` / `skill-scanner-pre-commit` scripts the same package installs. Node scripts
 * (ours) are never taken, and every PATH entry is checked, so ours shadowing it does not hide it.
 */

export const CISCO_INFO: AnalyzerInfo = {
  name: "cisco",
  title: "Cisco AI Defense Skill Scanner",
  binary: "skill-scanner",
  install: "uv tool install cisco-ai-skill-scanner",
  homepage: "https://github.com/cisco-ai-defense/skill-scanner",
  license: "Apache-2.0",
  network: false,
  description:
    "Cisco's static skill analyzers (signatures, YARA, bytecode, pipeline taint). Offline core only: no LLM, VirusTotal, or AI Defense.",
};

// Assembled at run time so this file, once bundled into our own CLI, does not contain the marker it looks for.
const ENTRY_MARKER = `${["skill", "scanner"].join("_")}.cli`;
const SIBLING_SCRIPTS = ["skill-scanner-api", "skill-scanner-pre-commit"];
/** Enough for a Windows launcher .exe, whose script is appended after the launcher. */
const HEAD_BYTES = 512 * 1024;
const NO_SKILLS = "No skills found to scan";

async function readHead(path: string): Promise<string> {
  const handle = await open(path, "r");
  try {
    const buf = Buffer.alloc(HEAD_BYTES);
    const { bytesRead } = await handle.read(buf, 0, HEAD_BYTES, 0);
    return buf.subarray(0, bytesRead).toString("latin1");
  } finally {
    await handle.close();
  }
}

type ScriptKind = "cisco" | "node" | "other";

async function scriptKind(path: string): Promise<ScriptKind> {
  let head: string;
  try {
    head = await readHead(path);
  } catch {
    return "other";
  }
  const newline = head.indexOf("\n");
  const firstLine = newline === -1 ? head : head.slice(0, newline);
  if (firstLine.startsWith("#!") && /\bnode\b/.test(firstLine)) return "node";
  return head.includes(ENTRY_MARKER) ? "cisco" : "other";
}

/** Cisco's `skill-scanner` on PATH, told apart from ours by content or by its sibling scripts. */
export async function locateCisco(env: NodeJS.ProcessEnv): Promise<string | undefined> {
  for (const dir of pathDirs(env)) {
    const candidate = await executableIn(dir, "skill-scanner", env);
    if (!candidate) continue;
    const kind = await scriptKind(candidate);
    if (kind === "cisco") return candidate;
    if (kind === "node") continue;
    for (const sibling of SIBLING_SCRIPTS) if (await executableIn(dir, sibling, env)) return candidate;
  }
  return undefined;
}

export function ciscoArgs(root: string, report: string): string[] {
  return ["scan-all", root, "--recursive", "--format", "json", "--output-json", report];
}

/** Cisco's ThreatCategory values (skill_scanner/core/models.py). */
const CATEGORY_MAP: Readonly<Record<string, Category>> = {
  prompt_injection: "prompt-injection",
  social_engineering: "prompt-injection",
  harmful_content: "prompt-injection",
  skill_discovery_abuse: "prompt-injection",
  command_injection: "remote-execution",
  malware: "remote-execution",
  data_exfiltration: "exfiltration",
  hardcoded_secrets: "secrets",
  obfuscation: "obfuscation",
  unicode_steganography: "hidden-content",
  unauthorized_tool_use: "execution-surface",
  autonomy_abuse: "execution-surface",
  tool_chaining_abuse: "execution-surface",
  resource_abuse: "destructive",
  policy_violation: "metadata",
  transitive_trust_abuse: "supply-chain",
  supply_chain_attack: "supply-chain",
};

function categoryOf(f: JsonObject): Category {
  const raw = str(f.category);
  return (raw ? CATEGORY_MAP[raw.toLowerCase()] : undefined) ?? categoryFrom([raw, str(f.rule_id), str(f.title)]);
}

/** Cisco reports paths relative to each skill directory; ours are relative to the scan root. */
function fileOf(root: string, skillDir: string, filePath: string | undefined): string {
  if (!filePath) return relativeFile(root, posix.join(skillDir, "SKILL.md"));
  return isAbsolute(filePath) ? relativeFile(root, filePath) : relativeFile(root, posix.join(skillDir, filePath));
}

function toFinding(f: JsonObject, root: string, skillDir: string): Finding {
  const ruleId = str(f.rule_id) ?? str(f.id) ?? "unknown-rule";
  return externalFinding("cisco", {
    toolRule: ruleId,
    title: str(f.title) ?? ruleId,
    category: categoryOf(f),
    severity: severityFrom(f.severity),
    message: str(f.description) ?? str(f.title) ?? "Cisco skill-scanner finding.",
    file: fileOf(root, skillDir, str(f.file_path)),
    line: posInt(f.line_number),
    snippet: str(f.snippet),
    remediation: str(f.remediation),
  });
}

/** Findings from Cisco's JSON: a multi-skill report (`results`) or a single skill result (`findings`). */
export function parseCiscoOutput(text: string, root: string): Finding[] {
  const report = expectObject(parseJson(text, "cisco"), "cisco", "the report");
  const results = Array.isArray(report.results) ? report.results.filter(isObject) : Array.isArray(report.findings) ? [report] : undefined;
  if (!results) throw new Error("cisco output is not in the expected format: no results or findings array");
  return results.flatMap((r) => {
    const skillDir = relativeFile(root, str(r.skill_path) ?? ".");
    const findings = Array.isArray(r.findings) ? r.findings.filter(isObject) : [];
    return findings.map((f) => toFinding(f, root, skillDir));
  });
}

export const ciscoDriver: ToolDriver = {
  info: CISCO_INFO,
  locate: locateCisco,
  versionArgs: ["--version"],
  toolEnv: (env) => ({
    ...env,
    // LiteLLM, imported by the CLI, otherwise fetches its model price map from GitHub at import time.
    LITELLM_LOCAL_MODEL_COST_MAP: "True",
    NO_COLOR: "1",
  }),
  network: () => false,
  create: (env) =>
    toolAnalyzer(ciscoDriver, env, async ({ root, workDir, exec }) => {
      const report = join(workDir, "cisco.json");
      const result = await exec(ciscoArgs(root, report));
      const text = result.code === 0 ? await readReport(report, "cisco") : undefined;
      if (text === undefined && result.code === 1 && result.stderr.includes(NO_SKILLS)) return [];
      expectExit("cisco", result, [0]);
      if (text === undefined) throw new Error("cisco did not write its report");
      return parseCiscoOutput(text, root);
    }),
};
