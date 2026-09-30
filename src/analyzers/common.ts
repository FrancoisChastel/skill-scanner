import { type FileHandle, mkdtemp, open, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import type { AnalyzerName } from "../config";
import { redactSecrets } from "../core/secrets";
import type { Category, Finding, Location, Severity } from "../core/types";
import type { ExternalAnalyzer } from "../scan";
import { type RunOptions, runTool, type ToolResult } from "./run";
import type { AnalyzerInfo, ToolDriver } from "./types";

/** Shared plumbing for the external analyzers: running a tool in a scratch directory and turning its output into findings. */

export const MAX_REPORT_BYTES = 50 * 1024 * 1024;
const MAX_TITLE = 120;
const MAX_MESSAGE = 1000;
const MAX_SNIPPET = 200;
const MAX_STDERR_TAIL = 300;

export type JsonObject = Readonly<Record<string, unknown>>;

export function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A non-empty string, else undefined. */
export const str = (v: unknown): string | undefined => (typeof v === "string" && v.trim() !== "" ? v : undefined);

/** A positive integer, else undefined. */
export const posInt = (v: unknown): number | undefined => (typeof v === "number" && Number.isInteger(v) && v > 0 ? v : undefined);

export function parseJson(text: string, tool: string): unknown {
  if (text.trim() === "") throw new Error(`${tool} produced no JSON output`);
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${tool} produced malformed JSON: ${(e as Error).message}`);
  }
}

export function expectObject(v: unknown, tool: string, what: string): JsonObject {
  if (!isObject(v)) throw new Error(`${tool} output is not in the expected format: ${what} is not an object`);
  return v;
}

export function expectArray(v: unknown, tool: string, what: string): readonly unknown[] {
  if (!Array.isArray(v)) throw new Error(`${tool} output is not in the expected format: ${what} is not an array`);
  return v;
}

/** POSIX path of `file` relative to `root`. Tools report absolute paths, paths relative to the root, or both. */
export function relativeFile(root: string, file: string): string {
  const native = sep === "\\" ? file.replace(/\//g, "\\") : file;
  const rel = isAbsolute(native) ? relative(root, native) : native;
  const normalized = posix.normalize(rel.split(sep).join("/")).replace(/\/+$/, "");
  return normalized === "" ? "." : normalized;
}

export function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 3)}...`;
}

const oneLine = (text: string): string => text.replace(/\s+/g, " ").trim();

/** One line of redacted text, bounded. Redaction comes first so a cut never leaves a partial secret the patterns miss. */
export const cleanText = (text: string, max: number): string => clip(oneLine(redactSecrets(text)), max);

/** The first non-empty line, redacted and bounded. */
export function snippetOf(text: string | undefined): string | undefined {
  const line = text
    ?.split(/\r?\n/)
    .map((l) => l.trim())
    .find((l) => l !== "");
  return line ? clip(redactSecrets(line), MAX_SNIPPET) : undefined;
}

const SEVERITY_WORDS: Readonly<Record<string, Severity>> = {
  critical: "critical",
  blocker: "critical",
  high: "high",
  error: "high",
  severe: "high",
  medium: "medium",
  moderate: "medium",
  warning: "medium",
  warn: "medium",
  low: "low",
  minor: "low",
  info: "info",
  informational: "info",
  note: "info",
  none: "info",
  safe: "info",
};

/** Map a tool's severity word (any case) to ours. */
export function severityFrom(value: unknown, fallback: Severity = "medium"): Severity {
  return (typeof value === "string" ? SEVERITY_WORDS[value.trim().toLowerCase()] : undefined) ?? fallback;
}

// First match wins, so the more specific intents come first.
const CATEGORY_KEYWORDS: readonly (readonly [RegExp, Category])[] = [
  [
    /prompt.?injection|jailbreak|anti.?refusal|instruction.?override|system.?prompt|tool.?poisoning|social.?engineering|harmful/i,
    "prompt-injection",
  ],
  [/steganograph|invisible|zero.?width|homoglyph|bidi|hidden/i, "hidden-content"],
  [/exfiltrat|data.?flow|leak/i, "exfiltration"],
  [/hard.?coded|secret|api.?key|private.?key|password|cwe-798\b/i, "secrets"],
  [/credential|env(?:ironment)?.?var|harvest|snoop|keychain/i, "credential-access"],
  [/obfuscat|base64|encoded|packed|evasion/i, "obfuscation"],
  [/persist|autostart|cron|launch.?agent|memory.?poison|rug.?pull/i, "persistence"],
  [/privilege|sudo|escalat|setuid/i, "privilege"],
  [/destruct|wipe|ransom|resource.?abuse|fork.?bomb/i, "destructive"],
  [/supply.?chain|dependenc|known.?vulnerab|vulnerable.?(?:package|version)|cve-\d|ghsa-|typosquat|transitive/i, "supply-chain"],
  [
    /command.?injection|code.?(?:execution|injection)|\bexec|\beval|subprocess|child.?process|\bshell\b|deserializ|\brce\b|remote.?code|malware|webshell|backdoor|exploit|hack.?tool|cwe-(?:77|78|94|95|502)\b/i,
    "remote-execution",
  ],
  [/ssrf|request.?forgery|network|\burl\b|\bdns\b|crypto.?miner|mining/i, "network"],
  [
    /tool.?misuse|excessive.?agency|autonomy|tool.?chain|unauthori[sz]ed.?tool|\bmcp\b|least.?privilege|rogue|output.?handling|trigger/i,
    "execution-surface",
  ],
  [/manifest|metadata|frontmatter|license|policy/i, "metadata"],
];

/** Best-effort category from free text (a tool's category, rule id, title). */
export function categoryFrom(texts: readonly (string | undefined)[], fallback: Category = "packaging"): Category {
  const hay = texts.filter((t): t is string => t !== undefined).join(" ");
  return CATEGORY_KEYWORDS.find(([re]) => re.test(hay))?.[1] ?? fallback;
}

export interface Draft {
  /** The tool's own rule id, shown as `[id]` in front of the message. */
  readonly toolRule: string;
  readonly title: string;
  readonly category: Category;
  readonly severity: Severity;
  readonly message: string;
  /** POSIX path relative to the scan root. */
  readonly file: string;
  readonly line?: number | undefined;
  readonly column?: number | undefined;
  readonly endLine?: number | undefined;
  /** Raw text; only its first line is kept, redacted. */
  readonly snippet?: string | undefined;
  readonly remediation?: string | undefined;
}

/** A finding in the scanner's shape. Every free-text field is redacted and bounded; the bundle is assigned later by the scan. */
export function externalFinding(tool: AnalyzerName, d: Draft): Finding {
  const snippet = snippetOf(d.snippet);
  const location: Location = {
    file: d.file,
    ...(d.line ? { line: d.line } : {}),
    ...(d.line && d.column ? { column: d.column } : {}),
    ...(d.line && d.endLine && d.endLine > d.line ? { endLine: d.endLine } : {}),
    ...(snippet ? { snippet } : {}),
  };
  return {
    ruleId: `external/${tool}`,
    title: cleanText(d.title, MAX_TITLE),
    category: d.category,
    severity: d.severity,
    confidence: "medium",
    message: cleanText(`[${d.toolRule}] ${d.message}`, MAX_MESSAGE),
    location,
    bundle: "",
    source: `external:${tool}`,
    ...(d.remediation ? { remediation: cleanText(d.remediation, MAX_MESSAGE) } : {}),
  };
}

export function notInstalled(info: AnalyzerInfo): string {
  return `${info.title} was not found on PATH (${info.binary}); install it with: ${info.install}`;
}

const stripAnsi = (text: string): string => text.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "");

/** The last lines of stderr, for an error message. */
export function stderrTail(stderr: string): string {
  const last = stripAnsi(stderr)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "")
    .slice(-3)
    .join(" | ");
  return last ? `: ${cleanText(last, MAX_STDERR_TAIL)}` : "";
}

/** Throw a readable error unless the tool finished in time, within the output cap, with an expected exit code. */
export function expectExit(tool: string, r: ToolResult, okCodes: readonly number[]): void {
  if (r.timedOut) throw new Error(`${tool} timed out`);
  if (r.truncated) throw new Error(`${tool} printed more output than the limit allows`);
  if (r.code === null || !okCodes.includes(r.code)) throw new Error(`${tool} exited with ${r.code ?? "a signal"}${stderrTail(r.stderr)}`);
}

/** Read a report the tool wrote, bounded. Undefined when the tool did not write it. */
export async function readReport(path: string, tool: string, max = MAX_REPORT_BYTES): Promise<string | undefined> {
  let handle: FileHandle;
  try {
    handle = await open(path, "r");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw e;
  }
  try {
    if ((await handle.stat()).size > max) throw new Error(`${tool} report is larger than ${max} bytes`);
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

/** The first version-looking token in a tool's `--version` output. */
export function versionFrom(text: string): string | undefined {
  return /\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?/.exec(text)?.[0];
}

/** One run of a tool over the scan root. */
export interface ToolRun {
  /** Real path of the scan root: what the tool is given and what reported paths are relative to. */
  readonly root: string;
  /** A private, initially empty directory: the tool's cwd and where its reports go. Removed afterwards. */
  readonly workDir: string;
  /** The executable being run. */
  readonly bin: string;
  exec(args: readonly string[], opts?: Pick<RunOptions, "timeoutMs" | "maxOutputBytes">): Promise<ToolResult>;
}

/**
 * An ExternalAnalyzer around `driver`. The tool runs in a fresh temporary directory rather than the
 * scanned tree or the user's cwd, so neither can feed it configuration or ignore files.
 */
export function toolAnalyzer(
  driver: Pick<ToolDriver, "info" | "locate" | "toolEnv">,
  env: NodeJS.ProcessEnv,
  scan: (run: ToolRun) => Promise<Finding[]>,
): ExternalAnalyzer {
  return {
    name: driver.info.name,
    async unavailable() {
      return (await driver.locate(env)) ? undefined : notInstalled(driver.info);
    },
    async run(root, signal) {
      const bin = await driver.locate(env);
      if (!bin) throw new Error(notInstalled(driver.info));
      const real = await realpath(resolve(root));
      const workDir = await mkdtemp(join(tmpdir(), `skill-scanner-${driver.info.name}-`));
      const toolEnv = driver.toolEnv(env);
      try {
        return await scan({
          root: real,
          workDir,
          bin,
          exec: (args, opts) => runTool(bin, args, { cwd: workDir, env: toolEnv, ...(signal ? { signal } : {}), ...opts }),
        });
      } finally {
        await rm(workDir, { recursive: true, force: true });
      }
    },
  };
}
