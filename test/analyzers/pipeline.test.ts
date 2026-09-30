import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { createAnalyzers } from "../../src/analyzers";
import { type AnalyzerName, DEFAULT_CONFIG } from "../../src/config";

/**
 * Each analyzer end to end against a fake tool: a shell script that records its arguments and answers
 * like the real one. POSIX only, since the fakes are shell scripts.
 */

const IS_WINDOWS = process.platform === "win32";
let base: string;
let bin: string;
let root: string;
let log: string;

async function fake(name: string, body: string): Promise<void> {
  const path = join(bin, name);
  // Record the arguments, one per line, before doing anything else.
  await writeFile(path, `#!/bin/sh\nfor a in "$@"; do printf '%s\\n' "$a"; done > "${log}"\n${body}\n`);
  await chmod(path, 0o755);
}

const env = (extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv => ({ PATH: [bin, "/usr/bin", "/bin"].join(delimiter), ...extra });
const loggedArgs = async (): Promise<string[]> => (await readFile(log, "utf8")).split("\n").filter((l) => l !== "");

async function analyzer(name: AnalyzerName, cfg = DEFAULT_CONFIG, extra: NodeJS.ProcessEnv = {}) {
  const [a] = await createAnalyzers([name], cfg, env(extra));
  return a!;
}

/** The value following `flag` in the recorded arguments. */
const after = (args: readonly string[], flag: string): string | undefined => args[args.indexOf(flag) + 1];

beforeAll(async () => {
  base = await realpath(await mkdtemp(join(tmpdir(), "analyzers-pipeline-")));
  bin = join(base, "bin");
  root = join(base, "root");
  log = join(base, "args.log");
  await mkdir(bin);
  await mkdir(join(root, "skills", "demo"), { recursive: true });
  await writeFile(join(root, "skills", "demo", "SKILL.md"), "---\nname: demo\ndescription: Demo skill.\n---\nHello.\n");

  await fake(
    "gitleaks",
    `root="$2"; report=""; config=""
while [ $# -gt 0 ]; do
  case "$1" in --report-path) report="$2";; --config) config="$2";; esac; shift
done
cp "$config" "${join(base, "gitleaks-config.toml")}"
cat > "$report" <<JSON
[{"RuleID":"github-pat","Description":"GitHub token.","StartLine":2,"EndLine":2,"StartColumn":3,"Match":"REDACTED","Secret":"REDACTED","File":"$root/skills/demo/run.sh"}]
JSON`,
  );
  await fake(
    "osv-scanner",
    `for last; do :; done
if [ -n "$OSV_FAKE_EMPTY" ]; then exit 128; fi
cat <<JSON
{"results":[{"source":{"path":"$last/skills/demo/requirements.txt","type":"lockfile"},"packages":[{"package":{"name":"pyyaml","version":"5.3","ecosystem":"PyPI"},"groups":[{"ids":["PYSEC-2021-142"],"aliases":["CVE-2020-14343"],"max_severity":"9.8"}],"vulnerabilities":[{"id":"PYSEC-2021-142"}]}]}]}
JSON
exit 1`,
  );
  await fake(
    "semgrep",
    `for last; do :; done
for a in "$@"; do
  if [ "$a" = "--x-ignore-semgrepignore-files" ] && [ -n "$SEMGREP_FAKE_OLD" ]; then echo "semgrep: unknown option '$a'" >&2; exit 2; fi
done
if [ -n "$SEMGREP_FAKE_BAD_CONFIG" ]; then echo '{"results":[],"errors":[{"type":"InvalidRuleSchemaError","message":"Invalid rule schema"}]}'; exit 7; fi
echo '{"results":[{"check_id":"demo-rule","path":"'"$last"'/skills/demo/run.py","start":{"line":1,"col":1},"end":{"line":1,"col":5},"extra":{"message":"eval of input","severity":"ERROR","metadata":{},"lines":"eval(x)"}}],"errors":[]}'`,
  );
  await fake(
    "skillspector",
    `root="$2"; report=""
while [ $# -gt 0 ]; do [ "$1" = "--output" ] && report="$2"; shift; done
printf '%s' "$SKILLSPECTOR_OSV_TIMEOUT" > "${join(base, "skillspector-env")}"
echo '{"issues":[{"id":"P1","category":"Prompt Injection","pattern":"Instruction Override","severity":"HIGH","location":{"file":"skills/demo/SKILL.md","start_line":5,"start_column":0},"finding":"Hello.","explanation":"Overrides instructions."}],"execution_successful":true}' > "$report"
echo "Report saved to: $report"
exit 1`,
  );
  await fake(
    "skill-scanner",
    `# from skill_scanner.cli.cli import main (entry-point marker)
root="$2"; report=""
while [ $# -gt 0 ]; do [ "$1" = "--output-json" ] && report="$2"; shift; done
if [ -n "$CISCO_FAKE_NO_SKILLS" ]; then echo "No skills found to scan." >&2; exit 1; fi
echo '{"summary":{},"results":[{"skill_name":"demo","skill_path":"'"$root"'/skills/demo","findings":[{"rule_id":"PROMPT_INJECTION_IGNORE_INSTRUCTIONS","category":"prompt_injection","severity":"HIGH","title":"Override","description":"Pattern detected.","file_path":"SKILL.md","line_number":5,"snippet":"Hello."}]}]}' > "$report"`,
  );
});

afterAll(async () => {
  await rm(base, { recursive: true, force: true });
});

describe.skipIf(IS_WINDOWS)("analyzers against fake tools", () => {
  test("gitleaks: pinned config, private cwd, finding relative to the root", async () => {
    // Arrange
    const a = await analyzer("gitleaks");

    // Act
    const findings = await a.run(root);
    const args = await loggedArgs();

    // Assert
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "external/gitleaks", location: { file: "skills/demo/run.sh", line: 2, column: 3 } });
    expect(args.slice(0, 2)).toEqual(["dir", root]);
    expect(await readFile(join(base, "gitleaks-config.toml"), "utf8")).toContain("useDefault = true");
    expect(after(args, "--gitleaks-ignore-path")).not.toStartWith(root);
  });

  test("the scratch directory is removed after a run", async () => {
    // Arrange
    const a = await analyzer("gitleaks");
    const before = (await readdir(tmpdir())).filter((n) => n.startsWith("skill-scanner-gitleaks-"));

    // Act
    await a.run(root);

    // Assert
    const now = (await readdir(tmpdir())).filter((n) => n.startsWith("skill-scanner-gitleaks-"));
    expect(now.length).toBeLessThanOrEqual(before.length);
  });

  test("osv-scanner: exit 1 means vulnerabilities, 128 means no packages", async () => {
    // Arrange / Act
    const findings = await (await analyzer("osv-scanner")).run(root);
    const none = await (await analyzer("osv-scanner", DEFAULT_CONFIG, { OSV_FAKE_EMPTY: "1" })).run(root);

    // Assert
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "critical", location: { file: "skills/demo/requirements.txt" } });
    expect(none).toEqual([]);
    expect(after(await loggedArgs(), "--config")).toEndWith("osv-scanner.toml");
  });

  test("semgrep: runs the configured rules and falls back when the engine rejects the ignore flag", async () => {
    // Arrange
    const cfg = { ...DEFAULT_CONFIG, semgrepConfig: "/rules/skills.yml" };

    // Act
    const current = await (await analyzer("semgrep", cfg)).run(root);
    const currentArgs = await loggedArgs();
    const old = await (await analyzer("semgrep", cfg, { SEMGREP_FAKE_OLD: "1" })).run(root);
    const oldArgs = await loggedArgs();

    // Assert
    expect(current[0]).toMatchObject({ severity: "high", location: { file: "skills/demo/run.py", line: 1, snippet: "eval(x)" } });
    expect(old).toHaveLength(1);
    expect(after(currentArgs, "--config")).toBe("/rules/skills.yml");
    expect(currentArgs).toContain("--x-ignore-semgrepignore-files");
    expect(currentArgs).toContain("--metrics=off");
    expect(oldArgs).not.toContain("--x-ignore-semgrepignore-files");
  });

  test("semgrep: a failing engine surfaces the error from its JSON report", async () => {
    // Arrange
    const a = await analyzer("semgrep", DEFAULT_CONFIG, { SEMGREP_FAKE_BAD_CONFIG: "1" });

    // Act / Assert
    await expect(a.run(root)).rejects.toThrow("semgrep exited with 7: Invalid rule schema");
  });

  test("skillspector: exit 1 is a normal result, OSV lookups are disabled", async () => {
    // Arrange / Act
    const findings = await (await analyzer("skillspector")).run(root);
    const args = await loggedArgs();

    // Assert
    expect(findings[0]).toMatchObject({ category: "prompt-injection", location: { file: "skills/demo/SKILL.md", line: 5, column: 1 } });
    expect(args).toContain("--no-llm");
    expect(await readFile(join(base, "skillspector-env"), "utf8")).toBe("0");
  });

  test("cisco: maps findings and treats 'no skills found' as an empty result", async () => {
    // Arrange / Act
    const findings = await (await analyzer("cisco")).run(root);
    const none = await (await analyzer("cisco", DEFAULT_CONFIG, { CISCO_FAKE_NO_SKILLS: "1" })).run(root);

    // Assert
    expect(findings[0]).toMatchObject({ category: "prompt-injection", location: { file: "skills/demo/SKILL.md", line: 5 } });
    expect(none).toEqual([]);
  });

  test("a tool that fails reports its exit code and stderr", async () => {
    // Arrange
    await fake("gitleaks", 'echo "fatal: something broke" >&2; exit 2');

    // Act / Assert
    await expect((await analyzer("gitleaks")).run(root)).rejects.toThrow("gitleaks exited with 2: fatal: something broke");
  });
});
