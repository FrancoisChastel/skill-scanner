import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { UsageError } from "../../src/cli/args";
import { guardCommand } from "../../src/cli/commands/guard";
import { fakeIO, hermeticGitEnv, tempDir } from "../sources/helpers";

const root = tempDir("ss-guard-cmd-");
afterAll(() => root.remove());

const probe = join(root.path, "probe.mjs");
const record = join(root.path, "probe.json");
writeFileSync(
  probe,
  [
    'import { existsSync, writeFileSync } from "node:fs";',
    "const hooks = process.env.GIT_CONFIG_VALUE_0 ?? '';",
    `writeFileSync(${JSON.stringify(record)}, JSON.stringify({`,
    "  argv: process.argv.slice(2),",
    "  key: process.env.GIT_CONFIG_KEY_0,",
    "  hookExists: existsSync(hooks + '/post-checkout'),",
    "  hooks,",
    "  download: process.env.SKILLS_DOWNLOAD_URL,",
    "}));",
    "if (process.env.PROBE_REFUSE) writeFileSync(process.env.SKILL_SCANNER_GUARD_STATE + '/refusals.log', 'skill-scanner blocked evil/repo: 1 critical.\\n');",
    "if (process.env.PROBE_SIGNAL) process.kill(process.pid, process.env.PROBE_SIGNAL);",
    "else process.exit(Number(process.env.PROBE_EXIT ?? 0));",
    "",
  ].join("\n"),
);

const env = (extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv => ({ ...hermeticGitEnv(join(root.path, "home")), ...extra });
const run = (argv: string[], e: NodeJS.ProcessEnv = env()) => {
  const f = fakeIO({ cwd: root.path, env: e });
  return guardCommand.run(argv, f.io).then((code) => ({ code, out: f.out(), err: f.err() }));
};

describe("guard", () => {
  test("runs the command with the hook environment and removes the hook afterwards", async () => {
    const r = await run(["--", process.execPath, probe, "update", "-g"]);
    expect(r.code).toBe(0);
    const seen = JSON.parse(readFileSync(record, "utf8"));
    expect(seen.argv).toEqual(["update", "-g"]);
    expect(seen.key).toBe("core.hooksPath");
    expect(seen.hookExists).toBe(true);
    expect(seen.download).toBe("http://127.0.0.1:9");
    expect(existsSync(seen.hooks)).toBe(false);
  });

  test("passes the exit code through, and 128 + signal when a signal ends the command", async () => {
    expect((await run([process.execPath, probe], env({ PROBE_EXIT: "3" }))).code).toBe(3);
    expect((await run([process.execPath, probe], env({ PROBE_SIGNAL: "SIGTERM" }))).code).toBe(143);
  });

  test("refusals logged by the hook are repeated, and a command that swallowed one does not exit 0", async () => {
    const r = await run([process.execPath, probe], env({ PROBE_REFUSE: "1", PROBE_EXIT: "0" }));
    expect(r.code).toBe(1);
    expect(r.err).toContain("skill-scanner guard refused these checkouts:\nskill-scanner blocked evil/repo: 1 critical.");
    expect((await run([process.execPath, probe], env({ PROBE_REFUSE: "1", PROBE_EXIT: "4" }))).code).toBe(4);
    const quiet = await run([process.execPath, probe]);
    expect(quiet.err).toBe("");
  });

  test("a missing command exits 127 like a shell", async () => {
    const r = await run(["definitely-not-a-command-ss"]);
    expect(r.code).toBe(127);
    expect(r.err).toContain("command not found");
  });

  test("usage errors and help", async () => {
    await expect(run([])).rejects.toThrow(UsageError);
    await expect(run(["--"])).rejects.toThrow(UsageError);
    const help = await run(["--help"]);
    expect(help.code).toBe(0);
    expect(help.out).toContain("npx skills update");
    expect(help.out).toContain("pi install");
    expect(help.out).toContain("git clone");
  });

  test("--help after the command belongs to the command", async () => {
    const r = await run([process.execPath, probe, "--help"]);
    expect(r.code).toBe(0);
    expect(JSON.parse(readFileSync(record, "utf8")).argv).toEqual(["--help"]);
  });
});
