import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { postCheckoutScript } from "../../src/sources/guard-env";
import { APPROVED_COMMITS_ENV, appendGitConfig, DEAD_DOWNLOAD_URL, guardCommandLine, guardEnv, shellQuote } from "../../src/sources/index";
import { BENIGN_SKILL, hasGit, hermeticGitEnv, MALICIOUS_SKILL, makeRepo, tempDir } from "./helpers";

const root = tempDir("ss-guard-env-");
const home = join(root.path, "home");
const env = hermeticGitEnv(home);
const argDump = join(root.path, 'it\'s a "dir"', "argdump.mjs");
const hookStub = join(root.path, "hook-stub.mjs");
const hookLog = join(root.path, "hook-log.jsonl");

beforeAll(() => {
  mkdirSync(home, { recursive: true });
  mkdirSync(join(root.path, 'it\'s a "dir"'), { recursive: true });
  writeFileSync(argDump, "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n");
  writeFileSync(
    hookStub,
    [
      'import { appendFileSync } from "node:fs";',
      `appendFileSync(${JSON.stringify(hookLog)}, JSON.stringify({ argv: process.argv.slice(2), cwd: process.cwd() }) + "\\n");`,
      "process.exit(Number(process.env.STUB_EXIT ?? 0));",
      "",
    ].join("\n"),
  );
});
afterAll(() => root.remove());

describe("appendGitConfig", () => {
  test("starts at 0 without existing entries", () => {
    expect(appendGitConfig({ A: "1" }, [["core.hooksPath", "/h"]])).toEqual({
      A: "1",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.hooksPath",
      GIT_CONFIG_VALUE_0: "/h",
    });
  });

  test("appends after the user's entries and leaves the input untouched", () => {
    const base = {
      GIT_CONFIG_COUNT: "2",
      GIT_CONFIG_KEY_0: "a.b",
      GIT_CONFIG_VALUE_0: "1",
      GIT_CONFIG_KEY_1: "c.d",
      GIT_CONFIG_VALUE_1: "2",
    };
    const out = appendGitConfig(base, [
      ["core.hooksPath", "/h"],
      ["url.file:///m.insteadOf", "https://x/y.git"],
    ]);
    expect(out.GIT_CONFIG_COUNT).toBe("4");
    expect([out.GIT_CONFIG_KEY_0, out.GIT_CONFIG_KEY_1, out.GIT_CONFIG_KEY_2, out.GIT_CONFIG_KEY_3]).toEqual([
      "a.b",
      "c.d",
      "core.hooksPath",
      "url.file:///m.insteadOf",
    ]);
    expect(out.GIT_CONFIG_VALUE_3).toBe("https://x/y.git");
    expect(base.GIT_CONFIG_COUNT).toBe("2");
  });

  test("an empty count is zero; a bogus count is an error", () => {
    expect(appendGitConfig({ GIT_CONFIG_COUNT: "" }, [["a.b", "c"]]).GIT_CONFIG_KEY_0).toBe("a.b");
    expect(() => appendGitConfig({ GIT_CONFIG_COUNT: "two" }, [["a.b", "c"]])).toThrow(/not a number/);
  });
});

describe("quoting", () => {
  test("shellQuote survives sh for hostile strings", () => {
    for (const s of ["plain", "it's", "a b", "$(touch x)", "`id`", "line\nbreak", "'", "", "\\"]) {
      const r = spawnSync("sh", ["-c", `printf %s ${shellQuote(s)}`], { encoding: "utf8" });
      expect(r.stdout).toBe(s);
    }
  });

  test("guardCommandLine runs the command under guard, verbatim", () => {
    const command = `npx skills add 'o/r' -s "a b" && echo $HOME \`id\`\nnext line`;
    const line = guardCommandLine({ node: process.execPath, script: argDump }, command);
    expect(line.startsWith(`${shellQuote(process.execPath)} `)).toBe(true);
    const r = spawnSync("sh", ["-c", line], { encoding: "utf8" });
    expect(JSON.parse(r.stdout)).toEqual(["guard", "--", "sh", "-c", command]);
  });

  test("the hook script runs the scanner outside the checkout, then chains a previous hook", () => {
    const runtime = { node: "/opt/my node/bin/node", script: "/x/it's/cli.js" };
    const chained = postCheckoutScript(runtime, { kind: "dir", path: "/home/me/hooks" }, "/tmp/h ooks");
    expect(chained.startsWith("#!/bin/sh\n")).toBe(true);
    expect(chained).toContain(
      `(cd '/tmp/h ooks' && exec '/opt/my node/bin/node' '/x/it'\\''s/cli.js' hook git-post-checkout --dir "$dir" --git-dir "$gitdir" "$@") || exit $?`,
    );
    expect(chained).toContain("prev='/home/me/hooks/post-checkout'");
    // The chained hook comes after the scan, so it never sees a refused checkout.
    expect(chained.indexOf("hook git-post-checkout")).toBeLessThan(chained.indexOf('exec "$prev" "$@"'));
    expect(postCheckoutScript(runtime, { kind: "default" }, "/h")).toContain("git rev-parse --git-common-dir");
    expect(postCheckoutScript(runtime, { kind: "relative" }, "/h")).not.toContain('"$prev"');
  });
});

describe.skipIf(!hasGit)("guardEnv with git", () => {
  const benign = join(root.path, "benign");
  // Stands in for `skill-scanner hook git-post-checkout`, straight from the sources.
  const runner = join(root.path, "run-hook.ts");
  let benignCommit = "";
  beforeAll(() => {
    benignCommit = makeRepo(benign, { "skills/tidy/SKILL.md": BENIGN_SKILL }, env);
    const src = join(import.meta.dir, "../../src");
    writeFileSync(
      runner,
      [
        `import { processIO } from ${JSON.stringify(join(src, "cli/io"))};`,
        `import { runPostCheckout } from ${JSON.stringify(join(src, "sources/post-checkout"))};`,
        "process.exitCode = await runPostCheckout(process.argv.slice(4), processIO());",
        "",
      ].join("\n"),
    );
  });

  const clone = (from: string, dest: string, e: NodeJS.ProcessEnv) =>
    spawnSync("git", ["clone", "-q", from, join(root.path, dest)], { env: e, encoding: "utf8" });
  const log = (): { argv: string[]; cwd: string }[] =>
    existsSync(hookLog)
      ? readFileSync(hookLog, "utf8")
          .trim()
          .split("\n")
          .map((l) => JSON.parse(l))
      : [];

  test("every clone runs the hook in the new checkout, and a failing hook fails the clone", async () => {
    const g = await guardEnv({ node: process.execPath, script: hookStub }, env);
    try {
      expect(g.env.SKILLS_DOWNLOAD_URL).toBe(DEAD_DOWNLOAD_URL);
      expect(g.env.GIT_CONFIG_KEY_0).toBe("core.hooksPath");
      expect(g.env.GIT_CONFIG_VALUE_0).toBe(g.hooksDir);
      expect(clone(`file://${benign}`, "c1", g.env).status).toBe(0);
      const last = log().at(-1)!;
      expect(last.argv.slice(0, 3)).toEqual(["hook", "git-post-checkout", "--dir"]);
      expect(last.argv[3]).toBe(realpathSync(join(root.path, "c1")));
      expect(last.argv.slice(4, 6)).toEqual(["--git-dir", realpathSync(join(root.path, "c1", ".git"))]);
      expect(last.argv[7]).toBe(benignCommit);
      // Never inside the untrusted checkout: runtimes read bunfig.toml and .env from their cwd.
      expect(last.cwd).toBe(realpathSync(g.hooksDir));
      const failed = clone(`file://${benign}`, "c2", { ...g.env, STUB_EXIT: "1" });
      expect(failed.status).not.toBe(0);
    } finally {
      await g.cleanup();
      await g.cleanup();
    }
    expect(existsSync(g.hooksDir)).toBe(false);
  });

  test("an absolute core.hooksPath the user had runs after a passing scan, and its failure still counts", async () => {
    const userHooks = join(root.path, "user-hooks");
    mkdirSync(userHooks, { recursive: true });
    const marker = join(root.path, "user-hook-ran");
    writeFileSync(join(userHooks, "post-checkout"), `#!/bin/sh\necho "$3" > '${marker}'\nexit "\${USER_HOOK_EXIT:-0}"\n`);
    chmodSync(join(userHooks, "post-checkout"), 0o755);
    const base = { ...env, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.hooksPath", GIT_CONFIG_VALUE_0: userHooks };
    const g = await guardEnv({ node: process.execPath, script: hookStub }, base);
    try {
      expect(g.env.GIT_CONFIG_COUNT).toBe("2");
      expect(readFileSync(join(g.hooksDir, "post-checkout"), "utf8")).toContain(join(userHooks, "post-checkout"));
      expect(clone(`file://${benign}`, "c3", g.env).status).toBe(0);
      expect(readFileSync(marker, "utf8").trim()).toBe("1");
      expect(clone(`file://${benign}`, "c4", { ...g.env, USER_HOOK_EXIT: "3" }).status).not.toBe(0);
      rmSync(marker);
      expect(clone(`file://${benign}`, "c4b", { ...g.env, STUB_EXIT: "1" }).status).not.toBe(0);
      expect(existsSync(marker)).toBe(false);
    } finally {
      await g.cleanup();
    }
  });

  test("mirrors redirect clone URLs to the scanned checkout, offline", async () => {
    const g = await guardEnv(
      {
        node: process.execPath,
        script: hookStub,
        extraMirrors: [{ mirror: benign, urls: ["https://github.com/acme/skills.git", "https://github.com/acme/skills"] }],
        approvedCommits: [benignCommit],
      },
      { ...env, [APPROVED_COMMITS_ENV]: "ABC" },
    );
    try {
      expect(g.gitConfig.map(([k]) => k)).toEqual(["core.hooksPath", `url.file://${benign}.insteadOf`, `url.file://${benign}.insteadOf`]);
      expect(g.env[APPROVED_COMMITS_ENV]).toBe(benignCommit);
      expect(clone("https://github.com/acme/skills.git", "c5", g.env).status).toBe(0);
      expect(clone("https://github.com/acme/skills", "c6", g.env).status).toBe(0);
      expect(readFileSync(join(root.path, "c5/skills/tidy/SKILL.md"), "utf8")).toBe(BENIGN_SKILL);
      const origin = execFileSync("git", ["config", "--get", "remote.origin.url"], { cwd: join(root.path, "c5"), encoding: "utf8" });
      expect(origin.trim()).toBe("https://github.com/acme/skills.git");
    } finally {
      await g.cleanup();
    }
  });

  test("the real hook entry point scans the checkout and refuses a malicious one", async () => {
    const evil = join(root.path, "evil");
    makeRepo(evil, { "skills/evil/SKILL.md": MALICIOUS_SKILL }, env);
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      expect(clone(`file://${benign}`, "c7", g.env).status).toBe(0);
      expect(await g.refusals()).toBe("");
      const refused = clone(`file://${evil}`, "c8", g.env);
      expect(refused.status).not.toBe(0);
      expect(refused.stderr).toContain("checkout refused");
      // Refusals are logged for installers that hide hook output, labelled with the remote URL.
      expect(await g.refusals()).toContain(`file://${evil}`);
      expect((await g.checkouts()).map((l) => l.split(" ")[1])).toEqual(["pass", "refused"]);
    } finally {
      await g.cleanup();
    }
  });

  test("a checkout cannot inject code into the scanner through runtime config in its root", async () => {
    const marker = join(root.path, "preload-ran");
    const trap = join(root.path, "trap");
    makeRepo(
      trap,
      {
        "bunfig.toml": 'preload = ["./pwn.js"]\n',
        "pwn.js": `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "pwned");\n`,
        ".env": "SKILL_SCANNER_CONFIG=./cfg.json\n",
        "cfg.json": '{"blockAt":"critical","warnAt":"critical"}',
        "skills/tidy/SKILL.md": BENIGN_SKILL,
      },
      env,
    );
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      expect(clone(`file://${trap}`, "c9", g.env).status).toBe(0);
      expect(existsSync(marker)).toBe(false);
    } finally {
      await g.cleanup();
    }
  });
});
