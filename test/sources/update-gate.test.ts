import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { addTrust } from "../../src/guard/state";
import { scanPath } from "../../src/scan";
import { referenceTransactionScript } from "../../src/sources/guard-env";
import { guardEnv } from "../../src/sources/index";
import { runPostCheckout } from "../../src/sources/post-checkout";
import { parseUpdates } from "../../src/sources/ref-transaction";
import { BENIGN_SKILL, commitFiles, fakeIO, hasGit, hermeticGitEnv, MALICIOUS_SKILL, makeRepo, tempDir } from "./helpers";

/**
 * The update gate `guard` installs: a reference-transaction hook that scans the commit a
 * checked-out branch (or its upstream) is about to move to, and a post-checkout hook that switches
 * back from a refused checkout. Real git, real hooks, the real hook entry point from the sources.
 */

const root = tempDir("ss-update-gate-");
const home = join(root.path, "home");
const env = hermeticGitEnv(home);
const runner = join(root.path, "run-hook.ts");
const OID = "a".repeat(40);
const OTHER = "b".repeat(40);
const ZERO = "0".repeat(40);

beforeAll(() => {
  mkdirSync(home, { recursive: true });
  const src = join(import.meta.dir, "../../src");
  // Stands in for the installed `skill-scanner`: `hook <target> ...` straight from the sources.
  writeFileSync(
    runner,
    [
      `import { processIO } from ${JSON.stringify(join(src, "cli/io"))};`,
      `import { runHook } from ${JSON.stringify(join(src, "cli/commands/hook"))};`,
      "process.exitCode = await runHook(process.argv.slice(3), processIO());",
      "",
    ].join("\n"),
  );
});
afterAll(() => root.remove());

const git = (cwd: string, args: readonly string[], e: NodeJS.ProcessEnv = env) =>
  spawnSync("git", [...args], { cwd, env: e, encoding: "utf8" });
const out = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, env, encoding: "utf8" }).trim();
const skillText = (dir: string): string => readFileSync(join(dir, "skills/tidy/SKILL.md"), "utf8");

/** An upstream with a benign first commit, a clone of it with an untracked local file, then a malicious upstream commit. */
function scenario(name: string): { up: string; clone: string; first: string; evil: string } {
  const up = join(root.path, `${name}-up`);
  const first = makeRepo(up, { "skills/tidy/SKILL.md": BENIGN_SKILL }, env);
  const clone = join(root.path, `${name}-clone`);
  expect(git(root.path, ["clone", "-q", up, clone]).status).toBe(0);
  writeFileSync(join(clone, "NOTES.txt"), "mine\n");
  const evil = commitFiles(up, { "skills/tidy/SKILL.md": MALICIOUS_SKILL }, env, "evil");
  return { up, clone, first, evil };
}

describe("parseUpdates", () => {
  test("keeps moves of existing refs between commits; drops creations, deletions, no-ops, and symref lines", () => {
    const text = [
      `${OID} ${OTHER} refs/heads/main`,
      `${ZERO} ${OTHER} refs/heads/new`,
      `${OID} ${ZERO} refs/heads/gone`,
      `${OID} ${OID} refs/heads/same`,
      `ref:refs/heads/a ref:refs/heads/b HEAD`,
      "garbage",
      `${"c".repeat(64)} ${"d".repeat(64)} HEAD`,
      "",
    ].join("\n");
    expect(parseUpdates(text).map((u) => u.ref)).toEqual(["refs/heads/main", "HEAD"]);
  });
});

describe("the reference-transaction script", () => {
  test("only prepared and aborted moves reach the scanner, and a previous hook still gets every line", () => {
    const script = referenceTransactionScript({ node: "/n", script: "/s" }, { kind: "dir", path: "/u/hooks" }, "/h");
    expect(script).toContain("prepared|aborted)");
    expect(script).toContain("hook git-reference-transaction");
    expect(script).toContain("prev='/u/hooks/reference-transaction'");
    expect(script.indexOf("hook git-reference-transaction")).toBeLessThan(script.indexOf('| "$prev" "$@"'));
  });
});

describe.skipIf(!hasGit)("guard gates updates of existing checkouts", () => {
  test("git pull of a malicious update is refused at the fetch; nothing in the working tree changes", async () => {
    const s = scenario("pull");
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      const r = git(s.clone, ["pull", "-q"], g.env);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain("update refused");
      expect(skillText(s.clone)).toBe(BENIGN_SKILL);
      expect(out(s.clone, "rev-parse", "HEAD")).toBe(s.first);
      expect(out(s.clone, "rev-parse", "origin/main")).toBe(s.first);
      expect(await g.refusals()).toContain("pull-up");
    } finally {
      await g.cleanup();
    }
  });

  test("reset, merge, and rebase to an already fetched malicious commit are refused and the working tree put back", async () => {
    const s = scenario("reset");
    expect(git(s.clone, ["fetch", "-q"]).status).toBe(0);
    for (const args of [
      ["reset", "--hard", "origin/main"],
      ["merge", "--ff-only", "origin/main"],
      ["rebase", "origin/main"],
    ]) {
      const g = await guardEnv({ node: process.execPath, script: runner }, env);
      try {
        const r = git(s.clone, args, g.env);
        expect(r.status).not.toBe(0);
        expect(r.stderr).toContain("restored the working tree");
        expect(skillText(s.clone)).toBe(BENIGN_SKILL);
        expect(out(s.clone, "rev-parse", "HEAD")).toBe(s.first);
        // Only the refused change is undone: the user's untracked file stays, and nothing is left staged.
        expect(out(s.clone, "status", "--porcelain")).toBe("?? NOTES.txt");
      } finally {
        await g.cleanup();
      }
    }
  });

  test("a refused reset --mixed puts the index back and leaves the files alone", async () => {
    const s = scenario("mixed");
    expect(git(s.clone, ["fetch", "-q"]).status).toBe(0);
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      const r = git(s.clone, ["reset", "--mixed", "origin/main"], g.env);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain("restored the index");
      expect(skillText(s.clone)).toBe(BENIGN_SKILL);
      expect(out(s.clone, "status", "--porcelain")).toBe("?? NOTES.txt");
    } finally {
      await g.cleanup();
    }
  });

  test("switching back acts on the checkout the hook ran in, whatever GIT_DIR the environment carries", async () => {
    const s = scenario("gitdir");
    const decoy = scenario("gitdir-decoy");
    expect(git(s.clone, ["fetch", "-q"]).status).toBe(0);
    // The checkout itself, unguarded, so the hook can be called on its result directly.
    expect(git(s.clone, ["checkout", "-q", "--detach", "origin/main"]).status).toBe(0);
    const f = fakeIO({ env: { ...env, GIT_DIR: join(decoy.clone, ".git"), GIT_WORK_TREE: decoy.clone }, cwd: root.path });
    const code = await runPostCheckout(["--dir", s.clone, "--git-dir", join(s.clone, ".git"), s.first, s.evil, "1"], f.io);
    expect(code).toBe(1);
    expect(out(s.clone, "symbolic-ref", "HEAD")).toBe("refs/heads/main");
    expect(skillText(s.clone)).toBe(BENIGN_SKILL);
    expect(out(decoy.clone, "rev-parse", "HEAD")).toBe(decoy.first);
  });

  test("a refused checkout in an existing repository switches back", async () => {
    const s = scenario("checkout");
    expect(git(s.clone, ["fetch", "-q"]).status).toBe(0);
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      const r = git(s.clone, ["checkout", "-q", "--detach", "origin/main"], g.env);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toContain("switched");
      expect(out(s.clone, "symbolic-ref", "HEAD")).toBe("refs/heads/main");
      expect(skillText(s.clone)).toBe(BENIGN_SKILL);
    } finally {
      await g.cleanup();
    }
  });

  test("a benign update passes and each tree is scanned once", async () => {
    const s = scenario("benign");
    const fixed = commitFiles(s.up, { "skills/tidy/SKILL.md": `${BENIGN_SKILL}\nKeep the header row.\n` }, env, "fix");
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      expect(git(s.clone, ["pull", "-q", "--ff-only"], g.env).status).toBe(0);
      expect(out(s.clone, "rev-parse", "HEAD")).toBe(fixed);
      // The fetch scanned the upstream commit; the fast-forward to the same tree did not scan again.
      expect((await g.checkouts()).filter((l) => l.startsWith(fixed))).toEqual([`${fixed} pass`]);
    } finally {
      await g.cleanup();
    }
  });

  test("an approved commit and a trusted digest are let through", async () => {
    const s = scenario("approved");
    const approved = await guardEnv({ node: process.execPath, script: runner, approvedCommits: [s.evil] }, env);
    try {
      expect(git(s.clone, ["pull", "-q", "--ff-only"], approved.env).status).toBe(0);
      expect(skillText(s.clone)).toBe(MALICIOUS_SKILL);
    } finally {
      await approved.cleanup();
    }
    const t = scenario("trusted");
    const report = await scanPath(join(t.up, "skills/tidy"));
    const trustEnv = { ...env, SKILL_SCANNER_HOME: join(root.path, "trust-home") };
    await addTrust({ digest: report.bundles[0]!.bundle.digest, name: "tidy", path: t.clone }, trustEnv);
    const g = await guardEnv({ node: process.execPath, script: runner }, trustEnv);
    try {
      expect(git(t.clone, ["pull", "-q", "--ff-only"], g.env).status).toBe(0);
    } finally {
      await g.cleanup();
    }
  });

  test("commits nothing watches (other branches, tags) do not reach the scanner", async () => {
    const s = scenario("other");
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      expect(git(s.clone, ["branch", "side", s.first], g.env).status).toBe(0);
      expect(git(s.clone, ["fetch", "-q", "origin", `${s.evil}:refs/heads/side`, "--force"], g.env).status).toBe(0);
      expect(git(s.clone, ["tag", "v1", s.evil], g.env).status).toBe(0);
      expect(await g.checkouts()).toEqual([]);
    } finally {
      await g.cleanup();
    }
  });

  test("a user's own reference-transaction hook still runs, with the same input", async () => {
    const s = scenario("chain");
    const userHooks = join(root.path, "user-hooks-rt");
    mkdirSync(userHooks, { recursive: true });
    const seen = join(root.path, "user-rt-seen");
    writeFileSync(join(userHooks, "reference-transaction"), `#!/bin/sh\ncat >> '${seen}'\necho "$1" >> '${seen}'\n`);
    chmodSync(join(userHooks, "reference-transaction"), 0o755);
    const base = { ...env, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.hooksPath", GIT_CONFIG_VALUE_0: userHooks };
    const g = await guardEnv({ node: process.execPath, script: runner }, base);
    try {
      expect(git(s.clone, ["pull", "-q"], g.env).status).not.toBe(0);
      // Refused before the user's hook saw "prepared"; it still sees the aborted transaction.
      const text = existsSync(seen) ? readFileSync(seen, "utf8") : "";
      expect(text).toContain("aborted");
      expect(text).toContain("refs/remotes/origin/main");
      expect(text).not.toContain("prepared");
    } finally {
      await g.cleanup();
    }
  });
});

describe.skipIf(!hasGit)("guard does not get in the way of work on a skill", () => {
  test("a new branch at the same commit is not scanned, even in a flagged repository", async () => {
    const dir = join(root.path, "dev-skill");
    makeRepo(dir, { "skills/tidy/SKILL.md": MALICIOUS_SKILL }, env);
    const g = await guardEnv({ node: process.execPath, script: runner }, env);
    try {
      expect(git(dir, ["checkout", "-q", "-b", "topic"], g.env).status).toBe(0);
      expect(out(dir, "symbolic-ref", "HEAD")).toBe("refs/heads/topic");
      expect(await g.checkouts()).toEqual([]);
    } finally {
      await g.cleanup();
    }
  });
});
