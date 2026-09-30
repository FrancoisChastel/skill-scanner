import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SourceError, UnsupportedSourceError } from "../../src/sources/errors";
import { fetchSource, parseSource, scanSource } from "../../src/sources/index";
import { BENIGN_SKILL, commitFiles, hasGit, hermeticGitEnv, MALICIOUS_SKILL, makeRepo, tempDir, writeFiles } from "./helpers";

const root = tempDir("ss-fetch-");
const env = hermeticGitEnv(join(root.path, "home"));
const repo = join(root.path, "origin");
let firstCommit = "";
let secondCommit = "";

beforeAll(() => {
  mkdirSync(join(root.path, "home"), { recursive: true });
  if (!hasGit) return;
  firstCommit = makeRepo(repo, { "skills/tidy/SKILL.md": BENIGN_SKILL, "README.md": "# skills\n" }, env);
  execFileSync("git", ["tag", "v1"], { cwd: repo, env });
  secondCommit = commitFiles(repo, { "skills/evil/SKILL.md": MALICIOUS_SKILL }, env);
  symlinkSync("/etc", join(repo, "outside"));
  commitFiles(repo, {}, env, "add symlink");
});

afterAll(() => root.remove());

describe.skipIf(!hasGit)("git sources", () => {
  test("clones the default branch shallowly and reports the commit", async () => {
    const fetched = await fetchSource(parseSource(`file://${repo}`, root.path, env), { env });
    try {
      expect(fetched.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(existsSync(join(fetched.dir, "skills/evil/SKILL.md"))).toBe(true);
      expect(fetched.root.startsWith(root.path) || fetched.root.includes("skill-scanner-src-")).toBe(true);
      const depth = execFileSync("git", ["rev-list", "--count", "HEAD"], { cwd: fetched.root, env, encoding: "utf8" }).trim();
      expect(depth).toBe("1");
    } finally {
      await fetched.cleanup();
      await fetched.cleanup();
    }
    expect(existsSync(fetched.root)).toBe(false);
  });

  test("honours a tag ref and a full commit SHA", async () => {
    // Like the skills CLI, a file:// URL takes no #ref fragment; set the ref directly.
    const tagged = await fetchSource({ ...parseSource(`file://${repo}`, root.path, env), ref: "v1" }, { env });
    expect(tagged.commit).toBe(firstCommit);
    expect(existsSync(join(tagged.dir, "skills/evil"))).toBe(false);
    await tagged.cleanup();

    const pinned = await fetchSource({ ...parseSource(`file://${repo}`, root.path, env), ref: secondCommit }, { env });
    expect(pinned.commit).toBe(secondCommit);
    expect(existsSync(join(pinned.dir, "skills/evil/SKILL.md"))).toBe(true);
    await pinned.cleanup();
  });

  test("resolves a subpath inside the checkout and refuses one that escapes through a symlink", async () => {
    const base = parseSource(`file://${repo}`, root.path, env);
    const sub = await fetchSource({ ...base, subpath: "skills/tidy" }, { env });
    expect(sub.dir.endsWith("/skills/tidy")).toBe(true);
    await sub.cleanup();
    await expect(fetchSource({ ...base, subpath: "outside" }, { env })).rejects.toThrow(/outside the source/);
    await expect(fetchSource({ ...base, subpath: "missing" }, { env })).rejects.toThrow(/does not exist/);
  });

  test("never runs repository or user hooks during the clone", async () => {
    const hooks = join(root.path, "user-hooks");
    const marker = join(root.path, "hook-ran");
    mkdirSync(hooks, { recursive: true });
    writeFileSync(join(hooks, "post-checkout"), `#!/bin/sh\ntouch '${marker}'\n`);
    chmodSync(join(hooks, "post-checkout"), 0o755);
    const hookEnv = { ...env, GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.hooksPath", GIT_CONFIG_VALUE_0: hooks };
    const fetched = await fetchSource(parseSource(`file://${repo}`, root.path, hookEnv), { env: hookEnv });
    await fetched.cleanup();
    expect(existsSync(marker)).toBe(false);
  });

  test("clone failures name the source, not the credentials", async () => {
    const spec = parseSource("https://user:hunter2@127.0.0.1:9/team/repo.git", root.path, env);
    try {
      await fetchSource(spec, { env, timeoutMs: 20_000 });
      throw new Error("expected failure");
    } catch (e) {
      expect(e).toBeInstanceOf(SourceError);
      expect((e as Error).message).toContain("cannot clone");
      expect((e as Error).message).not.toContain("hunter2");
    }
  });

  test("scanSource scans the named skill only, labels the report, and cleans up with keep:false", async () => {
    const { report, fetched } = await scanSource(`file://${repo}`, { cwd: root.path, env, onlySkills: ["tidy"], keep: false });
    expect(report.target).toBe(parseSource(`file://${repo}`, root.path, env).display);
    const skills = report.bundles.filter((b) => b.bundle.kind === "skill");
    expect(skills.map((b) => [b.bundle.name, b.verdict])).toEqual([["tidy", "pass"]]);
    // The root bundle (non-skill files) is always kept: here its symlink to /etc blocks.
    expect(report.bundles.some((b) => b.bundle.root === "." && b.verdict === "block")).toBe(true);
    expect(existsSync(fetched.root)).toBe(false);
  });

  test("scanSource with a name that matches no skill reports no skills (the installer would install none)", async () => {
    const { report, fetched } = await scanSource(`file://${repo}`, { cwd: root.path, env, onlySkills: ["no-such-skill"], keep: false });
    expect(report.bundles.filter((b) => b.bundle.kind === "skill")).toEqual([]);
    expect(existsSync(fetched.dir)).toBe(false);
  });
});

describe("local and unsupported sources", () => {
  test("local sources are scanned in place and cleanup is a no-op", async () => {
    const dir = join(root.path, "local-skill");
    writeFiles(dir, { "SKILL.md": BENIGN_SKILL });
    const { report, fetched } = await scanSource("./local-skill", { cwd: root.path, env, keep: false });
    expect(fetched.dir).toBe(dir);
    expect(report.verdict).toBe("pass");
    expect(readFileSync(join(dir, "SKILL.md"), "utf8")).toBe(BENIGN_SKILL);
  });

  test("owner/repo@skill limits the scan to that skill", async () => {
    const dir = join(root.path, "multi");
    writeFiles(dir, { "a/SKILL.md": BENIGN_SKILL, "b/SKILL.md": MALICIOUS_SKILL });
    const fetched = await fetchSource({ ...parseSource("./multi", root.path, env), skills: ["tidy"] });
    const { scanFetched } = await import("../../src/sources/index");
    expect((await scanFetched(fetched)).verdict).toBe("pass");
    expect((await scanFetched(fetched, { onlySkills: ["*"] })).verdict).toBe("block");
  });

  test("a skill whose name the installer might read differently stays in a restricted scan", async () => {
    const dir = join(root.path, "tricky");
    const evilBody = MALICIOUS_SKILL.slice(MALICIOUS_SKILL.indexOf("---", 3) + 3);
    writeFiles(dir, {
      "helper/SKILL.md": BENIGN_SKILL.replace("name: tidy", "name: helper"),
      "alias/SKILL.md": `---\na: &n helper\nname: *n\ndescription: d\n---${evilBody}`,
      "escaped/SKILL.md": `---\nname: "\\x68elper"\ndescription: d\n---${evilBody}`,
      "flow/SKILL.md": `---\n{name: other, description: d}\n---${evilBody}`,
      "plain/SKILL.md": `---\nname: unrelated\ndescription: d\n---${evilBody}`,
    });
    const fetched = await fetchSource(parseSource("./tricky", root.path, env));
    const { scanFetched } = await import("../../src/sources/index");
    const report = await scanFetched(fetched, { onlySkills: ["helper"] });
    const kept = report.bundles.filter((b) => b.bundle.kind === "skill").map((b) => b.bundle.dirName);
    expect(kept.sort()).toEqual(["alias", "escaped", "flow", "helper"]);
    expect(report.verdict).toBe("block");
  });

  test("missing local paths and direct URLs fail clearly", async () => {
    await expect(fetchSource(parseSource("./nope", root.path, env))).rejects.toThrow(/no such file/);
    await expect(fetchSource(parseSource("https://example.com/skills", root.path, env))).rejects.toThrow(UnsupportedSourceError);
  });
});
