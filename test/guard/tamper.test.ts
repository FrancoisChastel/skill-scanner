import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CONFIG } from "../../src/config";
import { evaluateCommand } from "../../src/guard";
import { guardTampering } from "../../src/guard/tamper";

describe("guardTampering", () => {
  test.each([
    ["GIT_CONFIG_COUNT=0 npx skills add acme/skills -y", "git configuration"],
    ["env GIT_CONFIG_PARAMETERS= npx skills update", "git configuration"],
    ["git -c core.hooksPath=/dev/null clone https://github.com/acme/skills ~/.claude/skills/x", "hooks path"],
    ["git -c url.file:///tmp/x.insteadOf=https://github.com/ clone https://github.com/a/b", "URL rewriting"],
    ["SKILLS_DOWNLOAD_URL=https://cdn.example npx skills add vercel-labs/agent-skills", "download endpoint"],
    ["SKILL_SCANNER_APPROVED_COMMITS=abc npx skills update", "skill-scanner's own settings"],
    ["env -i PATH=/usr/bin npx skills add acme/skills", "cleared environment"],
    ["unset GIT_CONFIG_COUNT; npx skills add acme/skills", "git configuration"],
  ])("%s", (command, what) => {
    expect(guardTampering(command)).toContain(what);
  });

  test.each([
    "npx skills add acme/skills -y -g",
    "git clone https://github.com/acme/skills ~/.claude/skills/x",
    "pi install git:github.com/acme/pkg",
  ])("leaves %s alone", (command) => {
    expect(guardTampering(command)).toBeUndefined();
  });
});

describe("evaluateCommand with a tampering install", () => {
  test("denies without scanning", async () => {
    // Arrange
    const home = await mkdtemp(join(tmpdir(), "skill-scanner-test-"));
    const env = { HOME: home, SKILL_SCANNER_HOME: join(home, ".skill-scanner") };
    let scanned = false;

    // Act
    const decision = await evaluateCommand(
      "GIT_CONFIG_COUNT=0 npx skills add acme/skills -y",
      { harness: "claude-code", cwd: home, env, config: DEFAULT_CONFIG },
      {
        scanSource: async () => {
          scanned = true;
          throw new Error("must not scan");
        },
      },
    );

    // Assert
    expect(decision.action).toBe("deny");
    expect(decision.reason).toContain("git configuration");
    expect(decision.rewrite).toBeUndefined();
    expect(scanned).toBe(false);
    await rm(home, { recursive: true, force: true });
  });

  test("an ordinary command that mentions the variables is not an install and passes", async () => {
    const home = await mkdtemp(join(tmpdir(), "skill-scanner-test-"));
    const decision = await evaluateCommand("echo $GIT_CONFIG_COUNT", {
      harness: "claude-code",
      cwd: home,
      env: { HOME: home, SKILL_SCANNER_HOME: join(home, ".skill-scanner") },
      config: DEFAULT_CONFIG,
    });
    expect(decision.action).toBe("allow");
    await rm(home, { recursive: true, force: true });
  });
});

describe("guardTampering sees what the shell sees", () => {
  test.each([
    ["export GIT_CONFIG_COU''NT=0; npx skills update", "git configuration"],
    ['export GIT_CONFIG_COU""NT=0 && npx skills add acme/skills', "git configuration"],
    ["git -c co''re.hooksPath=/tmp/x clone https://github.com/acme/skills ~/.claude/skills/x", "hooks path"],
    ["sh -c \"export GIT_CONFIG_COU''NT=0; git clone file:///tmp/r d\"", "git configuration"],
    ["bash -lc 'unset GIT_CONFIG_COU''NT; npx skills update'", "git configuration"],
    ["eval 'export GIT_CONFIG_COU''NT=0'; npx skills update", "git configuration"],
    ["echo $(export SKILLS_DOWNLOAD_U''RL=x); npx skills add a/b", "download endpoint"],
    ["V=GIT_CONFIG_; export ${V}COUNT=0; npx skills update", "computed at run time"],
    ['X="export A=1"; eval "$X"; npx skills update', "eval of text computed at run time"],
    ["unset $V; npx skills update", "computed at run time"],
  ])("%s", (command, what) => {
    expect(guardTampering(command)).toContain(what);
  });

  test.each([
    "unset HTTP_PROXY; npx skills add acme/skills",
    "env -u FOO npx skills add acme/skills",
    "export NODE_OPTIONS=--max-old-space-size=4096; npx skills add a/b",
  ])("leaves %s alone", (command) => {
    expect(guardTampering(command)).toBeUndefined();
  });
});
