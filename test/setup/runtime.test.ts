import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  chooseHookNode,
  findPackageRoot,
  locateRuntimeSource,
  PACKAGE_NAME,
  planRuntime,
  RUNTIME_FILES,
  SetupError,
  selfCommand,
  volatileNodeReason,
} from "../../src/setup/runtime";
import { writeFakeRuntime } from "./env";

const SOURCE = { "skill-scanner.mjs": "cli", "opencode-plugin.mjs": "oc", "pi-extension.mjs": "pi" };

describe("planRuntime", () => {
  test("installs every file with the entry executable, then changes nothing on a re-run", () => {
    const first = planRuntime("/b", SOURCE, {}, "1.2.3");
    expect(first.ops.map((o) => [o.path, o.kind === "write" ? o.mode : undefined])).toEqual([
      ["/b/skill-scanner.mjs", 0o755],
      ["/b/opencode-plugin.mjs", 0o644],
      ["/b/pi-extension.mjs", 0o644],
      ["/b/VERSION", 0o644],
    ]);
    const current = Object.fromEntries(
      first.ops.map((o) => [o.path.slice(3), { text: o.kind === "write" ? o.after : "", mode: o.kind === "write" ? (o.mode ?? 0) : 0 }]),
    );
    const again = planRuntime("/b", SOURCE, current, "1.2.3");
    expect(again.ops).toEqual([]);
    expect(again.unchanged).toHaveLength(4);
  });

  test("updates changed contents, a lost executable bit, and the version file", () => {
    const current = {
      "skill-scanner.mjs": { text: "cli", mode: 0o644 },
      "opencode-plugin.mjs": { text: "old", mode: 0o644 },
      "pi-extension.mjs": { text: "pi", mode: 0o644 },
      VERSION: { text: "1.0.0\n", mode: 0o644 },
    };
    const plan = planRuntime("/b", SOURCE, current, "1.2.3");
    expect(plan.ops.map((o) => o.path)).toEqual(["/b/skill-scanner.mjs", "/b/opencode-plugin.mjs", "/b/VERSION"]);
    expect(plan.ops[0]!.summary).toBe("update runtime (1.2.3)");
  });
});

describe("chooseHookNode", () => {
  const links: Record<string, string> = {
    "/opt/homebrew/bin/node": "/opt/homebrew/Cellar/node/25.9.0_3/bin/node",
    "/usr/bin/node": "/usr/bin/node",
  };
  const realpath = async (p: string) => links[p] ?? p;

  test("prefers a stable PATH link to the same binary over a versioned directory", async () => {
    const choice = await chooseHookNode({
      nodeExecPath: "/opt/homebrew/Cellar/node/25.9.0_3/bin/node",
      nodeVersion: "25.9.0",
      pathNodes: ["/opt/homebrew/bin/node", "/usr/bin/node"],
      realpath,
    });
    expect(choice).toEqual({ path: "/opt/homebrew/bin/node", version: "25.9.0", warnings: [] });
  });

  test("keeps a version-manager Node when nothing stable points at it, with a warning", async () => {
    const nvm = "/home/u/.nvm/versions/node/v22.1.0/bin/node";
    const choice = await chooseHookNode({ nodeExecPath: nvm, nodeVersion: "22.1.0", pathNodes: [nvm, "/usr/bin/node"], realpath });
    expect(choice.path).toBe(nvm);
    expect(choice.warnings[0]).toContain("re-run setup after changing Node versions");
  });

  test("under Bun, uses the first node on PATH; with none, explains", async () => {
    expect((await chooseHookNode({ pathNodes: ["/usr/bin/node"], realpath })).path).toBe("/usr/bin/node");
    await expect(chooseHookNode({ pathNodes: [], realpath })).rejects.toThrow(SetupError);
  });

  test("warns about a Node older than 22", async () => {
    const choice = await chooseHookNode({ nodeExecPath: "/usr/bin/node", nodeVersion: "20.11.0", pathNodes: [], realpath });
    expect(choice.warnings.some((w) => w.includes("older than 22"))).toBe(true);
  });

  test("recognises volatile locations", () => {
    expect(volatileNodeReason("/home/u/.npm/_npx/abc/node_modules/.bin/node")).toContain("npx");
    expect(volatileNodeReason("/home/u/.volta/tools/image/node/22.0.0/bin/node")).toContain("Volta");
    expect(volatileNodeReason("/home/u/.local/share/fnm/node-versions/v22/installation/bin/node")).toContain("fnm");
    expect(volatileNodeReason("/home/u/.asdf/installs/nodejs/22/bin/node")).toContain("asdf");
    expect(volatileNodeReason("/usr/local/bin/node")).toBeUndefined();
  });
});

describe("locating the runtime", () => {
  let dir: string | undefined;
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
    dir = undefined;
  });

  test("finds this checkout as the package root", async () => {
    const root = await findPackageRoot(import.meta.path);
    expect(root).toBe(join(import.meta.dir, "..", ".."));
  });

  test("a source checkout without a build asks for one; an installed runtime copy uses itself", async () => {
    dir = await realpath(await mkdtemp(join(tmpdir(), "skill-scanner-rt-")));
    const pkg = join(dir, "pkg");
    await mkdir(join(pkg, "src", "setup"), { recursive: true });
    await writeFile(join(pkg, "package.json"), JSON.stringify({ name: PACKAGE_NAME }));
    const self = join(pkg, "src", "setup", "runtime.ts");
    await expect(locateRuntimeSource({}, self)).rejects.toThrow("bun run build");
    await writeFakeRuntime(join(pkg, "dist", "runtime"));
    expect(await locateRuntimeSource({}, self)).toEqual({ dir: join(pkg, "dist", "runtime"), packageRoot: pkg });

    const bin = join(dir, "state", "bin");
    await writeFakeRuntime(bin);
    expect(await locateRuntimeSource({}, join(bin, RUNTIME_FILES[0]))).toEqual({ dir: bin });
  });

  test("SKILL_SCANNER_RUNTIME_DIR must hold every runtime file", async () => {
    dir = await realpath(await mkdtemp(join(tmpdir(), "skill-scanner-rt-")));
    await expect(locateRuntimeSource({ SKILL_SCANNER_RUNTIME_DIR: dir })).rejects.toThrow("does not contain");
    await writeFakeRuntime(dir);
    expect((await locateRuntimeSource({ SKILL_SCANNER_RUNTIME_DIR: dir })).dir).toBe(dir);
  });

  test("tells npx users to use npx", () => {
    expect(selfCommand("/home/u/.npm/_npx/1a2b/node_modules/@french-castle/skill-scanner")).toBe(`npx ${PACKAGE_NAME}`);
    expect(selfCommand("/usr/local/lib/node_modules/@french-castle/skill-scanner")).toBe("skill-scanner");
    expect(selfCommand(undefined)).toBe("skill-scanner");
  });
});

describe("--with-skill targets", () => {
  const env = { HOME: "/h", CLAUDE_CONFIG_DIR: "/h/.claude" };
  test("Claude Code gets its own copy, Codex and Pi the shared one, OpenCode whichever it already reads", async () => {
    const { skillTargets } = await import("../../src/setup/index");
    expect(skillTargets(["claude-code"], "user", env, "/p")).toEqual(["/h/.claude/skills/skill-scanner"]);
    expect(skillTargets(["claude-code", "opencode"], "user", env, "/p")).toEqual(["/h/.claude/skills/skill-scanner"]);
    expect(skillTargets(["opencode"], "user", env, "/p")).toEqual(["/h/.agents/skills/skill-scanner"]);
    expect(skillTargets(["claude-code", "pi"], "project", env, "/p")).toEqual([
      "/p/.claude/skills/skill-scanner",
      "/p/.agents/skills/skill-scanner",
    ]);
  });
});
