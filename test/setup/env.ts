import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CliIO } from "../../src/cli/io";
import { whichBinary } from "../../src/setup/harnesses";

/**
 * A throwaway home for setup tests. Every harness and state location is pointed inside it through
 * the same variables the harnesses read, and PATH holds only `node`, so nothing real is touched or detected.
 */

export interface TempEnv {
  readonly root: string;
  readonly home: string;
  readonly state: string;
  readonly runtimeDir: string;
  readonly env: NodeJS.ProcessEnv;
  cleanup(): Promise<void>;
}

/** A stand-in for the built runtime: the hook allows, scan blocks, like the real one on the canary inputs. */
export const FAKE_RUNTIME: Readonly<Record<string, string>> = {
  "skill-scanner.mjs": [
    "#!/usr/bin/env node",
    "const [cmd] = process.argv.slice(2);",
    'if (cmd === "hook") {',
    '  let d = "";',
    '  process.stdin.on("data", (c) => (d += c));',
    '  process.stdin.on("end", () => {',
    "    JSON.parse(d);",
    "    const deny = { hookSpecificOutput: { permissionDecision: 'deny', permissionDecisionReason: 'nope' } };",
    "    if (process.env.FAKE_HOOK_DENY) process.stdout.write(JSON.stringify(deny));",
    "  });",
    '} else if (cmd === "scan") {',
    '  process.stdout.write(JSON.stringify({ verdict: process.env.FAKE_SCAN_VERDICT ?? "block" }));',
    '  process.exitCode = process.env.FAKE_SCAN_VERDICT === "pass" ? 0 : 1;',
    "} else process.exit(2);",
    "",
  ].join("\n"),
  "opencode-plugin.mjs": "export const SkillScanner = async () => ({ marker: 'opencode' });\n",
  "pi-extension.mjs": "export default function skillScanner() { return 'pi'; }\n",
};

export async function writeFakeRuntime(dir: string, files: Readonly<Record<string, string>> = FAKE_RUNTIME): Promise<void> {
  await mkdir(dir, { recursive: true });
  for (const [name, text] of Object.entries(files)) await writeFile(join(dir, name), text);
}

export async function makeTempEnv(): Promise<TempEnv> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "skill-scanner-setup-")));
  const home = join(root, "home");
  const bin = join(root, "path-bin");
  const runtimeDir = join(root, "runtime");
  await mkdir(home, { recursive: true });
  await mkdir(bin, { recursive: true });
  const node = await whichBinary("node", process.env);
  if (node) await symlink(node, join(bin, "node"));
  else {
    // Fall back to the test runner itself; it runs the fake runtime just as well.
    await writeFile(join(bin, "node"), `#!/bin/sh\nexec "${process.execPath}" "$@"\n`);
    await chmod(join(bin, "node"), 0o755);
  }
  await writeFakeRuntime(runtimeDir);
  const state = join(home, ".skill-scanner");
  const env: NodeJS.ProcessEnv = {
    HOME: home,
    PATH: bin,
    SKILL_SCANNER_HOME: state,
    SKILL_SCANNER_RUNTIME_DIR: runtimeDir,
    CLAUDE_CONFIG_DIR: join(home, ".claude"),
    CODEX_HOME: join(home, ".codex"),
    XDG_CONFIG_HOME: join(home, ".config"),
    PI_CODING_AGENT_DIR: join(home, ".pi", "agent"),
  };
  return { root, home, state, runtimeDir, env, cleanup: () => rm(root, { recursive: true, force: true }) };
}

export interface FakeIO extends CliIO {
  out(): string;
  err(): string;
  readonly asked: string[];
}

export function fakeIO(env: NodeJS.ProcessEnv, cwd: string, opts: { tty?: boolean; answer?: boolean } = {}): FakeIO {
  let out = "";
  let err = "";
  const asked: string[] = [];
  return {
    stdout: (t) => {
      out += t;
    },
    stderr: (t) => {
      err += t;
    },
    isTTY: opts.tty ?? false,
    env,
    cwd,
    readStdin: async () => "",
    confirm: async (q) => {
      asked.push(q);
      return opts.answer ?? false;
    },
    out: () => out,
    err: () => err,
    asked,
  };
}
