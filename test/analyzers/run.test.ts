import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { runTool, which, whichAll } from "../../src/analyzers/run";

const IS_WINDOWS = process.platform === "win32";
const node = process.execPath;
let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "analyzers-run-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function fakeExecutable(path: string, mode = 0o755): Promise<void> {
  await writeFile(path, "#!/bin/sh\nexit 0\n");
  await chmod(path, mode);
}

describe("which", () => {
  test.skipIf(IS_WINDOWS)("finds an executable on PATH and ignores non-executables and missing names", async () => {
    // Arrange
    const bin = join(dir, "bin-a");
    await mkdir(bin);
    await fakeExecutable(join(bin, "fake-tool"));
    await fakeExecutable(join(bin, "not-executable"), 0o644);
    const env = { PATH: bin };

    // Act / Assert
    expect(await which("fake-tool", env)).toBe(join(bin, "fake-tool"));
    expect(await which("not-executable", env)).toBeUndefined();
    expect(await which("missing-tool", env)).toBeUndefined();
  });

  test.skipIf(IS_WINDOWS)("skips relative and empty PATH entries, which would resolve against the cwd", async () => {
    // Arrange
    const env = { PATH: ["", ".", "relative/bin"].join(delimiter) };

    // Act / Assert
    expect(await which("fake-tool", env)).toBeUndefined();
  });

  test.skipIf(IS_WINDOWS)("whichAll lists every match in PATH order", async () => {
    // Arrange
    const first = join(dir, "bin-first");
    const second = join(dir, "bin-second");
    await mkdir(first);
    await mkdir(second);
    await fakeExecutable(join(first, "dup-tool"));
    await fakeExecutable(join(second, "dup-tool"));
    const env = { PATH: [first, second, first].join(delimiter) };

    // Act
    const all = await whichAll("dup-tool", env);

    // Assert
    expect(all).toEqual([join(first, "dup-tool"), join(second, "dup-tool")]);
    expect(await which("dup-tool", env)).toBe(join(first, "dup-tool"));
  });
});

describe("runTool", () => {
  test("returns the exit code and both output streams", async () => {
    // Arrange / Act
    const r = await runTool(node, ["-e", "process.stdout.write('out'); process.stderr.write('err'); process.exit(3)"]);

    // Assert
    expect(r).toEqual({ code: 3, stdout: "out", stderr: "err", timedOut: false, truncated: false });
  });

  test("passes arguments verbatim, without a shell", async () => {
    // Arrange
    const hostile = "a; echo $HOME `id` $(whoami) | cat > /dev/null";

    // Act
    const r = await runTool(node, ["-e", "process.stdout.write(process.argv[1])", hostile]);

    // Assert
    expect(r.stdout).toBe(hostile);
  });

  test("kills the tool on timeout", async () => {
    // Arrange / Act
    const started = performance.now();
    const r = await runTool(node, ["-e", "setInterval(() => {}, 1000)"], { timeoutMs: 300 });

    // Assert
    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
    expect(performance.now() - started).toBeLessThan(5_000);
  });

  test.skipIf(IS_WINDOWS)("kills the whole process group on timeout, grandchildren included", async () => {
    // Arrange
    const pidFile = join(dir, "grandchild.pid");
    const script = [
      "const { spawn } = require('node:child_process');",
      `const c = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });`,
      `require('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(c.pid));`,
      "setInterval(() => {}, 1000);",
    ].join("\n");

    // Act
    const r = await runTool(node, ["-e", script], { timeoutMs: 1_000 });
    const pid = Number(await readFile(pidFile, "utf8"));
    await Bun.sleep(200);

    // Assert
    expect(r.timedOut).toBe(true);
    expect(() => process.kill(pid, 0)).toThrow();
  });

  test("caps output, marks it truncated, and stops the tool", async () => {
    // Arrange / Act
    const r = await runTool(node, ["-e", "process.stdout.write('x'.repeat(5_000_000)); setInterval(() => {}, 1000)"], {
      maxOutputBytes: 1_000,
      timeoutMs: 10_000,
    });

    // Assert
    expect(r.truncated).toBe(true);
    expect(r.timedOut).toBe(false);
    expect(r.stdout.length).toBe(1_000);
  });

  test("rejects with a readable error when the binary does not exist", async () => {
    // Arrange / Act / Assert
    await expect(runTool(join(dir, "no-such-binary"), [])).rejects.toThrow(/cannot run/);
  });

  test("rejects when the signal aborts the run, and when it is already aborted", async () => {
    // Arrange
    const running = new AbortController();
    setTimeout(() => running.abort(), 100);

    // Act / Assert
    await expect(runTool(node, ["-e", "setInterval(() => {}, 1000)"], { signal: running.signal })).rejects.toThrow(/aborted/);
    await expect(runTool(node, ["-e", "1"], { signal: AbortSignal.abort() })).rejects.toThrow(/aborted before start/);
  });

  test("runs in the given cwd with the given environment", async () => {
    // Arrange
    const env = { ...process.env, ANALYZER_TEST_VALUE: "from-env" };

    // Act
    const r = await runTool(node, ["-e", "process.stdout.write(process.cwd() + '|' + process.env.ANALYZER_TEST_VALUE)"], { cwd: dir, env });

    // Assert
    const [cwd, value] = r.stdout.split("|");
    expect(await realpath(cwd!)).toBe(await realpath(dir));
    expect(value).toBe("from-env");
  });
});
