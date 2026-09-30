import { afterAll, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { SourceError, TarError } from "../../src/sources/errors";
import { fetchSource, parseSource, scanSource } from "../../src/sources/index";
import { BENIGN_SKILL, tar, tempDir } from "./helpers";

const root = tempDir("ss-npm-");
afterAll(() => root.remove());

const FAKE_NPM = `#!/bin/sh
printf '%s\\n' "$@" > "$FAKE_NPM_ARGS"
printf '%s' "$npm_config_ignore_scripts" > "$FAKE_NPM_ARGS.env"
if [ -n "$FAKE_NPM_FAIL" ]; then echo "npm ERR! 404 Not Found - GET https://registry.npmjs.org/nope" >&2; exit 1; fi
dest=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--pack-destination" ]; then shift; dest="$1"; fi
  shift
done
cp "$FAKE_NPM_TGZ" "$dest/pkg-1.0.0.tgz"
echo '[{"id":"pkg@1.0.0","integrity":"sha512-abc","filename":"pkg-1.0.0.tgz"}]'
`;

const bin = join(root.path, "bin");
mkdirSync(bin);
writeFileSync(join(bin, "npm"), FAKE_NPM);
chmodSync(join(bin, "npm"), 0o755);

function envFor(tgz: Uint8Array, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const file = join(root.path, `pkg-${Math.random().toString(36).slice(2)}.tgz`);
  writeFileSync(file, tgz);
  return {
    PATH: `${bin}:${process.env.PATH}`,
    HOME: root.path,
    SKILL_SCANNER_HOME: join(root.path, ".ss"),
    FAKE_NPM_TGZ: file,
    FAKE_NPM_ARGS: join(root.path, "args.txt"),
    ...extra,
  };
}

const leftovers = (): string[] => readdirSync(tmpdir()).filter((n) => n.startsWith("skill-scanner-src-"));

describe.skipIf(process.platform === "win32")("npm sources", () => {
  test("packs with scripts off and unpacks package/", async () => {
    const env = envFor(
      gzipSync(
        tar([
          { name: "package/package.json", data: '{"name":"pkg","version":"1.0.0"}' },
          { name: "package/skills/tidy/SKILL.md", data: BENIGN_SKILL },
        ]),
      ),
    );
    const { report, fetched } = await scanSource("npm:pkg@1.0.0", { cwd: root.path, env });
    try {
      expect(fetched.dir.endsWith("/unpacked/package")).toBe(true);
      expect(readFileSync(join(fetched.dir, "skills/tidy/SKILL.md"), "utf8")).toBe(BENIGN_SKILL);
      expect(report.target).toBe("npm:pkg@1.0.0");
      expect(fetched.resolved).toBe("pkg@1.0.0 (sha512-abc)");
      expect(report.bundles.map((b) => b.bundle.name)).toContain("tidy");
    } finally {
      await fetched.cleanup();
    }
    const args = readFileSync(join(root.path, "args.txt"), "utf8").trim().split("\n");
    expect(args.slice(0, 3)).toEqual(["pack", "--json", "--ignore-scripts"]);
    expect(args.slice(-2)).toEqual(["--", "pkg@1.0.0"]);
    expect(readFileSync(join(root.path, "args.txt.env"), "utf8")).toBe("true");
    expect(existsSync(fetched.root)).toBe(false);
  });

  test("a tarball that climbs out is rejected and the temp dir removed", async () => {
    const before = leftovers().length;
    const env = envFor(gzipSync(tar([{ name: "package/../../../evil", data: "x" }])));
    await expect(fetchSource(parseSource("npm:pkg", root.path, env), { env })).rejects.toThrow(TarError);
    expect(leftovers().length).toBe(before);
  });

  test("a tarball with several top-level directories is refused: npm would merge them on install", async () => {
    const env = envFor(
      gzipSync(
        tar([
          { name: "package/SKILL.md", data: BENIGN_SKILL },
          { name: "zzz/SKILL.md", data: "evil" },
        ]),
      ),
    );
    await expect(fetchSource(parseSource("npm:pkg", root.path, env), { env })).rejects.toThrow(/one top-level directory/);
    const loose = envFor(
      gzipSync(
        tar([
          { name: "package/SKILL.md", data: BENIGN_SKILL },
          { name: "README.md", data: "x" },
        ]),
      ),
    );
    await expect(fetchSource(parseSource("npm:pkg", root.path, loose), { env: loose })).rejects.toThrow(/one top-level directory/);
  });

  test("npm failures surface its error", async () => {
    const env = envFor(new Uint8Array(0), { FAKE_NPM_FAIL: "1" });
    await expect(fetchSource(parseSource("npm:nope", root.path, env), { env })).rejects.toThrow(SourceError);
    await expect(fetchSource(parseSource("npm:nope", root.path, env), { env })).rejects.toThrow(/404/);
  });
});
