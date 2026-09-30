import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { TarError } from "../../src/sources/errors";
import { extractEntries, readTar, readTarGz } from "../../src/sources/tar";
import { pax, type TarTestEntry, tar, tempDir } from "./helpers";

const dirs: { remove: () => void }[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) d.remove();
});

describe("readTar", () => {
  test("reads files and directories; links are reported, never extracted (npm does not install them)", () => {
    const { entries, skipped } = readTar(
      tar([
        { name: "package/", type: "5", mode: 0o755 },
        { name: "package/SKILL.md", data: "# hi\n" },
        { name: "package/run.sh", data: "echo hi\n", mode: 0o4755 },
        { name: "package/link", type: "2", linkname: "../../etc/passwd" },
        { name: "package/hard", type: "1", linkname: "package/SKILL.md" },
      ]),
    );
    expect(entries.map((e) => [e.type, e.path])).toEqual([
      ["dir", "package"],
      ["file", "package/SKILL.md"],
      ["file", "package/run.sh"],
    ]);
    expect(skipped).toEqual([
      'package/link: symlink to "../../etc/passwd" not extracted (npm does not install links)',
      "package/hard: hard link not extracted (npm does not install links)",
    ]);
  });

  test("ustar prefix, GNU long names, and pax paths", () => {
    const long = `package/${"d".repeat(120)}/SKILL.md`;
    const { entries } = readTar(
      tar([
        { name: "SKILL.md", prefix: "package/nested", data: "a" },
        { name: "././@LongLink", type: "L", data: `${long}\0`, gnu: true },
        { name: "truncated", data: "b", gnu: true },
        { name: "PaxHeader", type: "x", data: pax({ path: "package/pax-name.md", mtime: "1" }) },
        { name: "short", data: "c" },
      ]),
    );
    expect(entries.map((e) => e.path)).toEqual(["package/nested/SKILL.md", long, "package/pax-name.md"]);
  });

  test("later duplicates win", () => {
    const { entries } = readTar(
      tar([
        { name: "a.md", data: "one" },
        { name: "a.md", data: "two" },
      ]),
    );
    expect(entries).toHaveLength(1);
    const e = entries[0]!;
    expect(e.type === "file" && new TextDecoder().decode(e.data)).toBe("two");
  });

  const UNSAFE: readonly (readonly [string, TarTestEntry[]])[] = [
    ["absolute path", [{ name: "/etc/passwd", data: "x" }]],
    ["dot-dot", [{ name: "package/../../escape", data: "x" }]],
    [
      "dot-dot via pax",
      [
        { name: "p", type: "x", data: pax({ path: "../escape" }) },
        { name: "ok", data: "x" },
      ],
    ],
    [
      "dot-dot via GNU long name",
      [
        { name: "././@LongLink", type: "L", data: "a/../../b", gnu: true },
        { name: "ok", data: "x", gnu: true },
      ],
    ],
    ["backslash", [{ name: "package\\..\\x", data: "x" }]],
    ["windows drive", [{ name: "C:/x", data: "x" }]],
    ["data after a lone end-of-archive block", [{ name: "a", data: "x" }]],
    [
      "a global pax path",
      [
        { name: "g", type: "g", data: pax({ path: "package/x" }) },
        { name: "ok", data: "x" },
      ],
    ],
    [
      "a global pax size",
      [
        { name: "g", type: "g", data: pax({ size: "3" }) },
        { name: "ok", data: "x" },
      ],
    ],
  ];
  for (const [what, entries] of UNSAFE) {
    test(`rejects ${what}`, () => {
      const archive = what.startsWith("data after") ? hiddenAfterZeroBlock(tar(entries)) : tar(entries);
      expect(() => readTar(archive)).toThrow(TarError);
    });
  }

  test("a global pax header with other keys is ignored", () => {
    const { entries } = readTar(
      tar([
        { name: "g", type: "g", data: pax({ comment: "hi" }) },
        { name: "ok", data: "x" },
      ]),
    );
    expect(entries.map((e) => e.path)).toEqual(["ok"]);
  });

  test("rejects a bad checksum and truncated data", () => {
    const good = tar([{ name: "a", data: "hello" }]);
    const bad = Uint8Array.from(good);
    bad[0] = 0x62;
    expect(() => readTar(bad)).toThrow(/checksum/);
    expect(() => readTar(good.subarray(0, 512 + 2))).toThrow(/truncated/);
  });

  test("enforces entry, size, and count limits", () => {
    const big = tar([{ name: "a", data: "x".repeat(2000) }]);
    expect(() => readTar(big, { maxEntries: 10, maxEntryBytes: 1000, maxTotalBytes: 10_000 })).toThrow(/larger than/);
    const many = tar(Array.from({ length: 5 }, (_, i) => ({ name: `f${i}`, data: "x" })));
    expect(() => readTar(many, { maxEntries: 3, maxEntryBytes: 1000, maxTotalBytes: 10_000 })).toThrow(/more than 3 entries/);
    const total = tar(Array.from({ length: 5 }, (_, i) => ({ name: `f${i}`, data: "x".repeat(600) })));
    expect(() => readTar(total, { maxEntries: 10, maxEntryBytes: 1000, maxTotalBytes: 2000 })).toThrow(/exceeds/);
  });

  test("gzip: rejects non-gzip input and archives that expand past the limit", () => {
    expect(() => readTarGz(new TextEncoder().encode("not gzip"))).toThrow(/not a gzip/);
    const bomb = gzipSync(new Uint8Array(4 * 1024 * 1024));
    expect(() => readTarGz(bomb, { maxEntries: 10, maxEntryBytes: 1000, maxTotalBytes: 64 * 1024 })).toThrow(/expands beyond/);
  });
});

describe("extractEntries", () => {
  test("writes files with safe modes and creates no links, even for colliding link names", async () => {
    const d = tempDir();
    dirs.push(d);
    const { entries } = readTarGz(
      gzipSync(
        tar([
          { name: "package/SKILL.md", data: "# hi\n" },
          { name: "package/bin/run.sh", data: "echo\n", mode: 0o6777 },
          // A link and a path through a differently cased twin: the classic case-insensitive escape.
          { name: "package/A", type: "2", linkname: d.path },
          { name: "package/a/x", type: "2", linkname: "/etc/passwd" },
        ]),
      ),
    );
    await extractEntries(entries, join(d.path, "out"));
    expect(readFileSync(join(d.path, "out/package/SKILL.md"), "utf8")).toBe("# hi\n");
    const mode = statSync(join(d.path, "out/package/bin/run.sh")).mode & 0o7777;
    expect(mode & 0o6000).toBe(0);
    expect(mode & 0o100).toBe(0o100);
    expect(readdirSync(join(d.path, "out/package")).sort()).toEqual(["SKILL.md", "bin"]);
    expect(existsSync(join(d.path, "x"))).toBe(false);
  });
});

/** Append an entry after a single zero block, where npm's parser would still read it. */
function hiddenAfterZeroBlock(archive: Uint8Array): Uint8Array {
  const body = archive.subarray(0, archive.length - 1024);
  const hidden = tar([{ name: "package/hidden.md", data: "evil" }]);
  const out = new Uint8Array(body.length + 512 + hidden.length);
  out.set(body, 0);
  out.set(hidden, body.length + 512);
  return out;
}
