import { afterAll, describe, expect, test } from "bun:test";
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stageTree } from "../../src/analyzers/stage";

const base = mkdtempSync(join(tmpdir(), "ss-stage-"));
afterAll(() => rmSync(base, { recursive: true, force: true }));

describe("stageTree", () => {
  test("copies regular files, leaves out skipped paths, symlinks, and oversized files", async () => {
    // Arrange
    const src = join(base, "src");
    mkdirSync(join(src, "a", "b"), { recursive: true });
    writeFileSync(join(src, "a", "b", "keep.txt"), "keep");
    writeFileSync(join(src, "skip.me"), "no");
    writeFileSync(join(src, "big.bin"), "x".repeat(2048));
    symlinkSync("/etc/passwd", join(src, "link"));
    const dest = join(base, "dest");

    // Act
    await stageTree(src, dest, { skip: (rel) => rel === "skip.me", maxFileBytes: 1024, maxEntries: 100 });

    // Assert
    expect(readdirSync(dest).sort()).toEqual(["a"]);
    expect(readFileSync(join(dest, "a", "b", "keep.txt"), "utf8")).toBe("keep");
    expect(lstatSync(join(dest, "a", "b", "keep.txt")).isFile()).toBe(true);
  });

  test("more entries than the limit is an error", async () => {
    const src = join(base, "many");
    mkdirSync(src);
    for (let i = 0; i < 5; i += 1) writeFileSync(join(src, `f${i}`), "x");
    await expect(stageTree(src, join(base, "many-dest"), { skip: () => false, maxFileBytes: 10, maxEntries: 3 })).rejects.toThrow(
      "more than 3",
    );
  });
});
