import { describe, expect, test } from "bun:test";
import { readZip, type ZipLimits } from "../../src/io/zip";
import { buildZip, concat } from "../helpers/zip";

const LIMITS: ZipLimits = { maxEntries: 100, maxEntryBytes: 1024 * 1024, maxTotalBytes: 4 * 1024 * 1024 };
const text = (d: Uint8Array | undefined) => (d ? new TextDecoder().decode(d) : undefined);

describe("readZip: readable entries", () => {
  test("reads stored and deflated entries in central-directory order", () => {
    // Arrange
    const zip = buildZip([
      { name: "SKILL.md", data: "---\nname: z\n---\nhello", method: 8 },
      { name: "scripts/run.sh", data: "echo stored", method: 0 },
    ]);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.notes).toEqual([]);
    expect(r.entries.map((e) => [e.name, e.size, text(e.data), e.skipped])).toEqual([
      ["SKILL.md", 21, "---\nname: z\n---\nhello", undefined],
      ["scripts/run.sh", 11, "echo stored", undefined],
    ]);
  });

  test("marks directory entries without data", () => {
    // Arrange
    const zip = buildZip([
      { name: "dir/", method: 0 },
      { name: "dir/a.txt", data: "a" },
    ]);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries[0]).toEqual({ name: "dir/", size: 0, skipped: "directory" });
    expect(text(r.entries[1]?.data)).toBe("a");
  });

  test("reads an empty archive", () => {
    // Arrange / Act
    const r = readZip(buildZip([]), LIMITS);

    // Assert
    expect(r).toEqual({ entries: [], notes: [] });
  });

  test("finds the end record behind a trailing archive comment", () => {
    // Arrange: an end record with a 5-byte comment.
    const base = buildZip([{ name: "a.txt", data: "abc" }]);
    const withComment = concat([base, new TextEncoder().encode("hello")]);
    new DataView(withComment.buffer).setUint16(base.byteLength - 2, 5, true);

    // Act
    const r = readZip(withComment, LIMITS);

    // Assert
    expect(text(r.entries[0]?.data)).toBe("abc");
  });

  test("reads a zip that sits inside a larger buffer view", () => {
    // Arrange
    const zip = buildZip([{ name: "a.txt", data: "view" }]);
    const padded = concat([new Uint8Array(7), zip]).subarray(7);

    // Act
    const r = readZip(padded, LIMITS);

    // Assert
    expect(text(r.entries[0]?.data)).toBe("view");
  });
});

describe("readZip: entries it refuses to read", () => {
  test("skips encrypted entries", () => {
    // Arrange
    const zip = buildZip([{ name: "secret.bin", data: "x", flags: 0x1 }]);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries).toEqual([{ name: "secret.bin", size: 1, skipped: "encrypted" }]);
  });

  test("skips unsupported compression methods", () => {
    // Arrange
    const zip = buildZip([{ name: "a.bz", data: "x", method: 12 }]);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries).toEqual([{ name: "a.bz", size: 1, skipped: "unsupported-method" }]);
  });

  test("refuses zip64 archives by entry count or directory offset", () => {
    // Arrange
    const byCount = buildZip([{ name: "a", data: "x" }], { eocdCount: 0xffff });
    const byOffset = buildZip([{ name: "a", data: "x" }], { eocdOffset: 0xffffffff });

    // Act / Assert
    expect(readZip(byCount, LIMITS)).toEqual({ entries: [], notes: ["zip64 archives are not read"] });
    expect(readZip(byOffset, LIMITS)).toEqual({ entries: [], notes: ["zip64 archives are not read"] });
  });

  test("reads only the first maxEntries entries and says so", () => {
    // Arrange
    const zip = buildZip(Array.from({ length: 5 }, (_, i) => ({ name: `f${i}.txt`, data: `${i}` })));

    // Act
    const r = readZip(zip, { ...LIMITS, maxEntries: 2 });

    // Assert
    expect(r.entries.map((e) => e.name)).toEqual(["f0.txt", "f1.txt"]);
    expect(r.notes).toEqual(["5 entries; only the first 2 were read"]);
  });

  test("skips an entry whose declared size exceeds maxEntryBytes", () => {
    // Arrange
    const zip = buildZip([{ name: "big.txt", data: "x".repeat(2000) }]);

    // Act
    const r = readZip(zip, { ...LIMITS, maxEntryBytes: 1000 });

    // Assert
    expect(r.entries).toEqual([{ name: "big.txt", size: 2000, skipped: "too-large" }]);
  });

  test("stops reading once the running total would pass maxTotalBytes", () => {
    // Arrange
    const zip = buildZip([
      { name: "a.txt", data: "a".repeat(600) },
      { name: "b.txt", data: "b".repeat(600) },
      { name: "c.txt", data: "c".repeat(100) },
    ]);

    // Act
    const r = readZip(zip, { ...LIMITS, maxTotalBytes: 1000 });

    // Assert
    expect(r.entries.map((e) => [e.name, e.skipped])).toEqual([
      ["a.txt", undefined],
      ["b.txt", "too-large"],
      ["c.txt", undefined],
    ]);
  });

  test("bounds a deflate bomb that understates its size instead of inflating it", () => {
    // Arrange: 1 MiB of zeros deflates to about a kilobyte but claims to be 10 bytes.
    const zip = buildZip([{ name: "bomb.txt", data: new Uint8Array(1024 * 1024), declaredSize: 10 }]);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries).toEqual([{ name: "bomb.txt", size: 10, skipped: "corrupt" }]);
  });

  test("bounds a bomb that claims size zero by maxEntryBytes", () => {
    // Arrange
    const zip = buildZip([{ name: "bomb.txt", data: new Uint8Array(64 * 1024), declaredSize: 0 }]);

    // Act
    const r = readZip(zip, { ...LIMITS, maxEntryBytes: 1024 });

    // Assert
    expect(r.entries[0]?.skipped).toBe("corrupt");
    expect(r.entries[0]?.data).toBeUndefined();
  });

  test("marks a stored entry whose length disagrees with its size as corrupt", () => {
    // Arrange
    const zip = buildZip([{ name: "a.txt", data: "abcd", method: 0, declaredSize: 3 }]);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries).toEqual([{ name: "a.txt", size: 3, skipped: "corrupt" }]);
  });
});

describe("readZip: damaged archives", () => {
  test("reports a missing end-of-central-directory record", () => {
    // Arrange / Act / Assert
    expect(readZip(new TextEncoder().encode("PK not really a zip"), LIMITS)).toEqual({
      entries: [],
      notes: ["no zip end-of-central-directory record"],
    });
    expect(readZip(new Uint8Array(0), LIMITS).notes).toEqual(["no zip end-of-central-directory record"]);
  });

  test("stops at a corrupt central directory header and keeps what it read", () => {
    // Arrange
    const zip = buildZip(
      [
        { name: "a.txt", data: "a" },
        { name: "b.txt", data: "b" },
      ],
      { corruptCentralAt: 1 },
    );

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries.map((e) => e.name)).toEqual(["a.txt"]);
    expect(r.notes).toEqual(["central directory is truncated or corrupt"]);
  });

  test("reports a central directory offset past the end of the file", () => {
    // Arrange
    const zip = buildZip([{ name: "a.txt", data: "a" }], { eocdOffset: 0x7fffffff });

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries).toEqual([]);
    expect(r.notes).toEqual(["central directory is truncated or corrupt"]);
  });

  test("marks an entry whose local header is missing as corrupt", () => {
    // Arrange: overwrite the first local header signature.
    const zip = buildZip([{ name: "a.txt", data: "a" }]);
    new DataView(zip.buffer).setUint32(0, 0, true);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries).toEqual([{ name: "a.txt", size: 1, skipped: "corrupt" }]);
  });

  test("marks an entry whose data is garbage for its method as corrupt", () => {
    // Arrange: a stored-looking body labelled as deflated.
    const zip = buildZip([{ name: "a.txt", data: new Uint8Array([0xff, 0xff, 0xff, 0xff]), method: 0 }]);
    const view = new DataView(zip.buffer);
    const central = zip.byteLength - 22 - (46 + 5);
    view.setUint16(8, 8, true);
    view.setUint16(central + 10, 8, true);

    // Act
    const r = readZip(zip, LIMITS);

    // Assert
    expect(r.entries[0]?.skipped).toBe("corrupt");
  });
});
