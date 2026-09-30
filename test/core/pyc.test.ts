import { describe, expect, test } from "bun:test";
import { bytecodeDiverges, bytecodeOnlyStrings, pycHeader, pycStrings } from "../../src/core/pyc";

/** A 16-byte PEP 552 header: magic (version number, 0x0d 0x0a), flags, then mtime+size or a source hash. */
function header(version: number, flags: number, sourceSize = 0): Uint8Array {
  const b = new Uint8Array(16);
  const v = new DataView(b.buffer);
  v.setUint16(0, version, true);
  b[2] = 0x0d;
  b[3] = 0x0a;
  v.setUint32(4, flags, true);
  v.setUint32(12, sourceSize, true);
  return b;
}

const enc = new TextEncoder();

/** Marshal short ASCII strings (type `z`, or `Z` with the ref flag) as a pyc body would hold them. */
function shortStrings(...values: string[]): Uint8Array {
  const parts = values.flatMap((s, i) => [i % 2 === 0 ? 0x7a : 0xda, s.length, ...enc.encode(s)]);
  return new Uint8Array(parts);
}

/** A bytes object (type `s`) with non-text content, like the bytecode itself. */
function bytesObject(content: number[]): Uint8Array {
  const b = new Uint8Array(5 + content.length);
  b[0] = 0x73;
  new DataView(b.buffer).setUint32(1, content.length, true);
  b.set(content, 5);
  return b;
}

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

describe("pycHeader", () => {
  test("reads a timestamp pyc and its recorded source size", () => {
    // Arrange / Act / Assert
    expect(pycHeader(header(3495, 0, 834))).toEqual({ invalidation: "timestamp", sourceSize: 834, length: 16 });
  });

  test("tells unchecked and checked hash pycs apart", () => {
    // Arrange / Act / Assert
    expect(pycHeader(header(3495, 1)).invalidation).toBe("unchecked-hash");
    expect(pycHeader(header(3495, 3)).invalidation).toBe("checked-hash");
  });

  test("accepts the hex form that SkillFile.header carries", () => {
    // Arrange
    const hex = Buffer.from(header(3439, 1)).toString("hex");

    // Act / Assert
    expect(pycHeader(hex).invalidation).toBe("unchecked-hash");
  });

  test("reads a pre-3.7 header without a flags word", () => {
    // Arrange
    const b = new Uint8Array(12);
    new DataView(b.buffer).setUint16(0, 3379, true);
    b[2] = 0x0d;
    b[3] = 0x0a;
    new DataView(b.buffer).setUint32(8, 99, true);

    // Act / Assert
    expect(pycHeader(b)).toEqual({ invalidation: "timestamp", sourceSize: 99, length: 12 });
  });

  test("calls anything without the magic suffix unknown", () => {
    // Arrange / Act / Assert
    expect(pycHeader(new Uint8Array(16)).invalidation).toBe("unknown");
    expect(pycHeader(undefined).invalidation).toBe("unknown");
  });
});

describe("pycStrings", () => {
  test("carves short strings with and without the ref flag", () => {
    // Arrange
    const pyc = concat(header(3495, 0), shortStrings("format_text", "system", "environ"));

    // Act / Assert
    expect(pycStrings(pyc)).toEqual(["format_text", "system", "environ"]);
  });

  test("skips a binary bytes object whole instead of carving noise from it", () => {
    // Arrange
    const noise = [0x7a, 3, 0x61, 0x62, 0x63, 0x00, 0xff, 0x01];
    const pyc = concat(header(3495, 0), bytesObject(noise), shortStrings("real_name"));

    // Act / Assert
    expect(pycStrings(pyc)).toEqual(["real_name"]);
  });
});

describe("bytecodeOnlyStrings and bytecodeDiverges", () => {
  const source = "class Formatter:\n    def __init__(self):\n        self.__cache = {}\n\ndef format_text(t):\n    return t.strip()\n";

  test("finds nothing extra in bytecode compiled from the same source", () => {
    // Arrange
    const strings = [
      "Formatter",
      "Formatter.__init__",
      "_Formatter__cache",
      "format_text",
      "strip",
      "<module>",
      "format_text.<locals>.<lambda>",
    ];

    // Act
    const diff = bytecodeOnlyStrings(strings, source);

    // Assert
    expect(diff.names).toEqual([]);
    expect(bytecodeDiverges(diff)).toBe(false);
  });

  test("reports names the source never mentions and calls a telling one divergent", () => {
    // Arrange
    const strings = ["format_text", "system", "whoami>pwn"];

    // Act
    const diff = bytecodeOnlyStrings(strings, source);

    // Assert
    expect(diff.names).toEqual(["system"]);
    expect(diff.constants).toEqual(["whoami>pwn"]);
    expect(bytecodeDiverges(diff)).toBe(true);
  });

  test("needs three unknown names before calling ordinary names divergent", () => {
    // Arrange / Act / Assert
    expect(bytecodeDiverges(bytecodeOnlyStrings(["alpha_one", "beta_two"], source))).toBe(false);
    expect(bytecodeDiverges(bytecodeOnlyStrings(["alpha_one", "beta_two", "gamma_three"], source))).toBe(true);
  });

  test("ignores folded constants and carving noise that look like names", () => {
    // Arrange
    const strings = ["uuuu", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_", "/usr/lib/python3/x.py"];

    // Act / Assert
    expect(bytecodeOnlyStrings(strings, source).names).toEqual([]);
  });
});
