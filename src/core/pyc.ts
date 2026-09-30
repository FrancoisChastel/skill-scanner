/**
 * Python bytecode (.pyc) inspection without running Python: the PEP 552 header, and the names and
 * string constants carved from the marshalled code object. A skill that ships bytecode next to its
 * source can make Python run code that is not in the source you reviewed; both checks catch that.
 */

export type PycInvalidation = "timestamp" | "checked-hash" | "unchecked-hash" | "unknown";

export interface PycHeader {
  /** How Python decides whether the bytecode is stale. `unchecked-hash` means it never checks. */
  readonly invalidation: PycInvalidation;
  /** Source size recorded in a timestamp pyc. */
  readonly sourceSize?: number;
  /** Header length in bytes: 16 since Python 3.7, 12 before. */
  readonly length: number;
}

/** First magic number of Python 3.7, the release that added the flags word. */
const MAGIC_37 = 3390;

const u32 = (b: ArrayLike<number>, i: number): number =>
  ((b[i] ?? 0) | ((b[i + 1] ?? 0) << 8) | ((b[i + 2] ?? 0) << 16) | ((b[i + 3] ?? 0) << 24)) >>> 0;

/** Parse the header from its first 16 bytes, as hex (SkillFile.header) or raw bytes. */
export function pycHeader(header: string | Uint8Array | undefined): PycHeader {
  const bytes = typeof header === "string" ? (header.match(/../g) ?? []).map((h) => Number.parseInt(h, 16)) : Array.from(header ?? []);
  if (bytes.length < 12 || bytes[2] !== 0x0d || bytes[3] !== 0x0a) return { invalidation: "unknown", length: 16 };
  const magic = (bytes[0] ?? 0) | ((bytes[1] ?? 0) << 8);
  if (magic < MAGIC_37) return { invalidation: "timestamp", sourceSize: u32(bytes, 8), length: 12 };
  if (bytes.length < 16) return { invalidation: "unknown", length: 16 };
  const flags = u32(bytes, 4);
  if (flags === 0) return { invalidation: "timestamp", sourceSize: u32(bytes, 12), length: 16 };
  if (flags === 1) return { invalidation: "unchecked-hash", length: 16 };
  if (flags === 3) return { invalidation: "checked-hash", length: 16 };
  return { invalidation: "unknown", length: 16 };
}

const MAX_STRINGS = 4000;
const MAX_STRING = 4096;

/** Marshal type codes for strings; bit 0x80 (FLAG_REF) may be set on any of them. */
const SHORT_ASCII = new Set([0x7a, 0x5a]); // z Z: one-byte length
const LONG_STRING = new Set([0x61, 0x41, 0x75, 0x74]); // a A u t: four-byte length
const BYTES = 0x73; // s: four-byte length; code, line tables, and bytes constants

const printable = (b: Uint8Array, from: number, len: number, allowHigh: boolean): boolean => {
  for (let k = from; k < from + len; k += 1) {
    const c = b[k]!;
    if (c === 0x09 || c === 0x0a || c === 0x0d || (c >= 0x20 && c < 0x7f) || (allowHigh && c >= 0x80)) continue;
    return false;
  }
  return true;
};

/**
 * The string objects in a pyc's marshalled code: names, identifiers, and string constants, in file
 * order. A carving walk rather than a full unmarshal, so it works across Python versions; bytes
 * objects that are not text (the bytecode itself, line tables) are skipped whole.
 */
export function pycStrings(bytes: Uint8Array): string[] {
  const out: string[] = [];
  const header = pycHeader(bytes.subarray(0, 16));
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let i = header.length;
  while (i < bytes.length && out.length < MAX_STRINGS) {
    const t = bytes[i]! & 0x7f;
    if (SHORT_ASCII.has(t)) {
      const len = bytes[i + 1] ?? 0;
      if (len > 0 && i + 2 + len <= bytes.length && printable(bytes, i + 2, len, false)) {
        out.push(decoder.decode(bytes.subarray(i + 2, i + 2 + len)));
        i += 2 + len;
        continue;
      }
    } else if (LONG_STRING.has(t) || t === BYTES) {
      const len = u32(bytes, i + 1);
      if (len > 0 && len <= MAX_STRING && i + 5 + len <= bytes.length) {
        if (printable(bytes, i + 5, len, t === 0x75 || t === 0x74)) {
          out.push(decoder.decode(bytes.subarray(i + 5, i + 5 + len)));
          i += 5 + len;
          continue;
        }
        if (t === BYTES) {
          i += 5 + len;
          continue;
        }
      }
    }
    i += 1;
  }
  return out;
}

const IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]{2,}$/;
/** A constant that could appear verbatim in the source: one line, no quotes or escapes, some words. */
const VERBATIM_CONSTANT_RE = /^[^\n\r\\"'`]{4,200}$/;

export interface BytecodeOnly {
  /** Identifiers (names, attributes, variables) the source never mentions: decisive. */
  readonly names: readonly string[];
  /**
   * String constants the source does not contain verbatim. Only evidence: the compiler folds
   * `"a" "b"` and `"a" + "b"` into constants the source never spells out.
   */
  readonly constants: readonly string[];
}

/**
 * What the bytecode contains that the source does not. Compiled from the same source, every
 * identifier appears in it (private names after undoing `_Class__name` mangling), so a missing
 * name means the bytecode was compiled from other code.
 */
export function bytecodeOnlyStrings(strings: readonly string[], source: string): BytecodeOnly {
  const names = new Set<string>();
  const constants = new Set<string>();
  const check = (s: string): void => {
    if ((s.startsWith("__") && s.endsWith("__")) || s.startsWith("<")) return;
    if (IDENTIFIER_RE.test(s)) {
      // Long or single-letter runs are folded constants or carving noise, not names.
      if (s.length > 40 || new Set(s).size <= 2) return;
      const unmangled = /^_[A-Za-z]\w*?(__\w+)$/.exec(s)?.[1] ?? s;
      if (!source.includes(unmangled)) names.add(s);
    } else if (VERBATIM_CONSTANT_RE.test(s) && /[A-Za-z]{3}/.test(s) && !source.includes(s)) constants.add(s);
  };
  for (const s of strings) {
    if (s.includes("/") || s.includes("\\") || s.endsWith(".py")) continue;
    // Qualified names (`Class.method`, `main.<locals>.<lambda>`) are built by the compiler from parts in the source.
    if (/^[\w<>]+(?:\.[\w<>]+)+$/.test(s)) for (const part of s.split(".")) check(part);
    else check(s);
  }
  return { names: [...names], constants: [...constants] };
}

/** Names whose presence in unreadable bytecode says what it does: run commands, read secrets, reach the network, hide code. */
const TELLING_NAMES = new Set([
  "system",
  "popen",
  "Popen",
  "exec",
  "eval",
  "compile",
  "environ",
  "getenv",
  "subprocess",
  "check_output",
  "check_call",
  "spawn",
  "execv",
  "execve",
  "fork",
  "socket",
  "connect",
  "urlopen",
  "urllib",
  "request",
  "requests",
  "post",
  "b64decode",
  "decompress",
  "marshal",
  "loads",
  "import_module",
  "rmtree",
  "unlink",
  "chmod",
  "ctypes",
]);

/** Whether the names missing from the source are enough to say the bytecode is other code. */
export function bytecodeDiverges(diff: BytecodeOnly): boolean {
  return diff.names.length >= 3 || diff.names.some((n) => TELLING_NAMES.has(n));
}
