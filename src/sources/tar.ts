import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { gunzipSync } from "node:zlib";
import { TarError } from "./errors";

/**
 * A minimal, strict tar reader for npm tarballs: ustar and GNU headers, GNU long names (`L`,
 * `K`), and pax `path`/`size`. It reads the same entries npm's extractor installs, and refuses
 * archives where the two could disagree (data after an end marker, global pax paths or sizes).
 * Only files and directories are extracted, as npm does: symlinks and hard links are reported
 * as skipped and never created, so nothing can be written through a link, whatever the case
 * sensitivity or Unicode normalization of the file system. Absolute paths and `..` are refused.
 */

export interface TarLimits {
  readonly maxEntries: number;
  readonly maxEntryBytes: number;
  readonly maxTotalBytes: number;
}

export const DEFAULT_TAR_LIMITS: TarLimits = Object.freeze({
  maxEntries: 10_000,
  maxEntryBytes: 32 * 1024 * 1024,
  maxTotalBytes: 128 * 1024 * 1024,
});

export type TarEntry =
  | { readonly type: "file"; readonly path: string; readonly mode: number; readonly data: Uint8Array }
  | { readonly type: "dir"; readonly path: string; readonly mode: number };

export interface TarContents {
  readonly entries: readonly TarEntry[];
  /** Entries that were present but not extracted (links, devices), with why. */
  readonly skipped: readonly string[];
}

const BLOCK = 512;

interface Header {
  readonly name: string;
  readonly mode: number;
  readonly size: number;
  readonly type: string;
  readonly linkname: string;
}

interface Pending {
  readonly path?: string;
  readonly linkpath?: string;
  readonly size?: number;
}

export function readTarGz(gz: Uint8Array, limits: TarLimits = DEFAULT_TAR_LIMITS): TarContents {
  let tar: Uint8Array;
  try {
    tar = gunzipSync(gz, { maxOutputLength: limits.maxTotalBytes + 64 * BLOCK });
  } catch (e) {
    const tooBig = e instanceof RangeError || (e as NodeJS.ErrnoException).code === "ERR_BUFFER_TOO_LARGE";
    throw new TarError(tooBig ? `archive expands beyond ${limits.maxTotalBytes} bytes` : `not a gzip archive: ${(e as Error).message}`);
  }
  return readTar(tar, limits);
}

/** Entries are views into `buf`; keep it alive while they are used. */
export function readTar(buf: Uint8Array, limits: TarLimits = DEFAULT_TAR_LIMITS): TarContents {
  const byPath = new Map<string, TarEntry>();
  const skipped: string[] = [];
  let pending: Pending = {};
  let total = 0;
  let count = 0;
  let offset = 0;
  while (offset + BLOCK <= buf.length) {
    const block = buf.subarray(offset, offset + BLOCK);
    if (isZero(block)) {
      assertEndOfArchive(buf, offset);
      break;
    }
    const header = parseHeader(block, offset);
    const size = pending.size ?? header.size;
    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + size;
    if (size > limits.maxEntryBytes) throw new TarError(`entry "${header.name}" is larger than ${limits.maxEntryBytes} bytes`);
    if (dataEnd > buf.length) throw new TarError(`archive is truncated inside "${header.name}"`);
    const data = buf.subarray(dataStart, dataEnd);
    offset = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    const meta = metadataUpdate(header.type, data, pending);
    if (meta) {
      pending = meta;
      continue;
    }
    const rawPath = pending.path ?? header.name;
    const target = pending.linkpath ?? header.linkname;
    pending = {};
    count += 1;
    if (count > limits.maxEntries) throw new TarError(`archive has more than ${limits.maxEntries} entries`);
    total += size;
    if (total > limits.maxTotalBytes) throw new TarError(`archive content exceeds ${limits.maxTotalBytes} bytes`);

    const path = safePath(rawPath);
    if (path === undefined) continue;
    const entry = toEntry(header.type, path, header.mode, data, target);
    if (typeof entry === "string") skipped.push(`${path}: ${entry}`);
    else byPath.set(path, entry);
  }
  return { entries: [...byPath.values()], skipped };
}

/** The pending metadata after a metadata entry (pax, GNU long name), or undefined for a real entry. */
function metadataUpdate(type: string, data: Uint8Array, pending: Pending): Pending | undefined {
  switch (type) {
    case "x":
      return { ...pending, ...paxEntry(parsePax(data)) };
    case "g": {
      // npm's extractor applies global pax keys to every later entry; we do not, so refuse the ones that matter.
      const keys = [...parsePax(data).keys()].filter((k) => k === "path" || k === "linkpath" || k === "size");
      if (keys.length > 0) throw new TarError(`global pax header sets ${keys.join(", ")}`);
      return pending;
    }
    case "L":
      return { ...pending, path: cString(data) };
    case "K":
      return { ...pending, linkpath: cString(data) };
    default:
      return undefined;
  }
}

function toEntry(type: string, path: string, mode: number, data: Uint8Array, target: string): TarEntry | string {
  switch (type) {
    case "0":
    case "\0":
    case "7":
    case "":
      return { type: "file", path, mode, data };
    case "5":
      return { type: "dir", path, mode };
    case "2":
      return `symlink to "${target}" not extracted (npm does not install links)`;
    case "1":
      return "hard link not extracted (npm does not install links)";
    default:
      return `entry type "${type}" not extracted`;
  }
}

/** Two zero blocks end an archive. npm's parser reads past a lone zero block, so data after one is refused. */
function assertEndOfArchive(buf: Uint8Array, offset: number): void {
  const rest = buf.subarray(offset);
  if (!isZero(rest)) throw new TarError(`data after an end-of-archive block at offset ${offset}`);
}

const isZero = (bytes: Uint8Array): boolean => bytes.every((b) => b === 0);

function parseHeader(block: Uint8Array, offset: number): Header {
  const stored = parseOctal(block.subarray(148, 156));
  let sum = 0;
  for (let i = 0; i < BLOCK; i += 1) sum += i >= 148 && i < 156 ? 0x20 : block[i]!;
  if (stored !== sum) throw new TarError(`bad tar header checksum at offset ${offset}`);
  const magic = cString(block.subarray(257, 263));
  const prefix = magic.startsWith("ustar") && block[263] === 0x30 ? cString(block.subarray(345, 500)) : "";
  const name = cString(block.subarray(0, 100));
  return {
    name: prefix ? `${prefix}/${name}` : name,
    mode: parseOctal(block.subarray(100, 108)),
    size: parseNumeric(block.subarray(124, 136)),
    type: String.fromCharCode(block[156]!),
    linkname: cString(block.subarray(157, 257)),
  };
}

/** Octal, or GNU base-256 when the high bit of the first byte is set. */
function parseNumeric(field: Uint8Array): number {
  if ((field[0]! & 0x80) === 0) return parseOctal(field);
  let n = field[0]! & 0x7f;
  for (let i = 1; i < field.length; i += 1) {
    n = n * 256 + field[i]!;
    if (n > Number.MAX_SAFE_INTEGER) throw new TarError("tar size field out of range");
  }
  return n;
}

function parseOctal(field: Uint8Array): number {
  const text = cString(field).trim();
  if (text === "") return 0;
  if (!/^[0-7]+$/.test(text)) throw new TarError(`bad octal field "${text}"`);
  return Number.parseInt(text, 8);
}

function cString(bytes: Uint8Array): string {
  const end = bytes.indexOf(0);
  return new TextDecoder().decode(end === -1 ? bytes : bytes.subarray(0, end));
}

/** pax records: `<len> <key>=<value>\n`, where len counts the whole record in bytes. */
function parsePax(data: Uint8Array): Map<string, string> {
  const out = new Map<string, string>();
  let i = 0;
  while (i < data.length) {
    const space = data.indexOf(0x20, i);
    if (space === -1) break;
    const len = Number.parseInt(new TextDecoder().decode(data.subarray(i, space)), 10);
    if (!Number.isInteger(len) || len <= 0 || i + len > data.length) throw new TarError("bad pax header");
    const record = new TextDecoder().decode(data.subarray(space + 1, i + len - 1));
    const eq = record.indexOf("=");
    if (eq > 0) out.set(record.slice(0, eq), record.slice(eq + 1));
    i += len;
  }
  return out;
}

function paxEntry(records: Map<string, string>): Pending {
  const size = records.get("size");
  if (size !== undefined && !/^\d+$/.test(size)) throw new TarError("bad pax size");
  const path = records.get("path");
  const linkpath = records.get("linkpath");
  return {
    ...(path !== undefined ? { path } : {}),
    ...(linkpath !== undefined ? { linkpath } : {}),
    ...(size !== undefined ? { size: Number(size) } : {}),
  };
}

/** A relative POSIX path inside the archive, or undefined for the archive root itself. */
function safePath(raw: string): string | undefined {
  if (raw.includes("\0")) throw new TarError("entry path contains NUL");
  if (raw.startsWith("/") || /^[a-zA-Z]:/.test(raw) || raw.includes("\\")) throw new TarError(`unsafe entry path "${raw}"`);
  const segments = raw.split("/").filter((s) => s !== "" && s !== ".");
  if (segments.includes("..")) throw new TarError(`entry path "${raw}" climbs out of the archive`);
  return segments.length > 0 ? segments.join("/") : undefined;
}

/**
 * Write entries under `dest`, an empty directory we created. No links exist there, so paths
 * resolve inside it; `wx` refuses to overwrite, so colliding names (e.g. `A` and `a` on a
 * case-insensitive file system) fail instead of replacing each other.
 */
export async function extractEntries(entries: readonly TarEntry[], dest: string): Promise<void> {
  for (const e of entries) if (e.type === "dir") await mkdir(join(dest, e.path), { recursive: true });
  for (const e of entries) {
    if (e.type !== "file") continue;
    const target = join(dest, e.path);
    await mkdir(dirname(target), { recursive: true });
    // Keep the executable bits (the scanner reports them); drop setuid/setgid/sticky and group/other write.
    await writeFile(target, e.data, { flag: "wx", mode: (e.mode & 0o755) | 0o600 });
  }
}
