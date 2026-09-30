import { inflateRawSync } from "node:zlib";

/**
 * Minimal zip reader for looking inside archives shipped in a skill (including .docx/.xlsx/.pptx,
 * which are zips). Stored and deflated entries only; zip64, encrypted, and other methods are
 * reported as unreadable rather than guessed at. Every size is bounded against zip bombs.
 */

export interface ZipEntry {
  readonly name: string;
  readonly data?: Uint8Array;
  readonly size: number;
  /** Why the entry has no data. */
  readonly skipped?: "encrypted" | "unsupported-method" | "too-large" | "corrupt" | "directory";
}

export interface ZipResult {
  readonly entries: readonly ZipEntry[];
  readonly notes: readonly string[];
}

export interface ZipLimits {
  readonly maxEntries: number;
  readonly maxEntryBytes: number;
  readonly maxTotalBytes: number;
}

const EOCD_SIG = 0x06054b50;
const CEN_SIG = 0x02014b50;
const LOC_SIG = 0x04034b50;

export function readZip(buf: Uint8Array, limits: ZipLimits): ZipResult {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const notes: string[] = [];
  const eocd = findEocd(view);
  if (eocd === -1) return { entries: [], notes: ["no zip end-of-central-directory record"] };
  const count = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  if (count === 0xffff || cdOffset === 0xffffffff) return { entries: [], notes: ["zip64 archives are not read"] };
  if (count > limits.maxEntries) notes.push(`${count} entries; only the first ${limits.maxEntries} were read`);

  const entries: ZipEntry[] = [];
  let p = cdOffset;
  let total = 0;
  const decoder = new TextDecoder("utf-8", { fatal: false });
  for (let i = 0; i < Math.min(count, limits.maxEntries); i += 1) {
    if (p + 46 > buf.byteLength || view.getUint32(p, true) !== CEN_SIG) {
      notes.push("central directory is truncated or corrupt");
      break;
    }
    const flags = view.getUint16(p + 8, true);
    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const size = view.getUint32(p + 24, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const localOffset = view.getUint32(p + 42, true);
    const name = decoder.decode(buf.subarray(p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;

    if (name.endsWith("/")) {
      entries.push({ name, size: 0, skipped: "directory" });
      continue;
    }
    if (flags & 0x1) {
      entries.push({ name, size, skipped: "encrypted" });
      continue;
    }
    if (method !== 0 && method !== 8) {
      entries.push({ name, size, skipped: "unsupported-method" });
      continue;
    }
    if (size > limits.maxEntryBytes || total + size > limits.maxTotalBytes) {
      entries.push({ name, size, skipped: "too-large" });
      continue;
    }
    const data = readEntry(buf, view, localOffset, method, compSize, size, limits.maxEntryBytes);
    if (!data) {
      entries.push({ name, size, skipped: "corrupt" });
      continue;
    }
    total += data.byteLength;
    entries.push({ name, size: data.byteLength, data });
  }
  return { entries, notes };
}

function findEocd(view: DataView): number {
  const min = Math.max(0, view.byteLength - 22 - 0xffff);
  for (let i = view.byteLength - 22; i >= min; i -= 1) if (view.getUint32(i, true) === EOCD_SIG) return i;
  return -1;
}

function readEntry(
  buf: Uint8Array,
  view: DataView,
  offset: number,
  method: number,
  compSize: number,
  size: number,
  cap: number,
): Uint8Array | undefined {
  if (offset + 30 > buf.byteLength || view.getUint32(offset, true) !== LOC_SIG) return undefined;
  const start = offset + 30 + view.getUint16(offset + 26, true) + view.getUint16(offset + 28, true);
  const end = start + compSize;
  if (end > buf.byteLength) return undefined;
  const raw = buf.subarray(start, end);
  if (method === 0) return raw.byteLength === size ? raw : undefined;
  try {
    return new Uint8Array(inflateRawSync(raw, { maxOutputLength: Math.max(1, Math.min(cap, size || cap)) }));
  } catch {
    return undefined;
  }
}
