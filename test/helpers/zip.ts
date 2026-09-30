import { deflateRawSync } from "node:zlib";

/** One entry of a hand-built zip. */
export interface ZipSpec {
  readonly name: string;
  readonly data?: string | Uint8Array;
  /** 0 = stored, 8 = deflated. Default 8. Any other number is written as-is. */
  readonly method?: number;
  /** General-purpose flags; bit 0 marks the entry encrypted. */
  readonly flags?: number;
  /** Override the uncompressed size recorded in the central directory (for bomb and corruption tests). */
  readonly declaredSize?: number;
}

export interface ZipBuildOptions {
  /** Override the entry count in the end-of-central-directory record (0xffff marks zip64). */
  readonly eocdCount?: number;
  /** Override the central directory offset in the end record (0xffffffff marks zip64). */
  readonly eocdOffset?: number;
  /** Corrupt the signature of the Nth central directory header. */
  readonly corruptCentralAt?: number;
}

const enc = new TextEncoder();

/** Build a zip archive in memory with local headers, a central directory, and an end record. CRCs are zero: the reader does not check them. */
export function buildZip(entries: readonly ZipSpec[], opts: ZipBuildOptions = {}): Uint8Array {
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;
  entries.forEach((e, i) => {
    const raw = typeof e.data === "string" ? enc.encode(e.data) : (e.data ?? new Uint8Array());
    const method = e.method ?? 8;
    const body = method === 8 ? new Uint8Array(deflateRawSync(raw)) : raw;
    const name = enc.encode(e.name);
    const size = e.declaredSize ?? raw.byteLength;

    const local = new Uint8Array(30 + name.byteLength + body.byteLength);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, e.flags ?? 0, true);
    lv.setUint16(8, method, true);
    lv.setUint32(18, body.byteLength, true);
    lv.setUint32(22, size, true);
    lv.setUint16(26, name.byteLength, true);
    lv.setUint16(28, 0, true);
    local.set(name, 30);
    local.set(body, 30 + name.byteLength);

    const central = new Uint8Array(46 + name.byteLength);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, opts.corruptCentralAt === i ? 0xdeadbeef : 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, e.flags ?? 0, true);
    cv.setUint16(10, method, true);
    cv.setUint32(20, body.byteLength, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, name.byteLength, true);
    cv.setUint32(42, offset, true);
    central.set(name, 46);

    locals.push(local);
    centrals.push(central);
    offset += local.byteLength;
  });
  const cdSize = centrals.reduce((n, c) => n + c.byteLength, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, opts.eocdCount ?? entries.length, true);
  ev.setUint16(10, opts.eocdCount ?? entries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, opts.eocdOffset ?? offset, true);
  return concat([...locals, ...centrals, eocd]);
}

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}
