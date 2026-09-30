import { printableRatio } from "./unicode";

/**
 * Encoded payloads: base64, hex escapes, and char-code arrays. Each one that decodes to readable
 * text is handed back so the rules can scan what the author tried to hide.
 */

export type Encoding = "base64" | "hex" | "charcode";

export interface EncodedBlob {
  readonly encoding: Encoding;
  readonly start: number;
  readonly end: number;
  readonly decoded: string;
}

const MIN_BASE64 = 80;
const MAX_DECODED = 64 * 1024;
const MAX_BLOBS = 50;

const HEX_ESCAPE_RE = /(?:\\x[0-9a-fA-F]{2}){16,}/g;
const CHARCODE_RE = /(?:fromCharCode|chr)\s*\(\s*((?:\d{2,3}\s*,\s*){8,}\d{2,3})\s*\)|\[\s*((?:\d{2,3}\s*,\s*){15,}\d{2,3})\s*\]/g;
const CHARCODE_HINT = /fromCharCode|chr\s*\(|\[\s*\d{2,3}\s*,\s*\d{2,3}\s*,/;

/** Character classes as lookup tables, so runs are found in one linear pass (regexes backtrack on long runs). */
const BASE64_BODY = new Uint8Array(128);
const HEX = new Uint8Array(128);
for (const c of "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") BASE64_BODY[c.charCodeAt(0)] = 1;
for (const c of "0123456789abcdefABCDEF") HEX[c.charCodeAt(0)] = 1;
const inClass = (table: Uint8Array, code: number): boolean => code < 128 && table[code] === 1;

/** Maximal runs of characters from `table`: [start, end) pairs. */
function runsOf(text: string, table: Uint8Array, minLength: number): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  let start = -1;
  for (let i = 0; i <= text.length; i += 1) {
    const inRun = i < text.length && inClass(table, text.charCodeAt(i));
    if (inRun && start === -1) start = i;
    else if (!inRun && start !== -1) {
      if (i - start >= minLength) out.push([start, i]);
      start = -1;
    }
  }
  return out;
}

/**
 * Base64 runs: at least 80 characters in whole 4-character groups, with `=` or `==` padding when
 * the length calls for it, not glued to URL-safe base64 on either side or to padding after it.
 */
function base64Runs(text: string): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  for (const [start, bodyEnd] of runsOf(text, BASE64_BODY, MIN_BASE64 - 2)) {
    // Glued to `_` or `-` it is part of URL-safe base64 or an identifier; after `=` it is an assigned value (`PAYLOAD=...`).
    const before = text[start - 1];
    if (before === "_" || before === "-") continue;
    let end = bodyEnd;
    const body = bodyEnd - start;
    if (text[end] === "=" && text[end + 1] === "=" && body % 4 === 2) end += 2;
    else if (text[end] === "=" && body % 4 === 3) end += 1;
    else if (body % 4 !== 0) continue;
    const after = text.charCodeAt(end);
    if (inClass(BASE64_BODY, after) || text[end] === "=") continue;
    if (end - start >= MIN_BASE64) out.push([start, end]);
  }
  return out;
}

export function findEncodedBlobs(text: string): EncodedBlob[] {
  const out: EncodedBlob[] = [];
  const push = (b: EncodedBlob | undefined) => {
    if (b && out.length < MAX_BLOBS) out.push(b);
  };
  for (const [start, end] of base64Runs(text)) {
    const s = text.slice(start, end);
    if (looksLikeHashOrId(s)) continue;
    push(textBlob("base64", start, end - start, decodeBase64(s)));
  }
  if (text.includes("\\x")) {
    for (const m of text.matchAll(HEX_ESCAPE_RE)) {
      const bytes = m[0]
        .split("\\x")
        .filter(Boolean)
        .map((h) => Number.parseInt(h, 16));
      push(textBlob("hex", m.index, m[0].length, bytesToText(bytes)));
    }
  }
  for (const [start, end] of runsOf(text, HEX, 80)) {
    if ((end - start) % 2 !== 0) continue;
    const bytes = text
      .slice(start, end)
      .match(/../g)!
      .map((h) => Number.parseInt(h, 16));
    push(textBlob("hex", start, end - start, bytesToText(bytes)));
  }
  if (CHARCODE_HINT.test(text)) {
    for (const m of text.matchAll(CHARCODE_RE)) {
      const list = (m[1] ?? m[2] ?? "").split(",").map((n) => Number.parseInt(n.trim(), 10));
      if (list.some((n) => n > 0x7e || n < 0x09)) continue;
      push(textBlob("charcode", m.index, m[0].length, String.fromCharCode(...list)));
    }
  }
  return out;
}

function textBlob(encoding: Encoding, start: number, length: number, decoded: string | undefined): EncodedBlob | undefined {
  if (decoded === undefined || decoded.length < 8) return undefined;
  if (printableRatio(decoded) < 0.85) return undefined;
  return { encoding, start, end: start + length, decoded: decoded.slice(0, MAX_DECODED) };
}

function decodeBase64(s: string): string | undefined {
  try {
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    return bytesToText(bytes);
  } catch {
    return undefined;
  }
}

function bytesToText(bytes: ArrayLike<number>): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(Array.from(bytes)));
  } catch {
    return undefined;
  }
}

/** Long runs of one character class (SHA digests, UUID-free ids) are not payloads. */
function looksLikeHashOrId(s: string): boolean {
  return /^[a-f0-9]+$/.test(s) || /^[A-Z0-9]+$/.test(s) || /^(.)\1+$/.test(s);
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
