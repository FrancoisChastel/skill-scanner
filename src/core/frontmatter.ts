import type { Frontmatter, FrontmatterValue } from "./types";

/**
 * SKILL.md frontmatter parser for the YAML subset skills use: block mappings, block sequences,
 * quoted and plain scalars (including multi-line plain scalars), literal and folded block
 * scalars, and one-line flow sequences and mappings. It never throws: anything it cannot
 * read is recorded in `errors`, because malformed frontmatter in untrusted input is itself
 * worth reporting, not a reason to stop scanning.
 */

interface Line {
  readonly text: string;
  readonly indent: number;
  /** 1-based line number in the whole file. */
  readonly no: number;
}

interface Parsed<T> {
  readonly value: T;
  readonly next: number;
}

const MAX_DEPTH = 16;

export interface SplitResult {
  readonly frontmatter?: Frontmatter;
  readonly body: string;
  readonly bodyStartLine: number;
}

/** Split a SKILL.md into frontmatter and body. A file without a leading `---` fence has no frontmatter. */
export function splitFrontmatter(source: string): SplitResult {
  const text = source.startsWith("\uFEFF") ? source.slice(1) : source;
  const lines = text.split(/\r?\n/);
  if (lines[0]?.trimEnd() !== "---") return { body: text, bodyStartLine: 1 };
  let close = -1;
  for (let i = 1; i < lines.length; i += 1) {
    const t = lines[i]!.trimEnd();
    if (t === "---" || t === "...") {
      close = i;
      break;
    }
  }
  if (close === -1) {
    const fm: Frontmatter = {
      data: {},
      raw: lines.slice(1).join("\n"),
      startLine: 2,
      bodyStartLine: lines.length + 1,
      errors: ["unterminated frontmatter: no closing ---"],
    };
    return { frontmatter: fm, body: "", bodyStartLine: lines.length + 1 };
  }
  const rawLines = lines.slice(1, close);
  const { data, errors } = parseYamlSubset(rawLines, 2);
  const bodyStartLine = close + 2;
  return {
    frontmatter: { data, raw: rawLines.join("\n"), startLine: 2, bodyStartLine, errors },
    body: lines.slice(close + 1).join("\n"),
    bodyStartLine,
  };
}

export function parseYamlSubset(
  rawLines: readonly string[],
  firstLineNo = 1,
): { data: Record<string, FrontmatterValue>; errors: string[] } {
  const errors: string[] = [];
  const lines: Line[] = rawLines.map((text, i) => ({ text, indent: indentOf(text), no: firstLineNo + i }));
  const start = skipBlank(lines, 0);
  if (start >= lines.length) return { data: {}, errors };
  const first = lines[start]!;
  if (isSequenceItem(first.text.trim())) {
    errors.push(`line ${first.no}: frontmatter must be a mapping, found a sequence`);
    return { data: {}, errors };
  }
  const parsed = parseMapping(lines, start, first.indent, errors, 0);
  const rest = skipBlank(lines, parsed.next);
  if (rest < lines.length) errors.push(`line ${lines[rest]!.no}: could not parse '${truncate(lines[rest]!.text.trim())}'`);
  return { data: parsed.value, errors };
}

function indentOf(text: string): number {
  let n = 0;
  while (n < text.length && text[n] === " ") n += 1;
  return n;
}

const isBlankOrComment = (l: Line): boolean => {
  const t = l.text.trim();
  return t === "" || t.startsWith("#");
};

function skipBlank(lines: readonly Line[], i: number): number {
  let j = i;
  while (j < lines.length && isBlankOrComment(lines[j]!)) j += 1;
  return j;
}

const isSequenceItem = (trimmed: string): boolean => trimmed === "-" || trimmed.startsWith("- ");

const KEY_RE = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"{[\]}>|,&*!%@`-][^:#]*?|-[^\s:#][^:#]*?)\s*:(?:\s+(.*))?$/;

function unquoteKey(k: string): string {
  if (k.startsWith('"') && k.endsWith('"')) return parseDoubleQuoted(k.slice(1, -1));
  if (k.startsWith("'") && k.endsWith("'")) return k.slice(1, -1).replace(/''/g, "'");
  return k.trim();
}

function parseMapping(
  lines: readonly Line[],
  start: number,
  indent: number,
  errors: string[],
  depth: number,
): Parsed<Record<string, FrontmatterValue>> {
  const out: Record<string, FrontmatterValue> = {};
  let i = start;
  while (i < lines.length) {
    i = skipBlank(lines, i);
    if (i >= lines.length) break;
    const line = lines[i]!;
    if (line.indent < indent) break;
    if (line.indent > indent) {
      errors.push(`line ${line.no}: unexpected indentation`);
      i += 1;
      continue;
    }
    const m = KEY_RE.exec(line.text.slice(indent));
    if (!m) break;
    const key = unquoteKey(m[1]!);
    if (Object.hasOwn(out, key)) errors.push(`line ${line.no}: duplicate key '${key}'`);
    const rest = stripComment(m[2] ?? "").trim();
    const parsed = parseValueAfterKey(lines, i, indent, rest, errors, depth);
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      errors.push(`line ${line.no}: reserved key '${key}' ignored`);
    } else {
      out[key] = parsed.value;
    }
    i = parsed.next;
  }
  return { value: out, next: i };
}

function parseValueAfterKey(
  lines: readonly Line[],
  i: number,
  indent: number,
  rest: string,
  errors: string[],
  depth: number,
): Parsed<FrontmatterValue> {
  const line = lines[i]!;
  if (depth > MAX_DEPTH) {
    errors.push(`line ${line.no}: nesting deeper than ${MAX_DEPTH}`);
    return { value: null, next: i + 1 };
  }
  if (rest === "") {
    const j = skipBlank(lines, i + 1);
    const child = lines[j];
    if (child && (child.indent > indent || (child.indent === indent && isSequenceItem(child.text.trim())))) {
      const t = child.text.trim();
      if (isSequenceItem(t)) return parseSequence(lines, j, child.indent, errors, depth + 1);
      if (KEY_RE.test(t)) return parseMapping(lines, j, child.indent, errors, depth + 1);
      // A scalar that starts on the next line (`description:` then indented text), as many skills write it.
      return parseValueAfterKey(lines, j, indent, stripComment(t).trim(), errors, depth + 1);
    }
    return { value: null, next: i + 1 };
  }
  if (/^[|>][+-]?[1-9]?$/.test(rest) || /^[|>][1-9]?[+-]?$/.test(rest)) return parseBlockScalar(lines, i, indent, rest);
  if (rest.startsWith('"') || rest.startsWith("'")) return parseQuotedMultiline(lines, i, indent, rest, errors);
  if (rest.startsWith("[") || rest.startsWith("{")) return { value: parseFlow(rest, line.no, errors), next: i + 1 };
  // Plain scalar, possibly continued on more-indented lines.
  const parts = [rest];
  let j = i + 1;
  while (j < lines.length) {
    const l = lines[j]!;
    const t = l.text.trim();
    if (t === "") {
      j += 1;
      continue;
    }
    if (l.indent <= indent || t.startsWith("#")) break;
    parts.push(stripComment(t));
    j += 1;
  }
  return { value: plainScalar(parts.join(" ")), next: j };
}

function parseSequence(lines: readonly Line[], start: number, indent: number, errors: string[], depth: number): Parsed<FrontmatterValue[]> {
  const out: FrontmatterValue[] = [];
  let i = start;
  while (i < lines.length) {
    i = skipBlank(lines, i);
    if (i >= lines.length) break;
    const line = lines[i]!;
    const t = line.text.trim();
    if (line.indent !== indent || !isSequenceItem(t)) break;
    const item = t === "-" ? "" : t.slice(2).trim();
    if (item === "") {
      const parsed = parseValueAfterKey(lines, i, indent, "", errors, depth);
      out.push(parsed.value);
      i = parsed.next;
      continue;
    }
    const itemIndent = indent + (line.text.slice(indent).length - line.text.slice(indent).replace(/^-\s+/, "").length);
    const nestedSequence = isSequenceItem(item);
    if (nestedSequence || (KEY_RE.test(item) && !item.startsWith('"') && !item.startsWith("'"))) {
      // "- key: value" starts a mapping, "- - item" a nested sequence, at the item's column.
      if (depth > MAX_DEPTH) {
        errors.push(`line ${line.no}: nesting deeper than ${MAX_DEPTH}`);
        out.push(null);
        i += 1;
        continue;
      }
      const virtual: Line[] = [{ text: `${" ".repeat(itemIndent)}${item}`, indent: itemIndent, no: line.no }, ...lines.slice(i + 1)];
      const parsed = nestedSequence
        ? parseSequence(virtual, 0, itemIndent, errors, depth + 1)
        : parseMapping(virtual, 0, itemIndent, errors, depth + 1);
      out.push(parsed.value);
      i = i + parsed.next;
      continue;
    }
    const parsed = parseValueAfterKey(lines, i, indent, stripComment(item).trim(), errors, depth);
    out.push(parsed.value);
    i = parsed.next;
  }
  return { value: out, next: i };
}

function parseBlockScalar(lines: readonly Line[], i: number, indent: number, header: string): Parsed<string> {
  const folded = header.startsWith(">");
  const chomp = header.includes("-") ? "strip" : header.includes("+") ? "keep" : "clip";
  const body: string[] = [];
  let contentIndent = -1;
  let j = i + 1;
  while (j < lines.length) {
    const l = lines[j]!;
    if (l.text.trim() === "") {
      body.push("");
      j += 1;
      continue;
    }
    if (l.indent <= indent) break;
    if (contentIndent === -1) contentIndent = l.indent;
    if (l.indent < contentIndent) break;
    body.push(l.text.slice(contentIndent));
    j += 1;
  }
  let trailing = 0;
  while (body.length > 0 && body[body.length - 1] === "") {
    body.pop();
    trailing += 1;
  }
  let text = folded ? foldLines(body) : body.join("\n");
  if (chomp === "clip" && body.length > 0) text += "\n";
  if (chomp === "keep") text += "\n".repeat(trailing + 1);
  return { value: text, next: j };
}

function foldLines(lines: readonly string[]): string {
  let out = "";
  for (let k = 0; k < lines.length; k += 1) {
    const l = lines[k]!;
    if (k === 0) out = l;
    else if (l === "") out += "\n";
    else if (lines[k - 1] === "" || l.startsWith(" ")) out += l;
    else out += ` ${l}`;
  }
  return out;
}

function parseQuotedMultiline(lines: readonly Line[], i: number, indent: number, rest: string, errors: string[]): Parsed<string> {
  const quote = rest[0]!;
  let buf = rest;
  let j = i + 1;
  while (!closesQuote(buf, quote) && j < lines.length && (lines[j]!.indent > indent || lines[j]!.text.trim() === "")) {
    buf += ` ${lines[j]!.text.trim()}`;
    j += 1;
  }
  const end = closingIndex(buf, quote);
  if (end === -1) {
    errors.push(`line ${lines[i]!.no}: unterminated ${quote === '"' ? "double" : "single"}-quoted string`);
    return { value: buf.slice(1), next: j };
  }
  const inner = buf.slice(1, end);
  const trailer = stripComment(buf.slice(end + 1)).trim();
  if (trailer !== "") errors.push(`line ${lines[i]!.no}: unexpected text after quoted string`);
  return { value: quote === '"' ? parseDoubleQuoted(inner) : inner.replace(/''/g, "'"), next: j };
}

function closingIndex(s: string, quote: string): number {
  for (let k = 1; k < s.length; k += 1) {
    const c = s[k];
    if (quote === '"' && c === "\\") {
      k += 1;
      continue;
    }
    if (c === quote) {
      if (quote === "'" && s[k + 1] === "'") {
        k += 1;
        continue;
      }
      return k;
    }
  }
  return -1;
}

const closesQuote = (s: string, quote: string): boolean => closingIndex(s, quote) !== -1;

const ESCAPES: Readonly<Record<string, string>> = {
  n: "\n",
  t: "\t",
  r: "\r",
  "0": "\0",
  '"': '"',
  "\\": "\\",
  "/": "/",
  " ": " ",
  e: "\x1b",
  a: "\x07",
  b: "\b",
};

function parseDoubleQuoted(s: string): string {
  return s.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (_m, esc: string) => {
    if (esc.length > 1) {
      const cp = Number.parseInt(esc.slice(1), 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : "\uFFFD";
    }
    return ESCAPES[esc] ?? esc;
  });
}

function stripComment(s: string): string {
  // A comment starts at " #" outside quotes.
  let inSingle = false;
  let inDouble = false;
  for (let k = 0; k < s.length; k += 1) {
    const c = s[k];
    if (c === "\\" && inDouble) {
      k += 1;
      continue;
    }
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "#" && !inSingle && !inDouble && (k === 0 || s[k - 1] === " " || s[k - 1] === "\t")) return s.slice(0, k);
  }
  return s;
}

function plainScalar(s: string): FrontmatterValue {
  const t = s.trim();
  if (t === "" || t === "~" || t === "null" || t === "Null" || t === "NULL") return null;
  if (/^(true|True|TRUE)$/.test(t)) return true;
  if (/^(false|False|FALSE)$/.test(t)) return false;
  if (/^[-+]?(\d+|\d*\.\d+)([eE][-+]?\d+)?$/.test(t)) return Number(t);
  return t;
}

/** One-line flow collections: `[a, "b", c]` and `{k: v, k2: [x]}`. Nested flow is supported; multi-line flow is not. */
function parseFlow(src: string, lineNo: number, errors: string[]): FrontmatterValue {
  let pos = 0;
  const fail = (why: string): never => {
    throw new Error(why);
  };
  const ws = () => {
    while (pos < src.length && /\s/.test(src[pos]!)) pos += 1;
  };
  const scalar = (stops: string): FrontmatterValue => {
    ws();
    const c = src[pos];
    if (c === '"' || c === "'") {
      const end = closingIndex(src.slice(pos), c);
      if (end === -1) fail("unterminated string in flow collection");
      const inner = src.slice(pos + 1, pos + end);
      pos += end + 1;
      return c === '"' ? parseDoubleQuoted(inner) : inner.replace(/''/g, "'");
    }
    const start = pos;
    while (pos < src.length && !stops.includes(src[pos]!)) pos += 1;
    return plainScalar(src.slice(start, pos));
  };
  const value = (depth: number): FrontmatterValue => {
    if (depth > MAX_DEPTH) fail("flow collection nested too deeply");
    ws();
    if (src[pos] === "[") {
      pos += 1;
      const arr: FrontmatterValue[] = [];
      ws();
      if (src[pos] === "]") {
        pos += 1;
        return arr;
      }
      for (;;) {
        arr.push(value(depth + 1));
        ws();
        if (src[pos] === ",") {
          pos += 1;
          continue;
        }
        if (src[pos] === "]") {
          pos += 1;
          return arr;
        }
        return fail("expected , or ] in flow sequence");
      }
    }
    if (src[pos] === "{") {
      pos += 1;
      const obj: Record<string, FrontmatterValue> = {};
      ws();
      if (src[pos] === "}") {
        pos += 1;
        return obj;
      }
      for (;;) {
        const k = scalar(":,}");
        ws();
        if (src[pos] !== ":") fail("expected : in flow mapping");
        pos += 1;
        const key = String(k);
        const v = value(depth + 1);
        if (key !== "__proto__" && key !== "constructor" && key !== "prototype") obj[key] = v;
        ws();
        if (src[pos] === ",") {
          pos += 1;
          continue;
        }
        if (src[pos] === "}") {
          pos += 1;
          return obj;
        }
        return fail("expected , or } in flow mapping");
      }
    }
    return scalar(",]}");
  };
  try {
    const v = value(0);
    ws();
    const trailer = stripComment(src.slice(pos)).trim();
    if (trailer !== "") errors.push(`line ${lineNo}: unexpected text after flow collection`);
    return v;
  } catch (e) {
    errors.push(`line ${lineNo}: ${e instanceof Error ? e.message : String(e)}`);
    return src;
  }
}

const truncate = (s: string, n = 60): string => (s.length > n ? `${s.slice(0, n)}\u2026` : s);

/** Read a frontmatter field as a string, joining sequences with spaces (the spec's `allowed-tools` is space-delimited). */
export function fieldAsString(fm: Frontmatter | undefined, key: string): string | undefined {
  const v = fm?.data[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ");
  return JSON.stringify(v);
}

/** 1-based line number of a top-level frontmatter key, for locations. */
export function lineOfKey(fm: Frontmatter, key: string): number {
  const lines = fm.raw.split("\n");
  const idx = lines.findIndex((l) => l.startsWith(`${key}:`) || l.startsWith(`"${key}":`) || l.startsWith(`'${key}':`));
  return idx === -1 ? fm.startLine : fm.startLine + idx;
}
