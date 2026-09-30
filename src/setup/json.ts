import { parseJsonLoose } from "../core/embedded";
import type { JsonObject } from "./hooks-table";

export type { JsonObject } from "./hooks-table";

export const isObject = (v: unknown): v is JsonObject => typeof v === "object" && v !== null && !Array.isArray(v);

export type ParsedJson =
  | {
      readonly ok: true;
      readonly value: JsonObject;
      /** The file needed comment or trailing-comma stripping, which a rewrite drops. */
      readonly loose: boolean;
      readonly indent: string;
    }
  | { readonly ok: false; readonly error: string };

/** Parse a harness config file tolerantly (JSON with comments). A missing or blank file is an empty object. */
export function parseJsonFile(text: string | undefined, path: string): ParsedJson {
  if (text === undefined || text.trim() === "") return { ok: true, value: {}, loose: false, indent: "  " };
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let value: unknown;
  let loose = false;
  try {
    value = JSON.parse(body);
  } catch {
    value = parseJsonLoose(body);
    loose = true;
  }
  if (value === undefined)
    return { ok: false, error: `${path} is not valid JSON, so setup will not touch it. Fix or move the file, then re-run setup.` };
  if (!isObject(value))
    return {
      ok: false,
      error: `${path} does not contain a JSON object, so setup will not touch it. Fix or move the file, then re-run setup.`,
    };
  return { ok: true, value, loose, indent: detectIndent(body) };
}

/** The indentation the file already uses, so a rewrite changes as few lines as possible. */
export function detectIndent(text: string): string {
  const m = /^([ \t]+)["}\]]/m.exec(text);
  if (!m) return "  ";
  if (m[1]!.startsWith("\t")) return "\t";
  return " ".repeat(Math.min(Math.max(m[1]!.length, 1), 8));
}

export const stringifyJson = (value: unknown, indent = "  "): string => `${JSON.stringify(value, null, indent)}\n`;

/** Key-order-independent serialization, for "is this already what we want" comparisons. */
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isObject(value))
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(",")}}`;
  return JSON.stringify(value) ?? "null";
}
