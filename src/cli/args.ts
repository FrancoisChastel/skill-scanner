/**
 * A small, strict argument parser: declared flags only, `--flag=value` and `--flag value`,
 * short aliases, repeatable flags, and `--` to stop parsing. Unknown flags are errors, so a
 * typo never silently changes what a security tool does.
 */

export interface FlagSpec {
  readonly type: "boolean" | "string";
  readonly short?: string;
  /** Collect every occurrence into an array. */
  readonly multiple?: boolean;
  readonly description: string;
  /** Placeholder shown in help, e.g. `<format>`. */
  readonly value?: string;
}

export type FlagSpecs = Readonly<Record<string, FlagSpec>>;

export interface ParsedArgs {
  readonly flags: Readonly<Record<string, string | boolean | readonly string[] | undefined>>;
  readonly positionals: readonly string[];
  /** Everything after `--`, untouched. */
  readonly rest: readonly string[];
}

export class UsageError extends Error {
  override readonly name = "UsageError";
}

export interface ParseOptions {
  /** Stop at the first positional and treat everything after it as `rest` (for wrapped commands). */
  readonly stopAtPositional?: boolean;
  /** Pass unknown flags through as positionals instead of failing (for `add`, which forwards to `skills`). */
  readonly passUnknown?: boolean;
}

export function parseArgs(argv: readonly string[], specs: FlagSpecs, opts: ParseOptions = {}): ParsedArgs {
  const flags: Record<string, string | boolean | string[] | undefined> = {};
  const positionals: string[] = [];
  const byShort = new Map(Object.entries(specs).flatMap(([name, s]) => (s.short ? [[s.short, name] as const] : [])));
  const set = (name: string, spec: FlagSpec, value: string | boolean) => {
    if (spec.multiple) flags[name] = [...((flags[name] as string[] | undefined) ?? []), String(value)];
    else flags[name] = value;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (a === "--") return { flags, positionals, rest: argv.slice(i + 1) };
    if (a.startsWith("--") && a.length > 2) {
      const eq = a.indexOf("=");
      const raw = eq === -1 ? a.slice(2) : a.slice(2, eq);
      const negated = raw.startsWith("no-") && specs[raw.slice(3)]?.type === "boolean";
      const name = negated ? raw.slice(3) : raw;
      const spec = specs[name];
      if (!spec) {
        if (opts.passUnknown) {
          positionals.push(a);
          continue;
        }
        throw new UsageError(`unknown option --${raw}`);
      }
      if (spec.type === "boolean") {
        if (eq !== -1) throw new UsageError(`--${name} does not take a value`);
        set(name, spec, !negated);
      } else {
        const value = eq !== -1 ? a.slice(eq + 1) : argv[++i];
        if (value === undefined) throw new UsageError(`--${name} needs a value`);
        set(name, spec, value);
      }
      continue;
    }
    if (a.startsWith("-") && a.length > 1 && !/^-\d/.test(a)) {
      const letters = a.slice(1);
      for (let k = 0; k < letters.length; k += 1) {
        const name = byShort.get(letters[k]!);
        if (!name) {
          if (opts.passUnknown) {
            positionals.push(a);
            break;
          }
          throw new UsageError(`unknown option -${letters[k]}`);
        }
        const spec = specs[name]!;
        if (spec.type === "boolean") set(name, spec, true);
        else {
          const value = k < letters.length - 1 ? letters.slice(k + 1) : argv[++i];
          if (value === undefined) throw new UsageError(`-${letters[k]} needs a value`);
          set(name, spec, value);
          break;
        }
      }
      continue;
    }
    positionals.push(a);
    if (opts.stopAtPositional) return { flags, positionals, rest: argv.slice(i + 1) };
  }
  return { flags, positionals, rest: [] };
}

export const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
export const bool = (v: unknown): boolean => v === true;
export const list = (v: unknown): string[] =>
  Array.isArray(v)
    ? v
        .flatMap((x) => String(x).split(","))
        .map((s) => s.trim())
        .filter(Boolean)
    : typeof v === "string"
      ? [v]
      : [];

export function formatFlags(specs: FlagSpecs): string {
  const rows = Object.entries(specs).map(
    ([name, s]) =>
      [`${s.short ? `-${s.short}, ` : "    "}--${name}${s.type === "string" ? ` ${s.value ?? "<value>"}` : ""}`, s.description] as const,
  );
  const width = Math.max(0, ...rows.map(([l]) => l.length));
  return rows.map(([l, d]) => `  ${l.padEnd(width)}  ${d}`).join("\n");
}
