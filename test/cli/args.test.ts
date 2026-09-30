import { describe, expect, test } from "bun:test";
import { type FlagSpecs, formatFlags, list, parseArgs, UsageError } from "../../src/cli/args";

const SPECS: FlagSpecs = {
  verbose: { type: "boolean", short: "v", description: "more" },
  quiet: { type: "boolean", short: "q", description: "less" },
  color: { type: "boolean", description: "colors" },
  format: { type: "string", short: "f", value: "<format>", description: "format" },
  output: { type: "string", short: "o", description: "output" },
  with: { type: "string", multiple: true, description: "analyzers" },
};

describe("parseArgs", () => {
  test("reads booleans, strings, and positionals in any order", () => {
    // Arrange
    const argv = ["a", "--verbose", "--format", "json", "b"];

    // Act
    const parsed = parseArgs(argv, SPECS);

    // Assert
    expect(parsed.flags).toEqual({ verbose: true, format: "json" });
    expect(parsed.positionals).toEqual(["a", "b"]);
    expect(parsed.rest).toEqual([]);
  });

  test("accepts --flag=value", () => {
    expect(parseArgs(["--format=sarif"], SPECS).flags.format).toBe("sarif");
    expect(parseArgs(["--format="], SPECS).flags.format).toBe("");
  });

  test("keeps = inside a value", () => {
    expect(parseArgs(["--output=a=b.json"], SPECS).flags.output).toBe("a=b.json");
  });

  test("negates a boolean with --no-", () => {
    expect(parseArgs(["--color", "--no-color"], SPECS).flags.color).toBe(false);
  });

  test("rejects --no- in front of a string flag", () => {
    expect(() => parseArgs(["--no-format"], SPECS)).toThrow(new UsageError("unknown option --no-format"));
  });

  test("rejects a value on a boolean flag", () => {
    expect(() => parseArgs(["--verbose=yes"], SPECS)).toThrow(UsageError);
  });

  test("groups short boolean flags", () => {
    expect(parseArgs(["-vq"], SPECS).flags).toEqual({ verbose: true, quiet: true });
  });

  test("lets the last short flag in a group take the next argument as its value", () => {
    expect(parseArgs(["-qf", "json"], SPECS).flags).toEqual({ quiet: true, format: "json" });
  });

  test("takes the rest of a short group as the value", () => {
    expect(parseArgs(["-fjson"], SPECS).flags.format).toBe("json");
  });

  test("fails when a value is missing", () => {
    expect(() => parseArgs(["--format"], SPECS)).toThrow(new UsageError("--format needs a value"));
    expect(() => parseArgs(["-f"], SPECS)).toThrow(new UsageError("-f needs a value"));
  });

  test("fails on unknown long and short flags", () => {
    expect(() => parseArgs(["--bogus"], SPECS)).toThrow(new UsageError("unknown option --bogus"));
    expect(() => parseArgs(["-vx"], SPECS)).toThrow(new UsageError("unknown option -x"));
  });

  test("passes unknown flags through as positionals when asked", () => {
    const parsed = parseArgs(["--bogus", "-x", "--verbose", "pkg"], SPECS, { passUnknown: true });

    expect(parsed.positionals).toEqual(["--bogus", "-x", "pkg"]);
    expect(parsed.flags.verbose).toBe(true);
  });

  test("stops at -- and keeps everything after it untouched", () => {
    const parsed = parseArgs(["a", "--", "--verbose", "-q"], SPECS);

    expect(parsed.positionals).toEqual(["a"]);
    expect(parsed.rest).toEqual(["--verbose", "-q"]);
    expect(parsed.flags).toEqual({});
  });

  test("treats a lone dash and negative numbers as positionals", () => {
    expect(parseArgs(["-", "-5"], SPECS).positionals).toEqual(["-", "-5"]);
  });

  test("collects repeated flags when multiple is set", () => {
    const parsed = parseArgs(["--with", "gitleaks,semgrep", "--with=auto"], SPECS);

    expect(parsed.flags.with).toEqual(["gitleaks,semgrep", "auto"]);
    expect(list(parsed.flags.with)).toEqual(["gitleaks", "semgrep", "auto"]);
  });

  test("stops at the first positional when asked, for wrapped commands", () => {
    const parsed = parseArgs(["--verbose", "add", "--bogus"], SPECS, { stopAtPositional: true });

    expect(parsed.positionals).toEqual(["add"]);
    expect(parsed.rest).toEqual(["--bogus"]);
  });
});

describe("formatFlags", () => {
  test("aligns flags with their descriptions", () => {
    const out = formatFlags({ format: SPECS.format!, verbose: SPECS.verbose! });

    expect(out).toBe("  -f, --format <format>  format\n  -v, --verbose          more");
  });
});
