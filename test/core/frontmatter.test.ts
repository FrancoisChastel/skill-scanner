import { describe, expect, test } from "bun:test";
import { fieldAsString, lineOfKey, parseYamlSubset, splitFrontmatter } from "../../src/core/frontmatter";

const fm = (yaml: string) => {
  const r = splitFrontmatter(`---\n${yaml}\n---\nbody`);
  if (!r.frontmatter) throw new Error("expected frontmatter");
  return r.frontmatter;
};

describe("splitFrontmatter", () => {
  test("returns no frontmatter when the file does not start with a fence", () => {
    // Arrange
    const source = "# Title\n\n---\nname: x\n---\n";

    // Act
    const r = splitFrontmatter(source);

    // Assert
    expect(r.frontmatter).toBeUndefined();
    expect(r.body).toBe(source);
    expect(r.bodyStartLine).toBe(1);
  });

  test("splits frontmatter and body and reports 1-based line numbers", () => {
    // Arrange
    const source = "---\nname: demo\ndescription: Does things\n---\n# Body\ntext";

    // Act
    const r = splitFrontmatter(source);

    // Assert
    expect(r.frontmatter?.data).toEqual({ name: "demo", description: "Does things" });
    expect(r.frontmatter?.raw).toBe("name: demo\ndescription: Does things");
    expect(r.frontmatter?.startLine).toBe(2);
    expect(r.frontmatter?.bodyStartLine).toBe(5);
    expect(r.bodyStartLine).toBe(5);
    expect(r.body).toBe("# Body\ntext");
    expect(r.frontmatter?.errors).toEqual([]);
  });

  test("strips a UTF-8 byte-order mark before the opening fence", () => {
    // Arrange
    const source = `${String.fromCodePoint(0xfeff)}---\nname: bom\n---\nbody`;

    // Act
    const r = splitFrontmatter(source);

    // Assert
    expect(r.frontmatter?.data).toEqual({ name: "bom" });
    expect(r.body).toBe("body");
  });

  test("accepts CRLF line endings", () => {
    // Arrange
    const source = "---\r\nname: crlf\r\n---\r\nbody";

    // Act
    const r = splitFrontmatter(source);

    // Assert
    expect(r.frontmatter?.data).toEqual({ name: "crlf" });
    expect(r.body).toBe("body");
  });

  test("accepts the YAML document end marker as the closing fence", () => {
    // Arrange
    const source = "---\na: 1\n...\nbody";

    // Act
    const r = splitFrontmatter(source);

    // Assert
    expect(r.frontmatter?.data).toEqual({ a: 1 });
    expect(r.body).toBe("body");
  });

  test("records an error and empty data for unterminated frontmatter", () => {
    // Arrange
    const source = "---\nname: a\ndescription: never closed\n";

    // Act
    const r = splitFrontmatter(source);

    // Assert
    expect(r.frontmatter?.data).toEqual({});
    expect(r.frontmatter?.errors).toEqual(["unterminated frontmatter: no closing ---"]);
    expect(r.body).toBe("");
    expect(r.frontmatter?.raw).toContain("never closed");
  });
});

describe("parseYamlSubset scalars", () => {
  test("reads plain scalars as strings, numbers, booleans, and null", () => {
    // Arrange / Act
    const f = fm("s: hello world\ni: 42\nneg: -3\nf: 1.5e3\nt: true\nT: True\nno: false\nn: null\nt2: ~\nempty:");

    // Assert
    expect(f.data).toEqual({ s: "hello world", i: 42, neg: -3, f: 1500, t: true, T: true, no: false, n: null, t2: null, empty: null });
  });

  test("keeps a colon inside a plain value", () => {
    // Arrange / Act
    const f = fm("description: Use when: the user asks\nurl: https://example.com/a:b");

    // Assert
    expect(f.data.description).toBe("Use when: the user asks");
    expect(f.data.url).toBe("https://example.com/a:b");
  });

  test("joins a multi-line plain scalar with spaces", () => {
    // Arrange / Act
    const f = fm("p: this is\n  a multi line\n\n  plain scalar\nnext: 1");

    // Assert
    expect(f.data).toEqual({ p: "this is a multi line plain scalar", next: 1 });
  });

  test("strips trailing comments but not a hash inside quotes or words", () => {
    // Arrange / Act
    const f = fm("x: 1 # comment\ny: 'a # not comment'\nz: \"b # neither\"\nw: c#d");

    // Assert
    expect(f.data).toEqual({ x: 1, y: "a # not comment", z: "b # neither", w: "c#d" });
  });

  test("decodes double-quoted escapes including hex and unicode forms", () => {
    // Arrange
    const yaml = 'q: "tab\\there \\"quoted\\" \\x41\\u0042\\U0001F600 back\\\\slash\\n"';

    // Act
    const f = fm(yaml);

    // Assert
    expect(f.data.q).toBe(`tab\there "quoted" AB${String.fromCodePoint(0x1f600)} back\\slash\n`);
  });

  test("replaces an out-of-range \\U escape with the replacement character", () => {
    // Arrange / Act
    const f = fm('q: "\\UFFFFFFFF"');

    // Assert
    expect(f.data.q).toBe(String.fromCodePoint(0xfffd));
  });

  test("unescapes doubled single quotes", () => {
    // Arrange / Act
    const f = fm("s: 'it''s ''quoted'''");

    // Assert
    expect(f.data.s).toBe("it's 'quoted'");
  });

  test("continues a quoted string over more-indented lines", () => {
    // Arrange / Act
    const f = fm('k: "multi\n  line"\nnext: x');

    // Assert
    expect(f.data).toEqual({ k: "multi line", next: "x" });
  });

  test("reports unterminated quoted strings", () => {
    // Arrange / Act
    const dq = fm('k: "unterminated');
    const sq = fm("k: 'unterminated");

    // Assert
    expect(dq.errors).toEqual(["line 2: unterminated double-quoted string"]);
    expect(sq.errors).toEqual(["line 2: unterminated single-quoted string"]);
    expect(dq.data.k).toBe("unterminated");
  });

  test("reports text after a closing quote", () => {
    // Arrange / Act
    const f = fm('k: "a" extra');

    // Assert
    expect(f.data.k).toBe("a");
    expect(f.errors).toEqual(["line 2: unexpected text after quoted string"]);
  });

  test("unquotes quoted keys", () => {
    // Arrange / Act
    const f = fm('"quoted key": v\n\'single key\': w\n"esc\\tkey": x');

    // Assert
    expect(f.data).toEqual({ "quoted key": "v", "single key": "w", "esc\tkey": "x" });
  });
});

describe("parseYamlSubset block scalars", () => {
  test("literal block keeps newlines and clips to one trailing newline", () => {
    // Arrange / Act
    const f = fm("d: |\n  line one\n  line two\n\n\nnext: 1");

    // Assert
    expect(f.data.d).toBe("line one\nline two\n");
    expect(f.data.next).toBe(1);
  });

  test("literal block keeps extra indentation relative to the first line", () => {
    // Arrange / Act
    const f = fm("k: |\n  keep\n    indented\n  back");

    // Assert
    expect(f.data.k).toBe("keep\n  indented\nback\n");
  });

  test("folded block joins lines with spaces and keeps paragraph breaks", () => {
    // Arrange / Act
    const f = fm("d: >\n  folded one\n  folded two\n\n  para");

    // Assert
    expect(f.data.d).toBe("folded one folded two\npara\n");
  });

  test("strip chomping removes every trailing newline", () => {
    // Arrange / Act
    const f = fm("a: |-\n  x\n\n\nb: >-\n  y\n  z");

    // Assert
    expect(f.data.a).toBe("x");
    expect(f.data.b).toBe("y z");
  });

  test("keep chomping preserves the trailing blank lines", () => {
    // Arrange / Act
    const f = fm("b: |+\n  y\n\n\nc: x");

    // Assert
    expect(f.data.b).toBe("y\n\n\n");
    expect(f.data.c).toBe("x");
  });

  test("accepts an explicit indentation indicator in either order", () => {
    // Arrange / Act
    const f = fm("a: |2-\n  x\nb: >-2\n  y");

    // Assert
    expect(f.data.a).toBe("x");
    expect(f.data.b).toBe("y");
  });

  test("an empty block scalar is the empty string", () => {
    // Arrange / Act
    const f = fm("a: |\nb: 1");

    // Assert
    expect(f.data.a).toBe("");
    expect(f.data.b).toBe(1);
  });
});

describe("parseYamlSubset collections", () => {
  test("reads flow sequences with quoted items containing commas", () => {
    // Arrange / Act
    const f = fm("t: [a, \"b, c\", 'd''e', 3, true]\nempty: []");

    // Assert
    expect(f.data).toEqual({ t: ["a", "b, c", "d'e", 3, true], empty: [] });
  });

  test("reads flow mappings with nested flow collections", () => {
    // Arrange / Act
    const f = fm("m: {k: v, n: [1, 2], o: {p: q}}\ne: {}");

    // Assert
    expect(f.data).toEqual({ m: { k: "v", n: [1, 2], o: { p: "q" } }, e: {} });
  });

  test("reports malformed flow collections and keeps the raw text", () => {
    // Arrange / Act
    const open = fm("k: [a, b");
    const trailer = fm("x: [a] trailing");
    const noColon = fm("m: {a b}");

    // Assert
    expect(open.data.k).toBe("[a, b");
    expect(open.errors).toEqual(["line 2: expected , or ] in flow sequence"]);
    expect(trailer.data.x).toEqual(["a"]);
    expect(trailer.errors).toEqual(["line 2: unexpected text after flow collection"]);
    expect(noColon.errors[0]).toContain("expected : in flow mapping");
  });

  test("refuses flow collections nested past the depth limit", () => {
    // Arrange
    const deep = `k: ${"[".repeat(30)}${"]".repeat(30)}`;

    // Act
    const f = fm(deep);

    // Assert
    expect(f.errors).toEqual(["line 2: flow collection nested too deeply"]);
  });

  test("reads block sequences at the parent's indentation and indented", () => {
    // Arrange / Act
    const f = fm("flat:\n- a\n- b\nindented:\n  - c\n  - 'd'");

    // Assert
    expect(f.data).toEqual({ flat: ["a", "b"], indented: ["c", "d"] });
  });

  test("reads nested block mappings", () => {
    // Arrange / Act
    const f = fm("metadata:\n  author: me\n  deep:\n    k: v\nafter: 1");

    // Assert
    expect(f.data).toEqual({ metadata: { author: "me", deep: { k: "v" } }, after: 1 });
  });

  test("reads '- key: value' items as mappings with their continuation keys", () => {
    // Arrange / Act
    const f = fm("items:\n  - name: one\n    value: 1\n  - name: two\n  - plain");

    // Assert
    expect(f.data.items).toEqual([{ name: "one", value: 1 }, { name: "two" }, "plain"]);
  });

  test("reads Claude Code hook declarations nested in sequences", () => {
    // Arrange
    const yaml = "hooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: echo hi";

    // Act
    const f = fm(yaml);

    // Assert
    expect(f.data.hooks).toEqual({ PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo hi" }] }] });
  });

  test("reads an empty sequence item as a nested block", () => {
    // Arrange / Act
    const f = fm("s:\n  -\n    k: v\n  - x");

    // Assert
    expect(f.data.s).toEqual([{ k: "v" }, "x"]);
  });

  test("reads a nested block sequence written on the item line", () => {
    // Arrange / Act
    const f = fm("seq:\n  - - a\n    - b\n  - c");

    // Assert
    expect(f.data.seq).toEqual([["a", "b"], "c"]);
  });
});

describe("parseYamlSubset errors and safety", () => {
  test("reports duplicate keys and keeps the last value", () => {
    // Arrange / Act
    const f = fm("name: a\nname: b");

    // Assert
    expect(f.data.name).toBe("b");
    expect(f.errors).toEqual(["line 3: duplicate key 'name'"]);
  });

  test("ignores __proto__, constructor, and prototype keys in block and flow mappings", () => {
    // Arrange / Act
    const f = fm("__proto__: x\nconstructor: y\nprototype: z\nok: z\nf: {__proto__: 1, a: 2}");

    // Assert
    expect(f.data).toEqual({ ok: "z", f: { a: 2 } });
    expect(Object.getPrototypeOf(f.data)).toBe(Object.prototype);
    expect(({} as Record<string, unknown>).x).toBeUndefined();
    expect(f.errors).toEqual([
      "line 2: reserved key '__proto__' ignored",
      "line 3: reserved key 'constructor' ignored",
      "line 4: reserved key 'prototype' ignored",
    ]);
  });

  test("rejects a top-level sequence", () => {
    // Arrange / Act
    const f = fm("- a\n- b");

    // Assert
    expect(f.data).toEqual({});
    expect(f.errors).toEqual(["line 2: frontmatter must be a mapping, found a sequence"]);
  });

  test("reports a line it cannot parse", () => {
    // Arrange / Act
    const f = fm("name: ok\nfoo bar baz");

    // Assert
    expect(f.data).toEqual({ name: "ok" });
    expect(f.errors).toEqual(["line 3: could not parse 'foo bar baz'"]);
  });

  test("reports unexpected indentation and nesting deeper than the limit", () => {
    // Arrange
    let yaml = "";
    for (let i = 0; i < 20; i += 1) yaml += `${"  ".repeat(i)}k${i}:\n`;
    yaml += `${"  ".repeat(20)}v: 1`;

    // Act
    const f = fm(yaml);

    // Assert
    expect(f.errors).toContain("line 19: nesting deeper than 16");
    expect(f.errors.some((e) => e.includes("unexpected indentation"))).toBe(true);
  });

  test("skips blank and comment lines and uses the given first line number", () => {
    // Arrange / Act
    const r = parseYamlSubset(["", "# comment", "a: 1", "b: ["], 10);

    // Assert
    expect(r.data).toEqual({ a: 1, b: "[" });
    expect(r.errors).toEqual(["line 13: expected , or ] in flow sequence"]);
  });

  test("returns empty data for empty input", () => {
    // Arrange / Act
    const r = parseYamlSubset(["", "  "]);

    // Assert
    expect(r).toEqual({ data: {}, errors: [] });
  });
});

describe("fieldAsString and lineOfKey", () => {
  const f = fm("name: x\nallowed-tools: [Bash, Read]\nmeta: {a: 1}\nn: 3\nb: true\nnothing: null\ndescription: d\n'quoted': q");

  test("joins sequences with spaces and serializes other values", () => {
    // Arrange / Act / Assert
    expect(fieldAsString(f, "allowed-tools")).toBe("Bash Read");
    expect(fieldAsString(f, "meta")).toBe('{"a":1}');
    expect(fieldAsString(f, "n")).toBe("3");
    expect(fieldAsString(f, "b")).toBe("true");
    expect(fieldAsString(f, "name")).toBe("x");
  });

  test("returns undefined for missing or null fields and missing frontmatter", () => {
    // Arrange / Act / Assert
    expect(fieldAsString(f, "missing")).toBeUndefined();
    expect(fieldAsString(f, "nothing")).toBeUndefined();
    expect(fieldAsString(undefined, "name")).toBeUndefined();
  });

  test("serializes non-string sequence items as JSON", () => {
    // Arrange
    const g = fm("tools: [a, {b: 1}, 2]");

    // Act / Assert
    expect(fieldAsString(g, "tools")).toBe('a {"b":1} 2');
  });

  test("finds the file line of a top-level key, falling back to the start line", () => {
    // Arrange / Act / Assert
    expect(lineOfKey(f, "name")).toBe(2);
    expect(lineOfKey(f, "description")).toBe(8);
    expect(lineOfKey(f, "quoted")).toBe(9);
    expect(lineOfKey(f, "nope")).toBe(2);
  });
});

describe("parseYamlSubset scalars on the line after their key", () => {
  test("a plain scalar indented under its key, as vercel-labs/agent-skills writes descriptions", () => {
    // Arrange
    const lines = [
      "name: vercel-composition-patterns",
      "description:",
      "  React composition patterns that scale. Use when refactoring components with",
      "  boolean prop proliferation.",
      "license: MIT",
      "metadata:",
      "  author: vercel",
    ];

    // Act
    const { data, errors } = parseYamlSubset(lines, 2);

    // Assert
    expect(errors).toEqual([]);
    expect(data.description).toBe(
      "React composition patterns that scale. Use when refactoring components with boolean prop proliferation.",
    );
    expect(data.license).toBe("MIT");
    expect(data.metadata).toEqual({ author: "vercel" });
  });

  test("a quoted scalar on the next line", () => {
    const { data, errors } = parseYamlSubset(["description:", '  "Formats dates: ISO 8601 only."'], 1);
    expect(errors).toEqual([]);
    expect(data.description).toBe("Formats dates: ISO 8601 only.");
  });

  test("an indented key on the next line is still a nested mapping", () => {
    const { data } = parseYamlSubset(["metadata:", "  author: vercel"], 1);
    expect(data.metadata).toEqual({ author: "vercel" });
  });
});
