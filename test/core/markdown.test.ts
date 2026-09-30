import { describe, expect, test } from "bun:test";
import { type Region, regionAt, segmentMarkdown } from "../../src/core/markdown";

const slices = (text: string, regions: readonly Region[]) => regions.map((r) => ({ kind: r.kind, text: text.slice(r.start, r.end) }));

describe("segmentMarkdown fenced code", () => {
  test("marks the content of a backtick fence as code with its language", () => {
    // Arrange
    const text = "intro\n```bash\necho hi\n```\nafter";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions).toHaveLength(1);
    expect(regions[0]).toMatchObject({ kind: "code", lang: "bash" });
    expect(text.slice(regions[0]!.start, regions[0]!.end)).toBe("echo hi\n");
  });

  test("lower-cases the fence language", () => {
    // Arrange / Act
    const regions = segmentMarkdown("```Python\nx\n```\n");

    // Assert
    expect(regions[0]?.lang).toBe("python");
  });

  test("supports tilde fences", () => {
    // Arrange
    const text = "~~~\ncode\n~~~\n";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(slices(text, regions)).toEqual([{ kind: "code", text: "code\n" }]);
  });

  test("a longer outer fence contains a shorter inner fence", () => {
    // Arrange
    const text = "````\n```\ninner\n```\n````\nafter";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(slices(text, regions)).toEqual([{ kind: "code", text: "```\ninner\n```\n" }]);
  });

  test("a tilde line does not close a backtick fence", () => {
    // Arrange
    const text = "```js\nx\n~~~\n```\n";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(slices(text, regions)).toEqual([{ kind: "code", text: "x\n~~~\n" }]);
  });

  test("a fence line with an info string does not close the block", () => {
    // Arrange
    const text = "```\nx\n``` trailing\ny\n```\n";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(slices(text, regions)).toEqual([{ kind: "code", text: "x\n``` trailing\ny\n" }]);
  });

  test("an unclosed fence runs to the end of the file", () => {
    // Arrange
    const text = "```\nunclosed\ncode";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(slices(text, regions)).toEqual([{ kind: "code", text: "unclosed\ncode" }]);
  });

  test("allows up to three spaces of fence indentation and CRLF endings", () => {
    // Arrange
    const text = "   ```sh\r\nls\r\n   ```\r\nafter";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions).toHaveLength(1);
    expect(regions[0]?.lang).toBe("sh");
    expect(text.slice(regions[0]!.start, regions[0]!.end)).toBe("ls\r\n");
  });

  test("hides nothing inside code: comments and backticks there stay code", () => {
    // Arrange
    const text = "```\n<!-- in code -->\n`inline in code`\n```\n";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions.map((r) => r.kind)).toEqual(["code"]);
  });
});

describe("segmentMarkdown hidden regions", () => {
  test("marks HTML comments, including multi-line ones", () => {
    // Arrange
    const text = "text <!-- hidden\nmulti --> more";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions).toEqual([{ kind: "hidden", start: 5, end: 26, via: "html-comment" }]);
  });

  test("an unclosed HTML comment hides the rest of the file", () => {
    // Arrange
    const text = "a <!-- never closed\nmore";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions).toEqual([{ kind: "hidden", start: 2, end: text.length, via: "html-comment" }]);
  });

  test("marks comment-style link definitions in all three title forms", () => {
    // Arrange
    const text = "[//]: # (secret comment)\n[comment]: <> \"quoted\"\n[x]: # 'single'\n[real]: https://x.example\n";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions.map((r) => [r.via, text.slice(r.start, r.end)])).toEqual([
      ["link-definition", "[//]: # (secret comment)"],
      ["link-definition", '[comment]: <> "quoted"'],
      ["link-definition", "[x]: # 'single'"],
    ]);
  });

  test("marks CSS-hidden elements and ignores visible ones", () => {
    // Arrange
    const text =
      '<div style="display:none">a</div> <span hidden>b</span> <p style="font-size: 0">c</p> <small style="opacity:0">d</small> <section style="visibility: hidden">e</section> <div class="x">shown</div>';

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions.every((r) => r.kind === "hidden" && r.via === "hidden-element")).toBe(true);
    expect(regions.map((r) => text.slice(r.start, r.end))).toEqual([
      '<div style="display:none">a</div>',
      "<span hidden>b</span>",
      '<p style="font-size: 0">c</p>',
      '<small style="opacity:0">d</small>',
      '<section style="visibility: hidden">e</section>',
    ]);
  });

  test("ignores HTML comments inside fenced code", () => {
    // Arrange
    const text = "```html\n<!-- example -->\n```\n<!-- real -->";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(slices(text, regions)).toEqual([
      { kind: "code", text: "<!-- example -->\n" },
      { kind: "hidden", text: "<!-- real -->" },
    ]);
  });
});

describe("segmentMarkdown inline code and frontmatter", () => {
  test("matches inline spans by backtick run length", () => {
    // Arrange
    const text = "use `code` and ``double ` tick`` and `unclosed";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(slices(text, regions)).toEqual([
      { kind: "inline-code", text: "`code`" },
      { kind: "inline-code", text: "``double ` tick``" },
    ]);
  });

  test("does not mark inline code inside a hidden region", () => {
    // Arrange
    const text = "<!-- `inline in hidden` -->";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    expect(regions.map((r) => r.kind)).toEqual(["hidden"]);
  });

  test("adds a frontmatter region and ignores constructs inside it", () => {
    // Arrange
    const text = "---\nname: x\ndescription: `tick` <!-- c -->\n---\nbody `x`";
    const fmEnd = text.indexOf("body");

    // Act
    const regions = segmentMarkdown(text, fmEnd);

    // Assert
    expect(slices(text, regions)).toEqual([
      { kind: "frontmatter", text: text.slice(0, fmEnd) },
      { kind: "inline-code", text: "`x`" },
    ]);
  });

  test("returns regions sorted by start, outer first on ties", () => {
    // Arrange
    const text = "<!-- a --> `b`\n```\nc\n```\n[//]: # (d)\n";

    // Act
    const regions = segmentMarkdown(text);

    // Assert
    const starts = regions.map((r) => r.start);
    expect(starts).toEqual([...starts].sort((a, b) => a - b));
  });
});

describe("regionAt", () => {
  test("returns prose for an offset outside every region", () => {
    // Arrange
    const regions = segmentMarkdown("plain `code` text");

    // Act
    const r = regionAt(regions, 0);

    // Assert
    expect(r).toEqual({ kind: "prose", start: 0, end: 0 });
  });

  test("returns the region containing the offset, with an exclusive end", () => {
    // Arrange
    const text = "a `b` c";
    const regions = segmentMarkdown(text);

    // Act / Assert
    expect(regionAt(regions, 2).kind).toBe("inline-code");
    expect(regionAt(regions, 4).kind).toBe("inline-code");
    expect(regionAt(regions, 5).kind).toBe("prose");
  });

  test("prefers hidden over inline code, code, and frontmatter when regions overlap", () => {
    // Arrange
    const regions: Region[] = [
      { kind: "frontmatter", start: 0, end: 100 },
      { kind: "code", start: 5, end: 50 },
      { kind: "inline-code", start: 10, end: 40 },
      { kind: "hidden", start: 20, end: 30, via: "html-comment" },
    ];

    // Act / Assert
    expect(regionAt(regions, 2).kind).toBe("frontmatter");
    expect(regionAt(regions, 7).kind).toBe("code");
    expect(regionAt(regions, 12).kind).toBe("inline-code");
    expect(regionAt(regions, 25).kind).toBe("hidden");
    expect(regionAt(regions, 45).kind).toBe("code");
    expect(regionAt(regions, 60).kind).toBe("frontmatter");
  });

  test("returns prose for an empty region list", () => {
    // Arrange / Act / Assert
    expect(regionAt([], 10).kind).toBe("prose");
  });
});
