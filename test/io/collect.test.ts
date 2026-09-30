import { afterEach, describe, expect, test } from "bun:test";
import { realpath } from "node:fs/promises";
import type { SkillBundle, SkillFile } from "../../src/core/types";
import { type CollectLimits, collect, DEFAULT_LIMITS } from "../../src/io/collect";
import { makeSkillTree, type SkillTree, skillMd, type TreeEntry } from "../helpers/tree";
import { buildZip } from "../helpers/zip";

const trees: SkillTree[] = [];
async function tree(files: Readonly<Record<string, TreeEntry>>): Promise<SkillTree> {
  const t = await makeSkillTree(files);
  trees.push(t);
  return t;
}
afterEach(async () => {
  await Promise.all(trees.splice(0).map((t) => t.cleanup()));
});

const limits = (over: Partial<CollectLimits>): CollectLimits => ({ ...DEFAULT_LIMITS, ...over });
const byRoot = (bundles: readonly SkillBundle[], root: string) => {
  const b = bundles.find((x) => x.root === root);
  if (!b) throw new Error(`no bundle at ${root}: ${bundles.map((x) => x.root).join(", ")}`);
  return b;
};
const file = (b: SkillBundle, path: string): SkillFile => {
  const f = b.files.find((x) => x.path === path);
  if (!f) throw new Error(`no file ${path} in ${b.root}: ${b.files.map((x) => x.path).join(", ")}`);
  return f;
};
const utf16le = (s: string) => new Uint8Array([0xff, 0xfe, ...[...s].flatMap((c) => [c.charCodeAt(0), 0])]);
const utf16be = (s: string) => new Uint8Array([0xfe, 0xff, ...[...s].flatMap((c) => [0, c.charCodeAt(0)])]);

describe("collect: bundles", () => {
  test("makes one skill bundle for a directory with SKILL.md and parses its frontmatter", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("Body", { name: "alpha" }), "scripts/run.py": "print('hi')" });

    // Act
    const { root, bundles } = await collect(t.root);

    // Assert
    expect(root).toBe(await realpath(t.root));
    expect(bundles).toHaveLength(1);
    expect(bundles[0]).toMatchObject({ kind: "skill", name: "alpha", root: ".", notes: [] });
    expect(bundles[0]?.frontmatter?.data.name).toBe("alpha");
    expect(file(bundles[0]!, "SKILL.md").kind).toBe("skill-md");
    expect(file(bundles[0]!, "scripts/run.py")).toMatchObject({ kind: "script", language: "python", text: "print('hi')" });
  });

  test("splits nested skills into their own bundles with bundle-relative paths", async () => {
    // Arrange
    const t = await tree({
      "README.md": "# repo",
      "skills/a/SKILL.md": skillMd("a", { name: "alpha" }),
      "skills/a/ref.md": "ref",
      "skills/a/nested/SKILL.md": skillMd("n", { name: "nested" }),
      "skills/a/nested/x.md": "x",
      "skills/b/SKILL.md": "no frontmatter",
    });

    // Act
    const { bundles } = await collect(t.root);

    // Assert
    expect(bundles.map((b) => [b.root, b.kind, b.name, b.dirName])).toEqual([
      ["skills/a", "skill", "alpha", "a"],
      ["skills/a/nested", "skill", "nested", "nested"],
      ["skills/b", "skill", "b", "b"],
      [".", "package", "(root)", "."],
    ]);
    expect(byRoot(bundles, "skills/a").files.map((f) => f.path)).toEqual(["SKILL.md", "ref.md"]);
    expect(byRoot(bundles, "skills/a/nested").files.map((f) => f.path)).toEqual(["SKILL.md", "x.md"]);
    expect(byRoot(bundles, "skills/b").frontmatter).toBeUndefined();
  });

  test("labels a root bundle with plugin manifests or hooks as a plugin", async () => {
    // Arrange
    const claude = await tree({ ".claude-plugin/plugin.json": "{}", "commands/x.md": "x" });
    const codex = await tree({ ".codex-plugin/plugin.json": "{}" });
    const hooks = await tree({ "hooks/hooks.json": "{}" });
    const pkg = await tree({ "package.json": "{}" });

    // Act
    const kinds = await Promise.all([claude, codex, hooks, pkg].map(async (x) => (await collect(x.root)).bundles[0]?.kind));

    // Assert
    expect(kinds).toEqual(["plugin", "plugin", "plugin", "package"]);
  });

  test("falls back to the directory name when the skill name is missing or blank, and truncates long names", async () => {
    // Arrange
    const t = await tree({
      "s1/SKILL.md": "---\nname: '  '\ndescription: d\n---\n",
      "s2/SKILL.md": `---\nname: ${"n".repeat(80)}\ndescription: d\n---\n`,
    });

    // Act
    const { bundles } = await collect(t.root);

    // Assert
    expect(byRoot(bundles, "s1").name).toBe("s1");
    expect(byRoot(bundles, "s2").name).toBe("n".repeat(64));
  });

  test("scans a SKILL.md path as its whole directory", async () => {
    // Arrange
    const t = await tree({ "SKILL.md": skillMd("b"), "other.md": "o" });

    // Act
    const { bundles } = await collect(t.path("SKILL.md"));

    // Assert
    expect(bundles[0]?.files.map((f) => f.path)).toEqual(["SKILL.md", "other.md"]);
  });

  test("scans a single non-skill file as a one-file package", async () => {
    // Arrange
    const t = await tree({ "a/notes.txt": "hello", "a/other.txt": "not scanned" });

    // Act
    const { root, bundles } = await collect(t.path("a/notes.txt"));

    // Assert
    expect(root).toBe(t.path("a"));
    expect(bundles).toHaveLength(1);
    expect(bundles[0]).toMatchObject({ kind: "package", root: "." });
    expect(bundles[0]?.files.map((f) => f.path)).toEqual(["notes.txt"]);
  });

  test("uses the first SKILL.md casing variant only when SKILL.md itself is absent", async () => {
    // Arrange
    const t = await tree({ "skill.md": skillMd("lower", { name: "lower" }) });

    // Act
    const { bundles } = await collect(t.root);

    // Assert
    expect(bundles[0]).toMatchObject({ kind: "skill", name: "lower" });
    expect(file(bundles[0]!, "skill.md").kind).toBe("skill-md");
  });
});

describe("collect: symlinks", () => {
  test("records links without following them and flags escapes and absolute targets", async () => {
    // Arrange
    const t = await tree({
      "SKILL.md": skillMd("x"),
      "scripts/run.sh": "echo hi",
      "internal.md": { symlink: "scripts/run.sh" },
      "escape.md": { symlink: "../../outside.txt" },
      absolute: { symlink: "/etc/hosts" },
      dirlink: { symlink: "scripts" },
    });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect(file(b!, "internal.md")).toEqual({
      path: "internal.md",
      kind: "symlink",
      size: 0,
      linkTarget: "scripts/run.sh",
      linkEscapes: false,
    });
    expect(file(b!, "escape.md")).toMatchObject({ kind: "symlink", linkTarget: "../../outside.txt", linkEscapes: true });
    expect(file(b!, "absolute")).toMatchObject({ kind: "symlink", linkTarget: "/etc/hosts", linkEscapes: true });
    expect(file(b!, "dirlink")).toMatchObject({ kind: "symlink", linkEscapes: false });
    expect(file(b!, "internal.md").text).toBeUndefined();
    expect(b!.files.some((f) => f.path.startsWith("dirlink/"))).toBe(false);
  });

  test("flags a link that leaves its own skill even when it stays inside the scanned repository", async () => {
    // Arrange
    const t = await tree({
      "README.md": "# repo",
      "skills/a/SKILL.md": skillMd("a", { name: "a" }),
      "skills/a/readme-link.md": { symlink: "../../README.md" },
    });

    // Act
    const { bundles } = await collect(t.root);

    // Assert
    expect(file(byRoot(bundles, "skills/a"), "readme-link.md").linkEscapes).toBe(true);
  });
});

describe("collect: skipped directories and notes", () => {
  test("skips vendored and VCS directories, noting all but .git", async () => {
    // Arrange
    const t = await tree({
      "SKILL.md": skillMd("x"),
      "node_modules/pkg/index.js": "x",
      "sub/node_modules/other/index.js": "x",
      ".venv/lib/x.py": "x",
      ".git/HEAD": "ref",
      "__MACOSX/._SKILL.md": "x",
    });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect(b!.files.map((f) => f.path)).toEqual(["SKILL.md"]);
    expect([...b!.notes].sort()).toEqual([
      "1 .venv/ directory was not scanned",
      "1 __MACOSX/ directory was not scanned",
      "2 node_modules/ directories were not scanned",
    ]);
  });

  test("attaches collection notes to the first bundle when there is no root bundle", async () => {
    // Arrange
    const t = await tree({
      "skills/a/SKILL.md": skillMd("a", { name: "a" }),
      "skills/b/SKILL.md": skillMd("b", { name: "b" }),
      "node_modules/x/i.js": "x",
    });

    // Act
    const { bundles } = await collect(t.root);

    // Assert
    expect(bundles.map((b) => b.root)).toEqual(["skills/a", "skills/b"]);
    expect(bundles[0]?.notes).toEqual(["1 node_modules/ directory was not scanned"]);
    expect(bundles[1]?.notes).toEqual([]);
  });

  test("attaches collection notes to the root bundle, not to nested skills", async () => {
    // Arrange
    const t = await tree({ "README.md": "r", "skills/a/SKILL.md": skillMd("a", { name: "a" }), "node_modules/x/i.js": "x" });

    // Act
    const { bundles } = await collect(t.root);

    // Assert
    expect(byRoot(bundles, "skills/a").notes).toEqual([]);
    expect(byRoot(bundles, ".").notes).toEqual(["1 node_modules/ directory was not scanned"]);
  });
});

describe("collect: limits", () => {
  const files = {
    "SKILL.md": skillMd("x".repeat(100)),
    "a/1.txt": "1",
    "a/2.txt": "2",
    "a/3.txt": "3",
    "b/1.txt": "1",
    "d1/d2/d3/deep.txt": "deep",
  };

  test("stops at maxFiles and notes it", async () => {
    // Arrange
    const t = await tree(files);

    // Act
    const [b] = (await collect(t.root, limits({ maxFiles: 2 }))).bundles;

    // Assert
    expect(b!.files.map((f) => f.path)).toEqual(["SKILL.md", "a/1.txt"]);
    expect(b!.notes).toContain("more than 2 files; the rest were not scanned");
  });

  test("notes the maxFiles limit once", async () => {
    // Arrange
    const t = await tree(files);

    // Act
    const [b] = (await collect(t.root, limits({ maxFiles: 2 }))).bundles;

    // Assert
    expect(b!.notes.filter((n) => n.startsWith("more than 2 files"))).toHaveLength(1);
  });

  test("stops descending past maxDepth and notes where", async () => {
    // Arrange
    const t = await tree(files);

    // Act
    const [b] = (await collect(t.root, limits({ maxDepth: 1 }))).bundles;

    // Assert
    expect(b!.files.some((f) => f.path.startsWith("d1/"))).toBe(false);
    expect(b!.notes).toEqual(["directory nesting deeper than 1 under d1/d2; deeper files were not scanned"]);
  });

  test("stops reading at maxTotalBytes, truncating the file that crosses it", async () => {
    // Arrange
    const t = await tree(files);

    // Act
    const [b] = (await collect(t.root, limits({ maxTotalBytes: 50 }))).bundles;

    // Assert
    expect(b!.files.map((f) => f.path)).toEqual(["SKILL.md"]);
    expect(file(b!, "SKILL.md")).toMatchObject({ truncated: true });
    expect(file(b!, "SKILL.md").text).toHaveLength(50);
    expect(b!.notes).toEqual(["scanned 50 bytes in total; a/1.txt and larger files were not read"]);
  });

  test("truncates files larger than maxFileBytes and keeps their full size", async () => {
    // Arrange
    const t = await tree({ "big.txt": "y".repeat(100), "small.txt": "s" });

    // Act
    const [b] = (await collect(t.root, limits({ maxFileBytes: 10 }))).bundles;

    // Assert
    expect(file(b!, "big.txt")).toMatchObject({ size: 100, truncated: true, text: "y".repeat(10) });
    expect(file(b!, "small.txt").truncated).toBeUndefined();
  });
});

describe("collect: file contents", () => {
  test("decodes UTF-16 text with a byte-order mark in either byte order", async () => {
    // Arrange
    const t = await tree({ "le.txt": utf16le("hi there"), "be.md": utf16be("# title") });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect(file(b!, "le.txt")).toMatchObject({ kind: "text", text: "hi there", size: 18 });
    expect(file(b!, "be.md")).toMatchObject({ kind: "markdown", text: "# title" });
  });

  test("records binary format and a hex header, without text", async () => {
    // Arrange
    const t = await tree({
      "logo.png": new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 1, 2, 3, 0]),
      "img.png": new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 0]),
    });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect(file(b!, "logo.png")).toEqual({ path: "logo.png", kind: "binary", size: 8, binaryFormat: "elf", header: "7f454c4601020300" });
    expect(file(b!, "img.png")).toMatchObject({ kind: "binary", binaryFormat: "image", header: "89504e470000" });
  });

  test("records the executable bit for scripts and binaries", async () => {
    // Arrange
    const t = await tree({
      "run.sh": { content: "#!/bin/sh\necho hi", mode: 0o755 },
      "plain.sh": { content: "echo", mode: 0o644 },
      tool: { content: new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0]), mode: 0o755 },
    });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect(file(b!, "run.sh").executable).toBe(true);
    expect(file(b!, "plain.sh").executable).toBeUndefined();
    expect(file(b!, "tool")).toMatchObject({ kind: "binary", binaryFormat: "elf", executable: true });
  });

  test("expands zip and office archives into '!/' entries and scans them as files", async () => {
    // Arrange
    const t = await tree({
      "SKILL.md": skillMd("x"),
      "assets/template.docx": buildZip([
        { name: "word/document.xml", data: "<w>hello</w>" },
        { name: "word/", method: 0 },
        { name: "evil.sh", data: "#!/bin/sh\necho x", method: 0 },
      ]),
      "bundle.zip": buildZip([{ name: "inner/SKILL.md", data: "---\nname: inner\n---\n" }]),
    });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect(file(b!, "assets/template.docx")).toMatchObject({ kind: "binary", binaryFormat: "office" });
    expect(file(b!, "assets/template.docx!/word/document.xml")).toMatchObject({ kind: "text", text: "<w>hello</w>" });
    expect(file(b!, "assets/template.docx!/evil.sh")).toMatchObject({ kind: "script", language: "shell" });
    expect(file(b!, "bundle.zip!/inner/SKILL.md")).toMatchObject({ kind: "markdown" });
    expect(b!.files.some((f) => f.path.endsWith("word/"))).toBe(false);
    expect((await collect(t.root)).bundles).toHaveLength(1);
  });

  test("notes archive entries it cannot read and archive-level problems", async () => {
    // Arrange
    const t = await tree({
      "a.zip": buildZip([
        { name: "locked.txt", data: "x", flags: 1 },
        { name: "ok.txt", data: "ok" },
      ]),
      "broken.zip": new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3]),
    });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect([...b!.notes].sort()).toEqual(["a.zip!/locked.txt: not read (encrypted)", "broken.zip: no zip end-of-central-directory record"]);
    expect(file(b!, "a.zip!/ok.txt").text).toBe("ok");
  });

  test("does not look inside an archive nested in an archive", async () => {
    // Arrange
    const inner = buildZip([{ name: "deep.txt", data: "deep" }]);
    const t = await tree({ "outer.zip": buildZip([{ name: "inner.zip", data: inner, method: 0 }]) });

    // Act
    const [b] = (await collect(t.root)).bundles;

    // Assert
    expect(file(b!, "outer.zip!/inner.zip")).toMatchObject({ kind: "binary", binaryFormat: "zip" });
    expect(b!.files.some((f) => f.path.includes("deep.txt"))).toBe(false);
  });

  test("notes an archive too large to look inside", async () => {
    // Arrange
    const t = await tree({ "big.zip": buildZip([{ name: "a.txt", data: "a".repeat(100), method: 0 }]) });

    // Act
    const [b] = (await collect(t.root, limits({ maxFileBytes: 32, maxArchiveBytes: 64 }))).bundles;

    // Assert
    expect(file(b!, "big.zip")).toMatchObject({ kind: "binary", truncated: true });
    expect(b!.notes).toEqual(["big.zip is too large to look inside"]);
  });
});

describe("collect: nested archives", () => {
  test("opens a workbook embedded in an Office document, but not a zip inside a zip", async () => {
    // Arrange
    const workbook = buildZip([{ name: "xl/sharedStrings.xml", data: "<sst>quarterly numbers</sst>" }]);
    const deck = buildZip([
      { name: "ppt/slides/slide1.xml", data: "<p>Slide</p>" },
      { name: "ppt/embeddings/Microsoft_Excel_Worksheet.xlsx", data: workbook, method: 0 },
    ]);
    const inner = buildZip([{ name: "deep.txt", data: "hidden deeper" }]);
    const outer = buildZip([{ name: "inner.zip", data: inner, method: 0 }]);
    const t = await tree({ "SKILL.md": skillMd("Slides."), "assets/deck.pptx": deck, "assets/outer.zip": outer });

    // Act
    const [b] = (await collect(t.root)).bundles;
    const paths = b!.files.map((f) => f.path);

    // Assert
    expect(paths).toContain("assets/deck.pptx!/ppt/embeddings/Microsoft_Excel_Worksheet.xlsx!/xl/sharedStrings.xml");
    expect(paths).toContain("assets/outer.zip!/inner.zip");
    expect(paths.some((p) => p.endsWith("inner.zip!/deep.txt"))).toBe(false);
  });
});

describe("collect: digest", () => {
  test("is stable across runs and independent of file creation order and location", async () => {
    // Arrange
    const a = await tree({ "SKILL.md": skillMd("x"), "z.txt": "z", "a/b.txt": "b" });
    const b = await tree({ "a/b.txt": "b", "z.txt": "z", "SKILL.md": skillMd("x") });

    // Act
    const first = (await collect(a.root)).bundles[0]?.digest;
    const again = (await collect(a.root)).bundles[0]?.digest;
    const other = (await collect(b.root)).bundles[0]?.digest;

    // Assert
    expect(first).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(again).toBe(first);
    expect(other).toBe(first);
  });

  test("changes when content, a path, or a link target changes", async () => {
    // Arrange
    const base = await tree({ "SKILL.md": skillMd("x"), "a.txt": "a", l: { symlink: "a.txt" } });
    const content = await tree({ "SKILL.md": skillMd("x"), "a.txt": "A", l: { symlink: "a.txt" } });
    const renamed = await tree({ "SKILL.md": skillMd("x"), "b.txt": "a", l: { symlink: "a.txt" } });
    const relinked = await tree({ "SKILL.md": skillMd("x"), "a.txt": "a", l: { symlink: "SKILL.md" } });

    // Act
    const digests = await Promise.all([base, content, renamed, relinked].map(async (t) => (await collect(t.root)).bundles[0]?.digest));

    // Assert
    expect(new Set(digests).size).toBe(4);
  });

  test("is the same for a nested skill as for the skill scanned on its own", async () => {
    // Arrange
    const t = await tree({ "README.md": "r", "skills/a/SKILL.md": skillMd("x", { name: "a" }), "skills/a/ref.md": "ref" });

    // Act
    const nested = byRoot((await collect(t.root)).bundles, "skills/a").digest;
    const alone = (await collect(t.path("skills/a"))).bundles[0]?.digest;

    // Assert
    expect(nested).toBe(alone!);
  });
});
