import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { codexPluginSource, configuredMarketplace } from "../../src/guard/codex-plugin";
import { type TempHome, tempHome } from "./helpers";

let h: TempHome;
beforeEach(async () => {
  h = await tempHome();
});
afterEach(async () => {
  await h.cleanup();
});

describe("configuredMarketplace", () => {
  test("reads the two keys of the named table and nothing else", async () => {
    const file = h.path("config.toml");
    await writeFile(
      file,
      [
        'model = "gpt-5"',
        "[marketplaces.other]",
        'source = "/elsewhere"',
        '[ marketplaces."demo" ]',
        'source_type = "local"   # a comment',
        "source = 'C:\\\\literal\\\\path'",
        'other = "x"',
        "[features]",
        'source = "/not/this"',
      ].join("\n"),
    );
    expect(await configuredMarketplace(file, "demo")).toEqual({ sourceType: "local", source: "C:\\\\literal\\\\path" });
    expect(await configuredMarketplace(file, "missing")).toBeUndefined();
    expect(await configuredMarketplace(h.path("absent.toml"), "demo")).toBeUndefined();
  });

  test("basic strings are unescaped", async () => {
    const file = h.path("esc.toml");
    await writeFile(file, '[marketplaces.m]\nsource = "/a \\"b\\"\\\\c\\u00e9"\n');
    expect((await configuredMarketplace(file, "m"))?.source).toBe('/a "b"\\c\u00e9');
  });
});

describe("codexPluginSource", () => {
  test("git marketplaces are read from their snapshot; manifests elsewhere are matched by name", async () => {
    const snap = join(h.env.CODEX_HOME!, ".tmp", "marketplaces", "snap");
    await mkdir(join(snap, ".claude-plugin"), { recursive: true });
    await writeFile(
      join(snap, ".claude-plugin", "marketplace.json"),
      JSON.stringify({ name: "snap", plugins: [{ name: "p", source: "./p" }] }),
    );
    expect(await codexPluginSource("p@snap", undefined, h.env)).toEqual({ kind: "dir", path: join(snap, "p") });

    await mkdir(h.path(".agents", "plugins"), { recursive: true });
    await writeFile(
      h.path(".agents", "plugins", "marketplace.json"),
      JSON.stringify({
        name: "home",
        plugins: [{ name: "q", source: { source: "git-subdir", url: "git@github.com:o/r.git", path: "/plugins/q/", sha: "abc" } }],
      }),
    );
    expect(await codexPluginSource("q", "home", h.env)).toEqual({ kind: "fetch", source: "o/r/plugins/q#abc" });
    expect(await codexPluginSource("q@nothome", undefined, h.env)).toBeUndefined();
  });

  test("other git hosts are fetched whole at the ref; bad names resolve to nothing", async () => {
    const snap = join(h.env.CODEX_HOME!, ".tmp", "marketplaces", "m");
    await mkdir(join(snap, ".agents", "plugins"), { recursive: true });
    await writeFile(
      join(snap, ".agents", "plugins", "marketplace.json"),
      JSON.stringify({
        name: "m",
        plugins: [{ name: "g", source: { source: "url", url: "https://git.example/o/r.git", ref: "v1", path: "x" } }],
      }),
    );
    expect(await codexPluginSource("g@m", undefined, h.env)).toEqual({ kind: "fetch", source: "https://git.example/o/r.git#v1" });
    expect(await codexPluginSource("g@../m", undefined, h.env)).toBeUndefined();
  });

  test("a repository on disk is cloned (never a path that walks out of it); with a ref it is left to the audit", async () => {
    const snap = join(h.env.CODEX_HOME!, ".tmp", "marketplaces", "disk");
    await mkdir(join(snap, ".agents", "plugins"), { recursive: true });
    await writeFile(
      join(snap, ".agents", "plugins", "marketplace.json"),
      JSON.stringify({
        name: "disk",
        plugins: [
          { name: "walk", source: { source: "url", url: "./x", path: "../../../../tmp/decoy" } },
          { name: "pinned", source: { source: "url", url: "/srv/repo", ref: "v2" } },
        ],
      }),
    );
    expect(await codexPluginSource("walk@disk", undefined, h.env)).toEqual({ kind: "fetch", source: `file://${join(snap, "x")}` });
    expect(await codexPluginSource("pinned@disk", undefined, h.env)).toBeUndefined();
    expect(await codexPluginSource("g", undefined, h.env)).toBeUndefined();
  });
});
