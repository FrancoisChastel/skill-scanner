import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseNpm, piNpmUpdates } from "../../src/guard/pi-update";
import { type TempHome, tempHome } from "./helpers";

let h: TempHome;
beforeEach(async () => {
  h = await tempHome();
});
afterEach(async () => {
  await h.cleanup();
});

describe("parseNpm", () => {
  test("names, scoped names, and ranges", () => {
    expect(parseNpm("npm:foo")).toEqual({ name: "foo" });
    expect(parseNpm("npm:@s/foo@^1.2")).toEqual({ name: "@s/foo", version: "^1.2" });
    expect(parseNpm("npm:@s/foo")).toEqual({ name: "@s/foo" });
    expect(parseNpm("git:github.com/o/r")).toBeUndefined();
  });
});

describe("piNpmUpdates", () => {
  test("global and project packages; exact pins and git sources are skipped; duplicates once", async () => {
    await mkdir(h.env.PI_CODING_AGENT_DIR!, { recursive: true });
    await writeFile(
      join(h.env.PI_CODING_AGENT_DIR!, "settings.json"),
      JSON.stringify({ packages: ["npm:a", "npm:b@1.0.0", "git:github.com/o/r"] }),
    );
    const proj = h.path("proj");
    await mkdir(join(proj, ".pi"), { recursive: true });
    await writeFile(join(proj, ".pi", "settings.json"), JSON.stringify({ packages: [{ source: "npm:@s/c@~2" }, "npm:a"] }));
    expect(await piNpmUpdates(undefined, proj, h.env)).toEqual(["npm:a", "npm:@s/c@~2"]);
    expect(await piNpmUpdates("npm:@s/c", proj, h.env)).toEqual(["npm:@s/c@~2"]);
    expect(await piNpmUpdates("npm:b", proj, h.env)).toEqual([]);
    // Not configured: what the command names is still scanned.
    expect(await piNpmUpdates("npm:new-one", proj, h.env)).toEqual(["npm:new-one"]);
    expect(await piNpmUpdates("git:github.com/o/r", proj, h.env)).toEqual([]);
  });

  test("missing or broken settings mean nothing to scan", async () => {
    await mkdir(h.env.PI_CODING_AGENT_DIR!, { recursive: true });
    await writeFile(join(h.env.PI_CODING_AGENT_DIR!, "settings.json"), "{ nope");
    expect(await piNpmUpdates(undefined, h.path("proj"), h.env)).toEqual([]);
  });
});
