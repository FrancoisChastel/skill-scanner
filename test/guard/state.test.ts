import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DEFAULT_CONFIG } from "../../src/config";
import {
  addTrust,
  cacheKey,
  findFlagged,
  loadFlagged,
  loadFlaggedRaw,
  loadTrust,
  logDecision,
  policyFingerprint,
  readCachedScan,
  readStatEntry,
  removeTrust,
  saveFlagged,
  writeCachedScan,
  writeStatEntry,
} from "../../src/guard/state";
import type { FlaggedEntry } from "../../src/guard/types";
import { scannerPaths } from "../../src/paths";
import { type TempHome, tempHome } from "./helpers";

let h: TempHome;
beforeEach(async () => {
  h = await tempHome();
});
afterEach(async () => {
  await h.cleanup();
});

const D1 = `sha256:${"1".repeat(64)}`;
const D2 = `sha256:${"2".repeat(64)}`;
const D3 = `sha256:${"3".repeat(64)}`;

function entry(name: string, digest: string, extra: Partial<FlaggedEntry> = {}): FlaggedEntry {
  return {
    name,
    path: `/s/${name}`,
    realPath: `/real/${name}`,
    digest,
    verdict: "block",
    summary: ["critical x/y: bad"],
    flaggedAt: "t",
    ...extra,
  };
}

describe("flagged registry", () => {
  test("round trip, atomic write leaves no temp files", async () => {
    await saveFlagged([entry("a", D1, { aliases: ["dir-a"] })], h.env);
    expect(await loadFlagged(h.env)).toEqual([entry("a", D1, { aliases: ["dir-a"] })]);
    const files = await readdir(scannerPaths(h.env).home);
    expect(files.filter((f) => f.endsWith(".tmp"))).toEqual([]);
    expect((await stat(scannerPaths(h.env).flagged)).mode & 0o777).toBe(0o600);
  });

  test("a corrupt or foreign file reads as empty", async () => {
    await mkdir(scannerPaths(h.env).home, { recursive: true });
    await writeFile(scannerPaths(h.env).flagged, "{ not json");
    expect(await loadFlagged(h.env)).toEqual([]);
    await writeFile(scannerPaths(h.env).flagged, JSON.stringify({ entries: [{ name: 1 }, entry("ok", D1)] }));
    expect((await loadFlagged(h.env)).map((e) => e.name)).toEqual(["ok"]);
  });

  test("trusted digests drop out of loadFlagged; addTrust prunes the stored registry", async () => {
    await saveFlagged(
      [entry("a", D1), entry("plug", D2, { kind: "plugin", riskyDigests: [D3] }), entry("c", D3, { verdict: "warn" })],
      h.env,
    );
    await addTrust({ digest: D1, name: "a", path: "/s/a" }, h.env);
    expect((await loadFlaggedRaw(h.env)).map((e) => e.name)).toEqual(["plug", "c"]);
    await addTrust({ digest: D3, name: "c", path: "/s/c" }, h.env);
    // D3 trusts both "c" and every risky bundle of the plugin.
    expect(await loadFlagged(h.env)).toEqual([]);
  });

  test("findFlagged by name, alias, plugin prefix, and path", () => {
    const list = [
      entry("Alpha", D1, { aliases: ["alpha-dir"] }),
      entry("mem", D2, { kind: "plugin", path: "/cache/m/mem/1", realPath: "/cache/m/mem/1" }),
    ];
    expect(findFlagged("alpha", list)?.name).toBe("Alpha");
    expect(findFlagged("alpha-dir", list)?.name).toBe("Alpha");
    expect(findFlagged("mem:do-thing", list)?.name).toBe("mem");
    expect(findFlagged("/s/Alpha/scripts/x.sh", list)?.name).toBe("Alpha");
    expect(findFlagged("/real/Alpha", list)?.name).toBe("Alpha");
    expect(findFlagged("/s/Alphabet", list)).toBeUndefined();
    expect(findFlagged("beta", list)).toBeUndefined();
  });
});

describe("trust store", () => {
  test("add, replace, list, and remove by digest, bare hex, name, or path", async () => {
    await addTrust({ digest: D1, name: "a", path: "/s/a", reason: "reviewed", trustedAt: "2026-01-01T00:00:00.000Z" }, h.env);
    await addTrust({ digest: D1, name: "a2", path: "/s/a" }, h.env);
    await addTrust({ digest: D2, name: "b", path: "/s/b" }, h.env);
    const store = await loadTrust(h.env);
    expect(store.version).toBe(1);
    expect(store.entries.map((e) => e.name)).toEqual(["a2", "b"]);
    expect((await removeTrust("1".repeat(64), h.env)).map((e) => e.name)).toEqual(["a2"]);
    expect((await removeTrust("b", h.env)).map((e) => e.name)).toEqual(["b"]);
    expect(await removeTrust("nothing", h.env)).toEqual([]);
    expect((await loadTrust(h.env)).entries).toEqual([]);
  });

  test("rejects a malformed digest and tolerates a corrupt file", async () => {
    await expect(addTrust({ digest: "sha256:abc", name: "x", path: "/x" }, h.env)).rejects.toThrow(/not a skill digest/);
    await mkdir(scannerPaths(h.env).home, { recursive: true });
    await writeFile(scannerPaths(h.env).trust, "[]");
    expect(await loadTrust(h.env)).toEqual({ version: 1, entries: [] });
  });
});

describe("scan cache", () => {
  test("results by digest and policy; stat entries by real path", async () => {
    const fp = policyFingerprint(DEFAULT_CONFIG);
    expect(policyFingerprint({ ...DEFAULT_CONFIG, blockAt: "critical" })).not.toBe(fp);
    const key = cacheKey(D1, fp);
    const cached = { digest: D1, verdict: "warn" as const, summary: ["x"], findings: 1, bundles: [], scannedAt: "t" };
    await writeCachedScan(key, cached, h.env);
    expect(await readCachedScan(key, h.env)).toEqual(cached);
    expect(await readCachedScan(cacheKey(D2, fp), h.env)).toBeUndefined();
    await writeStatEntry({ realPath: "/r/x", fingerprint: "f", digest: D1 }, h.env);
    expect(await readStatEntry("/r/x", h.env)).toEqual({ realPath: "/r/x", fingerprint: "f", digest: D1 });
    expect(await readStatEntry("/r/y", h.env)).toBeUndefined();
  });

  test("a corrupt cache entry is a miss", async () => {
    const key = cacheKey(D1, "fp");
    await mkdir(join(scannerPaths(h.env).cache, "scans"), { recursive: true });
    await writeFile(join(scannerPaths(h.env).cache, "scans", `${key}.json`), "garbage");
    expect(await readCachedScan(key, h.env)).toBeUndefined();
  });
});

describe("decision log", () => {
  test("appends JSON lines and rotates past 5 MB, keeping one old file", async () => {
    const log = scannerPaths(h.env).log;
    await logDecision({ harness: "codex", action: "deny" }, h.env, new Date("2026-09-30T00:00:00Z"));
    expect(JSON.parse((await readFile(log, "utf8")).trim())).toEqual({ ts: "2026-09-30T00:00:00.000Z", harness: "codex", action: "deny" });
    await writeFile(log, "x".repeat(5 * 1024 * 1024 + 10));
    await logDecision({ n: 2 }, h.env);
    expect((await stat(`${log}.1`)).size).toBeGreaterThan(5 * 1024 * 1024);
    expect((await readFile(log, "utf8")).trim().split("\n")).toHaveLength(1);
  });
});
