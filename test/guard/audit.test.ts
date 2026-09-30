import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { auditInstalled, auditInstalledDetailed } from "../../src/guard/audit";
import { skillRoots } from "../../src/guard/locations";
import { reconcileAfterChange } from "../../src/guard/reconcile";
import { addTrust, findFlagged, loadFlagged, loadFlaggedRaw } from "../../src/guard/state";
import type { GuardContext, InstalledSkill, SkillRoot } from "../../src/guard/types";
import { scanPath } from "../../src/scan";
import {
  BLOCK_MARK,
  guardCtx,
  link,
  markerFinding,
  markerScanner,
  type TempHome,
  tempHome,
  WARN_MARK,
  withMarkers,
  writeSkill,
} from "./helpers";

let h: TempHome;
let ctx: GuardContext;
let roots: SkillRoot[];

beforeEach(async () => {
  h = await tempHome();
  ctx = guardCtx(h.env, h.path("proj"));
  // Only roots inside the temp home, so the machine's managed directories never matter.
  roots = skillRoots("all", ctx.cwd, h.env).filter((r) => r.path.startsWith(h.home));
  await writeSkill(h.path(".agents", "skills", "shared-a"), "shared-a");
  await link("../../.agents/skills/shared-a", h.path(".claude", "skills", "shared-a"));
  await link(h.path(".agents", "skills", "shared-a"), h.path(".pi", "agent", "skills", "shared-a"));
  await writeSkill(h.path(".claude", "skills", "bad"), "bad", `Do this. ${BLOCK_MARK}`);
  await writeSkill(h.path(".claude", "skills", "warny"), "warny", `Careful. ${WARN_MARK}`);
  await mkdir(h.path(".claude", "skills", "not-a-skill"), { recursive: true });
  await writeFile(h.path(".claude", "skills", "README.md"), "notes");
  const plugin = h.path(".claude", "plugins", "cache", "mkt", "plug", "1.0");
  await writeSkill(join(plugin, "skills", "s1"), "s1", `Plugin skill. ${BLOCK_MARK}`);
  await writeFile(join(plugin, "README.md"), "plugin");
  await mkdir(join(plugin, ".in_use"), { recursive: true });
  await writeFile(join(plugin, ".in_use", "123"), "pid");
  const orphan = h.path(".claude", "plugins", "cache", "mkt", "plug", "0.9");
  await writeSkill(join(orphan, "skills", "s1"), "s1", BLOCK_MARK);
  await writeFile(join(orphan, ".orphaned_at"), "1");
  await writeSkill(h.path(".claude", "plugins", "cache", "temp_git_1", "x"), "x", BLOCK_MARK);
});
afterEach(async () => {
  await h.cleanup();
});

const byName = (skills: readonly InstalledSkill[]): Record<string, InstalledSkill> => Object.fromEntries(skills.map((s) => [s.name, s]));

describe("auditInstalled", () => {
  test("finds skills and live plugin versions, deduplicated by real path", async () => {
    const scanner = markerScanner();
    const r = await auditInstalledDetailed(ctx, { roots, scan: scanner.scan });
    const s = byName(r.skills);
    expect(Object.keys(s).sort()).toEqual(["bad", "plug", "shared-a", "warny"]);
    expect(s["shared-a"]).toMatchObject({
      verdict: "pass",
      path: h.path(".claude", "skills", "shared-a"),
      realPath: h.path(".agents", "skills", "shared-a"),
    });
    expect(s.bad).toMatchObject({ verdict: "block", harness: "claude-code", scope: "user", kind: "skill", trusted: false });
    expect(s.bad?.summary).toEqual(["critical test/marker: Blocking test marker (SKILL.md:1)"]);
    expect(s.warny?.verdict).toBe("warn");
    expect(s.plug).toMatchObject({ verdict: "block", kind: "plugin", scope: "plugin", aliases: ["plug@mkt", "plug:s1"] });
    expect(s.plug?.riskyDigests?.length).toBe(1);
    expect(scanner.calls).toHaveLength(4);
    expect(r.stats).toMatchObject({ targets: 4, scanned: 4, cached: 0 });
  });

  test("the public two-argument form works with default options", async () => {
    const skills = await auditInstalled(ctx, roots);
    expect(skills.map((s) => s.name).sort()).toEqual(["bad", "plug", "shared-a", "warny"]);
  });

  test("unchanged skills are neither read nor rescanned; a change rescans only that skill", async () => {
    const scanner = markerScanner();
    await auditInstalledDetailed(ctx, { roots, scan: scanner.scan });
    expect(scanner.calls).toHaveLength(4);
    const again = await auditInstalledDetailed(ctx, { roots, scan: scanner.scan });
    expect(scanner.calls).toHaveLength(4);
    expect(again.stats.cached).toBe(4);
    expect(byName(again.skills).bad?.verdict).toBe("block");
    // Claude Code's per-session bookkeeping in a plugin does not count as a change.
    await writeFile(h.path(".claude", "plugins", "cache", "mkt", "plug", "1.0", ".in_use", "456"), "pid");
    await writeFile(h.path(".claude", "skills", "bad", "SKILL.md"), "---\nname: bad\ndescription: Now fine and harmless.\n---\n\nok\n");
    const third = await auditInstalledDetailed(ctx, { roots, scan: scanner.scan });
    expect(scanner.calls.slice(4)).toEqual([h.path(".claude", "skills", "bad")]);
    expect(byName(third.skills).bad?.verdict).toBe("pass");
    const forced = await auditInstalledDetailed(ctx, { roots, scan: scanner.scan, useCache: false });
    expect(forced.stats.scanned).toBe(4);
  });

  test("refreshes the flagged registry, applies trust, and forgets removed skills", async () => {
    const r = await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    expect((await loadFlagged(h.env)).map((e) => `${e.name}:${e.verdict}`).sort()).toEqual(["bad:block", "plug:block", "warny:warn"]);
    const bad = byName(r.skills).bad!;
    await addTrust({ digest: bad.digest, name: "bad", path: bad.path }, h.env);
    const trustedRun = byName((await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan })).skills);
    expect(trustedRun.bad).toMatchObject({ verdict: "block", trusted: true });
    expect((await loadFlagged(h.env)).map((e) => e.name).sort()).toEqual(["plug", "warny"]);
    await rm(h.path(".claude", "skills", "warny"), { recursive: true });
    await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    expect((await loadFlagged(h.env)).map((e) => e.name)).toEqual(["plug"]);
  });

  test("trusting every risky bundle of a plugin trusts the plugin", async () => {
    const r = await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    for (const d of byName(r.skills).plug?.riskyDigests ?? []) await addTrust({ digest: d, name: "s1", path: "p" }, h.env);
    expect(findFlagged("plug:s1", await loadFlagged(h.env))).toBeUndefined();
    expect(byName((await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan })).skills).plug?.trusted).toBe(true);
  });

  test("findings on Claude Code's per-session files in a plugin do not count", async () => {
    const scan = async (dir: string, opts: Parameters<typeof scanPath>[1]) => {
      const report = await scanPath(dir, opts);
      if (!dir.includes("plugins")) return withMarkers(report);
      const bundles = report.bundles.map((b) => ({
        ...b,
        verdict: "block" as const,
        findings: [{ ...markerFinding(b.bundle.name, "block"), location: { file: ".in_use/123" } }],
      }));
      return { ...report, bundles, verdict: "block" as const };
    };
    const r = await auditInstalledDetailed(ctx, { roots, scan });
    expect(byName(r.skills).plug).toMatchObject({ verdict: "pass", summary: [] });
  });

  test("stops at the deadline, keeps what finished, and leaves earlier flags for pending skills", async () => {
    await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    await writeFile(h.path(".claude", "skills", "bad", "extra.md"), "changed");
    await writeFile(h.path(".claude", "skills", "warny", "extra.md"), "changed");
    const slow = async (dir: string, opts: Parameters<typeof scanPath>[1]) => {
      await new Promise((r) => setTimeout(r, 300));
      return withMarkers(await scanPath(dir, opts));
    };
    const t0 = Date.now();
    const r = await auditInstalledDetailed(ctx, { roots, scan: slow, deadlineMs: 100 });
    expect(Date.now() - t0).toBeLessThan(280);
    expect(r.timedOut).toBe(true);
    expect(r.pending.map((p) => p.name).sort()).toEqual(["bad", "warny"]);
    expect((await loadFlagged(h.env)).map((e) => e.name).sort()).toEqual(["bad", "plug", "warny"]);
  });

  test("an aborted signal stops waiting at once", async () => {
    const controller = new AbortController();
    controller.abort();
    const r = await auditInstalledDetailed({ ...ctx, signal: controller.signal }, { roots, scan: markerScanner().scan });
    expect(r.skills).toEqual([]);
    expect(r.timedOut).toBe(true);
  });
});

describe("reconcileAfterChange", () => {
  test("reports only newly flagged skills and quarantines new blocks, which stay blocked by name", async () => {
    await writeSkill(h.path(".claude", "skills", "bad"), "bad", "fine for now");
    const first = await reconcileAfterChange(
      { ...ctx, config: { ...ctx.config, hooks: { ...ctx.config.hooks, quarantine: false } } },
      { roots, scan: markerScanner().scan },
    );
    expect(first.newlyFlagged.map((s) => s.name).sort()).toEqual(["plug", "warny"]);
    expect(first.quarantined).toEqual([]);
    await writeFile(h.path(".claude", "skills", "bad", "SKILL.md"), `---\nname: bad\ndescription: x\n---\n${BLOCK_MARK}\n`);
    const second = await reconcileAfterChange(ctx, { roots, scan: markerScanner().scan });
    expect(second.newlyFlagged.map((s) => s.name)).toEqual(["bad"]);
    expect(second.quarantined).toEqual([h.path(".claude", "skills", "bad")]);
    const stored = (await loadFlaggedRaw(h.env)).find((e) => e.name === "bad");
    expect(stored?.quarantined).toMatch(/-bad$/);
    // The skill is gone from disk, but a harness may have cached it: it stays blocked by name.
    await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    expect(findFlagged("bad", await loadFlagged(h.env))?.quarantined).toBeDefined();
    // A clean skill taking its place lifts it.
    await writeSkill(h.path(".claude", "skills", "bad"), "bad", "clean now");
    await auditInstalledDetailed(ctx, { roots, scan: markerScanner().scan });
    expect(findFlagged("bad", await loadFlagged(h.env))).toBeUndefined();
  });
});
