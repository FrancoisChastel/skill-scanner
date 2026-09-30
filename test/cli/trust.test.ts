import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { digestsByPrefix, trustCommand } from "../../src/cli/commands/trust";
import { addTrust, loadTrust } from "../../src/guard/state";
import { fakeIO, makeTempEnv, type TempEnv } from "../setup/env";

let t: TempEnv;
let skill: string;
beforeEach(async () => {
  t = await makeTempEnv();
  skill = join(t.root, "skills", "deploy-helper");
  await mkdir(skill, { recursive: true });
  await writeFile(
    join(skill, "SKILL.md"),
    "---\nname: deploy-helper\ndescription: Deploys the app. Use when the user asks to deploy.\n---\n\nRun the deploy script.\n",
  );
});
afterEach(async () => {
  await t.cleanup();
});

const trust = async (argv: string[], opts: { tty?: boolean; answer?: boolean } = {}) => {
  const io = fakeIO(t.env, t.root, opts);
  const code = await trustCommand.run(argv, io);
  return { code, out: io.out(), err: io.err(), asked: io.asked };
};
const D1 = `sha256:abcdef01${"0".repeat(56)}`;
const D2 = `sha256:abcdef02${"0".repeat(56)}`;

describe("trust <path>", () => {
  test("scans, shows the summary, and records every bundle digest with the reason", async () => {
    const r = await trust([skill, "--yes", "--reason", "reviewed the deploy script"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Scanned ");
    expect(r.out).toContain("deploy-helper");
    expect(r.out).toContain("Trusted deploy-helper (sha256:");
    const { entries } = await loadTrust(t.env);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ name: "deploy-helper", path: skill, reason: "reviewed the deploy script" });
    expect(entries[0]!.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("asks on a terminal and trusts nothing on no; refuses without a terminal or --yes", async () => {
    const no = await trust([skill], { tty: true, answer: false });
    expect(no.code).toBe(1);
    expect(no.asked[0]).toContain("Any change flags it again");
    const headless = await trust([skill]);
    expect(headless.code).toBe(2);
    expect(headless.err).toContain("--yes");
    expect((await loadTrust(t.env)).entries).toEqual([]);
  });

  test("a missing path or a second path is a usage error", async () => {
    await expect(trust([join(t.root, "nope"), "--yes"])).rejects.toThrow("no such file or directory");
    await expect(trust([skill, skill])).rejects.toThrow("one path at a time");
    await expect(trust([])).rejects.toThrow("give the path");
  });
});

describe("trust --list and --remove", () => {
  test("lists entries as a table or JSON", async () => {
    expect((await trust(["--list"])).out).toBe("No trusted skills.\n");
    await addTrust({ digest: D1, name: "alpha", path: join(t.home, "skills", "alpha"), reason: "mine" }, t.env);
    const table = await trust(["--list"]);
    expect(table.out).toContain("DIGEST");
    expect(table.out).toContain("sha256:abcdef010000  alpha");
    expect(table.out).toContain("~/skills/alpha");
    expect(table.out).toContain("mine");
    const json = JSON.parse((await trust(["--list", "--json"])).out);
    expect(json).toEqual([expect.objectContaining({ digest: D1, name: "alpha" })]);
  });

  test("removes by name, by the short digest the list shows, and refuses an ambiguous prefix", async () => {
    await addTrust({ digest: D1, name: "alpha", path: "/a" }, t.env);
    await addTrust({ digest: D2, name: "beta", path: "/b" }, t.env);
    const ambiguous = await trust(["--remove", "abcdef"]);
    expect(ambiguous.code).toBe(2);
    expect(ambiguous.err).toContain("matches 2 digests");
    expect((await trust(["--remove", "sha256:abcdef010000"])).code).toBe(0);
    expect((await trust(["--remove", "beta"])).out).toContain("Removed 1 trusted entry");
    expect((await loadTrust(t.env)).entries).toEqual([]);
    const none = await trust(["--remove", "gamma"]);
    expect(none.code).toBe(2);
    expect(none.err).toContain('no trusted skill matches "gamma"');
  });

  test("digestsByPrefix only treats hex of six or more characters as a digest", () => {
    const entries = [{ digest: D1, name: "a", path: "/a", trustedAt: "" }];
    expect(digestsByPrefix("abcdef01", entries)).toEqual([D1]);
    expect(digestsByPrefix("abc", entries)).toBeUndefined();
    expect(digestsByPrefix("alpha", entries)).toBeUndefined();
    expect(digestsByPrefix("ffffff", entries)).toBeUndefined();
  });
});
