import { describe, expect, test } from "bun:test";
import { SourceError } from "../../src/sources/errors";
import { isRemoteSource, parseSource } from "../../src/sources/index";
import { cloneUrlVariants, hostAndPath } from "../../src/sources/urls";

const CWD = "/work/project";
const ENV = { HOME: "/home/me" };

type Expect = Record<string, unknown>;

const CASES: readonly (readonly [string, Expect])[] = [
  // local paths
  ["./skills/foo", { kind: "local", path: "/work/project/skills/foo", display: "./skills/foo" }],
  ["../other", { kind: "local", path: "/work/other" }],
  [".", { kind: "local", path: "/work/project" }],
  ["/abs/dir", { kind: "local", path: "/abs/dir" }],
  ["~/skills/x", { kind: "local", path: "/home/me/skills/x" }],
  // GitHub shorthand
  ["owner/repo", { kind: "git", cloneUrl: "https://github.com/owner/repo.git", display: "owner/repo" }],
  ["owner/repo/skills/foo", { kind: "git", cloneUrl: "https://github.com/owner/repo.git", subpath: "skills/foo" }],
  ["owner/repo/skills/foo/", { subpath: "skills/foo" }],
  [
    "owner/repo@my-skill",
    { kind: "git", cloneUrl: "https://github.com/owner/repo.git", skills: ["my-skill"], display: "owner/repo@my-skill" },
  ],
  ["owner/repo#v1.2", { cloneUrl: "https://github.com/owner/repo.git", ref: "v1.2", display: "owner/repo#v1.2" }],
  ["owner/repo#main@one", { ref: "main", skills: ["one"] }],
  ["owner/repo#@one", { skills: ["one"], ref: undefined }],
  ["owner/repo@a#main@b", { ref: "main", skills: ["b"] }],
  ["vercel-labs/vercel-skills", { cloneUrl: "https://github.com/vercel-labs/agent-skills.git" }],
  // prefixes
  ["github:owner/repo", { kind: "git", cloneUrl: "https://github.com/owner/repo.git" }],
  ["github:owner/repo#dev", { ref: "dev" }],
  ["github:owner/repo#@lost", { skills: undefined }],
  ["gitlab:group/sub/repo", { kind: "git", cloneUrl: "https://gitlab.com/group/sub/repo.git", display: "gitlab.com/group/sub/repo" }],
  // GitHub URLs
  ["https://github.com/owner/repo", { kind: "git", cloneUrl: "https://github.com/owner/repo.git", ref: undefined }],
  ["https://github.com/owner/repo.git", { cloneUrl: "https://github.com/owner/repo.git" }],
  ["https://github.com/owner/repo/tree/main", { ref: "main", subpath: undefined }],
  ["https://github.com/owner/repo/tree/main/skills/foo", { ref: "main", subpath: "skills/foo", display: "owner/repo/skills/foo#main" }],
  ["https://github.com/owner/repo#v2", { ref: "v2" }],
  ["https://github.com/owner/repo#v2@dropped", { ref: "v2", skills: undefined }],
  ["https://github.com/owner/repo/blob/main/README.md", { cloneUrl: "https://github.com/owner/repo.git", ref: undefined }],
  ["ssh://git@github.com/owner/repo.git", { cloneUrl: "https://github.com/owner/repo.git" }],
  // GitLab
  ["https://gitlab.com/group/sub/repo", { cloneUrl: "https://gitlab.com/group/sub/repo.git" }],
  ["https://gitlab.com/group/repo/-/tree/dev/skills/x", { cloneUrl: "https://gitlab.com/group/repo.git", ref: "dev", subpath: "skills/x" }],
  ["https://git.example.com/a/b/-/tree/v1", { cloneUrl: "https://git.example.com/a/b.git", ref: "v1" }],
  // Azure Repos
  [
    "https://dev.azure.com/org/proj/_git/repo?path=/skills/x&version=GBdev",
    { kind: "git", cloneUrl: "https://dev.azure.com/org/proj/_git/repo", ref: "dev", subpath: "skills/x" },
  ],
  // git URLs
  ["git@github.com:owner/repo.git", { kind: "git", cloneUrl: "git@github.com:owner/repo.git", display: "owner/repo" }],
  ["git@host.example:team/repo.git#v3", { cloneUrl: "git@host.example:team/repo.git", ref: "v3", display: "host.example/team/repo#v3" }],
  ["ssh://git@host.example:2222/team/repo.git", { kind: "git", cloneUrl: "ssh://git@host.example:2222/team/repo.git" }],
  ["https://git.example.com/team/repo.git", { kind: "git", cloneUrl: "https://git.example.com/team/repo.git" }],
  ["file:///srv/repos/skills.git", { kind: "git", cloneUrl: "file:///srv/repos/skills.git", display: "file:///srv/repos/skills.git" }],
  // Pi forms
  ["npm:@scope/pkg@1.2.3", { kind: "npm", packageSpec: "@scope/pkg@1.2.3", display: "npm:@scope/pkg@1.2.3" }],
  ["npm:pkg", { kind: "npm", packageSpec: "pkg" }],
  ["git:github.com/user/repo@v1", { kind: "git", cloneUrl: "https://github.com/user/repo", ref: "v1", display: "user/repo#v1" }],
  ["git:git@github.com:user/repo.git", { kind: "git", cloneUrl: "git@github.com:user/repo.git" }],
  ["git:https://gitlab.com/a/b@main", { cloneUrl: "https://gitlab.com/a/b", ref: "main" }],
  ["git:user/repo", { cloneUrl: "https://github.com/user/repo" }],
  // direct URLs
  ["https://example.com/skills", { kind: "url", url: "https://example.com/skills" }],
  ["https://raw.githubusercontent.com/o/r/main/SKILL.md", { kind: "url" }],
  ["https://github.com/o/r/archive/refs/heads/main.zip", { kind: "url" }],
  ["https://example.com/x#frag", { kind: "url", url: "https://example.com/x#frag" }],
];

describe("parseSource", () => {
  for (const [raw, expected] of CASES) {
    test(raw, () => {
      const spec = parseSource(raw, CWD, ENV) as unknown as Record<string, unknown>;
      expect(spec.raw).toBe(raw);
      for (const [key, value] of Object.entries(expected)) expect([key, spec[key]]).toEqual([key, value]);
    });
  }

  test("GH_HOST points shorthand at GitHub Enterprise", () => {
    expect(parseSource("o/r", CWD, { GH_HOST: "ghe.corp.example" }).cloneUrl).toBe("https://ghe.corp.example/o/r.git");
    expect(parseSource("o/r", CWD, { GH_HOST: "evil.example/x?" }).cloneUrl).toBe("https://github.com/o/r.git");
    const tree = parseSource("https://ghe.corp.example/o/r/tree/dev/skills", CWD, { GH_HOST: "ghe.corp.example" });
    expect([tree.cloneUrl, tree.ref, tree.subpath]).toEqual(["https://ghe.corp.example/o/r.git", "dev", "skills"]);
  });

  const REJECTED = [
    "",
    "   ",
    "--upload-pack=touch /tmp/x",
    "owner/repo/../../etc",
    "https://github.com/o/r/tree/main/../../x",
    "npm:git+https://example.com/x.git",
    "npm:github:user/repo",
    "npm:file:../x",
    "npm:foo@npm:bar",
    "git:github.com/a",
    "git:github.com/a/../b",
    "ext::sh -c touch% /tmp/pwned",
    "just-a-word",
    "owner/repo\nx",
  ];
  for (const raw of REJECTED) {
    test(`rejects ${JSON.stringify(raw)}`, () => {
      expect(() => parseSource(raw, CWD, ENV)).toThrow(SourceError);
    });
  }

  test("errors never echo URL credentials", () => {
    try {
      parseSource("git:https://user:s3cret@host.example/a", CWD, ENV);
      throw new Error("expected a SourceError");
    } catch (e) {
      expect((e as Error).message).not.toContain("s3cret");
    }
  });

  test("display redacts credentials", () => {
    expect(parseSource("https://tok3n@git.example.com/a/b.git", CWD, ENV).display).not.toContain("tok3n");
  });
});

describe("isRemoteSource", () => {
  test.each([
    ["owner/repo", true],
    ["npm:x", true],
    ["git:github.com/a/b", true],
    ["https://github.com/a/b", true],
    ["./local", false],
    ["/abs", false],
  ])("%s -> %p", (raw, remote) => {
    expect(isRemoteSource(raw)).toBe(remote);
  });
});

describe("cloneUrlVariants", () => {
  test("GitHub https URL expands to every spelling the skills CLI and Pi use", () => {
    expect(cloneUrlVariants("https://github.com/o/r.git")).toEqual([
      "https://github.com/o/r.git",
      "https://github.com/o/r",
      "git@github.com:o/r.git",
      "git@github.com:o/r",
      "ssh://git@github.com/o/r.git",
      "ssh://git@github.com/o/r",
    ]);
  });

  test("GitLab subgroups and scp-like URLs", () => {
    const v = cloneUrlVariants("git@gitlab.com:g/sub/r.git");
    expect(v).toContain("https://gitlab.com/g/sub/r.git");
    expect(v).toContain("ssh://git@gitlab.com/g/sub/r");
  });

  test("URLs with ports or file:// stay as given", () => {
    expect(cloneUrlVariants("ssh://git@h.example:2222/a/b.git")).toEqual(["ssh://git@h.example:2222/a/b.git"]);
    expect(cloneUrlVariants("file:///srv/a.git")).toEqual(["file:///srv/a.git"]);
    expect(hostAndPath("https://github.com/only-owner")).toBeUndefined();
  });
});
