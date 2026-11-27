#!/usr/bin/env bun
/**
 * Fetch the benchmark's corpora at pinned commits and write the manifest scripts/benchmark.ts reads.
 *
 *   bun scripts/benchmark-corpora.ts <root> <manifest.json> [--as /corpora]
 *
 * Every source is public. Benign skills come from vendor and community repositories; malicious ones
 * from MaliciousSkillBench's package archives and the attack samples Trail of Bits, Snyk, Cisco and a
 * scanner-bypass study published. Untrusted content is downloaded and unpacked, never run: trees come
 * out of `git archive` (no checkout, no hooks), and an archive member named by an absolute path or
 * through a parent directory is refused.
 *
 * The layout under <root> is what src/benchmark/split.ts hashes, so keep it: benign repositories at
 * calibration/benign/<owner>__<repo>, MaliciousSkillBench at calibration/msb/<source>/, the other
 * malicious samples at malicious/<name>/. Every directory holding a SKILL.md is one target, scanned on
 * its own the way a user installs it. `--as` rewrites <root> in the manifest, for a Docker mount.
 */
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

interface RepoSource {
  readonly corpus: string;
  readonly label: "benign" | "malicious";
  readonly repo: string;
  readonly commit: string;
  /** Only these subtrees, when the repository holds more than skills. */
  readonly only?: readonly string[];
  /** Subtrees left out. */
  readonly except?: readonly string[];
}

const BENIGN: ReadonlyArray<readonly [string, string]> = [
  ["alirezarezvani/claude-skills", "19392f7a08264ed00486a251f5b2098321771f94"],
  ["anthropics/claude-plugins-official", "d182ca456ca09d31d139f7d3818d1d333b103cce"],
  ["anthropics/skills", "8a1541c4a3ffa5a20a5a91de0dcf3f0bab1d1ef4"],
  ["better-auth/skills", "20c9e88a5c007461a703f1c213572b073196113e"],
  ["callstackincubator/agent-skills", "61e6e7dfdf3a8ee862254c200d751fcb1fb863dc"],
  ["cloudflare/skills", "41e0d19858946d18af9ee2c2feebbe2e11d829ff"],
  ["ComposioHQ/awesome-claude-skills", "be2a406907dbc61b73e6827ded415c96139d13a2"],
  ["datadog-labs/agent-skills", "9f3a8b065be670e70bb9b66999aae0b786a0bb7d"],
  ["expo/skills", "13ad8e05874195633b5c185f6947bb6400e228fc"],
  ["getsentry/skills", "d18b7aa8ba878354e5c348310230e652f7690f9c"],
  ["google-gemini/gemini-skills", "6fee1bec62d6a0ca92c1d0e34d62ff11f70c498a"],
  ["hashicorp/agent-skills", "f706481af9b8fedb66de909f6243ad29601afa0c"],
  ["huggingface/skills", "ca0325bb20b2d0a1b2efa893670c4c72f79e707b"],
  ["K-Dense-AI/claude-scientific-skills", "154988403bb5a18e9d3c0ce4e6d5e2e4b184a298"],
  ["mattpocock/skills", "24fe0ef7737efae15c87225755e9f6f5965e4888"],
  ["microsoft/skills", "ce7edea90860e0c69fa36db164584c87908e09f5"],
  ["neondatabase/agent-skills", "9e4a5705922fddb540c396111a7979e0dca79cc2"],
  ["obra/superpowers", "8ca22dba9a94f28898bbce59f2537ff4d87c747d"],
  ["openai/skills", "49f948faa9258a0c61caceaf225e179651397431"],
  ["remotion-dev/skills", "0b5db9daae40f42c73544d1cc0a8c733bd530eaa"],
  ["supabase/agent-skills", "c9be0e931b7930f7d02126d04774d904c381e7d7"],
  ["trailofbits/skills", "82fe8226252622fa807643bdca1710901198553a"],
  ["vercel-labs/agent-skills", "063bee94c3f4df8453406c830b0a7df0f2860278"],
  ["wshobson/agents", "46891e7e60da0e52baf1050b7b6391b64e84c6d9"],
];

const CISCO = { repo: "cisco-ai-defense/skill-scanner", commit: "669a2cdf64f81f748f6590d421c935c01c5b01b5" };
const CISCO_SAFE = ["evals/skills/safe-skills", "evals/skills/safe-skills-2"];

const REPOS: readonly RepoSource[] = [
  ...BENIGN.map(([repo, commit]) => ({ corpus: `benign/${repo.replace("/", "__")}`, label: "benign" as const, repo, commit })),
  { corpus: "benign/cisco-test-safe", label: "benign", ...CISCO, only: CISCO_SAFE },
  { corpus: "malicious/cisco-test-malicious", label: "malicious", ...CISCO, only: ["evals/skills"], except: CISCO_SAFE },
  {
    corpus: "malicious/trailofbits-overtly",
    label: "malicious",
    repo: "trailofbits/overtly-malicious-skills",
    commit: "4ffbf9461ef0505f9ce76a0d3694a18ec33ea531",
  },
  {
    corpus: "malicious/snyk-toxicskills",
    label: "malicious",
    repo: "snyk-labs/toxicskills-goof",
    commit: "80ce2e06f52fd384163c4bd6778676019723773c",
  },
  {
    corpus: "malicious/nedlir-bypass",
    label: "malicious",
    repo: "nedlir/skills-scanner-bypass",
    commit: "d7b584d6484305071c259ded94921881f9cf0d5d",
  },
];

/** MaliciousSkillBench's sources the benchmark uses (SRC012 holds payloads without a SKILL.md), at one commit of its repository. */
const MSB = {
  repo: "protectskills/MaliciousSkillBench",
  commit: "893afd609be22a2dfac5a2b94bbebb4eeb99515e",
  archives: [
    "SRC002_packages",
    "SRC004_packages",
    "SRC005_artifacts",
    "SRC006_packages",
    "SRC008_packages",
    "SRC011_artifacts",
    "SRC013_packages",
  ],
} as const;

function run(cmd: string, args: readonly string[], opts: { cwd?: string; input?: Buffer } = {}): Buffer {
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd,
    input: opts.input,
    maxBuffer: 1 << 30,
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
  });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed: ${r.stderr?.toString().trim()}`);
  return r.stdout;
}

/** The tree of `repo` at `commit`, or its `only` subtrees less `except`, as a tar stream: no checkout, so nothing in it runs. */
function archiveOf(src: RepoSource, cache: string): Buffer {
  const git = join(cache, src.repo.replace("/", "__"));
  if (!existsSync(join(git, ".git"))) {
    run("git", ["init", "-q", git]);
    run("git", ["-C", git, "remote", "add", "origin", `https://github.com/${src.repo}`]);
  }
  run("git", ["-C", git, "fetch", "-q", "--depth", "1", "origin", src.commit]);
  const exclude = (src.except ?? []).map((p) => `:(exclude)${p}`);
  return run("git", ["-C", git, "archive", "--format=tar", src.commit, "--", ...(src.only ?? ["."]), ...exclude]);
}

/**
 * Unpack a tar stream into `dir` after refusing a member named by an absolute path or through a parent
 * directory. Symlinks stay (skills ship them, and the scanner has rules about them); bsdtar will not
 * write through one.
 */
function unpack(tar: Buffer, dir: string, gzip = false): void {
  const names = run("tar", [gzip ? "-tzf" : "-tf", "-"], { input: tar })
    .toString()
    .split("\n")
    .filter(Boolean);
  for (const name of names) {
    if (name.startsWith("/") || /(^|\/)\.\.(\/|$)/.test(name)) throw new Error(`refusing archive member: ${name}`);
  }
  mkdirSync(dir, { recursive: true });
  run("tar", [gzip ? "-xzf" : "-xf", "-", "--no-same-owner", "--no-same-permissions", "-C", dir], { input: tar });
}

async function fetchMsb(root: string): Promise<void> {
  for (const name of MSB.archives) {
    const url = `https://github.com/${MSB.repo}/raw/${MSB.commit}/packages/${name}.tar.gz`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    const dir = join(root, "calibration", "msb", name.split("_")[0]!);
    rmSync(dir, { recursive: true, force: true });
    unpack(Buffer.from(await res.arrayBuffer()), dir, true);
    console.log(`msb  ${name}`);
  }
}

/** Every directory under `dir` that holds a SKILL.md, sorted. Symlinks are not followed: a skill linked into several agent folders is one skill. */
function skillDirs(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    const names = readdirSync(d);
    if (names.includes("SKILL.md")) out.push(d);
    for (const n of names) {
      const p = join(d, n);
      if (n !== ".git" && lstatSync(p, { throwIfNoEntry: false })?.isDirectory()) walk(p);
    }
  };
  if (existsSync(dir)) walk(dir);
  return out.sort();
}

function corpusDir(root: string, corpus: string, label: string): string {
  if (corpus.startsWith("malicious/msb-")) return join(root, "calibration", "msb", corpus.slice("malicious/msb-".length));
  return label === "benign" && !corpus.startsWith("benign/cisco") ? join(root, "calibration", corpus) : join(root, corpus);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const [rootArg, manifestPath] = args;
  if (!rootArg || !manifestPath) {
    console.error("usage: bun scripts/benchmark-corpora.ts <root> <manifest.json> [--as /corpora]");
    process.exit(2);
  }
  const root = resolve(rootArg);
  const asIdx = args.indexOf("--as");
  const as = asIdx >= 0 ? args[asIdx + 1] : undefined;
  const cache = join(root, ".git-cache");
  for (const src of REPOS) {
    const dir = corpusDir(root, src.corpus, src.label);
    rmSync(dir, { recursive: true, force: true });
    unpack(archiveOf(src, cache), dir);
    console.log(`git  ${src.corpus} ${src.commit.slice(0, 12)}`);
  }
  await fetchMsb(root);
  const msbCorpora = MSB.archives.map((a) => ({ corpus: `malicious/msb-${a.split("_")[0]}`, label: "malicious" as const }));
  const corpora = [...REPOS.map((s) => ({ corpus: s.corpus, label: s.label })), ...msbCorpora].map(({ corpus, label }) => {
    const paths = skillDirs(corpusDir(root, corpus, label)).map((d) => (as ? join(as, relative(root, d)) : d));
    return { name: corpus, label, mode: "repo" as const, paths };
  });
  writeFileSync(manifestPath, `${JSON.stringify({ corpora }, null, 1)}\n`);
  const count = (label: string): number => corpora.filter((c) => c.label === label).reduce((n, c) => n + c.paths.length, 0);
  console.log(`manifest: ${count("malicious")} malicious and ${count("benign")} benign skill directories -> ${manifestPath}`);
}

await main();
