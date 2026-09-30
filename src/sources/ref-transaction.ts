import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { CliIO } from "../cli/io";
import { git } from "./git";
import { APPROVED_COMMITS_ENV, CHECKOUTS_FILE, REFUSALS_FILE } from "./guard-env";
import { type GitHookDeps, hookGitEnv, isApproved, PASSED_FILE, readRecord, record, scanForGitHook } from "./hook-scan";
import { originOf } from "./post-checkout";

/**
 * The git `reference-transaction` hook installed by `skill-scanner guard`: it gates updates of
 * repositories that already exist, which never run `post-checkout` (`git pull`, `git reset`,
 * `git merge`, `pi update`). Git calls the hook with the state and one `<old> <new> <ref>` line
 * per ref; the hook script passes on the lines that update HEAD, a branch, or a remote-tracking
 * branch. Here:
 *
 * - `prepared`: when HEAD, the checked-out branch, or its upstream is about to move to a commit
 *   not scanned under this guard, that commit's tree is checked out into a temporary directory
 *   and scanned. A refusal exits 1, and git aborts the whole transaction. `git pull` and
 *   `pi update` are refused at their fetch, before the working tree changes.
 * - `aborted`: `reset`, `merge`, and `rebase` write the working tree before they move the branch.
 *   When the move this hook refused is aborted and the index holds the refused tree, the working
 *   tree is moved back (`git read-tree -m -u <refused> <previous>`), keeping unrelated local changes.
 */

/** Lines this hook refused, so the `aborted` call knows which moves were ours to undo. */
const REJECTED_FILE = "rejected.log";
const OID = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const ZERO_OID = /^0+$/;
const GIT_TIMEOUT_MS = 30_000;
/** Beyond this the collection limits would refuse the tree anyway; do not write it out to find that out. */
const MAX_TREE_ENTRIES = 50_000;
const MAX_TREE_BYTES = 512 * 1024 * 1024;

interface RefUpdate {
  readonly old: string;
  readonly new: string;
  readonly ref: string;
}

interface Repo {
  readonly dir: string;
  readonly gitDir: string;
  readonly bare: boolean;
  readonly env: NodeJS.ProcessEnv;
}

export async function runRefTransaction(argv: readonly string[], io: CliIO, deps: GitHookDeps = {}): Promise<number> {
  const { dir, gitDir, state } = parseArgs(argv, io.cwd);
  const env = hookGitEnv(io.env);
  const updates = parseUpdates(await io.readStdin());
  if (updates.length === 0 || (state !== "prepared" && state !== "aborted")) return 0;
  const lines = updates.map(line).join("");
  try {
    const repo = await openRepo(dir, gitDir, env);
    const moves = await watched(updates, repo);
    if (moves.length === 0) return 0;
    if (state === "aborted") {
      await undo(moves, repo, io);
      return 0;
    }
    return await gate(moves, repo, io, deps);
  } catch (e) {
    if (state !== "prepared") return 0;
    const why = `skill-scanner: cannot scan the update in ${dir} (${e instanceof Error ? e.message : String(e)}); refusing it.\n`;
    io.stderr(why);
    await record(io, REFUSALS_FILE, why);
    await record(io, REJECTED_FILE, lines);
    return 1;
  }
}

function parseArgs(argv: readonly string[], cwd: string): { dir: string; gitDir: string; state: string } {
  let dir = cwd;
  let gitDir = join(cwd, ".git");
  let state = "";
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    const value = argv[i + 1];
    if ((a === "--dir" || a === "--git-dir") && value !== undefined) {
      if (a === "--dir") dir = resolve(cwd, value);
      else gitDir = resolve(cwd, value);
      i += 1;
    } else state = a;
  }
  return { dir, gitDir, state };
}

/** `<old> <new> <ref>` lines that move an existing ref to another commit. Symbolic-ref lines (git 2.46+) are skipped. */
export function parseUpdates(text: string): RefUpdate[] {
  return text
    .split("\n")
    .map((l) => l.trim().split(" "))
    .filter((p): p is [string, string, string] => p.length === 3)
    .map(([old, next, ref]) => ({ old: old.toLowerCase(), new: next.toLowerCase(), ref }))
    .filter((u) => OID.test(u.old) && OID.test(u.new) && !ZERO_OID.test(u.old) && !ZERO_OID.test(u.new) && u.old !== u.new);
}

const line = (u: RefUpdate): string => `${u.old} ${u.new} ${u.ref}\n`;

async function openRepo(dir: string, gitDir: string, env: NodeJS.ProcessEnv): Promise<Repo> {
  const bare =
    (await git(["--git-dir", gitDir, "rev-parse", "--is-bare-repository"], { env, timeoutMs: GIT_TIMEOUT_MS })).trim() === "true";
  return { dir, gitDir, bare, env };
}

function inRepo(repo: Repo, args: readonly string[], env: NodeJS.ProcessEnv = repo.env): Promise<string> {
  const tree = repo.bare ? [] : ["--work-tree", repo.dir];
  return git(["--git-dir", repo.gitDir, ...tree, ...args], { env, timeoutMs: GIT_TIMEOUT_MS, cwd: repo.dir });
}

const quietly = (p: Promise<string>): Promise<string> => p.then((s) => s.trim()).catch(() => "");

/** The updates that change what is (or is about to be) checked out: HEAD, its branch, and that branch's upstream. */
async function watched(updates: readonly RefUpdate[], repo: Repo): Promise<RefUpdate[]> {
  const branch = await quietly(inRepo(repo, ["symbolic-ref", "-q", "HEAD"]));
  const upstream = branch ? await quietly(inRepo(repo, ["rev-parse", "--symbolic-full-name", "@{upstream}"])) : "";
  return updates.filter((u) => u.ref === "HEAD" || (branch !== "" && u.ref === branch) || (upstream !== "" && u.ref === upstream));
}

/** `prepared`: scan every new commit not already let through; refuse the transaction at the first refusal. */
async function gate(moves: readonly RefUpdate[], repo: Repo, io: CliIO, deps: GitHookDeps): Promise<number> {
  const passed = new Set(await readRecord(io, PASSED_FILE));
  for (const commit of [...new Set(moves.map((m) => m.new))]) {
    if (isApproved(commit, io.env[APPROVED_COMMITS_ENV])) continue;
    const tree = (await inRepo(repo, ["rev-parse", "--verify", `${commit}^{tree}`])).trim();
    if (passed.has(tree)) continue;
    const label = `${await originOf(repo.gitDir, repo.env)} at ${commit.slice(0, 12)}`;
    const scanned = await withTree(repo, tree, (dir) => scanForGitHook(dir, label, io, deps));
    io.stderr(scanned.summary);
    await record(io, CHECKOUTS_FILE, `${commit} ${scanned.refusal ? "refused" : scanned.report.verdict}\n`);
    if (scanned.refusal) {
      io.stderr(`skill-scanner: update refused: ${scanned.refusal}. Ask the user before retrying without the guard.\n`);
      await record(io, REFUSALS_FILE, scanned.summary);
      await record(io, REJECTED_FILE, moves.map(line).join(""));
      return 1;
    }
    passed.add(tree);
    await record(io, PASSED_FILE, `${tree}\n`);
  }
  return 0;
}

/**
 * Check `tree` out into a temporary directory through a temporary index (the repository's index,
 * working tree, and refs are untouched, and no hook runs) and hand the directory to `use`.
 */
async function withTree<T>(repo: Repo, tree: string, use: (dir: string) => Promise<T>): Promise<T> {
  await checkTreeSize(repo, tree);
  const tmp = await mkdtemp(join(tmpdir(), "skill-scanner-update-"));
  try {
    const work = join(tmp, "tree");
    await mkdir(work);
    const env = { ...repo.env, GIT_INDEX_FILE: join(tmp, "index") };
    await git(["--git-dir", repo.gitDir, "--work-tree", work, "read-tree", tree], { env, timeoutMs: GIT_TIMEOUT_MS, cwd: work });
    await git(["--git-dir", repo.gitDir, "--work-tree", work, "checkout-index", "--all", "--force"], {
      env,
      timeoutMs: GIT_TIMEOUT_MS,
      cwd: work,
    });
    return await use(work);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

async function checkTreeSize(repo: Repo, tree: string): Promise<void> {
  const listing = await inRepo(repo, ["ls-tree", "-r", "-l", tree]);
  let entries = 0;
  let bytes = 0;
  for (const row of listing.split("\n")) {
    if (!row) continue;
    entries += 1;
    const size = Number(row.split("\t")[0]?.split(/\s+/)[3]);
    if (Number.isFinite(size)) bytes += size;
  }
  if (entries > MAX_TREE_ENTRIES || bytes > MAX_TREE_BYTES) {
    throw new Error(`the update is too large to scan (${entries} files, ${Math.round(bytes / 1024 / 1024)} MB)`);
  }
}

/** `aborted`: put the working tree back when this hook refused a move that had already written it. */
async function undo(moves: readonly RefUpdate[], repo: Repo, io: CliIO): Promise<void> {
  if (repo.bare) return;
  const refused = new Set(await readRecord(io, REJECTED_FILE));
  const move = moves.find((m) => !m.ref.startsWith("refs/remotes/") && refused.has(line(m).trimEnd()));
  if (!move) return;
  // Only when the index holds exactly the refused tree: otherwise git stopped before writing it, or something else changed it.
  const holdsRefused = await inRepo(repo, ["diff-index", "--cached", "--quiet", move.new, "--"]).then(
    () => true,
    () => false,
  );
  if (!holdsRefused) return;
  const succeeded = (p: Promise<string>): Promise<boolean> =>
    p.then(
      () => true,
      () => false,
    );
  try {
    if (await succeeded(inRepo(repo, ["diff-files", "--quiet"]))) {
      // The working tree is exactly the refused tree: move it back, deleting only what the refused tree added.
      await inRepo(repo, ["read-tree", "-m", "-u", move.new, move.old]);
      const note = `skill-scanner: restored the working tree of ${repo.dir} to ${move.old.slice(0, 12)}.\n`;
      io.stderr(note);
      await record(io, REFUSALS_FILE, note);
      return;
    }
    // The refused tree reached the index but not (all of) the working tree (`reset --mixed`, or files
    // changed meanwhile): put the index back and leave every file as it is.
    await inRepo(repo, ["read-tree", move.old]);
    const note = `skill-scanner: restored the index of ${repo.dir} to ${move.old.slice(0, 12)}; its files were left as they are. Check \`git status\` there.\n`;
    io.stderr(note);
    await record(io, REFUSALS_FILE, note);
  } catch (e) {
    const note = `skill-scanner: could not restore the working tree of ${repo.dir} (${e instanceof Error ? e.message : String(e)}); the refused files are in it, uncommitted. Run \`git status\` there.\n`;
    io.stderr(note);
    await record(io, REFUSALS_FILE, note);
  }
}
