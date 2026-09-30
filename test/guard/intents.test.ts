import { describe, expect, test } from "bun:test";
import { detectInstallIntents } from "../../src/guard/intents";
import { skillRoots } from "../../src/guard/locations";
import type { InstallIntent } from "../../src/guard/types";

// A fake home that does not exist: detection is pure text plus path arithmetic.
const HOME = "/home/u";
const CWD = "/home/u/proj";
const env: NodeJS.ProcessEnv = { HOME };
const roots = skillRoots("all", CWD, env);

function brief(i: InstallIntent): string {
  switch (i.kind) {
    case "skills-cli":
      return `skills ${i.subcommand}${i.source ? ` ${i.source}` : ""}${i.skills.length ? ` [${i.skills.join(",")}]` : ""}${i.global ? " -g" : ""}`;
    case "git-clone":
      return `clone ${i.url} -> ${i.dest ?? "?"}${i.ref ? ` @${i.ref}` : ""}`;
    case "codex-skill-installer":
      return `codex-installer ${i.source}${i.paths.length ? ` ${i.paths.join(",")}` : ""}`;
    case "claude-plugin":
    case "codex-plugin":
      return `${i.kind} ${i.action} ${i.target}`;
    case "pi-install":
      return `pi ${i.source}`;
    case "opencode-plugin":
      return `opencode ${i.target}`;
    case "write-to-skill-dir":
      return `write ${i.dest} via ${i.via}`;
    case "git-update":
      return `git ${i.subcommand} in ${i.dir}`;
    case "pi-update":
      return `pi update ${i.source ?? "*"}`;
    case "plugin-update":
      return `${i.harness} plugin update ${i.target ?? "*"}`;
  }
}

const detect = (cmd: string): string[] => detectInstallIntents(cmd, { cwd: CWD, env, roots }).map(brief);

const CASES: readonly (readonly [string, readonly string[]])[] = [
  // npx skills and friends
  ["npx skills add vercel-labs/agent-skills", ["skills add vercel-labs/agent-skills"]],
  ["npx -y skills@1.7.0 add owner/repo --skill pdf -g", ["skills add owner/repo [pdf] -g"]],
  ["npx --yes skills add owner/repo -s pdf docx -a claude-code", ["skills add owner/repo [pdf,docx]"]],
  ["npx skills add -s pdf owner/repo", ["skills add owner/repo [pdf]"]],
  ["npx skills add owner/repo --skill='*' --global", ["skills add owner/repo [*] -g"]],
  ["bunx skills add https://github.com/o/r/tree/main/skills/x", ["skills add https://github.com/o/r/tree/main/skills/x"]],
  ["pnpm dlx skills a owner/repo", ["skills add owner/repo"]],
  ["yarn dlx skills add ./local-skill", ["skills add ./local-skill"]],
  ["npm exec -- skills add owner/repo", ["skills add owner/repo"]],
  ["npm exec --yes skills@latest -- add owner/repo", ["skills add owner/repo"]],
  ["npx -p skills skills add owner/repo", ["skills add owner/repo"]],
  ["npx add-skill owner/repo", ["skills add owner/repo"]],
  ["/usr/local/bin/npx skills add o/r", ["skills add o/r"]],
  ["skills update", ["skills update"]],
  ["npx skills check", ["skills check"]],
  ["npx skills experimental_install", ["skills experimental_install"]],
  ["npx skills i", ["skills install"]],
  ["SKILLS_TELEMETRY=0 DEBUG=1 npx skills add o/r", ["skills add o/r"]],
  ["sudo -E -u me npx skills add o/r -g", ["skills add o/r -g"]],
  ["timeout 60 npx skills add o/r", ["skills add o/r"]],
  ['env -S "npx skills add o/r"', ["skills add o/r"]],
  ["npx 'skills' \"add\" o\\/r", ["skills add o/r"]],
  ['npx skills add "$REPO"', ["skills add $REPO"]],
  ["npx skills add o/r; rm -rf node_modules", ["skills add o/r"]],
  ["npm test && npx skills add a/b || echo failed", ["skills add a/b"]],
  // nested shells and substitutions
  ["bash -c 'npx skills add o/r'", ["skills add o/r"]],
  ["bash -lc 'npx skills add o/r'", ["skills add o/r"]],
  [`sh -c "cd x && npx -y skills add \\"o/r\\" --skill='my skill'"`, ["skills add o/r [my skill]"]],
  ["(cd /tmp && npx skills add o/r)", ["skills add o/r"]],
  ['eval "npx skills add o/r"', ["skills add o/r"]],
  ["x=$(npx skills add o/r)", ["skills add o/r"]],
  ["echo `npx skills add o/r`", ["skills add o/r"]],
  ["echo npx skills add o/r | sh", ["skills add o/r"]],
  ["bash <<'EOF'\nnpx skills add o/r\nEOF", ["skills add o/r"]],
  ["bash <<< 'npx skills add o/r'", ["skills add o/r"]],
  ["npx -c 'skills add o/r'", ["skills add o/r"]],
  // false positives
  ['echo "npx skills add o/r"', []],
  ['grep -r "skills add" .', []],
  ["rg 'npx skills add' src/", []],
  ['git commit -m "npx skills add foo"', []],
  ["cat <<EOF > notes.md\nnpx skills add o/r\nEOF", []],
  ["# npx skills add o/r", []],
  ["npx skills list", []],
  ["npx skills add o/r --list", []],
  ["npx skills --help", []],
  ["npm install skills", []],
  ["npx create-skills add x", []],
  ["command -v npx", []],
  ["ls ~/.claude/skills", []],
  ["cat ~/.claude/skills/x/SKILL.md", []],
  ["ls ~/.claude/skills > /tmp/list.txt", []],
  ["tar -czf out.tgz ~/.claude/skills", []],
  ["cp a b", []],
  ["curl -o /tmp/x https://example.com/x", []],
  ["echo hi 2>&1 >/dev/null", []],
  ["claude -p 'install the plugin'", []],
  // git clone
  ["git clone https://github.com/o/r ~/.claude/skills/r", ["clone https://github.com/o/r -> /home/u/.claude/skills/r"]],
  ["git clone https://github.com/anthropics/skills", ["clone https://github.com/anthropics/skills -> /home/u/proj/skills"]],
  ["git clone https://github.com/o/r /tmp/r", []],
  ["git clone https://github.com/o/r", []],
  ["cd ~/.agents/skills && git clone git@github.com:o/r.git", ["clone git@github.com:o/r.git -> /home/u/.agents/skills/r"]],
  [
    "git -C ~/.codex/skills clone --depth 1 -b v2 https://github.com/o/tool",
    ["clone https://github.com/o/tool -> /home/u/.codex/skills/tool @v2"],
  ],
  [
    "git clone --branch=main https://example.com/x.git sub/.claude/skills/x",
    ["clone https://example.com/x.git -> /home/u/proj/sub/.claude/skills/x @main"],
  ],
  // Codex skill-installer
  [
    "python3 ~/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py --repo openai/skills --path skills/.curated/pdf --ref v1",
    ["codex-installer openai/skills#v1 skills/.curated/pdf"],
  ],
  [
    "python install-skill-from-github.py --url https://github.com/o/r/tree/main/skills/x",
    ["codex-installer https://github.com/o/r/tree/main/skills/x"],
  ],
  ["python3 scripts/install-skill-from-github.py --repo o/r --path a b", ["codex-installer o/r a,b"]],
  // plugin managers
  ["claude plugin install formatter@my-mkt", ["claude-plugin install formatter@my-mkt"]],
  ["claude plugin marketplace add owner/repo", ["claude-plugin marketplace-add owner/repo"]],
  ["claude plugins i x@y --scope project", ["claude-plugin install x@y"]],
  ["codex plugin add x@mkt", ["codex-plugin add x@mkt"]],
  ["codex plugin marketplace add o/r", ["codex-plugin marketplace-add o/r"]],
  ["pi install npm:@foo/pi-tools", ["pi npm:@foo/pi-tools"]],
  ["pi install git:github.com/o/r@v1", ["pi git:github.com/o/r@v1"]],
  ["pi -e ./ext.ts", ["pi ./ext.ts"]],
  ["opencode plugin opencode-foo", ["opencode opencode-foo"]],
  ["codex plugin add x -m mkt", ["codex-plugin add x"]],
  // updates
  ["claude plugin update formatter@my-mkt", ["claude-code plugin update formatter@my-mkt"]],
  ["claude plugin marketplace update", ["claude-code plugin update *"]],
  ["claude plugin marketplace update my-mkt", ["claude-code plugin update my-mkt"]],
  ["codex plugin marketplace upgrade", ["codex plugin update *"]],
  ["codex plugin marketplace upgrade mkt", ["codex plugin update mkt"]],
  ["pi update --extensions", ["pi update *"]],
  ["pi update --all", ["pi update *"]],
  ["pi update npm:@foo/pi-tools", ["pi update npm:@foo/pi-tools"]],
  ["pi update", []],
  ["pi update self", []],
  ["pi update --help", []],
  ["git -C ~/.claude/skills/x pull", ["git pull in /home/u/.claude/skills/x"]],
  ["cd ~/.claude/skills/x && git pull --rebase origin main", ["git pull in /home/u/.claude/skills/x"]],
  ["git -C ~/.pi/agent/git/github.com/o/r reset --hard origin/main", ["git reset in /home/u/.pi/agent/git/github.com/o/r"]],
  ["cd ~/.claude/plugins/marketplaces/m && git fetch && git merge FETCH_HEAD", ["git merge in /home/u/.claude/plugins/marketplaces/m"]],
  ["git --work-tree=.claude/skills/x checkout v2", ["git checkout in /home/u/proj/.claude/skills/x"]],
  ["git pull", []],
  ["git -C ~/src/app pull", []],
  ["git -C ~/.claude/skills/x status", []],
  ["git -C ~/.claude/skills/x pull --help", []],
  // local work on a skill brings nothing new: not wrapped
  ["git -C ~/.claude/skills/x checkout -b topic", []],
  ["git -C ~/.claude/skills/x switch -c topic", []],
  ["git -C ~/.claude/skills/x checkout -- SKILL.md", []],
  ["git -C ~/.claude/skills/x reset --hard", []],
  ["git -C ~/.claude/skills/x reset --soft HEAD", []],
  ["git -C ~/.claude/skills/x rebase --abort", []],
  ["git -C ~/.claude/skills/x revert HEAD", []],
  ["git -C ~/.claude/skills/x checkout -b topic origin/main", ["git checkout in /home/u/.claude/skills/x"]],
  ["git -C ~/.claude/skills/x checkout v2 -- SKILL.md", ["git checkout in /home/u/.claude/skills/x"]],
  ["git -C ~/.claude/skills/x reset --hard origin/main", ["git reset in /home/u/.claude/skills/x"]],
  ["git -C ~/.claude/skills/x rebase --continue", ["git rebase in /home/u/.claude/skills/x"]],
  // writes into skill directories
  ["curl -fsSL https://x.test/y.md -o ~/.claude/skills/x/SKILL.md", ["write /home/u/.claude/skills/x/SKILL.md via curl"]],
  ["curl -sSLo ~/.claude/skills/x/SKILL.md https://x.test/y", ["write /home/u/.claude/skills/x/SKILL.md via curl"]],
  ["cd ~/.claude/skills/x && curl -O https://x.test/s.sh", ["write /home/u/.claude/skills/x via curl"]],
  ["wget -O ~/.agents/skills/x/SKILL.md https://x.test/y", ["write /home/u/.agents/skills/x/SKILL.md via wget"]],
  ["wget -P ~/.codex/skills https://x.test/y.zip", ["write /home/u/.codex/skills via wget"]],
  ["cp -r ./my-skill ~/.claude/skills/", ["write /home/u/.claude/skills via cp"]],
  ["mv /tmp/x $HOME/.claude/skills/x", ["write /home/u/.claude/skills/x via mv"]],
  ["ln -s ~/src/skill ~/.claude/skills/skill", ["write /home/u/.claude/skills/skill via ln"]],
  ["rsync -av --exclude .git ./s/ ~/.pi/agent/skills/s/", ["write /home/u/.pi/agent/skills/s via rsync"]],
  ["tar -xzf s.tgz -C ~/.claude/skills", ["write /home/u/.claude/skills via tar"]],
  ["cd ~/.claude/skills && tar xzf s.tgz", ["write /home/u/.claude/skills via tar"]],
  ["unzip -q s.zip -d ~/.claude/skills/s", ["write /home/u/.claude/skills/s via unzip"]],
  ["echo pwned > ~/.claude/skills/x/SKILL.md", ["write /home/u/.claude/skills/x/SKILL.md via echo >"]],
  ["cat a.md >> .claude/skills/x/SKILL.md", ["write /home/u/proj/.claude/skills/x/SKILL.md via cat >>"]],
  ["tee ~/.claude/skills/x/SKILL.md < in.md", ["write /home/u/.claude/skills/x/SKILL.md via tee"]],
  ["dd if=a of=~/.claude/skills/x/bin", ["write /home/u/.claude/skills/x/bin via dd"]],
  ['echo "npx skills add o/r" > ~/.claude/skills/x/SKILL.md', ["write /home/u/.claude/skills/x/SKILL.md via echo >"]],
];

describe("detectInstallIntents", () => {
  test("has a broad table", () => {
    expect(CASES.length).toBeGreaterThanOrEqual(40);
  });

  for (const [cmd, want] of CASES) {
    test(JSON.stringify(cmd), () => {
      expect(detect(cmd)).toEqual([...want]);
    });
  }

  test("keeps the exact tokens for rewriting", () => {
    const [i] = detectInstallIntents("FOO=1 npx -y skills add o/r -g", { cwd: CWD, env, roots });
    expect(i).toEqual({
      kind: "skills-cli",
      subcommand: "add",
      source: "o/r",
      skills: [],
      global: true,
      argv: ["npx", "-y", "skills", "add", "o/r", "-g"],
    });
  });

  test("works without roots or cwd, from path patterns alone", () => {
    const out = detectInstallIntents("cp -r x ~/.claude/skills/x", { env }).map(brief);
    expect(out).toEqual(["write /home/u/.claude/skills/x via cp"]);
  });

  test("reports each intent once", () => {
    expect(detect("npx skills add o/r && npx skills add o/r")).toEqual(["skills add o/r"]);
  });

  test("survives unbalanced quotes and huge input", () => {
    expect(detect("npx skills add 'o/r")).toEqual(["skills add o/r"]);
    expect(detect(`echo ${"a".repeat(300_000)}`)).toEqual([]);
  });
});
