# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- A benchmark of the scanner's configurations (`docs/benchmark.md` and its figures): the static rules alone, with the jev judge, the judge alone, each external analyzer alone and on top of the rules, and their combinations, on 527 malicious and 2,240 benign skills, with what is blocked and what is flagged, wall time, and judge cost. A fixed split (`src/benchmark/split.ts`: training, validation, test, and seven held-out corpora) separates the data tuning reads from the data results are reported on. `scripts/benchmark.ts` runs it; `scripts/benchmark-report.ts`, `benchmark-tuning.ts`, `benchmark-subset.ts` and `benchmark-score.ts` score and tabulate it; `scripts/benchmark-plot.py` draws the figures; `scripts/judge-lab.ts` and `judge-lab-score.ts` tune the judge's questions on cached answers; `src/benchmark/metrics.ts` is the scoring.
- More judge backends, named with `judge.provider`: `cloudflare` (Workers AI, `typesafe/jev`, with `judge.accountId` or `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`), `ollama` (a local decision model such as `nimble` on Ollama 0.35+, no key), and `custom` (any host speaking TypeSafe's System One protocol, at `judge.baseUrl`). Cloudflare's response envelope is unwrapped. These follow the hosts' published request shapes and are not exercised against live hosts by the test suite.

### Changed

- The jev judge and gitleaks are on by default, in every scan, install hook, `add`, `guard`, the session audit, and the OpenCode and Pi adapters, not only in `scan`. The judge runs as soon as a jev key is set (`judge.enabled` defaults to `"auto"`: `SKILL_SCANNER_JEV_KEY` or `TYPESAFE_API_KEY`); without one, scans stay offline with no error, `setup` and `doctor` say what a key adds, and a scan in a terminal ends with a one-line tip. A general gateway key (OpenRouter, Vercel AI Gateway) still needs `--judge` or `"judge": {"enabled": true}`. gitleaks runs whenever it is installed and is skipped quietly otherwise. In install hooks a judge request is capped at 10 s with one retry, so a slow judge never holds an install; the audit cache is keyed by which second opinions run, so setting a key rescans. New library call `scanSkill()` scans with these defaults; `scanPath()` is unchanged.
- README: a numbered quick start (install, scan, protect your agents, when a scan is wrong) and a terminal recording (`docs/demo.gif`, rendered from `docs/demo.tape` with `scripts/demo-gif.sh`, which runs VHS in Docker) showing a scan, `setup`, and the Claude Code hook denying an agent's `npx skills add` of a malicious skill.
- Two deception rules for skills that hide what the agent produced from the person it works for: `deception/hidden-deliverable-content` (planting content in a hidden worksheet, tab, template, loader, or non-rendered metadata block the user never sees) and `deception/conceal-files-from-user` (tucking the agent's output or logs into a hidden/dotfile location so the user-visible tree stays clean, or out of a directory listing). Negated and descriptive wording stays quiet, and accessibility's "visually hidden", hidden form fields, and ordinary dotfile caches are excluded. On the static calibration splits these raise malicious skills caught at warn from 81 to 92 of 184 (train) and 51 to 53 of 93 (validation) with no change to benign flags or to any block verdict.

## [0.3.0] - 2026-09-30

### Added

- A `deception` category of 12 rules for skills that turn the agent against its user: reporting success whatever happened, keeping failures out of the summary, making up results, changing or skipping tests until they pass, hard-coding what the tests expect, silencing checks, quietly swapping the task for an easier one, lying, covering tracks, and planting bugs; plus scripts and pytest or Jest code that turn failing runs into passes (`|| echo "passed"`, outcomes rewritten to `passed`, patched assertions, objects equal to everything). The tactics come from published reward-hacking and scheming research (ImpossibleBench, METR, OpenAI, the Claude 3.7 Sonnet system card, Apollo Research, Anthropic's Sycophancy to Subterfuge) and the 2025 Replit incident. Negated and descriptive wording ("never modify tests to make them pass") is recognised, so honest verification skills stay quiet: the rules change no verdict in the 3,611 benign skills used for calibration.

## [0.2.0] - 2026-09-30

### Added

- Updates are gated, not just installs. `guard` now also installs a git `reference-transaction` hook: before a checked-out branch (or its upstream) moves to a new commit, that commit is scanned, and a refused update is aborted. `git pull` and `pi update` are refused at their fetch, before the working tree changes; `reset`, `merge`, and `rebase` have the working tree put back, and a refused `git checkout` in an existing repository switches back. The hooks and plugins run `npx skills update`, `git pull` (and `reset`, `merge`, `rebase`, `checkout`) in an installed skill or plugin, `pi update`, `claude plugin update`, and the Claude Code and Codex marketplace updates under `guard`; Codex, which cannot rewrite a command, refuses them with the guarded command to run instead.
- `pi update` has the npm versions it would install scanned first, since Pi runs their install scripts.
- `codex plugin add <plugin>@<marketplace>` is scanned before it runs: the plugin's directory in the marketplace, or the git repository or npm package the marketplace names.
- End-to-end suite in Docker (`bun run e2e`, `bun run e2e:registry`): installs the package next to the real Claude Code, Codex, OpenCode, Pi, and `skills` CLIs and the optional analyzers, and checks scan, add, guard, setup, the hooks, audit, trust, the adapters, the judge, and uninstall. A workflow runs it on demand before a release, on version tags against npm, and weekly against the latest harness versions.

### Changed

- The judge asks six new threat questions about intent (hidden instructions, a purpose other than the stated one, behavior its user would object to, malice, a download from an unofficial source) and adds one medium `judge/malicious-skill` finding when their combined score reaches 0.075; the eight review probes now only doubt static findings, never confirm or add. The state budget rises from 24,000 to 96,000 characters. Questions and threshold were tuned on a training split and gated on validation (docs/benchmark.md); on skills tuning never read, the judge alone now flags 71% of malicious skills at a 0.6% false-flag rate, where it flagged 26% at 1.5%, and static rules + jev flags 78% where it flagged 49%. The three delivery-trick rules (`exec/manual-install-lure`, `exec/password-protected-archive`, `injection/terminal-social-engineering`) are hard evidence the judge cannot doubt: no probe asks about a lure aimed at the user, and the judge was demoting correct findings on 24 of the 30 ClawHavoc samples.
- Hook scans have a hard time limit. Scans in the Claude Code and Codex hooks, the git hooks, `add`, and the OpenCode and Pi adapters run in a worker thread that is terminated at the deadline, so a scan that never finishes (a regular expression backtracking on hostile input) can no longer hold a hook past its harness's timeout. Git hook scans are limited to 60 s and refuse what they could not finish.
- The git hooks honor digests approved with `skill-scanner trust`, as installs already did.

### Security

- A skill can no longer hide its own secrets from gitleaks with a `.gitleaksignore`: gitleaks has no flag to skip that file, so it now scans a copy of the tree without it.

## [0.1.0] - 2026-09-30

First public release.

### Added

- `scan`: a static, offline scanner for Agent Skills, Claude Code plugins, and skill repositories. 109 rules across prompt injection, hidden and invisible text, code execution, credential access and exfiltration, persistence, destructive commands, privilege, embedded secrets, supply chain, packaging, frontmatter, and execution surfaces (hooks, MCP servers, load-time shell expansion, plugin binaries). Markdown-region and file-role awareness, decoding and rescanning of base64, hex, and char-code payloads, zip and Office archive inspection, bytecode-to-source checks, symlink analysis, and correlation of credential reads with network sends. Targets are local paths or any source `npx skills add` accepts.
- Output as text, JSON, SARIF 2.1.0 (for GitHub code scanning), and Markdown; secrets redacted in every format.
- `add`: scans a source, then runs `npx skills add` so it installs exactly the checkout that was scanned.
- `guard`: runs any command with a git post-checkout hook that scans every checkout it makes.
- `audit`: scans every skill and plugin Claude Code, Codex, OpenCode, and Pi load, with a digest cache, quarantine, and restore.
- Claude Code and Codex hooks (`hook`), an OpenCode plugin, and a Pi extension that pre-scan installs, rewrite them through `guard`, audit at session start, reconcile after changes, and block flagged skills at use time.
- `setup`, `doctor`, and `trust`: one-command, reversible installation into all four harnesses with backups and canaries; health checks with fixes; approval of reviewed skills by exact digest.
- Optional jev judge (TypeSafe, OpenRouter, or Vercel AI Gateway keys) that confirms or doubts findings through eight `choice` probes and never blocks alone.
- Optional external analyzers: NVIDIA SkillSpector, Cisco AI Defense skill-scanner, gitleaks, osv-scanner, semgrep and opengrep.
- A GitHub Action, a Claude Code marketplace plugin, a Codex hook template, a JSON Schema for the configuration, and the `skill-scanner` skill.
