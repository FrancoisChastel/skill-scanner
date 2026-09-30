# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- A `deception` category of 12 rules for skills that turn the agent against its user: reporting success whatever happened, keeping failures out of the summary, making up results, changing or skipping tests until they pass, hard-coding what the tests expect, silencing checks, quietly swapping the task for an easier one, lying, covering tracks, and planting bugs; plus scripts and pytest or Jest code that turn failing runs into passes (`|| echo "passed"`, outcomes rewritten to `passed`, patched assertions, objects equal to everything). The tactics come from published reward-hacking and scheming research (ImpossibleBench, METR, OpenAI, the Claude 3.7 Sonnet system card, Apollo Research, Anthropic's Sycophancy to Subterfuge) and the 2025 Replit incident. Negated and descriptive wording ("never modify tests to make them pass") is recognised, so honest verification skills stay quiet: the rules change no verdict in the 3,611 benign skills used for calibration.

## [0.2.0] - 2026-09-30

### Added

- Updates are gated, not just installs. `guard` now also installs a git `reference-transaction` hook: before a checked-out branch (or its upstream) moves to a new commit, that commit is scanned, and a refused update is aborted. `git pull` and `pi update` are refused at their fetch, before the working tree changes; `reset`, `merge`, and `rebase` have the working tree put back, and a refused `git checkout` in an existing repository switches back. The hooks and plugins run `npx skills update`, `git pull` (and `reset`, `merge`, `rebase`, `checkout`) in an installed skill or plugin, `pi update`, `claude plugin update`, and the Claude Code and Codex marketplace updates under `guard`; Codex, which cannot rewrite a command, refuses them with the guarded command to run instead.
- `pi update` has the npm versions it would install scanned first, since Pi runs their install scripts.
- `codex plugin add <plugin>@<marketplace>` is scanned before it runs: the plugin's directory in the marketplace, or the git repository or npm package the marketplace names.
- End-to-end suite in Docker (`bun run e2e`, `bun run e2e:registry`): installs the package next to the real Claude Code, Codex, OpenCode, Pi, and `skills` CLIs and the optional analyzers, and checks scan, add, guard, setup, the hooks, audit, trust, the adapters, the judge, and uninstall. A workflow runs it on demand before a release, on version tags against npm, and weekly against the latest harness versions.

### Changed

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
