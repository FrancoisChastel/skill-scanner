# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- End-to-end suite in Docker (`bun run e2e`, `bun run e2e:registry`): installs the package next to the real Claude Code, Codex, OpenCode, Pi, and `skills` CLIs and the optional analyzers, and checks scan, add, guard, setup, the hooks, audit, trust, the adapters, the judge, and uninstall. A workflow runs it on demand before a release, on version tags against npm, and weekly against the latest harness versions.

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
