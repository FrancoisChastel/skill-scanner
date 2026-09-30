# Contributing

Thanks for taking a look. The bar for every change: the scanner stays standalone, its verdicts stay explainable, and nothing it adds makes a user's machine less safe.

## Setup

```bash
git clone https://github.com/FrancoisChastel/skill-scanner
cd skill-scanner
bun install
bun run check          # typecheck, lint, tests, build, smoke test under Node
node scripts/self-scan.mjs
```

Bun runs the tests and the build; the published package runs on Node 22 or later with no runtime dependencies. Please keep it that way: `node:` modules only.

## How the code is laid out

| Directory | What lives there | Rule |
|---|---|---|
| `src/core` | Engine, frontmatter parser, Markdown regions, Unicode, decoders, embedded commands, severity and verdicts | Pure: no file system, network, clock, or randomness |
| `src/rules` | The built-in rules and the lists behind them | Each rule has a positive and a negative test |
| `src/io` | Walking directories, reading files within limits, opening zips | Never follows symlinks, never executes anything |
| `src/sources` | Resolving and fetching `owner/repo`, git, npm, and local sources; `add`, `guard`, the git post-checkout backstop | External programs are spawned without a shell |
| `src/guard` | Install-intent detection, pre-install decisions, audits, quarantine, trust, Claude Code and Codex hook handlers | Never breaks an ordinary tool call |
| `src/adapters` | OpenCode plugin and Pi extension | Thin: all decisions come from `src/guard` |
| `src/judge` | The optional jev judge | Can nudge findings, never decide |
| `src/analyzers` | Optional external tools | Invoke, never vendor |
| `src/report` | Text, JSON, SARIF, Markdown | JSON and SARIF never contain file contents |
| `src/setup` | `setup`, `doctor`, `trust` | Pure planners, then an executor that backs up what it touches |

[DESIGN.md](./DESIGN.md) explains the decisions. Read sections 3 and 14 before changing how verdicts are reached.

## Adding or changing a rule

1. Write the test first in `test/rules/`: at least one realistic positive and one benign lookalike (a warning sentence, a README, a code comment).
2. Keep regular expressions bounded (`{0,120}`, not `.*`); the input is hostile and large.
3. Choose severity by the question "is there a plausible benign reason for this in a skill?" Blocking severities are for patterns with none.
4. Write the description without live attack strings; the scanner must pass its own source (`node scripts/self-scan.mjs`).
5. Regenerate the reference: `bun run docs:rules`.
6. If it changes results on real skills, say how in the pull request (`skill-scanner scan` on a few public skill repositories before and after).

Test content that looks like malware or credentials is built at run time from pieces, and uses reserved domains (`example.com`, `.test`, `.invalid`), so the repository itself never trips antivirus or secret scanning.

## Source files are ASCII

A scanner for invisible Unicode must not carry any. Write non-ASCII characters as `\u` escapes; `bun run lint` runs `scripts/check-ascii.mjs`.

## Adding a harness or an analyzer

- A harness: add its skill roots to `src/guard/locations`, recognise its install commands in `src/guard/intents`, then either hook handlers (`src/guard/<harness>.ts` plus `setup` entries) or an in-process adapter in `src/adapters`.
- An analyzer: one module in `src/analyzers` with a pure output parser and fixture-based tests, plus an entry in the catalog with a one-line install command and whether it uses the network.

## Releasing

Maintainers only. Bump `version` in `package.json` and `src/version.ts`, the action's default version, and the plugin manifests; add a section to `CHANGELOG.md`; run `bun run check`; `npm publish`; tag `vX.Y.Z`; create the GitHub release from the changelog section.

## Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md).
