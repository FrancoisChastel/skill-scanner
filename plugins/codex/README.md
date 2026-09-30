# skill-scanner hooks for Codex

The easy way is `npx @french-castle/skill-scanner setup codex`: it merges these hooks into `~/.codex/hooks.json` (keeping yours, with a `.skill-scanner.bak` copy of the original) and points them at a pinned runtime with an absolute Node path.

To install by hand instead:

1. `npm install -g @french-castle/skill-scanner` and check that `skill-scanner --version` prints 0.1.0 or later (Cisco's Python scanner installs a command with the same name).
2. Copy `hooks.json` to `~/.codex/hooks.json`, or merge its `hooks` entries into your existing file. Codex rejects unknown fields in hook handlers, so keep only `type`, `command`, `timeout`, and `statusMessage`.
3. Open Codex, run `/hooks`, and trust the skill-scanner entries. Codex skips new or changed hooks until you do.

| Event | Matcher | What it does |
|---|---|---|
| `SessionStart` | startup, resume, clear | Audits installed skills (cached by digest) |
| `PreToolUse` | shell commands and `apply_patch` | Scans what a command or patch would install into a skill directory before it runs |
| `PostToolUse` | shell commands and `apply_patch` | Rescans changed skill directories and quarantines new blocked skills |
| `UserPromptSubmit` | all | Blocks `$name` for a flagged skill |

Codex has no "ask" decision, so a warning becomes a denial that tells the agent to ask you first.

To remove: `skill-scanner setup --uninstall codex`, or delete the entries whose command is `skill-scanner hook codex`.
