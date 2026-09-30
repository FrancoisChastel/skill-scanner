# Harness setup

`skill-scanner setup` configures every harness it finds. This page lists exactly what it writes, what each hook does, the manual and marketplace alternatives, and what each harness cannot gate.

Everything `setup` installs calls a pinned runtime at `~/.skill-scanner/bin/skill-scanner.mjs` through an absolute Node path, so hooks never depend on `npx`, the network, or `PATH`. Re-run `setup` after upgrading skill-scanner or changing Node versions; `skill-scanner doctor` tells you when it is needed. `setup --project` writes the same entries into the current project (`.claude/`, `.codex/`, `.opencode/`, `.pi/`) instead of your user config.

Decisions made by the hooks and plugins are appended to `~/.skill-scanner/decisions.jsonl`.

## Claude Code

`setup` merges five hooks into `~/.claude/settings.json` (`$CLAUDE_CONFIG_DIR` is respected), keeping every other setting and hook:

| Event | Matcher | Timeout | What it does |
|---|---|---|---|
| `PreToolUse` | `Bash\|PowerShell\|Write\|Edit\|MultiEdit\|NotebookEdit\|Skill` | 120 s | Recognises installs in shell commands (`npx skills add`, `git clone` into a skill folder, `claude plugin marketplace add`, Codex's skill-installer, `pi install`) and scans the source first. A block is denied with the findings; a warning asks you; a pass runs the install under `skill-scanner guard`. Writes into a skill folder are scanned with the new content. The `Skill` tool is denied for a flagged skill. |
| `PostToolUse` | `Bash\|PowerShell\|Write\|Edit\|MultiEdit` | 120 s | After a command or write that touched skill folders, rescans them; newly blocked skills are quarantined and the agent is told why. |
| `SessionStart` | `startup\|resume\|clear\|compact` | 60 s | Audits installed skills and plugins (cached by content digest), tells the agent which flagged skills not to use, and tells you. |
| `ConfigChange` | `skills` | 60 s | Claude Code reloads skills while a session runs; this rescans a skill whose files just changed and blocks the change if it is flagged. |
| `UserPromptExpansion` | all | 15 s | Blocks `/name` for a flagged skill, so its load-time shell commands never run. |

A pass returns nothing, deliberately: an explicit allow would skip Claude Code's own permission prompt. A rewrite to `skill-scanner guard ...` goes through your permission rules like any command. Each hook keeps a deadline shorter than its timeout, because a hook that times out lets the tool call through.

Interactive sessions run hooks only in folders you trusted. `disableAllHooks` in any settings file turns skill-scanner off with everything else; `doctor` warns when it is set.

**Marketplace plugin, instead of setup.** A plugin cannot carry the build, so its hooks run the global command:

```bash
npm install -g @french-castle/skill-scanner
claude plugin marketplace add FrancoisChastel/skill-scanner
claude plugin install skill-scanner@skill-scanner
```

Use one or the other, not both. See [plugins/claude-code/README.md](../plugins/claude-code/README.md).

**Not gated before install:** `/plugin install` typed inside Claude Code has no hook; the plugin is audited at the next session start and its skills are blocked at use time if flagged. Skills synced from claude.ai arrive the same way.

## Codex

`setup` merges four hooks into `~/.codex/hooks.json` (`$CODEX_HOME` is respected):

| Event | Matcher | Timeout | What it does |
|---|---|---|---|
| `SessionStart` | `startup\|resume\|clear` | 60 s | Audits installed skills and tells the agent and you about flagged ones |
| `PreToolUse` | `^(Bash\|shell\|exec_command\|apply_patch)$` | 120 s | Same install recognition and pre-scan as Claude Code; a command that reads or runs files inside a blocked skill is denied |
| `PostToolUse` | same | 120 s | Rescans skill folders the command or patch touched |
| `UserPromptSubmit` | all | 15 s | Blocks `$name` mentions of a flagged skill |

**Codex runs a new or edited hook only after you trust it.** Open Codex, run `/hooks`, and trust the skill-scanner entries. Until then nothing is checked; `setup` and `doctor` remind you.

Codex hooks cannot ask, so a warning becomes a deny that tells the agent to ask you; set `"hooks": {"onWarn": "allow"}` to let warnings through instead. Codex's `requirements.toml` can restrict hooks to managed ones; `doctor` reports when hooks are disabled.

Manual install: copy [plugins/codex/hooks.json](../plugins/codex/hooks.json) into `~/.codex/hooks.json` (it calls `skill-scanner` from `PATH`), then trust it in `/hooks`.

## OpenCode

`setup` writes `~/.config/opencode/plugins/skill-scanner.js` (`$XDG_CONFIG_HOME` and `$OPENCODE_CONFIG_DIR` are respected), a one-line re-export of the runtime's OpenCode plugin. The plugin:

- audits installed skills when OpenCode starts and shows a toast for flagged ones;
- scans installs in `bash` tool calls before they run (OpenCode plugins cannot ask, so a warning blocks with instructions for the agent to ask you);
- blocks the `skill` tool, `read`, and slash commands for a flagged skill;
- scans full-content writes into skill folders, and rescans after commands and edits that touched them.

To load it from npm instead, add `"plugin": ["@french-castle/skill-scanner/opencode"]` to `opencode.json`.

**Not gated:** `opencode --pure` and `OPENCODE_PURE=1` skip plugins. Skills listed under `skills.urls` in the config are downloaded by OpenCode itself; they are audited at the next start. OpenCode reads skill content once at startup, so a skill flagged later stays blocked by name for the rest of the session.

## Pi

`setup` writes `~/.pi/agent/extensions/skill-scanner.js` (`$PI_CODING_AGENT_DIR` is respected), a one-line re-export of the runtime's Pi extension. The extension:

- audits installed skills at session start and notifies you;
- scans installs in `bash` tool calls and in `!command` lines you type; a warning opens a confirmation dialog when Pi has a UI;
- blocks `read` of a flagged skill's files and swallows `/skill:name` for a flagged skill;
- removes flagged skills from the skill list in the system prompt;
- adds `/skill-scan` to rescan on demand.

To load it as a package instead: `pi install npm:@french-castle/skill-scanner`.

**Not gated:** `pi -ne` and `--no-skills` skip extensions and discovered skills. Pi package installs run `npm install` with lifecycle scripts; the pre-scan covers `pi install` run by the agent or typed after `!`, but a package listed in settings and auto-installed at startup is audited only after it lands. `pi update` moves checkouts without a git checkout, so `skill-scanner guard` cannot see it.

## npx skills

There is no hook in the `skills` CLI. Two ways to gate it:

```bash
skill-scanner add owner/repo -g -a claude-code          # instead of npx skills add
skill-scanner guard npx skills update                    # updates and checks
```

`add` scans the source, then runs the real `npx -y skills@1 add` with git configuration that makes it clone the copy that was scanned, so what lands on disk is what was reviewed, and `skills-lock.json` records the original source. It also points the CLI's snapshot download at a dead address so the few owners it serves from snapshots are cloned, and scanned, too. Set `SKILL_SCANNER_SKILLS_CLI` to use another skills command (for example `bunx skills`).

When an agent runs `npx skills add` inside Claude Code, Codex, OpenCode, or Pi, the hooks and plugins above do the same automatically. The `skills` CLI copies only skill folders, so only skill folders decide its verdict; the rest of the repository (tests, CI files, documentation) is reported but does not block.

## Removing everything

```bash
skill-scanner setup --uninstall          # removes the hooks, plugin, and extension files it added
skill-scanner setup --uninstall --purge  # also deletes ~/.skill-scanner (config, trust list, quarantine)
```

Edited files keep their `*.skill-scanner.bak` backup. Restart running agents so they drop the hooks.
