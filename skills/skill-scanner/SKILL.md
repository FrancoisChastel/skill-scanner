---
name: skill-scanner
description: Scan an Agent Skill, plugin, or skill repository for security risks before installing or using it. Use when the user asks to install, add, or update a skill or plugin (npx skills, a GitHub repository of skills, a Claude Code or Codex plugin, a Pi package), asks whether a skill is safe, or when a skill-scanner hook blocked or warned about an install.
license: MIT
---

# skill-scanner

skill-scanner reads a skill without running it and reports prompt injection, hidden or invisible instructions, commands that download and run code, credential reads that reach the network, persistence, and code that runs on install or on load. It works offline.

## Before installing a skill

Scan the source first. It accepts what the installers accept: a local path, `owner/repo`, `owner/repo@skill-name`, a GitHub URL, or `npm:<package>`.

```bash
npx -y @french-castle/skill-scanner scan <source>
```

To scan and install in one step through the `skills` CLI, use `add` in place of `npx skills add`. It takes the same flags and installs exactly the files it scanned:

```bash
npx -y @french-castle/skill-scanner add <source> [--skill <name>] [-g] [-a <agent>]
```

## Reading the result

- **PASS**: no finding reached the warning threshold. Install as the user asked.
- **WARN**: something deserves a look. Show the user the findings (rule, file, line, message) and ask before installing.
- **BLOCK**: at least one high or critical finding. Do not install. Tell the user what was found and where.

Each finding names a rule such as `exec/download-and-run` or `unicode/tag-characters`. Explain the rule in plain words; `npx -y @french-castle/skill-scanner rules` lists them all.

## When a hook blocks an install

If a `skill-scanner` hook denied a command, do not retry it, rephrase it, split it, or install the skill another way. Report the findings to the user. Only the user can approve a skill they reviewed, by running:

```bash
npx -y @french-castle/skill-scanner trust <path-to-the-reviewed-skill>
```

Trust applies to that exact content; any change is scanned again.

## Checking what is already installed

```bash
npx -y @french-castle/skill-scanner audit
```

lists every skill the installed agents load, with a verdict for each. `audit --quarantine` moves blocked skills aside; `audit --list-quarantine` and `audit --restore <id>` undo it.
