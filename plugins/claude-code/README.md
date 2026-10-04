# skill-scanner plugin for Claude Code

Hooks that scan Agent Skills before Claude Code installs or runs them. Most people should run `npx @french-castle/skill-scanner setup` instead: it installs the same hooks with a pinned runtime and an absolute Node path, so nothing depends on `PATH`. Use this plugin if you prefer to manage hooks through `/plugin`.

## Prerequisites

A plugin cannot carry the scanner's build, so the hooks run the globally installed command:

```bash
npm install -g @french-castle/skill-scanner
skill-scanner --version   # must print 0.1.0 or later
```

Cisco's Python scanner also installs a `skill-scanner` command. If `--version` prints something else, fix your `PATH` or use `setup` instead.

## Install

```bash
claude plugin marketplace add FrancoisChastel/skill-scanner
claude plugin install skill-scanner@skill-scanner
```

Restart Claude Code, then check with `skill-scanner doctor`. Do not also run `skill-scanner setup claude-code`: with both, every check runs twice (`doctor` warns about it).

## What the hooks do

| Event | Matcher | What it does |
|---|---|---|
| `PreToolUse` | Bash, PowerShell, Write, Edit, MultiEdit, NotebookEdit, Skill | Scans what a command would install (`npx skills add`, `git clone` into a skill directory, `claude plugin install`, ...) before it runs, and blocks flagged skills from being used |
| `PostToolUse` | Bash, PowerShell, Write, Edit, MultiEdit | Rescans skill directories the tool changed and quarantines new blocked skills |
| `SessionStart` | startup, resume, clear, compact | Audits installed skills (cached by digest) |
| `ConfigChange` | skills | Rescans when skill files change during a session |
| `UserPromptExpansion` | all | Blocks `/name` for a flagged skill |

A blocked install is denied with the findings; a warning asks you. Nothing is sent over the network unless you turn on jev (set `TYPESAFE_API_KEY`): it reads what a skill is trying to do and flags about twice as many malicious skills, and never blocks on its own. Approve a skill you reviewed with `skill-scanner trust <path>`.

## Remove

```bash
claude plugin uninstall skill-scanner@skill-scanner
claude plugin marketplace remove skill-scanner
```

`~/.skill-scanner` holds the config, trust list, and quarantine; delete it to remove every trace.
