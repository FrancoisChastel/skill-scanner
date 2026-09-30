# skill-scanner design

Status: v0.1.0, 2026-09-30 (npm `@french-castle/skill-scanner`). This document records what the scanner does, why it is built this way, and what it does not cover. Decisions are numbered in section 14 and kept current.

## 1. What this is

A security scanner for Agent Skills (directories with a `SKILL.md`, per [agentskills.io](https://agentskills.io/specification)) that runs at the moment a skill is installed, in the harnesses people use: Claude Code, Codex, OpenCode, Pi, and Vercel's `npx skills` CLI. It looks for the ways a skill can turn an agent against its user: instructions that override or hide, invisible text, commands that download and run code, reads of credentials followed by network sends, persistence in shell or agent configuration, and code that runs on install or on load without anyone reading it.

It is standalone. The core is a deterministic static analyzer with no runtime dependencies and no network access. Two things are optional and off by default: TypeSafe's jev, a "System One" decision model, as a second opinion; and established open-source scanners (NVIDIA SkillSpector, Cisco AI Defense skill-scanner, gitleaks, osv-scanner, semgrep) when they are installed.

## 2. Why it should exist

Skills are code and instructions that an agent executes with the user's permissions. Public registries have already carried malicious skills (the ClawHavoc campaign on ClawHub, macOS infostealers distributed as skills), and research has shown that every widely used scanner can be bypassed by padding, archives, or bytecode (Trail of Bits, June 2026).

Prior art, surveyed on 2026-09-30:

| Tool | Language | Runs offline | Gates installs in harnesses |
|---|---|---|---|
| Cisco AI Defense skill-scanner | Python | core rules yes; LLM, VirusTotal, AI Defense need keys | no |
| NVIDIA SkillSpector | Python | static mode yes | Pi and OpenCode extensions |
| Snyk agent-scan | Python | no (cloud analysis, token) | no |
| skills.sh audits (Gen, Socket, Snyk) | service | no | advisory table in `npx skills add`, never blocks |
| agentverus-scanner | TypeScript | yes | no |

The gaps this project fills:

1. **Install-time gating across harnesses.** A scan you have to remember to run protects nobody. The scanner sits in the install paths of all four harnesses and of `npx skills`, including the ones an agent triggers on its own.
2. **Zero dependencies, `npx`-runnable, offline.** Nothing to provision; nothing leaves the machine unless the user opts in.
3. **Execution surfaces other scanners skip.** Claude Code's load-time shell expansion (`` !`cmd` `` and ```` ```! ````), skill-scoped `hooks:` frontmatter, plugin `bin/` on PATH, marketplace `command` sources, Codex skill MCP dependencies, Pi and OpenCode in-process extensions.
4. **Not trusting its own truncation.** Oversize files, archives, bytecode, and padding are findings, not blind spots.

## 3. Principles

- **Code decides; models nudge.** Verdicts come from deterministic rules. The optional judge can raise confidence, doubt a finding by one step, or add a medium-severity note. It can never remove a finding, change a severity, or block on its own.
- **Standalone first.** Every feature works offline with no key. Network use (fetching a source to scan it, the judge, some external analyzers) is explicit and documented.
- **Fail safe where it matters, fail open where it does not.** An error while scanning an install asks or refuses (configurable). An error in a hook handling an ordinary command lets the command through: a broken scanner must never break someone's shell.
- **The scanned content never configures the scanner.** Configuration and allowlists come from the user's home or an explicit `--config`, never from the directory being scanned.
- **Evidence over verdicts.** Every finding carries a rule id, location, snippet, and, for decoded or hidden content, what was hidden. Secrets are redacted before anything is printed, written, or sent.
- **Honest about limits.** Static analysis misses purely semantic attacks. The README and section 15 say so.

## 4. Threat model

In scope: a skill (or plugin, or package that ships skills) authored or modified by an attacker, installed by a user or by the user's agent. The attacker controls every byte of the skill, including file names, encodings, symlinks, archives, and frontmatter. Goals the scanner looks for:

- Take over the agent: instruction overrides, concealment, fake system messages, hidden or invisible text, trigger stuffing in descriptions.
- Run code: download-and-execute, decode-and-execute, reverse shells, load-time shell expansion, hooks, lifecycle scripts, MCP servers, plugin binaries.
- Steal: reads of keys, credential stores, browser data, wallets, agent logins, the environment; followed by network sends, DNS lookups, or chat webhooks.
- Persist: cron, launchd, systemd, shell profiles, authorized keys, git hooks, agent settings and instruction files, other skill directories.
- Evade review: encodings, padding, minification, bytecode, archives, symlinks, deceptive names, parser differentials in frontmatter.

Out of scope: sandboxing (use the harness's sandbox, or a kernel-level policy), runtime behavior of code the user chose to trust, a compromised harness or Node installation, and attacks that are indistinguishable from the skill's stated purpose (a "deploy to production" skill that deploys).

## 5. Architecture

```
 sources ─────────────────► collect ──────────────► engine ─────────────► verdict ──► reporters
 local dir, zip,            walk (no symlink        file rules              severity ×      text, json,
 git, npm, owner/repo       following), read        (regex + structure)     confidence      sarif, markdown
 (src/sources)              bounded, expand         decode + rescan         policy          (src/report)
                            zip, group into         embedded commands       suppressions
                            bundles (src/io)        signals → correlation   trust
                                                    (src/core, src/rules)
                                                          │
                                         optional ────────┴──────── optional
                                         external analyzers         jev judge
                                         (src/analyzers)            (src/judge)

 guard (src/guard): recognise install intents in shell commands → pre-scan the source → decide
                    audit installed skills (cached by digest) → flag, quarantine, block at use time
       ├─ Claude Code and Codex hooks  (skill-scanner hook <harness>)
       ├─ OpenCode plugin, Pi extension (src/adapters)
       └─ skill-scanner add / guard     (npx skills delegation, git post-checkout backstop)
```

`src/core` is pure: no file system, no network, no clock. Everything testable from in-memory bundles.

## 6. Detection pipeline

1. **Collect.** Walk the target without following symlinks (a link is recorded with its target and whether it escapes). Read each file up to a limit; larger files are truncated and the truncation is a finding. Binary files are classified by magic bytes; zip-based archives, including Office documents, are opened in memory and their entries scanned as `archive.zip!/entry`. Every directory containing a `SKILL.md` becomes a bundle; files outside any skill form a root bundle (a plugin or package). Each bundle gets a content digest.
2. **Embedded commands.** Commands that run without anyone opening a script are extracted as virtual shell files: npm scripts, Claude Code and Codex hooks (settings, `hooks.json`, frontmatter `hooks:`), MCP server launch commands, Codex `agents/openai.yaml` stdio dependencies, and load-time shell expansions in `SKILL.md`, commands, and agents.
3. **File rules.** Each rule declares the file kinds it applies to. Markdown is split into regions (frontmatter, prose, fenced code, inline code, hidden) and a rule says what a match means in each: hidden regions raise severity, frontmatter raises it (the description is in every session's context), prose may lower confidence. Fenced code in `SKILL.md` is not discounted: it is what the agent runs. A match in a sentence that warns against the pattern, or inside a code comment, drops one severity step and to low confidence.
4. **Decode and rescan.** Base64, hex, and char-code payloads that decode to readable text are scanned again (two layers deep). Anything found there is reported at the original location, and the payload itself becomes a critical `obfuscation/encoded-payload` finding.
5. **Signals and correlation.** Rules record capabilities (credential read, environment dump, network send) when their confidence is not low. Bundle rules combine them: credential read plus a network send in the same file is critical; across files in one skill, high.
6. **Bundle rules.** Frontmatter checks, packaging (binaries, archives, extension mismatches, symlinks, bytecode against its source, dotfiles, duplicate `SKILL.md` variants, incomplete scans), and execution surfaces (hooks, MCP servers, LSP, monitors, marketplace sources, in-process extensions, editor auto-run tasks).
7. **Verdict.** Effective severity is the severity, one step lower when confidence is low. The bundle blocks when any effective severity reaches `blockAt` (default high) and warns at `warnAt` (default medium). Suppressions (`ignore` in the user config, by rule, path glob, and optionally exact digest) remove findings before the verdict; trust (`skill-scanner trust`) approves an exact digest for the install gates.

Rules are listed with their severity and rationale in [docs/rules.md](./docs/rules.md), generated from the code.

## 7. Severity calibration

Rules were tuned against 3,611 benign skills (20 vendor repositories, large community collections, 339 skills installed on a development machine, and a 1,052-skill Claude Code plugin cache), public benign corpora, and public malicious test sets. The target is zero blocks on reputable official skills unless the finding is real, meaningful warnings, and every malicious sample that static analysis can reasonably see. Current numbers and misses are recorded in [docs/evaluation.md](./docs/evaluation.md): 4 blocks in 3,611 benign skills, each reviewed and kept, and full detection of the ClawHavoc samples in MaliciousSkillBench. Blocking severities are reserved for patterns with no plausible benign reading in a skill: download-and-execute from an unknown host, decode-and-execute, invisible tag characters, reverse shells, credential reads that reach the network, symlinks to secrets, disk wipes.

## 8. The optional jev judge

jev answers typed questions about a state with calibrated probabilities, in a few hundred milliseconds, through TypeSafe's API, OpenRouter, or Vercel AI Gateway. It is used as a second opinion, never as the verdict.

Evidence that shaped this, from Cisco's published measurements on MaliciousSkillBench: asked as single `noul` (yes/no probability) questions, jev's answers were inverted relative to the label (AUC 0.25 to 0.31). Asked as boolean `choice` questions with `true` and `false` options, reading the probability of `true`, the same model separated well: obfuscation AUC 0.977 and prompt injection 0.963 on one split, 0.908 and 0.881 on held-out test. The question type was the problem, not the model.

So the judge asks eight threat probes (wording adapted from Cisco's, Apache-2.0) in one request, as `choice` questions, over the skill's text files, redacted and with invisible characters made visible. Text over 24,000 characters is not sent at all: a model answering about text it never saw would be a fail-open. The answers are applied monotonically:

- A static finding whose matching probe is below 0.05 is doubted: confidence becomes low, which lowers its effective severity one step. Hard evidence (invisible tag characters, decode-and-execute, binaries, symlinks, encoded payloads) and critical findings are never doubted.
- A finding whose probe is at or above 0.5 is confirmed: its confidence rises one step. A finding its context demoted (a warning sentence, a code comment) can be restored this way, which can turn a warning back into a block; nothing moves further than one step.
- A probe at or above 0.85 with no static finding in its family adds a medium `judge/*` finding. It warns; it never blocks alone.

These thresholds have not been calibrated on this pipeline; Cisco's selected screen thresholds for the prompt-injection probe were 0.048 to 0.061. They are constants in `src/judge` and will move when there is data.

## 9. External analyzers

When installed, and when enabled by `--with` or the config, established tools run over the same target and their findings join the report under `external/<tool>`: NVIDIA SkillSpector and Cisco's skill-scanner in their static, offline modes; gitleaks for secrets; osv-scanner for vulnerable dependencies (uses the network); semgrep or opengrep with a configured ruleset. They are invoked as separate programs without a shell, with a timeout and an output cap. Their rules are never vendored. `skill-scanner doctor` shows which are available and how to install the rest.

## 10. Install paths and how each is gated

| Install path | Before it runs | While it runs | After it runs |
|---|---|---|---|
| `npx skills add <src>` typed by the user | `skill-scanner add <src>` fetches, scans, and asks or refuses | the delegated `skills add` installs from the scanned mirror (`url.<mirror>.insteadOf`), with a git `post-checkout` hook as a backstop | |
| `npx skills add` run by an agent | Claude Code / Codex hook, OpenCode plugin, or Pi extension pre-scans the source and denies, asks, or allows | the command is rewritten to run under `skill-scanner guard` where the harness allows it | post-tool reconciliation rescans skill directories |
| `npx skills update`, `check` | not scannable in advance | `skill-scanner guard -- npx skills update` scans every git checkout | reconciliation |
| Codex `skill-installer` | hook pre-scans `--repo`/`--path` or `--url` | | reconciliation |
| Claude Code `plugin marketplace add`, `plugin install` from a shell | hook pre-scans the marketplace repository or the plugin's source | | session-start audit of the plugin cache |
| `/plugin install` inside Claude Code | no hook exists for it | | session-start audit; a flagged plugin's skills are blocked at use time |
| `pi install git:` / `npm:` | extension or hook pre-scans the package | `guard` for git sources | session-start audit |
| `git clone`, `cp`, `curl -o` into a skill directory | recognised when the destination is a skill root | `guard` for clones | reconciliation; Claude Code `ConfigChange` fires on skill writes |
| Skills synced from claude.ai, files written outside any tool call | none | | session-start audit, use-time blocking |

Use-time blocking: Claude Code `PreToolUse` on the `Skill` tool and `UserPromptExpansion` for `/name`; Codex `UserPromptSubmit` for `$name`; OpenCode `skill` tool, `read`, and slash commands; Pi `read` of the skill file, `/skill:name`, and the system prompt listing. A skill blocked this way cannot run its load-time shell commands.

## 11. Harness integration

- **Claude Code**: command hooks registered by `setup` (or the marketplace plugin): `PreToolUse` for Bash, PowerShell, Write, Edit, MultiEdit, NotebookEdit, and Skill; `PostToolUse`; `SessionStart`; `ConfigChange` (skills); `UserPromptExpansion`. Deny goes to the model with the findings and an instruction not to work around it; ask goes to the user. A pass returns nothing, because an explicit allow would bypass Claude Code's own permission prompts. Each hook keeps its own deadline shorter than the harness timeout, because a timed-out hook lets the call through.
- **Codex**: command hooks in `~/.codex/hooks.json` for `SessionStart`, `PreToolUse` and `PostToolUse` (shell and `apply_patch`), and `UserPromptSubmit`. Codex has no ask, so a warning becomes a deny that tells the agent to ask the user. Codex skips new hooks until the user trusts them in `/hooks`.
- **OpenCode**: a plugin (`tool.execute.before` throws to block, `tool.execute.after` reconciles, `command.execute.before` blocks flagged slash commands).
- **Pi**: an extension (`tool_call` blocks or confirms, `user_bash` for `!cmd`, `input` for `/skill:name`, `before_agent_start` hides flagged skills, `session_start` audits).

`setup` copies a self-contained runtime to `~/.skill-scanner/bin` and points every hook at it with an absolute Node path, so hooks never depend on `npx`, a network, or `PATH`.

## 12. State

Everything lives under `~/.skill-scanner` (override with `SKILL_SCANNER_HOME`): `config.json`, `trust.json` (approved digests), `flagged.json` (skills to block at use time), `cache/` (scan results by digest), `quarantine/` (skills moved aside, restorable), `bin/` (the pinned runtime), `decisions.jsonl` (hook decisions). Deleting the directory and running `skill-scanner setup --uninstall` removes every trace.

## 13. Privacy

Offline by default. Fetching a remote source to scan it uses git or npm with the user's own credentials, exactly as the install would. The judge, when enabled, receives the skill's text files only, redacted, and never over the size budget; the API key is read from the environment and sent only to the provider's HTTPS endpoint, and redirects are refused so the key cannot be forwarded. External analyzers run locally; osv-scanner and registry semgrep rules contact their services, and are marked as networked in `doctor`.

## 14. Decisions log

- **D-001 TypeScript on Node 22, zero runtime dependencies.** The ecosystem installs skills with `npx`; a scanner that needs Python or Docker will not be in that path. Bun for development and tests, as in the author's other tools.
- **D-002 Static rules own the verdict.** A model can be argued with by the content it reads (Trail of Bits bypassed LLM judges with rhetorical injection). Rules cannot.
- **D-003 jev asked with `choice`, never `noul`.** See section 8. Monotonic application; oversize skipped, not truncated.
- **D-004 Findings, not blind spots, for what cannot be read.** Truncation, archives that cannot be opened, bytecode, binaries, and padding are reported.
- **D-005 Region- and role-aware rules.** The same `curl | sh` means different things in a README, a warning sentence, a `SKILL.md` code block, and a script. Code blocks in `SKILL.md` are not discounted.
- **D-006 Correlation only on evidence.** Low-confidence matches do not feed correlations; tool configs such as kubeconfig do not count as credential reads for correlation.
- **D-007 Configuration never from the target.** No implicit project config file; `--config` is explicit.
- **D-008 `npx skills` gated by substitution, not reimplementation.** `skill-scanner add` scans a mirror and lets the real CLI install from it via git `insteadOf`, so discovery, selection, symlinks, and lock files stay the CLI's own and record the original source. `SKILLS_DOWNLOAD_URL` is pointed at a dead address so the snapshot fast path for some owners falls back to git.
- **D-009 A git `post-checkout` hook as the universal backstop.** Passed through `GIT_CONFIG_*` environment variables, it scans every checkout made by the wrapped command, including the child processes `skills update` spawns, and aborts the checkout on a block.
- **D-010 Hooks call an absolute runtime path.** Avoids `npx` latency on every tool call, `PATH` differences between terminals and apps, and name collisions (Cisco's Python tool also installs a `skill-scanner` command).
- **D-011 Pass returns nothing.** Returning an explicit allow from a Claude Code hook would skip the user's permission prompts. A rewrite through `guard` is returned as `updatedInput` alone, which Claude Code evaluates against the user's permission rules like any other command.
- **D-012 Quarantine moves, never deletes.** Blocked skills found after install are moved to `~/.skill-scanner/quarantine` with a record of where they came from, and can be restored.
- **D-013 Trust is per digest.** Approving a skill approves those exact bytes; any change flags it again.
- **D-014 Self-scan in CI.** The scanner's own source and build must pass its own rules, so rule descriptions are written without live attack strings.
- **D-015 An install that tampers with its own guard is refused, and `guard` checks that it was not.** An install command that also sets or clears `GIT_CONFIG_*`, `core.hooksPath`, URL rewrites, `SKILLS_DOWNLOAD_URL`, or skill-scanner's own variables is denied instead of being wrapped. The check runs on the words the shell will see after quote removal, recursing into `sh -c`, `eval`, and substitutions (`GIT_CONFIG_COU''NT` is `GIT_CONFIG_COUNT` to a shell), and refuses names computed at run time. Because shell text can always hide something from a parser, `guard` also verifies afterwards that an install which must clone produced a scanned checkout; if none went through the hook, it reports the install as refused and points to `audit`.
- **D-019 Unchecked writes into skill folders are refused.** A write cannot ask, so when the pre-write scan errors or times out the write is denied unless `hooks.onError` is `allow`.
- **D-016 `npx skills` is judged on what it installs.** The skills CLI copies skill folders only, so for its installs (pre-scan, `add`, and the post-checkout hook under `guard`) the verdict comes from skill bundles; the rest of the repository is reported but does not decide. Collection-limit notes are kept so padding cannot hide a skill. `pi install`, plugin installs, and plain clones are judged on everything, because they run package scripts and hooks.
- **D-017 Judge confirmation raises confidence one step.** A finding its context demoted can be restored, but a model cannot move anything further than one step.
- **D-018 External tools cannot be switched off by the skill.** Analyzers run with pinned or empty configuration and with ignore files, inline suppressions, and default skip lists disabled, because a skill can ship `.gitleaks.toml`, `.semgrepignore`, or `osv-scanner.toml` of its own. Such files are also reported (`packaging/scanner-suppression-file`).

## 15. Known gaps and risks

- Static analysis does not understand intent. A skill that tells an agent, in ordinary words, to do something harmful that matches no pattern will pass unless the judge flags it. Benchmarks of static skill scanners report recall well below half on semantic injection sets.
- Regex-based shell understanding can be evaded with constructions the tokenizer does not model (variables assembled at run time, `eval` of computed strings). The decoders and the post-install audit reduce, not remove, this gap.
- There is no hook for `/plugin install` inside Claude Code or for skills synced from claude.ai; those are caught by the session-start audit and blocked at use time, after they are on disk.
- Harness flags that disable hooks or plugins (`--bare`, `disableAllHooks`, `OPENCODE_PURE`, `pi -ne`) disable the scanner too. The agent itself can edit its hook configuration unless the harness's permissions prevent it.
- The trusted-installer list (vendor install scripts piped to a shell are reported at medium rather than critical) is a judgment call that needs maintenance.
- The git backstop sees checkouts only. Updates that move an existing checkout without one (`git pull`, `git reset`, `pi update`) are not scanned until the next audit. A `reference-transaction` hook could close this.
- gitleaks honors a `.gitleaksignore` at the scan root and has no flag to disable it; the file is reported, not neutralised.
- Scans run by the git hook have file and byte limits but no time limit, and our own clones have a time limit but no size cap.
- Codex runs hooks only after the user trusts them in `/hooks`, and Codex and OpenCode cannot ask, so a warning there becomes a deny with instructions.
- Rules were calibrated against the corpora in `docs/evaluation.md`; other ecosystems will surface new false positives.
- Hook deadlines are cooperative. A rule regular expression that backtracked catastrophically on hostile input would block the event loop past the harness timeout, and Claude Code lets a timed-out call through. Rules use bounded quantifiers and were stress-tested without finding one; the planned fix is to run install-time scans in a worker thread that can be terminated on the deadline.
- `codex plugin add <plugin>@<marketplace>` is not pre-scanned; the marketplace was scanned when it was added (`codex plugin marketplace add`), and installed plugins are audited at session start.

## 16. References

- Agent Skills specification: https://agentskills.io/specification
- Claude Code hooks, skills, plugins: https://code.claude.com/docs/en/hooks, https://code.claude.com/docs/en/skills, https://code.claude.com/docs/en/plugins-reference
- Codex hooks and skills: https://developers.openai.com/codex/hooks, https://developers.openai.com/codex/skills
- OpenCode plugins: https://opencode.ai/docs/plugins; Pi extensions: https://github.com/earendil-works/pi
- Vercel skills CLI: https://github.com/vercel-labs/skills
- Cisco AI Defense skill-scanner, measured results: https://github.com/cisco-ai-defense/skill-scanner
- NVIDIA SkillSpector: https://github.com/NVIDIA/skillspector
- Trail of Bits, "The sorry state of skill distribution" (2026-06-03)
- Unicode tag smuggling: https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/; variation-selector smuggling: https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/
- Trojan Source (CVE-2021-42574); Claude Code project-file RCE (CVE-2025-59536)
- OWASP Top 10 for Agentic Applications 2026
