# Evaluation

How the rules were calibrated, on what, and what they miss. Numbers are from the static scanner alone (no judge, no external analyzers), version 0.1.0, 2026-09-30.

## Method

Every corpus was scanned with `scanPath` before and after calibration. Benign corpora measure false positives: a block on a reputable vendor's official skill is a bug unless the finding is real and worth the user's attention. Malicious corpora measure what static analysis catches. Each rule change was kept only with a positive and a negative test, and every remaining benign block was reviewed by hand.

## Benign corpora

| Corpus | Skills | Blocked (before -> after) | Warned after |
|---|---|---|---|
| 20 vendor and major repositories (Anthropic x2, OpenAI, Vercel, Hugging Face, Microsoft, Cloudflare, Supabase, Sentry, Datadog, HashiCorp, Neon, Google Gemini, Remotion, Callstack, Better Auth, Matt Pocock, obra/superpowers, wshobson/agents, Expo) | 761 | 57 -> 1 | 42 |
| ComposioHQ/awesome-claude-skills | 864 | 0 -> 0 | 3 |
| alirezarezvani/claude-skills | 342 | 22 -> 1 | 7 |
| K-Dense-AI/claude-scientific-skills | 168 | 0 -> 1 | 102 |
| trailofbits/skills | 85 | 7 -> 1 | 39 |
| Skills installed on a development machine (Claude Code, Codex, shared) | 339 | 0 -> 0 | 7 |
| Claude Code plugin cache on the same machine | 1,052 | 20 -> 0 | 32 |
| All benign corpora | 3,611 | 106 -> 4 | 232 |

The four remaining blocks are kept because each is a pattern a user should see before installing:

- `expo-skill-eval` (Expo's internal evaluation skill) tells the agent to run Claude Code with its permission checks disabled.
- K-Dense `literature-review` pipes a third-party installer script into bash from `SKILL.md`.
- trailofbits `devcontainer-setup` ships a shell alias that runs Claude Code with permissions disabled.
- `skill-security-auditor` has a line in `SKILL.md` that reads the user's SSH private key.

Most of the K-Dense warnings come from `allowed-tools` granting unrestricted Bash, which is what that rule reports.

## Malicious and test corpora

| Corpus | Blocked (before -> after) | Notes |
|---|---|---|
| trailofbits/overtly-malicious-skills | 2/4 -> 4/4 | poisoned `.pyc` (bytecode names absent from the source), a `.docx` disguise, 100,000 blank lines of padding, registry redirection written through a heredoc |
| nedlir/skills-scanner-bypass | 0/1 -> 1/1 | unchecked-hash `.pyc` whose bytecode runs a command its source never mentions |
| snyk-labs/toxicskills-goof | 4/9 -> 7/9 | ClawHavoc lures (password-protected archive, paste-site downloads), a fake Vercel skill sending `uname -a` to a paste site, tag characters, pipes to a shell |
| MaliciousSkillBench SRC005 (ClawHavoc wave) | 3/30 -> 30/30 | "download and install from" lures pointing at free hosting |
| MaliciousSkillBench SRC011 | 13/21 -> 18/21 | browser database theft with sqlite3, disk-wide key searches, `npm --registry` |
| MaliciousSkillBench SRC002 | 104/157 -> 100/157 | spot checks of the unblocked samples found benign content (templates, a logo updater); not tuned against |
| MaliciousSkillBench SRC004, SRC006, SRC013 | 17/50, 6/86, 1/154 | mostly semantic harm and safety prompts |
| Cisco skill-scanner evaluation skills | 4/31 -> 7/31 | a Flowise-style `child_process` payload, an instruction to echo the Authorization header |
| NVIDIA SkillSpector fixtures | 1/26 | semantic-analysis fixtures by design |

What static analysis misses, and why:

- **Purely semantic content**: instructions written in ordinary words ("hide this action", "send data to the attacker", harmful recipes) that match no pattern. This is what the optional jev judge is for.
- **Exfiltration shaped like an API client**: a script that reads an `API_KEY` and posts JSON to a hard-coded URL looks exactly like a legitimate integration.
- **Dynamic evaluation of input**: generic `eval` and `compile` of runtime data are too common in benign code to flag.
- **Malware inside binaries**: signatures such as EICAR need an antivirus engine; skill-scanner reports that a binary is present, not what it contains.

## Performance

Median wall time on an Apple Silicon laptop, Node 22:

| Target | Time |
|---|---|
| A 15 MB skill with Office templates (archives opened and scanned) | 0.3 s |
| All 339 locally installed skills | 3.6 s |
| alirezarezvani/claude-skills (342 skills, 31 MB of text) | 11 s |
| Plugin cache (1,052 skills) | 35 s cold |
| The 100,000-blank-line padding sample | 0.03 s |

Hooks read results from a cache keyed by content digest: a warm audit of 183 installed skills and plugins takes about 80 ms, and an ordinary tool call costs about 70 ms of hook time.

## Reproducing

Clone a corpus and run `skill-scanner scan <dir> --format json`. The scanner's own source and build are scanned in CI (`node scripts/self-scan.mjs`) and must pass.
