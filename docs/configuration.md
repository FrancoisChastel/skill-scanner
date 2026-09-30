# Configuration

skill-scanner works with no configuration. When you want one, it lives at `~/.skill-scanner/config.json`, or in any file you pass with `--config`. Unknown keys are errors, so a typo never silently falls back to a default. The JSON Schema is [schema/config.schema.json](../schema/config.schema.json); add `"$schema": "https://raw.githubusercontent.com/FrancoisChastel/skill-scanner/main/schema/config.schema.json"` for editor completion.

skill-scanner never reads configuration from the directory it scans. There is no project config file on purpose: a skill must not be able to ship its own allowlist. For a team, commit a config file and pass it explicitly (`skill-scanner scan --config .github/skill-scanner.json`).

## Keys

| Key | Default | Meaning |
|---|---|---|
| `blockAt` | `"high"` | Block when any finding's effective severity reaches this. Effective severity is the severity, one level lower when the finding's confidence is low. |
| `warnAt` | `"medium"` | Warn when any finding's effective severity reaches this. |
| `ignore` | `[]` | Findings to drop before the verdict (see below). |
| `hooks.onWarn` | `"ask"` | What hooks and plugins do when an install scans as warn: `ask` the user (Codex and OpenCode cannot ask, so they deny and tell the agent to ask you), `allow`, or `deny`. |
| `hooks.onError` | `"ask"` | What they do when the scan itself fails, for example when the source cannot be fetched. |
| `hooks.quarantine` | `true` | Move skills found blocked after install to `~/.skill-scanner/quarantine`. With `false` they are flagged and blocked at use time but left in place. |
| `judge.enabled` | `false` | Ask the jev judge for a second opinion on every scan (also `--judge`). Sends redacted skill text to the provider. |
| `judge.provider` | from the key | `typesafe`, `openrouter`, or `vercel`. By default the key's prefix decides. |
| `judge.model` | provider default | jev model id override. |
| `judge.baseUrl` | provider default | HTTPS endpoint override (plain HTTP only for `localhost`). Used only with a key issued by the same provider. |
| `judge.timeoutMs` | `15000` | Per-request timeout. |
| `analyzers.<name>` | `false` | Run an external analyzer when it is installed: `skillspector`, `cisco`, `gitleaks`, `osv-scanner`, `semgrep`. `--with` adds more for one run. |
| `semgrepConfig` | `p/default` | Semgrep or opengrep `--config`. A local file keeps the scan offline. |

## Suppressing findings

```json
{
  "ignore": [
    { "rule": "network/suspicious-endpoint", "path": "notify-slack/**", "reason": "posts to our team webhook" },
    { "rule": "privilege/*", "path": "infra-tools/scripts/**" },
    { "rule": "exec/download-and-run", "digest": "sha256:<64 hex>", "reason": "reviewed 2026-09-30" }
  ]
}
```

- `rule`: a rule id, a category wildcard such as `privilege/*`, or `*`.
- `path`: a glob over finding paths as reports print them (`*` within a folder, `**` across folders).
- `digest`: only for this exact content of the skill, as `--format json` reports it (`bundles[].digest`). Any change to the skill brings the finding back.
- `reason`: for the next person who reads the file.

To approve a whole skill you reviewed, `skill-scanner trust <path>` is usually simpler: it records the skill's digest in `~/.skill-scanner/trust.json`, and the install and use-time gates let that exact content through.

## Environment variables

| Variable | Meaning |
|---|---|
| `SKILL_SCANNER_HOME` | State directory, default `~/.skill-scanner` |
| `SKILL_SCANNER_CONFIG` | Config file, default `$SKILL_SCANNER_HOME/config.json` |
| `SKILL_SCANNER_SKILLS_CLI` | Command `add` runs for the skills CLI, default `npx -y skills@1` |
| `TYPESAFE_API_KEY`, `OPENROUTER_API_KEY`, `AI_GATEWAY_API_KEY` | Keys for the optional judge; the prefix (`ts_`, `sk-or-`, `vck_`) picks the provider |
| `SKILL_SCANNER_JEV_KEY` | A judge key that takes precedence over the three above |
| `NO_COLOR`, `FORCE_COLOR` | Terminal colors |
| `SKILL_SCANNER_DEBUG` | Print stack traces on errors |

Harness locations follow each harness's own variables: `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_CONFIG_HOME`, `OPENCODE_CONFIG_DIR`, `PI_CODING_AGENT_DIR`.

## Files skill-scanner keeps

Everything is under `~/.skill-scanner`:

| Path | Content |
|---|---|
| `config.json` | Your configuration |
| `trust.json` | Digests you approved with `trust` |
| `flagged.json` | Installed skills currently flagged; hooks and plugins read it to block use |
| `cache/` | Scan results by content digest |
| `quarantine/` | Skills moved aside, each with a record of where it came from |
| `bin/` | The runtime `setup` installed for hooks |
| `decisions.jsonl` | One line per hook or plugin decision |
