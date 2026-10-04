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
| `judge.enabled` | `"auto"` | `"auto"`: the jev judge reviews every scan, install hook, and audit once a jev key is set (`SKILL_SCANNER_JEV_KEY` or `TYPESAFE_API_KEY`, or the key of the host `judge.provider` names); without one, scans stay offline with no error. `true` (also `--judge`): also use a general gateway key (`OPENROUTER_API_KEY`, `AI_GATEWAY_API_KEY`), and warn when there is no key at all. `false` (also `--no-judge`): never. The judge sends redacted skill text to the provider; in install hooks a request is capped at 10 s with one retry, and a slow or failing judge leaves the rules' verdict. |
| `judge.provider` | from the key | `typesafe`, `openrouter`, or `vercel` are picked from the key's prefix. `cloudflare` (Workers AI, model `typesafe/jev`), `ollama` (a local decision model such as `nimble`, no key), and `custom` (any host that speaks TypeSafe's System One protocol) must be named here; they are supported but not exercised by the test suite. |
| `judge.model` | provider default | Model id override. |
| `judge.baseUrl` | provider default | HTTPS endpoint override (plain HTTP only for `localhost`). Used only with a key issued by the same provider. Required for `custom`: the full endpoint. |
| `judge.accountId` | `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account id for `cloudflare`. |
| `judge.timeoutMs` | `15000` | Per-request timeout. |
| `analyzers.<name>` | `gitleaks`: `true`, others `false` | Run an external analyzer with every scan, install hook, and audit when it is installed: `skillspector`, `cisco`, `gitleaks`, `osv-scanner`, `semgrep`. gitleaks is on by default and skipped quietly until it is installed. `--with` adds more for one run. |
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
| `TYPESAFE_API_KEY` | The jev key: with it, the judge runs by default |
| `OPENROUTER_API_KEY`, `AI_GATEWAY_API_KEY` | Gateway keys the judge uses only when `judge.enabled` is `true` (or `--judge`) or `judge.provider` names the host; the prefix (`ts_`, `sk-or-`, `vck_`) picks the provider |
| `SKILL_SCANNER_JEV_KEY` | A jev key that takes precedence over the others, and turns the judge on by default like `TYPESAFE_API_KEY`; with `judge.provider` set to `cloudflare` or `custom`, any key |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | Workers AI token and account for `judge.provider: "cloudflare"` |
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
