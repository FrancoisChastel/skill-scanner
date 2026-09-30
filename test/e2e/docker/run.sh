#!/bin/bash
# End-to-end tests of @french-castle/skill-scanner as installed from a tarball or from npm, run
# inside a throwaway container (see Dockerfile and scripts/e2e-docker.sh). Prints PASS, FAIL, or
# SKIP per check and exits 1 when any check fails.
set -u
cd "$HOME"
T="$HOME/tests"
SS="$HOME/.npm-global/bin/skill-scanner"
PKG="$(npm root -g)/@french-castle/skill-scanner"
VERSION="${SKILL_SCANNER_VERSION:?set by the Dockerfile}"
SPEC="$(cat "$HOME/pkg/SPEC")"
PASS=0 FAIL=0 SKIP=0
FAILED=()

ok() { echo "PASS  $1"; PASS=$((PASS + 1)); }
ko() { echo "FAIL  $1 -- $2"; FAIL=$((FAIL + 1)); FAILED+=("$1"); }
skip() { echo "SKIP  $1 -- $2"; SKIP=$((SKIP + 1)); }
section() { echo; echo "== $1"; }
# check <name> <condition-command...>
check() { local n=$1; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else ko "$n" "condition failed: $*"; fi; }
# run <cmd...>: sets OUT (stdout+stderr), CODE
run() { OUT=$("$@" 2>&1); CODE=$?; }
expect_code() { local n=$1 want=$2; shift 2; run "$@"; if [ "$CODE" -eq "$want" ]; then ok "$n"; else ko "$n" "exit $CODE, want $want: $(echo "$OUT" | tail -4 | tr '\n' ' ')"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }

git config --global user.email t@example.com
git config --global user.name tester
git config --global init.defaultBranch main
python3 "$T/fixtures.py" >/dev/null
MAL="file://$HOME/repos/mal-repo"
GOOD="file://$HOME/repos/benign-repo"

section "A. install ($SPEC)"
run "$SS" --version; [ "$OUT" = "$VERSION" ] && ok "global install reports $VERSION" || ko "global install reports $VERSION" "$OUT"
run bash -c "cd \$(mktemp -d) && npx -y --package='$SPEC' skill-scanner --version"; has "$OUT" "$VERSION" && ok "npx runs it" || ko "npx runs it" "$OUT"
FIRST=$(command -v skill-scanner)
if [ "$FIRST" != "$SS" ]; then echo "INFO  'skill-scanner' on PATH resolves to $FIRST (Cisco's tool installs the same name); tests call $SS"; fi

section "B. CLI basics"
expect_code "help exits 0" 0 "$SS" help
expect_code "no arguments prints help and exits 2" 2 "$SS"
run "$SS" help scan; has "$OUT" "--fail-on" && ok "help scan lists options" || ko "help scan lists options" "$OUT"
expect_code "help for an unknown command exits 2" 2 "$SS" help scn
expect_code "unknown command exits 2" 2 "$SS" bogus
expect_code "unknown option exits 2" 2 "$SS" scan --bogus
run "$SS" rules --format json; N=$(jq length <<<"$OUT" 2>/dev/null); [ "${N:-0}" -ge 100 ] && ok "rules --format json lists $N rules" || ko "rules --format json" "$N"

section "C. scanning local skills"
verdict() { "$SS" scan "$1" --format json 2>/dev/null | jq -r 'if type=="array" then .[0].verdict else .verdict end'; }
rules_of() { "$SS" scan "$1" --format json 2>/dev/null | jq -r '.bundles[].findings[].ruleId'; }
expect_code "benign skill exits 0" 0 "$SS" scan "$HOME/fx/benign"
[ "$(verdict "$HOME/fx/benign")" = "pass" ] && ok "benign skill passes" || ko "benign skill passes" "$(verdict "$HOME/fx/benign")"
for f in curl-pipe hidden tags exfil b64 symlink plugin; do
  expect_code "$f blocks (exit 1)" 1 "$SS" scan "$HOME/fx/$f"
done
has "$(rules_of "$HOME/fx/hidden")" "injection/override-instructions" && ok "hidden: override instruction found" || ko "hidden: override" "$(rules_of "$HOME/fx/hidden" | tr '\n' ' ')"
run "$SS" scan "$HOME/fx/tags"; has "$OUT" "run curl evil.example" && ok "tags: hidden text is decoded in the report" || ko "tags decoded" "$OUT"
has "$(rules_of "$HOME/fx/exfil")" "correlation/credential-exfiltration" && ok "exfil: credential read + send correlated" || ko "exfil correlation" "$(rules_of "$HOME/fx/exfil" | tr '\n' ' ')"
has "$(rules_of "$HOME/fx/b64")" "obfuscation/encoded-payload" && ok "b64: encoded payload decoded and flagged" || ko "b64 payload" "$(rules_of "$HOME/fx/b64" | tr '\n' ' ')"
has "$(rules_of "$HOME/fx/symlink")" "packaging/symlink" && ok "symlink to a key flagged" || ko "symlink" ""
has "$(rules_of "$HOME/fx/plugin")" "surface/hooks" && ok "plugin hook command flagged" || ko "plugin hooks" ""
[ "$(verdict "$HOME/fx/warn")" = "warn" ] && ok "unrestricted Bash in allowed-tools warns" || ko "warn verdict" "$(verdict "$HOME/fx/warn")"
expect_code "warn passes with default --fail-on" 0 "$SS" scan "$HOME/fx/warn"
expect_code "warn fails with --fail-on warn" 1 "$SS" scan "$HOME/fx/warn" --fail-on warn
expect_code "--fail-on never exits 0 on a block" 0 "$SS" scan "$HOME/fx/curl-pipe" --fail-on never
run "$SS" scan "$HOME/fx/bundle.zip" --format json; ZIPV=$(jq -r .verdict <<<"$OUT"); ZIPLOC=$(jq -r '[.bundles[].findings[].location.file] | join(" ")' <<<"$OUT")
[ "$ZIPV" = "block" ] && has "$ZIPLOC" '!/' && ok "zip archive opened and its script blocked" || ko "zip archive" "$ZIPV $ZIPLOC"
KEY=$(cat "$HOME/fx-secret-key.txt"); LEAK=0
for fmt in text json sarif markdown; do "$SS" scan "$HOME/fx/secret" --format "$fmt" 2>&1 | grep -qF "$KEY" && LEAK=1; done
[ $LEAK -eq 0 ] && ok "embedded key redacted in text, json, sarif, markdown" || ko "secret redaction" "raw key printed"
has "$(rules_of "$HOME/fx/secret")" "secrets/embedded-credential" && ok "embedded key detected" || ko "secret detected" ""
run "$SS" scan "$HOME/fx/hidden" --format sarif --fail-on never
[ "$(jq -r .version <<<"$OUT")" = "2.1.0" ] && [ "$(jq '.runs[0].results | length' <<<"$OUT")" -gt 0 ] && ok "SARIF 2.1.0 with results" || ko "sarif" "$(head -c 200 <<<"$OUT")"
run "$SS" scan "$HOME/fx/hidden" --format markdown --fail-on never; has "$OUT" "| " && ok "markdown table" || ko "markdown" ""
run "$SS" scan "$HOME/fx/hidden" --format json --output /tmp/r.json --fail-on never
[ -s /tmp/r.json ] && jq -e .verdict /tmp/r.json >/dev/null && has "$OUT" "report written" && ok "--output writes the file and a summary line" || ko "--output" "$OUT"
run "$SS" scan "$HOME/fx/hidden" --quiet; [ -z "$OUT" ] && [ "$CODE" -eq 1 ] && ok "--quiet prints nothing, keeps the exit code" || ko "--quiet" "$CODE $OUT"
run "$SS" scan "$HOME/fx/benign" "$HOME/fx/hidden" --format json --fail-on never; [ "$(jq length <<<"$OUT")" = "2" ] && ok "two targets give a JSON array" || ko "multi-target json" ""

section "D. remote sources"
run "$SS" scan anthropics/skills --fail-on never --format json
if [ "$CODE" -eq 0 ]; then ok "scan anthropics/skills from GitHub ($(jq -r .verdict <<<"$OUT"), $(jq '.bundles|length' <<<"$OUT") bundles)"; else ko "scan anthropics/skills" "$(tail -3 <<<"$OUT")"; fi
run "$SS" scan "npm:@french-castle/jev-code" --fail-on never; [ "$CODE" -eq 0 ] && ok "scan an npm package source" || ko "scan npm:" "$(tail -3 <<<"$OUT")"
expect_code "scan a local git repo URL that is malicious" 1 "$SS" scan "$MAL"

section "E. add (gated npx skills add)"
expect_code "add refuses a malicious repo" 1 "$SS" add "$MAL" -y -a claude-code -g
[ ! -e "$HOME/.claude/skills/evil" ] && ok "nothing installed after the refusal" || ko "refused install left files" "$(ls -la "$HOME/.claude/skills")"
expect_code "add installs a benign repo" 0 "$SS" add "$GOOD" -y -a claude-code -g
[ -f "$HOME/.claude/skills/tidy/SKILL.md" ] && ok "benign skill landed in ~/.claude/skills" || ko "benign install" "$(ls -la "$HOME/.claude/skills" "$HOME/.agents/skills" 2>&1)"
run "$SS" add anthropics/skills --skill pdf -y -a claude-code -g
if [ "$CODE" -eq 0 ] && [ -f "$HOME/.claude/skills/pdf/SKILL.md" ]; then ok "add anthropics/skills --skill pdf installs from GitHub"; else ko "add anthropics pdf" "$(tail -4 <<<"$OUT")"; fi
LOCK="$HOME/.agents/.skill-lock.json"; [ -f "$LOCK" ] && jq -e '.skills.pdf.source == "anthropics/skills"' "$LOCK" >/dev/null && ok "global lock records the original source" || ko "lock source" "$(cat "$LOCK" 2>/dev/null | head -c 300)"
run "$SS" add anthropics/skills --skill xlsx --dry-run; has "$OUT" "GIT_CONFIG_COUNT" && has "$OUT" "SKILLS_DOWNLOAD_URL" && ok "add --dry-run prints the guarded command" || ko "add --dry-run" "$(tail -3 <<<"$OUT")"

section "F. guard (git post-checkout backstop)"
expect_code "guard refuses cloning a malicious repo" 1 "$SS" guard git clone -q "$MAL" /tmp/g1
expect_code "guard allows cloning a benign repo" 0 "$SS" guard git clone -q "$GOOD" /tmp/g2
expect_code "quote-split tamper is caught" 1 "$SS" guard -- sh -c "export GIT_CONFIG_COU''NT=0; git clone -q $MAL /tmp/g3"
echo "unset GIT_CONFIG_COUNT" >/tmp/clear.env
expect_code "a guard switched off from a sourced file is reported" 1 "$SS" guard -- sh -c ". /tmp/clear.env; git clone -q $MAL /tmp/g4"
expect_code "guard npx skills update" 0 "$SS" guard npx skills update -g -y

section "G. setup into the real harness installs"
for h in claude codex opencode pi; do command -v "$h" >/dev/null && ok "$h is installed in the image" || ko "$h installed" "missing"; done
run "$SS" setup --dry-run; has "$OUT" "Claude Code" && has "$OUT" "Codex" && has "$OUT" "OpenCode" && has "$OUT" "Pi" && ok "setup --dry-run plans all four harnesses" || ko "setup dry-run" "$(head -20 <<<"$OUT")"
[ ! -e "$HOME/.skill-scanner/bin" ] && ok "dry run changed nothing" || ko "dry run wrote files" ""
expect_code "setup --yes" 0 "$SS" setup --yes
has "$OUT" "hook claude-code allows a harmless command" && has "$OUT" "scan blocks a malicious test skill" && ok "setup canaries ran" || ko "canaries" "$(tail -8 <<<"$OUT")"
RT="$HOME/.skill-scanner/bin/skill-scanner.mjs"
[ -x "$RT" ] && ok "runtime installed at ~/.skill-scanner/bin" || ko "runtime" ""
jq -e '[.hooks.PreToolUse[].hooks[].command | select(test("skill-scanner.mjs"))] | length == 1' "$HOME/.claude/settings.json" >/dev/null && ok "Claude Code settings.json has the hooks" || ko "claude settings" "$(cat "$HOME/.claude/settings.json" 2>&1 | head -c 400)"
jq -e '.hooks.PreToolUse[0].hooks[0].command | test("hook codex")' "$HOME/.codex/hooks.json" >/dev/null && ok "Codex hooks.json written" || ko "codex hooks" ""
[ -f "$HOME/.config/opencode/plugins/skill-scanner.js" ] && ok "OpenCode plugin shim written" || ko "opencode shim" ""
[ -f "$HOME/.pi/agent/extensions/skill-scanner.js" ] && ok "Pi extension shim written" || ko "pi shim" ""
run "$SS" setup --yes; jq -e '[.hooks.PreToolUse[].hooks[].command | select(test("skill-scanner.mjs"))] | length == 1' "$HOME/.claude/settings.json" >/dev/null && ok "re-running setup changes nothing" || ko "idempotent setup" "$(tail -3 <<<"$OUT")"
expect_code "doctor passes" 0 "$SS" doctor
run "$SS" doctor --json; jq -e . <<<"$OUT" >/dev/null && ok "doctor --json is valid JSON" || ko "doctor json" ""
if claude plugin validate --help >/dev/null 2>&1; then
  expect_code "Claude Code validates the marketplace plugin" 0 claude plugin validate "$PKG/plugins/claude-code"
else skip "claude plugin validate" "command not available in this Claude Code version"; fi

section "H. hooks with realistic payloads"
hook() { printf '%s' "$2" | node "$RT" hook "$1"; }
cc_pre() { jq -nc --arg c "$1" --arg cwd "$HOME" '{hook_event_name:"PreToolUse",session_id:"s",cwd:$cwd,permission_mode:"default",tool_name:"Bash",tool_input:{command:$c,description:"install",timeout:120000},tool_use_id:"t"}'; }
run hook claude-code "$(cc_pre 'ls -la')"; [ -z "$OUT" ] && [ "$CODE" -eq 0 ] && ok "Claude: ordinary command gets no output" || ko "claude ordinary" "$OUT"
run hook claude-code "$(cc_pre "npx skills add $MAL -y")"; [ "$(jq -r .hookSpecificOutput.permissionDecision <<<"$OUT")" = "deny" ] && ok "Claude: malicious install denied" || ko "claude deny" "$OUT"
run hook claude-code "$(cc_pre "npx skills add $GOOD -y")"
jq -e '.hookSpecificOutput.updatedInput.command | test("guard --")' <<<"$OUT" >/dev/null && jq -e '.hookSpecificOutput.updatedInput.description == "install" and (.hookSpecificOutput | has("permissionDecision") | not)' <<<"$OUT" >/dev/null && ok "Claude: benign install rewritten through guard, other fields kept, no explicit allow" || ko "claude rewrite" "$OUT"
run hook claude-code "$(cc_pre "export GIT_CONFIG_COU''NT=0; npx skills update")"; [ "$(jq -r .hookSpecificOutput.permissionDecision <<<"$OUT")" = "deny" ] && ok "Claude: tampering install denied" || ko "claude tamper" "$OUT"
BAD_MD=$(cat "$HOME/fx/hidden/SKILL.md")
W=$(jq -nc --arg p "$HOME/.claude/skills/newone/SKILL.md" --arg c "$BAD_MD" --arg cwd "$HOME" '{hook_event_name:"PreToolUse",session_id:"s",cwd:$cwd,tool_name:"Write",tool_input:{file_path:$p,content:$c},tool_use_id:"w"}')
run hook claude-code "$W"; [ "$(jq -r .hookSpecificOutput.permissionDecision <<<"$OUT")" = "deny" ] && ok "Claude: writing a malicious SKILL.md denied" || ko "claude write" "$OUT"
cp -r "$HOME/fx/hidden" "$HOME/.claude/skills/dropped"
run hook claude-code "$(jq -nc --arg cwd "$HOME" '{hook_event_name:"SessionStart",session_id:"s",cwd:$cwd,source:"startup"}')"
has "$OUT" "dropped" && ok "Claude: session start reports the dropped malicious skill" || ko "session start" "$OUT"
[ ! -e "$HOME/.claude/skills/dropped" ] && ok "Claude: it was quarantined" || ko "quarantine" "still present"
jq -e '.hookSpecificOutput.reloadSkills == true' <<<"$OUT" >/dev/null && ok "Claude: asks Claude Code to reload skills" || ko "reloadSkills" "$OUT"
run hook claude-code "$(jq -nc --arg cwd "$HOME" '{hook_event_name:"PreToolUse",session_id:"s",cwd:$cwd,tool_name:"Skill",tool_input:{skill:"dropped"},tool_use_id:"k"}')"
[ "$(jq -r .hookSpecificOutput.permissionDecision <<<"$OUT")" = "deny" ] && ok "Claude: using the flagged skill is denied" || ko "skill tool" "$OUT"
run hook claude-code "$(jq -nc --arg cwd "$HOME" '{hook_event_name:"UserPromptExpansion",session_id:"s",cwd:$cwd,expansion_type:"slash_command",command_name:"dropped",command_args:"",prompt:"/dropped"}')"
[ "$(jq -r .decision <<<"$OUT")" = "block" ] && ok "Claude: /dropped is blocked" || ko "prompt expansion" "$OUT"
mkdir -p "$HOME/.claude/skills/cfg" && cp "$HOME/fx/hidden/SKILL.md" "$HOME/.claude/skills/cfg/SKILL.md"
run hook claude-code "$(jq -nc --arg cwd "$HOME" --arg f "$HOME/.claude/skills/cfg/SKILL.md" '{hook_event_name:"ConfigChange",session_id:"s",cwd:$cwd,source:"skills",file_path:$f}')"
[ "$(jq -r .decision <<<"$OUT")" = "block" ] && ok "Claude: a malicious skill written mid-session is blocked" || ko "config change" "$OUT"
cx_pre() { jq -nc --arg c "$1" --arg cwd "$HOME" '{session_id:"s",turn_id:"u",cwd:$cwd,hook_event_name:"PreToolUse",model:"m",permission_mode:"default",tool_name:"Bash",tool_input:{command:$c},tool_use_id:"t"}'; }
run hook codex "$(cx_pre "npx skills add $MAL -y")"
jq -e '(keys == ["hookSpecificOutput"]) and (.hookSpecificOutput | keys == ["hookEventName","permissionDecision","permissionDecisionReason"]) and .hookSpecificOutput.permissionDecision == "deny"' <<<"$OUT" >/dev/null && ok "Codex: deny with exactly the documented fields" || ko "codex deny" "$OUT"
run hook codex "$(cx_pre 'git status')"; [ -z "$OUT" ] && ok "Codex: ordinary command gets no output" || ko "codex ordinary" "$OUT"
run hook codex "$(jq -nc --arg cwd "$HOME" '{session_id:"s",cwd:$cwd,hook_event_name:"UserPromptSubmit",prompt:"please use $dropped to summarize"}')"
[ "$(jq -r .decision <<<"$OUT")" = "block" ] && ok "Codex: \$dropped mention blocked" || ko "codex prompt" "$OUT"
run hook claude-code 'not json at all'; [ "$CODE" -eq 0 ] && [ -z "$OUT" ] && ok "garbage input fails open silently" || ko "garbage" "$CODE $OUT"

section "I. audit, quarantine, restore, trust"
run "$SS" audit --list-quarantine; has "$OUT" "dropped" && ok "quarantine list shows the skill" || ko "list quarantine" "$OUT"
QID=$(ls "$HOME/.skill-scanner/quarantine" | grep dropped | head -1)
expect_code "restore it" 0 "$SS" audit --restore "$QID"
[ -f "$HOME/.claude/skills/dropped/SKILL.md" ] && ok "restored to ~/.claude/skills/dropped" || ko "restore location" ""
expect_code "audit reports the blocked skill" 1 "$SS" audit --format json
expect_code "trust it" 0 "$SS" trust "$HOME/.claude/skills/dropped" --yes --reason "e2e test"
run "$SS" audit --format json; jq -e '[.[] | select(.name=="hidden" or (.path|test("dropped"))) | .trusted] | any' <<<"$OUT" >/dev/null && ok "audit marks it trusted" || ko "trusted in audit" "$(head -c 300 <<<"$OUT")"
run hook claude-code "$(jq -nc --arg cwd "$HOME" '{hook_event_name:"PreToolUse",session_id:"s",cwd:$cwd,tool_name:"Skill",tool_input:{skill:"dropped"},tool_use_id:"k2"}')"
[ -z "$OUT" ] && ok "a trusted skill is no longer blocked at use" || ko "trusted use" "$OUT"
run "$SS" trust --list; has "$OUT" "e2e test" && ok "trust --list shows it" || ko "trust list" "$OUT"
expect_code "trust --remove" 0 "$SS" trust --remove hidden
run "$SS" audit --quarantine; [ ! -e "$HOME/.claude/skills/dropped" ] && ok "audit --quarantine moves blocked skills aside" || ko "audit quarantine" "$(tail -3 <<<"$OUT")"

section "J. OpenCode plugin and Pi extension, as published and as installed by setup"
run node "$T/adapters.mjs" "$PKG" "$MAL" "$GOOD" "$HOME/.config/opencode/plugins/skill-scanner.js" "$HOME/.pi/agent/extensions/skill-scanner.js"
if jq -e . <<<"$(tail -1 <<<"$OUT")" >/dev/null 2>&1; then
  while IFS=$'\t' read -r okv name detail; do [ "$okv" = "true" ] && ok "$name" || ko "$name" "$detail"; done < <(tail -1 <<<"$OUT" | jq -r '.[] | [.ok, .name, .detail] | @tsv')
else ko "adapter harness" "$(tail -5 <<<"$OUT")"; fi

section "K. jev judge against a local mock endpoint"
JH=/tmp/judgehome; mkdir -p "$JH"
echo '{"judge":{"enabled":true,"provider":"typesafe","baseUrl":"http://localhost:8787"}}' >"$JH/config.json"
MOCK_LOG=/tmp/jev.jsonl node "$T/mock-jev.mjs" >/tmp/mock.log 2>&1 & MOCK=$!
sleep 1
FAKEKEY="ts_e2e_$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
run env SKILL_SCANNER_HOME="$JH" TYPESAFE_API_KEY="$FAKEKEY" "$SS" scan "$HOME/fx/secret" "$HOME/fx/hidden" --format json --fail-on never
jq -e '[.[].analyzers[] | select(.status=="ran")] | length > 0' <<<"$OUT" >/dev/null && ok "judge ran against the endpoint" || ko "judge ran" "$(jq -c '[.[].analyzers]' <<<"$OUT" 2>/dev/null || tail -3 <<<"$OUT")"
jq -e '[.[].bundles[].findings[] | select(.judge != null)] | length > 0' <<<"$OUT" >/dev/null && ok "findings carry judge notes" || ko "judge notes" ""
[ -s /tmp/jev.jsonl ] && jq -e -s 'all(.[]; (.body.questions | length) == 8 and all(.body.questions[]; .type == "choice"))' /tmp/jev.jsonl >/dev/null && ok "8 choice questions per request, no noul" || ko "question shape" "$(head -c 300 /tmp/jev.jsonl)"
jq -e -s 'all(.[]; .hasAuth and .authScheme == "Bearer")' /tmp/jev.jsonl >/dev/null && ok "key sent as a bearer token" || ko "auth header" ""
grep -qF "$KEY" /tmp/jev.jsonl && ko "skill secret redacted before sending" "raw key reached the judge" || ok "skill secret redacted before sending"
grep -qF "$FAKEKEY" <<<"$OUT" && ko "API key never printed" "key in output" || ok "API key never printed"
: >/tmp/jev.jsonl
run env SKILL_SCANNER_HOME="$JH" TYPESAFE_API_KEY="$FAKEKEY" "$SS" scan "$HOME/fx/hidden" --no-judge --fail-on never
[ ! -s /tmp/jev.jsonl ] && ok "--no-judge sends nothing" || ko "--no-judge" "request sent"
run env SKILL_SCANNER_HOME=/tmp/nokeyhome "$SS" scan "$HOME/fx/benign" --judge; [ "$CODE" -eq 0 ] && has "$OUT" "key" && ok "--judge without a key warns and scans offline" || ko "judge without key" "$CODE $(tail -2 <<<"$OUT")"
kill $MOCK 2>/dev/null

section "L. external analyzers"
for a in gitleaks osv-scanner skillspector cisco semgrep; do
  bin=$a; [ "$a" = "cisco" ] && bin=skill-scanner
  if [ "$a" = "cisco" ] && ! ls "$HOME/.local/bin/skill-scanner" >/dev/null 2>&1; then skip "analyzer cisco" "not installed in the image"; continue; fi
  if [ "$a" != "cisco" ] && ! command -v "$bin" >/dev/null; then skip "analyzer $a" "not installed in the image"; continue; fi
  run "$SS" scan "$HOME/fx/secret" --with "$a" --format json --fail-on never
  ST=$(jq -r --arg a "$a" '.analyzers[] | select(.name|test($a;"i")) | .status' <<<"$OUT" 2>/dev/null | head -1)
  DET=$(jq -r --arg a "$a" '.analyzers[] | select(.name|test($a;"i")) | .detail // ""' <<<"$OUT" 2>/dev/null | head -1)
  NF=$(jq -r --arg a "$a" '[.bundles[].findings[] | select(.source|test($a;"i"))] | length' <<<"$OUT" 2>/dev/null)
  [ "$ST" = "ran" ] && ok "analyzer $a ran ($NF findings)" || ko "analyzer $a" "status=$ST $DET $(tail -2 <<<"$OUT")"
done
run "$SS" scan "$HOME/fx/secret" --with auto --format json --fail-on never; ok "--with auto ran: $(jq -r '[.analyzers[] | "\(.name)=\(.status)"] | join(", ")' <<<"$OUT" 2>/dev/null)"

section "M. library and TypeScript types"
P=$(mktemp -d); cd "$P" && npm init -y >/dev/null && npm install --silent "$SPEC" @types/node@22 >/dev/null 2>&1
cat >consumer.mts <<'TS'
import { scanPath, type Finding, type ScanReport } from "@french-castle/skill-scanner";
const report: ScanReport = await scanPath(process.argv[2] ?? ".");
const findings: Finding[] = report.bundles.flatMap((b) => b.findings);
// @ts-expect-error the verdict is a string union
const wrong: number = report.verdict;
console.log(report.verdict, findings.length, wrong === undefined);
TS
echo '{"compilerOptions":{"module":"NodeNext","moduleResolution":"NodeNext","target":"ES2022","strict":true,"noEmit":true,"types":["node"]},"include":["consumer.mts"]}' >tsconfig.json
run tsc -p .; [ "$CODE" -eq 0 ] && ok "types resolve under NodeNext" || ko "NodeNext types" "$OUT"
run node --input-type=module -e "const { scanPath } = await import('@french-castle/skill-scanner'); const r = await scanPath('$HOME/fx/hidden'); console.log(r.verdict)"; [ "$OUT" = "block" ] && ok "library scanPath works at run time" || ko "library runtime" "$OUT"
cd "$HOME"

section "N. uninstall"
expect_code "setup --uninstall" 0 "$SS" setup --uninstall --yes
jq -e '[.hooks // {} | .. | objects | select(.command? // "" | test("skill-scanner"))] | length == 0' "$HOME/.claude/settings.json" >/dev/null && ok "Claude Code hooks removed" || ko "claude uninstall" "$(cat "$HOME/.claude/settings.json")"
[ ! -e "$HOME/.config/opencode/plugins/skill-scanner.js" ] && [ ! -e "$HOME/.pi/agent/extensions/skill-scanner.js" ] && ok "plugin and extension removed" || ko "shims removed" ""
expect_code "doctor now reports the missing install" 1 "$SS" doctor
expect_code "setup --uninstall --purge" 0 "$SS" setup --uninstall --purge --yes
[ ! -e "$HOME/.skill-scanner" ] && ok "state directory purged" || ko "purge" "$(ls "$HOME/.skill-scanner")"

echo
echo "== summary: $PASS passed, $FAIL failed, $SKIP skipped"
for f in "${FAILED[@]}"; do echo "   failed: $f"; done
[ "$FAIL" -eq 0 ]
