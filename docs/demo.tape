# The README demo (docs/demo.gif): scan a malicious skill, gate Claude Code with `setup`, then hand
# the installed hook the tool call an agent makes to install that skill, the way Claude Code does.
#
# Render it with scripts/demo-gif.sh: VHS runs in Docker, in an image that provides skill-scanner,
# jq, an empty ~/.claude for setup to find, and the demo skills in /demo. Nothing runs on the host.
Output demo.gif

Require skill-scanner
Require jq

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set LetterSpacing 0
Set LineHeight 1.1
Set Width 1040
Set Height 840
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set CursorBlink false
Set TypingSpeed 40ms

Hide
Type "cd /demo && clear"
Enter
Show

# 1. A manual scan of a skill that hides instructions in an HTML comment and pipes curl into bash.
Sleep 1s
Type "skill-scanner scan ./notes-summarizer"
Sleep 500ms
Enter
Wait
Sleep 7s

Hide
Type "clear"
Enter
Show

# 2. Gate Claude Code: setup finds ~/.claude and merges its hooks into ~/.claude/settings.json.
Type "skill-scanner setup --yes"
Sleep 500ms
Enter
Wait
Sleep 5s

Hide
Type "clear"
Enter
Show

# 3. The agent tries to install the skill. Before the Bash call runs, Claude Code pipes it as JSON
#    to the PreToolUse hook, using the exact command setup wrote into ~/.claude/settings.json.
#    fold only rewraps the long reason lines at spaces for the recording.
Type@25ms "# Claude Code runs this hook from ~/.claude/settings.json before every Bash call:"
Enter
Sleep 500ms
Type@15ms `echo '{"hook_event_name":"PreToolUse","tool_name":"Bash",`
Enter
Type@15ms `  "tool_input":{"command":"npx skills add ./notes-summarizer -y"}}' |`
Enter
Type@15ms `  "/usr/local/bin/node" "/root/.skill-scanner/bin/skill-scanner.mjs" hook claude-code |`
Enter
Type@15ms "  jq -r '.hookSpecificOutput[]' | fold -sw 100"
Sleep 500ms
Enter
Wait
Sleep 8s
