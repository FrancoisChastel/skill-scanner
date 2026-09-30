import { patternRule } from "../core/pattern-rule";
import type { FileRule } from "../core/rule";
import { lineText, positionAt } from "../core/text";

/** Persistence, tampering with agent configuration, destructive commands, and privilege changes. */

/** The rest of a path token up to the target, so the target must be the file being written. */
const PATH_PREFIX = String.raw`["']?[^\s"';|&<>()]*`;

/**
 * A write to `target`: shell redirect, tee, cp/mv/rsync/install/ln destination, sed -i, a
 * file-write call, or `open(..., "w")`. Reads and mere mentions do not match.
 */
function writeTo(target: string): RegExp {
  const t = `(?:${target})`;
  return new RegExp(
    [
      String.raw`[\s\d&]>>?\s*${PATH_PREFIX}${t}`,
      String.raw`\btee\s+(?:-a\s+)?${PATH_PREFIX}${t}`,
      String.raw`\b(?:cp|mv|rsync|ln)\s+(?:-\S+\s+)*(?:\S+\s+){1,6}?${PATH_PREFIX}${t}`,
      String.raw`\binstall\s+(?:-\S+\s+)+(?:\S+\s+){1,6}?${PATH_PREFIX}${t}`,
      String.raw`\bsed\s+-i\S*\s+(?:'[^'\n]*'|"[^"\n]*"|\S+)\s+${PATH_PREFIX}${t}`,
      String.raw`\b(?:write|append)File(?:Sync)?\s*\(\s*[^,)\n]{0,120}?${t}`,
      String.raw`\b(?:Out-File|Add-Content|Set-Content)\s+(?:-\w+\s+)*${PATH_PREFIX}${t}`,
      String.raw`\bopen\s*\(\s*[^,)\n]{0,120}?${t}[^,)\n]{0,20},\s*["'](?:w|a|x|r\+)`,
      String.raw`${t}[^\n]{0,40}?\)\s*\.(?:write_text|write_bytes|open\s*\(\s*["'][wax])`,
    ].join("|"),
    "gi",
  );
}

/** A line hint accepting any line that mentions one of the targets; the write patterns only run there. */
const mentions = (...sources: string[]): RegExp => new RegExp(sources.join("|"), "i");

const SHELL_PROFILES = String.raw`(?:\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zprofile|\.zshenv|\.zlogin|(?:^|[\s"'/~])\.profile\b|config\.fish|\/etc\/profile|\/etc\/bash\.bashrc|\/etc\/zsh\/|\$PROFILE\b|Microsoft\.PowerShell_profile\.ps1)`;
const AUTHORIZED_KEYS = String.raw`authorized_keys2?\b`;
const GIT_HOOKS_DIR = String.raw`\.git\/hooks\/`;
const AGENT_CONFIG = String.raw`(?:\.claude\/(?:settings(?:\.local)?\.json|hooks\b|plugins\/|agents\/)|\.claude\.json\b|\.codex\/(?:config\.toml|hooks\.json)|\bopencode\.jsonc?\b|\.opencode\/plugins?\/|\.config\/opencode\/|\.pi\/agent\/(?:settings\.json|extensions)|\.pi\/extensions\/|\.gemini\/settings\.json|\.cursor\/(?:mcp\.json|rules)|\.mcp\.json\b|\.vscode\/(?:settings|tasks|mcp)\.json|\.openclaw\/)`;
const AGENT_CONFIG_KEYS = String.raw`\b(?:enableAllProjectMcpServers|apiKeyHelper|awsAuthRefresh|otelHeadersHelper|disableAllHooks)\b`;
const INSTRUCTION_FILES = String.raw`(?:CLAUDE|AGENTS|GEMINI|MEMORY|SOUL)\.md\b|\.cursorrules\b|\.windsurfrules\b|copilot-instructions\.md\b|\.clinerules\b`;
const SKILL_DIRS = String.raw`(?:\.claude|\.agents|\.codex|\.pi\/agent|\.pi|\.opencode|\.config\/opencode|\.gemini)\/skills?\/`;

export const persistenceRules: readonly FileRule[] = [
  patternRule({
    id: "persistence/scheduled-task",
    title: "Installs something that runs on a schedule or at login",
    category: "persistence",
    severity: "high",
    confidence: "medium",
    description:
      "Creates a cron job, launchd agent, systemd unit, Windows scheduled task, or Run key, so code keeps running after the agent session ends.",
    remediation: "Install only if the skill's purpose is to set up a background service and you want that service.",
    patterns: [
      // `crontab file`, `crontab -`, `... | crontab -`: installing a table. `crontab -l` only lists it.
      /\bcrontab[ \t]+(?:-u[ \t]+\S+[ \t]+)?(?:-[ \t]*$|-[ \t]*<|[~$./\w"'-]*[./~$][\w./~${}"'-]*[ \t]*$)|\|[ \t]*crontab[ \t]+-(?:[ \t]|$)/gm,
      writeTo(
        String.raw`\/etc\/cron(?:tab|\.d|\.daily|\.hourly|\.weekly)|\/var\/spool\/cron|Library\/Launch(?:Agents|Daemons)\/|\.config\/systemd\/user\/|\/etc\/systemd\/system\/|\/etc\/rc\.local\b|\/etc\/init\.d\/`,
      ),
      /\blaunchctl\s+(?:load|bootstrap|submit|enable|kickstart)\b/g,
      /\bsystemctl\s+(?:--user\s+)?(?:enable|link)\b/g,
      /\bschtasks(?:\.exe)?\s+\/create\b|\bRegister-ScheduledTask\b/gi,
      /\bNew-Service\s+-/g,
      // Writing a Run key; reading one (forensics, `reg query`) is not persistence.
      /\b(?:reg(?:\.exe)?\s+add|New-ItemProperty|Set-ItemProperty|SetValueEx)\b[^\n]{0,160}\\CurrentVersion\\Run(?:Once)?\b/gi,
      /\bat\s+now\s*\+/g,
    ],
    prefilter:
      /crontab|cron|Launch(?:Agents|Daemons)|launchctl|systemd|systemctl|schtasks|ScheduledTask|New-Service|CurrentVersion|rc\.local|init\.d|\bat\s+now/i,
    regions: { prose: "lower-confidence" },
    roles: { readme: "lower-confidence" },
    // Enabling a service that is already installed is ordinary setup for a daemon the skill is about.
    adjust: (m) =>
      /^(?:systemctl|launchctl\s+(?:enable|kickstart))/i.test(m[0])
        ? { severity: "medium", message: `\`${m[0].trim()}\` makes an installed service start at boot or login` }
        : undefined,
  }),
  patternRule({
    id: "persistence/shell-profile",
    title: "Modifies shell startup files",
    category: "persistence",
    severity: "high",
    confidence: "medium",
    description:
      "Writes to `.bashrc`, `.zshrc`, `.profile`, or a PowerShell profile, so its code runs in every future shell, including ones the agent opens.",
    patterns: [writeTo(SHELL_PROFILES)],
    lineHint: mentions(SHELL_PROFILES),
    regions: { prose: "lower-confidence", "inline-code": "lower-confidence" },
    roles: { readme: "lower-confidence" },
    adjust: (m, ctx) => {
      const line = lineText(ctx.index, positionAt(ctx.index, m.index).line);
      // Appending an environment variable or PATH entry is ordinary setup; code and aliases are not.
      return /\becho\s+["']?(?:export\s+[A-Z_][A-Z0-9_]*=|fpath=|path\+=)(?:[^;&|`$(]|\$(?!\())*["']?\s*>>/i.test(line) &&
        !/\$\(|`|\beval\b|\bcurl\b|\bwget\b|\balias\b/.test(line)
        ? { severity: "low", message: "Appends an environment variable to a shell startup file" }
        : undefined;
    },
  }),
  patternRule({
    id: "persistence/ssh-authorized-keys",
    title: "Adds an SSH key to authorized_keys",
    category: "persistence",
    severity: "critical",
    confidence: "high",
    hard: true,
    description: "Appends a key to `authorized_keys`, giving whoever holds the private key permanent remote login.",
    remediation: "Do not install.",
    patterns: [writeTo(AUTHORIZED_KEYS), /\bssh-copy-id\b[^\n]{0,80}\s-i\s/g],
    lineHint: mentions(AUTHORIZED_KEYS, "ssh-copy-id"),
  }),
  patternRule({
    id: "persistence/git-hooks",
    title: "Installs git hooks or rewires git",
    category: "persistence",
    severity: "medium",
    confidence: "medium",
    description:
      "Writes git hooks, changes `core.hooksPath`, credential helpers, `core.sshCommand`, or `url.*.insteadOf`. Git then runs attacker code or sends credentials elsewhere on every commit or fetch.",
    patterns: [
      writeTo(GIT_HOOKS_DIR),
      /\bgit\s+config\s+(?:--(?:global|system|local)\s+)?(?:core\.hooksPath|core\.sshCommand|credential\.helper|core\.fsmonitor|url\.[^\s]+\.insteadOf|core\.gitProxy|http\.proxy)\b/gi,
    ],
    lineHint: mentions(GIT_HOOKS_DIR, String.raw`\bgit\s+config\b`),
    roles: { readme: "lower-confidence" },
  }),
  patternRule({
    id: "persistence/agent-config-tampering",
    title: "Changes an AI agent's settings, hooks, or MCP servers",
    category: "persistence",
    severity: "medium",
    confidence: "medium",
    description:
      "Writes to Claude Code, Codex, OpenCode, Pi, Gemini, or Cursor settings, hooks, plugins, extensions, or MCP configuration, or registers MCP servers from the shell. This is how a skill gives itself permanent, automatic execution or disables safeguards (see CVE-2025-59536).",
    remediation: "Do not install unless configuring the agent is the skill's stated purpose. Review every hook and MCP server it adds.",
    patterns: [writeTo(AGENT_CONFIG), new RegExp(AGENT_CONFIG_KEYS, "g")],
    lineHint: mentions(AGENT_CONFIG, AGENT_CONFIG_KEYS),
    // The setting names matter where they configure something (a shipped settings file, a config snippet), not in
    // code that merely knows the names, such as a bundle embedding Claude Code's settings schema.
    ignoreMatch: (m, ctx) => new RegExp(AGENT_CONFIG_KEYS).test(m[0]) && m[0].length < 40 && ctx.file.kind === "script",
    regions: { prose: "lower-confidence", "inline-code": "lower-confidence" },
    roles: { readme: "lower-confidence", code: "raise" },
  }),
  patternRule({
    id: "persistence/agent-extension-install",
    title: "Installs agent plugins or MCP servers",
    category: "execution-surface",
    severity: "low",
    confidence: "high",
    description:
      "Registers an MCP server or installs a plugin or package into an agent (the mcp add and plugin install commands of Claude Code, Codex, and Gemini, or a Pi package install). Whatever it installs runs with the agent's access, so review it separately.",
    patterns: [
      // Commands are lowercase; "OpenCode plugin" in a sentence is not a command.
      /\b(?:claude|codex|gemini|cursor-agent)\s+mcp\s+add(?:-json)?\b|\bclaude\s+(?:config\s+set|plugins?\s+(?:install|i|marketplace\s+add))\b|\bcodex\s+plugin\s+(?:add|marketplace\s+add)\b|\bopencode\s+plugins?\s+(?:add|install)\b|\bpi\s+install\s+(?:npm|git|https?):/g,
    ],
    // Usage text in a CLI names these commands as often as code runs them; the finding is informational either way.
    roles: { readme: "lower-confidence" },
    maxHitsPerFile: 3,
  }),
  patternRule({
    id: "persistence/instruction-file-tampering",
    title: "Writes to the agent's standing instructions",
    category: "persistence",
    severity: "medium",
    confidence: "medium",
    description:
      "Writes to `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, Cursor or Copilot rule files, or agent memory files. Text placed there is obeyed in every future session, long after the skill is gone.",
    patterns: [writeTo(INSTRUCTION_FILES)],
    lineHint: mentions(INSTRUCTION_FILES),
    regions: { prose: "lower-confidence", "inline-code": "lower-confidence" },
    roles: { readme: "lower-confidence", code: "raise" },
  }),
  patternRule({
    id: "persistence/skill-propagation",
    title: "Writes into skill directories",
    category: "persistence",
    severity: "medium",
    confidence: "low",
    description:
      "Copies or writes files into an agent's skills directory. Skill-authoring tools do this legitimately; a skill that installs other skills can also spread or re-install itself.",
    patterns: [writeTo(SKILL_DIRS)],
    lineHint: mentions(SKILL_DIRS),
    regions: { prose: "skip", "inline-code": "lower-confidence" },
    roles: { readme: "skip" },
  }),
];

export const destructiveRules: readonly FileRule[] = [
  patternRule({
    id: "destructive/delete-root-or-home",
    title: "Deletes the root filesystem or home directory",
    category: "destructive",
    severity: "critical",
    confidence: "high",
    hard: true,
    description: "Recursively deletes `/`, `~`, `$HOME`, or a top-level system directory.",
    remediation: "Do not install.",
    patterns: [
      /\brm\s+(?:-[a-zA-Z]+\s+|--[a-z-]+\s+)*(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\s+(?:-[a-zA-Z]+\s+|--[a-z-]+\s+)*["']?(?:\/|\/\*|~\/?\*?|\$HOME\/?\*?|\$\{HOME\}\/?\*?|\/(?:etc|usr|bin|sbin|lib|var|opt|boot|System|Library|Users|home|Applications)\/?\*?)["']?(?=\s|$|;|&|\|)/gm,
      /\brm\s+[^\n]{0,40}--no-preserve-root\b/g,
      /\b(?:Remove-Item|rm|ri|del)\s+[^\n]{0,60}-Recurse[^\n]{0,60}(?:C:\\(?:\*|\s|$|Windows|Users)|\$env:USERPROFILE\\?\s|\$HOME\\?\s|~\\?\s)/gi,
      /\brd\s+\/s\s+\/q\s+[a-z]:\\(?:\s|$|windows|users)/gi,
      /\bshutil\.rmtree\s*\(\s*(?:["']\/["']|["']~["']|os\.path\.expanduser\s*\(\s*["']~["']\s*\)|Path\.home\(\)|os\.environ\[["']HOME["']\])\s*[,)]/g,
      /\b(?:fs\.)?rm(?:Sync)?\s*\(\s*(?:["']\/["']|os\.homedir\(\)|process\.env\.HOME)\s*,\s*\{[^}]*recursive\s*:\s*true/g,
    ],
  }),
  patternRule({
    id: "destructive/unguarded-variable-delete",
    title: "Recursive delete of a path built from a variable",
    category: "destructive",
    severity: "medium",
    confidence: "medium",
    description:
      "A recursive delete of everything under a path built from a variable removes from the root or home directory when the variable is empty. Guard the variable with `:?` so the command fails instead.",
    patterns: [/\brm\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)*["']?\$\{?[A-Za-z_]\w*\}?["']?\/["']?(?:\*|\s|$)/gm],
    kinds: ["script", "skill-md", "markdown"],
    ignoreMatch: (m) => /\$\{\w+:[?-]/.test(m[0]),
  }),
  patternRule({
    id: "destructive/disk-wipe",
    title: "Wipes disks, backups, or boot recovery",
    category: "destructive",
    severity: "critical",
    confidence: "high",
    hard: true,
    description: "Formats or overwrites block devices, erases disks, deletes volume shadow copies, disables recovery, or runs a fork bomb.",
    remediation: "Do not install.",
    patterns: [
      /\bmkfs(?:\.\w+)?\s+(?:-\S+\s+)*\/dev\/|\bdd\s+[^\n]{0,120}\bof=\/dev\/(?:sd|hd|nvme|disk|rdisk|mmcblk|xvd|vd)\w*/g,
      /\bdiskutil\s+(?:eraseDisk|eraseVolume|zeroDisk|randomDisk|secureErase|partitionDisk|apfs\s+deleteContainer)\b|\bwipefs\s+-a\b|\bshred\s+[^\n]{0,60}\/dev\/(?!null\b|zero\b|stdout\b|stderr\b|tty\b|u?random\b|fd\/)/g,
      /\bcipher\s+\/w:|\bvssadmin\s+delete\s+shadows\b|\bwmic\s+shadowcopy\s+delete\b|\bbcdedit\s+\/set\s+[^\n]{0,40}recoveryenabled\s+no\b/gi,
      // `format c: /q`, not "## Format A: Full" headings.
      /(?<=^|[\s;&|])(?:format|FORMAT)(?:\.com)?\s+[A-Za-z]:(?=\s*(?:\/[A-Za-z]|$))/gm,
      /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/g,
    ],
  }),
  patternRule({
    id: "destructive/recursive-permission-change",
    title: "Recursively opens up or takes over the filesystem",
    category: "destructive",
    severity: "high",
    confidence: "high",
    description: "`chmod -R 777 /` or `chown -R` on the root or home breaks the system's permission model.",
    patterns: [/\bch(?:mod|own)\s+(?:-\w+\s+)*-[a-zA-Z]*R[a-zA-Z]*\s+(?:\S+\s+)?["']?(?:\/|~|\$HOME)["']?(?=\s|$|;)/gm],
  }),
  patternRule({
    id: "destructive/force-push",
    title: "Force-pushes git history",
    category: "destructive",
    severity: "low",
    confidence: "medium",
    description: "`git push --force` overwrites remote history; `--force-with-lease` is the safer form.",
    patterns: [
      /\bgit\s+push\s+(?:[^\n;&|]*\s)?(?:--force(?!-with-lease|-if-includes)|-f)(?=\s|$)/gm,
      /\bgit\s+push\s+[^\n;&|]*\s\+[\w/-]+/g,
    ],
    kinds: ["script", "skill-md", "markdown"],
  }),
];

export const privilegeRules: readonly FileRule[] = [
  patternRule({
    id: "privilege/sudo",
    title: "Runs commands as root",
    category: "privilege",
    severity: "medium",
    confidence: "medium",
    description: "Uses `sudo` or `doas`. An agent running root commands can change anything on the machine; a skill should rarely need it.",
    patterns: [/(?<=^|[\s;&|(`$])(?:sudo|doas)\s+(?!-[lvkK]\b|--(?:list|validate|version|help)\b)\S/gm],
    kinds: ["script", "skill-md", "markdown"],
    regions: { prose: "skip" },
    roles: { readme: "lower-confidence" },
    maxHitsPerFile: 2,
  }),
  patternRule({
    id: "privilege/sudo-password",
    title: "Feeds a password to sudo, or edits sudoers",
    category: "privilege",
    severity: "high",
    confidence: "high",
    description:
      "Pipes a password into sudo's standard input, adds passwordless entries to the sudoers file, or otherwise edits sudoers, giving code root without asking.",
    patterns: [/\becho\s+[^\n|]{1,80}\|\s*sudo\s+-S\b|\bsudo\s+-S\b[^\n]{0,40}<<<|\bNOPASSWD\s*:|\/etc\/sudoers(?:\.d)?\b|\bvisudo\b/g],
  }),
  patternRule({
    id: "privilege/setuid",
    title: "Sets setuid bits or file capabilities",
    category: "privilege",
    severity: "high",
    confidence: "high",
    description: "`chmod u+s`, `chmod 4755`, or `setcap` let a program run with elevated privileges for every user.",
    patterns: [/\bchmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwx]*s[rwx]*|0?[2467][0-7]{3})\s/g, /\bsetcap\s+\S*cap_/g],
  }),
  patternRule({
    id: "privilege/world-writable",
    title: "Makes files world-writable",
    category: "privilege",
    severity: "low",
    confidence: "medium",
    description: "`chmod 777` lets any user or process modify the file.",
    patterns: [/\bchmod\s+(?:-\w+\s+)*(?:0?777|a\+rwx|o\+w)\s/g],
    kinds: ["script", "skill-md", "markdown"],
  }),
  patternRule({
    id: "privilege/admin-prompt",
    title: "Requests administrator rights through the GUI",
    category: "privilege",
    severity: "high",
    confidence: "medium",
    description:
      "Prompts the user for administrator rights on the skill's behalf, through AppleScript's administrator-privileges option, PowerShell's RunAs verb, or the Windows runas command.",
    patterns: [/\bwith\s+administrator\s+privileges\b|\bStart-Process\b[^\n]{0,120}-Verb\s+RunAs\b|\brunas\s+\/user:/gi],
  }),
  patternRule({
    id: "privilege/disable-security-controls",
    title: "Disables operating system security controls",
    category: "privilege",
    severity: "critical",
    confidence: "high",
    hard: true,
    description: "Turns off Gatekeeper, SIP, SELinux, Windows Defender, the firewall, or macOS quarantine for all downloads.",
    remediation: "Do not install.",
    patterns: [
      /\bspctl\s+--master-disable\b|\bspctl\s+--global-disable\b|\bcsrutil\s+disable\b|\bsetenforce\s+0\b|\bSet-MpPreference\b[^\n]{0,80}-Disable\w*\s+\$?true|\bAdd-MpPreference\b[^\n]{0,40}-ExclusionPath\b/gi,
      /\bufw\s+disable\b|\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off\b|\bdefaults\s+write\s+com\.apple\.LaunchServices\s+LSQuarantine\s+-bool\s+(?:NO|false)\b|\bsystemctl\s+(?:stop|disable)\s+(?:apparmor|auditd|firewalld)\b/gi,
    ],
    // `setenforce 0` lasts until reboot, a common diagnostic step; the others change the system for good.
    adjust: (m) =>
      /^setenforce/i.test(m[0])
        ? { severity: "high", confidence: "medium", message: "Switches SELinux to permissive mode until the next reboot" }
        : undefined,
  }),
];
