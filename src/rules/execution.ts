import { contextualize } from "../core/context";
import { patternRule } from "../core/pattern-rule";
import type { FileContext, FileRule } from "../core/rule";
import { lineText, positionAt } from "../core/text";
import type { Confidence, Severity } from "../core/types";
import { alignsWithSkill, hostOf, hostTier, isDemoHost, isTrustedInstaller, PLACEHOLDER_URL_RE, SUSPICIOUS_ENDPOINTS } from "./lists";

/**
 * Remote and hidden code execution. Fenced code in SKILL.md is what the agent runs, so these
 * rules do not discount code regions; only READMEs, which agents rarely load, are discounted.
 */

const URL_RE = /https?:\/\/[^\s"'`)|;&<>]+/i;

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Whether text marks `file` executable or runs it: chmod +x, an interpreter given the file, or the
 * file in command position with a path (`./x`, `/tmp/x`). Passing it as an argument (`git apply x`,
 * `tar xf x`) does not count.
 */
function runsFile(text: string, file: string): boolean {
  const f = escapeRe(file);
  return new RegExp(
    [
      `\\bchmod\\s+(?:-\\w+\\s+)*(?:[ugoa]*\\+[rw]*x\\w*|[0-7]*[1357][0-7]{0,2})\\s+\\S*${f}`,
      `(?:^|[;&|(]|\\b(?:then|do|sudo|exec|nohup|time|env))\\s*["']?(?:\\.\\/|\\/\\S*\\/|~\\/\\S*\\/|\\$\\{?\\w+\\}?\\/)\\S*${f}(?:["'\\s]|$|;|&)`,
      `\\b(?:ba|z|k|da)?sh\\s+(?:-\\w+\\s+)*["']?\\S*${f}\\b`,
      `\\b(?:python[0-9.]*|node|perl|ruby|bun|deno\\s+run)\\s+(?:-\\w+\\s+)*["']?\\S*${f}\\b`,
      `\\bStart-Process\\s+\\S*${f}`,
    ].join("|"),
    "m",
  ).test(text);
}

type HostClass = "hostile" | "unknown" | "vendor" | "illustration" | "variable";

const HOSTILE_ENDPOINTS = SUSPICIOUS_ENDPOINTS.filter((c) => c.kind !== "chat-webhook").map((c) => new RegExp(c.re.source, "i"));

/**
 * Where a download comes from. Hostile: plain HTTP, a raw IP, a paste site, tunnel, or shortener.
 * Vendor: a curated installer or the vendor the skill is named after. Illustration: a placeholder
 * or a parked example domain. Variable: the URL is only known at run time.
 */
function classifyDownload(matched: string, ctx: FileContext): { cls: HostClass; url?: string } {
  const url = URL_RE.exec(matched)?.[0];
  if (!url) return { cls: /\$\{?[A-Za-z_]/.test(matched) ? "variable" : "unknown" };
  const host = hostOf(url);
  if (isDemoHost(host) || PLACEHOLDER_URL_RE.test(url)) return { cls: "illustration", url };
  if (/^http:\/\//i.test(url) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || HOSTILE_ENDPOINTS.some((re) => re.test(url)))
    return { cls: "hostile", url };
  if (isTrustedInstaller(url) || alignsWithSkill(url, [ctx.bundle.name, ctx.bundle.dirName])) return { cls: "vendor", url };
  return { cls: "unknown", url };
}

/** Commands that run with nobody reading them: hooks, MCP launchers, package scripts, load-time shell. */
const runsUnattended = (ctx: FileContext): boolean => ctx.file.virtualOf !== undefined;

/**
 * The severity of running a download, by where it comes from and who runs it. Unattended commands
 * and hostile hosts are critical everywhere; a vendor's own installer in documentation is a warning.
 */
function gradeDownload(cls: HostClass, ctx: FileContext): { severity: Severity; confidence: Confidence } {
  if (cls === "hostile") return { severity: "critical", confidence: "high" };
  if (cls === "illustration") return { severity: "low", confidence: "low" };
  const unattended = runsUnattended(ctx);
  const doc = ctx.file.kind === "skill-md" || ctx.file.kind === "markdown";
  const instructions = ctx.role === "instructions";
  if (cls === "vendor") {
    if (unattended) return { severity: "high", confidence: "medium" };
    return { severity: "medium", confidence: doc && !instructions ? "low" : "medium" };
  }
  if (unattended) return { severity: "critical", confidence: "high" };
  if (doc && !instructions) return { severity: "high", confidence: "low" };
  return { severity: "high", confidence: cls === "variable" ? "medium" : "medium" };
}

const DOWNLOAD_MESSAGES: Readonly<Record<HostClass, (url: string | undefined) => string>> = {
  hostile: (url) => `Runs whatever ${url ?? "the server"} returns, from a host with no business serving installers`,
  unknown: (url) => (url ? `Runs whatever ${url} returns` : "Runs downloaded code without saving it for review"),
  vendor: (url) =>
    `Pipes the installer at ${url} into a shell. It belongs to a known vendor or the one this skill is for, but it still runs unreviewed remote code`,
  illustration: (url) => `Pipes ${url ?? "a placeholder URL"} into a shell in what looks like an example`,
  variable: () => "Runs code downloaded from a URL chosen at run time",
};

export const executionRules: readonly FileRule[] = [
  patternRule({
    id: "exec/download-and-run",
    title: "Downloads code and runs it",
    category: "remote-execution",
    severity: "critical",
    confidence: "high",
    description:
      "Pipes a download straight into an interpreter: curl or wget output piped to a shell, a shell reading a curl process substitution, PowerShell running a downloaded string, Python exec of a URL response. Whatever the server returns at that moment runs with your permissions, and nothing of it is in the skill for review.",
    remediation:
      "Do not install unless the URL is the official installer of a tool you already trust. Prefer a pinned package or a checked-in script with a checksum.",
    patterns: [
      /\b(?:curl|wget|fetch)\b[^\n|;&]{0,300}\|\s*(?:sudo\s+(?:-\S+\s+){0,3})?(?:env\s+\S+\s+)?(?:ba|z|k|da|fi)?sh\b/gi,
      /\b(?:curl|wget)\b[^\n|;&]{0,300}\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php|bun|deno|pwsh|powershell|osascript)\b/gi,
      /\b(?:ba|z|k)?sh\s+<\(\s*(?:curl|wget)\b|\b(?:source|\.)\s+<\(\s*(?:curl|wget)\b/gi,
      /\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)\b|\beval\s+["']?\$\(\s*(?:curl|wget)\b|\beval\s+["']?`\s*(?:curl|wget)\b/gi,
      /\b(?:iex|invoke-expression)\b[^\n]{0,60}\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)\b/gi,
      /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,300}\|\s*(?:iex|invoke-expression)\b/gi,
      /\bexec\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(|\bexec\s*\(\s*requests\.get\s*\(|\bexec\s*\(\s*httpx\.get\s*\(/g,
      /\beval\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?fetch\s*\(|\bnew\s+Function\s*\([^)\n]{0,200}\bfetch\s*\(/g,
    ],
    roles: { readme: "lower-confidence" },
    signal: "download",
    ignoreMatch: (m, ctx) => {
      // In Markdown, `curl | sh` with no URL, variable, or host is an illustration, not an instruction.
      if (ctx.regions !== undefined && !ctx.decoded && !/https?:\/\/|\$\{?\w|\b[\w-]+\.[a-z]{2,}\//i.test(m[0])) return true;
      // `| python3 -c "..."`, `| sh -c '...'`, or `| python3 parse.py -` run a program of their own on the downloaded
      // data; the data is not code.
      if (!/\|\s*(?:sudo\s+(?:-\S+\s+){0,3})?(?:env\s+\S+\s+)?[\w./-]*$/.test(m[0])) return false;
      const rest = ctx.text.slice(m.index + m[0].length, m.index + m[0].length + 200).split("\n", 1)[0] ?? "";
      return /^\s+(?:-[cemEp]\b|--eval\b|(?:-[\w-]+\s+)*[\w./-]+\.(?:py|js|mjs|cjs|ts|rb|pl|php)\b)/.test(rest);
    },
    adjust: (m, ctx) => {
      const { cls, url } = classifyDownload(m[0], ctx);
      return { ...gradeDownload(cls, ctx), message: DOWNLOAD_MESSAGES[cls](url) };
    },
  }),
  {
    id: "exec/download-then-execute",
    title: "Downloads a file, then makes it executable or runs it",
    category: "remote-execution",
    severity: "high",
    confidence: "medium",
    description:
      "Saves a download to disk and then marks it executable or runs it within a few lines. The payload is not part of the skill and cannot be reviewed.",
    scope: "file",
    kinds: ["script", "skill-md", "markdown"],
    check(ctx) {
      const DL =
        /\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n]{0,300}?(?:\s-o\s*|\s-O\s+|--output(?:-document)?[=\s]+|-OutFile\s+)["']?([^\s"'|;&]+)/gi;
      for (const m of ctx.text.matchAll(DL)) {
        if (/^["']?(?:\/dev\/|-$)/.test(m[1]!)) continue;
        const target = m[1]!.split("/").pop() ?? "";
        if (
          target.length < 2 ||
          /\.(?:json|txt|md|csv|tsv|html?|xml|ya?ml|toml|png|jpe?g|gif|svg|webp|pdf|tar|gz|tgz|xz|bz2|zst|7z|zip|diff|patch|dict|c|cc|cpp|h|hpp|rs|go|java|log|sql|db|sqlite|parquet|onnx|bin|pt|safetensors|gguf)$/i.test(
            target,
          )
        )
          continue;
        // The rest of the download's line plus the next five lines.
        const { line } = positionAt(ctx.index, m.index);
        const after = [
          ctx.text.slice(m.index + m[0].length, (ctx.index.starts[line] ?? ctx.text.length + 1) - 1),
          ...[1, 2, 3, 4, 5].map((k) => lineText(ctx.index, line + k)),
        ].join("\n");
        if (!runsFile(after, target)) continue;
        const { cls, url } = classifyDownload(m[0], ctx);
        const base =
          cls === "hostile"
            ? { severity: "critical" as const, confidence: "high" as const }
            : cls === "illustration"
              ? { severity: "low" as const, confidence: "low" as const }
              : cls === "vendor"
                ? { severity: "medium" as const, confidence: "medium" as const }
                : { severity: "high" as const, confidence: "medium" as const };
        const g = contextualize(ctx, m.index, m[0].length, base, { roles: { readme: "lower-confidence" } });
        if (!g) continue;
        if (g.confidence !== "low") ctx.signal("download", m.index, m[0]);
        ctx.report({
          offset: m.index,
          length: m[0].length,
          severity: g.severity,
          confidence: g.confidence,
          message: `Downloads ${url ?? "a file"} to ${target} and then executes it`,
        });
      }
    },
  },
  patternRule({
    id: "exec/decode-and-run",
    title: "Decodes hidden data and runs it",
    category: "obfuscation",
    severity: "critical",
    confidence: "high",
    hard: true,
    description:
      "Runs code that is only readable after decoding: base64 or hex output piped to a shell, JavaScript eval of atob or Buffer.from, Python exec of b64decode, zlib, or marshal, PowerShell's encoded-command switch. There is no benign reason for a skill to hide the code it runs.",
    remediation: "Do not install.",
    patterns: [
      /\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,100}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/gi,
      /\|\s*base64\s+(?:-d|--decode|-D)\s*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/gi,
      /\b(?:xxd\s+-r\s+-p|openssl\s+(?:enc\s+)?(?:-d\s+)?-?base64\s+-d|rev)\b[^\n]{0,80}\|\s*(?:ba|z)?sh\b/gi,
      /\beval\s+["']?\$\([^)\n]{0,200}\bbase64\s+(?:-d|--decode|-D)/gi,
      /\b(?:eval|exec|Function|setTimeout|setInterval)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent\s*\(\s*escape)\s*\(/g,
      /\bexec\s*\(\s*(?:base64\.b64decode|b64decode|base64\.decodebytes|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex|binascii\.(?:unhexlify|a2b_base64)|__import__\s*\(\s*['"](?:base64|zlib|marshal|codecs))/g,
      /\beval\s*\(\s*compile\s*\(|\bexec\s*\(\s*compile\s*\([^)\n]{0,200}(?:b64|decode|decompress)/g,
      /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/gi,
      /\bFromBase64String\s*\([^)\n]{0,300}\)[^\n]{0,120}\b(?:iex|invoke-expression)\b/gi,
    ],
    signal: "exec-dynamic",
  }),
  patternRule({
    id: "exec/packed-javascript",
    title: "Packed or machine-obfuscated JavaScript",
    category: "obfuscation",
    severity: "high",
    confidence: "high",
    description:
      "Output of a JavaScript packer or obfuscator: the Dean Edwards packer's eval wrapper, hexadecimal identifier tables, JSFuck. Code shipped this way is designed not to be read.",
    patterns: [
      /\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)/g,
      /(?:\b_0x[0-9a-f]{4,6}\b[^\n]{0,40}?){6,}/g,
      /[[\]()!+]{80,}/g,
    ],
    prefilter: /eval\s*\(\s*function|_0x[0-9a-f]{4}|[[\]()!+]{80}/,
    kinds: ["script", "skill-md", "markdown", "text"],
  }),
  {
    id: "obfuscation/minified-code",
    title: "Minified code that cannot be reviewed",
    category: "obfuscation",
    severity: "low",
    confidence: "medium",
    description:
      "Script lines thousands of characters long. Minified or generated code hides what it does from review; a skill should ship readable source.",
    scope: "file",
    kinds: ["script"],
    check(ctx) {
      const lines = ctx.text.split("\n");
      const longest = lines.reduce((acc, l, i) => (l.length > acc.len ? { len: l.length, i } : acc), { len: 0, i: 0 });
      if (longest.len >= 3000 || (lines.length > 0 && ctx.text.length / lines.length > 500 && ctx.text.length > 5000)) {
        ctx.report({
          offset: ctx.index.starts[longest.i] ?? 0,
          length: 1,
          message: `Line ${longest.i + 1} is ${longest.len} characters long; the file looks minified or generated`,
        });
      }
    },
  },
  patternRule({
    id: "exec/manual-install-lure",
    title: "Tells you to download and install software from a throwaway site",
    category: "remote-execution",
    severity: "high",
    confidence: "medium",
    description:
      'A prerequisite that sends you to download and install a program by hand from free web hosting or a throwaway domain ("OpenClawCLI must be installed before using this skill. Download and install (Windows, MacOS) from ..."). This is how the ClawHavoc campaign delivered infostealers through skills: the binary never passes through the agent or a package manager.',
    remediation: "Do not install. Get tools only from their vendor's site or a package manager, and never because a skill says so.",
    patterns: [
      /\b(?:download|install|get|grab|set\s*up|setup)\b[^.\n]{0,80}?\b(?:from|here|at|via)\b[^\w\n]{0,12}?(?:\[[^\]\n]{0,80}\]\(\s*)?<?https?:\/\/[^\s)>"'`]+/gi,
      // A bare link on its own line, as the lure's short variants use.
      /^[^\w\n]{0,4}<?https?:\/\/[^\s)>"'`]+>?[^\w\n]{0,4}$/gm,
    ],
    prefilter: /https?:\/\//i,
    kinds: ["skill-md", "markdown"],
    roles: { readme: "lower-confidence" },
    ignoreMatch: (m) => {
      const host = hostOf(URL_RE.exec(m[0])?.[0] ?? "");
      // A bare link counts only on a throwaway domain; docs on GitHub Pages or a raw IP are other rules' business.
      if (!/\b(?:download|install|get|grab|set\s*up|setup)\b/i.test(m[0])) return hostTier(host) !== "throwaway" || /^\d/.test(host);
      return hostTier(host) === "ordinary" && !/\((?:Windows|mac ?OS|Linux)[^)]*\)/i.test(m[0]);
    },
    adjust: (m, ctx) => {
      const tier = hostTier(hostOf(URL_RE.exec(m[0])?.[0] ?? ""));
      const { line } = positionAt(ctx.index, m.index);
      const around = [line - 2, line - 1, line].map((l) => lineText(ctx.index, l)).join("\n");
      const lure =
        /\b(?:must be installed|is required|required for (?:the|this) skill|requires? [\w -]{0,30}to be installed|install(?:ed)? before using)\b/i.test(
          around,
        ) || /\((?:Windows|mac ?OS|Linux)(?:\s*[,/]\s*(?:Windows|mac ?OS|Linux))+\)/i.test(around);
      if (tier === "throwaway") return { severity: "high", confidence: lure ? "high" : "medium" };
      if (tier === "free-hosting") return lure ? { severity: "high", confidence: "medium" } : { severity: "medium", confidence: "medium" };
      return { severity: "medium", confidence: "low" };
    },
    message: (m) => `Sends you to install software from ${URL_RE.exec(m[0])?.[0] ?? "a download page"}`,
  }),
  patternRule({
    id: "exec/code-in-data",
    title: "Process-spawning code inside a data value",
    category: "remote-execution",
    severity: "high",
    confidence: "medium",
    description:
      "A string or configuration value that carries code to start processes: a child_process require written with escaped quotes inside JSON, a sandbox escape through process.mainModule or constructor.constructor, a Python one-liner importing os or subprocess by name. This is the shape of injection payloads aimed at agent tools and MCP servers (Flowise CVE-2025-59528).",
    remediation: "Find out what reads this value. Configuration never needs to carry code that spawns processes.",
    patterns: [
      /\brequire\s*\(\s*\\["']child_process\\["']\s*\)/g,
      /\bprocess\.mainModule\.require\s*\(|\bconstructor\.constructor\s*\(\s*\\?["']return\s+process\b/g,
      /\b__import__\s*\(\s*\\?["'](?:os|subprocess|pty|socket)\\?["']\s*\)\s*\.\s*(?:system|popen|run|call|check_output|Popen|spawn|getoutput)\s*\(/g,
    ],
    prefilter: /child_process|mainModule|constructor\.constructor|__import__/,
    roles: { readme: "lower-confidence" },
    signal: "exec-dynamic",
  }),
  patternRule({
    id: "exec/reverse-shell",
    title: "Reverse shell",
    category: "remote-execution",
    severity: "critical",
    confidence: "high",
    hard: true,
    description:
      "Connects a shell's input and output to a remote host, handing interactive control of the machine to whoever listens there.",
    remediation: "Do not install.",
    patterns: [
      /\b(?:ba|z)?sh\s+-i\s*(?:>&|&>|>)\s*\/dev\/(?:tcp|udp)\//gi,
      /\/dev\/(?:tcp|udp)\/[\w.-]+\/\d{1,5}/g,
      /\b(?:nc|ncat|netcat)\b[^\n|;&]{0,80}\s-[a-z]*[ec]\s+(?:\/bin\/)?(?:ba|z)?sh\b/gi,
      /\bsocat\b[^\n]{0,120}\bexec:[^\n]{0,40}(?:ba|z)?sh/gi,
      /\bmkfifo\b[^\n]{0,120}\b(?:nc|ncat|netcat)\b/gi,
      /\bpty\.spawn\s*\(\s*["'](?:\/bin\/)?(?:ba|z)?sh["']\s*\)[\s\S]{0,300}?\bsocket\b|\bsocket\b[\s\S]{0,300}?\bpty\.spawn\s*\(/g,
      /\bos\.dup2\s*\(\s*\w+\.fileno\(\)\s*,\s*[012]\s*\)/g,
    ],
    prefilter: /\/dev\/(?:tcp|udp)|\b(?:nc|ncat|netcat|socat|mkfifo)\b|pty\.spawn|os\.dup2/,
    // `/dev/tcp/evil.com/4444` in a write-up about attacks names a host nobody can listen on.
    adjust: (m, ctx) => {
      const line = lineText(ctx.index, positionAt(ctx.index, m.index).line);
      const host = /\/dev\/(?:tcp|udp)\/([\w.-]+)\/|\b(?:nc|ncat|netcat)\b[^\n]*?\s([\w-]+(?:\.[\w-]+)+)\s+\d{2,5}\b/.exec(line);
      return host && isDemoHost(host[1] ?? host[2] ?? "") ? { severity: "low", confidence: "low" } : undefined;
    },
  }),
  patternRule({
    id: "exec/fake-password-prompt",
    title: "Fake system password prompt",
    category: "credential-access",
    severity: "critical",
    confidence: "high",
    hard: true,
    description:
      "Shows a system-looking dialog that asks for a password: an AppleScript dialog with a hidden answer field, or PowerShell's credential prompt with a custom message. This is how macOS infostealers distributed as skills collect the login password.",
    remediation: "Do not install.",
    patterns: [
      /\bosascript\b[^\n]{0,300}\bdisplay\s+dialog\b[^\n]{0,400}\b(?:hidden\s+answer|password)\b/gi,
      /\bdisplay\s+dialog\b[^\n]{0,300}\bdefault\s+answer\b[^\n]{0,200}\bhidden\s+answer\s+(?:true|yes)\b/gi,
      /\bGet-Credential\b[^\n]{0,200}(?:-Message|-Title)/gi,
    ],
    signal: "credential-read",
  }),
  patternRule({
    id: "exec/gatekeeper-bypass",
    title: "Removes macOS download quarantine",
    category: "privilege",
    severity: "high",
    confidence: "high",
    description:
      "Strips the macOS quarantine attribute with xattr, so Gatekeeper never checks a downloaded binary. Used to run unsigned payloads.",
    patterns: [/\bxattr\s+(?:-[a-z]+\s+){0,3}com\.apple\.quarantine\b/gi, /\bxattr\s+-[a-z]*c[a-z]*\s+\S/gi],
    // Clearing quarantine on a tool you installed is a workaround; clearing it on something just downloaded is the
    // macOS infostealer install chain (download, xattr -c, chmod +x, run).
    adjust: (m, ctx) => {
      const { line } = positionAt(ctx.index, m.index);
      const here = lineText(ctx.index, line);
      const rest = here.slice(Math.max(0, m.index - (ctx.index.starts[line - 1] ?? 0)) + m[0].length);
      const target = (/^\s*(\S+)/.exec(rest.split(/[;&|]/)[0] ?? "")?.[1] ?? "").replace(/["']/g, "");
      const name = target.split("/").pop() ?? "";
      const earlier = [1, 2, 3, 4, 5].map((d) => lineText(ctx.index, line - d)).join("\n");
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const downloaded =
        /\b(?:curl|wget|iwr|invoke-webrequest)\b/i.test(here) ||
        /\/tmp\/|\/Downloads\/|\$\{?TMP/.test(target) ||
        (name.length > 1 && new RegExp(`\\b(?:curl|wget)\\b[^\\n]*${escaped}`).test(earlier));
      return downloaded
        ? undefined
        : { severity: "medium", message: "Removes the macOS quarantine flag from a file, so Gatekeeper never checks it" };
    },
  }),
  patternRule({
    id: "exec/password-protected-archive",
    title: "Extracts a password-protected archive",
    category: "obfuscation",
    severity: "high",
    confidence: "medium",
    description:
      "Unpacks an archive with a password given in the command. Encryption keeps scanners from seeing the contents, which is why malware delivery uses it.",
    patterns: [
      /\bunzip\s+(?:-[a-zA-Z]+\s+)*-P\s*\S+/g,
      /\b7z[az]?\s+x\b[^\n]{0,100}\s-p\S+/g,
      /\bunrar\s+x\b[^\n]{0,100}\s-p\S+/g,
      // Prose: "extract with pass `openclaw`", "archive password: infected" (the ClawHavoc lure and malware-sharing habit).
      /\b(?:extract|unzip|unpack|decompress|open)\b[^.\n]{0,60}?\b(?:pass(?:word)?|passphrase|pwd)\b\s*(?::|=|is\b)?\s*[`'"](?!-)[^`'"\s]{3,40}[`'"]/gi,
      /\b(?:archive|zip|rar|7z)\s+(?:pass(?:word)?|passphrase)\s*(?::|=|is\b)\s*[`'"*]{0,2}(?!-)[\w!@#$%^&*.]{3,40}/gi,
    ],
    prefilter: /unzip|7z|unrar|pass(?:word|phrase)?\b|pwd/i,
    // A password is not a secret in "the password is required" or "use a password manager".
    ignoreMatch: (m) =>
      /\b(?:pass(?:word)?|passphrase|pwd)\b\s*(?:is\s+)?[:=]?\s*[`'"*]{0,2}(?:required|protected|manager|prompt|field|reset|policy|the|your|a|an|you|if|when|for|from|and|or|to|with|of)\b/i.test(
        m[0],
      ),
  }),
  patternRule({
    id: "exec/remote-package-exec",
    title: "Runs a package fetched at run time",
    category: "supply-chain",
    severity: "low",
    confidence: "medium",
    description:
      "Runs a package that is downloaded when the command runs (`npx -y`, `uvx`, `pipx run`, `pip install` from a URL or git). What runs depends on the registry at that moment, not on what you reviewed.",
    patterns: [
      /\b(?:npx|pnpx|bunx)\s+(?:--yes\s+|-y\s+)(?:--?\S+\s+){0,3}@?[\w.-]+(?:\/[\w.-]+)?(?!@\d)(?=\s|$|["'`])/g,
      /\b(?:pnpm|yarn)\s+dlx\s+@?[\w.-]+(?:\/[\w.-]+)?(?!@\d)(?=\s|$|["'`])/g,
      /\b(?:uvx|pipx\s+run)\s+(?:--from\s+)?(?:git\+|https?:\/\/)\S+/g,
      /\bpip[0-9.]*\s+install\s+(?:-[-\w]+\s+){0,4}(?:git\+|https?:\/\/)\S+/g,
      /\bnpm\s+(?:install|i)\s+(?:-g\s+|--global\s+)?(?:git\+|https?:\/\/|github:)\S+/g,
    ],
    message: (m) => `Fetches and runs \`${m[0].trim().slice(0, 80)}\` at run time`,
  }),
];
