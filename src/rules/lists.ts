/**
 * Curated lists behind several rules. Kept small and explicit so a reviewer can audit them;
 * additions need a source in the pull request.
 */

/** Vendor installers commonly piped to a shell in legitimate setup docs. Still remote code, so still reported, one step lower. */
export const TRUSTED_INSTALLER_HOSTS: readonly string[] = [
  "sh.rustup.rs",
  "bun.sh",
  "bun.com",
  "deno.land",
  "deno.com",
  "astral.sh",
  "get.docker.com",
  "get.pnpm.io",
  "install.python-poetry.org",
  "fnm.vercel.app",
  "get.volta.sh",
  "get.sdkman.io",
  "starship.rs",
  "tailscale.com",
  "ollama.com",
  "claude.ai",
  "opencode.ai",
  "pixi.sh",
  "mise.run",
  "fly.io",
  "foundry.paradigm.xyz",
  "cli.github.com",
  "brew.sh",
  "hf.co",
  "huggingface.co",
  "sh.vercel.com",
  "vercel.com",
  "get.helm.sh",
  "cli.doppler.com",
  // Microsoft's own link shortener: only Microsoft can create aka.ms links.
  "aka.ms",
  "deb.nodesource.com",
  "rpm.nodesource.com",
  "fluxcd.io",
  "run.linkerd.io",
  "get.k3s.io",
  "cli.sentry.dev",
  "sdk.cloud.google.com",
  "install.determinate.systems",
  "nixos.org",
  "get.rvm.io",
];

/** GitHub raw paths of well-known installers. Plain raw.githubusercontent.com is anyone's content. */
export const TRUSTED_INSTALLER_PREFIXES: readonly string[] = [
  "raw.githubusercontent.com/Homebrew/install/",
  "raw.githubusercontent.com/nvm-sh/nvm/",
  "raw.githubusercontent.com/helm/helm/",
  "raw.githubusercontent.com/ohmyzsh/ohmyzsh/",
  "raw.githubusercontent.com/huggingface/",
  "raw.githubusercontent.com/astral-sh/",
  "raw.githubusercontent.com/oven-sh/",
  // Vendor GitHub organizations: only the vendor can publish under them.
  "raw.githubusercontent.com/microsoft/",
  "raw.githubusercontent.com/OfficeDev/",
  "raw.githubusercontent.com/Azure/",
  "raw.githubusercontent.com/cloudflare/",
  "raw.githubusercontent.com/vercel/",
  "raw.githubusercontent.com/anthropics/",
  "raw.githubusercontent.com/openai/",
  "raw.githubusercontent.com/google/",
  "raw.githubusercontent.com/aws/",
  "raw.githubusercontent.com/hashicorp/",
  "raw.githubusercontent.com/getsentry/",
  "raw.githubusercontent.com/supabase/",
  "raw.githubusercontent.com/cli/",
  "raw.githubusercontent.com/docker/",
  "raw.githubusercontent.com/kubernetes/",
  "raw.githubusercontent.com/fluxcd/",
  "raw.githubusercontent.com/linkerd/",
  "raw.githubusercontent.com/nodesource/",
];

/** Host of a URL, lowercased, without port or credentials. */
export function hostOf(url: string): string {
  const u = url.replace(/^[a-z][\w+.-]*:\/\//i, "");
  const authority = u.split(/[/?#]/, 1)[0] ?? "";
  return (authority.slice(authority.lastIndexOf("@") + 1).split(":", 1)[0] ?? "").toLowerCase();
}

export function isTrustedInstaller(url: string): boolean {
  const u = url.replace(/^https?:\/\//i, "").toLowerCase();
  const host = hostOf(url);
  return (
    TRUSTED_INSTALLER_HOSTS.some((h) => host === h || host.endsWith(`.${h}`)) ||
    TRUSTED_INSTALLER_PREFIXES.some((p) => u.startsWith(p.toLowerCase()))
  );
}

/**
 * Hosts that exist only in examples and write-ups. They cannot serve anyone's payload (the
 * reserved ones by RFC 2606, the others because the name is parked), so a command using them
 * illustrates a technique rather than performing it.
 */
const DEMO_HOSTS: readonly string[] = [
  "evil.com",
  "evil.org",
  "evil.net",
  "evil.io",
  "attacker.com",
  "attacker.org",
  "attacker.net",
  "attacker.io",
  "attacker-controlled.com",
  "malicious.com",
  "malicious-site.com",
  "malicious-domain.com",
  "malware.com",
  "hacker.com",
  "evilcorp.com",
  "evil-server.com",
  "attacker-server.com",
  "bad.com",
  "badsite.com",
  "bad-domain.com",
];

export function isDemoHost(host: string): boolean {
  const h = host.toLowerCase();
  return DEMO_HOSTS.some((d) => h === d || h.endsWith(`.${d}`));
}

/** Placeholder markers in a URL or token: `...`, `xxx`, `<name>`, `{{var}}`, `YOUR_...`. */
export const PLACEHOLDER_URL_RE = /\.\.\.|\u2026|x{3,}|X{3,}|<[^>]*>|\{\{|\byour[-_]|\bYOUR[-_]|\bplaceholder\b|\bchangeme\b/;

/** Words too generic to tie a URL to a skill's vendor. */
const GENERIC_TOKENS = new Set([
  "skill",
  "skills",
  "agent",
  "agents",
  "tool",
  "tools",
  "tooling",
  "helper",
  "helpers",
  "setup",
  "install",
  "installer",
  "deploy",
  "deployment",
  "cloud",
  "code",
  "coding",
  "server",
  "client",
  "manager",
  "management",
  "workflow",
  "workflows",
  "plugin",
  "plugins",
  "utils",
  "util",
  "script",
  "scripts",
  "config",
  "project",
  "claude",
  "codex",
  "github",
  "google",
  "https",
  "http",
  "file",
  "files",
  "data",
  "download",
  "update",
  "auto",
  "local",
  "remote",
  "test",
  "tests",
  "debug",
  "check",
  "guide",
  "patterns",
  "best",
  "practices",
  "integration",
  "service",
  "services",
  "platform",
  "api",
  "apis",
  "sdk",
  "cli",
  "mcp",
  "web",
  "app",
  "apps",
  "dev",
  "ops",
]);

/**
 * Whether a URL belongs to the vendor a skill is named after: a name token of four or more letters
 * appears in the host or, for GitHub, the owning organization. `render-deploy` fetching from
 * `raw.githubusercontent.com/render-oss/...` or `sentry` from `cli.sentry.dev` align; a skill can
 * still lie about its name, so alignment lowers severity rather than clearing a finding.
 */
export function alignsWithSkill(url: string, names: readonly string[]): boolean {
  const tokens = new Set(names.flatMap((n) => n.toLowerCase().split(/[^a-z0-9]+/)).filter((t) => t.length >= 4 && !GENERIC_TOKENS.has(t)));
  if (tokens.size === 0) return false;
  const host = hostOf(url);
  const path = url.replace(/^https?:\/\/[^/]+/i, "");
  const owner = /^(?:raw\.githubusercontent\.com|github\.com|gitlab\.com|codeload\.github\.com)$/.test(host)
    ? (path.split("/")[1] ?? "").toLowerCase()
    : "";
  const labels = [...host.split(".").slice(0, -1), owner].map((l) => l.replace(/-/g, "")).filter(Boolean);
  return [...tokens].some((t) => labels.some((l) => l.includes(t.replace(/-/g, ""))));
}

export type EndpointKind = "tunnel" | "paste" | "catcher" | "chat-webhook" | "tor" | "dyndns" | "shortener";

export interface EndpointClass {
  readonly kind: EndpointKind;
  readonly re: RegExp;
  /** Cheap, case-insensitive pre-check: the class is skipped for files that do not contain it. */
  readonly hint: RegExp;
  readonly label: string;
  readonly severity: "high" | "medium";
  readonly confidence: "high" | "medium";
}

/** Services that receive data without an account, or that exist to relay traffic. */
export const SUSPICIOUS_ENDPOINTS: readonly EndpointClass[] = [
  {
    kind: "tunnel",
    re: /\b(?:[a-z0-9-]+\.)*(?:ngrok\.io|ngrok\.app|ngrok-free\.app|ngrok-free\.dev|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|pagekite\.me|bore\.pub|localhost\.run|lhr\.life|telebit\.cloud|tunnelmole\.net)\b/gi,
    hint: /ngrok|trycloudflare|loca\.lt|localtunnel|serveo|pagekite|bore\.pub|localhost\.run|lhr\.life|telebit|tunnelmole/i,
    label: "a public tunnel to someone's machine",
    severity: "high",
    confidence: "high",
  },
  {
    kind: "paste",
    re: /\b(?:[a-z0-9-]+\.)*(?:pastebin\.com|pastebin\.pl|paste\.ee|hastebin\.com|ghostbin\.\w+|dpaste\.(?:com|org)|termbin\.com|ix\.io|sprunge\.us|transfer\.sh|file\.io|0x0\.st|temp\.sh|catbox\.moe|litterbox\.catbox\.moe|gofile\.io|anonfiles\.com|bashupload\.com|oshi\.at|keep\.sh|filebin\.net|rentry\.(?:co|org)|glot\.io|paste\.c-net\.org|controlc\.com|justpaste\.it|privatebin\.net|paste\.rs|pastes\.io|paste2\.org|pastelink\.net|telegra\.ph|notes\.io)\b/gi,
    hint: /pastebin|paste\.|hastebin|ghostbin|dpaste|termbin|ix\.io|sprunge|transfer\.sh|file\.io|0x0\.st|temp\.sh|catbox|gofile|anonfiles|bashupload|oshi\.at|keep\.sh|filebin|rentry|glot\.io|controlc|justpaste|privatebin|pastes\.io|pastelink|telegra\.ph|notes\.io/i,
    label: "an anonymous paste or file-drop service",
    severity: "high",
    confidence: "high",
  },
  {
    kind: "catcher",
    re: /\b(?:[a-z0-9-]+\.)*(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|beeceptor\.com|hookbin\.com|requestcatcher\.com|mockbin\.org|postb\.in|interact\.sh|interactsh\.com|oast\.(?:pro|live|site|online|fun|me)|burpcollaborator\.net|oastify\.com|canarytokens\.com|dnslog\.cn|ceye\.io|requestrepo\.com|webhook\.cool)\b/gi,
    hint: /webhook\.site|requestbin|pipedream|beeceptor|hookbin|requestcatcher|mockbin|postb\.in|interact\.sh|interactsh|oast\.|burpcollaborator|oastify|canarytokens|dnslog|ceye\.io|requestrepo|webhook\.cool/i,
    label: "a request-capture service used to collect exfiltrated data",
    severity: "high",
    confidence: "high",
  },
  {
    kind: "chat-webhook",
    re: /\b(?:discord(?:app)?\.com\/api\/webhooks\/|hooks\.slack\.com\/(?:services|workflows)\/|api\.telegram\.org\/bot|outlook\.office\.com\/webhook\/|[a-z0-9-]+\.webhook\.office\.com\/)[^\s"'`<>)\]]*/gi,
    hint: /discord|hooks\.slack|telegram|webhook\.office|outlook\.office/i,
    label: "a chat webhook, a common exfiltration channel",
    severity: "high",
    confidence: "medium",
  },
  {
    kind: "tor",
    re: /\b[a-z2-7]{16,56}\.onion\b/gi,
    hint: /\.onion\b/i,
    label: "a Tor hidden service",
    severity: "high",
    confidence: "high",
  },
  {
    kind: "dyndns",
    re: /\b(?:[a-z0-9-]+\.)+(?:duckdns\.org|no-ip\.(?:com|org|biz)|ddns\.net|hopto\.org|zapto\.org|sytes\.net|servebeer\.com|dynu\.net|freedns\.afraid\.org)\b/gi,
    hint: /duckdns|no-ip|ddns\.net|hopto|zapto|sytes\.net|servebeer|dynu|afraid\.org/i,
    label: "a dynamic-DNS host",
    severity: "medium",
    confidence: "medium",
  },
  {
    kind: "shortener",
    re: /\bhttps?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|ow\.ly|buff\.ly|tiny\.cc|v\.gd|t\.ly|s\.id)\/[\w-]+/gi,
    hint: /bit\.ly|tinyurl|t\.co\/|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl|ow\.ly|buff\.ly|tiny\.cc|v\.gd|t\.ly|s\.id\//i,
    label: "a URL shortener that hides the real destination",
    severity: "medium",
    confidence: "medium",
  },
];

/** A chat webhook URL that carries its own channel id and token, as opposed to a template or placeholder. */
export function concreteChatWebhook(url: string): boolean {
  return (
    /hooks\.slack\.com\/(?:services|workflows)\/T[A-Z0-9]{6,}\/[A-Z0-9]{6,}\/[A-Za-z0-9]{12,}/.test(url) ||
    /discord(?:app)?\.com\/api\/webhooks\/\d{15,22}\/[\w-]{30,}/.test(url) ||
    /api\.telegram\.org\/bot\d{6,12}:[\w-]{30,}/.test(url) ||
    /webhook\.office\.com\/webhookb2\/[\w-]{30,}/.test(url)
  );
}

/** Files whose content is a credential or unlocks one. `high` ones are keys and vaults; `medium` ones are configs that may hold tokens. */
export const SECRET_STORE_PATTERNS: readonly RegExp[] = [
  // Private keys and the key directory itself. authorized_keys, known_hosts, config, and *.pub hold no secret.
  /(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\/home\/[\w.$-]+|\/Users\/[\w.$-]+|\bhomedir\(\)|expanduser\(\s*['"]~)?\/?\.ssh\/(?:id_[a-z0-9_]+|identity|[\w.-]*_key\b)?(?!authorized_keys|known_hosts|config\b|[\w.-]*\.pub\b)/gi,
  /\.aws\/credentials\b/gi,
  /\.config\/gcloud\/(?:credentials\.db|application_default_credentials\.json|access_tokens\.db|legacy_credentials)/gi,
  /\.azure\/(?:accessTokens\.json|msal_token_cache)/gi,
  /\.gnupg\/(?:private-keys|secring|trustdb)?/gi,
  /\.git-credentials\b/gi,
  /\.netrc\b/gi,
  /\/etc\/shadow\b/gi,
  /\bsecurity\s+(?:find-(?:generic|internet)-password|dump-keychain|export\s+-k)\b/gi,
  // The user's keychains, which infostealers copy to crack offline. The System keychain holds certificates.
  /(?:~|\$HOME|\/Users\/[\w.$-]+)\/Library\/Keychains\b|\blogin\.keychain(?:-db)?\b/gi,
  /(?:Google\/Chrome|google-chrome|Chromium|BraveSoftware|Microsoft\/Edge|Microsoft Edge|Opera Software|Vivaldi|Yandex\/YandexBrowser|Mozilla\/Firefox|\.mozilla\/firefox|Firefox\/Profiles)[^\n'"]{0,80}(?:Login Data|Web Data|Local State|Cookies|key[34]\.db|logins\.json|cookies\.sqlite)/gi,
  // Browser databases opened directly: sqlite3 on a profile's login or cookie store, or the SQL that reads saved passwords.
  /\bsqlite3\b[^\n]{0,160}(?:Login Data|Web Data|Cookies|key4\.db|logins\.json|History)\b|\b(?:password_value|encrypted_value)\b[^\n]{0,80}\bFROM\s+(?:logins|cookies)\b/g,
  // Browser profile folders and Safari's cookie jar.
  /(?:Google\/Chrome|Chromium|BraveSoftware\/Brave-Browser|Microsoft Edge|Microsoft\/Edge)\/(?:Default|Profile \d+)\b|\bCookies\.binarycookies\b|Library\/Cookies\//g,
  // Searching the whole disk for private keys and credential files, the collection step of a stealer.
  /\bfind\s+(?:\/|~|\$HOME|\/home|\/Users)\S*\s[^\n|;]{0,200}-i?name\s+["']?(?:\*\.pem|\*\.key|id_rsa\*?|id_ed25519\*?|\*\.p12|\*\.pfx|\*\.keystore|credentials\*?|\.env\*?)["']?/g,
  // Chrome-family profile files named together, as a stealer's loop over them does.
  /["'](?:Login Data|Web Data|Local State|Session Storage|Local Storage|Cookies)["']\s*,\s*["'](?:Login Data|Web Data|Local State|Session Storage|Local Storage|Cookies|Preferences|History)["']/g,
  // Wallet files and the extension ids of MetaMask, Phantom, Coinbase Wallet, and Trust Wallet.
  /\b(?:wallet\.dat|\.electrum\/wallets|Exodus\/exodus\.wallet|atomic\/Local Storage|\.bitcoin\/(?:wallets?\b|wallet\.dat)|Ledger Live\/|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|egjidjbpglichdcondbcbdnbeeppgdph)/g,
  /\.claude\/\.credentials\.json|\.codex\/auth\.json|\.pi\/agent\/auth\.json|opencode\/auth\.json|\.config\/github-copilot\/(?:hosts|apps)\.json|\.gemini\/oauth_creds\.json/gi,
  /\b(?:\.bash_history|\.zsh_history|\.psql_history|\.mysql_history|ConsoleHost_history\.txt)\b/g,
];

/** Cheap pre-check for SECRET_STORE_PATTERNS: a file that contains none of these cannot match. */
export const SECRET_STORE_HINT =
  /sqlite3|password_value|encrypted_value|Chrome|Chromium|Brave|Edge|binarycookies|Library\/Cookies|\bfind\s|Session Storage|Local Storage|\.ssh|\.aws|gcloud|\.azure|\.gnupg|git-credentials|netrc|\/etc\/shadow|security\s|keychain|Login Data|Web Data|Local State|Cookies|key[34]\.db|logins\.json|wallet|electrum|Exodus|atomic|bitcoin|Ledger|nkbihf|bfnael|hnfank|egjidj|credentials\.json|auth\.json|copilot|oauth_creds|_history|ConsoleHost/i;

export const CREDENTIAL_CONFIG_PATTERNS: readonly RegExp[] = [
  /\.aws\/config\b/gi,
  /\.kube\/config\b/gi,
  /\.docker\/config\.json\b/gi,
  /(?:~|\$HOME|\bhome)\/?\.npmrc\b/gi,
  /\.pypirc\b/gi,
  /\.config\/gh\/hosts\.yml\b/gi,
  /\.terraform\.d\/credentials/gi,
  /\.vault-token\b/gi,
  /\.config\/hub\b/gi,
  /(?:~|\$HOME|\/home\/[\w.$-]+|\/Users\/[\w.$-]+)\/\.ssh\/config\b/gi,
];

export const CREDENTIAL_CONFIG_HINT = /\.aws|\.kube|\.docker|npmrc|pypirc|\.config\/(?:gh|hub)|terraform\.d|vault-token|\.ssh\/config/i;

/**
 * Credential stores tied to the service a skill can reasonably be about. A skill named for AWS that
 * mentions ~/.aws/credentials is doing its job; one named for spreadsheets is not. Wallets, browser
 * stores, keychains, agent logins, and shell history are never aligned: stealers dress up as those tools.
 */
export const ALIGNED_CREDENTIALS: ReadonlyArray<readonly [RegExp, readonly string[]]> = [
  [/\.aws\//i, ["aws", "amazon", "bedrock", "boto", "sagemaker"]],
  [/\.ssh\//i, ["ssh", "sftp", "scp", "rsync"]],
  [/gcloud/i, ["gcp", "gcloud", "bigquery", "firebase", "vertex"]],
  [/\.azure\//i, ["azure", "entra"]],
  [/\.gnupg/i, ["gpg", "gnupg", "pgp", "signing"]],
  [/\.netrc/i, ["netrc", "curl"]],
  [/git-credentials/i, ["git", "github", "gitlab"]],
  [/\.kube\//i, ["kube", "kubernetes", "k8s", "kubectl", "helm", "eks", "gke", "aks"]],
  [/\.docker\//i, ["docker", "container", "registry"]],
  [/npmrc/i, ["npm", "node", "package", "publish"]],
  [/pypirc/i, ["pypi", "python", "package", "publish"]],
  [/terraform\.d/i, ["terraform", "hashicorp"]],
  [/vault-token/i, ["vault", "hashicorp"]],
  [/\.config\/gh\//i, ["github", "gh"]],
];

export function credentialAlignsWith(match: string, names: readonly string[]): boolean {
  const tokens = new Set(names.flatMap((n) => n.toLowerCase().split(/[^a-z0-9]+/)).filter((t) => t.length >= 2));
  return ALIGNED_CREDENTIALS.some(([re, words]) => re.test(match) && words.some((w) => tokens.has(w)));
}

/**
 * Free web hosting and app platforms: anyone can publish there in minutes, so they carry no
 * vendor identity. Vendors do host docs on some of them; a skill telling you to download and
 * install software from one is the ClawHavoc lure.
 */
const FREE_HOSTING: readonly string[] = [
  "vercel.app",
  "netlify.app",
  "pages.dev",
  "workers.dev",
  "github.io",
  "gitlab.io",
  "glitch.me",
  "onrender.com",
  "herokuapp.com",
  "fly.dev",
  "railway.app",
  "replit.app",
  "repl.co",
  "web.app",
  "firebaseapp.com",
  "surge.sh",
  "now.sh",
  "neocities.org",
  "000webhostapp.com",
  "wixsite.com",
  "weebly.com",
  "blogspot.com",
  "tiiny.site",
  "carrd.co",
];

/** Top-level domains that are cheap, rarely used by software vendors, and common in malware campaigns. */
const THROWAWAY_TLDS = new Set(["forum", "top", "click", "zip", "mov", "icu", "buzz", "cfd", "sbs", "rest", "lol", "su"]);

export type HostTier = "throwaway" | "free-hosting" | "ordinary";

export function hostTier(host: string): HostTier {
  const h = host.toLowerCase();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || THROWAWAY_TLDS.has(h.slice(h.lastIndexOf(".") + 1))) return "throwaway";
  if (FREE_HOSTING.some((d) => h === d || h.endsWith(`.${d}`))) return "free-hosting";
  return "ordinary";
}
