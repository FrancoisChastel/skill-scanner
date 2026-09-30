import type { Severity } from "./types";

/**
 * Credentials embedded in a skill. Patterns follow the shapes documented by the issuers and by
 * gitleaks (MIT); see THIRD_PARTY_NOTICES.md. A live token in a skill is a leak by the author and,
 * for exfiltration channels such as Telegram bots, a sign of where stolen data would go.
 */

export interface SecretPattern {
  readonly kind: string;
  readonly re: RegExp;
  readonly severity: Severity;
  /** Minimum Shannon entropy of the match, to skip placeholders. */
  readonly minEntropy?: number;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { kind: "private key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, severity: "high" },
  { kind: "AWS access key id", re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, severity: "medium", minEntropy: 3 },
  {
    kind: "GitHub token",
    re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,255}\b/g,
    severity: "medium",
    minEntropy: 3.5,
  },
  { kind: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, severity: "medium", minEntropy: 3.5 },
  { kind: "Anthropic API key", re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g, severity: "medium", minEntropy: 4 },
  {
    kind: "OpenAI API key",
    re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g,
    severity: "medium",
    minEntropy: 4,
  },
  { kind: "OpenRouter API key", re: /\bsk-or-v1-[a-f0-9]{64}\b/g, severity: "medium", minEntropy: 3.5 },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "low", minEntropy: 4 },
  { kind: "Slack token", re: /\bxox[abposr]-[0-9A-Za-z-]{10,}\b/g, severity: "medium", minEntropy: 3.5 },
  { kind: "Stripe live key", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g, severity: "high", minEntropy: 3.5 },
  { kind: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "medium", minEntropy: 3.5 },
  { kind: "PyPI token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g, severity: "medium" },
  { kind: "Hugging Face token", re: /\bhf_[A-Za-z]{34}\b/g, severity: "medium", minEntropy: 3.5 },
  { kind: "SendGrid key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "medium" },
  { kind: "Telegram bot token", re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, severity: "high", minEntropy: 3.5 },
  { kind: "Discord bot token", re: /\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38}\b/g, severity: "high", minEntropy: 4 },
  { kind: "Vercel AI Gateway key", re: /\bvck_[A-Za-z0-9]{40,}\b/g, severity: "medium", minEntropy: 3.5 },
];

export const PLACEHOLDER_RE =
  /x{4,}|X{4,}|\*{3,}|\.{3}|<[^>]*>|\$\{|\{\{|EXAMPLE|example|sample|dummy|fake|placeholder|your[_-]?|YOUR[_-]?|redacted|REDACTED|changeme|0{8,}|1234567/;

/** A generic `password = "..."` style assignment, checked by entropy. */
export const ASSIGNMENT_RE =
  /\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=.]{20,120})["']/gi;

export function maskSecret(value: string): string {
  if (value.startsWith("-----BEGIN")) return value;
  return value.length <= 8 ? "********" : `${value.slice(0, 4)}${"*".repeat(Math.min(12, value.length - 6))}${value.slice(-2)}`;
}

/** A whole PEM private key, or everything after its header when the text was cut before the END line. */
const PEM_PRIVATE_KEY_BLOCK =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----|$)/g;

/** Replace every recognised secret in `text` with a masked form. Used before anything leaves the process. */
export function redactSecrets(text: string): string {
  // Key bodies are base64 with no recognisable shape of their own, so the whole block goes.
  let out = text.replace(PEM_PRIVATE_KEY_BLOCK, "[REDACTED PRIVATE KEY]");
  for (const p of SECRET_PATTERNS)
    out = out.replace(new RegExp(p.re.source, p.re.flags), (m) => (p.kind === "private key" ? "[REDACTED PRIVATE KEY]" : maskSecret(m)));
  return out.replace(new RegExp(ASSIGNMENT_RE.source, ASSIGNMENT_RE.flags), (m, v: string) => m.replace(v, maskSecret(v)));
}
