import { contextualize } from "../core/context";
import { shannonEntropy } from "../core/decode";
import type { FileRule } from "../core/rule";
import { TEXT_KINDS } from "../core/rule";
import { ASSIGNMENT_RE, maskSecret, PLACEHOLDER_RE, SECRET_PATTERNS } from "../core/secrets";
import type { Confidence, Severity } from "../core/types";

/** At least 64 base64 characters right after a PEM header, possibly across (escaped) line breaks. */
const PEM_BODY_RE = /^(?:\s|\\n|\\r)*(?:[A-Za-z0-9+/=]{16,}(?:\s|\\n|\\r)*){4,}/;

/** Credentials embedded in a skill. The patterns live in core/secrets.ts so every report can redact them. */

export const secretRules: readonly FileRule[] = [
  {
    id: "secrets/embedded-credential",
    title: "Embedded credential",
    category: "secrets",
    severity: "medium",
    confidence: "medium",
    description:
      "A string with the shape of a live API key, token, or private key. The author leaked it, or it is the key to where stolen data would be sent.",
    remediation:
      "If you wrote the skill, revoke the credential now and load it from the environment instead. If you did not, ask why the skill carries someone's key.",
    scope: "file",
    kinds: TEXT_KINDS,
    check(ctx) {
      let n = 0;
      const report = (offset: number, length: number, severity: Severity, confidence: Confidence, message: string): boolean => {
        // Fake tokens are the input of a secret scanner's own tests.
        const g = contextualize(ctx, offset, length, { severity, confidence }, { cautionAware: false });
        if (g) ctx.report({ offset, length, severity: g.severity, confidence: g.confidence, message });
        return ++n >= 10;
      };
      for (const p of SECRET_PATTERNS) {
        for (const m of ctx.text.matchAll(p.re)) {
          if (PLACEHOLDER_RE.test(m[0])) continue;
          if (p.minEntropy && shannonEntropy(m[0]) < p.minEntropy) continue;
          // A PEM header alone (a scanner's regex, a checklist) is not a key; a key has a base64 body.
          if (p.kind === "private key" && !PEM_BODY_RE.test(ctx.text.slice(m.index + m[0].length, m.index + m[0].length + 200))) continue;
          if (report(m.index, m[0].length, p.severity, "medium", `Looks like a live ${p.kind}: ${maskSecret(m[0])}`)) return;
        }
      }
      for (const m of ctx.text.matchAll(ASSIGNMENT_RE)) {
        const value = m[1]!;
        if (PLACEHOLDER_RE.test(value) || shannonEntropy(value) < 4 || /^[a-z_]+$/i.test(value) || /^(?:process|os)\./.test(value))
          continue;
        if (report(m.index, m[0].length, "low", "low", `A hard-coded secret assignment: ${maskSecret(value)}`)) return;
      }
    },
  },
];
