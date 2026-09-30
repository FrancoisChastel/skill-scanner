import * as analyzersModule from "../analyzers";
import type { RuleMeta } from "../core/rule";
import { redactSecrets } from "../core/secrets";
import { compareFindings } from "../core/severity";
import { revealInvisible } from "../core/text";
import { type BundleKind, type Finding, type Location, type ScanReport, SEVERITIES, type Severity, type Verdict } from "../core/types";
import { JUDGE_RULES } from "../judge";
import { ruleCatalog } from "../rules";

/** Helpers shared by the reporters. Everything a scanned skill controls passes through `clean` before it is shown. */

/**
 * Make untrusted text safe to show: secrets masked, control, C1, and invisible characters written as `<U+XXXX>`.
 * Rule output is already cleaned by the engine; external analyzers and the judge may not be.
 */
export function clean(s: string): string {
  const shown = revealInvisible(redactSecrets(s));
  let out = "";
  for (const ch of shown) {
    const cp = ch.codePointAt(0)!;
    out += cp >= 0x80 && cp <= 0x9f ? `<U+${cp.toString(16).toUpperCase().padStart(4, "0")}>` : ch;
  }
  return out;
}

/** `file:line`, or just `file` when the finding has no line. */
export function formatLocation(loc: Location): string {
  return loc.line ? `${loc.file}:${loc.line}` : loc.file;
}

const DESCENDING: readonly Severity[] = [...SEVERITIES].reverse();

/** "2 critical, 1 high" for the non-zero counts, most severe first. Empty string when there are none. */
export function countsPhrase(counts: Readonly<Record<Severity, number>>): string {
  return DESCENDING.filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${s}`)
    .join(", ");
}

export const plural = (n: number, word: string, many = `${word}s`): string => `${n} ${n === 1 ? word : many}`;

export function totalFindings(report: ScanReport): number {
  return report.bundles.reduce((n, b) => n + b.findings.length, 0);
}

/** Every finding of the report, most severe first. */
export function sortedFindings(report: ScanReport): Finding[] {
  return report.bundles.flatMap((b) => b.findings).sort(compareFindings);
}

const KIND_WORDS: Readonly<Record<BundleKind, string>> = { skill: "skill", plugin: "plugin", package: "package" };

/** "3 skills", or "2 skills and 1 plugin" when the target also held non-skill bundles. */
export function describeBundles(report: ScanReport): string {
  const counts = new Map<BundleKind, number>();
  for (const b of report.bundles) counts.set(b.bundle.kind, (counts.get(b.bundle.kind) ?? 0) + 1);
  if (counts.size === 0) return "0 skills";
  const parts = [...counts.entries()].map(([kind, n]) => plural(n, KIND_WORDS[kind]));
  return parts.length === 1 ? parts[0]! : `${parts.slice(0, -1).join(", ")} and ${parts.at(-1)}`;
}

export function verdictCounts(report: ScanReport): Readonly<Record<Verdict, number>> {
  const counts: Record<Verdict, number> = { block: 0, warn: 0, pass: 0 };
  for (const b of report.bundles) counts[b.verdict] += 1;
  return counts;
}

export const VERDICT_LABEL: Readonly<Record<Verdict, string>> = { block: "BLOCK", warn: "WARN", pass: "PASS" };

/** Rule metadata from optional modules that may not export it (external analyzers). */
function optionalRules(mod: object, name: string): RuleMeta[] {
  const value: unknown = Reflect.get(mod, name);
  return Array.isArray(value) ? value.filter((r): r is RuleMeta => typeof r === "object" && r !== null && "id" in r) : [];
}

/** Every rule the scanner can report: built-in and engine rules, then judge and external-analyzer rules. First id wins. */
export function knownRules(): RuleMeta[] {
  const seen = new Set<string>();
  const out: RuleMeta[] = [];
  for (const r of [...ruleCatalog(), ...JUDGE_RULES, ...optionalRules(analyzersModule, "ANALYZER_RULES")]) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    out.push(r);
  }
  return out;
}

/** Rule metadata for a finding whose rule is not in any catalog, e.g. from an external analyzer. */
export function synthesizeRule(f: Finding): RuleMeta {
  return {
    id: f.ruleId,
    title: clean(f.title),
    category: f.category,
    severity: f.severity,
    confidence: f.confidence,
    description: `${clean(f.title)}. Reported by ${sourceLabel(f.source)}.`,
    ...(f.remediation ? { remediation: clean(f.remediation) } : {}),
  };
}

export function sourceLabel(source: Finding["source"]): string {
  if (source === "static" || source === "correlation") return "the skill-scanner rules";
  if (source === "judge") return "the jev judge";
  return source.slice("external:".length) || "an external analyzer";
}

/** Rules of the catalog plus one synthesized entry per unknown rule id among `findings`, in first-seen order. */
export function rulesFor(findings: readonly Finding[], catalog: readonly RuleMeta[] = knownRules()): RuleMeta[] {
  const ids = new Set(catalog.map((r) => r.id));
  const extra: RuleMeta[] = [];
  for (const f of findings) {
    if (ids.has(f.ruleId)) continue;
    ids.add(f.ruleId);
    extra.push(synthesizeRule(f));
  }
  return [...catalog, ...extra];
}
