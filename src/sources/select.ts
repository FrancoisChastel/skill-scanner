import { countBySeverity, worstVerdict } from "../core/severity";
import type { BundleReport, ScanReport } from "../core/types";

/**
 * Restricting a report to the skills an installer will pick (`-s name`, `owner/repo@name`).
 *
 * The skills CLI selects by the frontmatter `name` as its YAML library reads it; ours is a
 * smaller parser. Anchors, aliases, escapes, tags, folded lines, or flow mappings could make the
 * two disagree, so a skill counts as possibly selected unless its name is written so plainly that
 * both must read it the same way. Over-selecting only means scanning (and gating on) more.
 */

/** Keep every non-skill bundle and every skill that may match one of `names`; recompute verdict and counts. */
export function restrictToSkills(report: ScanReport, names: readonly string[]): ScanReport {
  const wanted = names.map((n) => n.toLowerCase());
  const bundles = report.bundles.filter((b) => b.bundle.kind !== "skill" || mayBeSelected(b, wanted));
  return {
    ...report,
    bundles,
    verdict: worstVerdict(bundles.map((b) => b.verdict)),
    counts: countBySeverity(bundles.flatMap((b) => b.findings)),
  };
}

function mayBeSelected(b: BundleReport, wanted: readonly string[]): boolean {
  const known = [b.bundle.name.toLowerCase(), b.bundle.dirName.toLowerCase()];
  if (wanted.some((n) => known.includes(n))) return true;
  const fm = b.bundle.frontmatter;
  if (!fm) return false;
  if (fm.errors.length > 0) return true;
  const raw = fm.raw.toLowerCase();
  if (wanted.some((n) => raw.includes(n))) return true;
  return !hasPlainName(fm.raw);
}

const PLAIN_VALUE = /^(?:[A-Za-z0-9][A-Za-z0-9 _.-]*|"[^"\\]*"|'[^']*')$/;

/** Exactly one top-level `name:` line, a plain or simply quoted value, nothing continuing it, block-style YAML only. */
function hasPlainName(raw: string): boolean {
  const lines = raw.split(/\r?\n/);
  const topLevel = lines.map((l, i) => ({ l, i })).filter(({ l }) => l.trim() !== "" && !/^\s/.test(l) && !l.startsWith("#"));
  if (topLevel.some(({ l }) => !/^[A-Za-z0-9_-]+\s*:/.test(l))) return false;
  const names = topLevel.filter(({ l }) => /^name\s*:/.test(l));
  if (names.length !== 1) return names.length === 0;
  const { l, i } = names[0]!;
  const value = l.slice(l.indexOf(":") + 1).trim();
  const next = lines[i + 1];
  const continued = next !== undefined && /^\s+\S/.test(next);
  return PLAIN_VALUE.test(value) && !continued;
}

/**
 * What `npx skills` installs: skill directories only. The rest of a repository (tests, CI, docs,
 * the README) is never copied, so it does not gate the install. A dropped bundle that recorded
 * collection limits keeps only that finding, so padding a repository still cannot hide a skill.
 */
export function onlySkillBundles(report: ScanReport): ScanReport {
  if (!report.bundles.some((b) => b.bundle.kind === "skill")) return report;
  const bundles = report.bundles.flatMap((b): BundleReport[] => {
    if (b.bundle.kind === "skill") return [b];
    if (b.bundle.notes.length === 0) return [];
    const findings = b.findings.filter((f) => f.ruleId === "packaging/incomplete-scan");
    return [{ ...b, findings, verdict: findings.length > 0 ? b.verdict : "pass" }];
  });
  return {
    ...report,
    bundles,
    verdict: worstVerdict(bundles.map((b) => b.verdict)),
    counts: countBySeverity(bundles.flatMap((b) => b.findings)),
  };
}

/** Collection limits hit while scanning (too many files, too deep, too large): parts were never read. */
export function scanGaps(report: ScanReport): readonly string[] {
  return report.bundles.flatMap((b) => b.bundle.notes);
}
