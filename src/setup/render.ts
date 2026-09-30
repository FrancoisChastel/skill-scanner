import type { ApplyResult } from "./apply";
import type { CanaryResult } from "./canary";
import { HARNESS_LABEL } from "./harnesses";
import type { SetupPlan } from "./index";
import { BACKUP_SUFFIX, type FileOp, opVerb } from "./ops";

/** Plain-text rendering of plans and results. Paths under the user's home are shown with `~`. */

export const tildify = (path: string, home: string): string =>
  home && (path === home || path.startsWith(`${home}/`)) ? `~${path.slice(home.length)}` : path;

/** Abbreviate every path under `home` inside a message. */
export const tildifyText = (text: string, home: string): string => (home.length > 1 ? text.split(`${home}/`).join("~/") : text);

const row = (marker: string, text: string): string => `  ${marker.padEnd(7)} ${text}`;

function opLine(op: FileOp, t: (p: string) => string): string {
  const backup = op.kind === "write" && op.backup && op.before !== undefined ? ` (original kept in ${t(op.path)}${BACKUP_SUFFIX})` : "";
  return row(opVerb(op), `${t(op.path)}  ${op.summary}${backup}`);
}

export function renderPlan(plan: SetupPlan, home: string): string {
  const t = (p: string) => tildify(p, home);
  const tt = (text: string) => tildifyText(text, home);
  const out: string[] = [];
  const names = plan.harnesses.map((h) => HARNESS_LABEL[h]).join(", ") || "nothing";
  out.push(`skill-scanner setup: ${plan.mode === "install" ? "install for" : "uninstall from"} ${names} (${plan.scope} scope)`);
  if (plan.detections) {
    const missing = plan.detections.filter((d) => !d.detected).map((d) => HARNESS_LABEL[d.harness]);
    if (missing.length > 0) out.push(`  not detected: ${missing.join(", ")} (name them to set them up anyway)`);
  }
  if (plan.node) out.push(`  node for hooks: ${t(plan.node.path)}${plan.node.version ? ` (v${plan.node.version})` : ""}`);
  for (const s of plan.sections) {
    out.push("", tt(s.title));
    if (s.error) out.push(row("refuse", tt(s.error)));
    for (const op of s.ops) out.push(opLine(op, t));
    for (const p of s.unchanged) out.push(row("ok", `${t(p)} (up to date)`));
    if (!s.error && s.ops.length === 0 && s.unchanged.length === 0 && plan.mode === "uninstall") out.push(row("ok", "nothing to remove"));
    for (const w of s.warnings) out.push(row("warn", tt(w)));
    for (const n of s.notes) out.push(row("note", tt(n)));
  }
  return `${out.join("\n")}\n`;
}

export function renderApply(result: ApplyResult, home: string): string {
  const t = (p: string) => tildify(p, home);
  const out: string[] = [];
  const n = result.applied.length;
  out.push(`Applied ${n} change${n === 1 ? "" : "s"}.`);
  for (const b of result.backups) out.push(row("backup", t(b)));
  if (result.failed)
    out.push(
      `Stopped before finishing: could not ${opVerb(result.failed.op)} ${t(result.failed.op.path)}: ${tildifyText(result.failed.error, home)}`,
      "The changes listed above were made; nothing after the failure was touched. Fix the problem and re-run setup.",
    );
  return `${out.join("\n")}\n`;
}

export function renderCanaries(results: readonly CanaryResult[]): string {
  return `${["Canary:", ...results.map((r) => row(r.ok ? "ok" : "fail", `${r.name}: ${r.detail}`))].join("\n")}\n`;
}
