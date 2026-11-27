import { type Paint, type Palette, palette, visibleWidth, wrap } from "../report/style";
import type { ApplyResult } from "./apply";
import type { CanaryResult } from "./canary";
import { HARNESS_LABEL } from "./harnesses";
import type { SetupPlan } from "./index";
import { BACKUP_SUFFIX, type FileOp, opVerb } from "./ops";

/** Text rendering of plans and results, colored when `color` is set. Paths under the user's home are shown with `~`. */

export const tildify = (path: string, home: string): string =>
  home && (path === home || path.startsWith(`${home}/`)) ? `~${path.slice(home.length)}` : path;

/** Abbreviate every path under `home` inside a message. */
export const tildifyText = (text: string, home: string): string => (home.length > 1 ? text.split(`${home}/`).join("~/") : text);

type Marker = "create" | "update" | "remove" | "delete" | "ok" | "warn" | "note" | "refuse" | "fail" | "backup";

function markerPaint(marker: Marker, c: Palette): Paint {
  if (marker === "create" || marker === "update" || marker === "ok") return c.ok;
  if (marker === "remove" || marker === "delete" || marker === "warn") return c.warn;
  if (marker === "refuse" || marker === "fail") return c.bad;
  return marker === "note" ? c.accent : c.dim;
}

const row = (marker: Marker, text: string, c: Palette = palette(false)): string => `  ${markerPaint(marker, c)(marker.padEnd(7))} ${text}`;

/** Where the text after a row's marker starts. */
const ROW_TEXT = "          ";

/** "  create  path  summary"; with a `width` it does not fit, the summary goes on the lines under the path. */
function opLines(op: FileOp, t: (p: string) => string, c: Palette, width?: number): string[] {
  const backup = op.kind === "write" && op.backup && op.before !== undefined ? ` (original kept in ${t(op.path)}${BACKUP_SUFFIX})` : "";
  const summary = `${op.summary}${backup}`;
  const one = row(opVerb(op), `${t(op.path)}  ${c.dim(summary)}`, c);
  if (!width || visibleWidth(one) <= width) return [one];
  return [row(opVerb(op), t(op.path), c), ...wrap(summary, width, ROW_TEXT).map(c.dim)];
}

export function renderPlan(plan: SetupPlan, home: string, color = false, width?: number): string {
  const c = palette(color);
  const t = (p: string) => tildify(p, home);
  const tt = (text: string) => tildifyText(text, home);
  const out: string[] = [];
  const names = plan.harnesses.map((h) => HARNESS_LABEL[h]).join(", ") || "nothing";
  out.push(
    `${c.bold("skill-scanner setup:")} ${plan.mode === "install" ? "install for" : "uninstall from"} ${names} ${c.dim(`(${plan.scope} scope)`)}`,
  );
  if (plan.detections) {
    const missing = plan.detections.filter((d) => !d.detected).map((d) => HARNESS_LABEL[d.harness]);
    if (missing.length > 0) out.push(c.dim(`  not detected: ${missing.join(", ")} (name them to set them up anyway)`));
  }
  if (plan.node) out.push(c.dim(`  node for hooks: ${t(plan.node.path)}${plan.node.version ? ` (v${plan.node.version})` : ""}`));
  for (const s of plan.sections) {
    out.push("", c.bold(tt(s.title)));
    if (s.error) out.push(row("refuse", tt(s.error), c));
    for (const op of s.ops) out.push(...opLines(op, t, c, width));
    for (const p of s.unchanged) out.push(row("ok", `${t(p)} ${c.dim("(up to date)")}`, c));
    if (!s.error && s.ops.length === 0 && s.unchanged.length === 0 && plan.mode === "uninstall")
      out.push(row("ok", "nothing to remove", c));
    for (const w of s.warnings) out.push(row("warn", tt(w), c));
    for (const n of s.notes) out.push(row("note", tt(n), c));
  }
  return `${out.join("\n")}\n`;
}

export function renderApply(result: ApplyResult, home: string, color = false): string {
  const c = palette(color);
  const t = (p: string) => tildify(p, home);
  const out: string[] = [];
  const n = result.applied.length;
  out.push((result.failed ? c.bold : (s: string) => c.ok(c.bold(s)))(`Applied ${n} change${n === 1 ? "" : "s"}.`));
  for (const b of result.backups) out.push(row("backup", t(b), c));
  if (result.failed)
    out.push(
      `Stopped before finishing: could not ${opVerb(result.failed.op)} ${t(result.failed.op.path)}: ${tildifyText(result.failed.error, home)}`,
      "The changes listed above were made; nothing after the failure was touched. Fix the problem and re-run setup.",
    );
  return `${out.join("\n")}\n`;
}

export function renderCanaries(results: readonly CanaryResult[], color = false): string {
  const c = palette(color);
  return `${[c.bold("Canary:"), ...results.map((r) => row(r.ok ? "ok" : "fail", `${r.name}${c.dim(`: ${r.detail}`)}`, c))].join("\n")}\n`;
}

/** "Heading:" and its items as "  - item" lines, each wrapped under itself when `width` is given. */
export function renderList(heading: string, items: readonly string[], color = false, width?: number): string {
  const c = palette(color);
  const item = (text: string): string[] => {
    const [first = "", ...rest] = width ? wrap(text, width, "    ") : [`    ${text}`];
    return [`  ${c.dim("-")} ${first.slice(4)}`, ...rest];
  };
  return `${[c.bold(heading), ...items.flatMap(item)].join("\n")}\n`;
}
