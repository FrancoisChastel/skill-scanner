import { redactSecrets } from "../core/secrets";
import { revealInvisible } from "../core/text";
import type { FileKind, SkillBundle, SkillFile } from "../core/types";

/**
 * The text jev reads about a bundle: its text files, SKILL.md first, each under a
 * `=== path ===` header, redacted. Never binaries, never symlink targets.
 */

/** Characters of state sent per bundle. Over this, the bundle is skipped, never truncated. */
export const STATE_BUDGET = 24_000;

/** Reading order: what the agent acts on first, then what runs, then the rest. */
const ORDER: Readonly<Partial<Record<FileKind, number>>> = { "skill-md": 0, script: 1, manifest: 2, markdown: 3, text: 4 };

// Redacts a whole PEM block; redactSecrets masks only the BEGIN line of a private key.
const PEM_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;

export type StateResult =
  | { readonly ok: true; readonly state: string; readonly files: number }
  | { readonly ok: false; readonly reason: string };

export function buildState(bundle: SkillBundle, budget: number = STATE_BUDGET): StateResult {
  const files = bundle.files.filter(isJudgeable).sort(byReadingOrder);
  if (files.length === 0) return { ok: false, reason: "no text files to judge" };
  // A model answering about text it never saw would be a fail-open, so partial files are not sent.
  const cut = files.find((f) => f.truncated);
  if (cut) return { ok: false, reason: `${revealInvisible(cut.path)} was truncated while collecting; not sent to the judge` };
  const state = files.map(section).join("\n\n");
  if (state.length > budget)
    return {
      ok: false,
      reason: `skill text is ${state.length} characters, over the judge's ${budget} budget; skipped rather than truncated`,
    };
  return { ok: true, state, files: files.length };
}

function isJudgeable(f: SkillFile): boolean {
  return f.text !== undefined && f.virtualOf === undefined && ORDER[f.kind] !== undefined;
}

function byReadingOrder(a: SkillFile, b: SkillFile): number {
  return (ORDER[a.kind] ?? 9) - (ORDER[b.kind] ?? 9) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

function section(f: SkillFile): string {
  // The path is revealed on its own so a newline in a file name cannot forge another `=== path ===` header.
  const body = redactSecrets(`=== ${revealInvisible(f.path)} ===\n${f.text ?? ""}`.replace(PEM_BLOCK, "[REDACTED PRIVATE KEY]"));
  return visible(body);
}

/**
 * Invisible and control characters become `<U+XXXX>` markers, line by line so line breaks survive.
 * The model then sees that something is hidden (the obfuscation probe needs that), hidden text
 * cannot instruct it unseen, and nothing invisible is shipped onward to a third party.
 */
function visible(text: string): string {
  return text.replace(/\r\n/g, "\n").split("\n").map(revealInvisible).join("\n");
}
