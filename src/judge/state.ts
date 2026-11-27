import { redactSecrets } from "../core/secrets";
import { revealInvisible } from "../core/text";
import type { FileKind, SkillBundle, SkillFile } from "../core/types";

/**
 * The text jev reads about a bundle: its text files, SKILL.md first, each under a
 * `=== path ===` header, redacted. Never binaries, never symlink targets.
 */

/**
 * Characters of state sent per request. At 24,000 the judge never saw 29% of the benchmark's
 * skills; at 96,000 one request holds 90% of them. A longer skill is sent in windows of this size.
 */
export const STATE_BUDGET = 96_000;

/**
 * Most windows sent for one skill. Past this, only the first are judged: the judge can still add its
 * finding, which only warns, but doubts none, since the text that would justify a doubt was not read.
 */
export const MAX_WINDOWS = 8;

/** A SKILL.md up to this long opens every window; a longer one is sent once, and its frontmatter (or its start) opens every window. */
const OPENER_MAX = STATE_BUDGET / 4;

/** Smallest part a file is cut into, whatever its label costs. */
const MIN_PART = 1_024;

/** Reading order: what the agent acts on first, then what runs, then the rest. */
const ORDER: Readonly<Partial<Record<FileKind, number>>> = { "skill-md": 0, script: 1, manifest: 2, markdown: 3, text: 4 };

// Redacts a whole PEM block; redactSecrets masks only the BEGIN line of a private key.
const PEM_BLOCK = /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;

const SEPARATOR = "\n\n";

export type StateResult =
  | { readonly ok: true; readonly state: string; readonly files: number }
  | { readonly ok: false; readonly reason: string };

export type WindowsResult =
  | {
      readonly ok: true;
      /** What each request sends, in reading order; one window when the skill fits the budget. */
      readonly windows: readonly string[];
      /** The files, or parts of files, each window carries besides its opener. */
      readonly contents: readonly (readonly string[])[];
      /** False when the skill needs more than MAX_WINDOWS windows and only the first are sent. */
      readonly complete: boolean;
      /** Windows the whole skill needs. */
      readonly needed: number;
      readonly files: number;
    }
  | { readonly ok: false; readonly reason: string };

/** A file as sent: its `=== path ===` label and its redacted, visible text. */
interface Section {
  readonly label: string;
  readonly body: string;
}

/** The whole skill in one state, or why it cannot be sent in one. The tuning lab asks about exactly this text. */
export function buildState(bundle: SkillBundle, budget: number = STATE_BUDGET): StateResult {
  const prepared = prepare(bundle);
  if (!prepared.ok) return prepared;
  const state = prepared.sections.map(render).join(SEPARATOR);
  if (state.length > budget) return { ok: false, reason: `skill text is ${state.length} characters, over the judge's ${budget} budget` };
  return { ok: true, state, files: prepared.sections.length };
}

/**
 * The skill in windows of at most `budget` characters. A skill that fits is one window, the same
 * text buildState sends. A longer one is cut between files, and inside a file between lines, never
 * dropped: every window opens with the SKILL.md (or its frontmatter), since the questions weigh what
 * a skill does against what it promises.
 */
export function buildWindows(bundle: SkillBundle, budget: number = STATE_BUDGET, maxWindows: number = MAX_WINDOWS): WindowsResult {
  const prepared = prepare(bundle);
  if (!prepared.ok) return prepared;
  const { sections } = prepared;
  const whole = sections.map(render).join(SEPARATOR);
  if (whole.length <= budget)
    return { ok: true, windows: [whole], contents: [sections.map((s) => s.label)], complete: true, needed: 1, files: sections.length };
  const { opener, rest } = openerOf(sections);
  const room = budget - (opener ? opener.length + SEPARATOR.length : 0);
  const packed = pack(
    rest.flatMap((s) => split(s, room)),
    room,
  );
  const sent = packed.slice(0, maxWindows);
  return {
    ok: true,
    windows: sent.map((w) => (opener ? `${opener}${SEPARATOR}${w.text}` : w.text)),
    contents: sent.map((w) => w.labels),
    complete: packed.length <= maxWindows,
    needed: packed.length,
    files: sections.length,
  };
}

function prepare(bundle: SkillBundle): { ok: true; sections: Section[] } | { ok: false; reason: string } {
  const files = bundle.files.filter(isJudgeable).sort(byReadingOrder);
  if (files.length === 0) return { ok: false, reason: "no text files to judge" };
  // A model answering about text it never saw would be a fail-open, so partial files are not sent.
  const cut = files.find((f) => f.truncated);
  if (cut) return { ok: false, reason: `${revealInvisible(cut.path)} was truncated while collecting; not sent to the judge` };
  return { ok: true, sections: files.map(section) };
}

const render = (s: Section): string => `=== ${s.label} ===\n${s.body}`;

/**
 * What opens every window: the first SKILL.md when it is short, else its frontmatter, else its start
 * cut to OPENER_MAX. Never nothing when there is a SKILL.md, or padding the description past the
 * opener's size would leave the windows that carry the code without the promise to weigh it against.
 */
function openerOf(sections: readonly Section[]): { opener: string; rest: readonly Section[] } {
  const [first, ...others] = sections;
  if (!first || !/(^|\/)SKILL\.md$/i.test(first.label)) return { opener: "", rest: sections };
  const whole = render(first);
  if (whole.length <= OPENER_MAX) return { opener: whole, rest: others };
  const frontmatter = /^---\n[\s\S]*?\n---(?=\n|$)/.exec(first.body)?.[0];
  const labelled = frontmatter ? `=== ${first.label} (frontmatter) ===\n${frontmatter}` : "";
  if (labelled && labelled.length <= OPENER_MAX) return { opener: labelled, rest: sections };
  const header = `=== ${first.label} (start) ===\n`;
  return { opener: `${header}${first.body.slice(0, cutAt(first.body, 0, OPENER_MAX - header.length, false))}`, rest: sections };
}

/** A section that fits in `room` as it is, or labelled parts that each fit, cut after a line break when there is one. */
function split(s: Section, room: number): string[] {
  const whole = render(s);
  if (whole.length <= room) return [whole];
  // Room for the longest label a part can have; a floor so a pathological path cannot stall the cut.
  const size = Math.max(room - `=== ${s.label} (part 99999 of 99999) ===\n`.length, MIN_PART);
  const bodies: string[] = [];
  for (let at = 0; at < s.body.length; ) {
    const end = cutAt(s.body, at, size);
    bodies.push(s.body.slice(at, end));
    at = end;
  }
  return bodies.map((body, i) => `=== ${s.label} (part ${i + 1} of ${bodies.length}) ===\n${body}`);
}

/**
 * Where a part that starts at `at` ends: after the last line break that fits (when `atLine`), else at
 * `size`, never inside a surrogate pair.
 */
function cutAt(text: string, at: number, size: number, atLine = true): number {
  if (text.length - at <= size) return text.length;
  const newline = atLine ? text.lastIndexOf("\n", at + size - 1) : -1;
  if (newline >= at) return newline + 1;
  const end = at + size;
  return /[\uDC00-\uDFFF]/.test(text[end] ?? "") ? end - 1 : end;
}

/** Pieces into windows of at most `room`, in order; a piece starts a new window when it does not fit the current one. */
function pack(pieces: readonly string[], room: number): { text: string; labels: string[] }[] {
  const windows: { text: string; labels: string[] }[] = [];
  for (const piece of pieces) {
    const label = piece.slice(4, piece.indexOf(" ===\n"));
    const last = windows.at(-1);
    if (last && last.text.length + SEPARATOR.length + piece.length <= room) {
      windows[windows.length - 1] = { text: `${last.text}${SEPARATOR}${piece}`, labels: [...last.labels, label] };
    } else windows.push({ text: piece, labels: [label] });
  }
  return windows;
}

function isJudgeable(f: SkillFile): boolean {
  return f.text !== undefined && f.virtualOf === undefined && ORDER[f.kind] !== undefined;
}

function byReadingOrder(a: SkillFile, b: SkillFile): number {
  return (ORDER[a.kind] ?? 9) - (ORDER[b.kind] ?? 9) || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

function section(f: SkillFile): Section {
  // The path is revealed on its own so a newline in a file name cannot forge another `=== path ===` header.
  const text = visible(redactSecrets(`=== ${revealInvisible(f.path)} ===\n${f.text ?? ""}`.replace(PEM_BLOCK, "[REDACTED PRIVATE KEY]")));
  const headerEnd = text.indexOf(" ===\n");
  return { label: text.slice(4, headerEnd), body: text.slice(headerEnd + 5) };
}

/**
 * Invisible and control characters become `<U+XXXX>` markers, line by line so line breaks survive.
 * The model then sees that something is hidden (the obfuscation probe needs that), hidden text
 * cannot instruct it unseen, and nothing invisible is shipped onward to a third party.
 */
function visible(text: string): string {
  return text.replace(/\r\n/g, "\n").split("\n").map(revealInvisible).join("\n");
}
