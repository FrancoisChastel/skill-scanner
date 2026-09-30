import type { Harness } from "./harnesses";

/** One change to the file system. Planners produce these without touching disk; `apply.ts` performs them. */
export type FileOp =
  | {
      readonly kind: "write";
      readonly path: string;
      /** Current contents; absent when the file does not exist yet. The executor refuses to write if the file changed since. */
      readonly before?: string;
      readonly after: string;
      readonly mode?: number;
      /** Keep `<path>.skill-scanner.bak` before the first modification (harness config files only). */
      readonly backup: boolean;
      /** A few words for the printed plan, e.g. "add hooks: PreToolUse, PostToolUse". */
      readonly summary: string;
    }
  | { readonly kind: "remove"; readonly path: string; readonly before: string; readonly summary: string }
  | { readonly kind: "remove-dir"; readonly path: string; readonly summary: string };

export type SectionId = Harness | "runtime" | "config" | "skill" | "state";

export interface PlanSection {
  readonly id: SectionId;
  readonly title: string;
  readonly ops: readonly FileOp[];
  /** Paths already in the wanted state. */
  readonly unchanged: readonly string[];
  readonly notes: readonly string[];
  readonly warnings: readonly string[];
  /** Set when setup refuses to touch this part (e.g. an unparsable file); the section has no ops. */
  readonly error?: string;
}

export const BACKUP_SUFFIX = ".skill-scanner.bak";

export const section = (id: SectionId, title: string, parts: Partial<Omit<PlanSection, "id" | "title">> = {}): PlanSection => ({
  id,
  title,
  ops: parts.ops ?? [],
  unchanged: parts.unchanged ?? [],
  notes: parts.notes ?? [],
  warnings: parts.warnings ?? [],
  ...(parts.error !== undefined ? { error: parts.error } : {}),
});

export const opVerb = (op: FileOp): "create" | "update" | "remove" | "delete" =>
  op.kind === "write" ? (op.before === undefined ? "create" : "update") : op.kind === "remove" ? "remove" : "delete";

/** A planned write, or nothing when the file already holds exactly this content. */
export function writeOp(
  path: string,
  before: string | undefined,
  after: string,
  summary: string,
  opts: { backup?: boolean; mode?: number; beforeMode?: number } = {},
): FileOp | undefined {
  const modeDiffers = opts.mode !== undefined && opts.beforeMode !== undefined && (opts.beforeMode & 0o777) !== opts.mode;
  if (before === after && !modeDiffers) return undefined;
  return {
    kind: "write",
    path,
    ...(before !== undefined ? { before } : {}),
    after,
    ...(opts.mode !== undefined ? { mode: opts.mode } : {}),
    backup: opts.backup ?? false,
    summary,
  };
}
