/**
 * Contract for resolving and fetching skill sources the way `npx skills add`, `pi install`, and
 * Codex's skill-installer name them. Implemented in `src/sources/`.
 */

export type SourceKind = "local" | "git" | "npm" | "url";

export interface SourceSpec {
  /** What the user typed, unchanged. */
  readonly raw: string;
  readonly kind: SourceKind;
  /** Absolute path for `local`. */
  readonly path?: string;
  /** Clone URL for `git`, e.g. `https://github.com/owner/repo.git`. */
  readonly cloneUrl?: string;
  /** Branch, tag, or commit, when given. */
  readonly ref?: string;
  /** Sub-directory inside the repository, when given (tree URLs, `owner/repo/path`). */
  readonly subpath?: string;
  /** Skill names selected in the source itself (`owner/repo@skill`, `#ref@skill`). */
  readonly skills?: readonly string[];
  /** npm package spec for `npm`, e.g. `@scope/pkg@1.2.3`. */
  readonly packageSpec?: string;
  /** Direct URL for `url` (archives, raw SKILL.md, well-known endpoints). */
  readonly url?: string;
  /** Short display form, e.g. `owner/repo`. */
  readonly display: string;
}

export interface FetchedSource {
  readonly spec: SourceSpec;
  /** Directory to scan: the checkout, or its subpath. */
  readonly dir: string;
  /** Root of the fetched copy (the git checkout for `git`), usable as a clone mirror. */
  readonly root: string;
  /** Commit that was fetched, for git sources. */
  readonly commit?: string;
  /** What npm resolved, `name@version (integrity)`, for npm sources: tags and ranges can move after a scan. */
  readonly resolved?: string;
  /** Remove every temporary file. Safe to call twice. */
  cleanup(): Promise<void>;
}

export interface FetchOptions {
  readonly signal?: AbortSignal;
  /** Per-operation timeout. Default 120 s. */
  readonly timeoutMs?: number;
  readonly env?: NodeJS.ProcessEnv;
}
