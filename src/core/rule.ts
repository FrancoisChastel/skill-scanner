import type { Region, RegionKind } from "./markdown";
import type { LineIndex } from "./text";
import type { Category, Confidence, FileKind, Language, Severity, SkillBundle, SkillFile } from "./types";

export interface RuleMeta {
  /** Stable id, `category/slug`. Used in suppressions, SARIF, and docs. */
  readonly id: string;
  readonly title: string;
  readonly category: Category;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** One or two sentences: what the pattern is and why it matters in a skill. */
  readonly description: string;
  readonly remediation?: string;
  /** Hard evidence the judge may confirm but never doubt. */
  readonly hard?: boolean;
}

/** How a file is used by an agent, which changes what a match means. */
export type FileRole = "instructions" | "reference" | "readme" | "code" | "manifest" | "other";

export interface Hit {
  readonly offset: number;
  readonly length: number;
  readonly message?: string;
  readonly severity?: Severity;
  readonly confidence?: Confidence;
  readonly evidence?: string;
}

/** A capability observed in a file, consumed by bundle-level correlation rules. */
export interface Signal {
  readonly tag: SignalTag;
  readonly file: string;
  readonly offset: number;
  readonly line: number;
  readonly detail: string;
}

export type SignalTag = "network-send" | "network" | "credential-read" | "env-dump" | "download" | "exec-dynamic" | "chmod-exec";

export interface FileContext {
  readonly bundle: SkillBundle;
  readonly file: SkillFile;
  readonly text: string;
  readonly index: LineIndex;
  readonly role: FileRole;
  /** Markdown regions, for markdown files only. */
  readonly regions?: readonly Region[];
  /** Set while rescanning a decoded payload; the payload is never documentation. */
  readonly decoded?: boolean;
  report(hit: Hit): void;
  signal(tag: SignalTag, offset: number, detail: string): void;
}

export interface FileRule extends RuleMeta {
  readonly scope: "file";
  readonly kinds: readonly FileKind[];
  readonly languages?: readonly Language[];
  check(ctx: FileContext): void;
}

export interface BundleFinding {
  readonly file: string;
  readonly line?: number;
  readonly snippet?: string;
  readonly message: string;
  readonly severity?: Severity;
  readonly confidence?: Confidence;
  readonly evidence?: string;
}

export interface BundleContext {
  readonly bundle: SkillBundle;
  readonly signals: readonly Signal[];
  report(finding: BundleFinding): void;
}

export interface BundleRule extends RuleMeta {
  readonly scope: "bundle";
  check(ctx: BundleContext): void;
}

export type Rule = FileRule | BundleRule;

/** What a match means in each Markdown region. `skip` ignores it; the others shift severity or confidence by one step. */
export type RegionEffect = "skip" | "keep" | "raise" | "lower-confidence" | "lower-severity";
export type RegionPolicy = Partial<Record<RegionKind, RegionEffect>>;

export const TEXT_KINDS: readonly FileKind[] = ["skill-md", "markdown", "script", "manifest", "text"];
export const MARKDOWN_KINDS: readonly FileKind[] = ["skill-md", "markdown"];
export const CODE_KINDS: readonly FileKind[] = ["script"];
