/** The shared vocabulary of the scanner. Pure data: nothing here touches the file system or the network. */

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["low", "medium", "high"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const CATEGORIES = [
  "prompt-injection",
  "hidden-content",
  "exfiltration",
  "credential-access",
  "remote-execution",
  "obfuscation",
  "persistence",
  "destructive",
  "privilege",
  "network",
  "secrets",
  "supply-chain",
  "packaging",
  "metadata",
  "execution-surface",
] as const;
export type Category = (typeof CATEGORIES)[number];

/** What a file is, as far as the rules care. */
export type FileKind = "skill-md" | "markdown" | "script" | "manifest" | "text" | "binary" | "symlink";

export type Language = "shell" | "powershell" | "python" | "javascript" | "typescript" | "ruby" | "perl" | "go" | "rust" | "other";

export interface SkillFile {
  /** POSIX path relative to the bundle root. Virtual files use `parent#pointer`, e.g. `package.json#scripts.postinstall`. */
  readonly path: string;
  readonly kind: FileKind;
  readonly language?: Language;
  readonly size: number;
  /** Decoded UTF-8 content for text files, possibly truncated. Absent for binaries and symlinks. */
  readonly text?: string;
  readonly truncated?: boolean;
  /** For binaries: the format detected from magic bytes, e.g. `elf`, `mach-o`, `pe`, `zip`. */
  readonly binaryFormat?: string;
  /** For binaries: the first 16 bytes as hex, for format-specific checks such as .pyc headers. */
  readonly header?: string;
  /** For Python bytecode: the names and string constants carved from its marshalled code, to compare with the source. */
  readonly strings?: readonly string[];
  readonly executable?: boolean;
  /** For symlinks: the link target as written, and whether it resolves outside the bundle root. */
  readonly linkTarget?: string;
  readonly linkEscapes?: boolean;
  /** Set on virtual files extracted from another file (a manifest command, a load-time shell snippet). */
  readonly virtualOf?: { readonly path: string; readonly line: number };
}

export interface Frontmatter {
  /** Parsed key/value pairs. Values are strings, string arrays, or nested records. */
  readonly data: Readonly<Record<string, FrontmatterValue>>;
  /** Raw frontmatter text, without the `---` fences. */
  readonly raw: string;
  /** 1-based line of the first frontmatter line in SKILL.md. */
  readonly startLine: number;
  /** 1-based line where the body starts. */
  readonly bodyStartLine: number;
  readonly errors: readonly string[];
}
export type FrontmatterValue =
  | string
  | boolean
  | number
  | null
  | readonly FrontmatterValue[]
  | { readonly [key: string]: FrontmatterValue };

export type BundleKind = "skill" | "plugin" | "package";

/** One unit of review: a skill directory, or the non-skill files of a repository (plugin manifests, packages). */
export interface SkillBundle {
  readonly kind: BundleKind;
  /** Display name: the skill `name` when valid, else the directory name. */
  readonly name: string;
  /** Path of the bundle root relative to the scan target, `.` for the target itself. */
  readonly root: string;
  /** Directory name of the bundle root, for the name/directory match check. */
  readonly dirName: string;
  readonly files: readonly SkillFile[];
  /** Present when the bundle has a SKILL.md. */
  readonly frontmatter?: Frontmatter;
  /** sha256 over paths and contents, stable across machines. */
  readonly digest: string;
  /** Limits hit while collecting, e.g. too many files. */
  readonly notes: readonly string[];
}

export interface Location {
  /** Path relative to the scan target. */
  readonly file: string;
  readonly line?: number;
  readonly column?: number;
  readonly endLine?: number;
  /** The offending text, trimmed and bounded. */
  readonly snippet?: string;
}

export type FindingSource = "static" | "correlation" | "judge" | `external:${string}`;

export interface JudgeNote {
  readonly model: string;
  /** Probability that the finding is a real risk, when the judge was asked about it. */
  readonly pTrue?: number;
  readonly effect: "confirmed" | "doubted" | "none";
}

export interface Finding {
  readonly ruleId: string;
  readonly title: string;
  readonly category: Category;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly message: string;
  readonly location: Location;
  /** Bundle name the finding belongs to. */
  readonly bundle: string;
  readonly source: FindingSource;
  /** Extra evidence, e.g. the decoded text behind an obfuscated payload. */
  readonly evidence?: string;
  readonly remediation?: string;
  readonly judge?: JudgeNote;
}

export type Verdict = "pass" | "warn" | "block";

export interface BundleReport {
  readonly bundle: SkillBundle;
  readonly findings: readonly Finding[];
  readonly verdict: Verdict;
}

export interface ScanReport {
  readonly schemaVersion: 1;
  readonly tool: { readonly name: string; readonly version: string };
  /** What was scanned, as the user gave it. */
  readonly target: string;
  readonly startedAt: string;
  readonly durationMs: number;
  readonly bundles: readonly BundleReport[];
  readonly verdict: Verdict;
  readonly counts: Readonly<Record<Severity, number>>;
  /** Which optional analyzers ran, and anything that failed without stopping the scan. */
  readonly analyzers: readonly AnalyzerRun[];
  readonly suppressed: number;
}

export interface AnalyzerRun {
  readonly name: string;
  readonly status: "ran" | "skipped" | "failed";
  readonly detail?: string;
}
