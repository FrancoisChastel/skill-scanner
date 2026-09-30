import type { Config } from "../config";
import type { ScanReport, Verdict } from "../core/types";

/**
 * Contract for the harness-agnostic guard used by Claude Code and Codex hooks, the OpenCode
 * plugin, and the Pi extension. Implemented in `src/guard/`.
 */

export type Harness = "claude-code" | "codex" | "opencode" | "pi";

/** Something a shell command is about to install, recognised before it runs. */
export type InstallIntent =
  | {
      readonly kind: "skills-cli";
      /** `add`, `update`, `check`, `experimental_install`, ... */
      readonly subcommand: string;
      /** Source argument for `add`, absent for updates. */
      readonly source?: string;
      /** `--skill` / `-s` selections. */
      readonly skills: readonly string[];
      readonly global: boolean;
      /** The exact command tokens, for rewriting. */
      readonly argv: readonly string[];
    }
  | { readonly kind: "git-clone"; readonly url: string; readonly dest?: string; readonly ref?: string }
  | { readonly kind: "codex-skill-installer"; readonly source: string; readonly paths: readonly string[] }
  | { readonly kind: "claude-plugin"; readonly action: "install" | "marketplace-add"; readonly target: string }
  | {
      readonly kind: "codex-plugin";
      readonly action: "add" | "marketplace-add";
      readonly target: string;
      /** `--marketplace <name>`, for `codex plugin add <plugin> -m <name>`. */
      readonly marketplace?: string;
    }
  | { readonly kind: "pi-install"; readonly source: string }
  /** `pi update <source>`, `pi update --extensions`, or `--all`: installed Pi packages move to newer versions. */
  | { readonly kind: "pi-update"; readonly source?: string }
  /** `git pull`, `reset`, `merge`, `rebase`, `checkout`, ... in the repository of an installed skill or plugin. */
  | { readonly kind: "git-update"; readonly dir: string; readonly subcommand: string }
  /** `claude plugin update`, `claude plugin marketplace update`, `codex plugin marketplace upgrade`. */
  | { readonly kind: "plugin-update"; readonly harness: "claude-code" | "codex"; readonly target?: string }
  | { readonly kind: "opencode-plugin"; readonly target: string }
  /** A download, copy, link, or extraction whose destination is inside a skill directory. */
  | { readonly kind: "write-to-skill-dir"; readonly dest: string; readonly via: string };

export type GuardAction = "allow" | "ask" | "deny";

export interface GuardDecision {
  readonly action: GuardAction;
  /** One paragraph for the agent (deny) or the user (ask). For allow, empty or a short note for the agent. */
  readonly reason: string;
  readonly verdict?: Verdict;
  readonly report?: ScanReport;
  /** When set, the harness may run this command instead (Claude Code `updatedInput`). */
  readonly rewrite?: string;
  /**
   * The command updates something that cannot be scanned before it runs, so it is only safe under
   * `guard`, which scans each update before it lands. A harness that cannot run `rewrite` instead
   * must refuse the command and show `rewrite`.
   */
  readonly guardRequired?: boolean;
  /** What was being installed or written, as the command named it (or the skill directory). */
  readonly source?: string;
}

export type TargetKind = "skill" | "plugin" | "package";

/** A skill found in a harness's skill directories and its last scan. */
export interface InstalledSkill {
  readonly harness: Harness | "shared";
  readonly scope: "user" | "project" | "plugin" | "system";
  readonly name: string;
  /** Directory as found (may be a symlink). */
  readonly path: string;
  readonly realPath: string;
  readonly digest: string;
  readonly verdict: Verdict;
  /** Top findings, one line each, for messages. */
  readonly summary: readonly string[];
  /** The user approved this exact digest with `skill-scanner trust`. */
  readonly trusted: boolean;
  /** A skill directory, a whole plugin version, or a package. Absent means `skill`. */
  readonly kind?: TargetKind;
  /** Other names the harness knows it by: the directory name, `plugin:skill` for plugin skills. */
  readonly aliases?: readonly string[];
  /** For multi-bundle targets (plugins): digests of the bundles that did not pass; trusting all of them trusts the target. */
  readonly riskyDigests?: readonly string[];
}

export interface GuardContext {
  readonly harness: Harness;
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly config: Config;
  readonly signal?: AbortSignal;
  /** Absolute node binary and runtime script, when known, so decisions can rewrite commands through `guard`. */
  readonly runtime?: { readonly node: string; readonly script: string };
}

export interface SkillRoot {
  readonly harness: Harness | "shared";
  readonly scope: "user" | "project" | "plugin" | "system";
  /** Directory whose children are skills (or, for plugin caches, contain skills). */
  readonly path: string;
  readonly kind: "skills" | "plugin-cache" | "package-cache";
  /** Skills may sit deeper than direct children (OpenCode's `skill/**` directories). */
  readonly recursive?: boolean;
}

export interface FlaggedEntry {
  readonly name: string;
  readonly path: string;
  readonly realPath: string;
  readonly digest: string;
  readonly verdict: "warn" | "block";
  readonly summary: readonly string[];
  readonly flaggedAt: string;
  /** Other names that resolve to this entry (directory name, `plugin:skill`). */
  readonly aliases?: readonly string[];
  readonly kind?: TargetKind;
  readonly harness?: Harness | "shared";
  /** See InstalledSkill.riskyDigests. */
  readonly riskyDigests?: readonly string[];
  /** Quarantine id when the skill was moved aside. Kept so a harness that cached the skill still blocks it by name. */
  readonly quarantined?: string;
}

export interface TrustEntry {
  readonly digest: string;
  readonly name: string;
  readonly path: string;
  readonly reason?: string;
  readonly trustedAt: string;
}

export interface TrustStore {
  readonly version: 1;
  readonly entries: readonly TrustEntry[];
}

export interface QuarantineRecord {
  /** Directory name under the quarantine directory; pass it to `restoreQuarantined`. */
  readonly id: string;
  /** Where the skill was found (may have been a symlink). */
  readonly originalPath: string;
  /** Where the skill's real directory was. */
  readonly realPath: string;
  readonly digest: string;
  readonly reason: string;
  readonly quarantinedAt: string;
  /** Symlinks removed because they pointed at the quarantined directory, recreated on restore. */
  readonly links: readonly { readonly path: string; readonly target: string }[];
  /** Absolute path of the quarantined directory. */
  readonly dir: string;
}

/** What a harness hook handler hands back to the process: exactly what to print and the exit code. */
export interface HookResult {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly exitCode: number;
  /** A deadline fired while work was still running; the process should exit promptly after printing. */
  readonly timedOut?: boolean;
}
