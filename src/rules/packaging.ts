import { basename, extensionOf, RISKY_BINARY_FORMATS } from "../core/classify";
import { bytecodeDiverges, bytecodeOnlyStrings, pycHeader } from "../core/pyc";
import type { BundleContext, BundleRule } from "../core/rule";
import { isInvisible } from "../core/text";
import type { SkillFile } from "../core/types";
import { CREDENTIAL_CONFIG_PATTERNS, SECRET_STORE_PATTERNS } from "./lists";

/** What ships in the skill directory, independent of what the text says. */

const EXECUTABLE_FORMATS = new Set(["elf", "mach-o", "pe", "wasm", "java-class", "python-bytecode"]);
const ARCHIVE_FORMATS = new Set(["zip", "gzip", "bzip2", "xz", "7z", "rar", "jar", "installer", "office"]);
const HARMLESS_EXT = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "ico",
  "bmp",
  "svg",
  "pdf",
  "txt",
  "md",
  "json",
  "csv",
  "woff",
  "woff2",
  "ttf",
  "otf",
  "mp3",
  "mp4",
  "wav",
]);
const ALLOWED_DOTFILES = new Set([
  ".gitignore",
  ".gitattributes",
  ".gitkeep",
  ".keep",
  ".editorconfig",
  ".prettierrc",
  ".prettierignore",
  ".npmignore",
  ".nvmrc",
  ".node-version",
  ".python-version",
  ".tool-versions",
  ".DS_Store",
  ".env.example",
  ".env.sample",
  ".env.template",
  ".markdownlint.json",
  ".markdownlint.yaml",
  ".eslintrc.json",
  ".eslintrc.js",
  ".eslintignore",
  ".dockerignore",
  ".gitmodules",
  ".skill-lock.json",
]);
const SHADOWED_COMMANDS = new Set([
  "git",
  "npm",
  "npx",
  "node",
  "python",
  "python3",
  "pip",
  "pip3",
  "curl",
  "wget",
  "ssh",
  "scp",
  "sudo",
  "ls",
  "cat",
  "sh",
  "bash",
  "zsh",
  "env",
  "gh",
  "claude",
  "codex",
  "opencode",
  "pi",
  "bun",
  "uv",
  "make",
  "docker",
  "kubectl",
  "aws",
]);

/**
 * Bytecode next to its source is the "pyc shadowing" trick: Python imports the .pyc, reviewers read
 * the .py. Unchecked-hash pycs are never compared with the source; for the others, the names in the
 * bytecode must all appear in the source.
 */
/** Names pytest's assertion rewriting adds to a test module's bytecode (`@py_assert1`, `%(py6)s`, `_call_reprcompare`...). */
const PYTEST_REWRITE_NAMES =
  /^(?:@|_pytest\b|_call_|_format_|_saferepr|_should_repr|_check_if|_ar_|py\d+$|builtins$|AssertionError$|locals$|append$|return$)/;

function reportBytecode(ctx: BundleContext, f: SkillFile): void {
  const source = f.path
    .replace(/__pycache__\//, "")
    .replace(/\.cpython-\d+(?:-pytest-\d+(?:\.\d+)*)?(?:\.opt-\d)?/, "")
    .replace(/\.py[co]$/, ".py");
  const src = ctx.bundle.files.find((g) => g.path === source);
  if (!src) {
    ctx.report({ file: f.path, message: "Compiled Python bytecode with no reviewable source" });
    return;
  }
  const header = pycHeader(f.header);
  // pytest rewrites asserts in test modules and caches them as `*-pytest-X.Y.pyc`; its helpers are not in the source.
  const pytest = /-pytest-\d+(?:\.\d+)*\.pyc$/.test(f.path);
  const strings = pytest ? f.strings?.filter((s) => !PYTEST_REWRITE_NAMES.test(s)) : f.strings;
  const diff = strings && src.text !== undefined ? bytecodeOnlyStrings(strings, src.text) : undefined;
  const evidence =
    diff && (diff.names.length > 0 || diff.constants.length > 0)
      ? `in the bytecode but not in ${source}: ${[...diff.names, ...diff.constants.map((c) => JSON.stringify(c))].slice(0, 16).join(", ")}`
      : undefined;
  if (diff && bytecodeDiverges(diff)) {
    ctx.report({
      file: f.path,
      severity: "critical",
      message: `Bytecode uses ${diff.names.slice(0, 6).join(", ")}, which ${source} never mentions: it was compiled from code you cannot read`,
      ...(evidence ? { evidence } : {}),
    });
  } else if (header.invalidation === "unchecked-hash") {
    ctx.report({
      file: f.path,
      message: `Unchecked-hash bytecode: Python runs it instead of ${source} without checking that they match`,
      ...(evidence ? { evidence } : {}),
    });
  } else if (header.sourceSize !== undefined && header.sourceSize !== src.size) {
    // Python checks a timestamp pyc's recorded size against the source and recompiles on a mismatch, so it never runs.
    ctx.report({
      file: f.path,
      severity: "low",
      message: `Stale bytecode: it records a ${header.sourceSize}-byte source but ${source} is ${src.size} bytes, so Python recompiles instead of loading it`,
      ...(evidence ? { evidence } : {}),
    });
  } else {
    ctx.report({
      file: f.path,
      severity: "low",
      message: `Bytecode cache for ${source}. Harmless if created by running the skill locally; a skill should not ship it`,
    });
  }
}

/** Config and ignore files that tell a security scanner what not to report, by file name. */
const SCANNER_SUPPRESSION_FILES: ReadonlyArray<readonly [RegExp, string]> = [
  [/^\.gitleaksignore$/i, "gitleaks"],
  [/^\.?gitleaks\.toml$/i, "gitleaks"],
  [/^\.semgrepignore$/i, "Semgrep"],
  [/^osv-scanner\.toml$/i, "OSV-Scanner"],
  [/^\.trufflehogignore$/i, "TruffleHog"],
  [/^\.secrets\.baseline$/i, "detect-secrets"],
  [/^\.snyk$/i, "Snyk"],
  [/^\.skill-scanner/i, "skill-scanner"],
  [/^\.bandit$/i, "Bandit"],
  [/^\.trivyignore(?:\.yaml)?$/i, "Trivy"],
  [/^\.grype\.ya?ml$/i, "Grype"],
];

function scannerSuppressionOf(name: string): string | undefined {
  return SCANNER_SUPPRESSION_FILES.find(([re]) => re.test(name))?.[1];
}

/** An allowlist that waves through whole paths, regexes, or everything, rather than one reviewed finding. */
const BROAD_ALLOWLIST_RE =
  /^\s*(?:paths|regexes|stopwords)\s*=|^\s*(?:\*|\*\*|\*\*\/\*|\.\*|\/|\.\/?)\s*$|["']\*\*?["']|^\s*-\s*["']?\*\*?(?:\/\*)?["']?\s*$|\bexclude[-_]?dirs?\b|^\s*skips?\s*[:=]/im;

export const packagingRules: readonly BundleRule[] = [
  {
    id: "packaging/executable-binary",
    title: "Ships a compiled executable",
    category: "packaging",
    severity: "high",
    confidence: "high",
    hard: true,
    description:
      "Native executables, WebAssembly, Java classes, or Python bytecode cannot be reviewed as text, and bytecode can shadow the source next to it. Malicious skill campaigns ship payloads this way.",
    remediation: "Install only if you trust the author enough to run their binaries unreviewed, or rebuild them from source yourself.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        const fmt = f.binaryFormat;
        const inPycache = /(^|\/)__pycache__\//.test(f.path);
        if (!(fmt && EXECUTABLE_FORMATS.has(fmt)) && !inPycache) continue;
        if (fmt === "python-bytecode" || inPycache) {
          reportBytecode(ctx, f);
          continue;
        }
        ctx.report({ file: f.path, message: `Ships a ${fmt} executable (${f.size} bytes)` });
      }
    },
  },
  {
    id: "packaging/archive",
    title: "Ships an archive",
    category: "packaging",
    severity: "medium",
    confidence: "high",
    description:
      "Archives (zip, tar, Office documents, installers) hide their contents from review. The scanner looks inside zip-based archives it can read; anything else is unscanned.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        if (!f.binaryFormat || !ARCHIVE_FORMATS.has(f.binaryFormat)) continue;
        const scanned = ctx.bundle.files.some((g) => g.path.startsWith(`${f.path}!/`));
        ctx.report({
          file: f.path,
          severity: f.binaryFormat === "installer" ? "high" : scanned && f.binaryFormat === "office" ? "low" : "medium",
          message: scanned
            ? `${f.binaryFormat} archive; its entries were extracted and scanned`
            : `${f.binaryFormat} archive whose contents were not scanned`,
        });
      }
    },
  },
  {
    id: "packaging/extension-mismatch",
    title: "File content does not match its extension",
    category: "packaging",
    severity: "critical",
    confidence: "high",
    hard: true,
    description:
      "An executable or archive named like an image, document, or text file. The disguise only makes sense if the file is meant to evade review.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        const ext = extensionOf(f.path);
        if (
          f.binaryFormat &&
          RISKY_BINARY_FORMATS.has(f.binaryFormat) &&
          HARMLESS_EXT.has(ext) &&
          !(f.binaryFormat === "zip" && ext === "json")
        ) {
          ctx.report({ file: f.path, message: `Named .${ext} but its bytes are a ${f.binaryFormat} file` });
        }
      }
    },
  },
  {
    id: "packaging/symlink",
    title: "Symlink out of the skill directory",
    category: "packaging",
    severity: "high",
    confidence: "high",
    hard: true,
    description:
      "A symlink whose target is absolute or outside the skill. When the agent reads the 'reference', it reads that target instead; `npx skills add` also copies the target's content into the installed skill, so a link to your SSH private key ships your key.",
    remediation: "Do not install. Skills should contain files, not links to the rest of the machine.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        if (f.kind !== "symlink") continue;
        const target = f.linkTarget ?? "";
        const sensitive =
          [...SECRET_STORE_PATTERNS, ...CREDENTIAL_CONFIG_PATTERNS].some((re) =>
            new RegExp(re.source, re.flags.replace("g", "")).test(target),
          ) || /(?:^|\/)\.env$|\/etc\/(?:passwd|shadow)/.test(target);
        if (!f.linkEscapes && !target.startsWith("/") && !sensitive) continue;
        ctx.report({
          file: f.path,
          snippet: `${f.path} -> ${target}`,
          severity: sensitive ? "critical" : "high",
          message: `Links to ${target}${sensitive ? ", a credential or system file" : ", outside the skill"}`,
        });
      }
    },
  },
  {
    id: "packaging/unexpected-dotfile",
    title: "Hidden file or directory",
    category: "packaging",
    severity: "low",
    confidence: "medium",
    description:
      "Dotfiles are hidden from normal listings. `.env` files may carry secrets or overrides; editor and agent config directories inside a skill can auto-run tasks.",
    scope: "bundle",
    check(ctx) {
      const seen = new Set<string>();
      for (const f of ctx.bundle.files) {
        const parts = f.path.split("!/")[0]!.split("/");
        const hidden = parts.find((p) => p.startsWith(".") && p !== "." && p !== "..");
        if (!hidden || ALLOWED_DOTFILES.has(hidden) || hidden.startsWith("._") || seen.has(hidden)) continue;
        if (hidden === ".claude-plugin" || hidden === ".codex-plugin" || hidden === ".github") continue;
        // Reported by packaging/scanner-suppression-file instead.
        if (scannerSuppressionOf(hidden)) continue;
        seen.add(hidden);
        // A plugin's .mcp.json is where its MCP servers live; surface/mcp-server reports them.
        if (hidden === ".mcp.json") continue;
        // Config that runs or holds secrets; a Cursor rules folder is only instructions for another editor.
        const risky =
          /^\.(?:env(?:\..+)?|npmrc|pypirc|netrc|vscode|claude|codex|opencode|pi|git)$/.test(hidden) ||
          (hidden === ".cursor" && !/(^|\/)\.cursor\/rules\//.test(f.path));
        ctx.report({
          file: f.path,
          severity: risky ? "medium" : "low",
          message: `Contains hidden ${hidden}${risky ? ", which can hold secrets or configuration that runs automatically" : ""}`,
        });
      }
    },
  },
  {
    id: "packaging/deceptive-filename",
    title: "Deceptive file name",
    category: "packaging",
    severity: "high",
    confidence: "high",
    description:
      "A file name with invisible or right-to-left characters, or a double extension such as `report.pdf.sh`, so it looks like something else.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        const name = basename(f.path.split("!/").pop()!);
        if ([...name].some((c) => isInvisible(c.codePointAt(0)!))) {
          ctx.report({ file: f.path, message: "File name contains invisible or direction-changing characters" });
        } else if (/\.(?:pdf|docx?|xlsx?|png|jpe?g|txt|md)\.(?:sh|bash|py|js|exe|bat|cmd|ps1|command|app|scr)$/i.test(name)) {
          ctx.report({ file: f.path, severity: "medium", message: `${name} has a double extension that hides an executable type` });
        }
      }
    },
  },
  {
    id: "packaging/plugin-bin-shadowing",
    title: "Plugin puts a common command name on PATH",
    category: "execution-surface",
    severity: "critical",
    confidence: "medium",
    description:
      "Claude Code puts a plugin's `bin/` on the Bash tool's PATH. An executable named like `git`, `npm`, or `curl` there can intercept the agent's commands.",
    scope: "bundle",
    check(ctx) {
      const isPlugin = ctx.bundle.kind === "plugin" || ctx.bundle.files.some((f) => /(^|\/)\.claude-plugin\/plugin\.json$/.test(f.path));
      if (!isPlugin) return;
      for (const f of ctx.bundle.files) {
        const file = /^bin\/([^/]+)$/.exec(f.path)?.[1];
        if (!file) continue;
        const name = file.replace(/\.(?:sh|js|py|exe|cmd)$/i, "");
        const shadows = SHADOWED_COMMANDS.has(name);
        ctx.report({
          file: f.path,
          severity: shadows ? "critical" : "medium",
          message: shadows ? `bin/${file} can shadow the system \`${name}\` command` : `bin/${file} is added to the agent's PATH`,
        });
      }
    },
  },
  {
    id: "packaging/duplicate-skill-file",
    title: "More than one SKILL.md variant",
    category: "packaging",
    severity: "medium",
    confidence: "high",
    description:
      "Both `SKILL.md` and another casing of it. Different harnesses and file systems may load different ones, so what you review may not be what runs.",
    scope: "bundle",
    check(ctx) {
      const variants = ctx.bundle.files.filter((f) => /^skill\.md$/i.test(f.path));
      if (variants.length > 1) ctx.report({ file: variants[1]!.path, message: `Found ${variants.map((v) => v.path).join(" and ")}` });
    },
  },
  {
    id: "packaging/incomplete-scan",
    title: "Part of the skill was not scanned",
    category: "packaging",
    severity: "medium",
    confidence: "high",
    description:
      "A file or the skill as a whole exceeded the scanner's limits, so some content was not read. Padding a skill past a scanner's limits is a known evasion.",
    scope: "bundle",
    check(ctx) {
      for (const note of ctx.bundle.notes) ctx.report({ file: ".", message: note });
      for (const f of ctx.bundle.files) {
        const isArchive = f.binaryFormat !== undefined && ARCHIVE_FORMATS.has(f.binaryFormat);
        if (f.truncated && (f.kind !== "binary" || isArchive))
          ctx.report({
            file: f.path,
            severity: f.kind === "skill-md" ? "high" : "medium",
            message: `${f.path} is ${f.size} bytes; only the first part was scanned`,
          });
      }
    },
  },
  {
    id: "packaging/scanner-suppression-file",
    title: "Ships configuration that silences a security scanner",
    category: "packaging",
    severity: "medium",
    confidence: "high",
    description:
      "An ignore, baseline, or config file for a security scanner (gitleaks, Semgrep, TruffleHog, detect-secrets, Snyk, Bandit, Trivy, Grype, OSV-Scanner, or skill-scanner itself). A skill has no use for one except to switch a scanner off for its own content.",
    remediation:
      "Remove the file. skill-scanner never reads configuration from the target it scans, and runs its optional scanners with their ignore files disabled, except gitleaks' .gitleaksignore, which gitleaks cannot be told to skip.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        const name = basename(f.path.split("!/").pop()!);
        const scanner = scannerSuppressionOf(name);
        if (!scanner) continue;
        const broad = f.text !== undefined && BROAD_ALLOWLIST_RE.test(f.text);
        const honored = /^\.gitleaksignore$/i.test(name);
        ctx.report({
          file: f.path,
          severity: broad ? "high" : "medium",
          message: `Ships ${name}, which tells ${scanner} what not to report${broad ? " and allowlists whole paths or patterns" : ""}. ${
            honored
              ? "gitleaks honors it even when run by skill-scanner (it has no flag to ignore the file)"
              : "Scanners run by skill-scanner ignore it; other tools you run on this skill may not"
          }`,
        });
      }
    },
  },
];
