import type { FileRole } from "./rule";
import type { BundleKind, FileKind, Language } from "./types";

/** Pure classification from a path, a content sample, and the bundle it sits in. */

const EXT_LANG: Readonly<Record<string, Language>> = {
  sh: "shell",
  bash: "shell",
  zsh: "shell",
  ksh: "shell",
  fish: "shell",
  command: "shell",
  ps1: "powershell",
  psm1: "powershell",
  psd1: "powershell",
  bat: "other",
  cmd: "other",
  py: "python",
  pyw: "python",
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  jsx: "javascript",
  ts: "typescript",
  mts: "typescript",
  cts: "typescript",
  tsx: "typescript",
  rb: "ruby",
  pl: "perl",
  pm: "perl",
  go: "go",
  rs: "rust",
  php: "other",
  lua: "other",
  r: "other",
  swift: "other",
  java: "other",
  kt: "other",
  cs: "other",
  c: "other",
  h: "other",
  cpp: "other",
  applescript: "other",
  scpt: "other",
  vbs: "other",
  awk: "other",
};

const SHEBANG_LANG: ReadonlyArray<readonly [RegExp, Language]> = [
  [/\b(ba|z|k|da|fi)?sh\b/, "shell"],
  [/\bpython[0-9.]*\b|\buv\b/, "python"],
  [/\b(node|bun|deno|tsx|ts-node)\b/, "javascript"],
  [/\bpwsh\b|\bpowershell\b/, "powershell"],
  [/\bruby\b/, "ruby"],
  [/\bperl\b/, "perl"],
  [/\bosascript\b/, "other"],
];

const MANIFEST_NAMES = new Set([
  "package.json",
  "pyproject.toml",
  "pipfile",
  "gemfile",
  "go.mod",
  "cargo.toml",
  ".mcp.json",
  "mcp.json",
  "plugin.json",
  "marketplace.json",
  "hooks.json",
  "settings.json",
  "settings.local.json",
  "opencode.json",
  "opencode.jsonc",
  "config.toml",
  "gemini-extension.json",
]);

const MARKDOWN_EXT = new Set(["md", "markdown", "mdx", "mdc"]);
const TEXT_EXT = new Set([
  "txt",
  "json",
  "jsonc",
  "yaml",
  "yml",
  "toml",
  "ini",
  "cfg",
  "conf",
  "xml",
  "html",
  "htm",
  "css",
  "csv",
  "tsv",
  "env",
  "properties",
  "sql",
  "graphql",
  "svg",
  "lock",
  "gitignore",
  "editorconfig",
  "tmpl",
  "template",
  "j2",
  "jinja",
]);

const BINARY_EXT = new Set([
  "exe",
  "dll",
  "so",
  "dylib",
  "bin",
  "o",
  "a",
  "class",
  "jar",
  "war",
  "pyc",
  "pyo",
  "whl",
  "egg",
  "wasm",
  "node",
  "msi",
  "dmg",
  "pkg",
  "deb",
  "rpm",
  "appimage",
  "apk",
  "zip",
  "tar",
  "gz",
  "tgz",
  "bz2",
  "xz",
  "7z",
  "rar",
  "zst",
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "ico",
  "bmp",
  "tiff",
  "avif",
  "pdf",
  "woff",
  "woff2",
  "ttf",
  "otf",
  "eot",
  "mp3",
  "mp4",
  "wav",
  "mov",
  "webm",
  "ogg",
  "sqlite",
  "db",
  "docx",
  "xlsx",
  "pptx",
  "potx",
  "dotx",
  "xltx",
  "docm",
  "xlsm",
  "pptm",
  "odt",
  "ods",
  "odp",
]);

export function extensionOf(path: string): string {
  const base = basename(path).toLowerCase();
  const dot = base.lastIndexOf(".");
  return dot <= 0 ? (base.startsWith(".") ? base.slice(1) : "") : base.slice(dot + 1);
}

export function basename(path: string): string {
  const i = path.lastIndexOf("/");
  return i === -1 ? path : path.slice(i + 1);
}

export function languageOf(path: string, head: string): Language | undefined {
  const firstLine = head.startsWith("#!") ? head.slice(0, head.indexOf("\n") === -1 ? head.length : head.indexOf("\n")) : "";
  if (firstLine) {
    for (const [re, lang] of SHEBANG_LANG) if (re.test(firstLine)) return lang;
    return "other";
  }
  return EXT_LANG[extensionOf(path)];
}

/** Kind of a text file. Binary detection happens on bytes, before this is called. */
export function textKindOf(path: string, head: string, isBundleSkillMd: boolean): { kind: FileKind; language?: Language } {
  if (isBundleSkillMd) return { kind: "skill-md" };
  const name = basename(path).toLowerCase();
  const ext = extensionOf(path);
  if (MANIFEST_NAMES.has(name) || /^requirements.*\.txt$/.test(name) || /^constraints.*\.txt$/.test(name)) return { kind: "manifest" };
  if (MARKDOWN_EXT.has(ext)) return { kind: "markdown" };
  const language = languageOf(path, head);
  if (language) return { kind: "script", language };
  if (TEXT_EXT.has(ext) || ext === "") return { kind: "text" };
  return { kind: "text" };
}

export function isBinaryExtension(path: string): boolean {
  return BINARY_EXT.has(extensionOf(path));
}

/** Zip-based office documents. The macro-enabled ones (`m` suffix) can carry VBA. */
export const OFFICE_EXT = new Set([
  "docx",
  "xlsx",
  "pptx",
  "potx",
  "dotx",
  "xltx",
  "docm",
  "xlsm",
  "pptm",
  "potm",
  "dotm",
  "odt",
  "ods",
  "odp",
]);

/** Formats that carry executable code or hide other files, as opposed to plain assets. */
export const RISKY_BINARY_FORMATS = new Set([
  "elf",
  "mach-o",
  "pe",
  "wasm",
  "java-class",
  "python-bytecode",
  "zip",
  "gzip",
  "bzip2",
  "xz",
  "7z",
  "rar",
  "jar",
  "installer",
]);

export function binaryFormatOf(path: string, bytes: Uint8Array): string {
  const b = (i: number) => bytes[i] ?? -1;
  const ext = extensionOf(path);
  if (b(0) === 0x7f && b(1) === 0x45 && b(2) === 0x4c && b(3) === 0x46) return "elf";
  const m = ((b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3)) >>> 0;
  if (m === 0xfeedface || m === 0xfeedfacf || m === 0xcefaedfe || m === 0xcffaedfe) return "mach-o";
  if (m === 0xcafebabe) return ext === "class" ? "java-class" : "mach-o";
  if (b(0) === 0x4d && b(1) === 0x5a) return "pe";
  if (b(0) === 0x00 && b(1) === 0x61 && b(2) === 0x73 && b(3) === 0x6d) return "wasm";
  if (b(0) === 0x50 && b(1) === 0x4b && (b(2) === 0x03 || b(2) === 0x05)) {
    if (ext === "jar" || ext === "war" || ext === "whl" || ext === "apk") return "jar";
    if (OFFICE_EXT.has(ext)) return "office";
    return "zip";
  }
  if (b(0) === 0x1f && b(1) === 0x8b) return "gzip";
  if (b(0) === 0x42 && b(1) === 0x5a && b(2) === 0x68) return "bzip2";
  if (b(0) === 0xfd && b(1) === 0x37 && b(2) === 0x7a && b(3) === 0x58) return "xz";
  if (b(0) === 0x37 && b(1) === 0x7a && b(2) === 0xbc && b(3) === 0xaf) return "7z";
  if (b(0) === 0x52 && b(1) === 0x61 && b(2) === 0x72 && b(3) === 0x21) return "rar";
  if (ext === "pyc" || ext === "pyo") return "python-bytecode";
  if (ext === "msi" || ext === "dmg" || ext === "pkg" || ext === "deb" || ext === "rpm" || ext === "appimage") return "installer";
  if (b(0) === 0x89 && b(1) === 0x50 && b(2) === 0x4e && b(3) === 0x47) return "image";
  if (b(0) === 0xff && b(1) === 0xd8) return "image";
  if (b(0) === 0x47 && b(1) === 0x49 && b(2) === 0x46) return "image";
  if (b(0) === 0x25 && b(1) === 0x50 && b(2) === 0x44 && b(3) === 0x46) return "pdf";
  if (["png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tiff", "avif", "svg"].includes(ext)) return "image";
  if (["woff", "woff2", "ttf", "otf", "eot"].includes(ext)) return "font";
  if (["mp3", "mp4", "wav", "mov", "webm", "ogg"].includes(ext)) return "media";
  if (ext === "sqlite" || ext === "db") return "database";
  return "unknown";
}

/** Heuristic: a NUL byte, or many control bytes, in the first 8 KiB means binary. */
export function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8192);
  let control = 0;
  for (let i = 0; i < n; i += 1) {
    const c = bytes[i]!;
    if (c === 0) return true;
    if (c < 0x09 || (c > 0x0d && c < 0x20)) control += 1;
  }
  return n > 0 && control / n > 0.1;
}

const README_RE =
  /^(readme|changelog|changes|history|license|licence|copying|contributing|code_of_conduct|security|notice|authors)(\.[\w-]+)*$/i;

/** Repository plumbing that no agent loads: CI workflows, issue and pull-request templates. */
const REPO_META_RE = /(^|\/)\.github\//;
/** Detection signatures describe malware by design: YARA, Sigma, Snort/Suricata rules. */
const SIGNATURE_EXT = new Set(["yar", "yara", "sigma", "rules"]);

export function roleOf(file: { readonly path: string; readonly kind: FileKind }, bundleKind: BundleKind): FileRole {
  if (file.kind === "skill-md") return "instructions";
  const name = basename(file.path);
  if (REPO_META_RE.test(file.path) || SIGNATURE_EXT.has(extensionOf(file.path))) return "readme";
  if (file.kind === "markdown") {
    if (README_RE.test(name)) return "readme";
    // Claude Code plugin commands and agents are loaded as instructions.
    if (bundleKind === "plugin" && /(^|\/)(commands|agents)\//.test(file.path)) return "instructions";
    return "reference";
  }
  if (file.kind === "script") return "code";
  if (file.kind === "manifest") return "manifest";
  if (README_RE.test(name)) return "readme";
  return "other";
}

/**
 * Where a file sits can say it never runs when the skill is used: development files (test suites,
 * fixtures, eval harnesses, CI configuration, repository docs and examples), container build files
 * (they run inside the container), and reference documents about attacks. Rules count a match there
 * as a mention, and for development and container files only while nothing the skill runs or reads
 * as instructions refers to the file.
 */
export type PathContext = "dev" | "container" | "educational";

const DEV_PATH_RE =
  /(^|\/)(?:tests?|__tests__|spec|specs|fixtures?|testdata|test[-_]data|evals?|__snapshots__|__mocks__|examples?|docs|\.github|\.circleci|\.buildkite|\.gitlab)\/|(^|\/)test_[^/]+\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[cm]?[jt]sx?$|(^|\/)conftest\.py$|(^|\/)(?:\.gitlab-ci\.ya?ml|\.travis\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile|bitbucket-pipelines\.ya?ml)$/i;
const CONTAINER_PATH_RE = /(^|\/)(?:Dockerfile|Containerfile)(?:\.[\w-]+)?$|\.dockerfile$|(^|\/)\.devcontainer\//i;
/** Reference documents about attacks, threats, and detection. Their examples describe, they do not instruct. */
const EDUCATIONAL_PATH_RE =
  /(?:^|[/_.-])(?:attacks?|threats?|threat-model|malicious|malware|exploits?|vulnerabilit(?:y|ies)|iocs?|red-?team|pentest(?:ing)?|dangerous|injection|jailbreaks?|anti-?patterns?|security-(?:guide|review|patterns|checklist)|detection|signatures?)(?:[/_.-]|$)/i;

export function pathContextOf(file: { readonly path: string; readonly kind: FileKind }): PathContext | undefined {
  if (file.kind === "skill-md") return undefined;
  const path = file.path.split("!/")[0]!;
  if (DEV_PATH_RE.test(path)) return "dev";
  if (CONTAINER_PATH_RE.test(path)) return "container";
  if ((file.kind === "markdown" || file.kind === "text") && EDUCATIONAL_PATH_RE.test(path)) return "educational";
  return undefined;
}
