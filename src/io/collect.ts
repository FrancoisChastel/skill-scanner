import { createHash } from "node:crypto";
import { lstat, open, readdir, readlink, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { binaryFormatOf, extensionOf, isBinaryExtension, looksBinary, OFFICE_EXT, textKindOf } from "../core/classify";
import { splitFrontmatter } from "../core/frontmatter";
import { pycStrings } from "../core/pyc";
import type { BundleKind, Frontmatter, SkillBundle, SkillFile } from "../core/types";
import { readZip } from "./zip";

/**
 * Turn a directory (or a single SKILL.md, or a zip) into skill bundles. Never follows symlinks
 * below the root: a link is recorded as a link, with where it points, because the target is
 * outside what the author shipped.
 */

export interface CollectLimits {
  readonly maxFiles: number;
  /** Bytes of each file that are read and scanned. Larger files are truncated and reported. */
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
  readonly maxDepth: number;
  readonly maxArchiveBytes: number;
  readonly maxArchiveEntries: number;
}

export const DEFAULT_LIMITS: CollectLimits = Object.freeze({
  maxFiles: 5000,
  maxFileBytes: 4 * 1024 * 1024,
  maxTotalBytes: 128 * 1024 * 1024,
  maxDepth: 16,
  maxArchiveBytes: 16 * 1024 * 1024,
  maxArchiveEntries: 1000,
});

/** Directories that are never part of what a skill ships. Their presence is noted, not scanned. */
const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__MACOSX"]);
const ZIP_FORMATS = new Set(["zip", "jar", "office"]);
const ARCHIVE_EXT = new Set(["zip", "jar", "whl", "war", "apk", "skill", ...OFFICE_EXT]);

interface Entry {
  readonly rel: string;
  readonly abs: string;
  readonly kind: "file" | "symlink";
  readonly size: number;
  readonly mode: number;
}

export interface CollectResult {
  /** Absolute, real path of the scanned root. */
  readonly root: string;
  readonly bundles: readonly SkillBundle[];
}

export async function collect(target: string, limits: CollectLimits = DEFAULT_LIMITS): Promise<CollectResult> {
  const abs = resolve(target);
  const info = await stat(abs);
  if (info.isFile()) {
    if (basename(abs).toLowerCase() === "skill.md") return collect(dirname(abs), limits);
    return collectSingleFile(abs, limits);
  }
  const root = await realpath(abs);
  const notes: string[] = [];
  const entries = await walk(root, limits, notes);
  const files = await readEntries(root, entries, limits, notes);
  return { root, bundles: groupIntoBundles(files, notes) };
}

async function collectSingleFile(abs: string, limits: CollectLimits): Promise<CollectResult> {
  const notes: string[] = [];
  const s = await lstat(abs);
  const files = await readEntries(dirname(abs), [{ rel: basename(abs), abs, kind: "file", size: s.size, mode: s.mode }], limits, notes);
  return { root: dirname(abs), bundles: groupIntoBundles(files, notes) };
}

async function walk(root: string, limits: CollectLimits, notes: string[]): Promise<Entry[]> {
  const out: Entry[] = [];
  const skipped = new Map<string, number>();
  let full = false;
  const visit = async (dir: string, depth: number): Promise<void> => {
    if (depth > limits.maxDepth) {
      notes.push(`directory nesting deeper than ${limits.maxDepth} under ${relative(root, dir) || "."}; deeper files were not scanned`);
      return;
    }
    let names: string[];
    try {
      names = (await readdir(dir)).sort();
    } catch (e) {
      notes.push(`could not read ${relative(root, dir) || "."}: ${(e as Error).message}`);
      return;
    }
    for (const name of names) {
      if (out.length >= limits.maxFiles) {
        if (!full) notes.push(`more than ${limits.maxFiles} files; the rest were not scanned`);
        full = true;
        return;
      }
      const abs = join(dir, name);
      const rel = relative(root, abs).split(sep).join("/");
      let s: Awaited<ReturnType<typeof lstat>>;
      try {
        s = await lstat(abs);
      } catch {
        continue;
      }
      if (s.isSymbolicLink()) out.push({ rel, abs, kind: "symlink", size: 0, mode: s.mode });
      else if (s.isDirectory()) {
        if (SKIP_DIRS.has(name)) {
          skipped.set(name, (skipped.get(name) ?? 0) + 1);
          continue;
        }
        await visit(abs, depth + 1);
      } else if (s.isFile()) out.push({ rel, abs, kind: "file", size: s.size, mode: s.mode });
    }
  };
  await visit(root, 0);
  for (const [name, n] of skipped) if (name !== ".git") notes.push(`${n} ${name}/ director${n === 1 ? "y was" : "ies were"} not scanned`);
  return out;
}

async function readHead(abs: string, max: number): Promise<Uint8Array> {
  const fh = await open(abs, "r");
  try {
    const { size } = await fh.stat();
    const buf = new Uint8Array(Math.min(size, max));
    let off = 0;
    while (off < buf.length) {
      const { bytesRead } = await fh.read(buf, off, buf.length - off, off);
      if (bytesRead === 0) break;
      off += bytesRead;
    }
    return buf.subarray(0, off);
  } finally {
    await fh.close();
  }
}

interface ReadFile extends SkillFile {
  /** Content hash used for the bundle digest. */
  readonly hash: string;
}

/**
 * Read order under the byte budget: SKILL.md files first, then smallest first. Padding a skill with
 * large files then pushes out only the padding, never the instructions and scripts.
 */
function readOrder(entries: readonly Entry[]): Entry[] {
  const rank = (e: Entry): number => (isSkillMd(e.rel) ? 0 : 1);
  return [...entries].sort((a, b) => rank(a) - rank(b) || a.size - b.size || a.rel.localeCompare(b.rel));
}

async function readEntries(root: string, entries: readonly Entry[], limits: CollectLimits, notes: string[]): Promise<ReadFile[]> {
  const byEntry = new Map<Entry, ReadFile[]>();
  let total = 0;
  let exhausted = false;
  for (const e of readOrder(entries)) {
    const out: ReadFile[] = [];
    byEntry.set(e, out);
    if (e.kind === "symlink") {
      const target = await readlink(e.abs).catch(() => "");
      const resolved = isAbsolute(target) ? target : resolve(dirname(e.abs), target);
      const escapes = !isInside(root, resolved);
      out.push({ path: e.rel, kind: "symlink", size: 0, linkTarget: target, linkEscapes: escapes, hash: sha256(`link:${target}`) });
      continue;
    }
    if (total >= limits.maxTotalBytes) {
      if (!exhausted) notes.push(`scanned ${limits.maxTotalBytes} bytes in total; ${e.rel} and larger files were not read`);
      exhausted = true;
      continue;
    }
    // Archives are read whole (up to their own limit) so their entries can be scanned.
    const perFile = ARCHIVE_EXT.has(extensionOf(e.rel)) ? Math.max(limits.maxFileBytes, limits.maxArchiveBytes) : limits.maxFileBytes;
    const cap = Math.min(perFile, limits.maxTotalBytes - total);
    let bytes: Uint8Array;
    try {
      bytes = await readHead(e.abs, Math.max(cap, 0));
    } catch (err) {
      notes.push(`could not read ${e.rel}: ${(err as Error).message}`);
      continue;
    }
    total += bytes.byteLength;
    const truncated = e.size > bytes.byteLength;
    const executable = (e.mode & 0o111) !== 0;
    out.push(...toFiles(e.rel, bytes, e.size, truncated, executable, limits, notes, 0));
  }
  // Back to walk order, so output does not depend on file sizes.
  return entries.flatMap((e) => byEntry.get(e) ?? []);
}

function toFiles(
  path: string,
  bytes: Uint8Array,
  size: number,
  truncated: boolean,
  executable: boolean,
  limits: CollectLimits,
  notes: string[],
  depth: number,
): ReadFile[] {
  const hash = sha256(bytes);
  if (isBinaryExtension(path) || looksBinary(bytes)) {
    const utf16 = decodeUtf16(bytes);
    if (utf16 !== undefined) return [{ ...textFile(path, utf16, size, truncated, executable), hash }];
    const binaryFormat = binaryFormatOf(path, bytes);
    const header = Buffer.from(bytes.subarray(0, 16)).toString("hex");
    const file: ReadFile = {
      path,
      kind: "binary",
      size,
      binaryFormat,
      header,
      ...(binaryFormat === "python-bytecode" ? { strings: pycStrings(bytes) } : {}),
      ...(executable ? { executable } : {}),
      ...(truncated ? { truncated } : {}),
      hash,
    };
    // Archives are opened one level deep; Office documents two, because charts embed whole workbooks.
    if (!ZIP_FORMATS.has(binaryFormat) || depth > (binaryFormat === "office" ? 1 : 0)) return [file];
    if (truncated || bytes.byteLength > limits.maxArchiveBytes) {
      notes.push(`${path} is too large to look inside`);
      return [file];
    }
    const zip = readZip(bytes, {
      maxEntries: limits.maxArchiveEntries,
      maxEntryBytes: limits.maxFileBytes,
      maxTotalBytes: limits.maxArchiveBytes * 4,
    });
    for (const n of zip.notes) notes.push(`${path}: ${n}`);
    const inner: ReadFile[] = [];
    for (const entry of zip.entries) {
      const innerPath = `${path}!/${entry.name}`;
      if (entry.skipped === "directory") continue;
      if (!entry.data) {
        notes.push(`${innerPath}: not read (${entry.skipped})`);
        continue;
      }
      inner.push(...toFiles(innerPath, entry.data, entry.size, false, false, limits, notes, depth + 1));
    }
    return [file, ...inner];
  }
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return [{ ...textFile(path, text, size, truncated, executable), hash }];
}

function textFile(path: string, text: string, size: number, truncated: boolean, executable: boolean): SkillFile {
  const { kind, language } = textKindOf(path, text.slice(0, 256), false);
  return {
    path,
    kind,
    ...(language ? { language } : {}),
    size,
    text,
    ...(truncated ? { truncated } : {}),
    ...(executable ? { executable } : {}),
  };
}

/** UTF-16 text with a byte-order mark, which looks binary to a naive check. */
function decodeUtf16(bytes: Uint8Array): string | undefined {
  if (bytes.length < 2) return undefined;
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder("utf-16le").decode(bytes.subarray(2));
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder("utf-16be").decode(bytes.subarray(2));
  return undefined;
}

const isSkillMd = (p: string): boolean => /^skill\.md$/i.test(basename(p));

/** Every directory holding a SKILL.md is its own bundle; everything else belongs to the root bundle. */
function groupIntoBundles(files: readonly ReadFile[], notes: readonly string[]): SkillBundle[] {
  const skillDirs = [
    ...new Set(
      files
        .filter((f) => !f.path.includes("!/") && f.kind !== "symlink" && isSkillMd(f.path))
        .map((f) => (f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/")) : ".")),
    ),
  ].sort((a, b) => b.length - a.length);
  const owner = (p: string): string | undefined => skillDirs.find((d) => d === "." || p === d || p.startsWith(`${d}/`));
  const groups = new Map<string, ReadFile[]>();
  for (const f of files) {
    const d = owner(f.path) ?? "";
    groups.set(d, [...(groups.get(d) ?? []), f]);
  }
  const bundles: SkillBundle[] = [];
  for (const [dir, list] of groups) {
    const isSkill = dir !== "";
    const root = isSkill ? dir : ".";
    const rel = list.map((f) => {
      const path = root === "." ? f.path : f.path.slice(root.length + 1);
      if (f.kind !== "symlink" || !f.linkTarget || isAbsolute(f.linkTarget)) return { ...f, path };
      // A link escapes when it leaves the skill it belongs to, not only the scan root.
      const resolved = posix.normalize(posix.join(posix.dirname(path), f.linkTarget));
      return { ...f, path, linkEscapes: f.linkEscapes === true || resolved === ".." || resolved.startsWith("../") };
    });
    const skillMdIndex = isSkill ? rel.findIndex((f) => f.path === "SKILL.md") : -1;
    const mdIndex = skillMdIndex !== -1 ? skillMdIndex : isSkill ? rel.findIndex((f) => isSkillMd(f.path) && !f.path.includes("/")) : -1;
    let frontmatter: Frontmatter | undefined;
    const finalFiles: SkillFile[] = rel.map((f, i) => {
      const { hash: _hash, ...file } = f;
      if (i !== mdIndex || file.text === undefined) return file;
      frontmatter = splitFrontmatter(file.text).frontmatter;
      const { language: _language, ...rest } = file;
      return { ...rest, kind: "skill-md" as const };
    });
    const kind: BundleKind = isSkill
      ? "skill"
      : rel.some((f) => /(^|\/)\.claude-plugin\/plugin\.json$|^\.codex-plugin\/plugin\.json$|^hooks\/hooks\.json$/.test(f.path))
        ? "plugin"
        : "package";
    const dirName = root === "." ? "." : root.slice(root.lastIndexOf("/") + 1);
    const nameField = frontmatter?.data.name;
    bundles.push({
      kind,
      name: typeof nameField === "string" && nameField.trim() ? nameField.trim().slice(0, 64) : dirName === "." ? "(root)" : dirName,
      root,
      dirName,
      files: finalFiles.map(stripUndefined),
      ...(frontmatter ? { frontmatter } : {}),
      digest: digestOf(rel),
      notes: isSkill && root !== "." ? [] : [...notes],
    });
  }
  // Put skills first, the root package bundle last; drop an empty root bundle.
  const sorted = bundles
    .filter((b) => b.files.length > 0)
    .sort((a, b) => (a.kind === "skill" ? 0 : 1) - (b.kind === "skill" ? 0 : 1) || a.root.localeCompare(b.root));
  // Collection notes belong to the root; when every file sits in a skill, the first bundle carries them.
  if (notes.length > 0 && !sorted.some((b) => b.root === ".") && sorted[0]) sorted[0] = { ...sorted[0], notes: [...notes] };
  return sorted;
}

function stripUndefined(f: SkillFile): SkillFile {
  return Object.fromEntries(Object.entries(f).filter(([, v]) => v !== undefined)) as unknown as SkillFile;
}

function digestOf(files: readonly ReadFile[]): string {
  const h = createHash("sha256");
  for (const f of [...files].sort((a, b) => a.path.localeCompare(b.path))) h.update(`${f.path}\0${f.hash}\n`);
  return `sha256:${h.digest("hex")}`;
}

function sha256(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function isInside(root: string, p: string): boolean {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}
