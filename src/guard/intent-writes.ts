import type { Redirect } from "./shell";
import { programName } from "./shell";

/**
 * Where a command writes files: downloads, copies, links, extractions, and output redirections.
 * Returns raw destination words; the caller resolves them and keeps those inside skill roots.
 */

export interface WriteDest {
  readonly dest: string;
  readonly via: string;
}

const NOT_FILES = /^(?:&|\/dev\/(?:null|stdout|stderr|tty|fd\/\d+))/;
const WRITE_REDIRECTS = new Set([">", ">>", ">|", "&>", "&>>", "<>"]);

export function writeDestinations(words: readonly string[], redirects: readonly Redirect[]): WriteDest[] {
  const prog = programName(words[0]);
  const args = words.slice(1);
  const out: WriteDest[] = [];
  const finder = FINDERS[prog];
  if (finder) for (const dest of finder(args)) out.push({ dest, via: prog });
  for (const r of redirects) {
    if (WRITE_REDIRECTS.has(r.op) && r.target && !NOT_FILES.test(r.target))
      out.push({ dest: r.target, via: prog ? `${prog} ${r.op}` : r.op });
  }
  return out;
}

const FINDERS: Readonly<Record<string, (args: readonly string[]) => string[]>> = {
  curl: curlDests,
  wget: wgetDests,
  cp: (a) => copyDest(a, COPY_VALUES),
  mv: (a) => copyDest(a, COPY_VALUES),
  install: (a) => copyDest(a, INSTALL_VALUES),
  ln: (a) => copyDest(a, COPY_VALUES, true),
  rsync: (a) => copyDest(a, RSYNC_VALUES).filter((d) => !/^[^/]*:/.test(d)),
  ditto: (a) => copyDest(a, new Set()),
  tar: tarDests,
  bsdtar: tarDests,
  unzip: unzipDests,
  tee: (a) => a.filter((w) => !w.startsWith("-")),
  dd: (a) => a.filter((w) => w.startsWith("of=")).map((w) => w.slice(3)),
};

/** Short options of curl that take a value; `o` is handled separately. */
const CURL_VALUE_LETTERS = new Set("dHXuAebcFTxwmrEKUYyzCDtQ".split(""));

function curlDests(args: readonly string[]): string[] {
  const out: string[] = [];
  let outputDir: string | undefined;
  let remoteName = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    const next = args[i + 1];
    if (a === "-o" || a === "--output" || a === "--output-dir") {
      if (a === "--output-dir") outputDir = next;
      else out.push(next ?? "");
      i += 1;
    } else if (a.startsWith("--output=")) out.push(a.slice(9));
    else if (a.startsWith("--output-dir=")) outputDir = a.slice(13);
    else if (a === "-O" || a === "--remote-name" || a === "--remote-name-all") remoteName = true;
    else if (/^-[a-zA-Z]{2,}/.test(a)) {
      const c = curlCluster(args, i);
      out.push(...c.outputs);
      remoteName ||= c.remote;
      i = c.last;
    }
  }
  if (remoteName) out.push(outputDir ?? ".");
  return out.filter((d) => d !== "" && d !== "-");
}

/** `-sSLo file`, `-oFILE`, `-sO`: letters until one that takes a value; `last` is the index of the last word consumed. */
function curlCluster(args: readonly string[], i: number): { outputs: string[]; remote: boolean; last: number } {
  const letters = args[i]!.slice(1);
  let remote = false;
  for (let k = 0; k < letters.length; k += 1) {
    const l = letters[k]!;
    if (l === "O") remote = true;
    if (l !== "o" && !CURL_VALUE_LETTERS.has(l)) continue;
    const attached = letters.slice(k + 1);
    const value = attached || args[i + 1];
    return { outputs: l === "o" && value !== undefined ? [value] : [], remote, last: attached ? i : i + 1 };
  }
  return { outputs: [], remote, last: i };
}

function wgetDests(args: readonly string[]): string[] {
  let file: string | undefined;
  let dir: string | undefined;
  let urls = 0;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    const next = args[i + 1];
    if (a === "-O" || a === "--output-document" || a === "-P" || a === "--directory-prefix") {
      if (a === "-O" || a === "--output-document") file = next;
      else dir = next;
      i += 1;
    } else if (a.startsWith("--output-document=")) file = a.slice(18);
    else if (/^-O./.test(a)) file = a.slice(2);
    else if (a.startsWith("--directory-prefix=")) dir = a.slice(19);
    else if (/^-P./.test(a)) dir = a.slice(2);
    else if (!a.startsWith("-")) urls += 1;
  }
  if (file !== undefined) return file === "-" ? [] : [file];
  return urls > 0 ? [dir ?? "."] : [];
}

const COPY_VALUES = new Set(["-S", "--suffix", "-t", "--target-directory"]);
const INSTALL_VALUES = new Set(["-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix", "-t", "--target-directory"]);
const RSYNC_VALUES = new Set([
  "-e",
  "--rsh",
  "--exclude",
  "--include",
  "--filter",
  "-f",
  "--files-from",
  "--exclude-from",
  "--include-from",
  "--chmod",
  "--chown",
  "-B",
  "--port",
  "--password-file",
  "--log-file",
  "-T",
  "--temp-dir",
  "--partial-dir",
  "--backup-dir",
  "--suffix",
  "--compare-dest",
  "--copy-dest",
  "--link-dest",
  "--max-size",
  "--min-size",
  "--timeout",
  "--bwlimit",
  "--out-format",
  "-M",
  "--remote-option",
]);

/** Destination of cp/mv/ln/install/rsync: `-t DIR`, else the last operand (for `ln` with one operand, the working directory). */
function copyDest(args: readonly string[], values: ReadonlySet<string>, single = false): string[] {
  const operands: string[] = [];
  let target: string | undefined;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    if (a === "--") {
      operands.push(...args.slice(i + 1));
      break;
    }
    if (a === "-t" || a === "--target-directory") target = args[i + 1];
    else if (a.startsWith("--target-directory=")) target = a.slice(20);
    if (!a.startsWith("-") || a === "-") operands.push(a);
    else if (values.has(a)) i += 1;
  }
  if (target !== undefined) return [target];
  if (operands.length >= 2) return [operands[operands.length - 1]!];
  return single && operands.length === 1 ? ["."] : [];
}

function tarDests(args: readonly string[]): string[] {
  const first = args[0] ?? "";
  const extracting =
    args.some((a) => a === "--extract" || a === "--get" || /^-[a-zA-Z]*x/.test(a)) || (/^[a-zA-Z]+$/.test(first) && first.includes("x"));
  if (!extracting) return [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    if (a === "-C" || a === "--directory" || a === "--cd") return [args[i + 1] ?? "."];
    if (a.startsWith("--directory=")) return [a.slice(12)];
  }
  return ["."];
}

function unzipDests(args: readonly string[]): string[] {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    if (a === "-d") return [args[i + 1] ?? "."];
    if (/^-d./.test(a)) return [a.slice(2)];
  }
  return args.some((a) => !a.startsWith("-")) ? ["."] : [];
}
