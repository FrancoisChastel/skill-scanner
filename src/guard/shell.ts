/**
 * A small POSIX-ish shell tokenizer: enough to find the simple commands in a command line
 * (quotes, escapes, operators, subshells, substitutions, heredocs) without running anything.
 * It does not expand variables or globs; callers treat what it returns as a best guess.
 */

export interface Redirect {
  readonly op: string;
  readonly target: string;
  /** Heredoc or here-string text, for `<<`, `<<-`, and `<<<`. */
  readonly body?: string;
}

export interface SimpleCommand {
  readonly words: readonly string[];
  readonly redirects: readonly Redirect[];
  /** The operator between this command and the previous one (`|`, `&&`, `;`, newline, ...). */
  readonly after?: string;
}

export interface ShellParse {
  readonly commands: readonly SimpleCommand[];
  /** Bodies of `$(...)`, backticks, and `<(...)`: commands that run too. */
  readonly substitutions: readonly string[];
}

/** Commands longer than this are only partly examined. */
const MAX_INPUT = 256 * 1024;

type Token =
  | { readonly t: "word"; readonly v: string }
  | { readonly t: "op"; readonly v: string }
  | { readonly t: "redir"; readonly op: string; readonly target: string; readonly heredoc?: number };

interface LexState {
  readonly src: string;
  i: number;
  readonly toks: Token[];
  readonly subs: string[];
  readonly bodies: string[];
  pending: { readonly delim: string; readonly strip: boolean; readonly index: number }[];
}

const OPERATORS = [
  "&>>",
  "<<<",
  "<<-",
  "&&",
  "||",
  ";;",
  "|&",
  "&>",
  ">>",
  ">|",
  ">&",
  "<<",
  "<&",
  "<>",
  ";",
  "|",
  "&",
  "(",
  ")",
  "<",
  ">",
];
const REDIRECTS = new Set(["&>>", "<<<", "<<-", "&>", ">>", ">|", ">&", "<<", "<&", "<>", "<", ">"]);
const WORD_BREAK = new Set([" ", "\t", "\r", "\n", ";", "&", "|", "(", ")", "<", ">"]);

export function parseShell(input: string): ShellParse {
  const s: LexState = { src: input.slice(0, MAX_INPUT), i: 0, toks: [], subs: [], bodies: [], pending: [] };
  while (s.i < s.src.length) step(s);
  return group(s);
}

function step(s: LexState): void {
  const c = s.src[s.i]!;
  if (c === " " || c === "\t" || c === "\r") {
    s.i += 1;
    return;
  }
  if (c === "\\" && s.src[s.i + 1] === "\n") {
    s.i += 2;
    return;
  }
  if (c === "\n") {
    s.i += 1;
    s.toks.push({ t: "op", v: "\n" });
    readHeredocs(s);
    return;
  }
  if (c === "#") {
    const nl = s.src.indexOf("\n", s.i);
    s.i = nl === -1 ? s.src.length : nl;
    return;
  }
  if ((c === "<" || c === ">") && s.src[s.i + 1] === "(") {
    const end = findClosingParen(s.src, s.i + 2);
    s.subs.push(s.src.slice(s.i + 2, end));
    s.i = end + 1;
    s.toks.push({ t: "word", v: "/dev/fd/63" });
    return;
  }
  const op = OPERATORS.find((o) => s.src.startsWith(o, s.i));
  if (op) {
    s.i += op.length;
    if (REDIRECTS.has(op)) lexRedirect(s, op);
    else s.toks.push({ t: "op", v: op });
    return;
  }
  const w = readWord(s);
  // `2>file`, `1>&2`: a bare number glued to a redirect is a file descriptor, not an argument.
  if (!w.quoted && /^\d+$/.test(w.text) && (s.src[s.i] === ">" || s.src[s.i] === "<")) return;
  s.toks.push({ t: "word", v: w.text });
}

function lexRedirect(s: LexState, op: string): void {
  while (s.src[s.i] === " " || s.src[s.i] === "\t") s.i += 1;
  const next = s.src[s.i];
  const target = next === undefined || WORD_BREAK.has(next) ? "" : readWord(s).text;
  if (op === "<<" || op === "<<-") {
    const index = s.bodies.length;
    s.bodies.push("");
    s.pending.push({ delim: target, strip: op === "<<-", index });
    s.toks.push({ t: "redir", op, target, heredoc: index });
    return;
  }
  s.toks.push({ t: "redir", op, target });
}

function readHeredocs(s: LexState): void {
  for (const h of s.pending) {
    const lines: string[] = [];
    while (s.i < s.src.length) {
      const nl = s.src.indexOf("\n", s.i);
      const end = nl === -1 ? s.src.length : nl;
      const line = s.src.slice(s.i, end);
      s.i = nl === -1 ? s.src.length : nl + 1;
      if ((h.strip ? line.replace(/^\t+/, "") : line) === h.delim) break;
      lines.push(line);
    }
    s.bodies[h.index] = lines.join("\n");
  }
  s.pending = [];
}

function readWord(s: LexState): { text: string; quoted: boolean } {
  let out = "";
  let quoted = false;
  while (s.i < s.src.length) {
    const c = s.src[s.i]!;
    if (WORD_BREAK.has(c)) break;
    if (c === "\\") {
      const n = s.src[s.i + 1];
      s.i += 2;
      if (n !== undefined && n !== "\n") out += n;
      quoted = true;
    } else if (c === "'") {
      const end = s.src.indexOf("'", s.i + 1);
      const stop = end === -1 ? s.src.length : end;
      out += s.src.slice(s.i + 1, stop);
      s.i = stop + 1;
      quoted = true;
    } else if (c === "$" && s.src[s.i + 1] === "'") {
      const r = readAnsiC(s.src, s.i + 2);
      out += r.text;
      s.i = r.end;
      quoted = true;
    } else if (c === '"') {
      out += readDouble(s);
      quoted = true;
    } else if (c === "$" || c === "`") {
      out += readDollar(s);
    } else {
      out += c;
      s.i += 1;
    }
  }
  return { text: out, quoted };
}

function readDouble(s: LexState): string {
  let out = "";
  s.i += 1;
  while (s.i < s.src.length) {
    const c = s.src[s.i]!;
    if (c === '"') {
      s.i += 1;
      break;
    }
    if (c === "\\" && '$`"\\\n'.includes(s.src[s.i + 1] ?? "")) {
      if (s.src[s.i + 1] !== "\n") out += s.src[s.i + 1];
      s.i += 2;
    } else if (c === "$" || c === "`") out += readDollar(s);
    else {
      out += c;
      s.i += 1;
    }
  }
  return out;
}

/** `$(...)`, `` `...` ``, `$((...))`, `${...}`, or a plain `$`. Substitution bodies are recorded as commands. */
function readDollar(s: LexState): string {
  const c = s.src[s.i]!;
  if (c === "`") {
    let j = s.i + 1;
    while (j < s.src.length && s.src[j] !== "`") j += s.src[j] === "\\" ? 2 : 1;
    const body = s.src.slice(s.i + 1, j).replace(/\\([`\\$])/g, "$1");
    s.subs.push(body);
    s.i = j + 1;
    return `\`${body}\``;
  }
  const next = s.src[s.i + 1];
  if (next === "(" && s.src[s.i + 2] !== "(") {
    const end = findClosingParen(s.src, s.i + 2);
    const body = s.src.slice(s.i + 2, end);
    s.subs.push(body);
    s.i = end + 1;
    return `$(${body})`;
  }
  if (next === "(" || next === "{") {
    const end = next === "(" ? findClosingParen(s.src, s.i + 2) : s.src.indexOf("}", s.i + 2);
    const stop = end === -1 ? s.src.length - 1 : end;
    const text = s.src.slice(s.i, stop + 1);
    s.i = stop + 1;
    return text;
  }
  s.i += 1;
  return "$";
}

/** Index of the `)` closing a group that starts at `start`, skipping quotes; the end of input when unbalanced. */
function findClosingParen(src: string, start: number): number {
  let depth = 1;
  let j = start;
  while (j < src.length) {
    const c = src[j]!;
    if (c === "\\") j += 2;
    else if (c === "'") j = skipTo(src, j + 1, "'") + 1;
    else if (c === '"') j = skipDouble(src, j + 1) + 1;
    else {
      if (c === "(") depth += 1;
      else if (c === ")") {
        depth -= 1;
        if (depth === 0) return j;
      }
      j += 1;
    }
  }
  return src.length;
}

function skipTo(src: string, from: number, ch: string): number {
  const k = src.indexOf(ch, from);
  return k === -1 ? src.length : k;
}

function skipDouble(src: string, from: number): number {
  let j = from;
  while (j < src.length && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
  return j;
}

const ANSI_ESCAPES: Readonly<Record<string, string>> = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", f: "\f", v: "\v" };

function readAnsiC(src: string, from: number): { text: string; end: number } {
  let out = "";
  let j = from;
  while (j < src.length && src[j] !== "'") {
    if (src[j] !== "\\") {
      out += src[j];
      j += 1;
      continue;
    }
    const n = src[j + 1] ?? "";
    const hex = n === "x" ? /^[0-9a-fA-F]{1,2}/.exec(src.slice(j + 2)) : null;
    if (hex) {
      out += String.fromCharCode(Number.parseInt(hex[0], 16));
      j += 2 + hex[0].length;
      continue;
    }
    out += ANSI_ESCAPES[n] ?? n;
    j += 2;
  }
  return { text: out, end: j + 1 };
}

function group(s: LexState): ShellParse {
  const commands: SimpleCommand[] = [];
  let words: string[] = [];
  let redirects: Redirect[] = [];
  let after: string | undefined;
  const flush = (): void => {
    if (words.length > 0 || redirects.length > 0) commands.push({ words, redirects, ...(after ? { after } : {}) });
    words = [];
    redirects = [];
  };
  for (const tok of s.toks) {
    if (tok.t === "word") words.push(tok.v);
    else if (tok.t === "redir") redirects.push(redirectOf(tok, s.bodies));
    else {
      flush();
      after = tok.v;
    }
  }
  flush();
  return { commands, substitutions: s.subs };
}

function redirectOf(tok: Extract<Token, { t: "redir" }>, bodies: readonly string[]): Redirect {
  if (tok.heredoc !== undefined) return { op: tok.op, target: tok.target, body: bodies[tok.heredoc] ?? "" };
  if (tok.op === "<<<") return { op: tok.op, target: tok.target, body: tok.target };
  return { op: tok.op, target: tok.target };
}

// ---- Unwrapping: from the words of a simple command to the program that actually runs.

interface WrapperSpec {
  /** Options that take a separate value. */
  readonly values?: readonly string[];
  /** Options after which nothing runs (`command -v`, `sudo -l`). */
  readonly noRun?: readonly string[];
  /** Options whose value is itself a command line to split (`env -S`). */
  readonly split?: readonly string[];
  /** Positional arguments before the command (`timeout 5 cmd`). */
  readonly leading?: number;
}

const WRAPPERS: Readonly<Record<string, WrapperSpec>> = {
  sudo: {
    values: ["-u", "-g", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "-R", "-h", "--user", "--group", "--prompt", "--chdir", "--host"],
    noRun: ["-l", "-v", "-k", "-K", "--list", "--validate"],
  },
  doas: { values: ["-u", "-C"] },
  command: { noRun: ["-v", "-V"] },
  builtin: {},
  exec: { values: ["-a"] },
  env: { values: ["-u", "-C", "-P", "--unset", "--chdir"], split: ["-S", "--split-string"] },
  nohup: {},
  time: { values: ["-f", "-o", "--format", "--output"] },
  nice: { values: ["-n", "--adjustment"] },
  ionice: { values: ["-c", "-n", "-p", "--class", "--classdata"] },
  timeout: { values: ["-s", "-k", "--signal", "--kill-after"], leading: 1 },
  stdbuf: { values: ["-i", "-o", "-e", "--input", "--output", "--error"] },
  caffeinate: { values: ["-w", "-t"] },
  xargs: {
    values: ["-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "--arg-file", "--delimiter", "--max-args", "--max-procs", "--replace"],
  },
};

const KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}", "time"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;

/** The last path segment, so `/usr/bin/npx` and `./node_modules/.bin/skills` compare by name. */
export function programName(word: string | undefined): string {
  if (!word) return "";
  const slash = Math.max(word.lastIndexOf("/"), word.lastIndexOf("\\"));
  return (slash === -1 ? word : word.slice(slash + 1)).replace(/\.exe$/i, "");
}

/** Strip assignments, shell keywords, and wrappers like `sudo` or `env`; empty when nothing runs. */
export function commandWords(words: readonly string[], depth = 0): readonly string[] {
  let i = 0;
  while (i < words.length) {
    const w = words[i]!;
    if (ASSIGNMENT.test(w) || KEYWORDS.has(w)) {
      i += 1;
      continue;
    }
    const spec = WRAPPERS[programName(w)];
    if (!spec) return words.slice(i);
    const r = skipWrapper(words, i + 1, spec);
    if (!r) return [];
    if (r.prepend && depth < 4) return commandWords([...r.prepend, ...words.slice(r.next)], depth + 1);
    i = r.next;
  }
  return [];
}

function skipWrapper(words: readonly string[], from: number, spec: WrapperSpec): { next: number; prepend?: string[] } | undefined {
  let i = from;
  while (i < words.length) {
    const w = words[i]!;
    if (w === "--") return { next: i + 1 + (spec.leading ?? 0) };
    if (!w.startsWith("-") || w === "-") break;
    if (spec.noRun?.includes(w)) return undefined;
    if (spec.split?.includes(w)) return { next: i + 2, prepend: (words[i + 1] ?? "").split(/\s+/).filter(Boolean) };
    i += spec.values?.includes(w) ? 2 : 1;
  }
  return { next: i + (spec.leading ?? 0) };
}

/** Quote a word for a POSIX shell, leaving plain words alone. */
export function shellQuote(word: string): string {
  if (/^[\w@%+=:,./-]+$/.test(word)) return word;
  return `'${word.replace(/'/g, "'\\''")}'`;
}
