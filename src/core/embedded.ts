import { basename } from "./classify";
import { parseYamlSubset } from "./frontmatter";
import { indexLines, positionAt } from "./text";
import type { FrontmatterValue, SkillBundle, SkillFile } from "./types";

/**
 * Commands that run without anyone reading a script: package lifecycle scripts, harness hooks,
 * MCP server launch commands, and shell snippets a harness expands when it loads a skill.
 * Each becomes a virtual shell file so every shell rule applies to it.
 */

export interface EmbeddedCommand {
  /** Where it came from, e.g. `scripts.postinstall` or `hooks.PreToolUse[0]`. */
  readonly pointer: string;
  readonly command: string;
  /** What runs it and when, for messages. */
  readonly trigger: EmbeddedTrigger;
  readonly line: number;
}

export type EmbeddedTrigger = "lifecycle-script" | "npm-script" | "hook" | "http-hook" | "mcp-server" | "load-time-shell" | "opencode-mcp";

const LIFECYCLE = new Set([
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "preprepare",
  "postprepare",
  "prepublish",
  "preuninstall",
  "postuninstall",
]);

/** The engine and several bundle rules ask for the same bundle's commands; bundles are immutable, so compute once. */
const cache = new WeakMap<SkillBundle, { commands: Map<string, EmbeddedCommand[]>; virtualFiles: SkillFile[] }>();

export function extractEmbedded(bundle: SkillBundle): { commands: Map<string, EmbeddedCommand[]>; virtualFiles: SkillFile[] } {
  const cached = cache.get(bundle);
  if (cached) return { commands: new Map(cached.commands), virtualFiles: [...cached.virtualFiles] };
  const result = computeEmbedded(bundle);
  cache.set(bundle, result);
  return { commands: new Map(result.commands), virtualFiles: [...result.virtualFiles] };
}

function computeEmbedded(bundle: SkillBundle): { commands: Map<string, EmbeddedCommand[]>; virtualFiles: SkillFile[] } {
  const commands = new Map<string, EmbeddedCommand[]>();
  const virtualFiles: SkillFile[] = [];
  for (const file of bundle.files) {
    if (file.text === undefined) continue;
    const found = commandsIn(file, bundle);
    if (found.length === 0) continue;
    commands.set(file.path, found);
    for (const c of found) {
      if (c.trigger === "http-hook") continue;
      virtualFiles.push({
        path: `${file.path}#${c.pointer}`,
        kind: "script",
        language: "shell",
        size: c.command.length,
        text: c.command,
        virtualOf: { path: file.path, line: c.line },
      });
    }
  }
  return { commands, virtualFiles };
}

function commandsIn(file: SkillFile, bundle: SkillBundle): EmbeddedCommand[] {
  const text = file.text!;
  const name = basename(file.path).toLowerCase();
  if (file.kind === "skill-md" || (file.kind === "markdown" && /(^|\/)(commands|agents|skills)\//.test(file.path))) {
    return [
      ...loadTimeShell(text),
      ...(file.kind === "skill-md" && bundle.frontmatter ? frontmatterHooks(bundle.frontmatter.data, text) : []),
    ];
  }
  if (/(^|\/)agents\/openai\.ya?ml$/i.test(file.path)) return codexSkillDependencies(text);
  if (file.kind !== "manifest" && !(file.kind === "text" && name.endsWith(".json"))) return [];
  const json = parseJsonLoose(text);
  if (json === undefined) return [];
  const out: EmbeddedCommand[] = [];
  if (name === "package.json") out.push(...packageScripts(json, text));
  out.push(...hookCommands(json, text, "hooks"));
  out.push(...mcpCommands(json, text));
  return out;
}

/** Claude Code expands !`cmd` (and ```! fenced blocks) when a skill or command loads, before the model reads it. */
function loadTimeShell(text: string): EmbeddedCommand[] {
  const out: EmbeddedCommand[] = [];
  if (!text.includes("!`") && !text.includes("```!")) return out;
  const index = indexLines(text);
  for (const m of text.matchAll(/(?:^|(?<=\s))!`([^`\n]{1,2000})`/gm)) {
    out.push({
      pointer: `load-shell@${positionAt(index, m.index).line}`,
      command: m[1]!,
      trigger: "load-time-shell",
      line: positionAt(index, m.index).line,
    });
  }
  for (const m of text.matchAll(/^ {0,3}```!\s*\n([\s\S]*?)\n {0,3}```/gm)) {
    out.push({
      pointer: `load-shell@${positionAt(index, m.index).line}`,
      command: m[1]!,
      trigger: "load-time-shell",
      line: positionAt(index, m.index).line + 1,
    });
  }
  return out;
}

/** Codex `agents/openai.yaml`: `dependencies.tools[]` of type mcp with a stdio `command` that Codex installs and starts. */
function codexSkillDependencies(text: string): EmbeddedCommand[] {
  const { data } = parseYamlSubset(text.split(/\r?\n/));
  const deps = data.dependencies;
  const tools =
    typeof deps === "object" && deps !== null && !Array.isArray(deps) ? (deps as Record<string, FrontmatterValue>).tools : undefined;
  if (!Array.isArray(tools)) return [];
  const out: EmbeddedCommand[] = [];
  tools.forEach((t, i) => {
    if (typeof t !== "object" || t === null || Array.isArray(t)) return;
    const tool = t as Record<string, FrontmatterValue>;
    const command = typeof tool.command === "string" ? tool.command : undefined;
    if (!command) return;
    const args = Array.isArray(tool.args) ? tool.args.filter((a): a is string => typeof a === "string") : [];
    out.push({
      pointer: `dependencies.tools[${i}]`,
      command: [command, ...args.map(shellQuote)].join(" "),
      trigger: "mcp-server",
      line: lineOfValue(text, command),
    });
  });
  return out;
}

function frontmatterHooks(data: Readonly<Record<string, FrontmatterValue>>, text: string): EmbeddedCommand[] {
  return data.hooks === undefined ? [] : hookCommands({ hooks: data.hooks as unknown }, text, "frontmatter.hooks");
}

function packageScripts(json: unknown, text: string): EmbeddedCommand[] {
  const scripts = recordAt(json, "scripts");
  if (!scripts) return [];
  return Object.entries(scripts)
    .filter((e): e is [string, string] => typeof e[1] === "string")
    .map(([key, command]) => ({
      pointer: `scripts.${key}`,
      command,
      trigger: LIFECYCLE.has(key) ? "lifecycle-script" : "npm-script",
      line: lineOfValue(text, command),
    }));
}

/** Claude Code and Codex hook shape: `{ hooks: { Event: [ { matcher?, hooks: [ { type, command | url } ] } ] } }`. */
function hookCommands(json: unknown, text: string, label: string): EmbeddedCommand[] {
  const hooks = recordAt(json, "hooks");
  if (!hooks) return [];
  const out: EmbeddedCommand[] = [];
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((group: unknown, gi) => {
      const inner = typeof group === "object" && group !== null ? (group as { hooks?: unknown }).hooks : undefined;
      const list: unknown[] = Array.isArray(inner) ? inner : [];
      list.forEach((h, hi) => {
        if (typeof h !== "object" || h === null) return;
        const hook = h as Record<string, unknown>;
        const pointer = `${label}.${event}[${gi}].hooks[${hi}]`;
        if (typeof hook.command === "string")
          out.push({ pointer, command: hook.command, trigger: "hook", line: lineOfValue(text, hook.command) });
        else if (typeof hook.url === "string")
          out.push({ pointer, command: hook.url, trigger: "http-hook", line: lineOfValue(text, hook.url) });
      });
    });
  }
  return out;
}

/** `.mcp.json` / plugin.json `mcpServers`, and opencode.json `mcp` with command arrays. */
function mcpCommands(json: unknown, text: string): EmbeddedCommand[] {
  const out: EmbeddedCommand[] = [];
  const servers = recordAt(json, "mcpServers") ?? recordAt(json, "mcp_servers");
  if (servers) {
    for (const [name, spec] of Object.entries(servers)) {
      const s = spec as Record<string, unknown> | null;
      if (!s || typeof s.command !== "string") continue;
      const args = Array.isArray(s.args) ? s.args.filter((a): a is string => typeof a === "string") : [];
      out.push({
        pointer: `mcpServers.${name}`,
        command: [s.command, ...args.map(shellQuote)].join(" "),
        trigger: "mcp-server",
        line: lineOfValue(text, s.command),
      });
    }
  }
  const oc = recordAt(json, "mcp");
  if (oc) {
    for (const [name, spec] of Object.entries(oc)) {
      const s = spec as Record<string, unknown> | null;
      if (!s || !Array.isArray(s.command)) continue;
      const parts = s.command.filter((a): a is string => typeof a === "string");
      if (parts.length > 0)
        out.push({
          pointer: `mcp.${name}`,
          command: parts.map(shellQuote).join(" "),
          trigger: "opencode-mcp",
          line: lineOfValue(text, parts[0]!),
        });
    }
  }
  return out;
}

const shellQuote = (s: string): string => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`);

function recordAt(v: unknown, key: string): Record<string, unknown> | undefined {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return undefined;
  const inner = (v as Record<string, unknown>)[key];
  return typeof inner === "object" && inner !== null && !Array.isArray(inner) ? (inner as Record<string, unknown>) : undefined;
}

function lineOfValue(text: string, value: string): number {
  const encoded = JSON.stringify(value).slice(1, -1);
  let i = text.indexOf(encoded);
  if (i === -1) i = text.indexOf(value);
  if (i === -1) return 1;
  let line = 1;
  for (let k = 0; k < i; k += 1) if (text.charCodeAt(k) === 10) line += 1;
  return line;
}

/** JSON with comments and trailing commas, as harness config files allow. Returns undefined when it cannot parse. */
export function parseJsonLoose(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    try {
      return JSON.parse(stripJsonComments(text).replace(/,(\s*[}\]])/g, "$1"));
    } catch {
      return undefined;
    }
  }
}

export function stripJsonComments(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]!;
    if (inString) {
      out += c;
      if (c === "\\") {
        out += text[i + 1] ?? "";
        i += 1;
      } else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i += 1;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 1;
    } else out += c;
  }
  return out;
}
