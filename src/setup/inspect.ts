import { fileURLToPath } from "node:url";
import type { HookHarness } from "./hooks-table";
import { isOurHandler } from "./hooks-table";
import { isObject, parseJsonFile } from "./json";
import { CLAUDE_PLUGIN_ID, countOurHandlers, DISABLE_HOOKS_KEY, isManagedShim, outdatedEvents } from "./plans";

/** Pure readers of what setup left in a harness's files, for `doctor`. */

export interface HooksFileState {
  readonly file: string;
  readonly exists: boolean;
  readonly parseError?: string;
  /** Number of our handlers. */
  readonly ours: number;
  /** Table events missing or registered differently. */
  readonly outdated: readonly string[];
  /** Node and runtime paths our commands run. */
  readonly runs: readonly { readonly node: string; readonly script: string }[];
  /** Claude Code: this file turns every hook off. */
  readonly hooksDisabled: boolean;
  /** Claude Code: the marketplace plugin is enabled in this file. */
  readonly pluginEnabled: boolean;
}

const COMMAND_RE = /^"([^"]+)"\s+"([^"]+)"\s+hook\s/;

export function inspectHooksFile(harness: HookHarness, file: string, text: string | undefined): HooksFileState {
  const empty = { file, exists: text !== undefined, ours: 0, outdated: [], runs: [], hooksDisabled: false, pluginEnabled: false };
  if (text === undefined) return empty;
  const parsed = parseJsonFile(text, file);
  if (!parsed.ok) return { ...empty, parseError: parsed.error };
  const v = parsed.value;
  const ours = countOurHandlers(v.hooks, harness);
  return {
    ...empty,
    ours,
    outdated: ours > 0 ? outdatedEvents(v.hooks, harness) : [],
    runs: ourCommands(v.hooks, harness).flatMap((c) => {
      const m = COMMAND_RE.exec(c);
      return m ? [{ node: m[1]!, script: m[2]! }] : [];
    }),
    hooksDisabled: v[DISABLE_HOOKS_KEY] === true,
    pluginEnabled: isObject(v.enabledPlugins) && v.enabledPlugins[CLAUDE_PLUGIN_ID] === true,
  };
}

function ourCommands(hooks: unknown, harness: HookHarness): string[] {
  if (!isObject(hooks)) return [];
  const out = new Set<string>();
  for (const groups of Object.values(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      if (!isObject(g) || !Array.isArray(g.hooks)) continue;
      for (const h of g.hooks) if (isOurHandler(h, harness)) out.add(String((h as { command: unknown }).command));
    }
  }
  return [...out];
}

export interface ShimState {
  readonly file: string;
  readonly exists: boolean;
  readonly managed: boolean;
  /** Absolute path of the runtime module the shim loads. */
  readonly target?: string;
}

export function inspectShim(file: string, text: string | undefined): ShimState {
  if (text === undefined) return { file, exists: false, managed: false };
  const m = /from\s+("(?:[^"\\]|\\.)*")/.exec(text);
  let target: string | undefined;
  if (m) {
    try {
      const spec = JSON.parse(m[1]!) as string;
      target = spec.startsWith("file:") ? fileURLToPath(spec) : spec;
    } catch {
      target = undefined;
    }
  }
  return { file, exists: true, managed: isManagedShim(text), ...(target ? { target } : {}) };
}

/** Whether a harness config also loads skill-scanner some other way (package, plugin list), which would run it twice. */
export function mentionsPackage(text: string | undefined): boolean {
  return text !== undefined && /@french-castle\/skill-scanner/.test(text);
}
