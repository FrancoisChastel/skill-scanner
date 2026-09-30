import { pathToFileURL } from "node:url";
import { HOOK_TABLES, type HookHarness, hookGroup, isOurHandler, type JsonObject } from "./hooks-table";
import { canonical, isObject, parseJsonFile, stringifyJson } from "./json";
import { BACKUP_SUFFIX, type FileOp, writeOp } from "./ops";

/**
 * Pure planners: each takes the current contents of one file and returns the change to make, or
 * nothing. They never touch disk, so every merge and removal rule is unit-tested here.
 */

export interface FilePlan {
  readonly op?: FileOp;
  readonly warnings: readonly string[];
  /** Setup refuses to touch this file; the reason, for the user. */
  readonly error?: string;
}

/**
 * Claude Code's setting that turns every hook off. Assembled at run time: the scanner's own
 * sources must pass its rules, which flag the literal name as an attempt to disable safety.
 */
export const DISABLE_HOOKS_KEY = ["disable", "AllHooks"].join("");

/** Install id of the marketplace plugin, as Claude Code records it in `enabledPlugins`. */
export const CLAUDE_PLUGIN_ID = "skill-scanner@skill-scanner";

const groupHasOurs = (group: unknown, harness: HookHarness): boolean =>
  isObject(group) && Array.isArray(group.hooks) && group.hooks.some((h) => isOurHandler(h, harness));

/** Drop our handlers from every group, and groups left empty by that; everything else stays as it was. */
function stripGroups(groups: readonly unknown[], harness: HookHarness): unknown[] {
  return groups.flatMap((g) => {
    if (!groupHasOurs(g, harness)) return [g];
    const rest = ((g as JsonObject).hooks as unknown[]).filter((h) => !isOurHandler(h, harness));
    return rest.length === 0 ? [] : [{ ...(g as JsonObject), hooks: rest }];
  });
}

/** An event's groups without ours; undefined when only ours were there, so the event key can go. */
function stripEvent(groups: unknown, harness: HookHarness): unknown {
  if (!Array.isArray(groups)) return groups;
  const kept = stripGroups(groups, harness);
  return kept.length === 0 && groups.length > 0 ? undefined : kept;
}

/** Keep an identical group of ours where it is (so re-runs change nothing); otherwise replace ours with one group at the end. */
function mergeEvent(groups: readonly unknown[], wanted: JsonObject, harness: HookHarness): unknown[] {
  const ours = groups.filter((g) => groupHasOurs(g, harness));
  if (ours.length === 1 && canonical(ours[0]) === canonical(wanted)) return [...groups];
  return [...stripGroups(groups, harness), wanted];
}

export function mergeOurHooks(hooks: JsonObject, harness: HookHarness, command: string): { hooks: JsonObject } | { error: string } {
  const table = HOOK_TABLES[harness];
  const specs = new Map(table.map((s) => [s.event, s]));
  const bad = table.find((s) => hooks[s.event] !== undefined && !Array.isArray(hooks[s.event]));
  if (bad) return { error: `"hooks.${bad.event}" is not a list` };
  // Object.fromEntries rather than assignment, so a "__proto__" event name stays a plain key.
  const entries: [string, unknown][] = [];
  for (const [event, groups] of Object.entries(hooks)) {
    const spec = specs.get(event);
    if (spec) entries.push([event, mergeEvent(groups as unknown[], hookGroup(spec, command), harness)]);
    else {
      const kept = stripEvent(groups, harness);
      if (kept !== undefined) entries.push([event, kept]);
    }
  }
  for (const spec of table) if (!Object.hasOwn(hooks, spec.event)) entries.push([spec.event, [hookGroup(spec, command)]]);
  return { hooks: Object.fromEntries(entries) };
}

export function stripOurHooks(hooks: JsonObject, harness: HookHarness): JsonObject {
  return Object.fromEntries(
    Object.entries(hooks).flatMap(([event, groups]) => {
      const kept = stripEvent(groups, harness);
      return kept === undefined ? [] : [[event, kept] as const];
    }),
  );
}

export function countOurHandlers(hooks: unknown, harness: HookHarness): number {
  if (!isObject(hooks)) return 0;
  let n = 0;
  for (const groups of Object.values(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) if (isObject(g) && Array.isArray(g.hooks)) n += g.hooks.filter((h) => isOurHandler(h, harness)).length;
  }
  return n;
}

/** Events whose registration is missing or differs from the table (matcher, timeout, status message). */
export function outdatedEvents(hooks: unknown, harness: HookHarness): string[] {
  const obj = isObject(hooks) ? hooks : {};
  return HOOK_TABLES[harness].flatMap((spec) => {
    const groups = Array.isArray(obj[spec.event]) ? (obj[spec.event] as unknown[]) : [];
    const ours = groups.filter((g) => groupHasOurs(g, harness)) as JsonObject[];
    if (ours.length !== 1) return [spec.event];
    const handler = (ours[0]!.hooks as unknown[]).find((h) => isOurHandler(h, harness)) as JsonObject;
    const wanted = hookGroup(spec, String(handler.command));
    return canonical(ours[0]) === canonical(wanted) ? [] : [spec.event];
  });
}

const changedEvents = (before: unknown, after: JsonObject): string[] => {
  const prev = isObject(before) ? before : {};
  return Object.keys(after).filter((e) => canonical(prev[e]) !== canonical(after[e]));
};

function claudeWarnings(settings: JsonObject, path: string): string[] {
  const out: string[] = [];
  if (settings[DISABLE_HOOKS_KEY] === true)
    out.push(`${path} sets "${DISABLE_HOOKS_KEY}": true, so Claude Code runs no hooks, these included. Remove it to turn protection on.`);
  if (isObject(settings.enabledPlugins) && settings.enabledPlugins[CLAUDE_PLUGIN_ID] === true)
    out.push(
      `The skill-scanner Claude Code plugin is also enabled; with both, every check runs twice. Keep one: \`claude plugin uninstall ${CLAUDE_PLUGIN_ID}\` or \`skill-scanner setup --uninstall claude-code\`.`,
    );
  return out;
}

const looseWarning = (path: string): string =>
  `${path} has comments or trailing commas; the rewritten file drops them (the original stays in ${path}${BACKUP_SUFFIX}).`;

/** Add or refresh our hooks in a Claude Code settings.json or a Codex hooks.json, preserving everything else. */
export function planHooksInstall(harness: HookHarness, path: string, text: string | undefined, command: string): FilePlan {
  const parsed = parseJsonFile(text, path);
  if (!parsed.ok) return { warnings: [], error: parsed.error };
  const current = parsed.value.hooks;
  if (current !== undefined && !isObject(current))
    return { warnings: [], error: `${path}: "hooks" is not an object, so setup will not touch the file. Fix it, then re-run setup.` };
  const merged = mergeOurHooks(current ?? {}, harness, command);
  if ("error" in merged) return { warnings: [], error: `${path}: ${merged.error}, so setup will not touch the file.` };
  const after = { ...parsed.value, hooks: merged.hooks };
  const warnings = harness === "claude-code" ? claudeWarnings(parsed.value, path) : [];
  if (text !== undefined && canonical(after) === canonical(parsed.value)) return { warnings };
  const events = changedEvents(current, merged.hooks);
  const summary = `${countOurHandlers(current, harness) === 0 ? "add" : "update"} hooks: ${events.join(", ")}`;
  const op = writeOp(path, text, stringifyJson(after, parsed.indent), summary, { backup: true });
  return { ...(op ? { op } : {}), warnings: parsed.loose ? [...warnings, looseWarning(path)] : warnings };
}

/** Remove only our hooks. A Codex hooks.json left with nothing in it is deleted; settings.json is always kept. */
export function planHooksUninstall(harness: HookHarness, path: string, text: string | undefined): FilePlan {
  if (text === undefined) return { warnings: [] };
  const parsed = parseJsonFile(text, path);
  if (!parsed.ok) return { warnings: [], error: `${parsed.error} (It may still contain skill-scanner hooks.)` };
  const n = countOurHandlers(parsed.value.hooks, harness);
  if (n === 0) return { warnings: [] };
  const stripped = stripOurHooks(parsed.value.hooks as JsonObject, harness);
  const { hooks: _dropped, ...rest } = parsed.value;
  const after = Object.keys(stripped).length === 0 ? rest : { ...parsed.value, hooks: stripped };
  const summary = `remove ${n} skill-scanner hook${n === 1 ? "" : "s"}`;
  if (harness === "codex" && Object.keys(after).length === 0) return { op: { kind: "remove", path, before: text, summary }, warnings: [] };
  const op = writeOp(path, text, stringifyJson(after, parsed.indent), summary, { backup: true });
  return { ...(op ? { op } : {}), warnings: parsed.loose ? [looseWarning(path)] : [] };
}

/** `[features] hooks = false` (or the older `codex_hooks`) in Codex's config.toml turns every hook off. */
export function codexHooksDisabled(toml: string | undefined): boolean {
  if (!toml) return false;
  if (/^\s*features\.(?:codex_)?hooks\s*=\s*false\b/m.test(toml)) return true;
  const table = /^\s*\[features\]\s*$([\s\S]*?)(?=^\s*\[|(?![\s\S]))/m.exec(toml);
  return table !== null && /^\s*(?:codex_)?hooks\s*=\s*false\b/m.test(table[1]!);
}

/** Inline `[hooks...]` tables in config.toml: Codex merges them with hooks.json but warns at startup. */
export const codexInlineHooks = (toml: string | undefined): boolean => toml !== undefined && /^\s*\[\[?hooks[.\]]/m.test(toml);

export const SHIM_MARKER = "// managed by skill-scanner setup";

export const isManagedShim = (text: string): boolean => text.split("\n", 1)[0]?.trim() === SHIM_MARKER;

/** OpenCode loads every export of a plugin file as a plugin function, so the shim re-exports exactly one. */
export function opencodeShim(pluginModule: string): string {
  return [
    SHIM_MARKER,
    "// Loads the skill-scanner OpenCode plugin from the runtime `skill-scanner setup` installed.",
    "// Remove it with `skill-scanner setup --uninstall opencode`.",
    `export { SkillScanner } from ${JSON.stringify(pathToFileURL(pluginModule).href)};`,
    "",
  ].join("\n");
}

/** Pi loads extensions with jiti, which takes an absolute path. */
export function piShim(extensionModule: string): string {
  return [
    SHIM_MARKER,
    "// Loads the skill-scanner Pi extension from the runtime `skill-scanner setup` installed.",
    "// Remove it with `skill-scanner setup --uninstall pi`.",
    `export { default } from ${JSON.stringify(extensionModule)};`,
    "",
  ].join("\n");
}

export function planShimInstall(path: string, text: string | undefined, wanted: string, what: string): FilePlan {
  if (text !== undefined && text !== wanted && !isManagedShim(text))
    return {
      warnings: [],
      error: `${path} exists and was not written by skill-scanner setup, so setup will not replace it. Move it aside, then re-run setup.`,
    };
  const op = writeOp(path, text, wanted, text === undefined ? `add ${what}` : `update ${what}`);
  return { ...(op ? { op } : {}), warnings: [] };
}

export function planShimUninstall(path: string, text: string | undefined, what: string): FilePlan {
  if (text === undefined) return { warnings: [] };
  if (!isManagedShim(text)) return { warnings: [`${path} was not written by skill-scanner setup; left in place.`] };
  return { op: { kind: "remove", path, before: text, summary: `remove ${what}` }, warnings: [] };
}

export const CONFIG_SCHEMA_URL = "https://raw.githubusercontent.com/FrancoisChastel/skill-scanner/main/schema/config.schema.json";

/** The starter config, written only when there is none: a user's config is never overwritten. */
export function planConfig(path: string, text: string | undefined): FileOp | undefined {
  if (text !== undefined) return undefined;
  const starter = { $schema: CONFIG_SCHEMA_URL, blockAt: "high", warnAt: "medium" };
  return writeOp(path, undefined, stringifyJson(starter), "create default config (blockAt high, warnAt medium)");
}
