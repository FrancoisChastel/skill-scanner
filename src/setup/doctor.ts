import { access, constants } from "node:fs/promises";
import { dirname, join } from "node:path";
import { scannerPaths } from "../paths";
import { VERSION } from "../version";
import { type CheckContext, environmentChecks } from "./doctor-env";
import {
  type Detection,
  detectHarnesses,
  type Harness,
  harnessConfigDir,
  harnessFile,
  type Probe,
  pathExists,
  whichBinary,
} from "./harnesses";
import type { HookHarness } from "./hooks-table";
import { type HooksFileState, inspectHooksFile, inspectShim, mentionsPackage, type ShimState } from "./inspect";
import { CLAUDE_PLUGIN_ID, codexHooksDisabled, DISABLE_HOOKS_KEY } from "./plans";
import { PACKAGE_NAME, RUNTIME_ENTRY, readText, VERSION_FILE } from "./runtime";

export type CheckStatus = "ok" | "warn" | "fail" | "skip";

export interface Check {
  /** What the check is about, e.g. `runtime`, `codex`, `gitleaks`. */
  readonly area: string;
  readonly status: CheckStatus;
  readonly message: string;
  /** The exact command or edit that fixes a warn or fail. */
  readonly fix?: string;
}

export interface DoctorReport {
  readonly version: string;
  readonly ok: boolean;
  readonly checks: readonly Check[];
  /** The last few hook decisions, one line each. */
  readonly decisions: readonly string[];
}

export interface DoctorOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly cwd: string;
  /** Also send one request to the judge. */
  readonly live: boolean;
  readonly probe?: Probe;
  /** How to invoke skill-scanner in fix commands. */
  readonly self?: string;
}

export async function runDoctor(opts: DoctorOptions): Promise<DoctorReport> {
  const self = opts.self ?? "skill-scanner";
  const paths = scannerPaths(opts.env);
  const detections = await detectHarnesses(opts.env, opts.probe);
  const harness = await Promise.all(detections.map((d) => harnessChecks(d, opts, self)));
  const installedBySetup = harness.some((h) => h.bySetup);
  const onlyPlugin = !installedBySetup && harness.some((h) => h.byPlugin);
  const ctx: CheckContext = { env: opts.env, live: opts.live, self, paths };
  const env = await environmentChecks(ctx);
  const checks = [
    ...(await runtimeChecks(paths.bin, self, onlyPlugin)),
    ...harness.flatMap((h) => h.checks),
    ...env.checks,
    await stateDirCheck(paths.home),
  ];
  return { version: VERSION, ok: !checks.some((c) => c.status === "fail"), checks, decisions: env.decisions };
}

async function runtimeChecks(bin: string, self: string, onlyPlugin: boolean): Promise<Check[]> {
  const entry = join(bin, RUNTIME_ENTRY);
  if (!(await pathExists(entry))) {
    if (onlyPlugin) return [{ area: "runtime", status: "skip", message: "not installed (the Claude Code plugin does not use it)" }];
    return [{ area: "runtime", status: "fail", message: `not installed: ${entry} is missing`, fix: `${self} setup` }];
  }
  const installed = (await readText(join(bin, VERSION_FILE)))?.trim();
  if (installed !== VERSION)
    return [
      {
        area: "runtime",
        status: "warn",
        message: `the hooks run ${installed ? `runtime ${installed}` : "a runtime of unknown version"} from ${bin}, but this CLI is ${VERSION}`,
        fix: `${self} setup`,
      },
    ];
  return [{ area: "runtime", status: "ok", message: `${VERSION} at ${bin}` }];
}

interface HarnessResult {
  readonly checks: Check[];
  readonly bySetup: boolean;
  readonly byPlugin: boolean;
}

async function harnessChecks(d: Detection, opts: DoctorOptions, self: string): Promise<HarnessResult> {
  switch (d.harness) {
    case "claude-code":
    case "codex":
      return hookHarnessChecks(d, opts, self);
    case "opencode":
    case "pi":
      return shimHarnessChecks(d, opts, self);
  }
}

async function hooksStates(harness: HookHarness, opts: DoctorOptions): Promise<HooksFileState[]> {
  const files = [harnessFile(harness, "user", opts.env, opts.cwd), harnessFile(harness, "project", opts.env, opts.cwd)];
  if (harness === "claude-code") files.push(join(opts.cwd, ".claude", "settings.local.json"));
  const unique = [...new Set(files)];
  return Promise.all(unique.map(async (f) => inspectHooksFile(harness, f, await readText(f))));
}

async function hookHarnessChecks(d: Detection, opts: DoctorOptions, self: string): Promise<HarnessResult> {
  const harness = d.harness as HookHarness;
  const area = harness;
  const states = await hooksStates(harness, opts);
  const checks: Check[] = states.flatMap((s) =>
    s.parseError ? [{ area, status: "fail" as const, message: s.parseError, fix: `fix the JSON in ${s.file}` }] : [],
  );
  const installed = states.filter((s) => s.ours > 0);
  const byPlugin = harness === "claude-code" && states.some((s) => s.pluginEnabled);
  const setupCmd = (s: HooksFileState) =>
    `${self} setup ${harness}${s.file === harnessFile(harness, "project", opts.env, opts.cwd) ? " --project" : ""}`;
  for (const s of installed) {
    const trust = harness === "codex" ? " (Codex runs them only once you trust them in its /hooks screen)" : "";
    checks.push(
      s.outdated.length > 0
        ? { area, status: "warn", message: `hooks in ${s.file} are outdated or incomplete: ${s.outdated.join(", ")}`, fix: setupCmd(s) }
        : { area, status: "ok", message: `hooks installed in ${s.file}${trust}` },
    );
    checks.push(...(await commandPathChecks(area, s, setupCmd(s))));
  }
  if (byPlugin) checks.push(...(await pluginChecks(opts, installed.length > 0, self)));
  if (installed.length === 0 && !byPlugin && checks.length === 0)
    checks.push(
      d.detected
        ? { area, status: "warn", message: "skill-scanner hooks are not installed", fix: `${self} setup ${harness}` }
        : { area, status: "skip", message: "not detected" },
    );
  checks.push(...(await disabledChecks(harness, states, opts)));
  return { checks, bySetup: installed.length > 0, byPlugin };
}

/** Every Node binary and runtime script our hook commands name must still exist. */
async function commandPathChecks(area: string, s: HooksFileState, fix: string): Promise<Check[]> {
  const out: Check[] = [];
  const seen = new Set<string>();
  for (const { node, script } of s.runs) {
    for (const [what, p] of [
      ["Node", node],
      ["runtime", script],
    ] as const) {
      if (seen.has(p)) continue;
      seen.add(p);
      if (!(await pathExists(p)))
        out.push({ area, status: "fail", message: `hooks in ${s.file} run ${what} at ${p}, which no longer exists`, fix });
    }
  }
  return out;
}

async function pluginChecks(opts: DoctorOptions, alsoSetup: boolean, self: string): Promise<Check[]> {
  const area = "claude-code";
  const out: Check[] = [{ area, status: "ok", message: `plugin ${CLAUDE_PLUGIN_ID} is enabled` }];
  const which = opts.probe?.which ?? ((b: string) => whichBinary(b, opts.env));
  const onPath = await which("skill-scanner");
  if (!onPath)
    out.push({
      area,
      status: "fail",
      message: "the plugin's hooks run `skill-scanner`, which is not on PATH",
      fix: `npm install -g ${PACKAGE_NAME}`,
    });
  if (alsoSetup)
    out.push({
      area,
      status: "warn",
      message: "both the plugin and setup's hooks are active, so every check runs twice",
      fix: `claude plugin uninstall ${CLAUDE_PLUGIN_ID}   (or: ${self} setup --uninstall claude-code)`,
    });
  return out;
}

async function disabledChecks(harness: HookHarness, states: readonly HooksFileState[], opts: DoctorOptions): Promise<Check[]> {
  if (harness === "claude-code") {
    const off = states.filter((s) => s.hooksDisabled);
    return off.map((s) => ({
      area: harness,
      status: "warn" as const,
      message: `${s.file} sets "${DISABLE_HOOKS_KEY}": true, so Claude Code runs no hooks`,
      fix: `remove "${DISABLE_HOOKS_KEY}" from ${s.file}`,
    }));
  }
  const tomls = [join(harnessConfigDir("codex", opts.env), "config.toml"), join(opts.cwd, ".codex", "config.toml")];
  const out: Check[] = [];
  for (const toml of new Set(tomls))
    if (codexHooksDisabled(await readText(toml)))
      out.push({
        area: harness,
        status: "warn",
        message: `${toml} turns Codex hooks off`,
        fix: `remove "hooks = false" from [features] in ${toml}`,
      });
  return out;
}

const SHIM_LABEL: Readonly<Record<"opencode" | "pi", string>> = { opencode: "plugin", pi: "extension" };

async function shimHarnessChecks(d: Detection, opts: DoctorOptions, self: string): Promise<HarnessResult> {
  const harness = d.harness as "opencode" | "pi";
  const area = harness;
  const what = SHIM_LABEL[harness];
  const files = [...new Set([harnessFile(harness, "user", opts.env, opts.cwd), harnessFile(harness, "project", opts.env, opts.cwd)])];
  const states: ShimState[] = await Promise.all(files.map(async (f) => inspectShim(f, await readText(f))));
  const checks: Check[] = [];
  const installed = states.filter((s) => s.managed);
  for (const s of states.filter((x) => x.exists && !x.managed))
    checks.push({ area, status: "warn", message: `${s.file} exists but was not written by setup; check what it loads` });
  for (const s of installed) {
    const project = s.file === harnessFile(harness, "project", opts.env, opts.cwd);
    const fix = `${self} setup ${harness}${project ? " --project" : ""}`;
    if (!s.target || !(await pathExists(s.target)))
      checks.push({ area, status: "fail", message: `${what} at ${s.file} loads ${s.target ?? "nothing"}, which is missing`, fix });
    else checks.push({ area, status: "ok", message: `${what} installed at ${s.file}` });
  }
  if (installed.length > 0) checks.push(...(await duplicateLoadChecks(harness, opts, self)));
  else if (checks.length === 0)
    checks.push(
      d.detected
        ? { area, status: "warn", message: `skill-scanner ${what} is not installed`, fix: `${self} setup ${harness}` }
        : { area, status: "skip", message: "not detected" },
    );
  return { checks, bySetup: installed.length > 0, byPlugin: false };
}

/** The package loaded a second way (OpenCode plugin list, Pi package) alongside setup's file runs every check twice. */
async function duplicateLoadChecks(harness: Harness, opts: DoctorOptions, self: string): Promise<Check[]> {
  const dir = harnessConfigDir(harness, opts.env);
  const files = harness === "opencode" ? ["opencode.json", "opencode.jsonc", "config.json"] : ["settings.json"];
  const out: Check[] = [];
  for (const f of files) {
    const path = join(dir, f);
    if (mentionsPackage(await readText(path)))
      out.push({
        area: harness,
        status: "warn",
        message: `${path} also loads ${PACKAGE_NAME}, so it runs twice`,
        fix: `remove ${PACKAGE_NAME} from ${path}   (or: ${self} setup --uninstall ${harness})`,
      });
  }
  return out;
}

async function stateDirCheck(home: string): Promise<Check> {
  const existing = (await pathExists(home)) ? home : dirname(home);
  try {
    await access(existing, constants.W_OK);
    return { area: "state", status: "ok", message: existing === home ? `${home} is writable` : `${home} will be created on first use` };
  } catch (e) {
    return {
      area: "state",
      status: "fail",
      message: `${existing} is not writable: ${(e as Error).message}`,
      fix: `fix the permissions of ${existing}, or point SKILL_SCANNER_HOME elsewhere`,
    };
  }
}
