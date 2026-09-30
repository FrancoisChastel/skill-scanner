// Load the published OpenCode plugin and Pi extension, and the shims `setup` wrote, with fake hosts.
import { pathToFileURL } from "node:url";

const [pkgRoot, maliciousSource, benignSource, opencodeShim, piShim] = process.argv.slice(2);
const results = [];
const check = (name, ok, detail = "") => results.push({ name, ok: Boolean(ok), detail: String(detail).slice(0, 300) });
const withTimeout = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(new Error(`timeout ${ms}ms`)), ms))]);

async function testOpenCode(modulePath, label) {
  const mod = await import(pathToFileURL(modulePath).href);
  const exports = Object.entries(mod);
  check(
    `${label}: every export is a function`,
    exports.length > 0 && exports.every(([, v]) => typeof v === "function"),
    exports.map(([k, v]) => `${k}:${typeof v}`).join(","),
  );
  const toasts = [];
  const client = { tui: { showToast: async (a) => toasts.push(a) }, app: { log: async () => {} } };
  const hooks = await mod.SkillScanner({
    client,
    project: {},
    directory: process.cwd(),
    worktree: process.cwd(),
    serverUrl: new URL("http://localhost"),
    $: () => {},
  });
  check(`${label}: returns tool hooks`, typeof hooks["tool.execute.before"] === "function", Object.keys(hooks).join(","));
  let threw;
  try {
    await withTimeout(
      hooks["tool.execute.before"](
        { tool: "bash", sessionID: "s", callID: "c" },
        { args: { command: `npx skills add ${maliciousSource} -y -a opencode` } },
      ),
      120000,
    );
  } catch (e) {
    threw = e;
  }
  check(`${label}: blocks a malicious install`, threw && /skill-scanner/i.test(threw.message), threw?.message);
  const benign = { args: { command: `npx skills add ${benignSource} -y -a opencode` } };
  let benignError;
  try {
    await withTimeout(hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c2" }, benign), 120000);
  } catch (e) {
    benignError = e;
  }
  check(
    `${label}: lets a benign install through (rewritten through guard when a runtime is installed)`,
    !benignError,
    benignError?.message ?? benign.args.command,
  );
  let plainError;
  try {
    await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c3" }, { args: { command: "ls -la" } });
  } catch (e) {
    plainError = e;
  }
  check(`${label}: ordinary commands pass`, !plainError, plainError?.message);
}

async function testPi(modulePath, label) {
  const mod = await import(pathToFileURL(modulePath).href);
  check(`${label}: default export is a function`, typeof mod.default === "function");
  const handlers = {};
  const notes = [];
  const on = (e, h) => {
    handlers[e] = [...(handlers[e] ?? []), h];
    return () => {};
  };
  const pi = { on, registerCommand: () => {}, registerTool: () => {} };
  mod.default(pi);
  check(
    `${label}: registers tool_call and session_start`,
    handlers.tool_call?.length && handlers.session_start?.length,
    Object.keys(handlers).join(","),
  );
  const ctx = {
    cwd: process.cwd(),
    hasUI: false,
    ui: { notify: (m) => notes.push(m), confirm: async () => false, setStatus() {}, setWidget() {} },
    isProjectTrusted: () => true,
  };
  const call = async (command) => {
    for (const h of handlers.tool_call) {
      const r = await withTimeout(Promise.resolve(h({ toolCallId: "t", toolName: "bash", input: { command } }, ctx)), 120000);
      if (r?.block) return r;
    }
    return undefined;
  };
  const blocked = await call(`npx skills add ${maliciousSource} -y -a pi`);
  check(`${label}: blocks a malicious install`, blocked?.block === true, blocked?.reason);
  const plain = await call("ls -la");
  check(`${label}: ordinary commands pass`, plain === undefined, plain?.reason);
}

try {
  await testOpenCode(`${pkgRoot}/dist/adapters/opencode.js`, "OpenCode plugin (npm subpath)");
  await testPi(`${pkgRoot}/dist/adapters/pi.js`, "Pi extension (npm subpath)");
  if (opencodeShim) await testOpenCode(opencodeShim, "OpenCode shim written by setup");
  if (piShim) await testPi(piShim, "Pi shim written by setup");
} catch (e) {
  check("adapters loaded without crashing", false, e?.stack ?? e);
}
console.log(JSON.stringify(results));
process.exit(0);
