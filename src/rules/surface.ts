import { basename } from "../core/classify";
import { extractEmbedded, parseJsonLoose } from "../core/embedded";
import type { BundleContext, BundleRule, Signal } from "../core/rule";
import type { Confidence, Severity, SkillFile } from "../core/types";

/** Code that a harness runs automatically because a plugin, package, or config file says so. */

const DANGEROUS_ENV =
  /^(?:NODE_OPTIONS|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|PYTHONSTARTUP|PYTHONPATH|PERL5OPT|RUBYOPT|BASH_ENV|ENV|PROMPT_COMMAND|ANTHROPIC_BASE_URL|OPENAI_BASE_URL|HTTPS?_PROXY|ALL_PROXY|GIT_SSH_COMMAND|NODE_TLS_REJECT_UNAUTHORIZED)$/i;
const LOCAL_URL = /^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::\d+)?(?:\/|$)/i;

function jsonOf(f: SkillFile): Record<string, unknown> | undefined {
  if (!f.text || !/\.jsonc?$/i.test(f.path)) return undefined;
  const v = parseJsonLoose(f.text);
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function lineOf(text: string | undefined, needle: string): number {
  if (!text) return 1;
  const i = text.indexOf(needle);
  return i === -1 ? 1 : text.slice(0, i).split("\n").length;
}

export const surfaceRules: readonly BundleRule[] = [
  {
    id: "surface/hooks",
    title: "Registers hooks that run automatically",
    category: "execution-surface",
    severity: "medium",
    confidence: "high",
    description:
      "Hook configuration (Claude Code or Codex `hooks.json`, plugin.json `hooks`, settings files) runs commands on agent events such as session start or every tool call, without the agent choosing to. HTTP hooks send event payloads, including your prompts and tool output, to a URL.",
    remediation: "Read every hook command. Install only if each one is necessary and pinned.",
    scope: "bundle",
    check(ctx) {
      const { commands } = extractEmbedded(ctx.bundle);
      for (const [path, list] of commands) {
        for (const c of list) {
          if (c.trigger === "http-hook") {
            const local = LOCAL_URL.test(c.command);
            ctx.report({
              file: path,
              line: c.line,
              snippet: c.command,
              severity: local ? "low" : "high",
              message: `HTTP hook (${c.pointer}) sends agent events to ${c.command}`,
            });
          } else if (c.trigger === "hook") {
            const event = /\.(\w+)\[/.exec(c.pointer)?.[1] ?? "an event";
            ctx.report({
              file: path,
              line: c.line,
              snippet: c.command,
              message: `Runs \`${c.command.slice(0, 100)}\` automatically on ${event}`,
            });
          }
        }
      }
    },
  },
  {
    id: "surface/mcp-server",
    title: "Declares MCP servers",
    category: "execution-surface",
    severity: "medium",
    confidence: "high",
    description:
      "MCP servers declared by a plugin, config file, or Codex skill dependency are started by the harness and their tools become available to the agent. Local servers run code on your machine; environment overrides such as `NODE_OPTIONS` or `LD_PRELOAD` inject code into them.",
    scope: "bundle",
    check(ctx) {
      const { commands } = extractEmbedded(ctx.bundle);
      for (const [path, list] of commands) {
        for (const c of list) {
          if (c.trigger !== "mcp-server" && c.trigger !== "opencode-mcp") continue;
          const unpinned = /\b(?:npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\s+(?:-y\s+|--yes\s+)?@?(?!-)[\w./-]+(?!@\d)(?:\s|$)/.test(c.command);
          ctx.report({
            file: path,
            line: c.line,
            snippet: c.command,
            severity: unpinned ? "medium" : "low",
            message: `${c.pointer} starts \`${c.command.slice(0, 100)}\`${unpinned ? ", an unpinned package fetched at start" : ""}`,
          });
        }
      }
      for (const f of ctx.bundle.files) {
        const json = jsonOf(f);
        const servers = (json?.mcpServers ?? json?.mcp_servers) as Record<string, unknown> | undefined;
        if (!servers || typeof servers !== "object") continue;
        for (const [name, spec] of Object.entries(servers)) {
          const s = spec as Record<string, unknown> | null;
          if (!s || typeof s !== "object") continue;
          const env = s.env as Record<string, unknown> | undefined;
          for (const key of Object.keys(env ?? {})) {
            if (DANGEROUS_ENV.test(key))
              ctx.report({
                file: f.path,
                line: lineOf(f.text, `"${key}"`),
                snippet: `${key}=${String(env![key]).slice(0, 60)}`,
                severity: "high",
                message: `MCP server ${name} sets ${key}, which changes what code runs or where traffic goes`,
              });
          }
          const url = typeof s.url === "string" ? s.url : undefined;
          if (url && /\.(?:mcpb|dxt)(?:$|\?)/i.test(url))
            ctx.report({
              file: f.path,
              line: lineOf(f.text, url),
              snippet: url,
              message: `MCP server ${name} is a bundle downloaded from ${url}`,
            });
        }
      }
    },
  },
  {
    id: "surface/background-runners",
    title: "Declares language servers, monitors, or workflows",
    category: "execution-surface",
    severity: "medium",
    confidence: "high",
    description:
      "Claude Code plugins can start LSP servers (`.lsp.json`), persistent background shell monitors (`monitors/monitors.json`), and JavaScript workflows. They run without a tool call.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        const name = basename(f.path);
        if (name === ".lsp.json" || (name === "plugin.json" && jsonOf(f)?.lspServers))
          ctx.report({ file: f.path, message: "Starts language server processes" });
        else if (/(^|\/)monitors\/monitors\.json$/.test(f.path))
          ctx.report({ file: f.path, severity: "high", message: "Runs persistent background shell monitors" });
        else if (/(^|\/)workflows\/[^/]+\.m?js$/.test(f.path) && ctx.bundle.kind === "plugin")
          ctx.report({ file: f.path, severity: "low", message: "Ships a plugin workflow script" });
      }
    },
  },
  {
    id: "surface/marketplace-source",
    title: "Marketplace entry runs or fetches code on install",
    category: "execution-surface",
    severity: "medium",
    confidence: "high",
    description:
      "Claude Code marketplace entries can point at npm packages, archives, or URLs, or at a `command` source that runs a shell command on install, on update, and once per session.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        if (basename(f.path) !== "marketplace.json") continue;
        const plugins = jsonOf(f)?.plugins;
        if (!Array.isArray(plugins)) continue;
        for (const p of plugins) {
          const src = (p as { source?: unknown; name?: unknown }).source;
          const name = String((p as { name?: unknown }).name ?? "?");
          if (typeof src !== "object" || src === null) continue;
          const kind = String((src as { source?: unknown }).source ?? "");
          if (kind === "command")
            ctx.report({
              file: f.path,
              line: lineOf(f.text, `"${name}"`),
              severity: "high",
              message: `Plugin ${name} is installed by running a shell command`,
            });
          else if (["npm", "url", "archive"].includes(kind))
            ctx.report({
              file: f.path,
              line: lineOf(f.text, `"${name}"`),
              severity: "low",
              message: `Plugin ${name} comes from a ${kind} source outside this repository`,
            });
        }
      }
    },
  },
  {
    id: "surface/in-process-extension",
    title: "Ships code that runs inside the agent",
    category: "execution-surface",
    severity: "medium",
    confidence: "high",
    description:
      "Pi extensions and OpenCode plugins run in the agent's own process with full access to its tools, credentials, and conversation.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        if (basename(f.path) === "package.json") {
          const pi = jsonOf(f)?.pi as Record<string, unknown> | undefined;
          if (pi && Array.isArray(pi.extensions) && pi.extensions.length > 0)
            ctx.report({
              file: f.path,
              line: lineOf(f.text, '"extensions"'),
              message: `Declares Pi extensions: ${pi.extensions.join(", ")}`,
            });
        }
        if (/(^|\/)\.opencode\/plugins?\/[^/]+\.[mc]?[jt]s$/.test(f.path)) ctx.report({ file: f.path, message: "OpenCode plugin file" });
        if (/(^|\/)\.pi\/extensions\/[^/]+\.[jt]s$|^extensions\/[^/]+\.[jt]s$/.test(f.path) && ctx.bundle.kind !== "skill")
          ctx.report({ file: f.path, message: "Pi extension file" });
      }
    },
  },
  {
    id: "surface/editor-autorun",
    title: "Editor task that runs when the folder opens",
    category: "execution-surface",
    severity: "high",
    confidence: "high",
    description: "A `.vscode/tasks.json` task with `runOn: folderOpen` runs as soon as the folder is opened in VS Code or Cursor.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        if (/(^|\/)\.vscode\/tasks\.json$/.test(f.path) && /"runOn"\s*:\s*"folderOpen"/.test(f.text ?? ""))
          ctx.report({ file: f.path, line: lineOf(f.text, "folderOpen"), message: "A task runs automatically when the folder is opened" });
      }
    },
  },
];

const describe = (s: Signal): string => `${s.file}:${s.line} (${s.detail.trim().slice(0, 60)})`;

/** Lines apart within which a read and a send in one script are one piece of code. */
const SCRIPT_SPAN = 80;
/** In Markdown, the read and the send must sit in the same command or snippet. */
const DOC_SPAN = 3;

interface Pairing {
  readonly source: Signal;
  readonly sink: Signal;
  readonly strength: "same-script" | "same-script-far" | "same-snippet" | "cross-script" | "cross-file";
}

/**
 * The strongest pairing of a source capability (reading credentials, dumping the environment) with
 * a network send. Proximity is the evidence: a stealer reads and sends in one place. Documentation
 * that mentions a key file in one section and a curl call in another is not a pairing.
 */
function strongestPairing(ctx: BundleContext, sources: readonly Signal[], sinks: readonly Signal[]): Pairing | undefined {
  const kindOf = (path: string) => ctx.bundle.files.find((f) => f.path === path)?.kind;
  const order = ["same-script", "same-snippet", "cross-script", "same-script-far", "cross-file"] as const;
  let best: Pairing | undefined;
  const consider = (p: Pairing) => {
    if (!best || order.indexOf(p.strength) < order.indexOf(best.strength)) best = p;
  };
  for (const source of sources) {
    const sourceIsScript = kindOf(source.file) === "script";
    for (const sink of sinks) {
      const distance = Math.abs(sink.line - source.line);
      if (sink.file === source.file) {
        if (sourceIsScript) consider({ source, sink, strength: distance <= SCRIPT_SPAN ? "same-script" : "same-script-far" });
        else if (distance <= DOC_SPAN) consider({ source, sink, strength: "same-snippet" });
      } else if (sourceIsScript && kindOf(sink.file) === "script") consider({ source, sink, strength: "cross-script" });
      else consider({ source, sink, strength: "cross-file" });
    }
  }
  return best;
}

/** Capabilities that are ordinary alone and dangerous together. */
export const correlationRules: readonly BundleRule[] = [
  {
    id: "correlation/credential-exfiltration",
    title: "Reads credentials and sends data out",
    category: "exfiltration",
    severity: "critical",
    confidence: "high",
    description:
      "One script, or one command, reads credentials and also sends data over the network. Each is sometimes legitimate; together, close to each other, they are the shape of a credential stealer.",
    remediation: "Do not install unless the credential and the destination belong to the same service the skill is for.",
    scope: "bundle",
    check(ctx) {
      const reads = ctx.signals.filter((s) => s.tag === "credential-read");
      const sends = ctx.signals.filter((s) => s.tag === "network-send" || s.tag === "network");
      const p = strongestPairing(ctx, reads, sends);
      if (!p) return;
      const grade: Record<Pairing["strength"], { severity: Severity; confidence: Confidence }> = {
        "same-script": { severity: "critical", confidence: "high" },
        "same-snippet": { severity: "high", confidence: "medium" },
        "cross-script": { severity: "high", confidence: "medium" },
        "same-script-far": { severity: "high", confidence: "low" },
        "cross-file": { severity: "medium", confidence: "low" },
      };
      const where = p.source.file === p.sink.file ? "and sends data at" : "; elsewhere the skill sends data at";
      ctx.report({
        file: p.source.file,
        line: p.source.line,
        ...grade[p.strength],
        message: `Reads ${describe(p.source)} ${where} ${describe(p.sink)}`,
      });
    },
  },
  {
    id: "correlation/environment-exfiltration",
    title: "Dumps the environment and sends data out",
    category: "exfiltration",
    severity: "high",
    confidence: "high",
    description: "Collects every environment variable (where API keys live) and, in the same script or command, makes network requests.",
    scope: "bundle",
    check(ctx) {
      const dumps = ctx.signals.filter((s) => s.tag === "env-dump");
      const sends = ctx.signals.filter((s) => s.tag === "network-send" || s.tag === "network");
      const p = strongestPairing(ctx, dumps, sends);
      if (!p) return;
      const grade: Record<Pairing["strength"], { severity: Severity; confidence: Confidence }> = {
        "same-script": { severity: "high", confidence: "high" },
        "same-snippet": { severity: "high", confidence: "medium" },
        "cross-script": { severity: "medium", confidence: "medium" },
        "same-script-far": { severity: "medium", confidence: "medium" },
        "cross-file": { severity: "medium", confidence: "low" },
      };
      const where = p.source.file === p.sink.file ? "and sends data at" : "; elsewhere the skill sends data at";
      ctx.report({
        file: p.source.file,
        line: p.source.line,
        ...grade[p.strength],
        message: `Dumps the environment at ${describe(p.source)} ${where} ${describe(p.sink)}`,
      });
    },
  },
];
