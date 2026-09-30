import { fieldAsString, lineOfKey } from "../core/frontmatter";
import type { BundleContext, BundleRule } from "../core/rule";
import type { Frontmatter } from "../core/types";

/**
 * SKILL.md frontmatter, per the Agent Skills specification (agentskills.io) and the fields
 * Claude Code, Codex, OpenCode, and Pi add. Spec violations are low severity; fields that grant
 * permissions or run commands are not.
 */

const NAME_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function withFrontmatter(ctx: BundleContext, fn: (fm: Frontmatter, skillMd: string) => void): void {
  if (ctx.bundle.kind !== "skill") return;
  const skillMd = ctx.bundle.files.find((f) => f.kind === "skill-md");
  if (!skillMd || !ctx.bundle.frontmatter) return;
  fn(ctx.bundle.frontmatter, skillMd.path);
}

export const metadataRules: readonly BundleRule[] = [
  {
    id: "metadata/missing-frontmatter",
    title: "SKILL.md has no frontmatter",
    category: "metadata",
    severity: "low",
    confidence: "high",
    description: "Without `name` and `description` frontmatter, harnesses skip or mislabel the skill.",
    scope: "bundle",
    check(ctx) {
      if (ctx.bundle.kind !== "skill") return;
      const skillMd = ctx.bundle.files.find((f) => f.kind === "skill-md");
      if (skillMd && !ctx.bundle.frontmatter)
        ctx.report({ file: skillMd.path, line: 1, message: "SKILL.md does not start with a `---` frontmatter block" });
    },
  },
  {
    id: "metadata/frontmatter-parse",
    title: "Frontmatter that parsers may read differently",
    category: "metadata",
    severity: "medium",
    confidence: "medium",
    description:
      "Duplicate keys, YAML anchors and aliases, explicit tags, or unparsable lines. Different YAML parsers resolve these differently, so the description you review may not be the one the agent loads.",
    scope: "bundle",
    check(ctx) {
      withFrontmatter(ctx, (fm, path) => {
        for (const err of fm.errors) {
          const line = Number(/line (\d+)/.exec(err)?.[1] ?? fm.startLine);
          ctx.report({ file: path, line, message: `Frontmatter: ${err}`, severity: /duplicate key/.test(err) ? "medium" : "low" });
        }
        // Only where a YAML node starts (after `key: `, `- `, or in a flow collection), so `*bold*` inside a description is text.
        const m = /(?:^|:\s+|^\s*-\s+|[[{,]\s*)(&[\w-]+|\*[\w-]+|!![\w/]+|![\w-]+\s)/m.exec(fm.raw);
        if (m)
          ctx.report({
            file: path,
            line: fm.startLine + fm.raw.slice(0, m.index).split("\n").length - 1,
            snippet: m[1] ?? "",
            severity: m[1]!.startsWith("!") ? "high" : "medium",
            message: `Frontmatter uses YAML ${m[1]!.startsWith("!") ? "tags" : "anchors or aliases"}, which parsers handle inconsistently`,
          });
      });
    },
  },
  {
    id: "metadata/invalid-name",
    title: "Skill name does not follow the spec",
    category: "metadata",
    severity: "low",
    confidence: "high",
    description: "`name` must be 1 to 64 lowercase letters, digits, and single hyphens, and match the skill's directory name.",
    scope: "bundle",
    check(ctx) {
      withFrontmatter(ctx, (fm, path) => {
        const name = fieldAsString(fm, "name");
        const line = lineOfKey(fm, "name");
        if (!name) return ctx.report({ file: path, line: fm.startLine, message: "Missing `name`" });
        if (name.length > 64 || !NAME_RE.test(name))
          ctx.report({ file: path, line, snippet: `name: ${name}`, message: `\`${name}\` is not a valid skill name` });
        else if (ctx.bundle.dirName !== "." && name !== ctx.bundle.dirName)
          ctx.report({
            file: path,
            line,
            snippet: `name: ${name}`,
            severity: "info",
            message: `name \`${name}\` differs from its directory \`${ctx.bundle.dirName}\``,
          });
        if (/anthropic|claude|openai/i.test(name))
          ctx.report({
            file: path,
            line,
            snippet: `name: ${name}`,
            severity: "info",
            message: `\`${name}\` uses a vendor name, which some platforms reserve and impostors use`,
          });
      });
    },
  },
  {
    id: "metadata/invalid-description",
    title: "Skill description missing or too long",
    category: "metadata",
    severity: "low",
    confidence: "high",
    description:
      "`description` is required and at most 1024 characters. Pi does not load skills without one; overlong descriptions crowd every session's context.",
    scope: "bundle",
    check(ctx) {
      withFrontmatter(ctx, (fm, path) => {
        const d = fieldAsString(fm, "description");
        if (!d || d.trim() === "") ctx.report({ file: path, line: fm.startLine, message: "Missing `description`" });
        else if (d.length > 1024)
          ctx.report({ file: path, line: lineOfKey(fm, "description"), message: `description is ${d.length} characters (limit 1024)` });
      });
    },
  },
  {
    id: "metadata/trigger-stuffing",
    title: "Description tries to make the skill load for everything",
    category: "prompt-injection",
    severity: "medium",
    confidence: "medium",
    description:
      "A description that demands the skill be used for every or any task, or stuffs dozens of keywords. The description is how agents choose skills; this hijacks that choice.",
    scope: "bundle",
    check(ctx) {
      withFrontmatter(ctx, (fm, path) => {
        const d = fieldAsString(fm, "description") ?? "";
        const line = lineOfKey(fm, "description");
        const m =
          /\b(?:always|must|should)\s+(?:be\s+)?(?:use[ds]?|invoked?|load(?:ed)?|call(?:ed)?|activated?|triggered?|run)\b[^.]{0,40}\b(?:every|all|any|each)\s+(?:task|request|prompt|message|conversation|query|question|interaction|session|response|turn)s?\b|\buse\s+(?:this\s+skill\s+)?(?:for|on|in|with)\s+(?:every|all|any)\s+(?:task|request|prompt|message|conversation|query|question|interaction)s?\b|\b(?:before|after)\s+(?:every|each|any)\s+(?:task|request|response|reply|message|tool\s+call|action)\b/i.exec(
            d,
          );
        if (m) ctx.report({ file: path, line, snippet: m[0], message: `The description asks to be used universally: "${m[0]}"` });
        const commas = d.split(",").length - 1;
        if (commas >= 25)
          ctx.report({
            file: path,
            line,
            severity: "low",
            message: `The description lists ${commas + 1} comma-separated items, which looks like keyword stuffing`,
          });
      });
    },
  },
  {
    id: "metadata/broad-allowed-tools",
    title: "Pre-approves unrestricted tools",
    category: "execution-surface",
    severity: "medium",
    confidence: "high",
    description:
      "`allowed-tools` grants permissions without asking while the skill is active. Unrestricted `Bash`, `Bash(*)`, or interpreters and downloaders (`Bash(curl:*)`, `Bash(python:*)`) mean any command the skill's text asks for runs without your approval.",
    remediation: "Narrow `allowed-tools` to the exact commands the skill needs, e.g. `Bash(git status:*)`.",
    scope: "bundle",
    check(ctx) {
      withFrontmatter(ctx, (fm, path) => {
        const raw = fieldAsString(fm, "allowed-tools") ?? fieldAsString(fm, "allowed_tools");
        if (!raw) return;
        const line = lineOfKey(fm, "allowed-tools");
        const tools = raw.split(/[\s,]+(?![^(]*\))/).filter(Boolean);
        for (const t of tools) {
          if (/^(?:\*|Bash|Bash\(\s*\*?\s*(?::\s*\*)?\s*\)|PowerShell|PowerShell\(\s*\*\s*\)|shell|exec_command)$/i.test(t)) {
            ctx.report({ file: path, line, snippet: `allowed-tools: ${raw}`, message: `\`${t}\` pre-approves any shell command` });
          } else if (
            /^Bash\(\s*(?:curl|wget|sh|bash|zsh|python[0-9.]*|node|npx|bunx|uvx|pip[0-9]*|npm|perl|ruby|eval|sudo|rm|ssh|scp|nc|osascript|powershell|pwsh|deno|bun)(?:\s+-[ce])?\s*(?::?\s*\*)?\s*\)$/i.test(
              t,
            )
          ) {
            ctx.report({
              file: path,
              line,
              snippet: `allowed-tools: ${raw}`,
              severity: "medium",
              message: `\`${t}\` pre-approves a command that can run arbitrary code or reach the network`,
            });
          }
        }
        if (tools.some((t) => /^(?:WebFetch|WebSearch)/.test(t)) && tools.some((t) => /^(?:Bash|Read)/.test(t))) {
          ctx.report({
            file: path,
            line,
            snippet: `allowed-tools: ${raw}`,
            severity: "low",
            message: "Pre-approves both reading local data and reaching the web",
          });
        }
      });
    },
  },
  {
    id: "metadata/skill-hooks",
    title: "Skill registers hooks",
    category: "execution-surface",
    severity: "medium",
    confidence: "high",
    description:
      "Claude Code skills can declare `hooks` in frontmatter. They register when the skill is used and run automatically for the rest of the session, even in untrusted non-interactive runs. Their commands are scanned below.",
    scope: "bundle",
    check(ctx) {
      withFrontmatter(ctx, (fm, path) => {
        if (fm.data.hooks !== undefined && fm.data.hooks !== null)
          ctx.report({
            file: path,
            line: lineOfKey(fm, "hooks"),
            message: "Frontmatter `hooks` run commands automatically on agent events once the skill is used",
          });
      });
    },
  },
  {
    id: "metadata/load-time-shell",
    title: "Runs shell commands when the skill loads",
    category: "execution-surface",
    severity: "low",
    confidence: "high",
    description:
      "Claude Code expands !`command` and ```! blocks by running them when the skill is invoked, before the model or you see the output, and without PreToolUse hooks seeing them. Each command is scanned as shell.",
    scope: "bundle",
    check(ctx) {
      if (ctx.bundle.kind !== "skill" && ctx.bundle.kind !== "plugin") return;
      for (const f of ctx.bundle.files) {
        if (f.kind !== "skill-md" && f.kind !== "markdown") continue;
        if (!f.text?.includes("!`") && !f.text?.includes("```!")) continue;
        const m = /(?:^|(?<=\s))!`[^`\n]{1,200}`|^ {0,3}```!\s*$/m.exec(f.text);
        if (m)
          ctx.report({
            file: f.path,
            line: (f.text ?? "").slice(0, m.index).split("\n").length,
            snippet: m[0],
            message: "Runs a shell command at load time, outside tool-call hooks and review",
          });
      }
    },
  },
  {
    id: "metadata/forked-background-agent",
    title: "Runs in a forked background agent",
    category: "execution-surface",
    severity: "low",
    confidence: "medium",
    description: "`context: fork` runs the skill in a subagent, in the background by default, where its actions are less visible.",
    scope: "bundle",
    check(ctx) {
      withFrontmatter(ctx, (fm, path) => {
        if (fieldAsString(fm, "context") === "fork")
          ctx.report({ file: path, line: lineOfKey(fm, "context"), message: "`context: fork` runs this skill in a separate subagent" });
      });
    },
  },
];
