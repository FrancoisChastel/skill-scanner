import { basename } from "../core/classify";
import { extractEmbedded, parseJsonLoose } from "../core/embedded";
import { patternRule } from "../core/pattern-rule";
import type { BundleRule, FileRule } from "../core/rule";

/** Dependencies and package manifests: what gets installed and run on the skill's behalf. */

/** Package indexes run by the registry itself or by the vendor of a major framework, used as documented. */
const KNOWN_INDEX_RE =
  /^https?:\/\/(?:(?:registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|test\.pypi\.org|files\.pythonhosted\.org|download\.pytorch\.org|pypi\.nvidia\.com|pypi\.ngc\.nvidia\.com|developer\.download\.nvidia\.com|data\.pyg\.org|storage\.googleapis\.com\/jax-releases|pip\.repos\.neuron\.amazonaws\.com|flashinfer\.ai|wheels\.vllm\.ai)(?:[/:]|$))/i;

const indexUrlOf = (s: string): string => /https?:\/\/\S+/.exec(s)?.[0] ?? "";

function lineOf(text: string, needle: string): number {
  const i = text.indexOf(needle);
  return i === -1 ? 1 : text.slice(0, i).split("\n").length;
}

export const supplyChainBundleRules: readonly BundleRule[] = [
  {
    id: "supply-chain/install-script",
    title: "Package runs a script on install",
    category: "supply-chain",
    severity: "medium",
    confidence: "high",
    description:
      "A package.json lifecycle script (`preinstall`, `postinstall`, `prepare`, ...) runs automatically when anyone, including the agent or a Pi package install, runs `npm install` here.",
    remediation: "Read the script. Prefer skills that need no install step, or run installs with `--ignore-scripts`.",
    scope: "bundle",
    check(ctx) {
      const { commands } = extractEmbedded(ctx.bundle);
      for (const [path, list] of commands) {
        if (basename(path) !== "package.json") continue;
        for (const c of list) {
          if (c.trigger !== "lifecycle-script") continue;
          ctx.report({
            file: path,
            line: c.line,
            snippet: `"${c.pointer.slice(8)}": "${c.command}"`,
            message: `\`${c.pointer.slice(8)}\` runs \`${c.command.slice(0, 120)}\` on npm install`,
          });
        }
      }
    },
  },
  {
    id: "supply-chain/non-registry-dependency",
    title: "Dependency from git, a URL, or a local path",
    category: "supply-chain",
    severity: "medium",
    confidence: "medium",
    description:
      "A dependency that bypasses the registry (git, tarball URL, GitHub shorthand, `file:`) or accepts any version (`*`, `latest`). Its content can change without a new release of the skill.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        if (basename(f.path) !== "package.json" || !f.text) continue;
        const json = parseJsonLoose(f.text) as Record<string, unknown> | undefined;
        if (!json || typeof json !== "object") continue;
        for (const field of ["dependencies", "optionalDependencies", "peerDependencies", "devDependencies"]) {
          const deps = json[field];
          if (typeof deps !== "object" || deps === null) continue;
          for (const [name, spec] of Object.entries(deps as Record<string, unknown>)) {
            if (typeof spec !== "string") continue;
            const remote = /^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:)|^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec);
            const floating = spec === "*" || spec === "latest" || spec === "" || spec === "x";
            if (!remote && !floating) continue;
            ctx.report({
              file: f.path,
              line: lineOf(f.text, `"${name}"`),
              snippet: `"${name}": "${spec}"`,
              severity: remote ? "medium" : "low",
              message: remote
                ? `${field}: ${name} comes from ${spec}, not the registry`
                : `${field}: ${name} accepts any version (${spec || "empty"})`,
            });
          }
        }
      }
    },
  },
  {
    id: "supply-chain/python-index-redirect",
    title: "Python requirements change the package index",
    category: "supply-chain",
    severity: "high",
    confidence: "medium",
    description:
      "`--extra-index-url`, `--index-url`, `--trusted-host`, or `--find-links` in a requirements file. An extra index is the classic dependency-confusion vector: a same-named package there wins.",
    scope: "bundle",
    check(ctx) {
      for (const f of ctx.bundle.files) {
        if (!/(^|\/)(?:requirements|constraints)[^/]*\.txt$/i.test(f.path) || !f.text) continue;
        f.text.split("\n").forEach((l, i) => {
          const t = l.trim();
          if (/^(?:--extra-index-url|--index-url|-i\s|--trusted-host|--find-links|-f\s)/.test(t)) {
            if (KNOWN_INDEX_RE.test(indexUrlOf(t))) return;
            ctx.report({
              file: f.path,
              line: i + 1,
              snippet: t,
              severity: t.startsWith("--extra-index-url") || t.startsWith("--trusted-host") ? "high" : "medium",
              message: `Requirements option \`${t.split(/\s+/)[0]}\` changes where packages come from`,
            });
          } else if (/^(?:git\+|https?:\/\/|[\w.-]+\s*@\s*(?:git\+|https?:))/.test(t)) {
            ctx.report({
              file: f.path,
              line: i + 1,
              snippet: t,
              severity: "medium",
              message: "Requirement installed from a URL or git rather than the index",
            });
          }
        });
      }
    },
  },
];

export const supplyChainFileRules: readonly FileRule[] = [
  patternRule({
    id: "supply-chain/registry-redirect",
    title: "Points a package manager at another registry",
    category: "supply-chain",
    severity: "high",
    confidence: "medium",
    description:
      "Changes the npm, yarn, or pip registry for the whole machine or project, so every later install can be served by someone else.",
    patterns: [
      /\bnpm\s+config\s+set\s+(?:@[\w-]+:)?registry\b[^\n]*|\byarn\s+config\s+set\s+npmRegistryServer\b[^\n]*|\bpnpm\s+config\s+set\s+registry\b[^\n]*|\bpip[0-9.]*\s+config\s+set\s+(?:global|user)\.(?:index-url|extra-index-url)\b[^\n]*/g,
      // An .npmrc `registry=` or .yarnrc `registry "..."` line, also when a script writes it with the URL in a variable.
      /^\s*(?:@[\w-]+:)?registry\s*(?:=\s*|\s+["'])(?:https?:\/\/|\$\{?[A-Za-z_])\S*/gm,
      /\b(?:pip[0-9.]*|uv\s+pip)\s+install\b[^\n]{0,200}\s--(?:extra-)?index-url[=\s]+\S+/g,
      /\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add)\b[^\n]{0,200}\s--registry[=\s]+\S+/g,
    ],
    prefilter: /registry|index-url|npmRegistryServer/,
    // The dependency-confusion vector is an extra index or a machine-wide switch. A scoped registry only serves
    // that scope's private packages, and a single install from a project's own index is the documented way to get it.
    adjust: (m) => {
      const url = indexUrlOf(m[0]);
      if (KNOWN_INDEX_RE.test(url)) return { severity: "info", confidence: "low" };
      if (/^\s*@[\w-]+:registry/.test(m[0])) return { severity: "low" };
      if (/\b(?:pip[0-9.]*|uv\s+pip)\s+install\b/.test(m[0]) && !/--extra-index-url/.test(m[0])) return { severity: "medium" };
      return undefined;
    },
  }),
];
