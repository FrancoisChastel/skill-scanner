#!/usr/bin/env node
// Build the npm package and the self-contained runtime that `setup` installs for harness hooks.
// Zero runtime dependencies, so every entry bundles to plain Node ESM.
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const run = (cmd, args) => execFileSync(cmd, args, { stdio: "inherit" });
const bun = process.env.BUN ?? "bun";
// Contributors running several builds at once can point each at its own directory.
const out = process.env.SKILL_SCANNER_OUTDIR ?? "dist";

rmSync(out, { recursive: true, force: true });

// Library and adapter entries for npm consumers. Harness SDKs are type-only imports.
run(bun, [
  "build",
  "src/index.ts",
  "src/cli.ts",
  "src/adapters/opencode.ts",
  "src/adapters/pi.ts",
  "--root",
  "src",
  "--outdir",
  out,
  "--target",
  "node",
  "--format",
  "esm",
  "--splitting",
  "--external",
  "@earendil-works/*",
  "--external",
  "@opencode-ai/*",
]);

// One file per runtime role, copied to ~/.skill-scanner/bin by `setup` so hooks never depend on npx or PATH.
for (const [entry, file] of [
  ["src/cli.ts", `${out}/runtime/skill-scanner.mjs`],
  ["src/adapters/opencode.ts", `${out}/runtime/opencode-plugin.mjs`],
  ["src/adapters/pi.ts", `${out}/runtime/pi-extension.mjs`],
]) {
  run(bun, [
    "build",
    entry,
    "--outfile",
    file,
    "--target",
    "node",
    "--format",
    "esm",
    "--external",
    "@earendil-works/*",
    "--external",
    "@opencode-ai/*",
  ]);
}

run("npx", ["tsc", "-p", "tsconfig.build.json", "--emitDeclarationOnly", "--declaration", "--outDir", out]);
addDeclarationExtensions(out);

// Keep exactly one shebang on the bin files and make them executable.
for (const bin of [`${out}/cli.js`, `${out}/runtime/skill-scanner.mjs`]) {
  if (!existsSync(bin)) throw new Error(`build did not produce ${bin}`);
  const body = readFileSync(bin, "utf8").replace(/^(#![^\n]*\n)+/, "");
  writeFileSync(bin, `#!/usr/bin/env node\n${body}`);
  chmodSync(bin, 0o755);
}
console.log(`built ${out}/`);

/**
 * Declarations are emitted with extension-less relative imports (the source uses bundler
 * resolution). Consumers on `moduleResolution: NodeNext` need explicit `.js` paths, or every type
 * behind such an import becomes `any` for them, so the specifiers are rewritten after emit.
 */
function addDeclarationExtensions(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) addDeclarationExtensions(path);
    else if (name.endsWith(".d.ts")) {
      const text = readFileSync(path, "utf8");
      const fixed = text.replace(/(\bfrom\s+|\bimport\s*\(\s*)(["'])(\.{1,2}\/[^"']+)\2/g, (m, lead, q, spec) => {
        if (/\.(?:js|mjs|cjs|json)$/.test(spec)) return m;
        const base = resolve(dirname(path), spec);
        if (existsSync(`${base}.d.ts`)) return `${lead}${q}${spec}.js${q}`;
        if (existsSync(join(base, "index.d.ts"))) return `${lead}${q}${spec}/index.js${q}`;
        throw new Error(`${path}: cannot resolve declaration import ${spec}`);
      });
      if (fixed !== text) writeFileSync(path, fixed);
    }
  }
}
