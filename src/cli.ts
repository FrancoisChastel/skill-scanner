#!/usr/bin/env node
// Bin entry: always runs. Everything testable lives in cli/main.ts.
import { processIO } from "./cli/io";
import { main } from "./cli/main";

// Ctrl+C and termination exit through process.exit so 'exit' handlers run, including the one that
// kills external analyzers running in their own process groups. Commands that manage a child
// themselves (`guard`, `add`) register their own handlers, and then this one stands aside.
for (const [signal, code] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
] as const) {
  process.on(signal, () => {
    if (process.listenerCount(signal) === 1) process.exit(code);
  });
}

main(process.argv.slice(2), processIO()).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`skill-scanner: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 2;
  },
);
