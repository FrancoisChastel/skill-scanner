import type { FlagSpecs } from "./args";
import type { CliIO } from "./io";

/** Exit codes, stable across releases. */
export const EXIT = Object.freeze({
  /** Nothing at or above the failure threshold. */
  ok: 0,
  /** The scan found something at or above the threshold, or an install was refused. */
  findings: 1,
  /** Bad arguments, unreadable config, or the scan itself failed. */
  error: 2,
});

export interface Command {
  readonly name: string;
  /** One line for `skill-scanner help`. */
  readonly summary: string;
  /** Usage line(s) after the command name, e.g. `<path> [options]`. */
  readonly usage: string;
  readonly flags: FlagSpecs;
  /** Extra help text shown under the flags. */
  readonly details?: string;
  run(argv: readonly string[], io: CliIO): Promise<number>;
}
