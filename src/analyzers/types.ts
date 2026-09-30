import type { AnalyzerName, Config } from "../config";
import type { ExternalAnalyzer } from "../scan";

export interface AnalyzerInfo {
  readonly name: AnalyzerName;
  readonly title: string;
  /** Executable looked up on PATH. */
  readonly binary: string;
  /** One command that installs it, shown by `doctor`. */
  readonly install: string;
  readonly homepage: string;
  readonly license: string;
  /** Whether the tool contacts the network during a scan (e.g. vulnerability databases). */
  readonly network: boolean;
  readonly description: string;
}

/** Everything the catalog needs to find, probe, and run one external tool. */
export interface ToolDriver {
  readonly info: AnalyzerInfo;
  /** Absolute path of the executable to run, or undefined when the tool is not installed. */
  locate(env: NodeJS.ProcessEnv): Promise<string | undefined>;
  /** Arguments that print the tool's version. */
  readonly versionArgs: readonly string[];
  /** The environment the tool runs with: the caller's plus settings that keep it offline and quiet. */
  toolEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv;
  /** Whether a scan with this configuration contacts the network. */
  network(cfg: Config): boolean;
  create(env: NodeJS.ProcessEnv, cfg: Config): ExternalAnalyzer;
}
