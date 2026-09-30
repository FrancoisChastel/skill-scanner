import type { VerdictPolicy } from "../core/severity";
import type { ScanReport, Severity } from "../core/types";

/** Contract for reporters in `src/report/`: pure functions from a ScanReport to text. */

export type ReportFormat = "text" | "json" | "sarif" | "markdown";

export const REPORT_FORMATS: readonly ReportFormat[] = ["text", "json", "sarif", "markdown"];

export const isReportFormat = (v: unknown): v is ReportFormat => typeof v === "string" && (REPORT_FORMATS as readonly string[]).includes(v);

export interface TextOptions {
  readonly color: boolean;
  /** Hide findings below this severity in the listing (counts still include them). Default `low`. */
  readonly minSeverity?: Severity;
  /** Show evidence and remediation for each finding. */
  readonly verbose?: boolean;
  /** Terminal width for wrapping; default 100. */
  readonly width?: number;
  /** The policy the scan used, to explain the verdict. Default `DEFAULT_POLICY`. */
  readonly policy?: VerdictPolicy;
}

export interface SarifOptions {
  /**
   * POSIX path to put before every result path of `report`, so paths are relative to the repository
   * root rather than the scan target (GitHub code scanning resolves them from the root). Default none.
   */
  readonly uriPrefix?: (report: ScanReport) => string | undefined;
}

export interface MarkdownOptions {
  /** Hide findings below this severity in the tables. Default `low`. */
  readonly minSeverity?: Severity;
  readonly policy?: VerdictPolicy;
  /** Stop adding table rows after this many, to stay under comment size limits. Default 150. */
  readonly maxRows?: number;
}

/** Options for any format; each reporter reads the fields it knows. */
export interface ReportOptions extends TextOptions, SarifOptions {
  readonly maxRows?: number;
}
