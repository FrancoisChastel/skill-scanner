import type { Category } from "../core/types";

/**
 * The eight threat probes jev answers about every judged skill, asked as boolean `choice`
 * questions. Never `noul`: Cisco measured `noul` answers inverted against the label on
 * MaliciousSkillBench (AUC 0.25 to 0.31), while the same model asked `choice` questions
 * separated well (obfuscation 0.908, prompt injection 0.881 on held-out test).
 *
 * The question wording and the shared instructions are adapted from Cisco AI Defense
 * skill-scanner (evals/experiments/c3_openjev_local.py), Copyright 2026 Cisco Systems, Inc.
 * and its affiliates, Apache License 2.0. See PROBE_ATTRIBUTION and THIRD_PARTY_NOTICES.md.
 */

/** Notice text for THIRD_PARTY_NOTICES.md, kept next to the wording it covers. */
export const PROBE_ATTRIBUTION =
  "The jev probe questions and their shared instructions in src/judge/probes.ts are adapted from " +
  "Cisco AI Defense skill-scanner (https://github.com/cisco-ai-defense/skill-scanner), " +
  "evals/experiments/c3_openjev_local.py. Copyright 2026 Cisco Systems, Inc. and its affiliates. " +
  "Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0). " +
  "Changes: each question is sent as a TypeSafe System One `choice` question with true/false criteria " +
  "written for skill-scanner.";

/** Sent with every probe. A skill may legitimately contain any code; the model is asked about behaviour, not presence. */
export const INSTRUCTIONS =
  "A skill is an open specification and may contain any code for any legitimate purpose. " +
  "Ordinary development, build, test and documentation work is not a threat. " +
  "Answer only about what the content actually does.";

export const PROBE_IDS = [
  "data_exfiltration",
  "destructive_command",
  "obfuscation",
  "prompt_injection",
  "remote_hidden_execution",
  "security_control_change",
  "sensitive_data_access",
  "supply_chain",
] as const;
export type ProbeId = (typeof PROBE_IDS)[number];

export interface Probe {
  readonly id: ProbeId;
  /** The question as asked. */
  readonly question: string;
  /** The question as a statement, completing "P(true) = 0.91 that this skill ...". */
  readonly claim: string;
  /** Criterion for the `false` option. The `true` criterion is built from `claim`. */
  readonly no: string;
  /** Category and title of the finding the judge adds when this probe fires with no static finding in its family. */
  readonly category: Category;
  readonly title: string;
}

export const PROBES: readonly Probe[] = Object.freeze([
  {
    id: "data_exfiltration",
    question: "Does this skill send sensitive data to an external destination?",
    claim: "sends sensitive data to an external destination",
    no: "No: it sends no sensitive data to an external destination.",
    category: "exfiltration",
    title: "jev: may send sensitive data out",
  },
  {
    id: "destructive_command",
    question: "Does this skill delete, overwrite or destroy data?",
    claim: "deletes, overwrites or destroys data",
    no: "No: it does not delete, overwrite or destroy data.",
    category: "destructive",
    title: "jev: may delete or overwrite data",
  },
  {
    id: "obfuscation",
    question: "Is any part of this skill obfuscated, encoded or deliberately hidden?",
    claim: "has a part that is obfuscated, encoded or deliberately hidden",
    no: "No: no part of it is obfuscated, encoded or deliberately hidden.",
    category: "obfuscation",
    title: "jev: may hide or encode content",
  },
  {
    id: "prompt_injection",
    question: "Does this skill try to override, ignore or manipulate an AI agent's instructions?",
    claim: "tries to override, ignore or manipulate an AI agent's instructions",
    no: "No: it does not try to override, ignore or manipulate an AI agent's instructions.",
    category: "prompt-injection",
    title: "jev: may manipulate the agent's instructions",
  },
  {
    id: "remote_hidden_execution",
    question: "Does this skill download and execute remote code?",
    claim: "downloads and executes remote code",
    no: "No: it does not download and execute remote code.",
    category: "remote-execution",
    title: "jev: may download and run remote code",
  },
  {
    id: "security_control_change",
    question: "Does this skill disable, weaken or bypass a security control?",
    claim: "disables, weakens or bypasses a security control",
    no: "No: it does not disable, weaken or bypass a security control.",
    category: "privilege",
    title: "jev: may weaken a security control",
  },
  {
    id: "sensitive_data_access",
    question: "Does this skill read credentials, keys, tokens or other secrets?",
    claim: "reads credentials, keys, tokens or other secrets",
    no: "No: it does not read credentials, keys, tokens or other secrets.",
    category: "credential-access",
    title: "jev: may read secrets",
  },
  {
    id: "supply_chain",
    question: "Does this skill install, substitute or tamper with software dependencies?",
    claim: "installs, substitutes or tampers with software dependencies",
    no: "No: it does not install, substitute or tamper with software dependencies.",
    category: "supply-chain",
    title: "jev: may tamper with dependencies",
  },
] satisfies Probe[]);

/** Which probe speaks to a finding of each category. Categories about packaging and metadata have none. */
export const PROBE_FOR_CATEGORY: Readonly<Record<Category, ProbeId | undefined>> = Object.freeze({
  exfiltration: "data_exfiltration",
  network: "data_exfiltration",
  destructive: "destructive_command",
  obfuscation: "obfuscation",
  "hidden-content": "obfuscation",
  "prompt-injection": "prompt_injection",
  // Instructions to deceive the user manipulate what the agent does and says.
  deception: "prompt_injection",
  "remote-execution": "remote_hidden_execution",
  privilege: "security_control_change",
  persistence: "security_control_change",
  "credential-access": "sensitive_data_access",
  secrets: "sensitive_data_access",
  "supply-chain": "supply_chain",
  packaging: undefined,
  metadata: undefined,
  "execution-surface": undefined,
});

/** `prompt_injection` -> `judge/prompt-injection`. */
export const judgeRuleId = (id: ProbeId): string => `judge/${id.replaceAll("_", "-")}`;

export const JUDGE_REMEDIATION =
  "Read the files the question is about and decide. If it is a false alarm, suppress this rule for this skill; " +
  "the judge alone never blocks under the default policy.";
