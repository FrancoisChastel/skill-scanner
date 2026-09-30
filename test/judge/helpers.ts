import type { JudgeConfig } from "../../src/config";
import type { Finding, SkillBundle, SkillFile } from "../../src/core/types";
import type { FetchLike } from "../../src/judge";
import { PROBE_IDS, type ProbeId } from "../../src/judge/probes";

/** Shared fixtures for the judge tests. Nothing here touches the network. */

export const judgeCfg = (over: Partial<JudgeConfig> = {}): JudgeConfig => ({ enabled: true, timeoutMs: 1000, ...over });

/** A key-shaped string built at run time, so no live-looking literal sits in the source. */
export const fakeKey = (prefix: string): string => `${prefix}${["unit", "test", "only"].join("-")}-${"9876543210".split("").join("")}`;

export function textFile(path: string, kind: SkillFile["kind"], text: string, extra: Partial<SkillFile> = {}): SkillFile {
  return { path, kind, size: text.length, text, ...extra };
}

export function makeBundle(over: Partial<SkillBundle> = {}): SkillBundle {
  return {
    kind: "skill",
    name: "demo",
    root: "skills/demo",
    dirName: "demo",
    files: [textFile("SKILL.md", "skill-md", "---\nname: demo\n---\nSay hello.\n")],
    digest: `sha256:${"0".repeat(64)}`,
    notes: [],
    ...over,
  };
}

export function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "exfiltration/test-soft-rule",
    title: "Test finding",
    category: "exfiltration",
    severity: "high",
    confidence: "medium",
    message: "a test finding",
    location: { file: "skills/demo/SKILL.md", line: 3 },
    bundle: "demo",
    source: "static",
    ...over,
  };
}

/** Every probe at `fill`, with the given overrides. */
export function scoresOf(over: Partial<Record<ProbeId, number>> = {}, fill = 0.3): Record<ProbeId, number> {
  return Object.fromEntries(PROBE_IDS.map((id) => [id, over[id] ?? fill])) as Record<ProbeId, number>;
}

/** A well-formed System One response for the given P(true) per probe. */
export function answersFor(scores: Readonly<Record<string, number>>, model = "jev-test"): unknown {
  const answers = Object.fromEntries(
    Object.entries(scores).map(([id, p]) => [
      id,
      { type: "choice", choice: p >= 0.5 ? "true" : "false", probabilities: { true: p, false: 1 - p }, confidence: Math.max(p, 1 - p) },
    ]),
  );
  return { answers, usage: { input_tokens: 10, output_tokens: 8 }, model };
}

export const jsonResponse = (value: unknown, status = 200): Response =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

export interface RecordedCall {
  readonly url: string;
  readonly init: RequestInit;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: { model?: unknown; state?: unknown; questions?: Record<string, Record<string, unknown>> };
  readonly rawBody: string;
}

/** A fake fetch that answers from `replies` in order (repeating the last) and records every call. */
export function fakeFetch(...replies: ReadonlyArray<() => Response | Promise<Response>>): { fetch: FetchLike; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetch: FetchLike = async (url, init) => {
    const rawBody = typeof init.body === "string" ? init.body : "";
    calls.push({ url, init, headers: { ...(init.headers as Record<string, string>) }, body: JSON.parse(rawBody || "{}"), rawBody });
    const reply = replies[Math.min(calls.length - 1, replies.length - 1)];
    if (!reply) throw new Error("fakeFetch has no replies");
    return reply();
  };
  return { fetch, calls };
}

/** Behaves like fetch on a server that never answers: settles only when the request is aborted. */
export const hangingFetch: FetchLike = (_url, init) =>
  new Promise<Response>((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => reject(new DOMException("The operation was aborted.", "AbortError")), { once: true });
  });

/** An answer for all eight probes at 0.3: no doubt, no confirmation, nothing added. */
export const neutralReply = (): Response => jsonResponse(answersFor(scoresOf()));
