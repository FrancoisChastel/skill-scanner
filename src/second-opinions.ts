import { createAnalyzers, detectAnalyzers } from "./analyzers";
import { ANALYZER_NAMES, type AnalyzerName, type Config, DEFAULT_CONFIG } from "./config";
import { createJudge, describeJudge } from "./judge";
import type { BundleJudge, ExternalAnalyzer, ScanOptions, SecondOpinions } from "./scan";

/**
 * The second opinions every scan the tool makes on the user's behalf gets by default: the jev judge
 * when a key allows it, and the analyzers the config turns on (gitleaks by default) that are
 * installed. Missing ones are left out without a word; `doctor` and `setup` say how to add them.
 */

/** In an install hook, a judge request never waits longer than this, and is retried once. */
export const QUICK_JUDGE_MS = 10_000;

/** Policy, suppressions, and second opinions from a config. `quick` is for install hooks. */
export function scanOptionsFrom(
  config: Config,
  opts: { readonly quick?: boolean } = {},
): Pick<ScanOptions, "policy" | "suppressions" | "secondOpinions"> {
  return {
    policy: { blockAt: config.blockAt, warnAt: config.warnAt },
    suppressions: config.ignore,
    secondOpinions: secondOpinionsFrom(config, opts.quick ?? false),
  };
}

export function secondOpinionsFrom(config: Config, quick = false): SecondOpinions {
  return {
    judge: config.judge,
    analyzers: ANALYZER_NAMES.filter((n) => config.analyzers[n]),
    ...(config.semgrepConfig ? { semgrepConfig: config.semgrepConfig } : {}),
    ...(quick ? { quick } : {}),
  };
}

/** The judge, when its mode and the keys allow, and the named analyzers that are installed. */
export async function buildSecondOpinions(
  s: SecondOpinions,
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ judge?: BundleJudge; analyzers: ExternalAnalyzer[] }> {
  const judgeCfg = s.quick ? { ...s.judge, timeoutMs: Math.min(s.judge.timeoutMs, QUICK_JUDGE_MS) } : s.judge;
  const { judge } = createJudge(judgeCfg, env, s.quick ? { maxRetries: 1 } : {});
  const config: Config = {
    ...DEFAULT_CONFIG,
    analyzers: Object.fromEntries(ANALYZER_NAMES.map((n) => [n, s.analyzers.includes(n)])) as Record<AnalyzerName, boolean>,
    ...(s.semgrepConfig ? { semgrepConfig: s.semgrepConfig } : {}),
  };
  const all = s.analyzers.length > 0 ? await createAnalyzers([...s.analyzers], config, env) : [];
  const installed = await Promise.all(all.map(async (a) => ((await a.unavailable().catch(() => "unavailable")) ? undefined : a)));
  return { ...(judge ? { judge } : {}), analyzers: installed.filter((a): a is ExternalAnalyzer => a !== undefined) };
}

/** Which second opinions would run here, as text, so cached results are not reused once that changes. */
export async function secondOpinionsFingerprint(s: SecondOpinions, env: NodeJS.ProcessEnv = process.env): Promise<string> {
  const { judge, analyzers } = await buildSecondOpinions(s, env);
  return `judge:${judge ? "on" : "off"};analyzers:${analyzers.map((a) => a.name).join(",")}`;
}

/** What `setup` tells a new user about the second opinions: what runs, and what a key or an install adds. */
export async function describeSecondOpinions(config: Config, env: NodeJS.ProcessEnv): Promise<string[]> {
  const lines: string[] = [];
  if (config.judge.enabled === false) lines.push('jev: off in the config ("judge": {"enabled": false}).');
  else {
    const d = describeJudge(config.judge, env);
    lines.push(
      d.problem
        ? "jev: runs as soon as it has a key, and then flags about twice as many malicious skills (78% against 40% for the rules alone), " +
            "for about $0.0003 a skill. Without one, scans stay offline. export TYPESAFE_API_KEY=<your key>   # from https://typesafe.ai"
        : `jev: on, with the key in $${d.keyEnv || "(none needed)"}. It warns, and never blocks on its own.`,
    );
  }
  const found = await detectAnalyzers(env);
  for (const name of ANALYZER_NAMES.filter((n) => config.analyzers[n])) {
    const a = found.find((f) => f.info.name === name);
    if (!a) continue;
    lines.push(a.path ? `${a.info.title}: on.` : `${a.info.title}: runs as soon as it is installed. ${a.info.install}`);
  }
  return lines;
}
