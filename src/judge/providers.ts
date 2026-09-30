import type { JudgeConfig } from "../config";

/**
 * Where jev is served and which key goes where. A key's prefix names the host that issued it,
 * whichever variable holds it, and a key is only ever sent to that host.
 */

export type ProviderName = NonNullable<JudgeConfig["provider"]>;

export interface Provider {
  readonly name: ProviderName;
  readonly label: string;
  /** Variable that conventionally holds this host's key. */
  readonly keyEnv: string;
  /** Prefix of the keys this host issues. */
  readonly keyPrefix: string;
  readonly base: string;
  readonly path: string;
  readonly model: string;
  readonly headers: Readonly<Record<string, string>>;
}

export const REPO_URL = "https://github.com/FrancoisChastel/skill-scanner";

/** Every host, in precedence order when several keys are set: TypeSafe first, as the direct hop. */
export const PROVIDERS: readonly Provider[] = Object.freeze([
  {
    name: "typesafe",
    label: "TypeSafe",
    keyEnv: "TYPESAFE_API_KEY",
    keyPrefix: "ts_",
    base: "https://api.typesafe.ai",
    path: "/v1/systemone",
    model: "jev-latest",
    headers: {},
  },
  {
    name: "openrouter",
    label: "OpenRouter",
    keyEnv: "OPENROUTER_API_KEY",
    keyPrefix: "sk-or-",
    base: "https://openrouter.ai/api",
    path: "/alpha/decisions",
    model: "typesafe/jev-1.13",
    // Optional app attribution OpenRouter asks integrations to send.
    headers: { "HTTP-Referer": REPO_URL, "X-Title": "skill-scanner" },
  },
  {
    name: "vercel",
    label: "Vercel AI Gateway",
    keyEnv: "AI_GATEWAY_API_KEY",
    keyPrefix: "vck_",
    base: "https://ai-gateway.vercel.sh/typesafe",
    path: "/v1/systemone",
    model: "typesafe-ai/jev",
    headers: {},
  },
] satisfies Provider[]);

/** A key for skill-scanner only. It wins over the provider variables; its prefix still decides the host. */
export const OVERRIDE_KEY_ENV = "SKILL_SCANNER_JEV_KEY";
export const DEFAULT_TIMEOUT_MS = 15_000;
export const NO_KEY = "no key: set TYPESAFE_API_KEY, OPENROUTER_API_KEY, or AI_GATEWAY_API_KEY";

const LOCAL_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export interface JudgeSetup {
  readonly provider: Provider;
  /** The variable the key was read from. Never the key itself. */
  readonly keyEnv: string;
  readonly apiKey: string;
  readonly url: string;
  readonly model: string;
  readonly timeoutMs: number;
}

export type SetupResult = { readonly ok: true; readonly setup: JudgeSetup } | { readonly ok: false; readonly problem: string };

interface KeyCandidate {
  readonly keyEnv: string;
  readonly key: string;
  /** Undefined only for an override key whose prefix no host claims. */
  readonly provider: Provider | undefined;
}

export function providerByName(name: ProviderName): Provider {
  return PROVIDERS.find((p) => p.name === name)!;
}

export function providerForKey(key: string): Provider | undefined {
  return PROVIDERS.find((p) => key.startsWith(p.keyPrefix));
}

/** Pick the host, key, endpoint and model from the config and environment, or say why none can be used. */
export function resolveSetup(cfg: JudgeConfig, env: NodeJS.ProcessEnv): SetupResult {
  const picked = pickKey(findKeys(env), cfg.provider);
  if ("problem" in picked) return { ok: false, problem: picked.problem };
  const { candidate, provider } = picked;

  const base = cfg.baseUrl === undefined ? { base: provider.base } : checkBaseUrl(cfg.baseUrl);
  if ("problem" in base) return { ok: false, problem: base.problem };
  // A custom endpoint set for TypeSafe must not quietly receive another host's ambient key.
  if (cfg.baseUrl !== undefined && cfg.provider === undefined && provider.name !== "typesafe")
    return {
      ok: false,
      problem: `judge.baseUrl is set but the key in use is ${article(provider.label)} ${provider.label} key (${candidate.keyEnv}); set judge.provider to "${provider.name}" to send it there`,
    };

  const model = cfg.model?.trim() || provider.model;
  const timeoutMs = Number.isInteger(cfg.timeoutMs) && cfg.timeoutMs > 0 ? cfg.timeoutMs : DEFAULT_TIMEOUT_MS;
  return {
    ok: true,
    setup: { provider, keyEnv: candidate.keyEnv, apiKey: candidate.key, url: `${base.base}${provider.path}`, model, timeoutMs },
  };
}

/** Every key that is set: the override first, then the provider variables in precedence order. */
function findKeys(env: NodeJS.ProcessEnv): KeyCandidate[] {
  const override = env[OVERRIDE_KEY_ENV]?.trim();
  const fromProviders = PROVIDERS.flatMap((p) => {
    const key = env[p.keyEnv]?.trim();
    // An unrecognised prefix belongs to the host of the variable it sits in.
    return key ? [{ keyEnv: p.keyEnv, key, provider: providerForKey(key) ?? p }] : [];
  });
  return [...(override ? [{ keyEnv: OVERRIDE_KEY_ENV, key: override, provider: providerForKey(override) }] : []), ...fromProviders];
}

type Picked = { readonly candidate: KeyCandidate; readonly provider: Provider } | { readonly problem: string };

function pickKey(candidates: readonly KeyCandidate[], forced: ProviderName | undefined): Picked {
  if (candidates.length === 0) return { problem: NO_KEY };
  if (forced) return pickForced(candidates, providerByName(forced));
  const [first] = candidates;
  if (first?.keyEnv === OVERRIDE_KEY_ENV) {
    return first.provider
      ? { candidate: first, provider: first.provider }
      : { problem: `${OVERRIDE_KEY_ENV} does not start with ts_, sk-or-, or vck_; set judge.provider to say which host issued it` };
  }
  const rank = (c: KeyCandidate): number => PROVIDERS.indexOf(c.provider!);
  // Stable sort: among keys for the same host, the host's own variable comes first.
  const best = [...candidates].sort((a, b) => rank(a) - rank(b))[0]!;
  return { candidate: best, provider: best.provider! };
}

/** With judge.provider set, only a key issued by that host is used; an override with an unknown prefix is taken as the user's word. */
function pickForced(candidates: readonly KeyCandidate[], forced: Provider): Picked {
  const match = candidates.find((c) => (c.provider ?? forced) === forced);
  if (match) return { candidate: match, provider: forced };
  const found = candidates.map((c) => `${c.keyEnv} (${c.provider?.label ?? "unknown"} key)`).join(", ");
  return {
    problem: `judge.provider is "${forced.name}" but no ${forced.label} key is set (found ${found}); keys are sent only to the host that issued them: set ${forced.keyEnv}`,
  };
}

/** https only, except plain http to this machine for a local proxy. The hostname is compared exactly. */
export function checkBaseUrl(raw: string): { readonly base: string } | { readonly problem: string } {
  const problem = "judge.baseUrl must be an https URL (http only for localhost, 127.0.0.1, or ::1) without credentials, query, or fragment";
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return { problem };
  }
  const local = url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname.toLowerCase());
  if ((url.protocol !== "https:" && !local) || url.username || url.password || url.search || url.hash) return { problem };
  return { base: `${url.origin}${url.pathname}`.replace(/\/+$/, "") };
}

function article(word: string): string {
  return /^[aeiou]/i.test(word) ? "an" : "a";
}
