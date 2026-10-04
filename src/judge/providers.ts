import type { JudgeConfig } from "../config";

/**
 * Where jev is served and which key goes where. A key's prefix names the host that issued it,
 * whichever variable holds it, and a key is only ever sent to that host.
 */

export type ProviderName = NonNullable<JudgeConfig["provider"]>;

export interface Provider {
  readonly name: ProviderName;
  readonly label: string;
  /** Variable that conventionally holds this host's key; empty for a host that takes none. */
  readonly keyEnv: string;
  /** Prefix of the keys this host issues; empty when its keys have no telling prefix (then `judge.provider` must name it). */
  readonly keyPrefix: string;
  /** Default endpoint base; empty when the user must give `judge.baseUrl`. `{accountId}` is filled from the config. */
  readonly base: string;
  /** Path under the base; `{model}` is filled in for hosts that put the model in the URL. */
  readonly path: string;
  readonly model: string;
  readonly headers: Readonly<Record<string, string>>;
  /** Whether a request needs a bearer key at all. */
  readonly auth: "bearer" | "none";
  /** Whether the key's prefix can identify this host; otherwise it is only used when `judge.provider` names it. */
  readonly detectable: boolean;
}

export const REPO_URL = "https://github.com/FrancoisChastel/skill-scanner";

/**
 * Every host, in precedence order when several keys are set: TypeSafe first, as the direct hop.
 * The first three are detected from a key's prefix. The others speak the same System One protocol
 * but must be named in `judge.provider`: Cloudflare tokens have no telling prefix, Ollama takes no
 * key, and a custom host is whatever the user points at. Only TypeSafe, OpenRouter, and Vercel
 * are exercised by the test suite; the rest follow their published request shapes.
 */
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
    auth: "bearer",
    detectable: true,
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
    auth: "bearer",
    detectable: true,
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
    auth: "bearer",
    detectable: true,
  },
  {
    // Workers AI REST: POST .../accounts/<id>/ai/run/<model>; the answer sits under `result`.
    name: "cloudflare",
    label: "Cloudflare Workers AI",
    keyEnv: "CLOUDFLARE_API_TOKEN",
    keyPrefix: "",
    base: "https://api.cloudflare.com/client/v4/accounts/{accountId}/ai/run",
    path: "/{model}",
    model: "typesafe/jev",
    headers: {},
    auth: "bearer",
    detectable: false,
  },
  {
    // Ollama 0.35+ serves the System One protocol locally for its decision models (nimble, tev1). No key.
    name: "ollama",
    label: "Ollama",
    keyEnv: "",
    keyPrefix: "",
    base: "http://localhost:11434",
    path: "/v1/systemone",
    model: "nimble",
    headers: {},
    auth: "none",
    detectable: false,
  },
  {
    // Any other host that speaks the System One protocol: a self-hosted jev, a proxy. `judge.baseUrl` is the full endpoint.
    name: "custom",
    label: "custom System One endpoint",
    keyEnv: "",
    keyPrefix: "",
    base: "",
    path: "",
    model: "jev-latest",
    headers: {},
    auth: "bearer",
    detectable: false,
  },
] satisfies Provider[]);

/** A key for skill-scanner only. It wins over the provider variables; its prefix still decides the host. */
export const OVERRIDE_KEY_ENV = "SKILL_SCANNER_JEV_KEY";
export const DEFAULT_TIMEOUT_MS = 15_000;
export const NO_KEY =
  "no key: set TYPESAFE_API_KEY, OPENROUTER_API_KEY, or AI_GATEWAY_API_KEY (or name a cloudflare, ollama, or custom host in judge.provider)";
export const ACCOUNT_ID_ENV = "CLOUDFLARE_ACCOUNT_ID";

const LOCAL_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export interface JudgeSetup {
  readonly provider: Provider;
  /** The variable the key was read from. Never the key itself. Empty for a host that takes no key. */
  readonly keyEnv: string;
  /** Empty for a host that takes no key. */
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
  return PROVIDERS.find((p) => p.detectable && key.startsWith(p.keyPrefix));
}

/** Pick the host, key, endpoint and model from the config and environment, or say why none can be used. */
export function resolveSetup(cfg: JudgeConfig, env: NodeJS.ProcessEnv): SetupResult {
  const forced = cfg.provider ? providerByName(cfg.provider) : undefined;
  if (forced && !forced.detectable) return resolveNamed(forced, cfg, env);
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
  return {
    ok: true,
    setup: {
      provider,
      keyEnv: candidate.keyEnv,
      apiKey: candidate.key,
      url: `${base.base}${provider.path}`,
      model,
      timeoutMs: timeoutOf(cfg),
    },
  };
}

/**
 * Hosts that are named rather than detected. The key, when one is needed, comes from the override
 * variable or the host's own variable, whatever its prefix: naming the host is the user's word.
 */
function resolveNamed(provider: Provider, cfg: JudgeConfig, env: NodeJS.ProcessEnv): SetupResult {
  const override = env[OVERRIDE_KEY_ENV]?.trim();
  const own = provider.keyEnv ? env[provider.keyEnv]?.trim() : undefined;
  const keyEnv = override ? OVERRIDE_KEY_ENV : own ? provider.keyEnv : "";
  const apiKey = override || own || "";
  if (provider.auth === "bearer" && !apiKey) {
    return { ok: false, problem: `judge.provider is "${provider.name}" but no key is set: set ${provider.keyEnv || OVERRIDE_KEY_ENV}` };
  }
  const model = cfg.model?.trim() || provider.model;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,99}$/.test(model)) return { ok: false, problem: "judge.model must be a plain model id" };
  let base: string;
  if (provider.name === "custom") {
    if (cfg.baseUrl === undefined)
      return { ok: false, problem: 'judge.provider "custom" needs judge.baseUrl: the full System One endpoint' };
    const checked = checkBaseUrl(cfg.baseUrl);
    if ("problem" in checked) return { ok: false, problem: checked.problem };
    base = checked.base;
  } else if (cfg.baseUrl !== undefined) {
    const checked = checkBaseUrl(cfg.baseUrl);
    if ("problem" in checked) return { ok: false, problem: checked.problem };
    base = checked.base;
  } else {
    base = provider.base;
  }
  if (base.includes("{accountId}")) {
    const accountId = cfg.accountId?.trim() || env[ACCOUNT_ID_ENV]?.trim() || "";
    if (!/^[0-9a-f]{32}$/i.test(accountId)) {
      return { ok: false, problem: `judge.provider "cloudflare" needs the account id: set judge.accountId or ${ACCOUNT_ID_ENV}` };
    }
    base = base.replace("{accountId}", accountId);
  }
  const url = `${base}${provider.path.replace("{model}", model)}`;
  return { ok: true, setup: { provider, keyEnv, apiKey, url, model, timeoutMs: timeoutOf(cfg) } };
}

function timeoutOf(cfg: JudgeConfig): number {
  return Number.isInteger(cfg.timeoutMs) && cfg.timeoutMs > 0 ? cfg.timeoutMs : DEFAULT_TIMEOUT_MS;
}

/** Every key that is set: the override first, then the provider variables in precedence order. */
function findKeys(env: NodeJS.ProcessEnv): KeyCandidate[] {
  const override = env[OVERRIDE_KEY_ENV]?.trim();
  // Only hosts whose keys announce themselves; a Cloudflare token or a custom key is used only when judge.provider names the host.
  const fromProviders = PROVIDERS.filter((p) => p.detectable).flatMap((p) => {
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
      : { problem: `${OVERRIDE_KEY_ENV} does not start with ts_, sk-or-, or vck_; set judge.provider to say which host it belongs to` };
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
