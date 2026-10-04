import { describe, expect, test } from "bun:test";
import { createJudge, type FetchLike } from "../../src/judge";
import { unwrapEnvelope } from "../../src/judge/protocol";
import { ACCOUNT_ID_ENV, OVERRIDE_KEY_ENV, resolveSetup } from "../../src/judge/providers";
import { fakeKey, judgeCfg, makeBundle } from "./helpers";

/**
 * The named hosts: Cloudflare Workers AI, Ollama, and a custom System One endpoint. They are
 * resolved from `judge.provider`, never detected from a key, and only their request shape is
 * tested here; no test reaches a real host.
 */

const ACCOUNT = "0123456789abcdef0123456789abcdef";

describe("ollama", () => {
  test("needs no key, defaults to the local endpoint and the nimble model", () => {
    const r = resolveSetup(judgeCfg({ provider: "ollama" }), {});
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.setup.url).toBe("http://localhost:11434/v1/systemone");
    expect(r.setup.model).toBe("nimble");
    expect(r.setup.apiKey).toBe("");
    expect(r.setup.keyEnv).toBe("");
  });

  test("takes another model and a local base URL, but not a plain-http remote one", () => {
    const ok = resolveSetup(judgeCfg({ provider: "ollama", model: "tev1", baseUrl: "http://127.0.0.1:11435" }), {});
    expect(ok.ok && ok.setup.url).toBe("http://127.0.0.1:11435/v1/systemone");
    expect(ok.ok && ok.setup.model).toBe("tev1");
    const remote = resolveSetup(judgeCfg({ provider: "ollama", baseUrl: "http://10.0.0.5:11434" }), {});
    expect(remote.ok).toBe(false);
  });

  test("sends no Authorization header", async () => {
    const seen: Record<string, string>[] = [];
    const fetch: FetchLike = async (_url, init) => {
      seen.push({ ...(init.headers as Record<string, string>) });
      return new Response(JSON.stringify({ model: "nimble", answers: {} }), { status: 200 });
    };
    const made = createJudge(judgeCfg({ provider: "ollama" }), {}, { fetch });
    expect(made.judge).toBeDefined();
    await made.judge!.review(makeBundle(), []);
    expect(seen).toHaveLength(1);
    expect(Object.keys(seen[0]!).map((k) => k.toLowerCase())).not.toContain("authorization");
  });
});

describe("cloudflare", () => {
  test("puts the account id and the model in the URL and uses the API token", () => {
    const token = fakeKey("cf");
    const r = resolveSetup(judgeCfg({ provider: "cloudflare", accountId: ACCOUNT }), { CLOUDFLARE_API_TOKEN: token });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.setup.url).toBe(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/ai/run/typesafe/jev`);
    expect(r.setup.apiKey).toBe(token);
    expect(r.setup.keyEnv).toBe("CLOUDFLARE_API_TOKEN");
  });

  test("the account id may come from the environment; without one, or a token, it says what to set", () => {
    const token = fakeKey("cf");
    const env = { CLOUDFLARE_API_TOKEN: token, [ACCOUNT_ID_ENV]: ACCOUNT };
    expect(resolveSetup(judgeCfg({ provider: "cloudflare" }), env).ok).toBe(true);
    const noAccount = resolveSetup(judgeCfg({ provider: "cloudflare" }), { CLOUDFLARE_API_TOKEN: token });
    expect(noAccount.ok === false && noAccount.problem).toContain("account id");
    const noToken = resolveSetup(judgeCfg({ provider: "cloudflare", accountId: ACCOUNT }), {});
    expect(noToken.ok === false && noToken.problem).toContain("CLOUDFLARE_API_TOKEN");
  });

  test("a Cloudflare token is never picked up without judge.provider naming the host", () => {
    const r = resolveSetup(judgeCfg(), { CLOUDFLARE_API_TOKEN: fakeKey("cf"), [ACCOUNT_ID_ENV]: ACCOUNT });
    expect(r.ok).toBe(false);
  });
});

describe("custom", () => {
  test("needs the full endpoint in judge.baseUrl and a key in the override variable", () => {
    const key = fakeKey("any-");
    const r = resolveSetup(judgeCfg({ provider: "custom", baseUrl: "https://jev.internal.example/v1/systemone" }), {
      [OVERRIDE_KEY_ENV]: key,
    });
    expect(r.ok && r.setup.url).toBe("https://jev.internal.example/v1/systemone");
    expect(r.ok && r.setup.apiKey).toBe(key);
    expect(r.ok && r.setup.model).toBe("jev-latest");
    const noUrl = resolveSetup(judgeCfg({ provider: "custom" }), { [OVERRIDE_KEY_ENV]: key });
    expect(noUrl.ok === false && noUrl.problem).toContain("judge.baseUrl");
    const noKey = resolveSetup(judgeCfg({ provider: "custom", baseUrl: "https://jev.internal.example/v1/systemone" }), {});
    expect(noKey.ok).toBe(false);
  });

  test("a model id is kept plain", () => {
    const bad = resolveSetup(judgeCfg({ provider: "custom", baseUrl: "https://h.example/x", model: "a model" }), {
      [OVERRIDE_KEY_ENV]: "k",
    });
    expect(bad.ok).toBe(false);
  });
});

describe("the Workers AI envelope", () => {
  test("answers under result are read; a plain System One body is untouched", () => {
    const inner = { model: "typesafe/jev", answers: { a: { type: "choice", probabilities: { true: 0.9, false: 0.1 } } } };
    expect(unwrapEnvelope({ result: inner, success: true, errors: [], messages: [] })).toEqual(inner);
    expect(unwrapEnvelope(inner)).toEqual(inner);
  });

  test("a failed envelope reports the host's error", () => {
    expect(() => unwrapEnvelope({ result: null, success: false, errors: [{ code: 10000, message: "Authentication error" }] })).toThrow(
      "Authentication error",
    );
  });
});
