import { describe, expect, test } from "bun:test";
import type { JudgeConfig } from "../../src/config";
import { createJudge, describeJudge } from "../../src/judge";
import { checkBaseUrl, NO_KEY, resolveSetup } from "../../src/judge/providers";
import { fakeKey, judgeCfg } from "./helpers";

const TS = fakeKey("ts_");
const OR = fakeKey("sk-or-");
const VCK = fakeKey("vck_");
const UNKNOWN = fakeKey("zz_");

interface Case {
  readonly name: string;
  readonly env: NodeJS.ProcessEnv;
  readonly cfg?: Partial<JudgeConfig>;
  readonly provider: string;
  readonly keyEnv: string;
}

const MATRIX: readonly Case[] = [
  { name: "a TypeSafe key", env: { TYPESAFE_API_KEY: TS }, provider: "typesafe", keyEnv: "TYPESAFE_API_KEY" },
  { name: "an OpenRouter key", env: { OPENROUTER_API_KEY: OR }, provider: "openrouter", keyEnv: "OPENROUTER_API_KEY" },
  { name: "a Vercel AI Gateway key", env: { AI_GATEWAY_API_KEY: VCK }, provider: "vercel", keyEnv: "AI_GATEWAY_API_KEY" },
  {
    name: "all three keys: TypeSafe wins",
    env: { TYPESAFE_API_KEY: TS, OPENROUTER_API_KEY: OR, AI_GATEWAY_API_KEY: VCK },
    provider: "typesafe",
    keyEnv: "TYPESAFE_API_KEY",
  },
  {
    name: "OpenRouter and Vercel keys: OpenRouter wins",
    env: { OPENROUTER_API_KEY: OR, AI_GATEWAY_API_KEY: VCK },
    provider: "openrouter",
    keyEnv: "OPENROUTER_API_KEY",
  },
  {
    name: "a ts_ key in OPENROUTER_API_KEY goes to TypeSafe",
    env: { OPENROUTER_API_KEY: TS },
    provider: "typesafe",
    keyEnv: "OPENROUTER_API_KEY",
  },
  { name: "a vck_ key in TYPESAFE_API_KEY goes to Vercel", env: { TYPESAFE_API_KEY: VCK }, provider: "vercel", keyEnv: "TYPESAFE_API_KEY" },
  {
    name: "precedence follows the prefix, not the variable",
    env: { TYPESAFE_API_KEY: VCK, OPENROUTER_API_KEY: OR },
    provider: "openrouter",
    keyEnv: "OPENROUTER_API_KEY",
  },
  {
    name: "an unknown prefix belongs to its variable",
    env: { OPENROUTER_API_KEY: UNKNOWN },
    provider: "openrouter",
    keyEnv: "OPENROUTER_API_KEY",
  },
  {
    name: "SKILL_SCANNER_JEV_KEY overrides the provider variables",
    env: { SKILL_SCANNER_JEV_KEY: VCK, TYPESAFE_API_KEY: TS },
    provider: "vercel",
    keyEnv: "SKILL_SCANNER_JEV_KEY",
  },
  {
    name: "judge.provider picks that host's key",
    env: { TYPESAFE_API_KEY: TS, OPENROUTER_API_KEY: OR, AI_GATEWAY_API_KEY: VCK },
    cfg: { provider: "vercel" },
    provider: "vercel",
    keyEnv: "AI_GATEWAY_API_KEY",
  },
  {
    name: "judge.provider finds its key by prefix in any variable",
    env: { TYPESAFE_API_KEY: OR },
    cfg: { provider: "openrouter" },
    provider: "openrouter",
    keyEnv: "TYPESAFE_API_KEY",
  },
  {
    name: "judge.provider claims an override key with an unknown prefix",
    env: { SKILL_SCANNER_JEV_KEY: UNKNOWN, TYPESAFE_API_KEY: TS },
    cfg: { provider: "vercel" },
    provider: "vercel",
    keyEnv: "SKILL_SCANNER_JEV_KEY",
  },
];

describe("provider detection", () => {
  for (const c of MATRIX) {
    test(c.name, () => {
      // Arrange
      const cfg = judgeCfg(c.cfg);

      // Act
      const described = describeJudge(cfg, c.env);

      // Assert
      expect(described).toMatchObject({ provider: c.provider, keyEnv: c.keyEnv });
      expect(described.problem).toBeUndefined();
    });
  }

  test("each host gets its own endpoint and default model", () => {
    // Arrange
    const envs = [{ TYPESAFE_API_KEY: TS }, { OPENROUTER_API_KEY: OR }, { AI_GATEWAY_API_KEY: VCK }];

    // Act
    const described = envs.map((env) => describeJudge(judgeCfg(), env));

    // Assert
    expect(described.map((d) => [d.url, d.model])).toEqual([
      ["https://api.typesafe.ai/v1/systemone", "jev-latest"],
      ["https://openrouter.ai/api/alpha/decisions", "typesafe/jev-1.13"],
      ["https://ai-gateway.vercel.sh/typesafe/v1/systemone", "typesafe-ai/jev"],
    ]);
  });

  test("judge.model overrides the default model", () => {
    // Act
    const described = describeJudge(judgeCfg({ model: "jev-1.14" }), { TYPESAFE_API_KEY: TS });

    // Assert
    expect(described.model).toBe("jev-1.14");
  });

  test("no key, or a blank one, is reported with the variables to set", () => {
    // Act
    const none = describeJudge(judgeCfg(), {});
    const blank = describeJudge(judgeCfg(), { TYPESAFE_API_KEY: "   " });

    // Assert
    expect(none).toEqual({ problem: NO_KEY });
    expect(blank).toEqual({ problem: NO_KEY });
  });

  test("judge.provider never borrows another host's key", () => {
    // Act
    const described = describeJudge(judgeCfg({ provider: "vercel" }), { TYPESAFE_API_KEY: TS, OPENROUTER_API_KEY: OR });

    // Assert
    expect(described.provider).toBeUndefined();
    expect(described.problem).toContain("no Vercel AI Gateway key");
  });

  test("an override key with an unknown prefix needs judge.provider", () => {
    // Act
    const described = describeJudge(judgeCfg(), { SKILL_SCANNER_JEV_KEY: UNKNOWN, TYPESAFE_API_KEY: TS });

    // Assert
    expect(described.problem).toContain("judge.provider");
  });

  test("problems and descriptions never contain a key", () => {
    // Arrange
    const envs: NodeJS.ProcessEnv[] = [
      { TYPESAFE_API_KEY: TS },
      { SKILL_SCANNER_JEV_KEY: UNKNOWN },
      { TYPESAFE_API_KEY: TS, OPENROUTER_API_KEY: OR, AI_GATEWAY_API_KEY: VCK },
    ];
    const cfgs = [judgeCfg(), judgeCfg({ provider: "vercel" }), judgeCfg({ baseUrl: "http://example.com" })];

    // Act
    const text = JSON.stringify(envs.flatMap((env) => cfgs.map((cfg) => [describeJudge(cfg, env), createJudge(cfg, env).reason])));

    // Assert
    for (const key of [TS, OR, VCK, UNKNOWN]) expect(text).not.toContain(key);
  });

  test("the key resolved is the one the chosen variable holds", () => {
    // Act
    const resolved = resolveSetup(judgeCfg(), { OPENROUTER_API_KEY: OR, AI_GATEWAY_API_KEY: VCK });

    // Assert
    expect(resolved.ok && resolved.setup.apiKey).toBe(OR);
  });
});

describe("judge.baseUrl", () => {
  const accepted: ReadonlyArray<[string, string]> = [
    ["https://proxy.example.com/jev/", "https://proxy.example.com/jev"],
    ["http://localhost:8080", "http://localhost:8080"],
    ["http://LOCALHOST:8080/", "http://localhost:8080"],
    ["http://127.0.0.1:9000", "http://127.0.0.1:9000"],
    ["http://[::1]:7000", "http://[::1]:7000"],
  ];
  for (const [raw, base] of accepted) {
    test(`accepts ${raw}`, () => {
      // Act
      const result = checkBaseUrl(raw);

      // Assert
      expect(result).toEqual({ base });
    });
  }

  const refused = [
    "http://localhost.attacker.example",
    "http://localhost.attacker.example:8080/v1",
    "http://127.0.0.1.nip.io",
    "http://example.com",
    "http://0.0.0.0:8080",
    "ftp://localhost/jev",
    "javascript:alert(1)",
    "not a url",
    "https://user:secret@proxy.example.com",
    "https://proxy.example.com/?key=1",
    "https://proxy.example.com/#frag",
  ];
  for (const raw of refused) {
    test(`refuses ${raw}`, () => {
      // Act
      const result = checkBaseUrl(raw);

      // Assert
      expect("problem" in result).toBe(true);
    });
  }

  test("a valid base URL replaces the host and keeps the provider path", () => {
    // Act
    const described = describeJudge(judgeCfg({ baseUrl: "http://localhost:8080/" }), { TYPESAFE_API_KEY: TS });

    // Assert
    expect(described.url).toBe("http://localhost:8080/v1/systemone");
  });

  test("createJudge refuses an insecure base URL", () => {
    // Act
    const created = createJudge(judgeCfg({ baseUrl: "http://localhost.attacker.example" }), { TYPESAFE_API_KEY: TS });

    // Assert
    expect(created.judge).toBeUndefined();
    expect(created.reason).toContain("judge.baseUrl");
  });

  test("a base URL does not take another host's ambient key unless judge.provider says so", () => {
    // Arrange
    const env = { OPENROUTER_API_KEY: OR };

    // Act
    const implicit = describeJudge(judgeCfg({ baseUrl: "https://proxy.example.com" }), env);
    const explicit = describeJudge(judgeCfg({ baseUrl: "https://proxy.example.com", provider: "openrouter" }), env);

    // Assert
    expect(implicit.problem).toContain("judge.provider");
    expect(explicit.url).toBe("https://proxy.example.com/alpha/decisions");
  });
});
