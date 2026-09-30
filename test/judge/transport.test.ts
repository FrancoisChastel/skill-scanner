import { describe, expect, test } from "bun:test";
import type { JudgeConfig } from "../../src/config";
import { createJudge, type FetchLike, pingJudge } from "../../src/judge";
import type { BundleJudge } from "../../src/scan";
import {
  answersFor,
  fakeFetch,
  fakeKey,
  hangingFetch,
  jsonResponse,
  judgeCfg,
  makeBundle,
  makeFinding,
  neutralReply,
  scoresOf,
} from "./helpers";

const KEY = fakeKey("ts_");
const ENV = { TYPESAFE_API_KEY: KEY };

function judgeWith(fetch: FetchLike, cfg: Partial<JudgeConfig> = {}): BundleJudge {
  const { judge } = createJudge(judgeCfg(cfg), ENV, { fetch, retryDelayMs: 0 });
  if (!judge) throw new Error("expected a judge");
  return judge;
}

describe("transport safety", () => {
  for (const status of [301, 302, 307, 308]) {
    test(`a ${status} redirect fails the review without following it`, async () => {
      // Arrange
      const fake = fakeFetch(() => new Response(null, { status, headers: { location: "https://collector.example/steal" } }));
      const findings = [makeFinding()];

      // Act
      const review = await judgeWith(fake.fetch).review(makeBundle(), findings);

      // Assert
      expect(review.status).toBe("failed");
      expect(review.detail).toContain("redirect");
      expect(review.detail).not.toContain(KEY);
      expect(review.findings).toEqual(findings);
      expect(fake.calls).toHaveLength(1);
      expect(fake.calls[0]?.init.redirect).toBe("manual");
      expect(fake.calls[0]?.url).toBe("https://api.typesafe.ai/v1/systemone");
    });
  }

  test("a request slower than timeoutMs fails with a timeout and is not retried", async () => {
    // Arrange
    let calls = 0;
    const counting: FetchLike = (url, init) => {
      calls += 1;
      return hangingFetch(url, init);
    };

    // Act
    const review = await judgeWith(counting, { timeoutMs: 30 }).review(makeBundle(), []);

    // Assert
    expect(review.status).toBe("failed");
    expect(review.detail).toBe("jev via typesafe failed: timed out after 30 ms");
    expect(calls).toBe(1);
  });

  test("a 429 is retried and the second answer is used", async () => {
    // Arrange
    const fake = fakeFetch(
      () => new Response("slow down", { status: 429 }),
      () => jsonResponse(answersFor(scoresOf())),
    );

    // Act
    const review = await judgeWith(fake.fetch).review(makeBundle(), []);

    // Assert
    expect(review.status).toBe("ok");
    expect(fake.calls).toHaveLength(2);
  });

  test("a persistent 503 gives up after two retries", async () => {
    // Arrange
    const fake = fakeFetch(() => new Response("down", { status: 503 }));

    // Act
    const review = await judgeWith(fake.fetch).review(makeBundle(), []);

    // Assert
    expect(review.status).toBe("failed");
    expect(review.detail).toBe("jev via typesafe failed: responded 503");
    expect(fake.calls).toHaveLength(3);
  });

  test("a 401 is not retried and points at the key", async () => {
    // Arrange
    const fake = fakeFetch(() => new Response(`bad key ${KEY}`, { status: 401 }));

    // Act
    const review = await judgeWith(fake.fetch).review(makeBundle(), []);

    // Assert
    expect(review.detail).toBe("jev via typesafe failed: responded 401 (check the API key)");
    expect(fake.calls).toHaveLength(1);
  });

  test("a network failure is retried, and its free text never reaches the detail", async () => {
    // Arrange
    const failing: FetchLike = async () => {
      throw new TypeError(`fetch failed for Bearer ${KEY}`, { cause: { code: "ECONNREFUSED" } });
    };

    // Act
    const review = await judgeWith(failing).review(makeBundle(), []);

    // Assert
    expect(review.status).toBe("failed");
    expect(review.detail).toBe("jev via typesafe failed: could not reach api.typesafe.ai (ECONNREFUSED)");
  });

  test("an aborted signal cancels before any request", async () => {
    // Arrange
    const fake = fakeFetch(neutralReply);
    const ctrl = new AbortController();
    ctrl.abort();

    // Act
    const review = await judgeWith(fake.fetch).review(makeBundle(), [], ctrl.signal);

    // Assert
    expect(review.status).toBe("failed");
    expect(review.detail).toContain("cancelled");
    expect(fake.calls).toHaveLength(0);
  });

  test("aborting mid-request cancels it", async () => {
    // Arrange
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 5);

    // Act
    const review = await judgeWith(hangingFetch, { timeoutMs: 5000 }).review(makeBundle(), [], ctrl.signal);

    // Assert
    expect(review.status).toBe("failed");
    expect(review.detail).toContain("cancelled");
  });
});

describe("answer validation", () => {
  const withProbe = (answer: unknown): unknown => {
    const good = answersFor(scoresOf()) as { answers: Record<string, unknown> };
    return { ...good, answers: { ...good.answers, prompt_injection: answer } };
  };
  const invalid: ReadonlyArray<[string, () => Response]> = [
    ["a body that is not JSON", () => new Response("<html>oops</html>", { status: 200 })],
    ["no answers object", () => jsonResponse({ usage: {} })],
    ["answers as an array", () => jsonResponse({ answers: [] })],
    [
      "a missing probe",
      () => {
        const { prompt_injection: _dropped, ...rest } = scoresOf();
        return jsonResponse(answersFor(rest));
      },
    ],
    ["a noul answer", () => jsonResponse(withProbe({ type: "noul", noul: 0.9 }))],
    ["P(true) above 1", () => jsonResponse(withProbe({ type: "choice", choice: "true", probabilities: { true: 1.5, false: 0 } }))],
    ["P(true) as a string", () => jsonResponse(withProbe({ type: "choice", choice: "true", probabilities: { true: "0.9" } }))],
    ["P(true) negative", () => jsonResponse(withProbe({ type: "choice", choice: "false", probabilities: { true: -0.1 } }))],
    ["no probabilities", () => jsonResponse(withProbe({ type: "choice", choice: "true" }))],
  ];
  for (const [name, reply] of invalid) {
    test(`${name} fails the review and leaves findings unchanged`, async () => {
      // Arrange
      const fake = fakeFetch(reply);
      const findings = [makeFinding(), makeFinding({ category: "prompt-injection", ruleId: "injection/test" })];

      // Act
      const review = await judgeWith(fake.fetch).review(makeBundle(), findings);

      // Assert
      expect(review.status).toBe("failed");
      expect(review.detail).toMatch(/invalid answer|not JSON/);
      expect(review.findings).toEqual(findings);
      expect(fake.calls).toHaveLength(1);
    });
  }

  test("a model name that is not a model id is replaced by the configured one", async () => {
    // Arrange
    const fake = fakeFetch(() => jsonResponse(answersFor(scoresOf(), "jev\n<script>")));

    // Act
    const review = await judgeWith(fake.fetch).review(makeBundle(), []);

    // Assert
    expect(review.status).toBe("ok");
    expect(review.detail).toMatch(/^jev via typesafe \(jev-latest\), \d+ ms$/);
  });
});

describe("pingJudge", () => {
  test("asks one question on a trivial state and reports latency", async () => {
    // Arrange
    const fake = fakeFetch(() => jsonResponse(answersFor({ ping: 0.97 })));

    // Act
    const result = await pingJudge(judgeCfg({ enabled: false }), ENV, { fetch: fake.fetch });

    // Assert
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/^jev via typesafe \(jev-test\) answered in \d+ ms$/);
    expect(typeof result.latencyMs).toBe("number");
    expect(Object.keys(fake.calls[0]?.body.questions ?? {})).toEqual(["ping"]);
    expect(fake.calls[0]?.body.questions?.ping?.type).toBe("choice");
  });

  test("does not retry, so doctor reports the first failure", async () => {
    // Arrange
    const fake = fakeFetch(() => new Response("down", { status: 500 }));

    // Act
    const result = await pingJudge(judgeCfg(), ENV, { fetch: fake.fetch, retryDelayMs: 0 });

    // Assert
    expect(result).toMatchObject({ ok: false, detail: "jev via typesafe failed: responded 500" });
    expect(fake.calls).toHaveLength(1);
  });

  test("reports a missing key without a request", async () => {
    // Arrange
    const fake = fakeFetch(neutralReply);

    // Act
    const result = await pingJudge(judgeCfg(), {}, { fetch: fake.fetch });

    // Assert
    expect(result.ok).toBe(false);
    expect(result.detail).toContain("no key");
    expect(fake.calls).toHaveLength(0);
  });
});
