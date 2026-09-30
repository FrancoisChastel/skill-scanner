import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ANALYZER_NAMES, ConfigError, DEFAULT_CONFIG, parseConfig } from "../src/config";

const schema = JSON.parse(readFileSync(join(import.meta.dir, "..", "schema", "config.schema.json"), "utf8"));

describe("parseConfig", () => {
  test("an empty object gives the defaults", () => {
    // Act
    const config = parseConfig({});

    // Assert
    expect(config).toEqual(DEFAULT_CONFIG);
  });

  test("a full config round-trips every field", () => {
    // Arrange
    const raw = {
      $schema: "x",
      blockAt: "critical",
      warnAt: "low",
      ignore: [{ rule: "network/*", path: "notify/**", reason: "posts to our own Slack" }],
      judge: { enabled: true, provider: "openrouter", model: "m", baseUrl: "https://proxy.example", timeoutMs: 5000 },
      analyzers: { gitleaks: true, skillspector: true },
      semgrepConfig: "./rules.yml",
      hooks: { onWarn: "deny", onError: "allow", quarantine: false },
    };

    // Act
    const config = parseConfig(raw);

    // Assert
    expect(config.blockAt).toBe("critical");
    expect(config.ignore).toEqual([{ rule: "network/*", path: "notify/**", reason: "posts to our own Slack" }]);
    expect(config.judge).toEqual({ enabled: true, provider: "openrouter", model: "m", baseUrl: "https://proxy.example", timeoutMs: 5000 });
    expect(config.analyzers.gitleaks).toBe(true);
    expect(config.analyzers.semgrep).toBe(false);
    expect(config.hooks).toEqual({ onWarn: "deny", onError: "allow", quarantine: false });
  });

  test.each([
    [{ blockat: "high" }, 'unknown key "blockat"'],
    [{ judge: { enable: true } }, 'unknown key "judge.enable"'],
    [{ hooks: { quarantined: false } }, 'unknown key "hooks.quarantined"'],
    [{ ignore: [{ rule: "x", paths: "y" }] }, 'unknown key "ignore[0].paths"'],
    [{ analyzers: { trufflehog: true } }, "not a known analyzer"],
    [{ blockAt: "severe" }, "blockAt must be one of"],
    [{ hooks: { onWarn: "maybe" } }, "hooks.onWarn must be ask, allow, or deny"],
    [{ ignore: [{ rule: "x", digest: "sha256:abc" }] }, "digest must look like"],
  ])("rejects %j", (raw, message) => {
    // Act / Assert
    expect(() => parseConfig(raw)).toThrow(ConfigError);
    expect(() => parseConfig(raw)).toThrow(message);
  });
});

describe("config schema", () => {
  test("lists exactly the keys parseConfig accepts", () => {
    // Assert: every top-level and nested key in the schema parses, and the analyzer list matches.
    expect(Object.keys(schema.properties).sort()).toEqual([
      "$schema",
      "analyzers",
      "blockAt",
      "hooks",
      "ignore",
      "judge",
      "semgrepConfig",
      "warnAt",
    ]);
    expect(Object.keys(schema.properties.analyzers.properties).sort()).toEqual([...ANALYZER_NAMES].sort());
    expect(Object.keys(schema.properties.hooks.properties).sort()).toEqual(Object.keys(DEFAULT_CONFIG.hooks).sort());
    expect(() =>
      parseConfig({
        judge: Object.fromEntries(
          Object.keys(schema.properties.judge.properties).map((k) => [
            k,
            k === "enabled" ? false : k === "timeoutMs" ? 1 : k === "provider" ? "typesafe" : "x",
          ]),
        ),
      }),
    ).not.toThrow();
  });

  test("defaults in the schema match the code", () => {
    expect(schema.properties.blockAt.default).toBe(DEFAULT_CONFIG.blockAt);
    expect(schema.properties.warnAt.default).toBe(DEFAULT_CONFIG.warnAt);
    expect(schema.properties.judge.properties.timeoutMs.default).toBe(DEFAULT_CONFIG.judge.timeoutMs);
    expect(schema.properties.hooks.properties.onWarn.default).toBe(DEFAULT_CONFIG.hooks.onWarn);
    expect(schema.properties.hooks.properties.onError.default).toBe(DEFAULT_CONFIG.hooks.onError);
    expect(schema.properties.hooks.properties.quarantine.default).toBe(DEFAULT_CONFIG.hooks.quarantine);
  });
});
