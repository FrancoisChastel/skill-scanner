import { describe, expect, test } from "bun:test";
import { ASSIGNMENT_RE, maskSecret, PLACEHOLDER_RE, redactSecrets, SECRET_PATTERNS } from "../../src/core/secrets";

/** Deterministic pseudo-random text, so token-shaped test data never sits in the source as a literal. */
function noise(n: number, alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", seed = 7): string {
  let s = "";
  let x = seed;
  for (let i = 0; i < n; i += 1) {
    x = (x * 1103515245 + 12345) % 2147483648;
    s += alphabet[x % alphabet.length];
  }
  return s;
}

const GITHUB = `${"gh"}p_${noise(36)}`;
const AWS = `${"AK"}IA${noise(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 3)}`;
const TELEGRAM = `${"12345"}67890:AA${noise(33, undefined, 11)}`;
const SLACK = `${"xo"}xb-${noise(24, undefined, 5)}`;
const PEM_BEGIN = `-----BEGIN ${"RSA PRIVATE"} KEY-----`;

describe("maskSecret", () => {
  test("keeps four leading and two trailing characters of a long value", () => {
    // Arrange / Act
    const masked = maskSecret(GITHUB);

    // Assert
    expect(masked).toBe(`${GITHUB.slice(0, 4)}${"*".repeat(12)}${GITHUB.slice(-2)}`);
    expect(masked).not.toContain(GITHUB.slice(4, -2));
  });

  test("hides short values entirely", () => {
    // Arrange / Act / Assert
    expect(maskSecret("short")).toBe("********");
    expect(maskSecret("12345678")).toBe("********");
  });

  test("uses fewer stars for values just over the short limit", () => {
    // Arrange / Act / Assert
    expect(maskSecret("123456789")).toBe("1234***89");
  });

  test("leaves a PEM header as it is", () => {
    // Arrange / Act / Assert
    expect(maskSecret(PEM_BEGIN)).toBe(PEM_BEGIN);
  });
});

describe("redactSecrets", () => {
  test("masks every recognised token shape in a text", () => {
    // Arrange
    const text = `token ${GITHUB} and ${AWS}\nbot ${TELEGRAM} slack ${SLACK}`;

    // Act
    const out = redactSecrets(text);

    // Assert
    for (const raw of [GITHUB, AWS, TELEGRAM, SLACK]) expect(out).not.toContain(raw);
    expect(out).toContain(maskSecret(GITHUB));
    expect(out).toContain("\nbot ");
  });

  test("masks the value of a generic secret assignment", () => {
    // Arrange
    const value = noise(32, undefined, 17);
    const text = `api_key = "${value}"`;

    // Act
    const out = redactSecrets(text);

    // Assert
    expect(out).toBe(`api_key = "${maskSecret(value)}"`);
  });

  test("leaves text without secrets unchanged", () => {
    // Arrange / Act / Assert
    expect(redactSecrets("nothing to see here, https://example.com")).toBe("nothing to see here, https://example.com");
  });

  test("is idempotent", () => {
    // Arrange
    const once = redactSecrets(`t ${GITHUB} ${AWS} api_key = "${noise(24, undefined, 19)}"`);

    // Act
    const twice = redactSecrets(once);

    // Assert
    expect(twice).toBe(once);
  });

  test("does not advance shared pattern state between calls", () => {
    // Arrange
    const text = `${GITHUB} ${GITHUB}`;

    // Act
    const a = redactSecrets(text);
    const b = redactSecrets(text);

    // Assert
    expect(a).toBe(b);
    expect(a).not.toContain(GITHUB);
  });
});

describe("secret pattern table", () => {
  test("every pattern is global and has a kind", () => {
    // Arrange / Act / Assert
    for (const p of SECRET_PATTERNS) {
      expect(p.re.global).toBe(true);
      expect(p.kind.length).toBeGreaterThan(0);
    }
    expect(ASSIGNMENT_RE.global).toBe(true);
  });

  test("placeholder detection matches common stand-ins", () => {
    // Arrange / Act / Assert
    for (const s of ["sk-xxxxxxxx", "YOUR_API_KEY", "<token>", `\${TOKEN}`, "{{secret}}", "example-key", "REDACTED", "changeme"]) {
      expect(PLACEHOLDER_RE.test(s)).toBe(true);
    }
    expect(PLACEHOLDER_RE.test(GITHUB)).toBe(false);
  });
});
