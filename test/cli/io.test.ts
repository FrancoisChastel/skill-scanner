import { describe, expect, test } from "bun:test";
import { formatHint } from "../../src/cli/commands/scan";
import { MAX_TEXT_WIDTH, textWidth, useColor } from "../../src/cli/io";

const ESC = String.fromCharCode(27);

describe("textWidth", () => {
  test("follows a terminal narrower than the maximum", () => {
    expect(textWidth({ isTTY: true, columns: 72 })).toBe(72);
  });

  test("stays at the maximum on a wider terminal", () => {
    expect(textWidth({ isTTY: true, columns: 240 })).toBe(MAX_TEXT_WIDTH);
  });

  test("leaves the default when stdout is not a terminal or its width is unknown", () => {
    expect(textWidth({ isTTY: false, columns: 72 })).toBeUndefined();
    expect(textWidth({ isTTY: true })).toBeUndefined();
    expect(textWidth({ isTTY: true, columns: 0 })).toBeUndefined();
  });
});

describe("useColor", () => {
  test("colors a terminal, unless NO_COLOR is set or the terminal is dumb; FORCE_COLOR wins", () => {
    expect(useColor({ isTTY: true, env: {} })).toBe(true);
    expect(useColor({ isTTY: true, env: { NO_COLOR: "1" } })).toBe(false);
    expect(useColor({ isTTY: true, env: { TERM: "dumb" } })).toBe(false);
    expect(useColor({ isTTY: false, env: { FORCE_COLOR: "1" } })).toBe(true);
  });
});

describe("formatHint", () => {
  const hint = "Tip: one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen";

  test("wraps the tip to the width, indented, with no escape codes when color is off", () => {
    const out = formatHint(hint, { color: false, width: 40 });

    const lines = out.split("\n");
    expect(lines[0]!.startsWith("  Tip: one")).toBe(true);
    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(40);
    expect(out.includes(ESC)).toBe(false);
  });

  test("highlights the label and dims the rest when color is on", () => {
    const out = formatHint(hint, { color: true, width: 40 });

    expect(out.startsWith(`  ${ESC}[36mTip:${ESC}[0m${ESC}[2m one`)).toBe(true);
  });
});
