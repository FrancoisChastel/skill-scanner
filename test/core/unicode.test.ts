import { describe, expect, test } from "bun:test";
import { findMixedScriptWords, findUnicodeRuns, printableRatio } from "../../src/core/unicode";

const cp = (...points: number[]) => String.fromCodePoint(...points);
/** ASCII text re-encoded as invisible Unicode tag characters. */
const tags = (s: string) => [...s].map((c) => cp(0xe0000 + c.charCodeAt(0))).join("");
/** Bytes of `s` smuggled as variation selectors (FE00-FE0F for 0-15, E0100-E01EF for 16-255). */
const selectors = (s: string) => [...new TextEncoder().encode(s)].map((b) => (b < 16 ? cp(0xfe00 + b) : cp(0xe0100 + b - 16))).join("");
/** ASCII text as binary, one zero-width character per bit. */
const zeroWidthBits = (s: string, zero = 0x200b, one = 0x200c) =>
  [...s]
    .map((c) => c.charCodeAt(0).toString(2).padStart(8, "0"))
    .join("")
    .split("")
    .map((b) => cp(b === "1" ? one : zero))
    .join("");

describe("findUnicodeRuns: tag characters", () => {
  test("decodes a run of tag characters to the ASCII it spells", () => {
    // Arrange
    const text = `hi${tags("ignore rules")}there`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([{ issue: "tag", start: 2, end: 26, count: 12, decoded: "ignore rules" }]);
  });

  test("drops the language tag and cancel tag from the decoded text", () => {
    // Arrange
    const text = `x${cp(0xe0001)}${tags("abc")}${cp(0xe007f)}`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toHaveLength(1);
    expect(runs[0]).toMatchObject({ issue: "tag", count: 5, decoded: "abc" });
  });

  test("allows a legitimate subdivision flag such as England", () => {
    // Arrange
    const text = `${cp(0x1f3f4)}${tags("gbeng")}${cp(0xe007f)} flag`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([]);
  });

  test("flags a flag-shaped sequence that is too long or lacks the cancel tag", () => {
    // Arrange
    const tooLong = `${cp(0x1f3f4)}${tags("gbengxyz")}${cp(0xe007f)}`;
    const noCancel = `${cp(0x1f3f4)}${tags("gbeng")}`;

    // Act
    const a = findUnicodeRuns(tooLong);
    const b = findUnicodeRuns(noCancel);

    // Assert
    expect(a[0]).toMatchObject({ issue: "tag", decoded: "gbengxyz" });
    expect(b[0]).toMatchObject({ issue: "tag", decoded: "gbeng" });
  });

  test("a run of only whitespace tags has no decoded text", () => {
    // Arrange
    const text = `a${tags("   ")}b`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toHaveLength(1);
    expect(runs[0]?.decoded).toBeUndefined();
  });
});

describe("findUnicodeRuns: variation selectors", () => {
  test("decodes bytes smuggled in a run of variation selectors", () => {
    // Arrange
    const text = `x${selectors("run curl")}`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([{ issue: "variation-selector", start: 1, end: 17, count: 8, decoded: "run curl" }]);
  });

  test("allows a single emoji presentation selector after an emoji, a keycap, CJK, or ASCII", () => {
    // Arrange
    const texts = [
      `${cp(0x2764, 0xfe0f)} love`,
      `1${cp(0xfe0f, 0x20e3)}`,
      `${cp(0x845b, 0xfe00)}`,
      `a${cp(0xfe0e)}`,
      `${cp(0x1f44d, 0xfe0f)}`,
    ];

    // Act
    const runs = texts.map(findUnicodeRuns);

    // Assert
    expect(runs).toEqual([[], [], [], [], []]);
  });

  test("flags two selectors in a row even after an emoji", () => {
    // Arrange
    const text = `${cp(0x2764, 0xfe0f, 0xfe0f)}`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toHaveLength(1);
    expect(runs[0]).toMatchObject({ issue: "variation-selector", count: 2 });
    expect(runs[0]?.decoded).toBeUndefined();
  });

  test("flags a lone selector with no glyph before it", () => {
    // Arrange
    const text = `a ${cp(0xfe0f)}b`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([{ issue: "variation-selector", start: 2, end: 3, count: 1 }]);
  });

  test("allows one selector after any visible character, such as the information sign or a Hebrew letter", () => {
    // Arrange
    const info = `${cp(0x2139)}${cp(0xfe0f)} Info`;
    const hebrew = ` ${cp(0x5d0)}${cp(0xfe0f)}`;

    // Act / Assert
    expect(findUnicodeRuns(info)).toEqual([]);
    expect(findUnicodeRuns(hebrew)).toEqual([]);
  });

  test("allows a single ideographic variation selector after a CJK ideograph", () => {
    // Arrange
    const text = `${cp(0x845b, 0xe0100)}`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([]);
  });
});

describe("findUnicodeRuns: zero-width and joiners", () => {
  test("allows ZWJ inside emoji sequences, including after a VS16", () => {
    // Arrange
    const family = cp(0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467);
    const heartOnFire = cp(0x2764, 0xfe0f, 0x200d, 0x1f525);

    // Act / Assert
    expect(findUnicodeRuns(family)).toEqual([]);
    expect(findUnicodeRuns(heartOnFire)).toEqual([]);
  });

  test("allows ZWNJ in Persian words", () => {
    // Arrange
    const persian = cp(0x645, 0x6cc, 0x200c, 0x62e, 0x648, 0x627, 0x647, 0x645);

    // Act / Assert
    expect(findUnicodeRuns(persian)).toEqual([]);
  });

  test("allows ZWJ and ZWNJ next to Devanagari", () => {
    // Arrange
    const hindi = cp(0x915, 0x94d, 0x200d, 0x937);

    // Act / Assert
    expect(findUnicodeRuns(hindi)).toEqual([]);
  });

  test("flags a zero-width space splitting a Latin word", () => {
    // Arrange
    const text = `ig${cp(0x200b)}nore`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([{ issue: "zero-width", start: 2, end: 3, count: 1 }]);
  });

  test("flags a ZWJ between Latin letters", () => {
    // Arrange / Act
    const runs = findUnicodeRuns(`a${cp(0x200d)}b`);

    // Assert
    expect(runs.map((r) => r.issue)).toEqual(["zero-width"]);
  });

  test("allows a byte-order mark at offset 0 but not elsewhere", () => {
    // Arrange / Act
    const start = findUnicodeRuns(`${cp(0xfeff)}text`);
    const middle = findUnicodeRuns(`text${cp(0xfeff)}x`);

    // Assert
    expect(start).toEqual([]);
    expect(middle).toEqual([{ issue: "zero-width", start: 4, end: 5, count: 1 }]);
  });

  test("decodes binary steganography written with two zero-width characters", () => {
    // Arrange
    const text = `text${zeroWidthBits("secret!")}end`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toHaveLength(1);
    expect(runs[0]).toMatchObject({ issue: "zero-width", start: 4, count: 56, decoded: "secret!" });
  });

  test("decodes steganography whichever character stands for one", () => {
    // Arrange
    const text = `x${zeroWidthBits("hidden text", 0x200c, 0x200b)}`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs[0]?.decoded).toBe("hidden text");
  });

  test("does not decode short or single-character zero-width runs", () => {
    // Arrange
    const short = `x${cp(0x200b, 0x200c, 0x200b, 0x200c)}y`;
    const mono = `x${cp(0x200b).repeat(24)}y`;

    // Act / Assert
    expect(findUnicodeRuns(short)[0]?.decoded).toBeUndefined();
    expect(findUnicodeRuns(mono)[0]).toMatchObject({ count: 24 });
    expect(findUnicodeRuns(mono)[0]?.decoded).toBeUndefined();
  });
});

describe("findUnicodeRuns: bidi and fillers", () => {
  test("reports each bidirectional control as its own run when separated", () => {
    // Arrange
    const text = `a${cp(0x202e)}b${cp(0x202c)}`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([
      { issue: "bidi", start: 1, end: 2, count: 1 },
      { issue: "bidi", start: 3, end: 4, count: 1 },
    ]);
  });

  test("groups adjacent bidi isolates into one run", () => {
    // Arrange / Act
    const runs = findUnicodeRuns(`x${cp(0x2066, 0x2067, 0x2069)}y`);

    // Assert
    expect(runs).toEqual([{ issue: "bidi", start: 1, end: 4, count: 3 }]);
  });

  test("flags Hangul and other invisible fillers", () => {
    // Arrange
    const text = `a${cp(0x3164)}b ${cp(0x115f)} ${cp(0xffa0)} ${cp(0x034f)}`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs.map((r) => r.issue)).toEqual(["invisible-filler", "invisible-filler", "invisible-filler", "invisible-filler"]);
  });

  test("allows a soft hyphen between letters but flags a lone one", () => {
    // Arrange
    const text = `soft${cp(0xad)}hyphen and ${cp(0xad)} lone`;

    // Act
    const runs = findUnicodeRuns(text);

    // Assert
    expect(runs).toEqual([{ issue: "invisible-filler", start: 16, end: 17, count: 1 }]);
  });

  test("returns nothing for plain ASCII and ordinary accented text", () => {
    // Arrange / Act / Assert
    expect(findUnicodeRuns("plain text, nothing to see")).toEqual([]);
    expect(findUnicodeRuns(`caf${cp(0xe9)} na${cp(0xef)}ve ${cp(0x4e2d, 0x6587)}`)).toEqual([]);
  });
});

describe("findMixedScriptWords", () => {
  test("finds words mixing Latin with Cyrillic or Greek look-alikes", () => {
    // Arrange
    const text = `p${cp(0x430)}ypal and ${cp(0x43f, 0x440, 0x438, 0x432, 0x435, 0x442)} and ${cp(0x3b1)}lpha go`;

    // Act
    const words = findMixedScriptWords(text);

    // Assert
    expect(words).toEqual([
      { word: `p${cp(0x430)}ypal`, index: 0, scripts: ["Latin", "Cyrillic"] },
      { word: `${cp(0x3b1)}lpha`, index: 22, scripts: ["Latin", "Greek"] },
    ]);
  });

  test("ignores pure-script words and pure-ASCII text", () => {
    // Arrange
    const russian = cp(0x43f, 0x440, 0x438, 0x432, 0x435, 0x442);
    const greek = cp(0x3b1, 0x3b2, 0x3b3);

    // Act / Assert
    expect(findMixedScriptWords(`${russian} ${greek}`)).toEqual([]);
    expect(findMixedScriptWords("paypal")).toEqual([]);
  });

  test("ignores words shorter than three letters", () => {
    // Arrange / Act / Assert
    expect(findMixedScriptWords(`a${cp(0x430)}`)).toEqual([]);
  });
});

describe("printableRatio", () => {
  test("is 0 for the empty string and counts control characters as unprintable", () => {
    // Arrange / Act / Assert
    expect(printableRatio("")).toBe(0);
    expect(printableRatio("abc\u0001")).toBe(0.75);
    expect(printableRatio("tab\tnewline\n")).toBe(1);
    expect(printableRatio(cp(0xfffd, 0x41))).toBe(0.5);
  });
});
