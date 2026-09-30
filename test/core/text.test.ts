import { describe, expect, test } from "bun:test";
import { clip, indexLines, isInvisible, lineText, positionAt, revealInvisible, snippetAt } from "../../src/core/text";

const ELLIPSIS = String.fromCodePoint(0x2026);

describe("indexLines and positionAt", () => {
  const text = "line one\r\nline two\n\nlast";
  const index = indexLines(text);

  test("records the offset of each line start", () => {
    // Arrange / Act / Assert
    expect(index.starts).toEqual([0, 10, 19, 20]);
    expect(index.text).toBe(text);
  });

  test("maps offsets to 1-based lines and columns", () => {
    // Arrange / Act / Assert
    expect(positionAt(index, 0)).toEqual({ line: 1, column: 1 });
    expect(positionAt(index, 5)).toEqual({ line: 1, column: 6 });
    expect(positionAt(index, 10)).toEqual({ line: 2, column: 1 });
    expect(positionAt(index, 19)).toEqual({ line: 3, column: 1 });
    expect(positionAt(index, 22)).toEqual({ line: 4, column: 3 });
  });

  test("clamps offsets past the end to the last line", () => {
    // Arrange / Act / Assert
    expect(positionAt(index, 999).line).toBe(4);
  });

  test("indexes an empty text as one line", () => {
    // Arrange / Act
    const empty = indexLines("");

    // Assert
    expect(empty.starts).toEqual([0]);
    expect(positionAt(empty, 0)).toEqual({ line: 1, column: 1 });
  });
});

describe("lineText", () => {
  const index = indexLines("line one\r\nline two\n\nlast");

  test("returns a line without its terminator, CR included", () => {
    // Arrange / Act / Assert
    expect(lineText(index, 1)).toBe("line one");
    expect(lineText(index, 2)).toBe("line two");
    expect(lineText(index, 3)).toBe("");
    expect(lineText(index, 4)).toBe("last");
  });

  test("returns an empty string for a line that does not exist", () => {
    // Arrange / Act / Assert
    expect(lineText(index, 5)).toBe("");
    expect(lineText(index, 0)).toBe("");
  });
});

describe("snippetAt", () => {
  test("returns the whole trimmed line when it is short", () => {
    // Arrange
    const index = indexLines("first\n   short TARGET   \nthird");

    // Act
    const s = snippetAt(index, 15, 6);

    // Assert
    expect(s).toBe("short TARGET");
  });

  test("bounds a long line around the match and marks both cuts", () => {
    // Arrange
    const text = `${"x".repeat(300)}TARGET${"y".repeat(300)}`;

    // Act
    const s = snippetAt(indexLines(text), 300, 6);

    // Assert
    expect(s).toContain("TARGET");
    expect(s.startsWith(ELLIPSIS)).toBe(true);
    expect(s.endsWith(ELLIPSIS)).toBe(true);
    expect(s.length).toBe(162);
  });

  test("marks only the end when the match is at the start of a long line", () => {
    // Arrange
    const text = `TARGET${"z".repeat(400)}`;

    // Act
    const s = snippetAt(indexLines(text), 0, 6);

    // Assert
    expect(s.startsWith("TARGET")).toBe(true);
    expect(s.endsWith(ELLIPSIS)).toBe(true);
    expect(s.length).toBe(161);
  });

  test("marks only the start when the match ends a long line", () => {
    // Arrange
    const text = `${"z".repeat(400)}TARGET`;

    // Act
    const s = snippetAt(indexLines(text), 400, 6);

    // Assert
    expect(s.startsWith(ELLIPSIS)).toBe(true);
    expect(s.endsWith("TARGET")).toBe(true);
  });

  test("reveals invisible characters in the snippet", () => {
    // Arrange
    const text = `ig${String.fromCodePoint(0x200b)}nore this`;

    // Act
    const s = snippetAt(indexLines(text), 2, 1);

    // Assert
    expect(s).toBe("ig<U+200B>nore this");
  });

  test("falls back to the raw match when the line is only whitespace", () => {
    // Arrange
    const index = indexLines("   \n\t  ");

    // Act
    const s = snippetAt(index, 1, 2);

    // Assert
    expect(s).toBe("  ");
  });
});

describe("revealInvisible and isInvisible", () => {
  test("replaces invisible and control characters but keeps tabs", () => {
    // Arrange
    const text = `a${String.fromCodePoint(0x200b)}b\tc\nd${String.fromCodePoint(0x7f, 0xe0041)}`;

    // Act
    const shown = revealInvisible(text);

    // Assert
    expect(shown).toBe("a<U+200B>b\tc<U+000A>d<U+007F><U+E0041>");
  });

  test("leaves ordinary Unicode alone", () => {
    // Arrange
    const text = `caf${String.fromCodePoint(0xe9)} ${String.fromCodePoint(0x1f600)}`;

    // Act / Assert
    expect(revealInvisible(text)).toBe(text);
  });

  test("classifies zero-width, bidi, tags, selectors, and fillers as invisible", () => {
    // Arrange
    const invisible = [
      0x200b, 0x200f, 0x202e, 0x2060, 0x2066, 0xfeff, 0x00ad, 0x180e, 0x034f, 0x115f, 0x3164, 0xffa0, 0xfe0f, 0xe0041, 0xe0100,
    ];
    const visible = [0x41, 0x20, 0xe9, 0x4e2d, 0x1f600, 0x2028];

    // Act / Assert
    expect(invisible.every(isInvisible)).toBe(true);
    expect(visible.some(isInvisible)).toBe(false);
  });
});

describe("clip", () => {
  test("shortens long strings with an ellipsis and keeps short ones", () => {
    // Arrange / Act / Assert
    expect(clip("abcdef", 4)).toBe(`abc${ELLIPSIS}`);
    expect(clip("abcd", 4)).toBe("abcd");
    expect(clip("", 4)).toBe("");
  });
});
