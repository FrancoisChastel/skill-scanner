import { describe, expect, test } from "bun:test";
import {
  basename,
  binaryFormatOf,
  extensionOf,
  isBinaryExtension,
  languageOf,
  looksBinary,
  roleOf,
  textKindOf,
} from "../../src/core/classify";

const bytes = (...b: number[]) => new Uint8Array(b);

describe("extensionOf and basename", () => {
  test("returns the lower-cased last extension", () => {
    // Arrange / Act / Assert
    expect(extensionOf("a/b.tar.gz")).toBe("gz");
    expect(extensionOf("a.B.PY")).toBe("py");
    expect(extensionOf("Makefile")).toBe("");
  });

  test("treats a leading-dot name as its own extension", () => {
    // Arrange / Act / Assert
    expect(extensionOf(".gitignore")).toBe("gitignore");
    expect(extensionOf("x/.env")).toBe("env");
  });

  test("basename returns the last path segment", () => {
    // Arrange / Act / Assert
    expect(basename("a/b/c.md")).toBe("c.md");
    expect(basename("c.md")).toBe("c.md");
  });
});

describe("languageOf", () => {
  test("prefers the shebang over the extension", () => {
    // Arrange / Act / Assert
    expect(languageOf("run.txt", "#!/bin/bash\necho")).toBe("shell");
    expect(languageOf("run.sh", "#!/usr/bin/env node\n")).toBe("javascript");
    expect(languageOf("x", "#!/usr/bin/env -S uv run\n")).toBe("python");
    expect(languageOf("x", "#!/usr/bin/env python3.12\n")).toBe("python");
    expect(languageOf("x", "#!/usr/bin/env deno\n")).toBe("javascript");
    expect(languageOf("x", "#!/usr/bin/env pwsh")).toBe("powershell");
    expect(languageOf("x", "#!/usr/bin/ruby")).toBe("ruby");
    expect(languageOf("x", "#!/usr/bin/perl -w")).toBe("perl");
    expect(languageOf("x", "#!/usr/bin/osascript")).toBe("other");
  });

  test("reports an unknown interpreter as other", () => {
    // Arrange / Act / Assert
    expect(languageOf("x", "#!/opt/weird/interp\n")).toBe("other");
  });

  test("falls back to the extension, undefined for non-code", () => {
    // Arrange / Act / Assert
    expect(languageOf("x.rb", "")).toBe("ruby");
    expect(languageOf("x.ps1", "")).toBe("powershell");
    expect(languageOf("x.tsx", "")).toBe("typescript");
    expect(languageOf("x.bat", "")).toBe("other");
    expect(languageOf("x.txt", "")).toBeUndefined();
  });
});

describe("textKindOf", () => {
  test("marks the bundle's SKILL.md as skill-md", () => {
    // Arrange / Act / Assert
    expect(textKindOf("SKILL.md", "", true)).toEqual({ kind: "skill-md" });
  });

  test("recognizes manifests by name, including requirements variants", () => {
    // Arrange / Act / Assert
    for (const name of [
      "package.json",
      "requirements-dev.txt",
      "constraints.txt",
      ".mcp.json",
      "x/hooks.json",
      "opencode.jsonc",
      "Cargo.toml",
    ]) {
      expect(textKindOf(name, "", false)).toEqual({ kind: "manifest" });
    }
  });

  test("recognizes Markdown by extension", () => {
    // Arrange / Act / Assert
    expect(textKindOf("docs/a.md", "#!/bin/sh", false)).toEqual({ kind: "markdown" });
    expect(textKindOf("a.mdx", "", false)).toEqual({ kind: "markdown" });
  });

  test("classifies scripts with their language", () => {
    // Arrange / Act / Assert
    expect(textKindOf("run", "#!/usr/bin/env python3\n", false)).toEqual({ kind: "script", language: "python" });
    expect(textKindOf("x.go", "", false)).toEqual({ kind: "script", language: "go" });
  });

  test("falls back to text for data and unknown files", () => {
    // Arrange / Act / Assert
    expect(textKindOf("x.yaml", "", false)).toEqual({ kind: "text" });
    expect(textKindOf("Makefile", "", false)).toEqual({ kind: "text" });
    expect(textKindOf("x.foo", "", false)).toEqual({ kind: "text" });
  });
});

describe("binaryFormatOf", () => {
  test("detects executables by magic bytes", () => {
    // Arrange / Act / Assert
    expect(binaryFormatOf("a", bytes(0x7f, 0x45, 0x4c, 0x46))).toBe("elf");
    expect(binaryFormatOf("a", bytes(0xcf, 0xfa, 0xed, 0xfe))).toBe("mach-o");
    expect(binaryFormatOf("a", bytes(0xfe, 0xed, 0xfa, 0xce))).toBe("mach-o");
    expect(binaryFormatOf("a", bytes(0xca, 0xfe, 0xba, 0xbe))).toBe("mach-o");
    expect(binaryFormatOf("A.class", bytes(0xca, 0xfe, 0xba, 0xbe))).toBe("java-class");
    expect(binaryFormatOf("a", bytes(0x4d, 0x5a, 0x90, 0x00))).toBe("pe");
    expect(binaryFormatOf("a", bytes(0x00, 0x61, 0x73, 0x6d))).toBe("wasm");
  });

  test("distinguishes zip, jar-like, and office archives by extension", () => {
    // Arrange
    const zip = bytes(0x50, 0x4b, 0x03, 0x04);

    // Act / Assert
    expect(binaryFormatOf("a.zip", zip)).toBe("zip");
    expect(binaryFormatOf("a.skill", zip)).toBe("zip");
    expect(binaryFormatOf("a.jar", zip)).toBe("jar");
    expect(binaryFormatOf("a.whl", zip)).toBe("jar");
    expect(binaryFormatOf("a.docx", zip)).toBe("office");
    expect(binaryFormatOf("a.potx", zip)).toBe("office");
    expect(binaryFormatOf("empty.zip", bytes(0x50, 0x4b, 0x05, 0x06))).toBe("zip");
  });

  test("detects compressed streams", () => {
    // Arrange / Act / Assert
    expect(binaryFormatOf("a", bytes(0x1f, 0x8b))).toBe("gzip");
    expect(binaryFormatOf("a", bytes(0x42, 0x5a, 0x68))).toBe("bzip2");
    expect(binaryFormatOf("a", bytes(0xfd, 0x37, 0x7a, 0x58))).toBe("xz");
    expect(binaryFormatOf("a", bytes(0x37, 0x7a, 0xbc, 0xaf))).toBe("7z");
    expect(binaryFormatOf("a", bytes(0x52, 0x61, 0x72, 0x21))).toBe("rar");
  });

  test("uses the extension for bytecode and installers", () => {
    // Arrange / Act / Assert
    expect(binaryFormatOf("a.pyc", bytes(1, 2, 3, 4))).toBe("python-bytecode");
    expect(binaryFormatOf("a.dmg", bytes(1))).toBe("installer");
    expect(binaryFormatOf("a.deb", bytes(1))).toBe("installer");
  });

  test("classifies assets by magic or extension", () => {
    // Arrange / Act / Assert
    expect(binaryFormatOf("a", bytes(0x89, 0x50, 0x4e, 0x47))).toBe("image");
    expect(binaryFormatOf("a", bytes(0xff, 0xd8, 0xff))).toBe("image");
    expect(binaryFormatOf("a", bytes(0x47, 0x49, 0x46, 0x38))).toBe("image");
    expect(binaryFormatOf("a.webp", bytes(1))).toBe("image");
    expect(binaryFormatOf("a", bytes(0x25, 0x50, 0x44, 0x46))).toBe("pdf");
    expect(binaryFormatOf("a.woff2", bytes(1))).toBe("font");
    expect(binaryFormatOf("a.mp3", bytes(1))).toBe("media");
    expect(binaryFormatOf("a.sqlite", bytes(1))).toBe("database");
    expect(binaryFormatOf("a.xyz", bytes(1))).toBe("unknown");
    expect(binaryFormatOf("a", bytes())).toBe("unknown");
  });

  test("magic bytes win over a harmless extension", () => {
    // Arrange / Act / Assert
    expect(binaryFormatOf("logo.png", bytes(0x7f, 0x45, 0x4c, 0x46))).toBe("elf");
    expect(binaryFormatOf("notes.txt", bytes(0x50, 0x4b, 0x03, 0x04))).toBe("zip");
  });
});

describe("looksBinary and isBinaryExtension", () => {
  test("a NUL byte means binary", () => {
    // Arrange / Act / Assert
    expect(looksBinary(bytes(104, 0, 105))).toBe(true);
  });

  test("more than ten percent control bytes means binary", () => {
    // Arrange / Act / Assert
    expect(looksBinary(new Uint8Array(100).fill(1))).toBe(true);
    expect(looksBinary(new Uint8Array([...new Array(95).fill(65), 1, 1, 1, 1, 1]))).toBe(false);
  });

  test("ordinary text and empty input are not binary", () => {
    // Arrange / Act / Assert
    expect(looksBinary(new TextEncoder().encode("hello\n\tworld\r\n"))).toBe(false);
    expect(looksBinary(bytes())).toBe(false);
  });

  test("only the first 8 KiB are sampled", () => {
    // Arrange
    const data = new Uint8Array(9000).fill(65);
    data[8500] = 0;

    // Act / Assert
    expect(looksBinary(data)).toBe(false);
  });

  test("knows binary extensions", () => {
    // Arrange / Act / Assert
    expect(isBinaryExtension("a.PNG")).toBe(true);
    expect(isBinaryExtension("a.pptx")).toBe(true);
    expect(isBinaryExtension("a.md")).toBe(false);
  });
});

describe("roleOf", () => {
  test("SKILL.md is instructions", () => {
    // Arrange / Act / Assert
    expect(roleOf({ path: "SKILL.md", kind: "skill-md" }, "skill")).toBe("instructions");
  });

  test("README-like Markdown is readme and other Markdown is reference", () => {
    // Arrange / Act / Assert
    expect(roleOf({ path: "README.md", kind: "markdown" }, "skill")).toBe("readme");
    expect(roleOf({ path: "docs/CHANGELOG.md", kind: "markdown" }, "skill")).toBe("readme");
    expect(roleOf({ path: "references/api.md", kind: "markdown" }, "skill")).toBe("reference");
  });

  test("plugin commands and agents are instructions, but only in plugins", () => {
    // Arrange / Act / Assert
    expect(roleOf({ path: "commands/x.md", kind: "markdown" }, "plugin")).toBe("instructions");
    expect(roleOf({ path: "plugins/p/agents/y.md", kind: "markdown" }, "plugin")).toBe("instructions");
    expect(roleOf({ path: "commands/x.md", kind: "markdown" }, "skill")).toBe("reference");
  });

  test("scripts are code, manifests are manifest, license text is readme", () => {
    // Arrange / Act / Assert
    expect(roleOf({ path: "a.py", kind: "script" }, "skill")).toBe("code");
    expect(roleOf({ path: "package.json", kind: "manifest" }, "skill")).toBe("manifest");
    expect(roleOf({ path: "LICENSE", kind: "text" }, "skill")).toBe("readme");
    expect(roleOf({ path: "x.txt", kind: "text" }, "skill")).toBe("other");
  });
});
