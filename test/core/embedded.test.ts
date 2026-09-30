import { describe, expect, test } from "bun:test";
import { extractEmbedded, parseJsonLoose, stripJsonComments } from "../../src/core/embedded";
import { bundleOf, type FileSpec } from "../helpers/bundle";

const extract = (files: Readonly<Record<string, FileSpec>>, kind?: "skill" | "plugin" | "package") =>
  extractEmbedded(bundleOf(files, kind ? { kind } : {}));
const json = (v: unknown) => JSON.stringify(v, null, 2);

describe("package.json scripts", () => {
  test("marks lifecycle scripts separately from ordinary npm scripts", () => {
    // Arrange
    const files = { "package.json": json({ name: "x", scripts: { postinstall: "node setup.js", test: "bun test", prepare: "husky" } }) };

    // Act
    const { commands } = extract(files);

    // Assert
    expect(commands.get("package.json")).toEqual([
      { pointer: "scripts.postinstall", command: "node setup.js", trigger: "lifecycle-script", line: 4 },
      { pointer: "scripts.test", command: "bun test", trigger: "npm-script", line: 5 },
      { pointer: "scripts.prepare", command: "husky", trigger: "lifecycle-script", line: 6 },
    ]);
  });

  test("turns every script into a virtual shell file pointing back at its line", () => {
    // Arrange
    const files = { "package.json": json({ scripts: { preinstall: "sh ./x.sh" } }) };

    // Act
    const { virtualFiles } = extract(files);

    // Assert
    expect(virtualFiles).toEqual([
      {
        path: "package.json#scripts.preinstall",
        kind: "script",
        language: "shell",
        size: 9,
        text: "sh ./x.sh",
        virtualOf: { path: "package.json", line: 3 },
      },
    ]);
  });

  test("ignores non-string scripts and a package.json that does not parse", () => {
    // Arrange
    const files = { "package.json": json({ scripts: { a: 1, b: ["x"] } }), "sub/package.json": "{ not json" };

    // Act
    const { commands, virtualFiles } = extract(files);

    // Assert
    expect(commands.size).toBe(0);
    expect(virtualFiles).toEqual([]);
  });

  test("does not read scripts from a JSON file that is not package.json", () => {
    // Arrange
    const files = { "data.json": json({ scripts: { postinstall: "node x.js" } }) };

    // Act / Assert
    expect(extract(files).commands.size).toBe(0);
  });
});

describe("hook configuration", () => {
  test("extracts command hooks and HTTP hooks, but only command hooks become virtual files", () => {
    // Arrange
    const files = {
      "hooks/hooks.json": json({
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [
                { type: "command", command: "echo pre" },
                { type: "http", url: "https://hooks.example/x" },
              ],
            },
          ],
        },
      }),
    };

    // Act
    const { commands, virtualFiles } = extract(files, "plugin");

    // Assert
    expect(commands.get("hooks/hooks.json")).toEqual([
      { pointer: "hooks.PreToolUse[0].hooks[0]", command: "echo pre", trigger: "hook", line: 9 },
      { pointer: "hooks.PreToolUse[0].hooks[1]", command: "https://hooks.example/x", trigger: "http-hook", line: 13 },
    ]);
    expect(virtualFiles.map((v) => v.path)).toEqual(["hooks/hooks.json#hooks.PreToolUse[0].hooks[0]"]);
  });

  test("reads hooks from settings files with comments and trailing commas", () => {
    // Arrange
    const files = {
      "settings.json":
        '// comment\n{\n  "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "say done" }, ] } ] }, /* c */\n}\n',
    };

    // Act
    const { commands } = extract(files);

    // Assert
    expect(commands.get("settings.json")).toEqual([{ pointer: "hooks.Stop[0].hooks[0]", command: "say done", trigger: "hook", line: 3 }]);
  });

  test("skips malformed hook groups and entries", () => {
    // Arrange
    const files = { "hooks.json": json({ hooks: { A: "nope", B: [null, { hooks: "x" }, { hooks: [null, { type: "command" }] }] } }) };

    // Act / Assert
    expect(extract(files).commands.size).toBe(0);
  });

  test("reads hooks declared in SKILL.md frontmatter", () => {
    // Arrange
    const skillMd =
      "---\nname: s\ndescription: d\nhooks:\n  PostToolUse:\n    - matcher: Write\n      hooks:\n        - type: command\n          command: ./fmt.sh\n---\nbody\n";

    // Act
    const { commands } = extract({ "SKILL.md": skillMd });

    // Assert
    expect(commands.get("SKILL.md")).toEqual([
      { pointer: "frontmatter.hooks.PostToolUse[0].hooks[0]", command: "./fmt.sh", trigger: "hook", line: 9 },
    ]);
  });
});

describe("MCP server declarations", () => {
  test("joins command and args with shell quoting where needed", () => {
    // Arrange
    const files = {
      ".mcp.json": json({
        mcpServers: { srv: { command: "npx", args: ["-y", "pkg@1.0", "--flag=a b", "it's", 3] }, remote: { url: "https://mcp.example" } },
      }),
    };

    // Act
    const { commands, virtualFiles } = extract(files);

    // Assert
    expect(commands.get(".mcp.json")).toEqual([
      { pointer: "mcpServers.srv", command: "npx -y pkg@1.0 '--flag=a b' 'it'\\''s'", trigger: "mcp-server", line: 4 },
    ]);
    expect(virtualFiles[0]?.path).toBe(".mcp.json#mcpServers.srv");
  });

  test("accepts the snake_case mcp_servers key", () => {
    // Arrange
    const files = { "x.json": json({ mcp_servers: { a: { command: "node", args: ["server.js"] } } }) };

    // Act
    const { commands } = extract(files);

    // Assert
    expect(commands.get("x.json")?.[0]).toMatchObject({ pointer: "mcpServers.a", command: "node server.js", trigger: "mcp-server" });
  });

  test("reads OpenCode command arrays", () => {
    // Arrange
    const files = {
      "opencode.json": json({ mcp: { local: { type: "local", command: ["bunx", "tool", "--x y"] }, empty: { command: [] } } }),
    };

    // Act
    const { commands } = extract(files);

    // Assert
    expect(commands.get("opencode.json")).toEqual([
      { pointer: "mcp.local", command: "bunx tool '--x y'", trigger: "opencode-mcp", line: 6 },
    ]);
  });

  test("ignores MCP-looking keys in non-JSON files", () => {
    // Arrange / Act / Assert
    expect(extract({ "config.yaml": "mcpServers:\n  a:\n    command: node\n" }).commands.size).toBe(0);
  });
});

describe("load-time shell in Markdown", () => {
  const body =
    "Run !`git status` now.\nNot this: a!`nope` or `!`also\n!`at start`\n\n```!\nls -la\npwd\n```\n\n```bash\necho normal fence\n```\n";

  test("extracts !`cmd` only at line start or after whitespace", () => {
    // Arrange
    const skillMd = `---\nname: s\ndescription: d\n---\n${body}`;

    // Act
    const list = extract({ "SKILL.md": skillMd }).commands.get("SKILL.md") ?? [];

    // Assert
    expect(list.map((c) => c.command)).toEqual(["git status", "at start", "ls -la\npwd"]);
    expect(list.every((c) => c.trigger === "load-time-shell")).toBe(true);
  });

  test("points a ```! block at its first content line", () => {
    // Arrange
    const skillMd = `---\nname: s\ndescription: d\n---\n${body}`;

    // Act
    const block = extract({ "SKILL.md": skillMd })
      .commands.get("SKILL.md")
      ?.find((c) => c.command.startsWith("ls"));

    // Assert
    expect(block).toEqual({ pointer: "load-shell@9", command: "ls -la\npwd", trigger: "load-time-shell", line: 10 });
  });

  test("applies to plugin commands, agents, and skills directories but not other Markdown", () => {
    // Arrange
    const files = {
      "commands/do.md": "Context: !`date`",
      "agents/a.md": "!`whoami`",
      "skills/x/notes.md": "!`id`",
      "docs/other.md": "Context: !`date`",
    };

    // Act
    const { commands } = extract(files, "plugin");

    // Assert
    expect([...commands.keys()].sort()).toEqual(["agents/a.md", "commands/do.md", "skills/x/notes.md"]);
  });
});

describe("Codex agents/openai.yaml", () => {
  test("extracts stdio MCP dependencies with their args", () => {
    // Arrange
    const yaml =
      'interface:\n  display_name: X\ndependencies:\n  tools:\n    - type: mcp\n      value: srv\n      command: uvx\n      args: ["server-pkg", "--opt"]\n    - type: env_var\n      value: TOKEN\n';

    // Act
    const { commands, virtualFiles } = extract({ "agents/openai.yaml": yaml });

    // Assert
    expect(commands.get("agents/openai.yaml")).toEqual([
      { pointer: "dependencies.tools[0]", command: "uvx server-pkg --opt", trigger: "mcp-server", line: 7 },
    ]);
    expect(virtualFiles[0]?.virtualOf).toEqual({ path: "agents/openai.yaml", line: 7 });
  });

  test("returns nothing when dependencies are missing or malformed", () => {
    // Arrange / Act / Assert
    expect(extract({ "agents/openai.yaml": "interface:\n  display_name: X\n" }).commands.size).toBe(0);
    expect(extract({ "agents/openai.yml": "dependencies:\n  tools: none\n" }).commands.size).toBe(0);
  });
});

describe("parseJsonLoose and stripJsonComments", () => {
  test("parses strict JSON directly", () => {
    // Arrange / Act / Assert
    expect(parseJsonLoose('{"a": 1}')).toEqual({ a: 1 });
  });

  test("tolerates comments and trailing commas without touching strings", () => {
    // Arrange / Act / Assert
    expect(parseJsonLoose('{"a": "http://x//y", /* c */ "b": [1,],}')).toEqual({ a: "http://x//y", b: [1] });
  });

  test("returns undefined for text that is not JSON", () => {
    // Arrange / Act / Assert
    expect(parseJsonLoose("{bad")).toBeUndefined();
    expect(parseJsonLoose("")).toBeUndefined();
  });

  test("keeps escaped quotes inside strings when stripping comments", () => {
    // Arrange / Act / Assert
    expect(stripJsonComments('{"s":"a\\"//b"} // c')).toBe('{"s":"a\\"//b"} \n');
    expect(stripJsonComments("a /* unterminated")).toBe("a ");
  });
});
