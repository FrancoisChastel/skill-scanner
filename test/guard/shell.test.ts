import { describe, expect, test } from "bun:test";
import { commandWords, parseShell, programName, shellQuote } from "../../src/guard/shell";

const words = (src: string): string[][] => parseShell(src).commands.map((c) => [...c.words]);

describe("parseShell", () => {
  test("splits on operators and keeps quoted text whole", () => {
    expect(words(`a "b c" 'd e' f\\ g && h | i; j || k & l`)).toEqual([["a", "b c", "d e", "f g"], ["h"], ["i"], ["j"], ["k"], ["l"]]);
  });

  test("records the connecting operator", () => {
    const cmds = parseShell("echo x | sh; ls").commands;
    expect(cmds.map((c) => c.after)).toEqual([undefined, "|", ";"]);
  });

  test("ANSI-C quoting, escapes inside double quotes, and line continuations", () => {
    expect(words(`printf $'a\\tb\\x41' "q\\"x\\$y" one\\\ntwo`)).toEqual([["printf", "a\tbA", 'q"x$y', "onetwo"]]);
  });

  test("file-descriptor redirects are not arguments", () => {
    const [c] = parseShell("cmd 2>&1 >/dev/null 1>out.txt").commands;
    expect(c?.words).toEqual(["cmd"]);
    expect(c?.redirects.map((r) => `${r.op}${r.target}`)).toEqual([">&1", ">/dev/null", ">out.txt"]);
  });

  test("heredoc bodies attach to their command and are not commands", () => {
    const p = parseShell("cat <<-EOF > f\n\tnpx skills add x\n\tEOF\necho done");
    expect(p.commands.map((c) => c.words[0])).toEqual(["cat", "echo"]);
    expect(p.commands[0]?.redirects.find((r) => r.op === "<<-")?.body).toBe("\tnpx skills add x");
  });

  test("collects command and process substitutions (nested ones when the body is parsed in turn)", () => {
    const braced = ["$", "{HOME}"].join("");
    expect(parseShell(`a=$(b $(c)) \`d\` <(e) $((1+2)) ${braced}`).substitutions).toEqual(["b $(c)", "d", "e"]);
    expect(parseShell("b $(c)").substitutions).toEqual(["c"]);
  });

  test("comments end at the newline", () => {
    expect(words("a # b c\nd")).toEqual([["a"], ["d"]]);
  });
});

describe("commandWords", () => {
  test("strips assignments, keywords, and wrappers", () => {
    expect(commandWords(["FOO=1", "sudo", "-u", "me", "env", "-i", "BAR=2", "nice", "-n", "5", "npx", "skills"])).toEqual([
      "npx",
      "skills",
    ]);
    expect(commandWords(["if", "timeout", "--signal=KILL", "30", "git", "clone"])).toEqual(["git", "clone"]);
    expect(commandWords(["xargs", "-I", "{}", "cp", "{}", "dest"])).toEqual(["cp", "{}", "dest"]);
  });

  test("returns nothing when the wrapper only looks something up", () => {
    expect(commandWords(["command", "-v", "npx"])).toEqual([]);
    expect(commandWords(["sudo", "-l"])).toEqual([]);
  });

  test("programName and shellQuote", () => {
    expect(programName("/usr/local/bin/npx")).toBe("npx");
    expect(programName("C:\\tools\\git.exe")).toBe("git");
    expect(shellQuote("plain/path-1.0")).toBe("plain/path-1.0");
    expect(shellQuote("it's here")).toBe("'it'\\''s here'");
  });
});
