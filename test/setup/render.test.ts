import { describe, expect, test } from "bun:test";
import type { CanaryResult } from "../../src/setup/canary";
import type { SetupPlan } from "../../src/setup/index";
import { renderCanaries, renderList, renderPlan } from "../../src/setup/render";

const ESC = String.fromCharCode(27);
const results: CanaryResult[] = [
  { name: "hook allows a harmless command", ok: true, detail: "exit 0" },
  { name: "scan blocks a malicious test skill", ok: false, detail: "exit 0, verdict pass" },
];

describe("setup rendering", () => {
  test("stays plain text without color", () => {
    expect(renderCanaries(results)).toBe(
      "Canary:\n  ok      hook allows a harmless command: exit 0\n  fail    scan blocks a malicious test skill: exit 0, verdict pass\n",
    );
    expect(renderList("Next:", ["Restart", "Check"])).toBe("Next:\n  - Restart\n  - Check\n");
  });

  test("paints passing checks green, failures red, and headings bold with color", () => {
    const out = renderCanaries(results, true);

    expect(out).toContain(`${ESC}[1mCanary:${ESC}[0m`);
    expect(out).toContain(`${ESC}[32mok     ${ESC}[0m`);
    expect(out).toContain(`${ESC}[31mfail   ${ESC}[0m`);
    expect(renderList("Next:", ["Restart"], true)).toBe(`${ESC}[1mNext:${ESC}[0m\n  ${ESC}[2m-${ESC}[0m Restart\n`);
  });

  test("wraps each list item under itself to the terminal width", () => {
    const out = renderList("Next:", ["one two three four five six seven eight nine ten"], false, 40);

    expect(out).toBe("Next:\n  - one two three four five six seven\n    eight nine ten\n");
  });

  test("moves a plan line's summary under its path when the line is wider than the terminal", () => {
    const plan: SetupPlan = {
      mode: "install",
      scope: "user",
      harnesses: ["claude-code"],
      stateDir: "/home/u/.skill-scanner",
      script: "/home/u/.skill-scanner/bin/skill-scanner.mjs",
      sections: [
        {
          id: "claude-code",
          title: "Claude Code",
          ops: [
            {
              kind: "write",
              path: "/home/u/.claude/settings.json",
              after: "{}",
              backup: true,
              summary: "add hooks: PreToolUse, PostToolUse, SessionStart",
            },
          ],
          unchanged: [],
          notes: [],
          warnings: [],
        },
      ],
    };

    const wide = renderPlan(plan, "/home/u");
    const narrow = renderPlan(plan, "/home/u", false, 50);

    expect(wide).toContain("  create  ~/.claude/settings.json  add hooks: PreToolUse, PostToolUse, SessionStart\n");
    expect(narrow).toContain("  create  ~/.claude/settings.json\n          add hooks: PreToolUse, PostToolUse,\n          SessionStart\n");
  });
});
