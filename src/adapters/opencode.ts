/**
 * OpenCode plugin (verified against OpenCode 1.18.33). OpenCode calls every export of this module
 * as a plugin and rejects any that is not a function, so `SkillScanner` is the only export; the
 * factory with injectable dependencies is `createSkillScannerPlugin` in `./shared`.
 */
import type { Plugin } from "@opencode-ai/plugin";
import { createSkillScannerPlugin } from "./shared";

export const SkillScanner: Plugin = createSkillScannerPlugin();
