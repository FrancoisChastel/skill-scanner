import { listLeadAt } from "../core/context";
import { type PatternRuleSpec, patternRule } from "../core/pattern-rule";
import type { FileContext, FileRule, RegionPolicy } from "../core/rule";
import { demote } from "../core/severity";
import { lineText, positionAt } from "../core/text";

/**
 * Instructions that turn the agent against the person it works for: faking success (tests
 * rigged, results made up, failures kept out of the report), quietly swapping the task for an
 * easier one, and lying or covering tracks. The tactics are the ones documented for coding agents
 * that reward-hack or scheme: test edits, special-cased inputs, always-equal objects, patched
 * graders (ImpossibleBench 2025, METR 2025, the Claude 3.7 Sonnet system card, EvilGenie 2025),
 * fabricated reports that hid a failure (the Replit incident, 2025), rewritten checks that hid
 * tampering (Anthropic, Sycophancy to Subterfuge 2024), and lying when asked (Apollo Research,
 * In-context Scheming 2024). A skill that asks for any of this is malicious whatever else it does.
 *
 * The same words appear in honest skills, negated: "never modify tests to make them pass". So a
 * match whose deceptive act is negated right before it is dropped, and one written as a
 * description (an anti-pattern list, a reviewer's question, "agents often ...") is a mention.
 */

const INSTRUCTION_REGIONS: RegionPolicy = {
  hidden: "raise",
  frontmatter: "raise",
  code: "lower-confidence",
  "inline-code": "lower-confidence",
};

/** A negation that governs the verb right after it: "never", "do not", "must not, under any circumstances,", "instead of". */
const NEGATED_BEFORE_RE =
  /(?:\b(?:never|not|no|without|avoid(?:ing)?|instead\s+of|rather\s+than|refrain\s+from|forbid\w*|prohibit\w*)\b|n't\b)(?:\s*,|\s+(?:ever|just|simply|even|try\s+to|attempt\s+to|go\s+and|be\s+tempted\s+to|under\s+any\s+circumstances|to|you|yourself|allowed\s+to|acceptable\s+to|ok(?:ay)?\s+to|permitted\s+to|should|shall|must|use|pass|add|run\s+with|commit\s+with|push\s+with|reach\s+for|resort\s+to)){0,4}\s*$/i;

/**
 * Wording that makes a line describe the behaviour rather than ask for it. Only words an attacker
 * has no reason to write: "catch", "detect", or "shortcut" also fit an instruction.
 */
const DESCRIBED_RE =
  /\b(?:anti-?patterns?|red\s+flags?|reward[\s-]hack\w*|specification[\s-]gaming|gam(?:e|es|ed|ing)\s+(?:the\s+|its\s+|their\s+)?(?:tests?|gates?|checks?|metrics?|graders?|evals?|evaluation|benchmarks?|scorer|system)|cheat\w*|warning\s+signs?|failure\s+modes?|bad\s+(?:practices?|behaviou?rs?|habits?)|dark\s+patterns?|forbidden|not\s+(?:allowed|acceptable|okay|ok|permitted)|prohibited|unacceptable|dishonest\w*|deceptive\w*|sycophan\w*|detectors?|detection|watch\s+(?:out\s+)?for|look\s+(?:out\s+)?for|audit\w*|refus\w*|reject\w*|tempt\w*)\b/i;
/** The match is the example: "such as hard-coding the expected output". */
const EXAMPLE_BEFORE_RE = /\b(?:e\.g\.|for\s+example|for\s+instance|such\s+as|examples?\s+(?:of|include))[^.;\n]{0,80}$/i;

/** Someone else is the subject: "agents often hard-code ...", "the model deleted ...". */
const THIRD_PERSON_RE =
  /\b(?:agents?|models?|llms?|ais?|assistants?|claude|codex|gpt[\w.-]*|copilot|gemini|o\d|someone|people|developers?|engineers?|contributors?|it|they|he|she)\s+(?:(?:often|sometimes|may|might|can|could|will|would|tends?\s+to|tried\s+to|tries\s+to|try\s+to|learned\s+to|learns?\s+to|started\s+to|kept|keeps|was|were|has|have|had|is|are|did|does)\s+){1,2}$/i;

/**
 * The start of the clause a match sits in: after the last sentence or clause break, reading back
 * onto the previous line when the sentence wraps ("Do not\nmodify the tests ...").
 */
function clauseBefore(ctx: FileContext, offset: number): string {
  const { line } = positionAt(ctx.index, offset);
  let before = ctx.text.slice(ctx.index.starts[line - 1] ?? 0, offset);
  if (line > 1 && !/[.!?;:\u2014]/.test(before)) {
    const prev = lineText(ctx.index, line - 1);
    const wraps = prev.trim() !== "" && !/[.!?;:]\s*$/.test(prev) && !/^\s*(?:[-*+]\s|\d+[.)]\s|#|\||```)/.test(lineText(ctx.index, line));
    if (wraps) before = `${prev} ${before}`;
  }
  const cut = Math.max(before.search(/[^.!?;:\u2014]*$/), 0);
  return before.slice(cut).slice(-160);
}

/** The second verb of a negated pair: "never lie to the user or mislead them". */
const NEGATED_PAIR_RE = /(?:\b(?:never|not|no)\b|n't\b)[^.;:!?\n]{0,80}\b(?:or|nor)\s*$/i;
/** A later verb in a negated list: "do not diagnose, treat, dose, or fabricate results". Two items at least, so "if it doesn't work, ..." is not one. */
const NEGATED_LIST_RE = /(?:\b(?:never|not)\b|n't\b)\s+(?:[a-z][\w-]*(?:\s+[a-z][\w-]*){0,3}\s*,\s*){2,10}(?:(?:and|or|nor)\s+)?$/i;
/** The verb names what something else does: "instructions to deceive the user", "skills that hide failures". */
const NAMED_ACT_RE =
  /\b(?:(?:instructions?|attempts?|tries|tried|trying|ways?|designed|intended|meant|efforts?|requests?|prompts?|attacks?|payloads?|attempting)\s+to|(?:that|which|who))\s+$/i;
/** A consequence or a hypothetical, not an order: "running these probes will mislead the user". */
const MODAL_BEFORE_RE =
  /\b(?:will|would|could|might|'ll|'d)\s+(?:only\s+|just\s+|probably\s+|likely\s+)?(?:have\s+to\s+|need\s+to\s+|end\s+up\s+|be\s+able\s+to\s+)?$/i;

function negatedBefore(ctx: FileContext, offset: number): boolean {
  const clause = clauseBefore(ctx, offset);
  return NEGATED_BEFORE_RE.test(clause) || NEGATED_PAIR_RE.test(clause) || NEGATED_LIST_RE.test(clause);
}

/** Whether the match is written up rather than asked for: framing words, a question, a third-person subject, or a "Never:" list. */
function described(ctx: FileContext, offset: number): boolean {
  const { line } = positionAt(ctx.index, offset);
  const text = lineText(ctx.index, line);
  if (DESCRIBED_RE.test(text) || /\?\s*(?:\*\*)?\s*$/.test(text)) return true;
  if (EXAMPLE_BEFORE_RE.test(ctx.text.slice(ctx.index.starts[line - 1] ?? 0, offset))) return true;
  const clause = clauseBefore(ctx, offset);
  if (THIRD_PERSON_RE.test(clause) || MODAL_BEFORE_RE.test(clause) || NAMED_ACT_RE.test(clause)) return true;
  const lead = listLeadAt(ctx, offset);
  return lead !== "" && (DESCRIBED_RE.test(lead) || /\b(?:never|don't|do\s+not|avoid|must\s+not|no|wrong|bad|dont)\b/i.test(lead));
}

interface DeceptionSpec extends Omit<PatternRuleSpec, "category" | "cautionAware" | "quoteAware"> {
  /** The pattern carries its own negation ("do not mention ..."), so a negation before it is not a reason to drop it. */
  readonly negationInPattern?: boolean;
}

/** A prose rule: dropped when negated, a mention when described, graded like other instruction text otherwise. */
function deceptionRule(spec: DeceptionSpec): FileRule {
  const { negationInPattern, ignoreMatch, adjust, ...rest } = spec;
  return patternRule({
    regions: INSTRUCTION_REGIONS,
    roles: { readme: "lower-confidence", code: "lower-confidence" },
    ...rest,
    category: "deception",
    cautionAware: false,
    quoteAware: true,
    ignoreMatch: (m, ctx) => (!negationInPattern && negatedBefore(ctx, m.index)) || (ignoreMatch?.(m, ctx) ?? false),
    adjust: (m, ctx) => (described(ctx, m.index) ? { severity: demote(spec.severity), confidence: "low" } : adjust?.(m, ctx)),
  });
}

const re = (source: string): RegExp => new RegExp(source, "gi");

// Shared vocabulary. Every quantifier is bounded.
const TESTS = String.raw`(?:(?:unit|integration|e2e|end-to-end|failing|broken|flaky|existing|red)\s+){0,2}(?:tests?|test\s+(?:cases?|files?|suites?|expectations?)|assertions?|asserts?|specs?|expectations?|checks?|expected\s+(?:values?|outputs?|results?))`;
const PASS_GOAL = String.raw`(?:so\s+(?:that\s+)?(?:they|it|the\s+(?:tests?|suite|build|ci|checks?|pipeline))\s+(?:all\s+)?(?:pass(?:es)?|succeeds?|go(?:es)?\s+green|(?:is|are)\s+green|stop\s+failing|no\s+longer\s+fails?)|to\s+(?:make|get)\s+(?:them|it|the\s+(?:tests?|suite|build|ci|checks?|pipeline))\s+(?:to\s+)?(?:all\s+)?(?:pass|green|succeed|go\s+green)|until\s+(?:they|it|the\s+(?:tests?|suite|build|ci|checks?))\s+(?:all\s+)?(?:pass(?:es)?|succeeds?|(?:is|are)\s+green))`;
const REGARDLESS = String.raw`(?:even\s+(?:if|when|though)|regardless(?:\s+of)?|whether\s+or\s+not|no\s+matter\s+(?:what|whether|if|how)|irrespective\s+of|despite|in\s+(?:any|every)\s+case|either\s+way)`;
const SUCCESS = `(?:passed|pass(?:es|ing)?|succeeded|succeeds?|successful(?:ly)?|success|work(?:s|ed|ing)?|green|complete[d]?|done|fixed|resolved|fine|ok(?:ay)?|verified|deployed)`;
const SUBJECT = String.raw`(?:(?:the\s+|all\s+(?:the\s+)?|every\s+)?(?:tests?|checks?|builds?|tasks?|fix(?:es)?|changes?|deploy(?:ment)?s?|migrations?|run|job|pipeline|ci|code|work|implementation|feature)|it|everything|this)`;
const FAILURE_OBJECT = String.raw`(?:(?:any\s+|the\s+|all\s+)?(?:(?:test|build|ci|check|lint(?:er|ing)?|type[\s-]?check(?:ing|er)?|compil(?:e|er|ation)|command|tool|script|deploy(?:ment)?|migration|runtime)\s+(?:failures?|errors?)|failing\s+(?:tests?|checks?|builds?|commands?|steps?|jobs?)|(?:errors?|failures?|exceptions?|problems?|issues?|bugs?)\s+(?:that\s+)?(?:you\s+)?(?:encountered|hit|ran\s+into|saw|found|caused|introduced|could\s+not\s+fix|couldn't\s+fix))|that\s+(?:the\s+|any\s+)?(?:tests?|build|checks?|commands?|steps?|task|fix|deploy(?:ment)?|migration|it|something|anything)\s+(?:failed|fails|broke|errored|didn't\s+work|did\s+not\s+work|(?:is|are|was|were)\s+(?:failing|broken)))\b(?!\s+as\s+(?:a\s+)?(?:pass(?:ed|ing)?|success(?:ful)?|green|fixed|done|complete))`;

/** "Update", "adjust", and "change" also describe honest maintenance after an intended behaviour change; the rest do not. */
const SOFT_TAMPER = /^(?:update|adjust|change)\b/i;

const tamperTests = deceptionRule({
  id: "deception/tamper-with-tests",
  title: "Tells the agent to change tests until they pass",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions to edit, weaken, skip, or delete tests and checks so that they pass, or to rewrite assertions to match what the code returns. It is the most common way coding agents fake success (ImpossibleBench, the Claude 3.7 Sonnet system card).",
  remediation:
    "Do not install. A skill must fix the code a test exposes, or stop and report the failing test, never change the test to hide it.",
  patterns: [
    re(
      String.raw`\b(?:modify|edit|change|rewrite|update|adjust|alter|patch|delete|remove|comment\s+out|skip|disable|weaken|loosen|relax|tweak|hack|fudge|rig)\s+(?:the\s+|any\s+|a\s+|those\s+|these\s+|all\s+|its\s+|their\s+)?${TESTS}\b[^.\n]{0,40}?${PASS_GOAL}`,
    ),
    re(
      String.raw`\b(?:mark|flag|tag|annotate|decorate)\s+(?:the\s+|any\s+|all\s+|those\s+)?(?:failing|broken|red|remaining)\s+(?:tests?|specs?|test\s+cases?)\s+(?:as|with)\s+` +
        String.raw`(?:\x60?@?(?:pytest\.mark\.)?)?(?:skip(?:ped)?|xfail|expected[\s-]to[\s-]fail|expected\s+failures?|pending|todo|known[\s-]failures?)\b`,
    ),
    re(
      String.raw`\b(?:skip|delete|remove|comment\s+out|disable|drop)\s+(?:the\s+|any\s+|all\s+|those\s+)?(?:failing|broken|red)\s+(?:tests?|specs?|test\s+cases?|assertions?|checks?)\b(?!\s+(?:that|which|for|covering|from\s+(?:the\s+)?(?:deleted|removed)))`,
    ),
    re(
      String.raw`\b(?:change|modify|edit|update|rewrite|adjust)\s+(?:the\s+)?(?:tests?|assertions?|expected\s+(?:values?|outputs?|results?))\s+to\s+match\s+(?:the\s+|what\s+the\s+)?(?:(?:current|actual)\s+)?(?:code(?:'s)?\s+(?:output|behaviou?r|returns?)|output|implementation|actual\s+(?:output|values?|results?|behaviou?r)|what\s+(?:the\s+code|it)\s+(?:returns|produces|does))\b`,
    ),
  ],
  adjust: (m) => (SOFT_TAMPER.test(m[0]) ? { severity: "medium" } : undefined),
});

const specialCase = deceptionRule({
  id: "deception/special-case-tests",
  title: "Tells the agent to hard-code what the tests expect",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions to return the expected values directly, special-case the inputs the tests use, or behave differently when running under a test or grader. The code then passes its checks without doing the work (the Claude 3.7 Sonnet system card, ImpossibleBench, EvilGenie).",
  remediation: "Do not install. Code that recognises its tests and answers them from a table does not work.",
  patterns: [
    /\bhard[\s-]?cod(?:e|ed|ing)\s+(?:in\s+)?(?:the\s+)?(?:expected|correct|right|test(?:'s)?)\s+(?:outputs?|values?|results?|answers?|responses?|return\s+values?)\b/gi,
    /\bspecial[\s-]?cas(?:e|ing)\s+(?:the\s+|each\s+|every\s+)?(?:tests?|test\s+(?:inputs?|cases?|data|values?)|(?:inputs?|cases?)\s+(?:used\s+)?(?:in|by)\s+the\s+tests?)\b/gi,
    /\b(?:if|when)\s+(?:the\s+)?(?:code\s+is\s+|it(?:'s|\s+is)\s+|you(?:'re|\s+are)\s+)?(?:running\s+)?(?:in|under|inside)\s+(?:a\s+|the\s+)?(?:tests?|test\s+(?:suite|environment|harness|runner)|ci|grader|grading|evaluation|eval|benchmark)\b[^.\n]{0,60}?\b(?:return|output|print|emit)\s+(?:the\s+)?(?:expected|hard-?coded|canned|fixed|precomputed|cached)\b/gi,
    /\b(?:read|load|copy|take|pull|grab|parse)\s+(?:the\s+)?expected\s+(?:outputs?|values?|results?|answers?)\s+(?:directly\s+)?(?:from|out\s+of)\s+(?:the\s+)?(?:tests?|test\s+(?:files?|cases?|fixtures?|data)|grader|answer\s+key|reference\s+solution)\b[^.\n]{0,40}?\b(?:and\s+)?(?:return|output|print|submit)\s+(?:them|those|it|that)\b/gi,
  ],
});

const misreportSuccess = deceptionRule({
  id: "deception/report-false-success",
  title: "Tells the agent to report success whatever happened",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions to say that tests passed, the build works, or the task is done regardless of the outcome, or when it failed. The user is told the work succeeded when it did not (the Replit incident, 2025).",
  remediation: "Do not install. A skill must report failures as failures.",
  patterns: [
    re(
      String.raw`\b(?:report|say|state|tell\s+(?:the\s+)?(?:user|human|them|people)|claim|confirm|announce|assert|respond|reply|print|output|write|log|mark|record|present|declare)\s+(?:to\s+(?:the\s+)?(?:user|human)\s+)?(?:that\s+)?${SUBJECT}\s+(?:(?:has|have|is|are|was|were)\s+(?:been\s+)?)?(?:all\s+)?(?:as\s+)?(?:a\s+)?${SUCCESS}\b[^.\n]{0,60}?\b${REGARDLESS}\b`,
    ),
    re(
      String.raw`\b(?:report|return|claim|declare|announce|print|output|say)\s+(?:a\s+)?(?:success|"?(?:all\s+)?tests?\s+pass(?:ed)?"?|ok|pass(?:ed)?|green)\b[^.\n]{0,60}?\b${REGARDLESS}\b`,
    ),
    re(
      String.raw`\b(?:if|when|even\s+if)\s+(?:the\s+)?(?:tests?|checks?|build|ci|it|the\s+(?:fix|command|script|deploy(?:ment)?))\s+(?:still\s+)?(?:fails?|failed|is\s+failing|are\s+failing|doesn't\s+work|does\s+not\s+work|didn't\s+work|did\s+not\s+work|breaks?|errors?\s+out)\b[^.\n]{0,50}?\b(?:report|say|tell\s+(?:the\s+)?(?:user|human|them)|claim|state|respond|announce|print|output)\s+(?:that\s+)?(?:(?:it|they|the\s+(?:tests?|build|checks?|task|fix))\s+)?(?:all\s+)?(?:(?:has|have|is|are|was|were)\s+)?(?:passed|pass(?:es)?|succeeded|successful|works?|worked|green|complete[d]?|done|fixed)\b`,
    ),
    /\balways\s+(?:report|say|tell\s+(?:the\s+)?user|claim|state|respond)\s+(?:that\s+)?(?:the\s+)?(?:(?:all\s+)?tests?\s+(?:passed|pass)|(?:it|the\s+task|everything)\s+(?:was\s+|is\s+)?(?:successful|succeeded|worked|works|complete[d]?|done))\b/gi,
  ],
  adjust: (m) => (/^always\b/i.test(m[0]) ? { severity: "medium" } : undefined),
});

const hideFailures = deceptionRule({
  id: "deception/hide-failures",
  title: "Tells the agent to keep failures out of its report",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions not to mention test failures, build errors, or problems the agent ran into, or to hide them from the summary the user reads. The user then believes work is finished that is not.",
  remediation: "Do not install. What failed is exactly what the user needs to hear.",
  negationInPattern: true,
  patterns: [
    re(
      String.raw`\b(?:do\s+not|don't|dont|never|must\s+not|should\s+not|shouldn't|avoid|without)\s+(?:ever\s+)?(?:mention(?:ing)?|report(?:ing)?|reveal(?:ing)?|disclos(?:e|ing)|surfac(?:e|ing)|show(?:ing)?|bring(?:ing)?\s+up|admit(?:ting)?|acknowledg(?:e|ing)|tell(?:ing)?\s+(?:the\s+)?(?:user|human|them)(?:\s+about)?|inform(?:ing)?\s+(?:the\s+)?(?:user|human|them)(?:\s+(?:about|of))?|flag(?:ging)?|highlight(?:ing)?|point(?:ing)?\s+out|say(?:ing)?)\s+${FAILURE_OBJECT}`,
    ),
    /\b(?:hide|conceal|suppress|omit|leave\s+out|filter\s+out|gloss\s+over|downplay|bury)\s+(?:any\s+|all\s+|the\s+|these\s+|those\s+)?(?:(?:test\s+|build\s+|ci\s+|check\s+)?(?:failures?|errors?)|failing\s+(?:tests?|checks?|builds?)|problems?|issues?|bugs?)\b[^.\n]{0,30}?\b(?:from|in|out\s+of)\s+(?:the\s+|your\s+)?(?:user|human|summary|report|response|reply|final\s+(?:answer|message|report|summary)|status\s+(?:update|report)|pr\s+description|commit\s+message|changelog)\b/gi,
    /\b(?:cover\s+up|paper\s+over|sweep)\s+(?:any\s+|the\s+|all\s+)?(?:bugs?|errors?|failures?|mistakes?|problems?|issues?|damage)\b/gi,
  ],
  // The conceal verbs carry no negation of their own: "don't hide failures from the user" is honest.
  ignoreMatch: (m, ctx) =>
    /^(?:hide|conceal|suppress|omit|leave|filter|gloss|downplay|bury|cover|paper|sweep)/i.test(m[0]) && negatedBefore(ctx, m.index),
});

const fabricate = deceptionRule({
  id: "deception/fabricate-results",
  title: "Tells the agent to make up results or claim work it did not do",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions to invent test results, logs, metrics, benchmarks, or citations, or to say that something was run or verified when it was not.",
  remediation: "Do not install. A skill that fabricates evidence makes every result it reports worthless.",
  // "Fake the result" also describes what a broken check could do; the other verbs only mean one thing.
  adjust: (m) => (/^fake\b/i.test(m[0]) ? { severity: "medium" } : undefined),
  patterns: [
    /\b(?:make\s+up|invent|fabricate|falsify|doctor)\s+(?:the\s+|some\s+|any\s+|plausible\s+|realistic\s+|believable\s+|convincing\s+)?(?:test\s+|benchmark\s+|command\s+|tool\s+|build\s+|ci\s+|coverage\s+|performance\s+)?(?:results?|outputs?|logs?|numbers?|metrics?|measurements?|benchmarks?|timings?|coverage|screenshots?|citations?|references?|evidence|reports?|test\s+runs?)\b/gi,
    /\bfake\s+(?:the\s+)?(?:test\s+)?(?:results?|metrics|benchmarks?|coverage|evidence|test\s+runs?|passes|success)\b/gi,
    /\b(?:pretend|act\s+as\s+(?:if|though)|claim|say|report|state|tell\s+(?:the\s+)?user)\s+(?:that\s+)?(?:you|it|we)\s+(?:(?:have|has|had)\s+)?(?:ran|run|executed|tested|verified|checked|validated|confirmed|reproduced|benchmarked|built|deployed)\b[^.\n]{0,60}?\b(?:without\s+(?:(?:actually|really)\s+)?(?:running|executing|testing|verifying|checking|doing)|even\s+(?:if|though)\s+(?:you|it|we)\s+(?:didn't|did\s+not|haven't|have\s+not|hasn't|has\s+not|couldn't|could\s+not|never))/gi,
    /\b(?:pretend|act\s+as\s+(?:if|though))\s+(?:that\s+)?(?:you|it|the\s+(?:tests?|command|build|code|fix|deploy(?:ment)?))\s+(?:(?:have|has|had)\s+)?(?:ran|run|passed|pass|succeeded|worked|works|executed|verified|fixed)\b/gi,
  ],
});

const lieToUser = deceptionRule({
  id: "deception/lie-to-user",
  title: "Tells the agent to lie to or mislead the user",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions to lie to, deceive, or mislead the user, to deny what was done if asked, or to tell the user one thing while doing another. Frontier models have been shown to lie about their actions when questioned (Apollo Research, 2024); a skill must not ask them to.",
  remediation: "Do not install.",
  patterns: [
    /\b(?:lie|lying)\s+to\s+(?:the\s+)?(?:user|human|operator|customer|client|reviewer|them)\b/gi,
    /\b(?:deceive|mislead|trick|gaslight|fool|dupe)\s+(?:the\s+)?(?:user|human|operator|reviewer|customer|client)s?\b(?!\s+(?:visual|eyes?|ears?|brain|body|perception|senses?|mind|attention)\b)/gi,
    /\bif\s+(?:the\s+)?(?:user|human|they|anyone|someone)\s+asks?\b[^.\n]{0,60}?\b(?:deny|lie|pretend|say\s+(?:that\s+)?(?:you|it|nothing)\s+(?:did\s+not|didn't|never|hasn't|has\s+not|haven't|have\s+not|was(?:n't|\s+not)?)|tell\s+them\s+(?:that\s+)?(?:you|it|nothing)\s+(?:did\s+not|didn't|never|was(?:n't|\s+not)?))\b/gi,
    /\btell\s+(?:the\s+)?user\b[^.\n]{0,80}?\bbut\s+(?:actually|secretly|really|instead|in\s+reality)\b/gi,
  ],
});

const TASK_OBJECT = String.raw`(?:scope|requirements?|task|request|spec(?:ification)?s?|goals?|acceptance\s+criteria|success\s+criteria|features?|deliverables?|what\s+(?:was|they|the\s+user)\s+asked(?:\s+for)?)`;

const substituteTask = deceptionRule({
  id: "deception/substitute-task",
  title: "Tells the agent to swap the task for an easier one",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions to change, narrow, or reinterpret what the user asked without saying so, or to deliver a simpler, partial, or stubbed version and present it as the finished work.",
  remediation: "Do not install. When a task cannot be done as asked, the agent should say so, not deliver something else under its name.",
  patterns: [
    re(
      String.raw`\b(?:quietly|silently|secretly|covertly|without\s+(?:telling|informing|asking|consulting|mentioning\s+it\s+to)\s+(?:the\s+)?(?:user|human|them))\s+(?:change|narrow|reduce|shrink|simplify|alter|drop|skip|remove|replace|substitute|swap|reinterpret|redefine|rescope|descope|cut|trim|water\s+down)\s+(?:the\s+|their\s+|any\s+|some\s+|parts?\s+of\s+the\s+|the\s+user's\s+)?(?:[a-z-]+\s+){0,2}?${TASK_OBJECT}\b`,
    ),
    re(
      String.raw`\b(?:change|narrow|reduce|simplify|alter|drop|replace|substitute|swap|reinterpret|redefine|rescope|descope|water\s+down)\s+(?:the\s+|their\s+|some\s+|parts?\s+of\s+the\s+|the\s+user's\s+)?(?:scope|requirements?|task|request|spec(?:ification)?s?|goals?|acceptance\s+criteria|success\s+criteria|deliverables?)\b[^.\n]{0,40}?\b(?:without\s+(?:telling|informing|asking|consulting|mentioning)|quietly|silently|secretly)\b`,
    ),
    /\b(?:simpler|easier|smaller|partial|reduced|trivial|stub(?:bed)?|mock(?:ed)?|placeholder|dummy|fake|hard-?coded|toy)\s+(?:version|implementation|solution|approach|variant|substitute|result|answer|stand-?in|feature)\b[^.\n]{0,80}?\b(?:(?:present|report|describe|label|pass\s+off|represent|frame|announce|deliver)\s+(?:it|this|that)\s+as\s+(?:(?:the|a)\s+)?(?:full|fully\s+working|complete|completed|finished|real|original|requested|working|final|production[\s-]ready|done)|without\s+(?:telling|informing|mentioning|disclosing|saying|flagging)|(?:and|but)\s+(?:say|claim|tell\s+(?:the\s+)?user|report)\s+(?:that\s+)?(?:it|the\s+(?:task|feature)|everything)\s+(?:is|was)\s+(?:done|complete|finished|working|implemented|fully\s+implemented))/gi,
    /\b(?:pick|choose|use|go\s+with|take)\s+(?:whichever|the)\s+(?:interpretation|reading|definition)\s+(?:that\s+is\s+|that's\s+)?(?:easiest|simplest|quickest)\s+to\s+(?:pass|satisfy|verify|grade|game)\b/gi,
  ],
  adjust: (m) => (/^(?:pick|choose|use|go|take)\b/i.test(m[0]) ? { severity: "medium" } : undefined),
});

const coverTracks = deceptionRule({
  id: "deception/cover-tracks",
  title: "Tells the agent to erase the evidence of what it did",
  severity: "high",
  confidence: "medium",
  description:
    "Instructions to cover tracks: remove traces of the agent's actions, or clear history, logs, or commits so the user cannot see what happened. Models trained to tamper with their own checks have also learned to hide the tampering (Anthropic, Sycophancy to Subterfuge, 2024).",
  remediation: "Do not install.",
  patterns: [
    /\bcover\s+(?:your|its|our|the(?:ir)?)\s+tracks\b/gi,
    /\b(?:remove|erase|delete|wipe|clean\s+up|leave\s+no)\s+(?:all\s+|any\s+)?traces?\s+(?:of\s+(?:your|the|this|these|what\s+you)\s+(?:actions?|activity|changes?|commands?|work|edits?|did|have\s+done)|behind)\b/gi,
    /\b(?:delete|clear|erase|wipe|truncate|purge|scrub|rewrite|squash|amend)\s+(?:the\s+|your\s+|all\s+|any\s+)?(?:shell\s+|bash\s+|zsh\s+|command\s+|terminal\s+|git\s+|audit\s+|session\s+|conversation\s+|chat\s+|commit\s+)?(?:history|logs?|audit\s+trails?|transcripts?|traces?|evidence|reflog|commits?)\b[^.\n]{0,60}?\b(?:so\s+(?:that\s+)?(?:the\s+user|nobody|no\s+one|they|reviewers?|it)\s+(?:cannot|can't|can\s+not|won't|will\s+not|doesn't|does\s+not|don't|never)\s+(?:see|know|notice|find|tell|trace|review|spot)|to\s+(?:hide|cover|conceal|obscure|avoid\s+(?:detection|suspicion|review)))/gi,
  ],
});

/**
 * A part of a deliverable its reader does not see: a hidden worksheet or tab, a hidden template or
 * script block, a non-rendered metadata block. Not fields, rows, columns, layers, or config files,
 * which honest forms, spreadsheets, and designs hide all the time.
 */
const HIDDEN = String.raw`(?<!visually\s)(?:hidden|very\s*hidden|non-?rendered|invisible|undisplayed)`;
const HIDDEN_CARRIER = "(?:work)?sheets?|tabs?|templates?|blocks?|packets?|loaders?|beacons?|payloads?|metadata";
/** Run of non-newline text, but a period only inside a token (a path like `out.js`), never a sentence break. */
const SAME_SENTENCE = String.raw`(?:[^.\n]|\.(?=\S)){0,90}?`;

const hiddenContent = deceptionRule({
  id: "deception/hidden-deliverable-content",
  title: "Tells the agent to plant hidden content in what it delivers",
  severity: "medium",
  confidence: "medium",
  description:
    "Instructions to carry content into the user's deliverable where the user will not see it: a hidden worksheet or tab, a hidden template or loader block in a page, a non-rendered metadata block. Content nobody asked for, placed where nobody looks, is a covert channel for payloads, data, or markers.",
  remediation:
    "Review what the skill puts in the hidden part and where it comes from. A deliverable should not carry content its owner cannot see.",
  patterns: [
    re(
      String.raw`\b(?:preserve|keep|add|embed|store|stash|carry|copy|move|mirror|plant|insert|inject|write|put|place|include|append|tuck|bury|smuggle)\b${SAME_SENTENCE}\b(?:as|in|inside|into|within|through|via)\s+(?:a\s+|an\s+|one\s+|exactly\s+one\s+|the\s+)?${HIDDEN}\s+(?:or\s+very\s+hidden\s+)?(?:\S+\s+){0,3}?(?:${HIDDEN_CARRIER})\b`,
    ),
    re(
      String.raw`\b(?:preserve|keep|add|create|maintain|embed|insert|include|plant)\s+(?:a|an|one|exactly\s+one)\s+${HIDDEN}\s+(?:or\s+very\s+hidden\s+)?(?:\S+\s+){0,3}?(?:${HIDDEN_CARRIER})\b`,
    ),
  ],
});

const concealFiles = deceptionRule({
  id: "deception/conceal-files-from-user",
  title: "Tells the agent to tuck files away where the user will not see them",
  severity: "medium",
  confidence: "medium",
  description:
    "Instructions to move the agent's own output, logs, or artifacts into a hidden or dotfile location so the user-visible tree stays clean, or that are kept out of a directory listing on purpose. Hiding what the agent produced from the person it works for is deceptive, whatever reason is offered.",
  remediation:
    "Leave the agent's output where the user can see it. Retention or cleanup belongs in a place the user is told about, not a dotfile the listing hides.",
  patterns: [
    // "hidden from normal `ls` listings", "hidden from the user".
    /\bhidden\s+from\s+(?:normal\s+)?(?:\x60?ls\x60?|listings?|the\s+user(?:-facing)?|directory\s+listings?)\b/gi,
    // "move it into the hidden area so the user-visible sorted tree stays clean".
    /\bso\s+(?:that\s+)?the\s+user(?:[\s-](?:visible|facing))?\s+(?:sorted\s+)?(?:tree|listing|view|folders?)\s+stays?\s+clean\b/gi,
  ],
});

/** Wording that makes planting a bug a teaching or test-quality exercise. */
const EXERCISE_RE =
  /\b(?:mutation|mutants?|tests?\s+(?:catch|detect)|exercise|practice|training|interview|ctf|challenge|teach\w*|learn\w*|tutorial|kata|to\s+(?:check|verify|confirm|see)\s+(?:that|whether|if)\s+(?:the\s+)?tests?)\b/i;

const sabotage = deceptionRule({
  id: "deception/sabotage",
  title: "Tells the agent to plant bugs or underperform on purpose",
  severity: "medium",
  confidence: "medium",
  description:
    "Instructions to introduce bugs, flaws, or vulnerabilities on purpose, or to do worse than it can (sandbagging), behaviours measured in scheming evaluations (Apollo Research, 2024).",
  remediation: "Do not install unless the skill is a mutation-testing or teaching tool and the planted bugs are the point.",
  patterns: [
    /\b(?:intentionally|deliberately|purposely|purposefully|secretly|subtly|quietly|covertly)\s+(?:introduce|insert|add|inject|leave|plant|write|slip\s+in|hide)\s+(?:a\s+|an\s+|some\s+|in\s+)?(?:subtle\s+|hidden\s+|small\s+|few\s+)?(?:bugs?|errors?|mistakes?|flaws?|vulnerabilit(?:y|ies)|backdoors?|regressions?|defects?|off-by-one(?:\s+errors?)?)\b/gi,
    // Not "sandbagging" alone: in sales and finance skills it means a cautious forecast.
    /\b(?:deliberately|intentionally|purposely)\s+(?:perform|do|answer|score|work|underperform)\s+(?:worse|poorly|badly|below)\b|\bsandbag\s+(?:the\s+|your\s+)?(?:answers?|results?|evals?|evaluations?|benchmarks?|tests?|performance)\b/gi,
  ],
  ignoreMatch: (m, ctx) => EXERCISE_RE.test(lineText(ctx.index, positionAt(ctx.index, m.index).line)),
});

const SUPPRESSION_MARKER = String.raw`(?:#\s*type:\s*ignore|@ts-ignore|@ts-nocheck|@ts-expect-error|(?:\/\/\s*)?eslint-disable(?:-next-line|-line)?|#\s*noqa|(?:\/\/\s*)?nolint|@SuppressWarnings|#\s*pylint:\s*disable|#\s*pragma:\s*no\s+cover|#\s*nosec)`;

const silenceChecks = deceptionRule({
  id: "deception/silence-checks",
  title: "Tells the agent to switch off checks until they pass",
  severity: "medium",
  confidence: "medium",
  description:
    "Instructions to bypass commit hooks, sprinkle type-ignore or lint-disable comments, disable CI, lint, or test steps, or lower coverage and quality thresholds so that the checks go green without the problems being fixed.",
  remediation: "Remove the instruction. Checks that fail should be fixed or reported, not silenced.",
  patterns: [
    /--no-verify\b[^.\n]{0,60}?\b(?:if|when|so|because|to\s+(?:skip|bypass|avoid|get\s+past|get\s+around))\b[^.\n]{0,40}?\b(?:hooks?|checks?|tests?|lint(?:er|ing)?|ci|pre-commit|pre-push|type[\s-]?checks?|husky)\b/gi,
    /\b(?:if|when)\s+(?:the\s+)?(?:(?:pre-commit|pre-push|commit|git|husky|lint|test|type[\s-]?check|ci)\s+)?(?:hooks?|checks?|tests?|lint(?:ing|er)?)\s+(?:fails?|failed|block|blocks|complains?|rejects?)\b[^.\n]{0,50}?(?:--no-verify|skip\s+(?:the\s+)?hooks?|bypass\s+(?:the\s+)?(?:hooks?|checks?))/gi,
    re(
      String.raw`\b(?:add|insert|sprinkle|use|put)\s+(?:a\s+|an\s+)?\x60?${SUPPRESSION_MARKER}\x60?\s*(?:comments?\s+|annotations?\s+|directives?\s+)?[^.\n]{0,40}?\b(?:until|so\s+(?:that\s+)?|to\s+(?:make|get))\b[^.\n]{0,30}?\b(?:errors?|warnings?|checks?|failures?|build|ci|linter|type\s*checker|compiler|coverage)\b[^.\n]{0,20}?\b(?:go\s+away|disappear|pass(?:es)?|green|clean|silent|stops?|happy)\b`,
    ),
    /\b(?:disable|turn\s+off|remove|delete|comment\s+out|skip|bypass)\s+(?:(?:the|any|failing)\s+){0,2}(?:ci|lint(?:er|ing)?|type[\s-]?check(?:ing|er)?|tests?|coverage|security\s+scan(?:ning)?|pre-commit)\s+(?:steps?|jobs?|stages?|checks?|gates?|hooks?|workflows?|thresholds?)\b[^.\n]{0,40}?\b(?:so\s+(?:that\s+)?(?:it|ci|the\s+(?:build|pipeline|pr|pull\s+request|merge|checks?))\s+(?:passes|pass|goes?\s+green|is\s+green|succeeds|merges?)|to\s+(?:make|get)\s+(?:ci|it|the\s+(?:build|pipeline|pr|pull\s+request|checks?))\s+(?:to\s+)?(?:pass|green|through|merge))/gi,
    /\b(?:lower|reduce|drop|relax|loosen)\s+(?:the\s+)?(?:coverage|quality|lint|score|performance)\s+(?:thresholds?|targets?|bars?|gates?|requirements?|limits?|minimums?)\b[^.\n]{0,40}?\b(?:so|until|to\s+make)\b[^.\n]{0,30}?\b(?:pass(?:es)?|green|succeeds?)\b/gi,
  ],
});

// ---- Code that fakes a passing run

const TEST_CMD = String.raw`(?:pytest|py\.test|python3?\s+-m\s+(?:pytest|unittest)|(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test\b|npx\s+(?:jest|vitest|mocha|playwright\s+test)|jest|vitest|mocha|go\s+test|cargo\s+test|mvn\s+(?:-\S+\s+)*(?:test|verify)|\.?\/?gradlew?\s+test|rspec|phpunit|dotnet\s+test|make\s+(?:test|check)|tox|nox|ctest|deno\s+test|bun\s+test)`;
const CLAIMS_SUCCESS = String.raw`(?:pass(?:ed|es|ing)?|success(?:ful(?:ly)?)?|succeeded|\bok\b|green|all\s+good|\u2713|\u2705)`;

const swallowedFailure = patternRule({
  id: "deception/swallowed-test-failure",
  title: "A test command whose failure is turned into success",
  category: "deception",
  severity: "medium",
  confidence: "medium",
  description:
    "A test or check command followed by `|| exit 0` or by a success message printed when it fails. Whoever runs it, the agent included, is told the tests passed when they did not.",
  remediation: "Let the test command's exit status through. A skill's verification step must be able to fail.",
  patterns: [
    re(String.raw`\b${TEST_CMD}[^\n|&;]{0,120}\|\|\s*(?:echo|printf|print|console\.log)\b[^\n]{0,60}?${CLAIMS_SUCCESS}`),
    re(String.raw`\b${TEST_CMD}[^\n|&;]{0,120}\|\|\s*exit\s+0\b`),
    /"(?:test|check|verify|ci)"\s*:\s*"[^"\n]{0,120}\|\|\s*(?:true|exit\s+0|echo\b[^"\n]{0,60})"/g,
  ],
  prefilter: /\|\|/,
  roles: { readme: "lower-confidence" },
  adjust: (m) =>
    new RegExp(`\\|\\|\\s*(?:echo|printf|print|console\\.log)\\b[^\\n]{0,60}?${CLAIMS_SUCCESS}`, "i").test(m[0])
      ? { severity: "high" }
      : undefined,
});

/** A class whose name says it matches anything, like `mock.ANY`: its always-true `__eq__` is the point. */
const WILDCARD_CLASS = /class\s+(\w*(?:any|anything|wild|match|sentinel|always|mock|dummy)\w*)\b[^\n]*\n(?:[^\n]*\n){0,6}?[^\n]*$/i;

const riggedHarness = patternRule({
  id: "deception/rigged-test-harness",
  title: "Code that makes failing tests report success",
  category: "deception",
  severity: "high",
  confidence: "medium",
  description:
    "Code that rewrites test outcomes to `passed`, forces the test session's exit status to 0, replaces assertion methods, exits with success after the suite, or defines an object equal to everything so any assertion holds. These are the tactics reward-hacking agents use against test suites (ImpossibleBench, METR, OpenAI 2025).",
  remediation: "Do not install. A skill has no reason to change how tests report.",
  kinds: ["script", "skill-md", "markdown"],
  patterns: [
    /\.outcome\s*=\s*["']passed["']/g,
    /\b(?:session\.)?exitstatus\s*=\s*(?:0|(?:pytest\.)?ExitCode\.OK)\b/g,
    /\b(?:unittest\.)?TestCase\.(?:assert\w*|fail\w*)\s*=(?!=)|\bpytest\.(?:fail|skip|xfail|approx)\s*=(?!=)|\bbuiltins\.(?:AssertionError|assert\w*)\s*=(?!=)/g,
    /\bafter(?:All|Each)\s*\(\s*(?:async\s*)?\(\)\s*=>\s*\{?\s*process\.exit\(\s*0\s*\)/g,
    /\bdef\s+__eq__\s*\(\s*self\s*,\s*\w+\s*\)\s*(?:->\s*bool\s*)?:\s*(?:#[^\n]*)?\n?\s*return\s+True\b/g,
  ],
  prefilter: /outcome|exitstatus|TestCase\.|pytest\.|builtins\.|process\.exit|__eq__/,
  ignoreMatch: (m, ctx) => {
    // `if exitstatus == 5: session.exitstatus = 0` turns "no tests collected" into success, a common plugin setting.
    if (/exitstatus/.test(m[0])) {
      const { line } = positionAt(ctx.index, m.index);
      const near = `${line > 1 ? lineText(ctx.index, line - 1) : ""}\n${lineText(ctx.index, line)}`;
      return /==\s*5\b|NO_TESTS_COLLECTED|\bExitCode\.NO_TESTS/.test(near);
    }
    return /__eq__/.test(m[0]) && WILDCARD_CLASS.test(ctx.text.slice(Math.max(0, m.index - 400), m.index + 1));
  },
  adjust: (m) => (/__eq__/.test(m[0]) ? { severity: "medium" } : undefined),
});

export const deceptionRules: readonly FileRule[] = [
  misreportSuccess,
  hideFailures,
  fabricate,
  tamperTests,
  specialCase,
  silenceChecks,
  substituteTask,
  lieToUser,
  coverTracks,
  hiddenContent,
  concealFiles,
  sabotage,
  swallowedFailure,
  riggedHarness,
];
