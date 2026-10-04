# Benchmark

What each configuration of skill-scanner catches, what it wrongly flags, and what it costs, measured on the same labeled skills: the static rules alone, with TypeSafe's jev judge, the judge alone, each external tool alone and on top of the rules, and their combinations. The rules and the judge's questions were then tuned on part of the data, and every headline number below is on the part tuning never read.

![skill-scanner with jev catches 79% of malicious agent skills: the key numbers, and how it compares with skill-scanner alone and with other scanners](./benchmark-summary.png)

## What to run

skill-scanner's defaults are the two configurations at the top: the rules and gitleaks always, and jev as soon as its API key is set.

- **With jev (rules + gitleaks + jev), the default once jev has an API key.** On skills tuning never read it flags 79% of the malicious ones (50% for the rules and the judge before tuning, at the same 96,000-character budget) and wrongly flags 10.1% of the benign ones, fewer than without jev (10.7%). It blocks what the rules block, less three malicious skills the judge's doubts moved to a warning, and wrongly blocks 3 benign skills in 851. It takes 0.65 s a skill and costs $0.28 per 1,000 skills.
- **Without jev (rules + gitleaks), the default out of the box.** It flags 42% and blocks a third (32.8%) of malicious skills, with the same 3 false blocks, offline, in 0.17 s a skill.
- **jev alone** is the most precise reader: it flags 71% of malicious skills with 0.6% of benign skills flagged. It never blocks on its own.
- **The external tools** catch more but flag too much to gate on. SkillSpector alone catches 77% and flags 46% of benign skills; with the rules, 84% and 49%. Cisco's scanner alone catches 41% at 10%. Each takes about 2 s a skill. gitleaks alone catches 2%: these skills do not attack through leaked secrets, and gitleaks is in the defaults for the secrets it does find, not for detection.

![Malicious skills caught, per approach](./benchmark-caught.png)

![Harmless skills wrongly flagged, per approach](./benchmark-false-alarms.png)

![Time and money to scan 1,000 skills, per approach](./benchmark-cost.png)

## Setup

**Configurations.** A row's name says what runs. `static` is skill-scanner's rules; `jev` is the rules with the judge reviewing them; `jev-only` is the judge's own findings without the rules; `<tool>-only` is a tool's own findings without the rules; `<tool>` is the rules plus the tool.

| Configuration | What runs | Network | How it is measured |
|---|---|---|---|
| `static` | the rules | no | run |
| `jev+gitleaks` | the rules, gitleaks, and jev: the default with jev | yes (the judge) | run |
| `gitleaks` | the rules and gitleaks: the default without jev | no | derived from gitleaks' own findings |
| `jev` | the rules and the judge | yes (the judge) | run |
| `jev-only` | the judge's own `judge/*` findings | yes | derived from `jev`: the judge adds them whatever the rules found |
| `skillspector-only`, `cisco-only`, `gitleaks-only` | one tool | no | derived from a "rules + tool" run: the tool's `external/<tool>` findings |
| `skillspector`, `cisco`, `gitleaks` | the rules and one tool | no | derived: the worse of the rules' and the tool's verdicts |
| `skillspector+gitleaks`, `all-offline` | the rules and several tools | no | derived the same way |

Derivations are exact because a verdict is the worst finding and the engine never lets one rule's finding hide another's. Each was checked: rebuilding the static arm from the "rules + tool" runs disagrees with the measured static arm on 0 of 2,767 bundles, and the three-tool union disagreed with a measured three-tool run on 0 of 634. The tools ran once, before the rules changed; their own findings do not depend on the rules, so "rules + tool" is rebuilt from the tool alone and the final rules. osv-scanner and semgrep call the network once per skill and ran only on a reduced set (525 malicious, 107 benign): alone they caught 1.5% and 7.6% of malicious skills.

**Corpora.** Benign: 20 vendor and community repositories ([evaluation.md](./evaluation.md)), Cisco's "safe" evaluation skills, and skill-scanner's own benign sample, 2,240 skill bundles. Malicious: MaliciousSkillBench sources SRC002, SRC004, SRC005, SRC006, SRC008, SRC011 and SRC013 (every package labelled malicious by its authors), Trail of Bits' overtly malicious skills, Snyk's ToxicSkills, the skills-scanner-bypass sample, Cisco's malicious test skills, and skill-scanner's own samples, 527 bundles. Each skill directory is scanned alone, the way a user installs one; a package's root bundle (README, CI files) is not scored. An earlier version of this page counted skill-scanner's benign sample as malicious; it is corrected everywhere.

**Splits** (`src/benchmark/split.ts`). Seven whole corpora are held out: the MaliciousSkillBench sources SRC004 and SRC006, Cisco's, Snyk's, Trail of Bits' and the bypass sample, and the benign repositories of Microsoft, Trail of Bits, OpenAI, Sentry, Hugging Face, HashiCorp and Cloudflare. Every other skill falls by a hash of its directory: half training, a quarter validation, a quarter test.

| Split | Malicious | Benign | Used for |
|---|---:|---:|---|
| training | 184 | 922 | reading failures and proposing changes |
| validation | 93 | 467 | keeping a change only if it beats the current best |
| test | 97 | 423 | the result, read once at the end |
| held-out corpora | 153 | 428 | the result on attack families and repositories tuning never saw |

Four held-out bundles were read before the split was fixed, while looking at what the rules miss; they count as training. The static rules were written, long before this, against all of the benign repositories ([evaluation.md](./evaluation.md)), so their false-flag rate on held-out benign repositories is not a fresh measurement; the judge's is.

**Scoring.** A malicious skill is caught when the verdict reaches the threshold; a benign one is wrongly flagged the same way. Two thresholds, because they gate different things: *blocked* is what the hooks deny outright, *flagged* is blocked or warned, what the interactive prompts ask about.

**Cost.** Time per skill comes from a separate run: every main configuration one after another on the same random sample of 200 unseen skill directories (285 skill bundles), in one 16-core Linux container (the e2e image) from the packed npm package, with nothing else running, so the times compare. A configuration not timed there is derived as its verdicts are: a tool alone is "rules + tool" minus the rules, a combination adds its parts. The full runs' wall times are in the tables too; they shared the machine with other runs, and count a few skills twice (some repositories were also scanned whole). The judge's cost is the input tokens TypeSafe reported, at its list price of $0.042 per million; output is free.

## Results on skills tuning never read

The test split and the held-out corpora: 250 malicious and 851 benign skills, with the released rules and judge. The same configurations before tuning are compared split by split under [Tuning](#tuning).

![Every configuration: malicious skills caught, benign skills wrongly flagged, and time and cost per skill](./benchmark.png)

![Malicious skills caught against benign skills wrongly flagged, and time and money for 1,000 skills](./benchmark-tradeoff.png)

<!-- benchmark:summary-block -->
### released configurations: 250 malicious and 851 benign bundles

#### Detection at the block threshold

A bundle counts as detected when its verdict is `block` (what the hooks deny).

| Configuration | TP | FP | FN | TN | Precision | Recall | Specificity | F1 | Balanced acc. |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| jev+gitleaks | 79 | 3 | 171 | 848 | 96.3% | 31.6% | 99.6% | 47.6% | 65.6% |
| gitleaks (derived) | 82 | 3 | 168 | 848 | 96.5% | 32.8% | 99.6% | 49.0% | 66.2% |
| static | 82 | 3 | 168 | 848 | 96.5% | 32.8% | 99.6% | 49.0% | 66.2% |
| jev | 79 | 3 | 171 | 848 | 96.3% | 31.6% | 99.6% | 47.6% | 65.6% |
| jev-only (derived) | 0 | 0 | 250 | 851 | 0.0% | 0.0% | 100.0% | 0.0% | 50.0% |
| skillspector-only | 124 | 265 | 126 | 586 | 31.9% | 49.6% | 68.9% | 38.8% | 59.2% |
| cisco-only | 78 | 55 | 172 | 796 | 58.6% | 31.2% | 93.5% | 40.7% | 62.4% |
| gitleaks-only | 0 | 0 | 250 | 851 | 0.0% | 0.0% | 100.0% | 0.0% | 50.0% |
| skillspector (derived) | 146 | 265 | 104 | 586 | 35.5% | 58.4% | 68.9% | 44.2% | 63.6% |
| cisco (derived) | 109 | 55 | 141 | 796 | 66.5% | 43.6% | 93.5% | 52.7% | 68.6% |
| skillspector+gitleaks (derived) | 146 | 265 | 104 | 586 | 35.5% | 58.4% | 68.9% | 44.2% | 63.6% |
| all-offline (derived) | 155 | 276 | 95 | 575 | 36.0% | 62.0% | 67.6% | 45.5% | 64.8% |

#### Detection at the warn threshold

A bundle counts as detected when its verdict is `warn` or `block` (what `--fail-on warn` and the interactive prompts act on).

| Configuration | TP | FP | FN | TN | Precision | Recall | Specificity | F1 | Balanced acc. |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| jev+gitleaks | 198 | 86 | 52 | 765 | 69.7% | 79.2% | 89.9% | 74.2% | 84.5% |
| gitleaks (derived) | 105 | 91 | 145 | 760 | 53.6% | 42.0% | 89.3% | 47.1% | 65.7% |
| static | 100 | 90 | 150 | 761 | 52.6% | 40.0% | 89.4% | 45.5% | 64.7% |
| jev | 196 | 87 | 54 | 764 | 69.3% | 78.4% | 89.8% | 73.5% | 84.1% |
| jev-only (derived) | 178 | 5 | 72 | 846 | 97.3% | 71.2% | 99.4% | 82.2% | 85.3% |
| skillspector-only | 193 | 392 | 57 | 459 | 33.0% | 77.2% | 53.9% | 46.2% | 65.6% |
| cisco-only | 103 | 88 | 147 | 763 | 53.9% | 41.2% | 89.7% | 46.7% | 65.4% |
| gitleaks-only | 6 | 3 | 244 | 848 | 66.7% | 2.4% | 99.6% | 4.6% | 51.0% |
| skillspector (derived) | 209 | 414 | 41 | 437 | 33.5% | 83.6% | 51.4% | 47.9% | 67.5% |
| cisco (derived) | 134 | 145 | 116 | 706 | 48.0% | 53.6% | 83.0% | 50.7% | 68.3% |
| skillspector+gitleaks (derived) | 209 | 414 | 41 | 437 | 33.5% | 83.6% | 51.4% | 47.9% | 67.5% |
| all-offline (derived) | 214 | 422 | 36 | 429 | 33.6% | 85.6% | 50.4% | 48.3% | 68.0% |

#### Cost and time

| Configuration | Bundles | Wall time | Per bundle | Judge input tokens | Judge cost | Cost per 1,000 bundles |
|---|---:|---:|---:|---:|---:|---:|
| jev+gitleaks | 1,101 | 1265.5 s | 648 ms | 7,285,204 | $0.3060 | $0.278 |
| gitleaks (derived) | 1,101 | 275.2 s | 168 ms | 0 | $0 | $0 |
| static | 1,101 | 22.9 s | 18 ms | 0 | $0 | $0 |
| jev | 1,101 | 396.9 s | 558 ms | 7,285,204 | $0.3060 | $0.278 |
| jev-only (derived) | 1,101 | 374.0 s | 541 ms | 7,285,204 | $0.3060 | $0.278 |
| skillspector-only | 1,101 | 3527.6 s | 2.3 s | 0 | $0 | $0 |
| cisco-only | 1,101 | 3428.0 s | 2.1 s | 0 | $0 | $0 |
| gitleaks-only | 1,101 | 252.3 s | 151 ms | 0 | $0 | $0 |
| skillspector (derived) | 1,101 | 3550.5 s | 2.3 s | 0 | $0 | $0 |
| cisco (derived) | 1,101 | 3450.9 s | 2.1 s | 0 | $0 | $0 |
| skillspector+gitleaks (derived) | 1,101 | 3802.8 s | 2.4 s | 0 | $0 | $0 |
| all-offline (derived) | 1,101 | 7230.9 s | 4.5 s | 0 | $0 | $0 |

Per-bundle time: from a separate run of every configuration, one after another on the same 285 skill bundles (a random sample of the skills the tables are on) with nothing else running, so the times compare; a tool alone is "rules + tool" minus the rules, a combination adds its parts. Wall time is the full run's, which shared the machine.

#### Per corpus, at the block threshold

| Corpus | Label | Bundles | jev+gitleaks | gitleaks (derived) | static | jev | jev-only (derived) | skillspector-only | cisco-only | gitleaks-only | skillspector (derived) | cisco (derived) | skillspector+gitleaks (derived) | all-offline (derived) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign/ComposioHQ__awesome-claude-skills | benign | 207 | 0/207 flagged | 0/207 flagged | 0/207 flagged | 0/207 flagged | 0/207 flagged | 5/207 flagged | 1/207 flagged | 0/207 flagged | 5/207 flagged | 1/207 flagged | 5/207 flagged | 5/207 flagged |
| benign/K-Dense-AI__claude-scientific-skills | benign | 32 | 0/32 flagged | 0/32 flagged | 0/32 flagged | 0/32 flagged | 0/32 flagged | 18/32 flagged | 3/32 flagged | 0/32 flagged | 18/32 flagged | 3/32 flagged | 18/32 flagged | 19/32 flagged |
| benign/alirezarezvani__claude-skills | benign | 72 | 1/72 flagged | 1/72 flagged | 1/72 flagged | 1/72 flagged | 0/72 flagged | 27/72 flagged | 7/72 flagged | 0/72 flagged | 27/72 flagged | 7/72 flagged | 27/72 flagged | 29/72 flagged |
| benign/anthropics__claude-plugins-official | benign | 8 | 0/8 flagged | 0/8 flagged | 0/8 flagged | 0/8 flagged | 0/8 flagged | 6/8 flagged | 1/8 flagged | 0/8 flagged | 6/8 flagged | 1/8 flagged | 6/8 flagged | 6/8 flagged |
| benign/anthropics__skills | benign | 5 | 0/5 flagged | 0/5 flagged | 0/5 flagged | 0/5 flagged | 0/5 flagged | 3/5 flagged | 2/5 flagged | 0/5 flagged | 3/5 flagged | 2/5 flagged | 3/5 flagged | 3/5 flagged |
| benign/better-auth__skills | benign | 2 | 0/2 flagged | 0/2 flagged | 0/2 flagged | 0/2 flagged | 0/2 flagged | 1/2 flagged | 0/2 flagged | 0/2 flagged | 1/2 flagged | 0/2 flagged | 1/2 flagged | 1/2 flagged |
| benign/callstackincubator__agent-skills | benign | 1 | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged |
| benign/cloudflare__skills | benign | 15 | 0/15 flagged | 0/15 flagged | 0/15 flagged | 0/15 flagged | 0/15 flagged | 6/15 flagged | 0/15 flagged | 0/15 flagged | 6/15 flagged | 0/15 flagged | 6/15 flagged | 6/15 flagged |
| benign/datadog-labs__agent-skills | benign | 11 | 0/11 flagged | 0/11 flagged | 0/11 flagged | 0/11 flagged | 0/11 flagged | 3/11 flagged | 2/11 flagged | 0/11 flagged | 3/11 flagged | 2/11 flagged | 3/11 flagged | 4/11 flagged |
| benign/expo__skills | benign | 9 | 0/9 flagged | 0/9 flagged | 0/9 flagged | 0/9 flagged | 0/9 flagged | 1/9 flagged | 1/9 flagged | 0/9 flagged | 1/9 flagged | 1/9 flagged | 1/9 flagged | 2/9 flagged |
| benign/getsentry__skills | benign | 29 | 1/29 flagged | 1/29 flagged | 1/29 flagged | 1/29 flagged | 0/29 flagged | 10/29 flagged | 6/29 flagged | 0/29 flagged | 10/29 flagged | 6/29 flagged | 10/29 flagged | 11/29 flagged |
| benign/google-gemini__gemini-skills | benign | 2 | 0/2 flagged | 0/2 flagged | 0/2 flagged | 0/2 flagged | 0/2 flagged | 1/2 flagged | 0/2 flagged | 0/2 flagged | 1/2 flagged | 0/2 flagged | 1/2 flagged | 1/2 flagged |
| benign/hashicorp__agent-skills | benign | 21 | 0/21 flagged | 0/21 flagged | 0/21 flagged | 0/21 flagged | 0/21 flagged | 3/21 flagged | 0/21 flagged | 0/21 flagged | 3/21 flagged | 0/21 flagged | 3/21 flagged | 3/21 flagged |
| benign/huggingface__skills | benign | 27 | 0/27 flagged | 0/27 flagged | 0/27 flagged | 0/27 flagged | 0/27 flagged | 15/27 flagged | 3/27 flagged | 0/27 flagged | 15/27 flagged | 3/27 flagged | 15/27 flagged | 15/27 flagged |
| benign/mattpocock__skills | benign | 13 | 0/13 flagged | 0/13 flagged | 0/13 flagged | 0/13 flagged | 0/13 flagged | 2/13 flagged | 0/13 flagged | 0/13 flagged | 2/13 flagged | 0/13 flagged | 2/13 flagged | 2/13 flagged |
| benign/microsoft__skills | benign | 206 | 0/206 flagged | 0/206 flagged | 0/206 flagged | 0/206 flagged | 0/206 flagged | 70/206 flagged | 10/206 flagged | 0/206 flagged | 70/206 flagged | 10/206 flagged | 70/206 flagged | 73/206 flagged |
| benign/neondatabase__agent-skills | benign | 3 | 0/3 flagged | 0/3 flagged | 0/3 flagged | 0/3 flagged | 0/3 flagged | 2/3 flagged | 0/3 flagged | 0/3 flagged | 2/3 flagged | 0/3 flagged | 2/3 flagged | 2/3 flagged |
| benign/obra__superpowers | benign | 3 | 0/3 flagged | 0/3 flagged | 0/3 flagged | 0/3 flagged | 0/3 flagged | 2/3 flagged | 0/3 flagged | 0/3 flagged | 2/3 flagged | 0/3 flagged | 2/3 flagged | 2/3 flagged |
| benign/openai__skills | benign | 44 | 0/44 flagged | 0/44 flagged | 0/44 flagged | 0/44 flagged | 0/44 flagged | 28/44 flagged | 4/44 flagged | 0/44 flagged | 28/44 flagged | 4/44 flagged | 28/44 flagged | 29/44 flagged |
| benign/remotion-dev__skills | benign | 3 | 0/3 flagged | 0/3 flagged | 0/3 flagged | 0/3 flagged | 0/3 flagged | 2/3 flagged | 0/3 flagged | 0/3 flagged | 2/3 flagged | 0/3 flagged | 2/3 flagged | 2/3 flagged |
| benign/trailofbits__skills | benign | 86 | 1/86 flagged | 1/86 flagged | 1/86 flagged | 1/86 flagged | 0/86 flagged | 45/86 flagged | 11/86 flagged | 0/86 flagged | 45/86 flagged | 11/86 flagged | 45/86 flagged | 45/86 flagged |
| benign/vercel-labs__agent-skills | benign | 2 | 0/2 flagged | 0/2 flagged | 0/2 flagged | 0/2 flagged | 0/2 flagged | 2/2 flagged | 1/2 flagged | 0/2 flagged | 2/2 flagged | 1/2 flagged | 2/2 flagged | 2/2 flagged |
| benign/wshobson__agents | benign | 49 | 0/49 flagged | 0/49 flagged | 0/49 flagged | 0/49 flagged | 0/49 flagged | 13/49 flagged | 3/49 flagged | 0/49 flagged | 13/49 flagged | 3/49 flagged | 13/49 flagged | 14/49 flagged |
| benign/cisco-test-safe | benign | 1 | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged | 0/1 flagged |
| malicious/trailofbits-overtly | malicious | 4 | 4/4 (100.0%) | 4/4 (100.0%) | 4/4 (100.0%) | 4/4 (100.0%) | 0/4 (0.0%) | 3/4 (75.0%) | 2/4 (50.0%) | 0/4 (0.0%) | 4/4 (100.0%) | 4/4 (100.0%) | 4/4 (100.0%) | 4/4 (100.0%) |
| malicious/snyk-toxicskills | malicious | 9 | 7/9 (77.8%) | 7/9 (77.8%) | 7/9 (77.8%) | 7/9 (77.8%) | 0/9 (0.0%) | 5/9 (55.6%) | 4/9 (44.4%) | 0/9 (0.0%) | 8/9 (88.9%) | 8/9 (88.9%) | 8/9 (88.9%) | 8/9 (88.9%) |
| malicious/nedlir-bypass | malicious | 1 | 1/1 (100.0%) | 1/1 (100.0%) | 1/1 (100.0%) | 1/1 (100.0%) | 0/1 (0.0%) | 1/1 (100.0%) | 1/1 (100.0%) | 0/1 (0.0%) | 1/1 (100.0%) | 1/1 (100.0%) | 1/1 (100.0%) | 1/1 (100.0%) |
| malicious/cisco-test-malicious | malicious | 7 | 4/7 (57.1%) | 4/7 (57.1%) | 4/7 (57.1%) | 4/7 (57.1%) | 0/7 (0.0%) | 4/7 (57.1%) | 4/7 (57.1%) | 0/7 (0.0%) | 6/7 (85.7%) | 6/7 (85.7%) | 6/7 (85.7%) | 6/7 (85.7%) |
| malicious/samples | malicious | 2 | 2/2 (100.0%) | 2/2 (100.0%) | 2/2 (100.0%) | 2/2 (100.0%) | 0/2 (0.0%) | 1/2 (50.0%) | 1/2 (50.0%) | 0/2 (0.0%) | 2/2 (100.0%) | 2/2 (100.0%) | 2/2 (100.0%) | 2/2 (100.0%) |
| malicious/msb-SRC002 | malicious | 45 | 28/45 (62.2%) | 28/45 (62.2%) | 28/45 (62.2%) | 28/45 (62.2%) | 0/45 (0.0%) | 35/45 (77.8%) | 29/45 (64.4%) | 0/45 (0.0%) | 36/45 (80.0%) | 32/45 (71.1%) | 36/45 (80.0%) | 36/45 (80.0%) |
| malicious/msb-SRC004 | malicious | 48 | 15/48 (31.3%) | 17/48 (35.4%) | 17/48 (35.4%) | 15/48 (31.3%) | 0/48 (0.0%) | 24/48 (50.0%) | 15/48 (31.3%) | 0/48 (0.0%) | 29/48 (60.4%) | 22/48 (45.8%) | 29/48 (60.4%) | 32/48 (66.7%) |
| malicious/msb-SRC005 | malicious | 6 | 5/6 (83.3%) | 6/6 (100.0%) | 6/6 (100.0%) | 5/6 (83.3%) | 0/6 (0.0%) | 3/6 (50.0%) | 2/6 (33.3%) | 0/6 (0.0%) | 6/6 (100.0%) | 6/6 (100.0%) | 6/6 (100.0%) | 6/6 (100.0%) |
| malicious/msb-SRC006 | malicious | 84 | 6/84 (7.1%) | 6/84 (7.1%) | 6/84 (7.1%) | 6/84 (7.1%) | 0/84 (0.0%) | 37/84 (44.0%) | 13/84 (15.5%) | 0/84 (0.0%) | 40/84 (47.6%) | 17/84 (20.2%) | 40/84 (47.6%) | 43/84 (51.2%) |
| malicious/msb-SRC011 | malicious | 8 | 7/8 (87.5%) | 7/8 (87.5%) | 7/8 (87.5%) | 7/8 (87.5%) | 0/8 (0.0%) | 5/8 (62.5%) | 3/8 (37.5%) | 0/8 (0.0%) | 8/8 (100.0%) | 7/8 (87.5%) | 8/8 (100.0%) | 8/8 (100.0%) |
| malicious/msb-SRC013 | malicious | 36 | 0/36 (0.0%) | 0/36 (0.0%) | 0/36 (0.0%) | 0/36 (0.0%) | 0/36 (0.0%) | 6/36 (16.7%) | 4/36 (11.1%) | 0/36 (0.0%) | 6/36 (16.7%) | 4/36 (11.1%) | 6/36 (16.7%) | 9/36 (25.0%) |

#### What each addition changed

Verdict moves on the same bundles, relative to `static`. A bundle is flagged when its verdict is warn or block.

| Configuration | Malicious: pass -> flagged | Malicious: flagged -> pass | Benign: pass -> flagged | Benign: flagged -> pass |
|---|---:|---:|---:|---:|
| jev+gitleaks | 98 | 0 | 2 | 6 |
| gitleaks (derived) | 5 | 0 | 1 | 0 |
| jev | 96 | 0 | 3 | 6 |
| jev-only (derived) | 96 | 18 | 3 | 88 |
| skillspector-only | 109 | 16 | 324 | 22 |
| cisco-only | 34 | 31 | 55 | 57 |
| gitleaks-only | 5 | 99 | 1 | 88 |
| skillspector (derived) | 109 | 0 | 324 | 0 |
| cisco (derived) | 34 | 0 | 55 | 0 |
| skillspector+gitleaks (derived) | 109 | 0 | 324 | 0 |
| all-offline (derived) | 114 | 0 | 332 | 0 |

#### Analyzer and judge status

- jev+gitleaks / gitleaks: ran 1,101
- jev+gitleaks / jev: ran 998, skipped 102, failed 1
- gitleaks (derived) / gitleaks: ran 1,101
- jev / jev: ran 998, skipped 102, failed 1
- jev-only (derived) / jev: ran 998, skipped 102, failed 1
- skillspector-only / skillspector: ran 1,097, failed 4
- cisco-only / cisco: ran 1,101
- gitleaks-only / gitleaks: ran 1,101
- skillspector (derived) / skillspector: ran 1,097, failed 4
- cisco (derived) / cisco: ran 1,101
- skillspector+gitleaks (derived) / skillspector: ran 1,097, failed 4
- skillspector+gitleaks (derived) / gitleaks: ran 1,101
- all-offline (derived) / skillspector: ran 1,097, failed 4
- all-offline (derived) / cisco: ran 1,101
- all-offline (derived) / gitleaks: ran 1,101

#### Derived combinations

- skillspector (derived): the worse of the static arm's and skillspector-only's verdicts per bundle; skillspector was run before the rules changed
- cisco (derived): the worse of the static arm's and cisco-only's verdicts per bundle; cisco was run before the rules changed
- gitleaks (derived): the worse of the static arm's and gitleaks-only's verdicts per bundle; gitleaks was run before the rules changed
- jev-only (derived): the judge's own `judge/*` findings in the static + jev arm, without the static rules
- all-offline (derived): the worst verdict of skillspector, cisco, gitleaks per bundle; not run as one arm
- skillspector+gitleaks (derived): the worst verdict of skillspector, gitleaks per bundle; not run as one arm

<!-- /benchmark:summary-block -->




## Tuning

Both the rules and the judge's questions were tuned the way [skill-factory](https://github.com/FrancoisChastel/skill-factory) tunes a skill: read the training split's failures, propose a general change, score it, and keep it only if it beats the current best on validation. Test and held-out skills were scored once, after both were frozen. Every judge number here is at the 96,000-character budget, before and after alike, so the comparison isolates the questions: at that budget the released questions caught 27% of unseen malicious skills at 2.4% false flags, against 71% at 0.6% after.

![skill-factory's loop took jev from 29% to 81% of malicious skills caught on validation; the rules moved from 55% to 57%](./benchmark-evolution.png)

![Before and after tuning, on each split](./benchmark-tuning.png)

<!-- benchmark:tuning -->
| Configuration | Split | Malicious flagged | Malicious blocked | Benign flagged | Benign blocked |
|---|---|---:|---:|---:|---:|
| static rules | training (184 / 922) | 44.0% -> **50.0%** | 36.4% -> **36.4%** | 8.6% -> **8.6%** | 0.1% -> **0.1%** |
| static rules | validation (93 / 467) | 54.8% -> **57.0%** | 49.5% -> **49.5%** | 8.1% -> **8.1%** | 0.2% -> **0.2%** |
| static rules | test (97 / 423) | 51.5% -> **52.6%** | 44.3% -> **44.3%** | 6.6% -> **6.6%** | 0.2% -> **0.2%** |
| static rules | held-out corpora (153 / 428) | 32.0% -> **32.0%** | 25.5% -> **25.5%** | 14.5% -> **14.5%** | 0.5% -> **0.5%** |
| jev alone | training (184 / 922) | 19.0% -> **77.7%** | 0.0% -> **0.0%** | 1.5% -> **0.4%** | 0.0% -> **0.0%** |
| jev alone | validation (93 / 467) | 29.0% -> **80.6%** | 0.0% -> **0.0%** | 1.3% -> **0.4%** | 0.0% -> **0.0%** |
| jev alone | test (97 / 423) | 21.6% -> **73.2%** | 0.0% -> **0.0%** | 2.1% -> **0.5%** | 0.0% -> **0.0%** |
| jev alone | held-out corpora (153 / 428) | 30.7% -> **69.9%** | 0.0% -> **0.0%** | 2.6% -> **0.7%** | 0.0% -> **0.0%** |
| static rules + jev | training (184 / 922) | 48.9% -> **85.3%** | 37.0% -> **36.4%** | 8.9% -> **8.2%** | 0.2% -> **0.1%** |
| static rules + jev | validation (93 / 467) | 62.4% -> **87.1%** | 49.5% -> **49.5%** | 8.8% -> **7.9%** | 0.4% -> **0.2%** |
| static rules + jev | test (97 / 423) | 52.6% -> **80.4%** | 43.3% -> **43.3%** | 8.7% -> **6.9%** | 0.2% -> **0.2%** |
| static rules + jev | held-out corpora (153 / 428) | 47.7% -> **77.1%** | 24.2% -> **24.2%** | 15.7% -> **13.6%** | 0.5% -> **0.5%** |
<!-- /benchmark:tuning -->

The judge's gains hold on skills it never saw: jev alone goes from about a quarter to about three quarters of malicious skills on every split, and its false flags fall. The rules' gains do not carry: two new rules caught 11 more training skills and 2 more validation skills, but one more test skill and no held-out one.

### The judge

`scripts/judge-lab.ts` asks jev any set of questions about every skill of a split, with the exact text the scanner sends, and caches each answer, so a question set can be rescored offline; `scripts/judge-lab-score.ts` replays the judge's rules on the cached answers. Tuning took 30 million input tokens, $1.27 at list price.

All rounds are scored at the 96,000-character budget the released judge uses (`scripts/benchmark-rounds.json`).

| Round | What changed | Why | jev alone, training | jev alone, validation |
|---|---|---|---|---|
| 0 | the eight capability probes, four of them adding a finding at P >= 0.85 | the released judge | 19.0% at 1.5% false flags | 29.0% at 1.3% |
| 1 | fifteen intent questions, each under two framings; the best pair kept | the training misses were skills that steer the agent to a planted file, claim another skill is deprecated, or game a grader: intent, not capability | 70.7% at 1.0% | 73.1% at 1.3% |
| 2 | an ensemble of five intent questions and a fake-prerequisite question; the budget raised from 24,000 characters | single questions were fragile at their low thresholds; 26 of the remaining training misses had been too long to send; the rest were "install this tool from a vercel.app link first" | 78.8% at 0.3% | 79.6% at 0.6% |
| released | round 2, measured in the packed package | | 77.7% at 0.4% | 80.6% at 0.4% |

Each question's separation, scored at the 96,000-character budget (AUC; recall at a 1% false-flag threshold chosen on training):

| Question | Training AUC | Validation AUC | Validation recall at 1% |
|---|---:|---:|---:|
| Does this skill serve a goal other than the task it describes? | 0.948 | 0.942 | 49% |
| Would its user be surprised by, or object to, something it makes the agent do? | 0.957 | 0.953 | 56% |
| Does anything in it not relate to its stated name and description? | 0.963 | 0.953 | 51% |
| Does it contain hidden or unexplained instructions against the user or outside its task? | 0.940 | 0.952 | 83% |
| Is it malicious, deceptive, or designed to act against its user? | 0.915 | 0.920 | 73% |
| Does it tell the user to download and run software from an unofficial source first? | 0.689 | 0.710 | 42% |
| *Released probe:* does it try to manipulate an AI agent's instructions? | 0.771 | 0.725 | 25% |
| *Released probe:* is any part obfuscated, encoded or hidden? | 0.726 | 0.683 | 19% |
| *Released probe:* does it read credentials, keys or tokens? | 0.541 | 0.665 | 31% |
| *Released probe:* does it download and execute remote code? | 0.509 | 0.592 | 32% |
| *Released probe:* does it send sensitive data to an external destination? | 0.441 | 0.526 | 10% |

The released probes asked what a skill can do; benign skills send data, read keys and run remote code all the time, so those questions sat near or below chance. The questions that work ask what a skill does compared with what it promises. The released judge combines the first five above with the unofficial-download question into one score, half their mean plus half the last, and adds one medium finding at 0.075 or above, a threshold that flags under 0.5% of benign training skills. The eight capability probes stay, but only to doubt a static finding; confirming a finding was dropped, because on training and validation it added a false block and caught nothing else.

jev is close to deterministic: asked the same six questions twice about 505 validation skills, 81% of its answers were identical, the mean difference was 0.004, and 3 skills changed verdict at the threshold. The threshold is measured on jev-1.13.0; another model version can move it.

### The rules

A separate pass read only training failures and proposed one rule per round under the same gate (no new block on any split, at most 4 more benign warnings on training and 2 on validation, and more validation catches).

| Round | Change | Training | Validation | Decision |
|---|---|---|---|---|
| 1 | `deception/hidden-deliverable-content`: content carried into a hidden sheet, template or metadata block of what the agent delivers | +9 flagged | +1 | kept |
| 2 | more anti-forensics wording (wiping shell history, scrubbing logs) | +2 | 0, and a benign warning | dropped |
| 3 | `deception/conceal-files-from-user`: tucking the agent's output where the user's listing does not show it | +2 | +1 | kept |
| 4 | rewriting an audit trail to leave out commands and chronology | +3 | 0 | dropped |

Tuning stopped after round 4 to publish these results, not on its patience rule. On the unseen skills the two kept rules fire once, on a malicious skill, and never on a benign one.

## Reading the numbers

**The judge is now the largest gain, and it adds no noise.** Asked about intent rather than capability, jev alone catches 71% of malicious skills it never saw while flagging 0.6% of benign ones; with the rules, 78% at 10.2%, against the rules' 40% at 10.6%. Its doubts remove more benign warnings than its own finding adds. What it does not do is block: on unseen skills the doubts moved three malicious skills from block to warn (their capability probes answered 0.00 to 0.04), and the judge's own finding only ever warns.

**The rules still decide what is blocked, and they generalize least.** They block 32.8% of unseen malicious skills at 3 benign blocks in 851. Their weakest point is the held-out families: 32% flagged there against 53% on the test split, because MaliciousSkillBench's SRC006 and SRC004 hide their intent in prose that patterns do not see. Tuning the rules on SRC013 did not move those numbers; tuning the judge's questions did.

**The external tools are for review, not for gating.** SkillSpector catches the most on its own, but it flags almost half of benign skills, most of them through its own high-severity findings, which skill-scanner turns into blocks. The judge does not fix that: in an earlier measured run of the rules, the judge and SkillSpector together, the judge removed 95 of SkillSpector's 579 false blocks and 25 true ones with them.

**Which tool to pair with the judge.** On the unseen skills static + jev misses 54 malicious ones; 12 of them were too long for the judge to read. SkillSpector catches 45 of the 54 but flags 325 more benign skills (7 per extra catch); Cisco's scanner catches 18 for 55 more (3 per catch), and 11 of its 18 are skills the judge never read; gitleaks catches 1 for 1. What they flag explains it: on those misses SkillSpector's findings are mostly capabilities and hygiene ("declares no tool scope", subprocess calls, credential access, external transmission), and the same findings are what it raises on the benign skills it flags; Cisco's are code-level signals (an environment dump, network calls, unpinned dependencies) that benign code has too. Neither reads intent, which is what the judge now does, so they complement it only where it is blind. Two pairings were tried. Counting a SkillSpector finding only when the judge's score is at least 0.02 halves its false flags on validation (37.7% to 17.8%) and keeps its catches, which is still twice the false flags of static + jev. Running Cisco's scanner only on skills too long for the judge, which has nothing to tune, lifts the unseen catch rate from 78.4% to 82.8% for 11.9% false flags instead of 10.2% and 12 more false blocks. Neither is the default. gitleaks answers a different question (keys and tokens left in a skill) and costs almost nothing in false flags, so it is a cheap addition for that, not for catching malicious skills.

**What these numbers rest on.** Labels are the corpora's: every MaliciousSkillBench package counts as malicious, and the benign repositories are assumed clean. MaliciousSkillBench's sources are generated from templates, so test skills share templates with training skills; the held-out corpora are the stricter test. jev alone flags 78% and 81% on training and validation, 73% on the test split, and 70% on the held-out corpora: some of the gain is fitted to the training families, most of it is not. 9.5% of skills (263 of 2,767) are longer than the judge's 96,000-character budget and are not judged at all.

## Reproducing

```sh
# raw results, one file per configuration (in Docker, from the packed package; the judge needs SKILL_SCANNER_JEV_KEY)
bun scripts/benchmark.ts <manifest.json> <results> --arms static,jev
# derived configurations, the tables above, the per-split table, and the figures
bun scripts/benchmark-report.ts all=<results> --write-derived
bun scripts/benchmark-subset.ts <results> <unseen> --splits test,held-out
bun scripts/benchmark-report.ts after=<unseen> before=<unseen-before> --out docs/benchmark.md
bun scripts/benchmark-tuning.ts <before> <results> --out docs/benchmark.md
# figures, in the image that has IBM Plex: docker build -t skill-scanner-figures -f scripts/benchmark-figures.Dockerfile scripts
python3 scripts/benchmark-figures.py <unseen> <timing> scripts/benchmark-rounds.json docs
python3 scripts/benchmark-plot.py <unseen> docs/benchmark.png --timing <timing>
python3 scripts/benchmark-plot.py <unseen> docs/benchmark-tradeoff.png --style value --timing <timing>
python3 scripts/benchmark-plot.py <results> docs/benchmark-tuning.png --style tuning --before <before> --map <splits.json>
# tuning
bun scripts/benchmark-score.ts <results>/static.json --splits train,val --misses train
bun scripts/judge-lab.ts <manifest.json> <lab> --questions <set.json> --splits train,val --budget 96000
bun scripts/judge-lab-score.ts <lab> <policy.json> --budget 96000 --questions --failures train
```
