#!/usr/bin/env python3
"""The two headline figures, drawn from the tables already in docs/benchmark.md.

    python3 scripts/benchmark-headline.py docs/benchmark.md docs [font-dir]

benchmark-scorecard.png    skill-scanner with jev against Cisco's and NVIDIA's scanners, at one glance: caught, false
                           alarms, time and cost, and the data they were measured on
benchmark-improvement.png  before and after skill-factory: rules alone, jev alone, and both

Both are on the skills tuning never read (test split + held-out corpora). Each split's percentages in the Tuning table
are turned back into skill counts (exact: a 0.1% step is far below one skill on splits this size) and pooled; the
pooled "after" counts must equal the released tables, or the script stops. Draws with the palette and helpers of
scripts/benchmark-figures.py, in its image (scripts/benchmark-figures.Dockerfile) or with IBM Plex in [font-dir].
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass

import matplotlib

matplotlib.use("Agg")
from matplotlib import font_manager  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

UNSEEN = ("test", "held-out corpora")
DEFAULT = "jev+gitleaks"  # the default with jev
RIVALS = (("cisco-only", "Cisco skill-scanner"), ("skillspector-only", "NVIDIA SkillSpector"))
TEAL = "#0d9488"  # benchmark-figures.py's jev teal, one step brighter: clears the chroma floor of a categorical palette
BAND = "#e6f4f1"
ARROW, TIMES = "\u2192", "\u00d7"


def load_style():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benchmark-figures.py")
    spec = importlib.util.spec_from_file_location("benchmark_figures", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_figures"] = module  # its dataclasses look their module up while being defined
    spec.loader.exec_module(module)
    return module


# ---- data


@dataclass(frozen=True)
class Rates:
    caught: int  # malicious skills flagged or blocked
    flagged: int  # benign skills flagged or blocked
    malicious: int
    benign: int

    @property
    def caught_pct(self) -> float:
        return 100 * self.caught / self.malicious

    @property
    def flagged_pct(self) -> float:
        return 100 * self.flagged / self.benign

    def __add__(self, other: Rates) -> Rates:
        return Rates(self.caught + other.caught, self.flagged + other.flagged,
                     self.malicious + other.malicious, self.benign + other.benign)


@dataclass(frozen=True)
class Change:
    name: str
    before: Rates
    after: Rates
    color: str


@dataclass(frozen=True)
class Scanner:
    name: str
    mode: str
    caught: float  # %
    flagged: float  # %
    seconds: float  # per skill, from the clean sequential timing run
    usd_per_1000: float
    ours: bool


def count(pct: float, n: int) -> int:
    """The skill count behind a percentage printed to 0.1%; fails loudly if no count rounds back to it."""
    k = round(pct * n / 100)
    if round(100 * k / n, 1) != pct:
        raise ValueError(f"{pct}% of {n} is not a whole number of skills")
    return k


TUNING_ROW = re.compile(r"^\| (?P<config>[^|]+?) \| (?P<split>[^|(]+?) \((?P<mal>\d+) / (?P<ben>\d+)\) \| (?P<cells>.+) \|$")
TUNING_CELL = re.compile(r"([\d.]+)% -> \*\*([\d.]+)%\*\*")


def parse_tuning(markdown: str) -> dict[tuple[str, str], tuple[Rates, Rates]]:
    block = markdown.split("<!-- benchmark:tuning -->")[1].split("<!-- /benchmark:tuning -->")[0]
    out: dict[tuple[str, str], tuple[Rates, Rates]] = {}
    for line in block.strip().splitlines():
        m = TUNING_ROW.match(line)
        if not m:
            continue
        mal, ben = int(m["mal"]), int(m["ben"])
        (mal_b, mal_a), _, (ben_b, ben_a), _ = [tuple(map(float, c)) for c in TUNING_CELL.findall(m["cells"])]
        out[(m["config"], m["split"])] = (Rates(count(mal_b, mal), count(ben_b, ben), mal, ben),
                                          Rates(count(mal_a, mal), count(ben_a, ben), mal, ben))
    return out


def unseen(table: dict, config: str) -> tuple[Rates, Rates]:
    first, second = (table[(config, split)] for split in UNSEEN)
    return first[0] + second[0], first[1] + second[1]


def table_rows(markdown: str, heading: str) -> dict[str, list[str]]:
    """The first table under `heading`, as {configuration: cells}."""
    section = markdown.split(heading, 1)[1].split("\n#### ", 1)[0]
    rows = {}
    for line in section.splitlines():
        if line.startswith("| ") and not line.startswith(("| Configuration", "|---")):
            cells = [c.strip() for c in line.strip("|").split("|")]
            rows[cells[0]] = cells[1:]
    return rows


def seconds(cell: str) -> float:
    m = re.fullmatch(r"([\d.]+) (ms|s)", cell)
    if not m:
        raise ValueError(f"not a duration: {cell!r}")
    return float(m[1]) / (1000 if m[2] == "ms" else 1)


def scanners(markdown: str) -> list[Scanner]:
    detection = table_rows(markdown, "#### Detection at the warn threshold")
    cost = table_rows(markdown, "#### Cost and time")
    rows = [(DEFAULT, "skill-scanner with jev", "after skill-factory (v0.4.0)", True)] + [(a, n, "offline mode", False) for a, n in RIVALS]
    out = []
    for arm, name, mode, ours in rows:
        tp, fp, fn, tn = (int(x) for x in detection[arm][:4])
        out.append(Scanner(name, mode, 100 * tp / (tp + fn), 100 * fp / (fp + tn), seconds(cost[arm][2]),
                           float(cost[arm][5].lstrip("$")), ours))
    return out


def changes(table: dict, markdown: str, blue: str) -> list[Change]:
    rows = [("jev alone", "jev alone", "jev-only (derived)", TEAL), ("static rules + jev", "rules + jev", "jev", TEAL),
            ("static rules", "rules alone", "static", blue)]
    released = table_rows(markdown, "#### Detection at the warn threshold")
    out = []
    for config, name, arm, color in rows:
        before, after = unseen(table, config)
        if (after.caught, after.flagged) != (int(released[arm][0]), int(released[arm][1])):
            raise ValueError(f"{name}: rebuilt {after.caught}/{after.flagged}, released table {released[arm][:2]}")
        out.append(Change(name, before, after, color))
    return out


# ---- shared drawing


def pct(x: float, digits: int | None = None) -> str:
    if digits is not None:
        return f"{x:.{digits}f}%"
    return f"{x:.1f}%" if x < 10 else f"{x:.0f}%"


def side_label(ax, x: float, y: float, text: str, right: bool, **kw) -> None:
    ax.annotate(text, (x, y), xytext=(11 if right else -11, 0), textcoords="offset points",
                ha="left" if right else "right", va="center", annotation_clip=False, **kw)


def frame(fig, style, box: tuple[float, float, float, float], rounding: float = 0.012) -> None:
    fig.patches.append(FancyBboxPatch(box[:2], box[2], box[3], boxstyle=f"round,pad=0,rounding_size={rounding}",
                                      transform=fig.transFigure, facecolor=style.TILE, edgecolor=style.LINE,
                                      linewidth=1.2, zorder=0))


# ---- the scorecard


def bar_column(ax, style, rows: list[Scanner], value, fmt, xmax: float, was: str | None) -> None:
    """Horizontal bars, one per scanner, ours in teal; `was` is printed after our value."""
    style.clean(ax)
    ax.set_facecolor("none")
    ax.set(xlim=(0, xmax), ylim=(-0.5, len(rows) - 0.5), xticks=[], yticks=[])
    ax.axvline(0, color=style.FAINT, linewidth=1, zorder=3)
    for y, s in zip(range(len(rows) - 1, -1, -1), rows):
        v = value(s)
        ax.barh(y, v, height=0.46, color=TEAL if s.ours else style.OTHER, zorder=2)
        main = ax.annotate(fmt(v), (v, y), xytext=(8, 0), textcoords="offset points", va="center", fontsize=15,
                           fontweight="semibold", color=style.INK, annotation_clip=False)
        if s.ours and was:
            ax.figure.canvas.draw()
            right = ax.transData.inverted().transform((main.get_window_extent().x1, 0))[0]
            ax.annotate(was, (right, y), xytext=(7, 0), textcoords="offset points", va="center", fontsize=11.5,
                        color=style.MUTED, annotation_clip=False)


def column_header(fig, style, x: float, y: float, title: str, hint: str) -> None:
    fig.text(x, y, title, fontsize=14, fontweight="semibold", color=style.INK, va="bottom")
    fig.text(x, y - 0.012, hint, fontsize=11, color=style.MUTED, va="top")


def data_tile(fig, style, box: tuple[float, float, float, float], value: str, label: str, body: str) -> None:
    x, y, _, h = box
    frame(fig, style, box, 0.01)
    number = fig.text(x + 0.016, y + h - 0.062, value, fontsize=22, fontweight="semibold", color=style.INK, va="baseline")
    right = fig.transFigure.inverted().transform((number.get_window_extent(fig.canvas.get_renderer()).x1, 0))[0]
    fig.text(right + 0.007, y + h - 0.062, label, fontsize=13.5, fontweight="medium", color=style.INK, va="baseline")
    fig.text(x + 0.016, y + h - 0.09, body, fontsize=11, color=style.MUTED, va="top", linespacing=1.45)


def scorecard_figure(rows: list[Scanner], before: Rates, style, out: str) -> None:
    h = 7.8
    fig = style.setup_figure(13.5, h)
    ours, rivals = rows[0], rows[1:]
    faster = min(r.seconds for r in rivals) / ours.seconds
    style.heading(fig, f"skill-scanner now catches {ours.caught:.0f}% of malicious skills, up from {before.caught_pct:.0f}%",
                  "After tuning with skill-factory: more than Cisco's or NVIDIA's scanner, with fewer false alarms, "
                  f"{faster:.0f}{TIMES} faster.", h)
    top, rows_h = 0.43, 0.285
    fig.patches.append(Rectangle((0.035, top + rows_h * 2 / 3), 0.93, rows_h / 3, transform=fig.transFigure,
                                 facecolor=BAND, edgecolor="none", zorder=-1))
    centers = [top + rows_h * (len(rows) - i - 0.5) / len(rows) for i in range(len(rows))]
    for y, s in zip(centers, rows):
        fig.text(0.045, y + 0.012, s.name, fontsize=14, fontweight="semibold" if s.ours else "regular", color=style.INK, va="bottom")
        fig.text(0.045, y + 0.004, s.mode, fontsize=11, color=style.MUTED, va="top")
    head_y = top + rows_h + 0.06
    columns = [
        (0.225, 0.255, "Malicious skills caught", "higher is better", lambda s: s.caught, lambda v: f"{v:.0f}%", 125,
         f"was {before.caught_pct:.0f}%"),
        (0.52, 0.155, "Harmless skills flagged", "false alarms, lower is better", lambda s: s.flagged,
         lambda v: f"{v:.1f}%", 62, f"was {before.flagged_pct:.1f}%"),
        (0.715, 0.11, "Time per skill", "same skills, same machine", lambda s: s.seconds,
         lambda v: f"{v:.2f} s" if v < 1 else f"{v:.1f} s", 3.1, None),
    ]
    for x, w, title, hint, value, fmt, xmax, was in columns:
        column_header(fig, style, x, head_y, title, hint)
        bar_column(fig.add_axes((x, top, w, rows_h)), style, rows, value, fmt, xmax, was)
    column_header(fig, style, 0.875, head_y, "Cost", "per 1,000 skills")
    for y, s in zip(centers, rows):
        text, color = (f"${s.usd_per_1000:.2f}", style.INK) if s.usd_per_1000 else ("free", style.MUTED)
        fig.text(0.875, y, text, fontsize=15, fontweight="semibold" if s.ours else "regular", color=color, va="center")
    fig.text(0.045, 0.345, f"Measured on {before.malicious + before.benign:,} labeled agent skills (SKILL.md bundles) "
             "that tuning never read", fontsize=13, fontweight="semibold", color=style.INK, va="bottom")
    tiles = [
        (f"{before.malicious}", "malicious skills", "227 from MaliciousSkillBench, a research\nbenchmark of malicious agent "
         "skills; 23 from\nSnyk's ToxicSkills, Cisco, Trail of Bits, a\nscanner-bypass sample and our own tests."),
        (f"{before.benign}", "harmless skills", "Real published skills from 24 public\nsources: Microsoft, OpenAI, "
         "Anthropic,\nHugging Face, Cloudflare, Sentry, HashiCorp,\nTrail of Bits and others."),
        ("0", "seen during tuning", "A held-back test split plus 7 whole\ncollections left out of tuning. Each skill\n"
         "is scanned on its own, the way a user\ninstalls it."),
    ]
    w, gap = 0.293, 0.0155
    for i, t in enumerate(tiles):
        data_tile(fig, style, (0.045 + i * (w + gap), 0.08, w, 0.235), *t)
    fig.savefig(out, dpi=200, facecolor=style.PAPER)


# ---- before and after skill-factory


def tile(fig, style, box: tuple[float, float, float, float], value: str, label: str, note: str, color: str) -> None:
    x, y, _, h = box
    frame(fig, style, box)
    fig.text(x + 0.018, y + h - 0.035, value, fontsize=28, fontweight="semibold", color=color, va="top")
    fig.text(x + 0.018, y + h - 0.118, label, fontsize=13, fontweight="medium", color=style.INK, va="top")
    fig.text(x + 0.018, y + 0.03, note, fontsize=11, color=style.MUTED, va="bottom", linespacing=1.35)


def dumbbell(ax, style, rows: list[Change], value, fmt, xmax: float, ticks: Sequence[float], names: bool) -> None:
    """One row per configuration: a hollow gray ring before, a filled dot after, an arrow between."""
    style.clean(ax)
    ax.set(xlim=(0, xmax), ylim=(-0.6, len(rows) - 0.4), yticks=[])
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{t:g}%" for t in ticks], fontsize=10.5, color=style.MUTED)
    ax.grid(True, axis="x", color=style.LINE, linewidth=0.9, zorder=0)
    for y, c in zip(range(len(rows) - 1, -1, -1), rows):
        b, a = value(c.before), value(c.after)
        moved = abs(a - b) >= xmax * 0.02
        if moved:
            ax.annotate("", xy=(a, y), xytext=(b, y), zorder=2,
                        arrowprops=dict(arrowstyle="-|>", color=c.color, alpha=0.45, lw=2.4, mutation_scale=16, shrinkA=8, shrinkB=9))
            side_label(ax, b, y, fmt(b), right=a < b, fontsize=12, color=style.MUTED)
            side_label(ax, a, y, fmt(a), right=a >= b, fontsize=14, fontweight="semibold", color=style.INK)
        else:
            side_label(ax, max(a, b), y, f"{fmt(a)}  unchanged", right=True, fontsize=12.5, color=style.INK)
        ax.scatter(b, y, s=120, facecolor=style.PAPER, edgecolor=style.FAINT, linewidth=2.2, zorder=3)
        ax.scatter(a, y, s=135, color=c.color, edgecolor=style.PAPER, linewidth=2, zorder=4)
        if names:
            ax.text(-xmax * 0.04, y, c.name, ha="right", va="center", fontsize=13.5, color=style.INK,
                    fontweight="semibold" if c.name == "jev alone" else "regular")


def legend(fig, style, x: float, y: float) -> None:
    fig.add_artist(Line2D([x], [y], marker="o", markersize=10, markerfacecolor=style.PAPER, markeredgecolor=style.FAINT,
                          markeredgewidth=2.2, linestyle="none", transform=fig.transFigure))
    fig.text(x + 0.012, y, "before: the released rules and jev questions (v0.3.0)", fontsize=11, color=style.INK, va="center")
    x2 = x + 0.39
    for dx, color in ((0, TEAL), (0.013, style.OURS)):
        fig.add_artist(Line2D([x2 + dx], [y], marker="o", markersize=10.5, color=color, markeredgecolor=style.PAPER,
                              linestyle="none", transform=fig.transFigure))
    fig.text(x2 + 0.025, y, "after the skill-factory loop (v0.4.0)", fontsize=11, color=style.INK, va="center")


def improvement_figure(rows: list[Change], ours: Scanner, style, out: str) -> None:
    h = 7.8
    fig = style.setup_figure(13.5, h)
    jev, both = rows[0], rows[1]
    style.heading(fig, f"skill-factory took jev from {pct(jev.before.caught_pct)} to {pct(jev.after.caught_pct)} of malicious skills caught",
                  f"Before and after the loop, on {jev.after.malicious} malicious and {jev.after.benign} harmless skills tuning never read. "
                  "Same 96,000-character budget on both sides.", h)
    tiles = [
        (f"{pct(jev.before.caught_pct)} {ARROW} {pct(jev.after.caught_pct)}", "malicious skills jev catches",
         f"{jev.after.caught_pct / jev.before.caught_pct:.1f}{TIMES} as many: {jev.before.caught} {ARROW} {jev.after.caught}\nof {jev.after.malicious}", TEAL),
        (f"{pct(jev.before.flagged_pct)} {ARROW} {pct(jev.after.flagged_pct)}", "harmless skills jev flags",
         f"{jev.before.flagged_pct / jev.after.flagged_pct:.0f}{TIMES} fewer false alarms:\n{jev.before.flagged} {ARROW} {jev.after.flagged} of {jev.after.benign}", style.INK),
        (f"{pct(both.before.caught_pct)} {ARROW} {pct(both.after.caught_pct)}", "caught by rules + jev",
         f"false flags {pct(both.before.flagged_pct, 1)} {ARROW} {pct(both.after.flagged_pct, 1)};\nrules alone barely moved", style.INK),
        (f"${ours.usd_per_1000:.2f}", "per 1,000 skills scanned", f"{ours.seconds:.2f} s a skill, with jev's\nAPI at list price", style.INK),
    ]
    w, gap = 0.21, 0.0167
    for i, t in enumerate(tiles):
        tile(fig, style, (0.045 + i * (w + gap), 0.55, w, 0.235), *t)
    panels = [
        ("Malicious skills caught", "higher is better", lambda r: r.caught_pct, pct, 100, [0, 25, 50, 75, 100], (0.17, 0.155, 0.37, 0.26)),
        ("Harmless skills wrongly flagged", "lower is better", lambda r: r.flagged_pct, lambda x: pct(x, 1), 15, [0, 5, 10, 15],
         (0.665, 0.155, 0.255, 0.26)),
    ]
    for i, (title, hint, value, fmt, xmax, ticks, box) in enumerate(panels):
        dumbbell(fig.add_axes(box), style, rows, value, fmt, xmax, ticks, names=i == 0)
        x = box[0] - (0.125 if i == 0 else 0)
        fig.text(x, 0.47, title, fontsize=13.5, fontweight="semibold", color=style.INK)
        fig.text(x, 0.443, hint, fontsize=11, color=style.MUTED)
    legend(fig, style, 0.055, 0.075)
    fig.savefig(out, dpi=200, facecolor=style.PAPER)


def main() -> None:
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    markdown_path, out = sys.argv[1:3]
    if len(sys.argv) == 4:
        for f in os.listdir(sys.argv[3]):
            font_manager.fontManager.addfont(os.path.join(sys.argv[3], f))
    sys.dont_write_bytecode = True
    style = load_style()
    with open(markdown_path) as fh:
        markdown = fh.read()
    tuning = parse_tuning(markdown)
    before, _ = unseen(tuning, "static rules + jev")
    rows = scanners(markdown)
    setattr(style, "SOURCE", ("Cisco skill-scanner and NVIDIA SkillSpector ran in their free offline modes (no LLM). "
                    "\"was\": v0.3.0's rules and jev questions at the same budget. Tables: docs/benchmark.md"))
    scorecard_figure(rows, before, style, os.path.join(out, "benchmark-scorecard.png"))
    setattr(style, "SOURCE", "skill-scanner benchmark: test split + held-out corpora, each skill scanned on its own. Tables: docs/benchmark.md, Tuning")
    improvement_figure(changes(tuning, markdown, style.OURS), rows[0], style, os.path.join(out, "benchmark-improvement.png"))
    print("wrote benchmark-scorecard.png and benchmark-improvement.png")


if __name__ == "__main__":
    main()
