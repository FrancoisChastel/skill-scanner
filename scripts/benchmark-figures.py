#!/usr/bin/env python3
"""The benchmark's presentation figures: one message each, every number printed, the same order and colors
throughout. scripts/benchmark-plot.py keeps the dense analysis figures.

    python3 scripts/benchmark-figures.py <unseen-results> <timing-results> <rounds.json> <out-dir>

<unseen-results>  arm files on the skills tuning never read (scripts/benchmark-subset.ts), derived files included
<timing-results>  the clean timing run: every configuration one after another on the same skills
<rounds.json>     scripts/benchmark-rounds.json: each round of the skill-factory loop
Writes benchmark-summary.png, benchmark-caught.png, benchmark-false-alarms.png, benchmark-cost.png,
and benchmark-evolution.png. Drawn in the image of scripts/benchmark-figures.Dockerfile, for IBM Plex Sans.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

INK = "#0f172a"
MUTED = "#64748b"
FAINT = "#94a3b8"
LINE = "#e2e8f0"
TILE = "#f8fafc"
PAPER = "#ffffff"
JEV = "#0f766e"
JEV_LIGHT = "#99d6c8"
OURS = "#2563eb"
OURS_LIGHT = "#bcd0fb"
OTHER = "#94a3b8"
OTHER_LIGHT = "#dbe2ea"
ALARM = "#ea580c"
ALARM_LIGHT = "#fbd2b4"
MONEY = "#b45309"

# (arm, label, color, light color): the same order in every chart.
ROWS = [
    ("jev+gitleaks", "skill-scanner with jev", JEV, JEV_LIGHT),
    ("gitleaks", "skill-scanner", OURS, OURS_LIGHT),
    ("jev-only", "jev alone", JEV, JEV_LIGHT),
    ("cisco-only", "Cisco skill-scanner", OTHER, OTHER_LIGHT),
    ("skillspector-only", "NVIDIA SkillSpector", OTHER, OTHER_LIGHT),
    ("all-offline", "skill-scanner + 3 tools", OTHER, OTHER_LIGHT),
]
HERO = "jev+gitleaks"
SOURCE = "skill-scanner benchmark: skills held out from tuning, each scanned on its own. Method and tables: docs/benchmark.md"


@dataclass(frozen=True)
class Result:
    caught: float  # % of malicious skills blocked or flagged
    blocked: float  # % of malicious skills blocked
    false_flagged: float  # % of harmless skills blocked or flagged
    false_blocked: float  # % of harmless skills blocked
    malicious: int
    harmless: int
    ms: float  # per skill
    usd_per_1000: float


def kept_rows(path: str) -> list[dict]:
    """One row per skill directory, preferring the skill's own scan when it was also scanned inside its repository."""
    best: dict[str, dict] = {}
    for r in json.load(open(path))["rows"]:
        k = r["target"] if r.get("root") in (None, ".") else f'{r["target"]}/{r["root"]}'
        cur = best.get(k)
        if cur is None or (cur.get("root") != "." and r.get("root") == "."):
            best[k] = r
    return list(best.values())


def arm_file(d: str, arm: str) -> str | None:
    for name in (f"{arm}.json", f"{arm}.derived.json"):
        if os.path.exists(os.path.join(d, name)):
            return os.path.join(d, name)
    return None


def timing(d: str) -> dict[str, float]:
    t = {}
    for name in os.listdir(d):
        if name.endswith(".json"):
            rows = kept_rows(os.path.join(d, name))
            t[json.load(open(os.path.join(d, name)))["arm"]] = sum(r["ms"] for r in rows) / len(rows)
    rules = t["static"]
    # Not timed on its own: a tool alone is "rules + tool" minus the rules, three tools add their parts.
    for tool in ("skillspector", "cisco", "gitleaks"):
        t.setdefault(f"{tool}-only", t[tool] - rules)
    t.setdefault("jev-only", t["jev"] - rules)
    t.setdefault("all-offline", rules + sum(t[x] - rules for x in ("skillspector", "cisco", "gitleaks")))
    return t


def load(unseen: str, timed: dict[str, float]) -> dict[str, Result]:
    out = {}
    for arm, *_ in ROWS:
        path = arm_file(unseen, arm)
        if not path:
            continue
        rows = kept_rows(path)
        meta = json.load(open(path))
        m = [r for r in rows if r["label"] == "malicious"]
        b = [r for r in rows if r["label"] != "malicious"]
        share = lambda rs, hit: 100 * sum(1 for r in rs if hit(r["verdict"])) / len(rs)  # noqa: E731
        tokens = sum(r.get("judgeTokensReported") or 0 for r in rows)
        out[arm] = Result(
            share(m, lambda v: v != "pass"),
            share(m, lambda v: v == "block"),
            share(b, lambda v: v != "pass"),
            share(b, lambda v: v == "block"),
            len(m),
            len(b),
            timed[arm],
            tokens / 1e6 * meta.get("usdPerMillionInputTokens", 0) / len(rows) * 1000 if meta.get("judge") else 0.0,
        )
    return out


def pct(x: float, digits: int | None = None) -> str:
    if digits is not None:
        return f"{x:.{digits}f}%"
    return "0%" if x == 0 else f"{x:.1f}%" if x < 10 else f"{x:.0f}%"


def minutes(ms_per_skill: float) -> str:
    s = ms_per_skill  # ms per skill x 1,000 skills = seconds
    return f"{s:.0f} s" if s < 90 else f"{s / 60:.0f} min" if s < 5400 else f"{s / 3600:.1f} h"


def setup_figure(w: float, h: float):
    plt.rcParams.update({"font.family": ["IBM Plex Sans", "DejaVu Sans"], "font.size": 12, "text.color": INK})
    fig = plt.figure(figsize=(w, h))
    fig.patch.set_facecolor(PAPER)
    return fig


def heading(fig, title: str, subtitle: str, h: float) -> None:
    fig.text(0.045, 1 - 0.42 / h, title, fontsize=24, fontweight="semibold", color=INK, va="top")
    fig.text(0.045, 1 - 0.98 / h, subtitle, fontsize=13, color=MUTED, va="top")
    fig.text(0.045, 0.22 / h, SOURCE, fontsize=9.5, color=FAINT, va="bottom")


def clean(ax) -> None:
    for side in ax.spines.values():
        side.set_visible(False)
    ax.tick_params(length=0)
    ax.set_facecolor(PAPER)


def bars(
    ax,
    results: dict[str, Result],
    value,
    light_value,
    label,
    xmax: float,
    big: bool = True,
    alarm: bool = False,
    extra=None,
    band_from: float = -1.0,
) -> None:
    """Horizontal bars in ROWS order: `value` dark, `light_value` (when given) as the lighter extension behind it.
    `extra(result)` gives a second, lighter label piece and its color; the highlight band starts at `band_from`
    (axes fraction), so side-by-side panels never paint over each other."""
    clean(ax)
    renderer = ax.figure.canvas.get_renderer()
    shown = [r for r in ROWS if r[0] in results]
    # Limits first: label positions are measured in data coordinates.
    ax.set_xlim(0, xmax)
    ax.set_ylim(-0.6, len(shown) - 0.4)
    ys = list(range(len(shown)))[::-1]
    for y, (arm, name, color, light) in zip(ys, shown):
        r = results[arm]
        dark_c, light_c = (ALARM, ALARM_LIGHT) if alarm else (color, light)
        if light_value is not None:
            ax.barh(y, light_value(r), height=0.62, color=light_c, zorder=2)
        ax.barh(y, max(value(r), 0.25 if alarm else 0), height=0.62, color=dark_c, zorder=3)
        end = light_value(r) if light_value is not None else value(r)
        main = ax.text(end + xmax * 0.012, y, label(r), va="center", ha="left", fontsize=15 if big else 12, fontweight="semibold", color=INK)
        if extra is not None:
            text, color = extra(r)
            right = ax.transData.inverted().transform((main.get_window_extent(renderer).x1, 0))[0]
            ax.text(right + xmax * 0.012, y, text, va="center", ha="left", fontsize=13 if big else 11, color=color)
        weight = "semibold" if arm == HERO else "regular"
        ax.text(-xmax * 0.015, y, name, va="center", ha="right", fontsize=13.5 if big else 11.5, fontweight=weight,
                color=JEV if arm == HERO else INK)
    if any(a == HERO for a, *_ in shown):
        y = ys[[a for a, *_ in shown].index(HERO)]
        ax.axhspan(y - 0.45, y + 0.45, xmin=band_from, color="#ecf7f4", zorder=0, clip_on=False)
    ax.set_xlim(0, xmax)
    ax.set_ylim(-0.6, len(shown) - 0.4)
    ax.set_xticks([])
    ax.set_yticks([])


# ---- the single-message charts


def caught_figure(results: dict[str, Result], out: str) -> None:
    fig = setup_figure(12, 6.75)
    hero, base = results[HERO], results["gitleaks"]
    heading(fig, f"skill-scanner with jev catches {pct(hero.caught)} of malicious skills",
            f"Of {hero.malicious} malicious skills it never saw during tuning (higher is better). "
            "Dark: blocked at install. Light: flagged for a look.", 6.75)
    ax = fig.add_axes((0.3, 0.1, 0.62, 0.66))
    bars(ax, results, lambda r: r.blocked, lambda r: r.caught, lambda r: pct(r.caught), 112)
    fig.savefig(out, dpi=200, facecolor=PAPER)


def alarms_figure(results: dict[str, Result], out: str) -> None:
    fig = setup_figure(12, 6.75)
    hero, base = results[HERO], results["gitleaks"]
    heading(fig, f"With jev, fewer harmless skills are flagged: {pct(hero.false_flagged, 1)} against {pct(base.false_flagged, 1)}",
            f"Of {hero.harmless} harmless skills (lower is better). Dark: blocked at install, {pct(hero.false_blocked, 2)} with or without jev.", 6.75)
    ax = fig.add_axes((0.3, 0.1, 0.62, 0.66))
    worst = max(r.false_flagged for r in results.values())
    bars(ax, results, lambda r: r.false_blocked, lambda r: r.false_flagged, lambda r: pct(r.false_flagged, 1), worst * 1.22, alarm=True)
    fig.savefig(out, dpi=200, facecolor=PAPER)


def cost_figure(results: dict[str, Result], out: str) -> None:
    fig = setup_figure(12, 6.75)
    hero = results[HERO]
    tools = [results[a] for a in ("cisco-only", "skillspector-only") if a in results]
    heading(fig, f"skill-scanner with jev checks 1,000 skills in {minutes(hero.ms)} for ${hero.usd_per_1000:.2f}",
            f"Time to scan 1,000 skills one at a time (lower is better), and jev's API cost. "
            f"Cisco's scanner and SkillSpector take {minutes(min(t.ms for t in tools))} to {minutes(max(t.ms for t in tools))}.", 6.75)
    ax = fig.add_axes((0.3, 0.1, 0.62, 0.66))
    worst = max(r.ms for r in results.values())
    bars(ax, results, lambda r: r.ms / 60, None, lambda r: minutes(r.ms), worst / 60 * 1.3,
         extra=lambda r: (f"+ ${r.usd_per_1000:.2f}", MONEY) if r.usd_per_1000 else ("free", FAINT))
    fig.savefig(out, dpi=200, facecolor=PAPER)


# ---- the one-page summary


def tile(fig, x: float, y: float, w: float, h: float, value: str, label: str, note: str, color: str) -> None:
    fig.patches.append(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.012", transform=fig.transFigure,
                                      facecolor=TILE, edgecolor=LINE, linewidth=1.2, zorder=0))
    fig.text(x + 0.018, y + h - 0.035, value, fontsize=36, fontweight="semibold", color=color, va="top")
    fig.text(x + 0.018, y + h - 0.125, label, fontsize=13, fontweight="medium", color=INK, va="top")
    fig.text(x + 0.018, y + 0.03, note, fontsize=11, color=MUTED, va="bottom", linespacing=1.35)


def summary_figure(results: dict[str, Result], out: str) -> None:
    h = 7.6
    fig = setup_figure(13.5, h)
    hero, base = results[HERO], results["gitleaks"]
    heading(fig, f"skill-scanner with jev catches {pct(hero.caught)} of malicious agent skills",
            f"Measured on {hero.malicious} malicious and {hero.harmless} harmless skills it never saw during tuning, "
            "against skill-scanner without jev and other scanners.", h)
    tiles = [
        (pct(hero.caught), "malicious skills caught", f"{pct(base.caught)} without jev", JEV),
        (pct(hero.false_blocked, 2), "harmless skills blocked", f"{round(hero.false_blocked * hero.harmless / 100)} of {hero.harmless};\njev never blocks on its own", INK),
        (pct(hero.false_flagged, 1), "harmless skills flagged", f"{pct(base.false_flagged, 1)} without jev:\njev also clears false alarms", INK),
        (f"${hero.usd_per_1000:.2f}", "per 1,000 skills", f"{hero.ms / 1000:.2f} s a skill;\nother scanners take ~{min(results[a].ms for a in ('cisco-only', 'skillspector-only')) / 1000:.0f} s", INK),
    ]
    w, gap, x0, y0, th = 0.21, 0.0167, 0.045, 0.52, 0.25
    for i, t in enumerate(tiles):
        tile(fig, x0 + i * (w + gap), y0, w, th, *t)
    compare = {a: results[a] for a in ("jev+gitleaks", "gitleaks", "cisco-only", "skillspector-only") if a in results}
    panels = [
        ("Malicious skills caught", lambda r: r.caught, lambda r: pct(r.caught), 118, False),
        ("Harmless skills flagged", lambda r: r.false_flagged, lambda r: pct(r.false_flagged, 1), 62, True),
        ("Time for 1,000 skills", lambda r: r.ms / 60, lambda r: minutes(r.ms), 52, False),
    ]
    for i, (title, val, lab, xmax, alarm) in enumerate(panels):
        ax = fig.add_axes((0.205 + i * 0.27, 0.09, 0.17, 0.32))
        bars(ax, compare, val, None, lab, xmax, big=False, alarm=alarm, band_from=-1.3 if i == 0 else -0.02)
        if i > 0:
            for t in ax.texts[1::2]:
                t.set_visible(False)  # row names once, on the first panel
        fig.text(0.205 + i * 0.27 - (0.15 if i == 0 else 0.005), 0.435, title, fontsize=13.5, fontweight="semibold", color=INK)
    fig.savefig(out, dpi=200, facecolor=PAPER)


# ---- the skill-factory evolution


def end_labels(ax, x: float, items: list[tuple[float, str, bool]], min_gap_px: float = 17.0) -> None:
    """Labels to the right of the last points, pushed apart so none overlaps, each at its value when it can be."""
    fig = ax.figure
    to_px = lambda v: ax.transData.transform((x, v))[1]  # noqa: E731
    placed: list[float] = []
    for value, text, bold in sorted(items, key=lambda i: -i[0]):
        y = to_px(value)
        if placed and placed[-1] - y < min_gap_px:
            y = placed[-1] - min_gap_px
        placed.append(y)
        fx, fy = fig.transFigure.inverted().transform((ax.transData.transform((x, 0))[0] + 18, y))
        fig.text(fx, fy, text, fontsize=11.5, color=INK, va="center", fontweight="semibold" if bold else "regular")


def evolution_panel(ax, data: list[dict], color: str, title: str, note: str, short: bool) -> None:
    clean(ax)
    ax.grid(True, axis="y", color=LINE, linewidth=0.9, zorder=0)
    xs = list(range(len(data)))
    ax.set_ylim(0, 100)
    ax.set_xlim(-0.35, len(data) - 0.55)
    kept = [i for i, d in enumerate(data) if d.get("kept", True)]
    for split, style, marker in (("train", "-", "o"), ("val", "--", "s")):
        ax.plot([xs[i] for i in kept], [data[i][split][0] for i in kept], linestyle=style, color=color, linewidth=2.6, zorder=3,
                marker=marker, markersize=7.5, markerfacecolor=PAPER if split == "val" else color, markeredgewidth=2.2)
        for i, d in enumerate(data):
            if not d.get("kept", True):
                ax.scatter(i, d[split][0], s=48, marker=marker, facecolor=PAPER, edgecolor=FAINT, linewidth=1.6, zorder=3)
    # The data tuning never read: only before and after, nudged clear of the training lines.
    for split, marker in (("test", "D"), ("heldOut", "^")):
        pts = [(i + (-0.14 if i == 0 else 0.14), d[split][0]) for i, d in enumerate(data) if split in d]
        if len(pts) == 2:
            ax.plot([p[0] for p in pts], [p[1] for p in pts], linestyle=(0, (1, 2.5)), color=INK, linewidth=1.3, zorder=2)
        for x, v in pts:
            ax.scatter(x, v, s=60, marker=marker, color=INK, zorder=4)
    ax.set_xticks(xs)
    ax.set_xticklabels([(d["round"] if not short else d.get("short", d["round"])) + ("\n" + d["detail"] if d.get("detail") and not short else "")
                        + ("\n(dropped)" if not d.get("kept", True) else "") for d in data], fontsize=10.5, color=INK, linespacing=1.35)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_yticklabels([f"{v}%" for v in (0, 25, 50, 75, 100)], fontsize=10.5, color=MUTED)
    ax.text(0, 1.115, title, transform=ax.transAxes, fontsize=15, fontweight="semibold", color=INK, va="bottom")
    ax.text(0, 1.05, note, transform=ax.transAxes, fontsize=11, color=MUTED, va="bottom")
    last = data[-1]
    labels = [(last["val"][0], f"validation {last['val'][0]:.0f}%", True), (last["train"][0], f"training {last['train'][0]:.0f}%", False)]
    labels += [(last[k][0], f"{n} {last[k][0]:.0f}%", False) for k, n in (("test", "test"), ("heldOut", "held-out")) if k in last]
    ax.figure.canvas.draw()
    end_labels(ax, xs[-1] + 0.14, labels)


def evolution_figure(rounds: dict, out: str) -> None:
    h = 7.4
    fig = setup_figure(13.5, h)
    jev, rules = rounds["jev"], rounds["rules"]
    heading(fig, f"skill-factory's loop took jev from {jev[0]['val'][0]:.0f}% to {jev[-1]['val'][0]:.0f}% of malicious skills caught",
            "Each round reads the training misses, rewrites, and keeps a change only if it beats validation. "
            "Test and held-out skills are read once, at the end.", h)
    left = fig.add_axes((0.06, 0.2, 0.47, 0.5))
    evolution_panel(left, jev, JEV, "jev's questions",
                    f"jev alone. False flags on validation: {jev[0]['val'][1]:.1f}% before, {jev[-1]['val'][1]:.1f}% after.", short=False)
    for d in rules:
        d.setdefault("short", {"Released rules": "Released", "Tuned": "Tuned"}.get(d["round"], d["round"].replace("Round ", "R")))
    right = fig.add_axes((0.665, 0.2, 0.21, 0.5))
    evolution_panel(right, rules, OURS, "skill-scanner's rules", "Two rules kept, two dropped. False flags unchanged.", short=True)
    legend = [("o", JEV, JEV, "training (read)"), ("s", PAPER, JEV, "validation (the gate)"),
              ("D", INK, INK, "test (read once)"), ("^", INK, INK, "held-out corpora (read once)")]
    for i, (m, fc, ec, label) in enumerate(legend):
        x = 0.06 + i * 0.17
        fig.add_artist(plt.Line2D([x], [0.085], marker=m, color=ec, markerfacecolor=fc, markersize=8, markeredgewidth=2.2,
                                  linestyle="none", transform=fig.transFigure))
        fig.text(x + 0.013, 0.085, label, fontsize=11, color=INK, va="center")
    fig.savefig(out, dpi=200, facecolor=PAPER)


def main() -> None:
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    unseen, timing_dir, rounds_path, out = sys.argv[1:]
    results = load(unseen, timing(timing_dir))
    figures = {
        "benchmark-summary.png": lambda p: summary_figure(results, p),
        "benchmark-caught.png": lambda p: caught_figure(results, p),
        "benchmark-false-alarms.png": lambda p: alarms_figure(results, p),
        "benchmark-cost.png": lambda p: cost_figure(results, p),
        "benchmark-evolution.png": lambda p: evolution_figure(json.load(open(rounds_path)), p),
    }
    for name, draw in figures.items():
        draw(os.path.join(out, name))
        print(f"wrote {name}")


if __name__ == "__main__":
    main()
