#!/usr/bin/env python3
"""Draw the benchmark figures from the results scripts/benchmark.ts writes.

    python3 scripts/benchmark-plot.py <results-dir> <out.png> [--only a,b,c] [--note TEXT]
    python3 scripts/benchmark-plot.py <results-dir> <out.png> --style scatter [--only a,b,c]
    python3 scripts/benchmark-plot.py <after-dir> <out.png> --style tuning --before <before-dir> --map <splits.json>

table (default)  one row per configuration, every number printed: the share of malicious skills caught
                 (blocked, and flagged for a question), the share of benign skills wrongly flagged, and
                 the time and judge cost per skill. --note says which skills the numbers are on.
scatter          the trade-off view: caught against wrongly flagged, one point per configuration and threshold.
value            the headline: caught against wrongly flagged for the main approaches, and the time and money
                 to scan 1,000 skills; one figure for the README.
tuning           before and after tuning, per split (train, validation, test, held-out corpora), for the
                 static rules, jev alone, and static + jev; --map comes from scripts/benchmark-subset.ts --map.

Needs matplotlib. To keep the host clean, run it in Docker:
    docker run --rm -v "$PWD:/w" -w /w python:3.12-slim \\
      sh -c 'pip -q install matplotlib && python3 scripts/benchmark-plot.py bench/out docs/benchmark.png'
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

TOOLS = ["skillspector", "cisco", "gitleaks", "osv-scanner", "semgrep"]
TOOL_NAMES = {"skillspector": "SkillSpector", "cisco": "Cisco", "gitleaks": "gitleaks", "osv-scanner": "osv-scanner", "semgrep": "semgrep"}
# Rows in reading order, in groups; a configuration not in the results is skipped.
GROUPS: list[tuple[str, list[str]]] = [
    ("skill-scanner", ["gitleaks", "jev+gitleaks", "static", "jev", "jev-only"]),
    ("Each tool alone, without skill-scanner's rules", [f"{t}-only" for t in TOOLS]),
    ("skill-scanner's rules + other tools", [t for t in TOOLS if t != "gitleaks"] + ["skillspector+gitleaks", "all-offline", "all-analyzers"]),
    ("With the judge and tools", ["jev+skillspector", "jev+all"]),
]
LABELS = {
    "static": "rules only",
    "jev": "rules + jev",
    "jev-only": "jev alone",
    **{f"{t}-only": f"{TOOL_NAMES[t]} alone" for t in TOOLS},
    **{t: f"rules + {TOOL_NAMES[t]}" for t in TOOLS},
    "skillspector+gitleaks": "rules + SkillSpector + gitleaks",
    "all-offline": "rules + 3 offline tools",
    "all-analyzers": "rules + 5 tools",
    "jev+gitleaks": "rules + gitleaks + jev",
    "jev+skillspector": "rules + jev + SkillSpector",
    "jev+all": "everything",
}
# The two configurations a user gets by default: without jev, and with it.
TAGS = {"gitleaks": "default without jev", "jev+gitleaks": "default with jev"}

INK = "#16181d"
MUTED = "#6b7280"
FAINT = "#9ca3af"
GRID = "#eceef1"
PAPER = "#ffffff"
CATCH = "#13795b"
CATCH_LIGHT = "#a7d9c5"
FALSE = "#c2410c"
FALSE_LIGHT = "#f6c7a8"
TIME = "#334155"
BAND = "#f0f7f3"
# The scatter keeps one hue per configuration.
COLORS = {
    "static": "#16181d", "jev": "#c2410c", "jev-only": "#e0703a",
    "skillspector": "#13795b", "cisco": "#b7791f", "gitleaks": "#6d4fb3", "osv-scanner": "#8b6b4e", "semgrep": "#be4b8a",
    "skillspector+gitleaks": "#2f7d5d", "all-offline": "#64748b", "all-analyzers": "#1f6f85",
    "jev+gitleaks": "#7c3aed", "jev+skillspector": "#9a3412", "jev+all": "#6b2380",
}


@dataclass(frozen=True)
class Point:
    arm: str
    blocked: float  # share of malicious skills blocked
    flagged: float  # share of malicious skills blocked or warned about
    fp_blocked: float
    fp_flagged: float
    positives: int
    negatives: int


def base(arm: str) -> str:
    return arm.replace(" (derived)", "")


def point(arm: dict) -> Point:
    m = [r for r in arm["rows"] if r["label"] == "malicious"]
    b = [r for r in arm["rows"] if r["label"] != "malicious"]
    share = lambda rs, hit: sum(1 for r in rs if hit(r["verdict"])) / len(rs) if rs else 0.0  # noqa: E731
    blocked = lambda v: v == "block"  # noqa: E731
    flagged = lambda v: v != "pass"  # noqa: E731
    return Point(base(arm["arm"]), share(m, blocked), share(m, flagged), share(b, blocked), share(b, flagged), len(m), len(b))


def judge_cost_per_1000(arm: dict) -> float | None:
    if not arm.get("judge"):
        return None
    reported = [r.get("judgeTokensReported") for r in arm["rows"]]
    tokens = sum(t or 0 for t in reported) if any(t is not None for t in reported) else sum(r.get("judgeBytes", 0) for r in arm["rows"]) / 4
    return tokens / 1e6 * arm["usdPerMillionInputTokens"] / max(1, len(arm["rows"])) * 1000


# Times from a separate clean run (--timing): every configuration one after another on the same skills, nothing
# else running. A configuration not timed there is derived the way its verdicts were: a tool alone is "rules +
# tool" minus the rules, a combination adds its parts.
TIMING: dict[str, float] = {}
PARTS = {"all-offline": ["skillspector", "cisco", "gitleaks"], "skillspector+gitleaks": ["skillspector", "gitleaks"]}


def timed(arm_id: str) -> float | None:
    if arm_id in TIMING:
        return TIMING[arm_id]
    rules = TIMING.get("static")
    if rules is None:
        return None
    if arm_id.endswith("-only") and arm_id[:-5] in TIMING:
        return max(0.0, TIMING[arm_id[:-5]] - rules)
    if arm_id in PARTS and all(p in TIMING for p in PARTS[arm_id]):
        return rules + sum(TIMING[p] - rules for p in PARTS[arm_id])
    return None


def ms_per_skill(arm: dict) -> float:
    """Time to scan one skill on its own: from the clean timing run when there is one, else the mean of each kept
    row's own time (the arm's wall time also counts skills scanned twice, so it is not divided)."""
    t = timed(base(arm["arm"]))
    return t if t is not None else sum(r["ms"] for r in arm["rows"]) / max(1, len(arm["rows"]))


def bundle_dir(r: dict) -> str:
    root = r.get("root")
    return (r["target"] if root in (None, ".") else f'{r["target"]}/{root}').rstrip("/")


def dedupe(rows: list[dict]) -> list[dict]:
    """One row per bundle directory: a nested skill scanned alone and again inside its plugin keeps the solo scan."""
    best: dict[str, dict] = {}
    for r in rows:
        d = bundle_dir(r) if r.get("root") is not None else f'{r["target"]}\0{r["bundle"]}'
        cur = best.get(d)
        if cur is None or (cur.get("root", ".") != "." and r.get("root") == "."):
            best[d] = r
    return list(best.values())


def load(results_dir: str) -> dict[str, dict]:
    arms: dict[str, dict] = {}
    for name in sorted(os.listdir(results_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(results_dir, name)) as f:
            a = json.load(f)
        if "rows" not in a:
            continue
        # scripts/benchmark-report.ts --write-derived saves configurations it computed from other runs.
        a["derived"] = bool(a.get("derived")) or name.endswith(".derived.json")
        a["rows"] = dedupe(a["rows"])
        arms[base(a["arm"])] = a
    return arms


def pct(x: float) -> str:
    v = x * 100
    if v == 0:
        return "0%"
    if v < 0.1:
        return f"{v:.2f}%"
    return f"{v:.1f}%" if v < 10 else f"{v:.0f}%"


def style_axis(ax) -> None:
    ax.set_facecolor(PAPER)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(FAINT)
    ax.spines["bottom"].set_linewidth(0.8)
    ax.tick_params(colors=MUTED, labelsize=8.5, length=0, pad=6)
    ax.grid(True, axis="x", color=GRID, linewidth=0.9)
    ax.set_axisbelow(True)


def header(fig, height: float, title: str, subtitle: str) -> float:
    """Title and subtitle at fixed distances from the top; returns the figure fraction where the panels start."""
    top = lambda inches: 1 - inches / height  # noqa: E731
    fig.text(0.012, top(0.34), title, ha="left", va="center", fontsize=15, fontweight="bold", color=INK)
    fig.text(0.012, top(0.66), subtitle, ha="left", va="center", fontsize=9.2, color=MUTED)
    fig.text(0.988, 0.10 / height, "skill-scanner benchmark: scripts/benchmark-plot.py, tables in docs/benchmark.md", fontsize=7.5, color=FAINT, ha="right")
    return top(1.25)


# ---- table: one row per configuration, every number printed


def layout_rows(arms: dict[str, dict], only: list[str] | None) -> list[tuple[str, str | None]]:
    """(arm, None) rows and (None-arm, group title) headers, top to bottom; groups with nothing to show are skipped."""
    out: list[tuple[str, str | None]] = []
    for title, members in GROUPS:
        present = [m for m in members if m in arms and (only is None or m in only)]
        if not present:
            continue
        if only is None:
            out.append(("", title))
        out.extend((m, None) for m in present)
    return out


def table_figure(arms: dict[str, dict], out: str, only: list[str] | None, note: str | None) -> None:
    rows = layout_rows(arms, only)
    n_rows = len(rows)
    height = 2.15 + 0.5 * n_rows
    fig = plt.figure(figsize=(14, height))
    fig.patch.set_facecolor(PAPER)
    first = arms[next(a for a, h in rows if h is None)]
    p0 = point(first)
    subtitle = note or f"{p0.positives:,} malicious and {p0.negatives:,} benign skills, each scanned on its own."
    top = header(fig, height, "What each skill-scanner configuration catches, and what it costs", subtitle)
    gs = fig.add_gridspec(1, 3, width_ratios=[1.35, 1.15, 1.05], wspace=0.06, left=0.2, right=0.985, top=top, bottom=0.62 / height)
    axes = [fig.add_subplot(gs[0, i]) for i in range(3)]
    ys = list(range(n_rows))[::-1]
    for ax in axes:
        style_axis(ax)
        ax.set_ylim(-0.6, n_rows - 0.4)
        ax.set_yticks([])
    # Row bands, group headers, labels.
    for y, (arm, head) in zip(ys, rows):
        if head is not None:
            axes[0].annotate(head.upper(), (0, y), xycoords=("axes fraction", "data"), xytext=(-198, -2), textcoords="offset points",
                             ha="left", va="center", fontsize=7.6, color=FAINT, fontweight="bold", annotation_clip=False)
            for ax in axes:
                ax.axhline(y - 0.42, color=GRID, linewidth=0.9, zorder=1)
            continue
        if arm in TAGS:
            for ax in axes:
                ax.axhspan(y - 0.46, y + 0.46, color=BAND, zorder=0, linewidth=0)
        a = arms[arm]
        weight = "bold" if arm in TAGS else "normal"
        axes[0].annotate(LABELS.get(arm, arm), (0, y), xycoords=("axes fraction", "data"), xytext=(-12, 3 if arm in TAGS else 0),
                         textcoords="offset points", ha="right", va="center", fontsize=10, color=INK, fontweight=weight, annotation_clip=False)
        if arm in TAGS:
            axes[0].annotate(TAGS[arm], (0, y), xycoords=("axes fraction", "data"), xytext=(-12, -8.5), textcoords="offset points",
                             ha="right", va="center", fontsize=7.4, color=CATCH, annotation_clip=False)
        elif a.get("derived"):
            axes[0].annotate("derived", (0, y), xycoords=("axes fraction", "data"), xytext=(-12, -8.5), textcoords="offset points",
                             ha="right", va="center", fontsize=7, color=FAINT, style="italic", annotation_clip=False)
    bar_h = 0.56
    hatch = lambda a: "/////" if a.get("derived") else None  # noqa: E731

    # Column 1: malicious skills caught.
    ax = axes[0]
    for y, (arm, head) in zip(ys, rows):
        if head is not None:
            continue
        a, p = arms[arm], point(arms[arm])
        ax.barh(y, p.flagged * 100, height=bar_h, color=CATCH_LIGHT, edgecolor="none", zorder=2)
        ax.barh(y, p.blocked * 100, height=bar_h, color=CATCH, edgecolor=CATCH_LIGHT if a.get("derived") else "none", hatch=hatch(a), linewidth=0, zorder=3)
        ax.annotate(f"{pct(p.flagged)}", (p.flagged * 100, y), xytext=(6, 0), textcoords="offset points", va="center",
                    fontsize=10.5, color=INK, fontweight="bold")
        ax.annotate(f"blocked {pct(p.blocked)}", (p.flagged * 100, y), xytext=(6 + 7.2 * len(pct(p.flagged)) + 6, 0), textcoords="offset points",
                    va="center", fontsize=8, color=MUTED)
    ax.set_xlim(0, 118)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_title(f"Malicious skills caught   n = {p0.positives:,}", loc="left", fontsize=10.5, fontweight="bold", color=INK, pad=10)

    # Column 2: benign skills wrongly flagged.
    ax = axes[1]
    worst = max(point(arms[a]).fp_flagged for a, h in rows if h is None)
    for y, (arm, head) in zip(ys, rows):
        if head is not None:
            continue
        a, p = arms[arm], point(arms[arm])
        ax.barh(y, p.fp_flagged * 100, height=bar_h, color=FALSE_LIGHT, edgecolor="none", zorder=2)
        ax.barh(y, p.fp_blocked * 100, height=bar_h, color=FALSE, edgecolor=FALSE_LIGHT if a.get("derived") else "none", hatch=hatch(a), linewidth=0, zorder=3)
        ax.annotate(f"{pct(p.fp_flagged)}", (p.fp_flagged * 100, y), xytext=(6, 0), textcoords="offset points", va="center",
                    fontsize=10.5, color=INK, fontweight="bold")
        ax.annotate(f"blocked {pct(p.fp_blocked)}", (p.fp_flagged * 100, y), xytext=(6 + 7.2 * len(pct(p.fp_flagged)) + 6, 0),
                    textcoords="offset points", va="center", fontsize=8, color=MUTED)
    ax.set_xlim(0, max(worst * 100, 4) * 1.65)
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_title(f"Benign skills wrongly flagged   n = {p0.negatives:,}", loc="left", fontsize=10.5, fontweight="bold", color=INK, pad=10)

    # Column 3: time per skill, and the judge's price.
    ax = axes[2]
    pers = []
    for y, (arm, head) in zip(ys, rows):
        if head is not None:
            continue
        a = arms[arm]
        v = max(1.0, ms_per_skill(a))
        pers.append(v)
        ax.barh(y, v, height=bar_h, color=TIME, edgecolor="#cbd5e1" if a.get("derived") else "none", hatch=hatch(a), linewidth=0, zorder=3, left=0.8)
        label = f"{v / 1000:.1f} s" if v >= 1000 else f"{v:.0f} ms"
        c = judge_cost_per_1000(a)
        ax.annotate(label, (v, y), xytext=(6, 0 if c is None else 4), textcoords="offset points", va="center", fontsize=9.5, color=INK)
        if c is not None:
            ax.annotate(f"+ ${c:.2f} per 1,000 skills", (v, y), xytext=(6, -7.5), textcoords="offset points", va="center", fontsize=7.6, color=FALSE)
    ax.set_xscale("log")
    hi = max(pers) * 150
    ax.set_xlim(0.8, hi)
    ticks = [t for t in (10, 100, 1000, 10000) if t <= hi]
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{t // 1000} s" if t >= 1000 else f"{t} ms" for t in ticks])
    ax.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    ax.set_title("Time per skill, and judge cost", loc="left", fontsize=10.5, fontweight="bold", color=INK, pad=10)

    legend = [
        Patch(facecolor=CATCH, label="blocked: what the hooks deny"),
        Patch(facecolor=CATCH_LIGHT, label="flagged: blocked, or a warning the prompts ask about"),
    ]
    if any(arms[a].get("derived") for a, h in rows if h is None):
        legend.append(Patch(facecolor="white", edgecolor=FAINT, hatch="/////", label="derived from other runs, not run as one configuration"))
    fig.legend(handles=legend, loc="lower left", bbox_to_anchor=(0.012, 0.02 / height * 4), ncol=len(legend), frameon=False, fontsize=8, handlelength=1.4)
    fig.savefig(out, dpi=160, facecolor=PAPER)
    print(f"wrote {out}")


# ---- scatter: the trade-off


def scatter_figure(arms: dict[str, dict], out: str, only: list[str] | None, note: str | None) -> None:
    names = [a for a, h in layout_rows(arms, only) if h is None]
    fig, ax = plt.subplots(figsize=(10.5, 6.6))
    fig.patch.set_facecolor(PAPER)
    pts = [point(arms[a]) for a in names]
    p0 = pts[0]
    top = header(fig, 6.6, "Malicious skills caught against benign skills wrongly flagged",
                 note or f"{p0.positives:,} malicious and {p0.negatives:,} benign skills. Up and to the left is better.")
    fig.subplots_adjust(top=top, bottom=0.12, left=0.08, right=0.97)
    style_axis(ax)
    ax.grid(True, axis="y", color=GRID, linewidth=0.9)
    ax.spines["left"].set_visible(True)
    ax.spines["left"].set_color(FAINT)
    for p in pts:
        c = COLORS.get(p.arm, MUTED)
        ax.plot([p.fp_blocked * 100, p.fp_flagged * 100], [p.blocked * 100, p.flagged * 100], color=c, linewidth=1.1, alpha=0.5, zorder=2)
        ax.scatter(p.fp_flagged * 100, p.flagged * 100, s=60, marker="^", color=c, alpha=0.6, edgecolor="white", linewidth=0.8, zorder=3)
        derived = arms[p.arm].get("derived")
        ax.scatter(p.fp_blocked * 100, p.blocked * 100, s=150 if derived else 95, marker="o",
                   facecolor="none" if derived else c, edgecolor=c if derived else "white", linewidth=1.8 if derived else 1.0, zorder=4)
    fig.canvas.draw()
    px_per_pt = fig.dpi / 72.0
    line_px = 11.5 * px_per_pt
    placed: list[tuple[float, float, float]] = []
    for p in sorted(pts, key=lambda p: -p.flagged):
        text = f"{LABELS.get(p.arm, p.arm)}  {pct(p.flagged)}"
        x, y = p.fp_flagged * 100, p.flagged * 100
        px, py = ax.transData.transform((x, y))
        width = len(text) * 5.5 * px_per_pt
        lx, ly = px + 9 * px_per_pt, py
        for _ in range(14):
            if not any(abs(ox - lx) < (ow + width) / 2 and abs(oy - ly) < line_px * 0.95 for ox, oy, ow in placed):
                break
            ly -= line_px
        placed.append((lx, ly, width))
        ax.annotate(text, (x, y), xytext=((lx - px) / px_per_pt, (ly - py) / px_per_pt), textcoords="offset points",
                    fontsize=8.6, color=COLORS.get(p.arm, INK), va="center")
    ax.set_xlim(-0.5, max(p.fp_flagged for p in pts) * 100 * 1.35 + 1)
    ax.set_ylim(0, 103)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_xlabel("Benign skills wrongly flagged", color=INK, fontsize=10)
    ax.set_ylabel("Malicious skills caught", color=INK, fontsize=10)
    handles = [
        Line2D([], [], marker="o", color=INK, linestyle="none", markersize=8, label="blocked"),
        Line2D([], [], marker="^", color=INK, alpha=0.6, linestyle="none", markersize=7, label="flagged (blocked or warned)"),
        Line2D([], [], marker="o", markerfacecolor="white", markeredgecolor=INK, markeredgewidth=1.6, linestyle="none", markersize=8, label="derived from other runs"),
    ]
    ax.legend(handles=handles, loc="lower right", fontsize=8, frameon=False)
    fig.savefig(out, dpi=160, facecolor=PAPER)
    print(f"wrote {out}")


# ---- value: the headline figure


# (arm, label, family): skill-scanner's own configurations in green, the judge's in teal, other tools in grey.
VALUE = [
    ("gitleaks", "skill-scanner", "ours"),
    ("jev+gitleaks", "skill-scanner with jev", "jev"),
    ("jev-only", "jev alone", "jev"),
    ("cisco-only", "Cisco skill-scanner alone", "other"),
    ("skillspector-only", "NVIDIA SkillSpector alone", "other"),
    ("all-offline", "skill-scanner + 3 offline tools", "other"),
]
FAMILY = {"ours": "#1d4ed8", "jev": "#0f766e", "other": "#94a3b8"}
# Where each label sits relative to its point, in points; chosen for these data, checked by eye.
LABEL_AT = {
    "gitleaks": (12, -13, "left"), "jev+gitleaks": (14, 8, "left"), "jev-only": (12, -3, "left"),
    "cisco-only": (12, 9, "left"), "skillspector-only": (-12, -14, "right"), "all-offline": (-12, 8, "right"),
}


def human_time(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def value_figure(arms: dict[str, dict], out: str, note: str | None) -> None:
    shown = [(a, label, fam) for a, label, fam in VALUE if a in arms]
    fig = plt.figure(figsize=(14, 6.4))
    fig.patch.set_facecolor(PAPER)
    pts = {a: point(arms[a]) for a, _, _ in shown}
    p0 = next(iter(pts.values()))
    s, j = pts.get("gitleaks"), pts.get("jev+gitleaks")
    title = (f"With jev, skill-scanner catches {pct(j.flagged)} of malicious skills it never saw, with fewer false alarms than without"
             if s and j and j.fp_flagged <= s.fp_flagged else "What each approach catches, and what it costs")
    top = header(fig, 6.4, title, note or f"{p0.positives:,} malicious and {p0.negatives:,} benign skills, each scanned on its own.")
    gs = fig.add_gridspec(1, 2, width_ratios=[1.35, 1], wspace=0.34, left=0.06, right=0.985, top=top, bottom=0.13)
    ax, bx = fig.add_subplot(gs[0, 0]), fig.add_subplot(gs[0, 1])

    # Left: caught against wrongly flagged. Up and to the left is better.
    style_axis(ax)
    ax.grid(True, axis="y", color=GRID, linewidth=0.9)
    ax.spines["left"].set_visible(True)
    ax.spines["left"].set_color(FAINT)
    xmax = max(p.fp_flagged for p in pts.values()) * 100 * 1.12 + 2
    ax.set_xlim(-1, xmax)
    ax.set_ylim(0, 100)
    ax.axvspan(-1, 2, color="#ecfdf5", zorder=0)
    ax.text(0.2, 3, "almost no\nfalse alarms", fontsize=7.6, color=CATCH, va="bottom", ha="left", linespacing=1.1)
    for a, label, fam in shown:
        p = pts[a]
        c = FAMILY[fam]
        x, y = p.fp_flagged * 100, p.flagged * 100
        big = a in ("jev+gitleaks", "gitleaks")
        ax.scatter(x, y, s=170 if big else 95, color=c, edgecolor="white", linewidth=1.5, zorder=5)
        dx, dy, ha = LABEL_AT.get(a, (10, 0, "left"))
        ax.annotate(f"{label}  {pct(p.flagged)}", (x, y), xytext=(dx, dy), textcoords="offset points", ha=ha, va="center",
                    fontsize=9.4 if big else 8.6, color=INK if fam != "other" else MUTED, fontweight="bold" if big else "normal")
    if s and j:
        ax.annotate("", xy=(j.fp_flagged * 100, j.flagged * 100 - 2.4), xytext=(s.fp_flagged * 100, s.flagged * 100 + 2.4),
                    arrowprops={"arrowstyle": "-|>", "color": "#0f766e", "linewidth": 1.6, "mutation_scale": 14}, zorder=4)
        mid = (s.flagged + j.flagged) / 2 * 100
        ax.annotate(f"adding jev: {(j.flagged - s.flagged) * 100:+.0f} points caught,\n{(j.fp_flagged - s.fp_flagged) * 100:+.1f} points of false alarms",
                    (max(s.fp_flagged, j.fp_flagged) * 100, mid), xytext=(12, 0), textcoords="offset points", ha="left", va="center",
                    fontsize=8.6, color="#0f766e", fontweight="bold")
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_xlabel(f"Benign skills wrongly flagged   (n = {p0.negatives:,})", fontsize=9.5, color=INK, labelpad=8)
    ax.set_ylabel(f"Malicious skills caught   (n = {p0.positives:,})", fontsize=9.5, color=INK, labelpad=8)
    ax.set_title("Catch more, flag less: up and to the left is better", loc="left", fontsize=11, fontweight="bold", color=INK, pad=10)
    ax.legend(handles=[
        Line2D([], [], marker="o", color=FAMILY["ours"], linestyle="none", markersize=8, label="skill-scanner's rules"),
        Line2D([], [], marker="o", color=FAMILY["jev"], linestyle="none", markersize=8, label="with TypeSafe's jev"),
        Line2D([], [], marker="o", color=FAMILY["other"], linestyle="none", markersize=8, label="other scanners"),
    ], loc="lower right", frameon=False, fontsize=8.2, title="caught = blocked or warned", title_fontsize=7.8)

    # Right: time and money to scan 1,000 skills.
    style_axis(bx)
    bx.grid(True, axis="x", color=GRID, linewidth=0.9)
    order = list(reversed(shown))
    ys = range(len(order))
    secs = [ms_per_skill(arms[a]) for a, _, _ in order]
    bx.barh(list(ys), secs, height=0.58, color=[FAMILY[f] for _, _, f in order], zorder=3, left=0)
    bx.set_xscale("log")
    bx.set_xlim(5, max(secs) * 40)
    for y, (a, label, fam), ms in zip(ys, order, secs):
        cost = judge_cost_per_1000(arms[a])
        text = human_time(ms)  # per 1,000 skills: ms per skill x 1,000 = seconds
        extra = f"   + ${cost:.2f}" if cost else "   free, offline" if fam != "other" or a != "all-offline" else "   free, offline"
        bx.annotate(text, (ms, y), xytext=(6, 0), textcoords="offset points", va="center", fontsize=9.6, color=INK, fontweight="bold")
        bx.annotate(extra.strip(), (ms, y), xytext=(6 + 7 * len(text) + 8, 0), textcoords="offset points", va="center", fontsize=8.4,
                    color="#b45309" if cost else MUTED)
    bx.set_yticks(list(ys))
    bx.set_yticklabels([label for _, label, _ in order], fontsize=8.8, color=INK)
    bx.tick_params(axis="y", pad=8)
    ticks = [t for t in (10, 60, 600, 3600) if t <= max(secs) * 40]
    bx.set_xticks(ticks)
    bx.set_xticklabels(["10 s", "1 min", "10 min", "1 h"][: len(ticks)])
    bx.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    bx.set_xlabel("Time to scan 1,000 skills, one at a time (log scale)", fontsize=9.5, color=INK, labelpad=8)
    bx.set_title("Time and money for 1,000 skills", loc="left", fontsize=11, fontweight="bold", color=INK, pad=10)
    fig.savefig(out, dpi=170, facecolor=PAPER)
    print(f"wrote {out}")


# ---- tuning: before and after, per split


SPLITS = [("train", "training"), ("val", "validation"), ("test", "test"), ("held-out", "held-out corpora")]
TUNED = [("static", "rules only"), ("jev-only", "jev alone"), ("jev", "rules + jev")]


def tuning_figure(after: dict[str, dict], before: dict[str, dict], split_of: dict[str, str], out: str) -> None:
    fig, axes = plt.subplots(1, len(TUNED), figsize=(14, 5.3), sharey=True)
    fig.patch.set_facecolor(PAPER)
    top = header(fig, 5.3, "What tuning changed, on the skills it read and on the ones it never saw",
                 "Malicious skills flagged (bars), benign skills wrongly flagged (below). Tuned on training, kept only if better on validation; "
                 "test and held-out read once, at the end.")
    fig.subplots_adjust(top=top, bottom=0.2, left=0.085, right=0.99, wspace=0.08)
    width = 0.36
    for ax, (arm, title) in zip(axes, TUNED):
        style_axis(ax)
        ax.grid(True, axis="y", color=GRID, linewidth=0.9)
        ax.grid(False, axis="x")
        for i, (split, _) in enumerate(SPLITS):
            for j, (src, color) in enumerate(((before, "#cbd5e1"), (after, CATCH))):
                a = src.get(arm)
                if a is None:
                    continue
                rows = [r for r in a["rows"] if split_of.get(bundle_dir(r)) == split]
                p = point({**a, "rows": rows})
                x = i + (j - 0.5) * width
                ax.bar(x, p.flagged * 100, width=width * 0.92, color=color, zorder=3)
                ax.annotate(pct(p.flagged), (x, p.flagged * 100), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8.6,
                            color=INK if j else MUTED, fontweight="bold" if j else "normal")
                ax.annotate(pct(p.fp_flagged), (x, 0), xytext=(0, -26), textcoords="offset points", ha="center", fontsize=7.8,
                            color=FALSE if j else FAINT, annotation_clip=False)
        ax.set_xticks(range(len(SPLITS)))
        ax.set_xticklabels([s for _, s in SPLITS], fontsize=8.6, color=INK)
        ax.tick_params(axis="x", pad=4)
        ax.set_ylim(0, 105)
        ax.set_title(title, loc="left", fontsize=11, fontweight="bold", color=INK, pad=8)
        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:.0f}%"))
    axes[0].annotate("benign flagged:", (0, 0), xycoords=("axes fraction", "data"), xytext=(-4, -26), textcoords="offset points",
                     ha="right", fontsize=7.6, color=MUTED, annotation_clip=False)
    fig.legend(handles=[Patch(facecolor="#cbd5e1", label="before tuning"), Patch(facecolor=CATCH, label="after tuning")],
               loc="lower left", bbox_to_anchor=(0.012, 0.015), ncol=2, frameon=False, fontsize=8.5)
    fig.savefig(out, dpi=160, facecolor=PAPER)
    print(f"wrote {out}")


def main() -> None:
    argv = sys.argv[1:]
    opts: dict[str, str] = {}
    for flag in ("--only", "--style", "--note", "--before", "--map", "--timing"):
        if flag in argv:
            i = argv.index(flag)
            opts[flag] = argv[i + 1]
            argv = argv[:i] + argv[i + 2 :]
    style = opts.get("--style", "table")
    if len(argv) != 2 or style not in ("table", "scatter", "tuning", "value"):
        sys.exit(__doc__)
    plt.rcParams["font.family"] = ["IBM Plex Sans", "DejaVu Sans", "sans-serif"]
    if "--timing" in opts:
        TIMING.update({k: sum(r["ms"] for r in a["rows"]) / max(1, len(a["rows"])) for k, a in load(opts["--timing"]).items()})
    arms = load(argv[0])
    if not arms:
        sys.exit(f"no results in {argv[0]}")
    only = opts["--only"].split(",") if "--only" in opts else None
    if style == "tuning":
        if "--before" not in opts or "--map" not in opts:
            sys.exit("--style tuning needs --before <dir> and --map <splits.json>")
        with open(opts["--map"]) as f:
            split_of = json.load(f)
        tuning_figure(arms, load(opts["--before"]), split_of, argv[1])
    elif style == "value":
        value_figure(arms, argv[1], opts.get("--note"))
    elif style == "scatter":
        scatter_figure(arms, argv[1], only, opts.get("--note"))
    else:
        table_figure(arms, argv[1], only, opts.get("--note"))


if __name__ == "__main__":
    main()
