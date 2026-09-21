#!/usr/bin/env python3
"""Static report figures; run with uv run --with matplotlib python .../plot.py."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[1] / "docs/assets/oss-study-2026-09-21"
OUT.mkdir(parents=True, exist_ok=True)
summary = json.loads((HERE / "summary.json").read_text())
accuracy = json.loads((HERE / "accuracy.json").read_text())
colors = {"pleno-dlp": "#2166ac", "trufflehog": "#c75b12"}
plt.rcParams.update({"font.size": 10, "svg.fonttype": "none", "axes.spines.top": False, "axes.spines.right": False})

fig, axes = plt.subplots(1, 2, figsize=(12, 5.5), layout="constrained")
for tool, color in colors.items():
    sizes = [row["bytes"] / 2**20 for row in summary["rows"]]
    for ax, metric, scale in ((axes[0], "seconds", 1), (axes[1], "rss_bytes", 2**20)):
        ax.scatter(sizes, [row["tools"][tool][metric] / scale for row in summary["rows"]],
                   label=tool, color=color, s=30, alpha=0.8)
        ax.set_xscale("log")
        ax.set_xlabel("Retained source input (MiB, log scale)")
        ax.grid(alpha=0.2)
        ax.set_axisbelow(True)
axes[0].set_yscale("log")
axes[0].set_ylabel("Wall time (seconds, log scale)")
axes[0].set_title("Time: median of 3 measured scans")
axes[1].set_ylabel("Peak RSS (MiB)")
axes[1].set_title("Memory: median of 3 process peaks")
axes[0].legend(frameon=False)
fig.suptitle(f"{summary['repositories']} OSS snapshots / {summary['files']:,} files / {summary['bytes']/2**30:.2f} GiB\n"
             "Shared-load reference: pleno-dlp v0.65.0 source build vs TruffleHog v3.97.5", fontsize=13)
fig.savefig(OUT / "performance.svg")
fig.savefig(HERE.parents[0] / ".cache/oss-study/performance.png", dpi=150)
plt.close(fig)

fig, ax = plt.subplots(figsize=(9, 5), layout="constrained")
keys = ("precision_on_labelled_lines", "recall_on_labelled_lines", "f1_on_labelled_lines")
for offset, (tool, color) in zip((-0.19, 0.19), colors.items()):
    scores = [accuracy["tools"][tool]["score"][k] for k in keys]
    values = [v * 100 if v is not None else 0 for v in scores]
    bars = ax.bar([i + offset for i in range(3)], values, width=0.36, label=tool, color=color)
    ax.bar_label(bars, labels=[f"{v * 100:.2f}%" if v is not None else "N/A" for v in scores], padding=4)
ax.set_xticks(range(3), ["Precision*", "Recall", "F1*"])
ax.set_ylim(0, 110)
ax.set_ylabel("Percent")
ax.set_title("CredData: 100 pinned repositories, labelled line-start classification\n* Conditional on labelled lines; unlabelled detections excluded", pad=16)
ax.grid(axis="y", alpha=0.2)
ax.set_axisbelow(True)
ax.legend(frameon=False, loc="upper right")
fig.savefig(OUT / "accuracy.svg")
fig.savefig(HERE.parents[0] / ".cache/oss-study/accuracy.png", dpi=150)
plt.close(fig)
for path in OUT.glob("*.svg"):
    path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines()) + "\n")
print("matplotlib", matplotlib.__version__)
