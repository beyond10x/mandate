"""Render the single-sign-on sequence figure used by federated-login-approval.tex."""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HEAD, TEXT, MUTED, LINE, CYAN, LIME, MUTEDBG = "#08131e", "#1c2932", "#52616a", "#898b88", "#1686a1", "#8ebf3d", "#eae7de"
actors = ["User's browser", "Your identity\nprovider", "Mandate", "Your\napplication", "Mandate-protected\nservice"]
xs = [0.08, 0.29, 0.50, 0.71, 0.92]
steps = [
    (0, 1, "signs in to your platform", CYAN),
    (1, 0, "signed proof of identity", CYAN),
    (0, 2, "presents the proof", HEAD),
    (2, 2, "verifies issuer, signature, client,\ntenant claim; first visit: creates account", HEAD),
    (2, 0, "session established", HEAD),
    (0, 2, "requests a token for your application (PKCE)", HEAD),
    (2, 3, "short-lived Mandate token, one audience", LIME),
    (3, 4, "calls the service with the token", LIME),
    (4, 2, "checks the token with Mandate", MUTED),
    (2, 4, "active / inactive", MUTED),
    (4, 3, "response", LIME),
]
fig, ax = plt.subplots(figsize=(7.6, 5.4), dpi=220)
ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
for x, a in zip(xs, actors):
    ax.add_patch(plt.Rectangle((x - 0.085, 0.9), 0.17, 0.085, fc=MUTEDBG, ec=HEAD, lw=1.0))
    ax.text(x, 0.9425, a, ha="center", va="center", fontsize=7.2, color=HEAD, fontweight="bold")
    ax.plot([x, x], [0.9, 0.03], color=LINE, lw=0.8, ls=(0, (3, 3)), zorder=0)
y = 0.845
for src, dst, label, color in steps:
    if src == dst:
        ax.add_patch(plt.Rectangle((xs[src] - 0.008, y - 0.052), 0.016, 0.06, fc=color, ec=color))
        ax.text(xs[src] + 0.02, y - 0.02, label, ha="left", va="center", fontsize=6.4, color=TEXT)
        y -= 0.085; continue
    x0, x1 = xs[src], xs[dst]
    ax.annotate("", xy=(x1, y), xytext=(x0, y), arrowprops=dict(arrowstyle="-|>", lw=1.1, color=color, shrinkA=0, shrinkB=0))
    ax.text((x0 + x1) / 2, y + 0.012, label, ha="center", va="bottom", fontsize=6.6, color=TEXT)
    y -= 0.072
fig.savefig(sys.argv[1], bbox_inches="tight", pad_inches=0.05)
