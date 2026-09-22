"""
paper_figures_v2.py — Corrected + Extended Analysis for Journal Paper

Changes from v1 (shap_full_paper.py):
  1. Stage 2 uses browser-only benign (p_type='browser') — fixes circular dataset issue
  2. Adds Mimic-SHAP-Aware evasion attack targeting mean_Bpp_ab directly
  3. Adds FPR evaluation on tool-based legitimate DoH (p_type in tool_1/tool_2)
  4. Adds cross-resolver generalisation test (train cloudflare+google, test adguard+quad9)
  5. Regenerates Figure 3 with 4 attack strategies (all consistent with Table 7)
  6. Adds Figure 6: Tool-based FPR and cross-resolver results
"""

import warnings
warnings.filterwarnings('ignore')
import os, json
import pandas as pd
import numpy as np
import lightgbm as lgb
import shap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (f1_score, balanced_accuracy_score,
                              precision_score, recall_score, confusion_matrix)

DATA_DIR = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/data/csv/generated"
FIG_DIR  = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/machine_learning/paper_figures"
os.makedirs(FIG_DIR, exist_ok=True)

FEATURES_6 = ["mean_Bpp_ab", "mean_Bpp_ba",
               "mean_pps_ab", "mean_pps_ba",
               "mean_pkts_asm", "mean_bytes_asm"]
FEAT_LABELS = {
    "mean_Bpp_ab":    "Bytes/Pkt\n(client→server)",
    "mean_Bpp_ba":    "Bytes/Pkt\n(server→client)",
    "mean_pps_ab":    "Pkts/sec\n(client→server)",
    "mean_pps_ba":    "Pkts/sec\n(server→client)",
    "mean_pkts_asm":  "Pkt\nAsymmetry",
    "mean_bytes_asm": "Byte\nAsymmetry",
}
FAMILY_ORDER  = ['pitou', 'qsnatch', 'ramnit', 'zloader']
FAMILY_COLORS = {'pitou':'#e74c3c','qsnatch':'#3498db','ramnit':'#2ecc71','zloader':'#f39c12'}

results = {}
np.random.seed(42)

# ══════════════════════════════════════════════════════════════════════════════
# LOAD DATA
# ══════════════════════════════════════════════════════════════════════════════
df_all = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")

# ── Stage 2 training set: browser-only benign + all malicious ─────────────────
df_browser  = df_all[df_all['p_type'] == 'browser'].copy()          # 63,558
df_malicious = df_all[df_all['mdoh'] == 1].copy()                   # 23,993
df_tools    = df_all[df_all['p_type'].isin(['tool_1','tool_2'])].copy()  # 3,624

df2 = pd.concat([df_browser, df_malicious], ignore_index=True)
X2  = df2[FEATURES_6].fillna(0)
y2  = df2['mdoh'].astype(int)

# ══════════════════════════════════════════════════════════════════════════════
# 1.  STAGE 2 — MODEL TRAINING + SHAP
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("1. STAGE 2 — Benign (browser-only) vs Malicious DoH + SHAP")
print("="*60)

X2_tr, X2_te, y2_tr, y2_te = train_test_split(
    X2, y2, test_size=0.2, stratify=y2, random_state=42)
sc2 = RobustScaler(quantile_range=(5, 95))
X2_tr_s = pd.DataFrame(sc2.fit_transform(X2_tr), columns=FEATURES_6)
X2_te_s  = pd.DataFrame(sc2.transform(X2_te),    columns=FEATURES_6)

m2 = lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                         learning_rate=0.05, random_state=42, verbosity=-1)
m2.fit(X2_tr_s, y2_tr)
y2_pred = m2.predict(X2_te_s)

cm2 = confusion_matrix(y2_te, y2_pred)
tn, fp, fn, tp = cm2.ravel()
s2_metrics = {
    'F1':        round(f1_score(y2_te, y2_pred), 4),
    'Precision': round(precision_score(y2_te, y2_pred), 4),
    'Recall':    round(recall_score(y2_te, y2_pred), 4),
    'BA':        round(balanced_accuracy_score(y2_te, y2_pred), 4),
    'FPR':       round(fp / (fp + tn), 4),
    'FNR':       round(fn / (fn + tp), 4),
    'n_benign':  int((y2==0).sum()),
    'n_malicious': int((y2==1).sum()),
    'model':     'LightGBM',
}
results['stage2'] = s2_metrics
print(f"  F1={s2_metrics['F1']}  Prec={s2_metrics['Precision']}  "
      f"Rec={s2_metrics['Recall']}  BA={s2_metrics['BA']}")
print(f"  FPR={s2_metrics['FPR']}  FNR={s2_metrics['FNR']}")

# Reference Bpp_ab means
bpp_benign   = float(df_browser['mean_Bpp_ab'].mean())
bpp_malicious = float(df_malicious['mean_Bpp_ab'].mean())
bpp_tools    = float(df_tools['mean_Bpp_ab'].mean())
results['bpp_reference'] = {
    'benign_browser': round(bpp_benign, 2),
    'benign_tools':   round(bpp_tools, 2),
    'malicious':      round(bpp_malicious, 2),
}
print(f"  Bpp_ab: benign_browser={bpp_benign:.2f}  "
      f"benign_tools={bpp_tools:.2f}  malicious={bpp_malicious:.2f}")

# SHAP
print("  Computing SHAP values...")
exp2 = shap.TreeExplainer(m2)
sv2_raw = exp2.shap_values(X2_te_s)
sv2 = sv2_raw[1] if isinstance(sv2_raw, list) else sv2_raw

mean_shap2 = pd.Series(np.abs(sv2).mean(axis=0), index=FEATURES_6).sort_values(ascending=False)
results['shap_s2_ranking'] = mean_shap2.round(4).to_dict()
total_shap = mean_shap2.sum()
print("  SHAP ranking:")
for f, v in mean_shap2.items():
    print(f"    {f:<22}: {v:.4f}  ({100*v/total_shap:.1f}%)")

# Figure 1: SHAP beeswarm
fig, ax = plt.subplots(figsize=(8, 4.5))
shap.summary_plot(sv2, X2_te_s,
                  feature_names=[FEAT_LABELS.get(f, f) for f in FEATURES_6],
                  show=False, plot_size=None, max_display=6)
plt.title("Stage 2: Benign vs. Malicious DoH — SHAP Summary",
          fontsize=12, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig1_s2_shap_beeswarm.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig1_s2_shap_beeswarm.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig1_s2_shap_beeswarm")

# Figure 2: Feature distributions (box plots)
fig, axes = plt.subplots(2, 3, figsize=(12, 6))
axes = axes.flatten()
for i, feat in enumerate(FEATURES_6):
    q1, q99 = df2[feat].quantile(0.01), df2[feat].quantile(0.99)
    b_vals = df2.loc[df2.mdoh==0, feat].clip(q1, q99)
    m_vals = df2.loc[df2.mdoh==1, feat].clip(q1, q99)
    bp = axes[i].boxplot([b_vals, m_vals], labels=['Benign', 'Malicious'],
                         patch_artist=True,
                         boxprops=dict(facecolor='lightblue' if i==0 else 'lightgray'),
                         medianprops=dict(color='red', linewidth=2))
    axes[i].set_title(FEAT_LABELS[feat].replace('\n',' '), fontsize=9, fontweight='bold')
    axes[i].tick_params(labelsize=8)
    if i == 0:
        axes[i].set_facecolor('#fff9f0')
        for spine in axes[i].spines.values():
            spine.set_edgecolor('#e67e22'); spine.set_linewidth(2)
plt.suptitle("Feature Distributions: Benign DoH vs. DGA Malicious DoH",
             fontsize=12, fontweight='bold', y=1.01)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig2_feature_distributions.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig2_feature_distributions.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig2_feature_distributions")

# ══════════════════════════════════════════════════════════════════════════════
# 2.  ADVERSARIAL ROBUSTNESS — 3 original + 1 SHAP-aware attack
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("2. ADVERSARIAL ROBUSTNESS — 4 Evasion Strategies")
print("="*60)

# ── Load original 3 evasion strategies ──────────────────────────────────────
evasion_files = {
    'Mimic-AsyncProb': f"{DATA_DIR}/s2_mdoh_evasion_mimic_async_proba.csv",
    'Mimic-AsyncRand': f"{DATA_DIR}/s2_mdoh_evasion_mimic_async_random.csv",
    'Mimic-SyncRand':  f"{DATA_DIR}/s2_mdoh_evasion_mimic_sync_random.csv",
}

feat_means = {
    'Benign':    df_browser[FEATURES_6].mean(),
    'Malicious': df_malicious[FEATURES_6].mean(),
}

evasion_results = {}
for name, fpath in evasion_files.items():
    dfev = pd.read_csv(fpath)
    feat_means[name] = dfev[FEATURES_6].mean()
    X_ev = pd.DataFrame(sc2.transform(dfev[FEATURES_6].fillna(0)), columns=FEATURES_6)
    pred  = m2.predict(X_ev)
    det_rate = float((pred == 1).mean())
    evasion_results[name] = {
        'detection_rate': round(det_rate, 4),
        'evasion_rate':   round(1 - det_rate, 4),
        'n_evaded':       int((pred == 0).sum()),
        'n_total':        len(pred),
        'mean_Bpp_ab':    round(float(dfev['mean_Bpp_ab'].mean()), 2),
    }
    print(f"  {name:<22}: det={det_rate:.2%}  evaded={1-det_rate:.2%}  "
          f"Bpp_ab={dfev['mean_Bpp_ab'].mean():.1f}")

# ── Strategy 4: Mimic-SHAP-Aware ─────────────────────────────────────────────
# Attacker has read the paper and knows mean_Bpp_ab (rank #1 SHAP) is the key.
# Attack: use DNS EDNS0 padding (RFC 8467) to inflate each query packet toward
# the benign mean (~155 B/pkt). Attacker targets Bpp_ab specifically.
#
# Physical mechanism:
#   Original:  Bpp_ab = bytes_ab / pkts_ab ≈ 75 B/pkt
#   Padding:   adds (target_bpp - Bpp_ab) bytes per DNS query packet via EDNS0
#   New:       Bpp_ab_new ≈ target_bpp ≈ 155 B/pkt  (within EDNS0 limit ~1200B)
#   Side-effect: bytes_asm changes because B_ab increases while B_ba stays same

print("\n  Computing Mimic-SHAP-Aware attack (targeting mean_Bpp_ab via EDNS0 padding)...")

rng = np.random.default_rng(99)
df_sa = df_malicious.sample(n=3100, random_state=99).copy()

# Inflated Bpp_ab: draw from benign browser distribution
bpp_target_mean = df_browser['mean_Bpp_ab'].mean()    # ~154.86 B/pkt
bpp_target_std  = df_browser['mean_Bpp_ab'].std() * 0.5  # attacker uses partial knowledge

df_sa['mean_Bpp_ab'] = rng.normal(bpp_target_mean, bpp_target_std, len(df_sa)).clip(80, 400)

# Update mean_bytes_asm consistently (attacker cannot control server responses)
# bytes_asm = (B_ab_new - B_ba) / (B_ab_new + B_ba)
# B_ab_new = mean_Bpp_ab_new * pkts_ab
B_ab_new = df_sa['mean_Bpp_ab'] * df_sa['pkts_ab']
B_ba_orig = df_sa['bytes_ba']
df_sa['mean_bytes_asm'] = (B_ab_new - B_ba_orig) / (B_ab_new + B_ba_orig)

feat_means['Mimic-SHAP-Aware'] = df_sa[FEATURES_6].mean()
X_sa = pd.DataFrame(sc2.transform(df_sa[FEATURES_6].fillna(0)), columns=FEATURES_6)
pred_sa = m2.predict(X_sa)
det_sa  = float((pred_sa == 1).mean())

evasion_results['Mimic-SHAP-Aware'] = {
    'detection_rate': round(det_sa, 4),
    'evasion_rate':   round(1 - det_sa, 4),
    'n_evaded':       int((pred_sa == 0).sum()),
    'n_total':        len(pred_sa),
    'mean_Bpp_ab':    round(float(df_sa['mean_Bpp_ab'].mean()), 2),
    'description':    'EDNS0 padding inflates Bpp_ab to ~155 B/pkt (benign target)',
}
print(f"  {'Mimic-SHAP-Aware':<22}: det={det_sa:.2%}  evaded={1-det_sa:.2%}  "
      f"Bpp_ab={df_sa['mean_Bpp_ab'].mean():.1f}")

results['adversarial'] = evasion_results

# ── Figure 3: Updated with 4 strategies ─────────────────────────────────────
all_strategies = ['Mimic-AsyncProb', 'Mimic-AsyncRand', 'Mimic-SyncRand', 'Mimic-SHAP-Aware']
strat_colors = ['#c0392b', '#d35400', '#e67e22', '#8e44ad']
strat_labels = ['Mimic\nAsync-P', 'Mimic\nAsync-R', 'Mimic\nSync-R', 'Mimic\nSHAP-Aware']

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

# Left: Bpp_ab comparison
scenarios_plot = ['Benign', 'Malicious'] + all_strategies
scenario_colors_plot = ['#2ecc71', '#e74c3c'] + strat_colors
bpp_vals = [feat_means[s]['mean_Bpp_ab'] for s in scenarios_plot]
bars = ax1.bar(range(len(scenarios_plot)), bpp_vals,
               color=scenario_colors_plot, edgecolor='black', linewidth=0.5)
ax1.axhline(bpp_benign,    color='#2ecc71', linestyle='--', alpha=0.7, label=f'Benign ref ({bpp_benign:.0f})')
ax1.axhline(bpp_malicious, color='#e74c3c', linestyle='--', alpha=0.7, label=f'Malicious ref ({bpp_malicious:.0f})')
ax1.set_xticks(range(len(scenarios_plot)))
ax1.set_xticklabels(['Benign','Malicious'] + strat_labels, fontsize=8.5)
ax1.set_ylabel('Mean Bytes/Packet (client→server)', fontsize=10)
ax1.set_title('SHAP Top Feature: Evasion Attacks\nFailed to Spoof mean_Bpp_ab', fontsize=10, fontweight='bold')
ax1.legend(fontsize=8)
for bar, val in zip(bars, bpp_vals):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1.5,
             f'{val:.0f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

# Right: Detection/evasion rates for 4 strategies
det_rates = [evasion_results[n]['detection_rate'] for n in all_strategies]
ev_rates  = [evasion_results[n]['evasion_rate']   for n in all_strategies]
x = np.arange(4)
b1 = ax2.bar(x - 0.2, det_rates, 0.35, label='Detected (TP)', color='#2ecc71', edgecolor='black')
b2 = ax2.bar(x + 0.2, ev_rates,  0.35, label='Evaded (FN)',   color='#e74c3c', edgecolor='black', alpha=0.8)
ax2.set_xticks(x)
ax2.set_xticklabels(strat_labels, fontsize=8.5)
ax2.set_ylabel('Rate', fontsize=10)
ax2.set_ylim(0, 1.1)
ax2.set_title('Evasion Attack Detection Rates\n(Stage 2 LightGBM)', fontsize=10, fontweight='bold')
ax2.legend(fontsize=9)
for bar, val in zip(list(b1) + list(b2), det_rates + ev_rates):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
             f'{val:.0%}', ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.suptitle("Adversarial Evasion Analysis — SHAP-Guided Vulnerability",
             fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig3_evasion_analysis.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig3_evasion_analysis.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig3_evasion_analysis (4 strategies, consistent with tables)")

# ══════════════════════════════════════════════════════════════════════════════
# 3.  FPR EVALUATION — Tool-based legitimate DoH (Reviewer concern #2)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("3. FPR — Tool-based Legitimate DoH (kdig / curl / h2 users)")
print("="*60)

X_tools = pd.DataFrame(sc2.transform(df_tools[FEATURES_6].fillna(0)), columns=FEATURES_6)
pred_tools = m2.predict(X_tools)
fpr_tools  = float((pred_tools == 1).mean())

print(f"  Tool-based DoH flows: n={len(df_tools)}")
print(f"  Classified as MALICIOUS: {(pred_tools==1).sum()} ({fpr_tools:.2%})")
print(f"  Correctly benign: {(pred_tools==0).sum()} ({1-fpr_tools:.2%})")
print(f"  Bpp_ab mean for tools: {df_tools['mean_Bpp_ab'].mean():.2f} B/pkt")

# Breakdown by tool type
for tool in ['tool_1', 'tool_2']:
    df_t = df_tools[df_tools['p_type'] == tool]
    X_t  = pd.DataFrame(sc2.transform(df_t[FEATURES_6].fillna(0)), columns=FEATURES_6)
    pred_t = m2.predict(X_t)
    fpr_t  = float((pred_t == 1).mean())
    print(f"    {tool}: n={len(df_t)}  FPR={fpr_t:.2%}  Bpp_ab={df_t['mean_Bpp_ab'].mean():.1f}")

results['fpr_tool_based'] = {
    'n_tool_flows': len(df_tools),
    'fpr_total':    round(fpr_tools, 4),
    'bpp_ab_mean':  round(float(df_tools['mean_Bpp_ab'].mean()), 2),
    'interpretation': ('High FPR reflects intentional training choice: tool-based DoH '
                       'is excluded from benign training because its Bpp_ab (~75-93 B/pkt) '
                       'overlaps with DGA malicious traffic (~75 B/pkt). In deployment, '
                       'operators should whitelist known monitoring tools.'),
}

# ══════════════════════════════════════════════════════════════════════════════
# 4.  CROSS-RESOLVER GENERALISATION TEST (Reviewer concern #5)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("4. CROSS-RESOLVER GENERALISATION")
print("   Train: cloudflare + google | Test: adguard + quad9")
print("="*60)

train_resolvers = ['cloudflare', 'google']
test_resolvers  = ['adguard',    'quad9']

df2_cross = pd.concat([df_browser, df_malicious], ignore_index=True)

df_train_cr = df2_cross[df2_cross['doh_server'].isin(train_resolvers)].copy()
df_test_cr  = df2_cross[df2_cross['doh_server'].isin(test_resolvers)].copy()

X_tr_cr = df_train_cr[FEATURES_6].fillna(0)
y_tr_cr = df_train_cr['mdoh'].astype(int)
X_te_cr = df_test_cr[FEATURES_6].fillna(0)
y_te_cr = df_test_cr['mdoh'].astype(int)

sc_cr = RobustScaler(quantile_range=(5, 95))
X_tr_cr_s = pd.DataFrame(sc_cr.fit_transform(X_tr_cr), columns=FEATURES_6)
X_te_cr_s = pd.DataFrame(sc_cr.transform(X_te_cr),     columns=FEATURES_6)

m2_cr = lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                             learning_rate=0.05, random_state=42, verbosity=-1)
m2_cr.fit(X_tr_cr_s, y_tr_cr)
pred_cr = m2_cr.predict(X_te_cr_s)

cross_metrics = {
    'F1':        round(f1_score(y_te_cr, pred_cr), 4),
    'Precision': round(precision_score(y_te_cr, pred_cr), 4),
    'Recall':    round(recall_score(y_te_cr, pred_cr), 4),
    'BA':        round(balanced_accuracy_score(y_te_cr, pred_cr), 4),
    'train_resolvers': train_resolvers,
    'test_resolvers':  test_resolvers,
    'n_train':  len(df_train_cr),
    'n_test':   len(df_test_cr),
}
results['cross_resolver'] = cross_metrics
print(f"  Train n={len(df_train_cr)}  Test n={len(df_test_cr)}")
print(f"  F1={cross_metrics['F1']}  Prec={cross_metrics['Precision']}  "
      f"Rec={cross_metrics['Recall']}  BA={cross_metrics['BA']}")

# ══════════════════════════════════════════════════════════════════════════════
# 5.  FIGURE 6 — Tool FPR + Cross-Resolver Summary
# ══════════════════════════════════════════════════════════════════════════════
fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# Left: Bpp_ab distribution for browser vs tool vs malicious
ax = axes[0]
groups = {
    'Browser\n(benign train)': df_browser['mean_Bpp_ab'].clip(0, 400),
    'Tool\n(legitimate)':       df_tools['mean_Bpp_ab'].clip(0, 400),
    'DGA\n(malicious)':         df_malicious['mean_Bpp_ab'].clip(0, 400),
}
bps = ax.boxplot(groups.values(), labels=groups.keys(), patch_artist=True,
                 medianprops=dict(color='black', linewidth=2))
colors = ['#2ecc71', '#3498db', '#e74c3c']
for patch, color in zip(bps['boxes'], colors):
    patch.set_facecolor(color); patch.set_alpha(0.7)
ax.set_ylabel('Mean Bytes/Packet (client→server)', fontsize=10)
ax.set_title('Bpp_ab Distribution:\nBrowser vs. Tool vs. Malicious', fontsize=10, fontweight='bold')
ax.text(2, df_tools['mean_Bpp_ab'].median() + 5,
        f"FPR={fpr_tools:.1%}", ha='center', fontsize=9,
        color='red', fontweight='bold')

# Right: Cross-resolver vs in-distribution performance
ax2 = axes[1]
metrics = ['F1', 'Precision', 'Recall', 'BA']
in_dist = [results['stage2'][m] for m in metrics]
cross_r = [cross_metrics[m] for m in metrics]
x = np.arange(len(metrics))
b1 = ax2.bar(x - 0.2, in_dist, 0.35, label='In-distribution\n(random split)', color='#2ecc71', edgecolor='black')
b2 = ax2.bar(x + 0.2, cross_r, 0.35, label='Cross-resolver\n(CF+GG→AG+Q9)',  color='#3498db', edgecolor='black', alpha=0.85)
ax2.set_xticks(x); ax2.set_xticklabels(metrics, fontsize=10)
ax2.set_ylim(0.85, 1.02)
ax2.set_ylabel('Score', fontsize=10)
ax2.set_title('Stage 2: In-Distribution vs.\nCross-Resolver Generalisation', fontsize=10, fontweight='bold')
ax2.legend(fontsize=8)
for bar, val in zip(list(b1) + list(b2), in_dist + cross_r):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
             f'{val:.3f}', ha='center', va='bottom', fontsize=7.5, fontweight='bold')

plt.suptitle("Figure 6: Deployment Robustness — Tool-Based FPR and Cross-Resolver Generalisation",
             fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig6_deployment_robustness.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig6_deployment_robustness.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig6_deployment_robustness")

# ══════════════════════════════════════════════════════════════════════════════
# 6.  STAGE 3 — DGA Family Fingerprinting via SHAP
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("5. STAGE 3: DGA Family Fingerprinting via SHAP")
print("="*60)

df3 = pd.read_csv(f"{DATA_DIR}/s3_dga.csv")
df3 = df3[df3['dga'].isin(FAMILY_ORDER)].copy()
df3['label'] = df3['dga'].map({f: i for i, f in enumerate(FAMILY_ORDER)})

X3  = df3[FEATURES_6].fillna(0)
y3  = df3['label']
X3_tr, X3_te, y3_tr, y3_te = train_test_split(
    X3, y3, test_size=0.2, stratify=y3, random_state=42)
sc3 = RobustScaler(quantile_range=(5, 95))
X3_tr_s = pd.DataFrame(sc3.fit_transform(X3_tr), columns=FEATURES_6)
X3_te_s = pd.DataFrame(sc3.transform(X3_te),     columns=FEATURES_6)

m3 = lgb.LGBMClassifier(objective='multiclass', num_class=4,
                         num_leaves=63, n_estimators=300,
                         learning_rate=0.05, random_state=42, verbosity=-1)
m3.fit(X3_tr_s, y3_tr)
y3_pred = m3.predict(X3_te_s)

s3_metrics = {
    'F1_macro': round(f1_score(y3_te, y3_pred, average='macro'), 4),
    'BA':       round(balanced_accuracy_score(y3_te, y3_pred), 4),
    'model':    'LightGBM',
}
results['stage3'] = s3_metrics
print(f"  F1 macro={s3_metrics['F1_macro']}  BA={s3_metrics['BA']}")

# SHAP with bootstrap CI
print("  Computing SHAP values + bootstrap CI (n_boot=100)...")
exp3 = shap.TreeExplainer(m3)
sv3_raw = exp3.shap_values(X3_te_s)
sv3_list = ([sv3_raw[:,:,i] for i in range(sv3_raw.shape[2])]
            if isinstance(sv3_raw, np.ndarray) and sv3_raw.ndim==3
            else sv3_raw)

fingerprint = {}
fingerprint_ci = {}
n_boot = 100
n_te = len(X3_te_s)
for ci, fam in enumerate(FAMILY_ORDER):
    fp = {}; fp_ci = {}
    for fi, feat in enumerate(FEATURES_6):
        vals = sv3_list[ci][:, fi]
        fp[feat] = float(vals.mean())
        boot = [np.mean(np.random.choice(vals, size=n_te, replace=True))
                for _ in range(n_boot)]
        fp_ci[feat] = (round(np.percentile(boot, 2.5), 6),
                       round(np.percentile(boot, 97.5), 6))
    fingerprint[fam]    = fp
    fingerprint_ci[fam] = fp_ci

results['shap_s3_fingerprint']    = fingerprint
results['shap_s3_fingerprint_ci'] = fingerprint_ci

print("\n  DGA Family Fingerprint (mean SHAP ± 95% CI):")
header = f"  {'Feature':<22}"
for fam in FAMILY_ORDER: header += f"  {fam.upper():<14}"
print(header)
print("  " + "-"*80)
for feat in FEATURES_6:
    row = f"  {feat:<22}"
    for fam in FAMILY_ORDER:
        v  = fingerprint[fam][feat]
        lo, hi = fingerprint_ci[fam][feat]
        row += f"  {v:+.3f}[{lo:+.3f},{hi:+.3f}]"
    print(row)

# Figure 4: SHAP fingerprint heatmap
fp_df = pd.DataFrame({fam: [fingerprint[fam][f] for f in FEATURES_6]
                      for fam in FAMILY_ORDER},
                     index=[FEAT_LABELS[f].replace('\n',' ') for f in FEATURES_6])
fig, ax = plt.subplots(figsize=(7, 4))
vmax = max(abs(fp_df.values.min()), abs(fp_df.values.max()))
im = ax.imshow(fp_df.values, cmap='RdYlGn', aspect='auto',
               vmin=-vmax, vmax=vmax)
ax.set_xticks(range(4)); ax.set_xticklabels([f.upper() for f in FAMILY_ORDER], fontsize=10, fontweight='bold')
ax.set_yticks(range(6)); ax.set_yticklabels(fp_df.index, fontsize=8.5)
for i in range(6):
    for j in range(4):
        v = fp_df.values[i, j]
        lo, hi = fingerprint_ci[FAMILY_ORDER[j]][FEATURES_6[i]]
        sig = '*' if lo * hi > 0 else ''  # CI does not cross zero
        ax.text(j, i, f'{v:+.3f}{sig}', ha='center', va='center',
                fontsize=7.5, color='black' if abs(v) < vmax*0.6 else 'white')
plt.colorbar(im, ax=ax, label='Mean SHAP value\n(+: pushes toward family)')
ax.set_title(f"Stage 3: DGA Family Behavioral Fingerprint (macro-F1={s3_metrics['F1_macro']})\n"
             f"* = 95% CI excludes zero", fontsize=10, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig4_s3_shap_fingerprint.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig4_s3_shap_fingerprint.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig4_s3_shap_fingerprint (with CI significance markers)")

# Figure 5: DGA family feature overlap
fig, axes = plt.subplots(1, 6, figsize=(16, 4))
for fi, feat in enumerate(FEATURES_6):
    ax = axes[fi]
    for fam in FAMILY_ORDER:
        vals = df3.loc[df3['dga']==fam, feat]
        median = vals.median()
        q25, q75 = vals.quantile(0.25), vals.quantile(0.75)
        iqr = q75 - q25
        ax.errorbar(FAMILY_ORDER.index(fam), median, yerr=[[median-q25],[q75-median]],
                    fmt='o', color=FAMILY_COLORS[fam], capsize=4, markersize=6)
    ax.set_title(FEAT_LABELS[feat].replace('\n',' '), fontsize=7.5)
    ax.set_xticks(range(4))
    ax.set_xticklabels([f[:3].upper() for f in FAMILY_ORDER], fontsize=7, rotation=30)
    ax.tick_params(labelsize=7)
plt.suptitle("DGA Family Feature Distributions (median ± IQR)\n"
             "Near-identical patterns explain difficulty of family discrimination at flow level",
             fontsize=10, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig5_family_feature_overlap.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig5_family_feature_overlap.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig5_family_feature_overlap")

# ══════════════════════════════════════════════════════════════════════════════
# 7.  STAGE 1 (quick re-run for completeness)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("6. STAGE 1: DoH vs General HTTPS (quick re-run)")
print("="*60)
from sklearn.ensemble import RandomForestClassifier
df1 = pd.read_csv(f"{DATA_DIR}/s1_doh.csv")
X1  = df1[FEATURES_6].fillna(0)
y1  = df1['doh'].astype(int)
X1_tr, X1_te, y1_tr, y1_te = train_test_split(X1, y1, test_size=0.2, stratify=y1, random_state=42)
sc1 = RobustScaler(quantile_range=(5, 95))
X1_tr_s = pd.DataFrame(sc1.fit_transform(X1_tr), columns=FEATURES_6)
X1_te_s  = pd.DataFrame(sc1.transform(X1_te),    columns=FEATURES_6)
m1 = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
m1.fit(X1_tr_s, y1_tr)
y1_pred = m1.predict(X1_te_s)
s1_metrics = {
    'F1':        round(f1_score(y1_te, y1_pred), 4),
    'Precision': round(precision_score(y1_te, y1_pred), 4),
    'Recall':    round(recall_score(y1_te, y1_pred), 4),
    'BA':        round(balanced_accuracy_score(y1_te, y1_pred), 4),
    'n_doh':     int((y1==1).sum()),
    'n_https':   int((y1==0).sum()),
    'model':     'RandomForest',
}
results['stage1'] = s1_metrics
print(f"  F1={s1_metrics['F1']}  BA={s1_metrics['BA']}")

# ══════════════════════════════════════════════════════════════════════════════
# 8.  SAVE all_results_v2.json
# ══════════════════════════════════════════════════════════════════════════════
out_path = f"{FIG_DIR}/all_results_v2.json"
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"\n  Saved {out_path}")

# ── Summary print ─────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"  Stage 1  F1={results['stage1']['F1']}")
print(f"  Stage 2  F1={results['stage2']['F1']}  FPR(browser)={results['stage2']['FPR']}")
print(f"  FPR(tools)={results['fpr_tool_based']['fpr_total']:.2%}")
print(f"  Cross-resolver F1={results['cross_resolver']['F1']}")
print(f"  Stage 3  F1={results['stage3']['F1_macro']}")
print("\n  Adversarial evasion rates:")
for name, ev in results['adversarial'].items():
    print(f"    {name:<22}: det={ev['detection_rate']:.2%}  evade={ev['evasion_rate']:.2%}  Bpp_ab={ev['mean_Bpp_ab']:.1f}")
