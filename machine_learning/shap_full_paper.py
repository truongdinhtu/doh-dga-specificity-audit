"""
Full SHAP + Adversarial Robustness Analysis — Journal Paper Figures & Tables
Generates all figures and numerical results for the paper.
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
import matplotlib.gridspec as gridspec
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (f1_score, balanced_accuracy_score, roc_auc_score,
                              confusion_matrix, precision_score, recall_score)

DATA_DIR = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/data/csv/generated"
FIG_DIR  = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/machine_learning/paper_figures"
os.makedirs(FIG_DIR, exist_ok=True)

FEATURES_6 = [
    "mean_Bpp_ab", "mean_Bpp_ba",
    "mean_pps_ab", "mean_pps_ba",
    "mean_pkts_asm", "mean_bytes_asm"
]
FEAT_LABELS = {
    "mean_Bpp_ab":    "Bytes/Pkt\n(client→server)",
    "mean_Bpp_ba":    "Bytes/Pkt\n(server→client)",
    "mean_pps_ab":    "Pkts/sec\n(client→server)",
    "mean_pps_ba":    "Pkts/sec\n(server→client)",
    "mean_pkts_asm":  "Pkt\nAsymmetry",
    "mean_bytes_asm": "Byte\nAsymmetry",
}
FEAT_LABELS_SHORT = {
    "mean_Bpp_ab":    "Bpp↑",
    "mean_Bpp_ba":    "Bpp↓",
    "mean_pps_ab":    "pps↑",
    "mean_pps_ba":    "pps↓",
    "mean_pkts_asm":  "PktAsm",
    "mean_bytes_asm": "BytAsm",
}
FAMILY_ORDER = ['pitou', 'qsnatch', 'ramnit', 'zloader']
FAMILY_COLORS = {'pitou': '#e74c3c', 'qsnatch': '#3498db', 'ramnit': '#2ecc71', 'zloader': '#f39c12'}

results = {}

# ══════════════════════════════════════════════════════════════════════════════
# 1. STAGE 2 — MODEL TRAINING + SHAP
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("1. STAGE 2: Benign DoH vs Malicious DoH + SHAP")
print("="*60)

df2 = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
X2  = df2[FEATURES_6].fillna(0)
y2  = df2['mdoh'].astype(int)

X2_tr, X2_te, y2_tr, y2_te = train_test_split(
    X2, y2, test_size=0.2, stratify=y2, random_state=42)
sc2 = RobustScaler(quantile_range=(5, 95))
X2_tr_s = pd.DataFrame(sc2.fit_transform(X2_tr), columns=FEATURES_6)
X2_te_s  = pd.DataFrame(sc2.transform(X2_te),     columns=FEATURES_6)

m2 = lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                         learning_rate=0.05, random_state=42, verbosity=-1)
m2.fit(X2_tr_s, y2_tr)
y2_pred = m2.predict(X2_te_s)

s2_metrics = {
    'F1':        round(f1_score(y2_te, y2_pred), 4),
    'Precision': round(precision_score(y2_te, y2_pred), 4),
    'Recall':    round(recall_score(y2_te, y2_pred), 4),
    'BA':        round(balanced_accuracy_score(y2_te, y2_pred), 4),
    'n_benign':  int((y2==0).sum()),
    'n_malicious': int((y2==1).sum()),
}
results['stage2'] = s2_metrics
print(f"  F1={s2_metrics['F1']}  Prec={s2_metrics['Precision']}  Rec={s2_metrics['Recall']}  BA={s2_metrics['BA']}")

# SHAP
print("  Computing SHAP values...")
exp2 = shap.TreeExplainer(m2)
sv2_raw = exp2.shap_values(X2_te_s)
sv2 = sv2_raw[1] if isinstance(sv2_raw, list) else sv2_raw

mean_shap2 = pd.Series(np.abs(sv2).mean(axis=0), index=FEATURES_6).sort_values(ascending=False)
results['shap_s2_ranking'] = mean_shap2.to_dict()
print("  SHAP ranking:")
for f, v in mean_shap2.items():
    print(f"    {f:<22}: {v:.4f}")

# Figure 1: SHAP beeswarm Stage 2
fig, ax = plt.subplots(figsize=(8, 4.5))
shap.summary_plot(
    sv2, X2_te_s,
    feature_names=[FEAT_LABELS.get(f, f) for f in FEATURES_6],
    show=False, plot_size=None, max_display=6
)
plt.title("Stage 2: Benign vs. Malicious DoH — SHAP Summary", fontsize=12, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig1_s2_shap_beeswarm.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig1_s2_shap_beeswarm.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig1_s2_shap_beeswarm")

# Figure 2: Feature distribution — Benign vs Malicious (box plots)
fig, axes = plt.subplots(2, 3, figsize=(12, 6))
axes = axes.flatten()
for i, feat in enumerate(FEATURES_6):
    benign_vals  = df2.loc[df2.mdoh==0, feat].clip(
        df2[feat].quantile(0.01), df2[feat].quantile(0.99))
    malicious_vals = df2.loc[df2.mdoh==1, feat].clip(
        df2[feat].quantile(0.01), df2[feat].quantile(0.99))
    axes[i].boxplot([benign_vals, malicious_vals],
                    labels=['Benign', 'Malicious'],
                    patch_artist=True,
                    boxprops=dict(facecolor='lightblue' if i==0 else 'lightgray'),
                    medianprops=dict(color='red', linewidth=2))
    axes[i].set_title(FEAT_LABELS[feat].replace('\n',' '), fontsize=9, fontweight='bold')
    axes[i].tick_params(labelsize=8)
    if i == 0:
        axes[i].set_facecolor('#fff9f0')
        for spine in axes[i].spines.values():
            spine.set_edgecolor('#e67e22')
            spine.set_linewidth(2)
plt.suptitle("Feature Distributions: Benign DoH vs. DGA Malicious DoH",
             fontsize=12, fontweight='bold', y=1.01)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig2_feature_distributions.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig2_feature_distributions.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig2_feature_distributions")

# ══════════════════════════════════════════════════════════════════════════════
# 2. ADVERSARIAL ROBUSTNESS ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("2. ADVERSARIAL ROBUSTNESS — Evasion Experiments")
print("="*60)

evasion_files = {
    'Mimic-AsyncProb':  (f"{DATA_DIR}/s2_mdoh_evasion_mimic_async_proba.csv",  1, '#e74c3c'),
    'Mimic-AsyncRand':  (f"{DATA_DIR}/s2_mdoh_evasion_mimic_async_random.csv", 1, '#e67e22'),
    'Mimic-SyncRand':   (f"{DATA_DIR}/s2_mdoh_evasion_mimic_sync_random.csv",  1, '#f39c12'),
}

# Reference feature means per scenario
feat_means = {
    'Benign':    df2.loc[df2.mdoh==0, FEATURES_6].mean(),
    'Malicious': df2.loc[df2.mdoh==1, FEATURES_6].mean(),
}

evasion_results = {}
for name, (fpath, true_label, color) in evasion_files.items():
    dfev = pd.read_csv(fpath)
    feat_means[name] = dfev[FEATURES_6].mean()
    X_ev = pd.DataFrame(sc2.transform(dfev[FEATURES_6].fillna(0)), columns=FEATURES_6)
    pred_ev = m2.predict(X_ev)
    det_rate = (pred_ev == 1).mean()
    evasion_results[name] = {
        'detection_rate': round(det_rate, 4),
        'evasion_rate':   round(1 - det_rate, 4),
        'n_evaded':       int((pred_ev == 0).sum()),
        'n_total':        len(pred_ev),
        'mean_Bpp_ab':    round(float(dfev['mean_Bpp_ab'].mean()), 2),
    }
    print(f"  {name}: DetRate={det_rate:.2%}  EvasionRate={1-det_rate:.2%}")

results['adversarial'] = evasion_results

# Why mimic attacks partially fail: mean_Bpp_ab comparison
print("\n  Key insight — mean_Bpp_ab:")
print(f"    Benign:          {feat_means['Benign']['mean_Bpp_ab']:.2f}")
print(f"    Malicious:       {feat_means['Malicious']['mean_Bpp_ab']:.2f}")
for name in evasion_files:
    print(f"    {name:<18}: {feat_means[name]['mean_Bpp_ab']:.2f}  ← {'SAME AS MALICIOUS' if abs(feat_means[name]['mean_Bpp_ab'] - feat_means['Malicious']['mean_Bpp_ab']) < 10 else 'closer to benign'}")

# Figure 3: Evasion analysis — feature means radar + detection rates
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Left: Feature means comparison
scenarios = ['Benign', 'Malicious', 'Mimic-AsyncProb', 'Mimic-AsyncRand', 'Mimic-SyncRand']
scenario_colors = ['#2ecc71', '#e74c3c', '#e74c3c', '#e67e22', '#f39c12']
scenario_ls = ['-', '-', '--', '--', '--']

x = np.arange(len(FEATURES_6))
width = 0.15
for i, (scen, col) in enumerate(zip(scenarios, scenario_colors)):
    vals = [feat_means[scen][f] for f in FEATURES_6]
    # Normalize to 0-1 range for visualization
    pass

# Simpler: grouped bar for mean_Bpp_ab only (the key feature) + evasion rates
feat_key = 'mean_Bpp_ab'
vals_key = [feat_means[s][feat_key] for s in ['Benign', 'Malicious', 'Mimic-AsyncProb', 'Mimic-AsyncRand', 'Mimic-SyncRand']]
colors_key = ['#2ecc71', '#e74c3c', '#c0392b', '#d35400', '#e67e22']
bars = ax1.bar(range(5), vals_key, color=colors_key, edgecolor='black', linewidth=0.5)
ax1.axhline(feat_means['Benign'][feat_key], color='#2ecc71', linestyle='--', alpha=0.7, label='Benign reference')
ax1.axhline(feat_means['Malicious'][feat_key], color='#e74c3c', linestyle='--', alpha=0.7, label='Malicious reference')
ax1.set_xticks(range(5))
ax1.set_xticklabels(['Benign', 'Malicious', 'Mimic\nAsync-P', 'Mimic\nAsync-R', 'Mimic\nSync-R'], fontsize=9)
ax1.set_ylabel('Mean Bytes/Packet (client→server)', fontsize=10)
ax1.set_title('SHAP Top Feature: Evasion Attacks\nFailed to Spoof mean_Bpp_ab', fontsize=10, fontweight='bold')
ax1.legend(fontsize=8)
for bar, val in zip(bars, vals_key):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
             f'{val:.0f}', ha='center', va='bottom', fontsize=8, fontweight='bold')

# Right: Detection rates
names_short = ['Mimic\nAsync-P', 'Mimic\nAsync-R', 'Mimic\nSync-R']
det_rates  = [evasion_results[n]['detection_rate'] for n in evasion_files]
ev_rates   = [evasion_results[n]['evasion_rate']   for n in evasion_files]
x = np.arange(3)
b1 = ax2.bar(x - 0.2, det_rates, 0.35, label='Detected (TP)', color='#2ecc71', edgecolor='black')
b2 = ax2.bar(x + 0.2, ev_rates,  0.35, label='Evaded (FN)',   color='#e74c3c', edgecolor='black', alpha=0.8)
ax2.set_xticks(x)
ax2.set_xticklabels(names_short, fontsize=9)
ax2.set_ylabel('Rate', fontsize=10)
ax2.set_ylim(0, 1.1)
ax2.set_title('Evasion Attack Detection Rates\n(Stage 2 LightGBM)', fontsize=10, fontweight='bold')
ax2.legend(fontsize=9)
for bar, val in zip(list(b1) + list(b2), det_rates + ev_rates):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
             f'{val:.0%}', ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.suptitle("Figure 3: Adversarial Evasion Analysis — SHAP-Guided Vulnerability",
             fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig3_evasion_analysis.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig3_evasion_analysis.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig3_evasion_analysis")

# ══════════════════════════════════════════════════════════════════════════════
# 3. STAGE 3 — DGA FAMILY FINGERPRINTING via SHAP
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("3. STAGE 3: DGA Family Fingerprinting via SHAP")
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
X3_te_s  = pd.DataFrame(sc3.transform(X3_te),     columns=FEATURES_6)

m3 = lgb.LGBMClassifier(objective='multiclass', num_class=4,
                         num_leaves=63, n_estimators=300,
                         learning_rate=0.05, random_state=42, verbosity=-1)
m3.fit(X3_tr_s, y3_tr)
y3_pred = m3.predict(X3_te_s)

s3_metrics = {
    'F1_macro': round(f1_score(y3_te, y3_pred, average='macro'), 4),
    'BA':       round(balanced_accuracy_score(y3_te, y3_pred), 4),
}
results['stage3'] = s3_metrics
print(f"  F1 macro={s3_metrics['F1_macro']}  BA={s3_metrics['BA']}")

# SHAP Stage 3
print("  Computing SHAP values...")
exp3 = shap.TreeExplainer(m3)
sv3_raw = exp3.shap_values(X3_te_s)

if isinstance(sv3_raw, np.ndarray) and sv3_raw.ndim == 3:
    sv3_list = [sv3_raw[:, :, i] for i in range(sv3_raw.shape[2])]
elif isinstance(sv3_raw, list):
    sv3_list = sv3_raw
else:
    sv3_list = [sv3_raw]

# Build fingerprint table
fingerprint = {}
for class_idx, fam in enumerate(FAMILY_ORDER):
    fingerprint[fam] = {}
    for feat_idx, feat in enumerate(FEATURES_6):
        fingerprint[fam][feat] = float(sv3_list[class_idx][:, feat_idx].mean())

results['shap_s3_fingerprint'] = fingerprint

print("\n  DGA Family Behavioral Fingerprint (mean SHAP):")
print(f"  {'Feature':<22}", end="")
for fam in FAMILY_ORDER: print(f"  {fam.upper():<12}", end="")
print()
print("  " + "-"*70)
for feat in FEATURES_6:
    print(f"  {feat:<22}", end="")
    for fam in FAMILY_ORDER:
        v = fingerprint[fam][feat]
        arrow = "↑" if v > 0.001 else ("↓" if v < -0.001 else "~")
        print(f"  {v:+.4f} {arrow}  ", end="")
    print()

# Figure 4: SHAP fingerprint heatmap
fig, ax = plt.subplots(figsize=(9, 4))
fp_matrix = np.array([[fingerprint[fam][feat] for fam in FAMILY_ORDER]
                       for feat in FEATURES_6])
im = ax.imshow(fp_matrix, cmap='RdYlGn', aspect='auto',
               vmin=-max(abs(fp_matrix.min()), abs(fp_matrix.max())),
               vmax=max(abs(fp_matrix.min()), abs(fp_matrix.max())))
ax.set_xticks(range(4))
ax.set_xticklabels([f.upper() for f in FAMILY_ORDER], fontsize=11, fontweight='bold')
ax.set_yticks(range(6))
ax.set_yticklabels([FEAT_LABELS[f].replace('\n', ' ') for f in FEATURES_6], fontsize=9)
for i, feat in enumerate(FEATURES_6):
    for j, fam in enumerate(FAMILY_ORDER):
        v = fp_matrix[i, j]
        ax.text(j, i, f'{v:+.3f}', ha='center', va='center',
                fontsize=9, fontweight='bold',
                color='white' if abs(v) > 0.03 else 'black')
plt.colorbar(im, ax=ax, label='Mean SHAP value (positive = pushes toward this family)')
ax.set_title("Stage 3: DGA Family Behavioral Fingerprint via SHAP\n"
             "(6 NetFlow features — positive = feature pushes prediction toward this family)",
             fontsize=10, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig4_s3_shap_fingerprint.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig4_s3_shap_fingerprint.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig4_s3_shap_fingerprint")

# Figure 5: DGA family feature means — parallel coordinates style
fig, axes = plt.subplots(1, 6, figsize=(14, 4), sharey=False)
for feat_idx, (feat, ax) in enumerate(zip(FEATURES_6, axes)):
    for fam in FAMILY_ORDER:
        fam_vals = df3.loc[df3.dga == fam, feat]
        q25, q50, q75 = fam_vals.quantile([0.25, 0.5, 0.75])
        ax.errorbar([FAMILY_ORDER.index(fam)], [q50],
                    yerr=[[q50-q25], [q75-q50]],
                    fmt='o', color=FAMILY_COLORS[fam], capsize=4,
                    label=fam.upper() if feat_idx == 0 else None,
                    markersize=6)
    ax.set_xticks(range(4))
    ax.set_xticklabels([f[:4].upper() for f in FAMILY_ORDER], fontsize=7, rotation=30)
    ax.set_title(FEAT_LABELS[feat].replace('\n', ' '), fontsize=8, fontweight='bold')
    ax.tick_params(labelsize=7)

axes[0].legend(fontsize=7, loc='upper right')
plt.suptitle("DGA Family Feature Distributions (median ± IQR)\n"
             "Near-identical patterns explain difficulty of family discrimination at flow level",
             fontsize=10, fontweight='bold')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig5_family_feature_overlap.pdf", dpi=150, bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig5_family_feature_overlap.png", dpi=150, bbox_inches='tight')
plt.close()
print("  Saved fig5_family_feature_overlap")

# ══════════════════════════════════════════════════════════════════════════════
# 4. SAVE ALL NUMERICAL RESULTS
# ══════════════════════════════════════════════════════════════════════════════
with open(f"{FIG_DIR}/all_results.json", 'w') as f:
    json.dump(results, f, indent=2)

print("\n" + "="*60)
print("ALL RESULTS SUMMARY")
print("="*60)
print(f"Stage 2  F1={results['stage2']['F1']}  BA={results['stage2']['BA']}")
print(f"Stage 3  F1={results['stage3']['F1_macro']}  BA={results['stage3']['BA']}")
print(f"\nSHAP Top Feature Stage 2: {list(results['shap_s2_ranking'].keys())[0]} "
      f"(|SHAP|={list(results['shap_s2_ranking'].values())[0]:.4f})")
print(f"\nEvasion rates:")
for name, r in results['adversarial'].items():
    print(f"  {name}: {r['evasion_rate']:.2%}")
print(f"\nAll figures saved to: {FIG_DIR}/")
