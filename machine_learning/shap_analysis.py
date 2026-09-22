"""
SHAP Sanity Check — Stage 2 (Benign vs Malicious DoH) + Stage 3 (DGA Family ID)
Priority 2: Verify SHAP patterns before committing to journal paper direction.
"""

import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
import lightgbm as lgb
import shap
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # non-interactive backend

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import f1_score, balanced_accuracy_score

# ── Configuration ─────────────────────────────────────────────────────────────
DATA_DIR  = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/data/csv/generated"
OUT_DIR   = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/machine_learning/shap_output"

import os
os.makedirs(OUT_DIR, exist_ok=True)

# 6 selected features from thesis (Table 4.3, bold entries)
FEATURES_6 = [
    "mean_Bpp_ab", "mean_Bpp_ba",
    "mean_pps_ab", "mean_pps_ba",
    "mean_pkts_asm", "mean_bytes_asm"
]

FEATURE_LABELS = {
    "mean_Bpp_ab":    "Mean Bytes/Packet (client→server)",
    "mean_Bpp_ba":    "Mean Bytes/Packet (server→client)",
    "mean_pps_ab":    "Mean Packets/sec (client→server)",
    "mean_pps_ba":    "Mean Packets/sec (server→client)",
    "mean_pkts_asm":  "Bidirectional Packet Asymmetry",
    "mean_bytes_asm": "Bidirectional Byte Asymmetry",
}

# ── Helper ─────────────────────────────────────────────────────────────────────
def train_lgbm(X_tr, y_tr, n_class=2):
    params = dict(
        objective="binary" if n_class == 2 else "multiclass",
        num_class=n_class if n_class > 2 else 1,
        num_leaves=63, n_estimators=300,
        learning_rate=0.05, random_state=42,
        verbosity=-1,
    )
    model = lgb.LGBMClassifier(**params)
    model.fit(X_tr, y_tr)
    return model

def shap_summary(shap_values, X_test, title, fname, feature_labels):
    fig, ax = plt.subplots(figsize=(9, 5))
    shap.summary_plot(
        shap_values, X_test,
        feature_names=[feature_labels.get(f, f) for f in X_test.columns],
        show=False, plot_size=None
    )
    plt.title(title, fontsize=13, fontweight='bold', pad=12)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, fname), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {fname}")

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2 — Benign DoH vs Malicious DoH
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("STAGE 2 — Benign DoH vs Malicious DoH")
print("="*60)

df2 = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
print(f"Loaded: {len(df2):,} flows  |  Class dist: {df2['mdoh'].value_counts().to_dict()}")

X2 = df2[FEATURES_6].fillna(0)
y2 = df2['mdoh'].astype(int)

X2_tr, X2_te, y2_tr, y2_te = train_test_split(
    X2, y2, test_size=0.2, stratify=y2, random_state=42
)

scaler2 = RobustScaler(quantile_range=(5, 95))
X2_tr_s = pd.DataFrame(scaler2.fit_transform(X2_tr), columns=FEATURES_6)
X2_te_s = pd.DataFrame(scaler2.transform(X2_te),    columns=FEATURES_6)

model2 = train_lgbm(X2_tr_s, y2_tr, n_class=2)
y2_pred = model2.predict(X2_te_s)
f1_s2   = f1_score(y2_te, y2_pred)
ba_s2   = balanced_accuracy_score(y2_te, y2_pred)
print(f"LightGBM  →  F1: {f1_s2:.4f}  |  BA: {ba_s2:.4f}")

# SHAP for Stage 2
print("Computing SHAP values...")
explainer2   = shap.TreeExplainer(model2)
shap_vals2   = explainer2.shap_values(X2_te_s)

# For binary LightGBM, shap_values may be list[2] (one per class)
sv2 = shap_vals2[1] if isinstance(shap_vals2, list) else shap_vals2

shap_summary(sv2, X2_te_s,
             "Stage 2: Benign vs Malicious DoH — SHAP Feature Importance",
             "s2_shap_summary.png", FEATURE_LABELS)

# Mean |SHAP| per feature
mean_shap2 = pd.Series(np.abs(sv2).mean(axis=0), index=FEATURES_6)
mean_shap2 = mean_shap2.sort_values(ascending=False)
print("\n  Mean |SHAP| per feature (Stage 2):")
for feat, val in mean_shap2.items():
    print(f"    {FEATURE_LABELS[feat]:<40s}: {val:.4f}")

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3 — DGA Family Fingerprinting
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("STAGE 3 — DGA Family Fingerprinting via SHAP")
print("="*60)

df3 = pd.read_csv(f"{DATA_DIR}/s3_dga.csv")
print(f"Loaded: {len(df3):,} flows  |  Class dist: {df3['dga'].value_counts().to_dict()}")

FAMILY_ORDER = ['pitou', 'qsnatch', 'ramnit', 'zloader']
df3 = df3[df3['dga'].isin(FAMILY_ORDER)].copy()
df3['label'] = df3['dga'].map({f: i for i, f in enumerate(FAMILY_ORDER)})

X3 = df3[FEATURES_6].fillna(0)
y3 = df3['label']

X3_tr, X3_te, y3_tr, y3_te = train_test_split(
    X3, y3, test_size=0.2, stratify=y3, random_state=42
)

scaler3 = RobustScaler(quantile_range=(5, 95))
X3_tr_s = pd.DataFrame(scaler3.fit_transform(X3_tr), columns=FEATURES_6)
X3_te_s = pd.DataFrame(scaler3.transform(X3_te),    columns=FEATURES_6)

model3 = train_lgbm(X3_tr_s, y3_tr, n_class=4)
y3_pred = model3.predict(X3_te_s)
f1_s3   = f1_score(y3_te, y3_pred, average='macro')
ba_s3   = balanced_accuracy_score(y3_te, y3_pred)
print(f"LightGBM  →  F1 (macro): {f1_s3:.4f}  |  BA: {ba_s3:.4f}")

# ── Stage 3 diagnostics ───────────────────────────────────────────────────
from sklearn.metrics import confusion_matrix
cm3 = confusion_matrix(y3_te, y3_pred)
print("\n  Confusion matrix (rows=true, cols=pred):")
print(f"  Labels: {FAMILY_ORDER}")
for row in cm3:
    print("  ", row)

# Feature means per family — check if features are actually discriminative
print("\n  Feature means per DGA family (raw, test set):")
print(f"  {'Feature':<22}", end="")
for fam in FAMILY_ORDER:
    print(f"  {fam.upper():<10}", end="")
print()
for feat in FEATURES_6:
    print(f"  {feat:<22}", end="")
    for fam in FAMILY_ORDER:
        idx = FAMILY_ORDER.index(fam)
        mask = (y3_te == idx)
        vals = X3_te_s.loc[mask.values if hasattr(mask, 'values') else mask, feat]
        print(f"  {vals.mean():+.3f}    ", end="")
    print()

# SHAP for Stage 3
print("\nComputing SHAP values...")
explainer3 = shap.TreeExplainer(model3)
shap_vals3_raw = explainer3.shap_values(X3_te_s)

# Handle different SHAP output shapes for multiclass LightGBM
if isinstance(shap_vals3_raw, np.ndarray) and shap_vals3_raw.ndim == 3:
    # Shape: [n_samples, n_features, n_classes]
    shap_vals3_list = [shap_vals3_raw[:, :, i] for i in range(shap_vals3_raw.shape[2])]
    sv3_mean = np.mean(np.abs(shap_vals3_raw), axis=2)
elif isinstance(shap_vals3_raw, list):
    shap_vals3_list = shap_vals3_raw
    sv3_mean = np.mean(np.abs(np.array(shap_vals3_raw)), axis=0)
else:
    shap_vals3_list = [shap_vals3_raw]
    sv3_mean = np.abs(shap_vals3_raw)

print(f"  SHAP output type: {type(shap_vals3_raw)}, n_classes={len(shap_vals3_list)}")
print(f"  sv3_mean shape: {sv3_mean.shape}, X3_te_s shape: {X3_te_s.shape}")

shap_summary(sv3_mean, X3_te_s,
             "Stage 3: DGA Family ID — SHAP Feature Importance (macro avg)",
             "s3_shap_summary.png", FEATURE_LABELS)

# ── DGA Family Behavioral Fingerprint Table ────────────────────────────────
print("\n  DGA Family Behavioral Fingerprint (Mean SHAP per class):")
print(f"  {'Feature':<42}", end="")
for fam in FAMILY_ORDER:
    print(f"  {fam.upper():<12}", end="")
print()
print("  " + "-"*90)

fingerprint = {}
for feat_idx, feat in enumerate(FEATURES_6):
    row = {}
    print(f"  {FEATURE_LABELS[feat]:<42}", end="")
    for class_idx, fam in enumerate(FAMILY_ORDER):
        val = shap_vals3_list[class_idx][:, feat_idx].mean()
        row[fam] = val
        direction = "↑" if val > 0.001 else ("↓" if val < -0.001 else "~")
        print(f"  {val:+.4f} {direction}  ", end="")
    fingerprint[feat] = row
    print()

# ── Per-family SHAP bar plots ──────────────────────────────────────────────
for class_idx, fam in enumerate(FAMILY_ORDER):
    fig, ax = plt.subplots(figsize=(9, 4))
    shap.summary_plot(
        shap_vals3_list[class_idx], X3_te_s,
        feature_names=[FEATURE_LABELS.get(f, f) for f in FEATURES_6],
        show=False, plot_size=None,
        plot_type="bar"
    )
    plt.title(f"Stage 3 SHAP — {fam.upper()} family fingerprint", fontsize=12, fontweight='bold')
    plt.tight_layout()
    fname = f"s3_shap_{fam}.png"
    plt.savefig(os.path.join(OUT_DIR, fname), dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {fname}")

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY VERDICT
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("SANITY CHECK VERDICT")
print("="*60)
print(f"Stage 2 LightGBM  F1={f1_s2:.4f}  BA={ba_s2:.4f}  ({'✅ OK' if f1_s2 > 0.98 else '⚠ Check'})")
print(f"Stage 3 LightGBM  F1={f1_s3:.4f}  BA={ba_s3:.4f}  ({'✅ OK' if f1_s3 > 0.75 else '⚠ Check'})")
print(f"\nTop feature Stage 2: {FEATURE_LABELS[mean_shap2.index[0]]}")
print(f"SHAP plots saved to: {OUT_DIR}/")
print("\n✅ GAP A (XAI) sanity check complete.")
print("   → If DGA families show distinct SHAP patterns, fingerprinting is viable.")
