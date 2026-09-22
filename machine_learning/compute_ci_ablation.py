"""
compute_ci_ablation.py
Bootstrap CI for Stage 1/2 F1  +  Feature-subset ablation for Stage 2.
Results saved to paper_figures/ci_ablation_results.json
"""
import warnings; warnings.filterwarnings('ignore')
import os, json
import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import f1_score, precision_score, recall_score

DATA_DIR = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/data/csv/generated"
FIG_DIR  = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/machine_learning/paper_figures"

FEATURES_6 = ["mean_Bpp_ab", "mean_Bpp_ba", "mean_pps_ab", "mean_pps_ba",
               "mean_pkts_asm", "mean_bytes_asm"]

# SHAP-ranked order (from all_results_v2.json)
SHAP_ORDER = ["mean_Bpp_ab", "mean_bytes_asm", "mean_pkts_asm",
              "mean_Bpp_ba",  "mean_pps_ba",   "mean_pps_ab"]
FEAT_SYMBOL = {
    "mean_Bpp_ab":    r"\overline{B^{pp}_{ab}}",
    "mean_bytes_asm": r"\overline{A}_{byte}",
    "mean_pkts_asm":  r"\overline{A}_{pkt}",
    "mean_Bpp_ba":    r"\overline{B^{pp}_{ba}}",
    "mean_pps_ba":    r"\overline{pps}_{ba}",
    "mean_pps_ab":    r"\overline{pps}_{ab}",
}

results = {}
np.random.seed(42)
N_BOOT = 1000

# ══════════════════════════════════════════════════════════════
# STAGE 2 — train, bootstrap CI, feature-subset ablation
# ══════════════════════════════════════════════════════════════
print("="*60)
print("STAGE 2: Load, train, CI, ablation")
print("="*60)

df_all     = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
df_browser  = df_all[df_all['p_type'] == 'browser'].copy()
df_malicious= df_all[df_all['mdoh'] == 1].copy()
df2 = pd.concat([df_browser, df_malicious], ignore_index=True)
X2  = df2[FEATURES_6].fillna(0)
y2  = df2['mdoh'].astype(int)

X2_tr, X2_te, y2_tr, y2_te = train_test_split(
    X2, y2, test_size=0.2, stratify=y2, random_state=42)
sc2 = RobustScaler(quantile_range=(5, 95))
X2_tr_s = pd.DataFrame(sc2.fit_transform(X2_tr), columns=FEATURES_6)
X2_te_s  = pd.DataFrame(sc2.transform(X2_te),    columns=FEATURES_6)

print("  Training Stage 2 LightGBM...")
m2 = lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                         learning_rate=0.05, random_state=42, verbosity=-1)
m2.fit(X2_tr_s, y2_tr)
y2_pred = m2.predict(X2_te_s)
f1_s2   = f1_score(y2_te, y2_pred)
print(f"  Stage 2 F1: {f1_s2:.4f}")

# --- Bootstrap CI for Stage 2 F1 ---
print(f"  Bootstrap CI (n={N_BOOT}) for Stage 2 F1...")
rng = np.random.default_rng(0)
n2  = len(y2_te)
y2_te_arr   = np.array(y2_te)
boot_f1_s2  = []
for _ in range(N_BOOT):
    idx = rng.integers(0, n2, n2)
    boot_f1_s2.append(f1_score(y2_te_arr[idx], y2_pred[idx]))
s2_ci = (round(float(np.percentile(boot_f1_s2, 2.5)),  4),
         round(float(np.percentile(boot_f1_s2, 97.5)), 4))
print(f"  Stage 2 F1 95% CI: [{s2_ci[0]}, {s2_ci[1]}]")
results['stage2_f1']    = round(f1_s2, 4)
results['stage2_f1_ci'] = s2_ci

# --- Feature-subset ablation ---
print("  Feature-subset ablation (SHAP-ranked, k=1..6)...")
ablation = {}
prev_f1 = None
for k in range(1, 7):
    k_feats = SHAP_ORDER[:k]
    m_k = lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                              learning_rate=0.05, random_state=42, verbosity=-1)
    m_k.fit(X2_tr_s[k_feats], y2_tr)
    pred_k = m_k.predict(X2_te_s[k_feats])
    f1_k   = round(float(f1_score(y2_te, pred_k)), 4)
    delta  = round(f1_k - prev_f1, 4) if prev_f1 is not None else None
    ablation[k] = {
        'feature_added':  k_feats[-1],
        'features':       k_feats,
        'F1':             f1_k,
        'Precision':      round(float(precision_score(y2_te, pred_k)), 4),
        'Recall':         round(float(recall_score(y2_te, pred_k)), 4),
        'delta_F1':       delta,
    }
    prev_f1 = f1_k
    delta_str = f"+{delta:.4f}" if delta is not None else "---"
    print(f"    k={k}: F1={f1_k}  ΔF1={delta_str}  feat={k_feats[-1]}")
results['ablation_stage2'] = ablation

# ══════════════════════════════════════════════════════════════
# STAGE 1 — train, bootstrap CI
# ══════════════════════════════════════════════════════════════
print()
print("="*60)
print("STAGE 1: Load, train, CI  (RF on 409K rows — may take ~2 min)")
print("="*60)

df1 = pd.read_csv(f"{DATA_DIR}/s1_doh.csv")
X1  = df1[FEATURES_6].fillna(0)
y1  = df1['doh'].astype(int)
X1_tr, X1_te, y1_tr, y1_te = train_test_split(
    X1, y1, test_size=0.2, stratify=y1, random_state=42)
sc1 = RobustScaler(quantile_range=(5, 95))
X1_tr_s = pd.DataFrame(sc1.fit_transform(X1_tr), columns=FEATURES_6)
X1_te_s  = pd.DataFrame(sc1.transform(X1_te),    columns=FEATURES_6)

print("  Training Stage 1 RF...")
m1 = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
m1.fit(X1_tr_s, y1_tr)
y1_pred = m1.predict(X1_te_s)
f1_s1   = f1_score(y1_te, y1_pred)
print(f"  Stage 1 F1: {f1_s1:.4f}")

# --- Bootstrap CI for Stage 1 F1 ---
print(f"  Bootstrap CI (n={N_BOOT}) for Stage 1 F1...")
rng1 = np.random.default_rng(0)
n1   = len(y1_te)
y1_te_arr   = np.array(y1_te)
boot_f1_s1  = []
for _ in range(N_BOOT):
    idx = rng1.integers(0, n1, n1)
    boot_f1_s1.append(f1_score(y1_te_arr[idx], y1_pred[idx]))
s1_ci = (round(float(np.percentile(boot_f1_s1, 2.5)),  4),
         round(float(np.percentile(boot_f1_s1, 97.5)), 4))
print(f"  Stage 1 F1 95% CI: [{s1_ci[0]}, {s1_ci[1]}]")
results['stage1_f1']    = round(f1_s1, 4)
results['stage1_f1_ci'] = s1_ci

# ══════════════════════════════════════════════════════════════
# SAVE
# ══════════════════════════════════════════════════════════════
out_path = f"{FIG_DIR}/ci_ablation_results.json"
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"\n  Saved {out_path}")

print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"  Stage 1: F1={results['stage1_f1']}  95%CI=[{s1_ci[0]}, {s1_ci[1]}]")
print(f"  Stage 2: F1={results['stage2_f1']}  95%CI=[{s2_ci[0]}, {s2_ci[1]}]")
print("\n  Ablation:")
for k, v in ablation.items():
    delta_str = f"+{v['delta_F1']:.4f}" if v['delta_F1'] is not None else "  ---  "
    print(f"    k={k}  F1={v['F1']}  ΔF1={delta_str}  (+{FEAT_SYMBOL[v['feature_added']]})")
