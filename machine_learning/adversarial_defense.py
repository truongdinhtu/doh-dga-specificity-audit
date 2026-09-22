"""
adversarial_defense.py
Adversarial training defense for Stage 2.

Experiment:
  Baseline:  train on {browser-benign + malicious}, evaluate evasion under 4 attacks.
  Defense:   augment training with SHAP-aware padded malicious flows, retrain,
             re-evaluate evasion under same 4 attacks.

Saves results to: paper_figures/adversarial_defense_results.json
"""
import warnings; warnings.filterwarnings('ignore')
import os, json
import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import f1_score, precision_score, recall_score

DATA_DIR = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/data/csv/generated"
FIG_DIR  = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/machine_learning/paper_figures"

FEATURES_6 = ["mean_Bpp_ab", "mean_Bpp_ba", "mean_pps_ab", "mean_pps_ba",
               "mean_pkts_asm", "mean_bytes_asm"]

np.random.seed(42)

# ══════════════════════════════════════════════════════════════
# LOAD DATA — identical to original Stage 2 setup
# ══════════════════════════════════════════════════════════════
df_all      = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
df_browser  = df_all[df_all['p_type'] == 'browser'].copy()
df_malicious= df_all[df_all['mdoh'] == 1].copy()
df2 = pd.concat([df_browser, df_malicious], ignore_index=True)
X2  = df2[FEATURES_6].fillna(0)
y2  = df2['mdoh'].astype(int)

X2_tr, X2_te, y2_tr, y2_te = train_test_split(
    X2, y2, test_size=0.2, stratify=y2, random_state=42)

# Scaler fitted on original training set — reused for both models
sc2 = RobustScaler(quantile_range=(5, 95))
X2_tr_s = pd.DataFrame(sc2.fit_transform(X2_tr), columns=FEATURES_6)
X2_te_s  = pd.DataFrame(sc2.transform(X2_te),    columns=FEATURES_6)

# ══════════════════════════════════════════════════════════════
# BASELINE MODEL (original, no defense)
# ══════════════════════════════════════════════════════════════
print("="*60)
print("BASELINE MODEL (original Stage 2)")
print("="*60)

m_base = lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                             learning_rate=0.05, random_state=42, verbosity=-1)
m_base.fit(X2_tr_s, y2_tr)
pred_base = m_base.predict(X2_te_s)
f1_base   = round(f1_score(y2_te, pred_base), 4)
p_base    = round(precision_score(y2_te, pred_base), 4)
r_base    = round(recall_score(y2_te, pred_base), 4)
print(f"  F1={f1_base}  P={p_base}  R={r_base}")


def eval_evasion(model, scaler, df_mal_source, df_browser_ref, rng_seed=99):
    """Evaluate all 4 attack strategies against a given model."""
    results = {}

    # Strategies 1-3: load from pre-generated CSV files
    strategy_files = {
        'Mimic-Async-Prob':   (f"{DATA_DIR}/s2_mdoh_evasion_mimic_async_proba.csv",  1),
        'Mimic-Async-Random': (f"{DATA_DIR}/s2_mdoh_evasion_mimic_async_random.csv", 1),
        'Mimic-Sync-Random':  (f"{DATA_DIR}/s2_mdoh_evasion_mimic_sync_random.csv",  1),
    }
    for name, (fpath, _) in strategy_files.items():
        dfev = pd.read_csv(fpath)
        X_ev = pd.DataFrame(scaler.transform(dfev[FEATURES_6].fillna(0)), columns=FEATURES_6)
        pred = model.predict(X_ev)
        det_rate = float((pred == 1).mean())
        results[name] = {
            'detection_rate': round(det_rate, 4),
            'evasion_rate':   round(1 - det_rate, 4),
            'mean_Bpp_ab':    round(float(dfev['mean_Bpp_ab'].mean()), 2),
        }

    # Strategy 4: Mimic-SHAP-Aware — simulate EDNS(0) inflation on test malicious
    rng = np.random.default_rng(rng_seed)
    df_sa = df_mal_source.sample(n=min(3100, len(df_mal_source)),
                                 random_state=rng_seed).copy()
    bpp_target_mean = df_browser_ref['mean_Bpp_ab'].mean()
    bpp_target_std  = df_browser_ref['mean_Bpp_ab'].std() * 0.5
    df_sa['mean_Bpp_ab'] = rng.normal(bpp_target_mean, bpp_target_std, len(df_sa)).clip(80, 400)
    B_ab_new = df_sa['mean_Bpp_ab'] * df_sa['pkts_ab']
    B_ba_orig = df_sa['bytes_ba']
    df_sa['mean_bytes_asm'] = (B_ab_new - B_ba_orig) / (B_ab_new + B_ba_orig)

    X_sa = pd.DataFrame(scaler.transform(df_sa[FEATURES_6].fillna(0)), columns=FEATURES_6)
    pred_sa = model.predict(X_sa)
    det_sa  = float((pred_sa == 1).mean())
    results['Mimic-SHAP-Aware'] = {
        'detection_rate': round(det_sa, 4),
        'evasion_rate':   round(1 - det_sa, 4),
        'mean_Bpp_ab':    round(float(df_sa['mean_Bpp_ab'].mean()), 2),
    }
    return results


print("\n  Evaluating baseline evasion rates...")
ev_base = eval_evasion(m_base, sc2, df_malicious, df_browser)
for name, r in ev_base.items():
    print(f"    {name:<24}: det={r['detection_rate']:.2%}  evade={r['evasion_rate']:.2%}  "
          f"Bpp_ab={r['mean_Bpp_ab']:.1f}")

# ══════════════════════════════════════════════════════════════
# BUILD ADVERSARIAL AUGMENTATION — SHAP-AWARE padded training flows
# ══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("ADVERSARIAL TRAINING AUGMENTATION")
print("="*60)

# Isolate training malicious flows (same split as above)
train_indices = X2_tr.index
mal_train_idx = [i for i in train_indices if y2.iloc[i] == 1]
df_mal_train  = df_all.loc[mal_train_idx].copy()

rng_aug = np.random.default_rng(42)
bpp_target_mean = df_browser['mean_Bpp_ab'].mean()
bpp_target_std  = df_browser['mean_Bpp_ab'].std() * 0.5

df_aug = df_mal_train.copy()
df_aug['mean_Bpp_ab'] = rng_aug.normal(bpp_target_mean, bpp_target_std,
                                       len(df_aug)).clip(80, 400)
B_ab_new  = df_aug['mean_Bpp_ab'] * df_aug['pkts_ab']
B_ba_orig = df_aug['bytes_ba']
df_aug['mean_bytes_asm'] = (B_ab_new - B_ba_orig) / (B_ab_new + B_ba_orig)

# y_aug = 1 (still malicious, just padded)
X_aug = df_aug[FEATURES_6].fillna(0)
y_aug = pd.Series(np.ones(len(df_aug), dtype=int), index=df_aug.index)

print(f"  Original training size:   {len(X2_tr)}")
print(f"  Augmented flows added:    {len(X_aug)} (SHAP-aware padded malicious)")

# Combine original training + adversarial augmentation
X_tr_aug = pd.concat([X2_tr.reset_index(drop=True),
                       X_aug.reset_index(drop=True)], ignore_index=True)
y_tr_aug = pd.concat([y2_tr.reset_index(drop=True),
                       y_aug.reset_index(drop=True)], ignore_index=True)

# Scale augmented training using SAME scaler (fitted on original training)
X_tr_aug_s = pd.DataFrame(sc2.transform(X_tr_aug), columns=FEATURES_6)

# ══════════════════════════════════════════════════════════════
# DEFENSE MODEL
# ══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("DEFENSE MODEL (adversarially trained)")
print("="*60)

m_def = lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                            learning_rate=0.05, random_state=42, verbosity=-1)
m_def.fit(X_tr_aug_s, y_tr_aug)

pred_def = m_def.predict(X2_te_s)
f1_def   = round(f1_score(y2_te, pred_def), 4)
p_def    = round(precision_score(y2_te, pred_def), 4)
r_def    = round(recall_score(y2_te, pred_def), 4)
print(f"  F1={f1_def}  P={p_def}  R={r_def}")

print("\n  Evaluating defense model evasion rates...")
ev_def = eval_evasion(m_def, sc2, df_malicious, df_browser)
for name, r in ev_def.items():
    print(f"    {name:<24}: det={r['detection_rate']:.2%}  evade={r['evasion_rate']:.2%}  "
          f"Bpp_ab={r['mean_Bpp_ab']:.1f}")

# ══════════════════════════════════════════════════════════════
# SUMMARY TABLE
# ══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"\n  Detection performance on clean test set:")
print(f"    {'Model':<22} {'F1':>6}  {'P':>6}  {'R':>6}")
print(f"    {'Baseline':<22} {f1_base:>6}  {p_base:>6}  {r_base:>6}")
print(f"    {'Defense (adv. train)':<22} {f1_def:>6}  {p_def:>6}  {r_def:>6}")

print(f"\n  Evasion rate comparison (lower = better defense):")
print(f"    {'Attack':<24} {'Baseline':>10}  {'Defense':>10}  {'Delta':>10}")
for name in ['Mimic-Async-Prob', 'Mimic-Async-Random', 'Mimic-Sync-Random', 'Mimic-SHAP-Aware']:
    eb = ev_base[name]['evasion_rate']
    ed = ev_def[name]['evasion_rate']
    delta = ed - eb
    sign = "+" if delta > 0 else ""
    print(f"    {name:<24} {eb:>10.2%}  {ed:>10.2%}  {sign}{delta:.2%}")

# ══════════════════════════════════════════════════════════════
# SAVE JSON
# ══════════════════════════════════════════════════════════════
output = {
    'baseline': {
        'F1': f1_base, 'Precision': p_base, 'Recall': r_base,
        'evasion': ev_base,
    },
    'defense': {
        'F1': f1_def, 'Precision': p_def, 'Recall': r_def,
        'aug_size': len(X_aug),
        'evasion': ev_def,
    }
}
out_path = f"{FIG_DIR}/adversarial_defense_results.json"
with open(out_path, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\n  Saved {out_path}")
