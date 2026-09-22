"""
experiments_extended.py
Three experiments in one script:
  A. Adaptive attacker variants (Bpp_ab targets: 120, 130, 155, 180, 200 + random-block)
  B. Leave-one-resolver-out cross-resolver validation (4 folds)
  C. Bootstrap CI for defense table (baseline vs. adversarial training, 10 seeds)

Also clarifies that adversarial training uses TRAIN-partition benign statistics only
(no leakage from test set).

Saves: paper_figures/extended_results.json
"""
import warnings; warnings.filterwarnings('ignore')
import json
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

# ── Load & split (identical to original Stage 2 / adversarial_defense.py) ─────
df_all      = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
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

# ── Baseline model ─────────────────────────────────────────────────────────────
def make_lgbm(seed=42):
    return lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                               learning_rate=0.05, random_state=seed, verbosity=-1)

m_base = make_lgbm()
m_base.fit(X2_tr_s, y2_tr)

# ── Adversarial augmentation helper ────────────────────────────────────────────
# IMPORTANT: benign reference computed from TRAINING partition only — no test leakage
train_benign_idx = X2_tr.index[y2_tr.values == 0]
bpp_train_benign = X2_tr.loc[train_benign_idx, 'mean_Bpp_ab']
BPP_BENIGN_MEAN  = bpp_train_benign.mean()   # training-only reference
BPP_BENIGN_STD   = bpp_train_benign.std()

print(f"Benign Bpp_ab reference (TRAIN ONLY): mean={BPP_BENIGN_MEAN:.2f}  std={BPP_BENIGN_STD:.2f}")

def augment_training(target_bpp_mean, seed=42):
    """Return (X_tr_aug_scaled, y_tr_aug) with SHAP-aware padded malicious added."""
    rng = np.random.default_rng(seed)
    mal_idx = X2_tr.index[y2_tr.values == 1]
    df_mal_tr = df_all.loc[mal_idx].copy()

    df_aug = df_mal_tr.copy()
    df_aug['mean_Bpp_ab'] = rng.normal(target_bpp_mean, BPP_BENIGN_STD * 0.5,
                                        len(df_aug)).clip(80, 400)
    B_ab_new  = df_aug['mean_Bpp_ab'] * df_aug['pkts_ab']
    B_ba_orig = df_aug['bytes_ba']
    df_aug['mean_bytes_asm'] = (B_ab_new - B_ba_orig) / (B_ab_new + B_ba_orig)

    X_aug = df_aug[FEATURES_6].fillna(0)
    y_aug = pd.Series(np.ones(len(df_aug), dtype=int), index=df_aug.index)

    X_tr_aug = pd.concat([X2_tr.reset_index(drop=True),
                           X_aug.reset_index(drop=True)], ignore_index=True)
    y_tr_aug = pd.concat([y2_tr.reset_index(drop=True),
                           y_aug.reset_index(drop=True)], ignore_index=True)
    X_tr_aug_s = pd.DataFrame(sc2.transform(X_tr_aug), columns=FEATURES_6)
    return X_tr_aug_s, y_tr_aug

def shap_aware_attack(target_bpp_mean, seed=99, n=3100, block_mode=False):
    """Simulate SHAP-aware attack on held-out malicious flows."""
    rng = np.random.default_rng(seed)
    df_sa = df_malicious.sample(n=min(n, len(df_malicious)), random_state=seed).copy()

    if block_mode:
        # Random-block padding: RFC 8467 block sizes 128/468/1200 (random choice)
        blocks = np.array([128, 468, 1200])
        chosen = rng.choice(blocks, size=len(df_sa))
        df_sa['mean_Bpp_ab'] = df_sa['mean_Bpp_ab'] + chosen
    else:
        df_sa['mean_Bpp_ab'] = rng.normal(target_bpp_mean, BPP_BENIGN_STD * 0.5,
                                            len(df_sa)).clip(80, 400)

    B_ab_new  = df_sa['mean_Bpp_ab'] * df_sa['pkts_ab']
    B_ba_orig = df_sa['bytes_ba']
    df_sa['mean_bytes_asm'] = (B_ab_new - B_ba_orig) / (B_ab_new + B_ba_orig)
    return df_sa

results = {}

# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT A — Adaptive attacker variants
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("EXPERIMENT A: Adaptive attacker variants")
print("="*60)

# Defense model trained with target ~155 (BPP_BENIGN_MEAN)
X_def_s, y_def = augment_training(BPP_BENIGN_MEAN, seed=42)
m_def = make_lgbm()
m_def.fit(X_def_s, y_def)
pred_def_clean = m_def.predict(X2_te_s)
f1_def = round(f1_score(y2_te, pred_def_clean), 4)

attack_variants = {
    'Target-120':      {'target': 120,            'block': False},
    'Target-130':      {'target': 130,            'block': False},
    'Target-155':      {'target': BPP_BENIGN_MEAN,'block': False},  # original
    'Target-180':      {'target': 180,            'block': False},
    'Target-200':      {'target': 200,            'block': False},
    'Random-Block':    {'target': None,            'block': True},
}

exp_a = {}
print(f"\n  {'Variant':<18}  {'Base evade':>10}  {'Def evade':>10}  {'Delta':>8}  {'Bpp_ab':>8}")
for vname, cfg in attack_variants.items():
    df_sa = shap_aware_attack(cfg['target'], block_mode=cfg['block'])
    X_sa = pd.DataFrame(sc2.transform(df_sa[FEATURES_6].fillna(0)), columns=FEATURES_6)

    pred_b = m_base.predict(X_sa)
    pred_d = m_def.predict(X_sa)
    ev_b = round(1 - float((pred_b==1).mean()), 4)
    ev_d = round(1 - float((pred_d==1).mean()), 4)
    bpp  = round(float(df_sa['mean_Bpp_ab'].mean()), 1)
    exp_a[vname] = {'baseline_evasion': ev_b, 'defense_evasion': ev_d,
                    'delta': round(ev_d-ev_b, 4), 'mean_Bpp_ab': bpp}
    print(f"  {vname:<18}  {ev_b:>10.2%}  {ev_d:>10.2%}  "
          f"{ev_d-ev_b:>+8.2%}  {bpp:>8.1f}")

results['adaptive_attack'] = exp_a

# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT B — Leave-one-resolver-out
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("EXPERIMENT B: Leave-one-resolver-out")
print("="*60)

resolvers = ['adguard', 'cloudflare', 'google', 'quad9']
exp_b = {}

print(f"\n  {'Held-out':>12}  {'F1':>6}  {'P':>6}  {'R':>6}  {'BA':>6}")
for held_out in resolvers:
    train_res = [r for r in resolvers if r != held_out]

    # Build train: browser (train resolvers) + all malicious (train resolvers)
    mask_tr_b = (df_all['p_type']=='browser') & (df_all['doh_server'].isin(train_res))
    mask_tr_m = (df_all['mdoh']==1)           & (df_all['doh_server'].isin(train_res))
    mask_te_b = (df_all['p_type']=='browser') & (df_all['doh_server']==held_out)
    mask_te_m = (df_all['mdoh']==1)           & (df_all['doh_server']==held_out)

    df_tr = pd.concat([df_all[mask_tr_b], df_all[mask_tr_m]], ignore_index=True)
    df_te = pd.concat([df_all[mask_te_b], df_all[mask_te_m]], ignore_index=True)

    if len(df_te) == 0 or df_te['mdoh'].nunique() < 2:
        print(f"  {held_out:>12}: skipped (insufficient test data)")
        continue

    X_tr = df_tr[FEATURES_6].fillna(0)
    y_tr = df_tr['mdoh'].astype(int)
    X_te = df_te[FEATURES_6].fillna(0)
    y_te = df_te['mdoh'].astype(int)

    sc_lo = RobustScaler(quantile_range=(5, 95))
    X_tr_s = pd.DataFrame(sc_lo.fit_transform(X_tr), columns=FEATURES_6)
    X_te_s = pd.DataFrame(sc_lo.transform(X_te),     columns=FEATURES_6)

    m_lo = make_lgbm()
    m_lo.fit(X_tr_s, y_tr)
    pred_lo = m_lo.predict(X_te_s)

    from sklearn.metrics import balanced_accuracy_score
    f1 = round(f1_score(y_te, pred_lo), 4)
    p  = round(precision_score(y_te, pred_lo), 4)
    r  = round(recall_score(y_te, pred_lo), 4)
    ba = round(balanced_accuracy_score(y_te, pred_lo), 4)
    exp_b[held_out] = {'F1': f1, 'Precision': p, 'Recall': r, 'BalancedAcc': ba,
                       'n_train': len(df_tr), 'n_test': len(df_te)}
    print(f"  {held_out:>12}  {f1:>6}  {p:>6}  {r:>6}  {ba:>6}")

vals = list(exp_b.values())
for m in ['F1','Precision','Recall','BalancedAcc']:
    v = [x[m] for x in vals]
    exp_b[f'{m}_mean'] = round(float(np.mean(v)), 4)
    exp_b[f'{m}_std']  = round(float(np.std(v)),  4)
print(f"  {'Mean±SD':>12}  "
      f"{exp_b['F1_mean']:.4f}±{exp_b['F1_std']:.4f}  "
      f"P={exp_b['Precision_mean']:.4f}  R={exp_b['Recall_mean']:.4f}")

results['leave_one_resolver_out'] = exp_b

# ══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT C — Bootstrap CI for defense (10 seeds)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("EXPERIMENT C: Bootstrap CI for defense (10 seeds)")
print("="*60)

N_SEEDS = 10
base_f1s, def_f1s = [], []
base_ev_sa, def_ev_sa = [], []

for seed in range(N_SEEDS):
    # Baseline
    m_b_s = make_lgbm(seed)
    m_b_s.fit(X2_tr_s, y2_tr)
    pred_b_s = m_b_s.predict(X2_te_s)
    base_f1s.append(f1_score(y2_te, pred_b_s))

    # Defense
    X_d_s, y_d_s = augment_training(BPP_BENIGN_MEAN, seed=seed)
    m_d_s = make_lgbm(seed)
    m_d_s.fit(X_d_s, y_d_s)
    pred_d_s = m_d_s.predict(X2_te_s)
    def_f1s.append(f1_score(y2_te, pred_d_s))

    # SHAP-aware evasion under each seed's models
    df_sa_s = shap_aware_attack(BPP_BENIGN_MEAN, seed=seed+100)
    X_sa_s  = pd.DataFrame(sc2.transform(df_sa_s[FEATURES_6].fillna(0)), columns=FEATURES_6)
    base_ev_sa.append(1 - float((m_b_s.predict(X_sa_s)==1).mean()))
    def_ev_sa.append( 1 - float((m_d_s.predict(X_sa_s)==1).mean()))
    print(f"  seed={seed}  base_f1={base_f1s[-1]:.4f}  def_f1={def_f1s[-1]:.4f}  "
          f"base_ev={base_ev_sa[-1]:.2%}  def_ev={def_ev_sa[-1]:.2%}")

exp_c = {
    'baseline': {
        'F1_mean':  round(float(np.mean(base_f1s)), 4),
        'F1_std':   round(float(np.std(base_f1s)),  4),
        'evasion_SHAP_mean': round(float(np.mean(base_ev_sa)), 4),
        'evasion_SHAP_std':  round(float(np.std(base_ev_sa)),  4),
    },
    'defense': {
        'F1_mean':  round(float(np.mean(def_f1s)), 4),
        'F1_std':   round(float(np.std(def_f1s)),  4),
        'evasion_SHAP_mean': round(float(np.mean(def_ev_sa)), 4),
        'evasion_SHAP_std':  round(float(np.std(def_ev_sa)),  4),
    }
}
print(f"\n  Baseline: F1={exp_c['baseline']['F1_mean']}±{exp_c['baseline']['F1_std']}"
      f"  ev_SHAP={exp_c['baseline']['evasion_SHAP_mean']:.2%}±{exp_c['baseline']['evasion_SHAP_std']:.2%}")
print(f"  Defense:  F1={exp_c['defense']['F1_mean']}±{exp_c['defense']['F1_std']}"
      f"  ev_SHAP={exp_c['defense']['evasion_SHAP_mean']:.2%}±{exp_c['defense']['evasion_SHAP_std']:.2%}")

results['defense_stability'] = exp_c

# ══════════════════════════════════════════════════════════════════════════════
# SAVE
# ══════════════════════════════════════════════════════════════════════════════
out_path = f"{FIG_DIR}/extended_results.json"
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"\n  Saved {out_path}")
