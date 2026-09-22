"""
ieee_access_round3.py — experiments added in response to the second pre-submission review.

  E15  Full factorial Probe 2b: client x resolver x encoding held fixed (24 cells)
  E16  Nested session-grouped CV for Model-B hyperparameters (model-selection leakage check)
  E17  Intervention: match Bpp_ab distributions across classes -> does F1 collapse?
  E18  Leave-one-client-out (Model-T)
  E19  Flow-size-matched cross-dataset check (partial control for aggregation mismatch)
  E20  Probe 2b at realistic prevalence: PR-AUC, FPR at fixed recall

Writes results/ieee_results_round3.json; figures into paper_figures_ieee/.
"""

import warnings; warnings.filterwarnings('ignore')
import os, glob, json, itertools
import numpy as np
import pandas as pd
import lightgbm as lgb
import shap
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, StratifiedGroupKFold, GroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             balanced_accuracy_score, roc_auc_score,
                             average_precision_score)

ROOT     = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA_DIR = f"{ROOT}/Code/data/csv/generated"
HKD_DIR  = f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD"
FIG_DIR  = f"{ROOT}/Code/machine_learning/paper_figures_ieee"
RES_DIR  = f"{ROOT}/Code/machine_learning/results"

F6 = ["mean_Bpp_ab", "mean_Bpp_ba", "mean_pps_ab", "mean_pps_ba",
      "mean_pkts_asm", "mean_bytes_asm"]
R = {}

d = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
df_browser = d[d.p_type == 'browser'].copy()
df_tools   = d[d.p_type.isin(['tool_1', 'tool_2'])].copy()
df_mal     = d[d.mdoh == 1].copy()


def load_hkd():
    out = []
    for f in sorted(glob.glob(f"{HKD_DIR}/*.csv")):
        h = pd.read_csv(f); h = h[(h.dport == 443) | (h.sport == 443)]
        B_ab = h.sum_paysize_ab + h.sum_ip_header_len_ab + h.sum_trans_header_len_ab
        B_ba = h.sum_paysize_ba + h.sum_ip_header_len_ba + h.sum_trans_header_len_ba
        dur = h.duration / 1e6
        o = pd.DataFrame({'mean_Bpp_ab': B_ab / h.num_packets_ab, 'mean_Bpp_ba': B_ba / h.num_packets_ba,
                          'mean_pps_ab': h.num_packets_ab / dur, 'mean_pps_ba': h.num_packets_ba / dur,
                          'mean_pkts_asm': h.num_packets_ba / (h.num_packets_ab + h.num_packets_ba),
                          'mean_bytes_asm': B_ba / (B_ab + B_ba), 'pkts_aggr': h.num_packets})
        o['family'] = os.path.basename(f).split('-')[0]; out.append(o)
    return pd.concat(out, ignore_index=True).replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)

hkd = load_hkd()


def lgbm(seed=42, balanced=False, **hp):
    return lgb.LGBMClassifier(objective='binary', random_state=seed, verbosity=-1,
                              class_weight='balanced' if balanced else None,
                              **({'num_leaves': 63, 'n_estimators': 300, 'learning_rate': 0.05} | hp))


def fit(X, y, feats=F6, seed=42, balanced=False, **hp):
    sc = RobustScaler(quantile_range=(5, 95))
    m = lgbm(seed, balanced, **hp).fit(pd.DataFrame(sc.fit_transform(X[feats]), columns=feats), y)
    return m, sc


def pred(m, sc, X, feats=F6):
    return m.predict(pd.DataFrame(sc.transform(X[feats]), columns=feats))


def proba(m, sc, X, feats=F6):
    return m.predict_proba(pd.DataFrame(sc.transform(X[feats]), columns=feats))[:, 1]


def grouped_eval(sub, nsplit, balanced=True):
    X, y, g = sub[F6].fillna(0), sub.mdoh.astype(int), sub.file_name
    BA, AUC, AP = [], [], []
    for tr, te in StratifiedGroupKFold(n_splits=nsplit, shuffle=True, random_state=42).split(X, y, groups=g):
        m, sc = fit(X.iloc[tr], y.iloc[tr], balanced=balanced)
        p = pred(m, sc, X.iloc[te]); pr = proba(m, sc, X.iloc[te])
        BA.append(balanced_accuracy_score(y.iloc[te], p))
        AUC.append(roc_auc_score(y.iloc[te], pr))
        AP.append(average_precision_score(y.iloc[te], pr))
    return {'BA': round(float(np.mean(BA)), 4), 'BA_std': round(float(np.std(BA)), 4),
            'AUC': round(float(np.mean(AUC)), 4), 'AUC_std': round(float(np.std(AUC)), 4),
            'PR_AUC': round(float(np.mean(AP)), 4)}


# ═══════════════════════════════════════════════════════════════════════
# E15  Full factorial Probe 2b
# ═══════════════════════════════════════════════════════════════════════
print("[E15] Full factorial Probe 2b: client x resolver x encoding")
cli = pd.concat([df_tools, df_mal], ignore_index=True)
cells = {}
for (c, r, e), g in cli.groupby(['p_name', 'doh_server', 'doh_method']):
    nb, nm = (g.mdoh == 0).sum(), (g.mdoh == 1).sum()
    if nb < 30 or nm < 30:
        continue
    gb = g[g.mdoh == 0]; gm = g[g.mdoh == 1].sample(n=min(nm, nb), random_state=42)
    sub = pd.concat([gb, gm], ignore_index=True)
    ns = min(4, sub.file_name.nunique())
    if ns < 2:
        continue
    res = grouped_eval(sub, ns)
    cells[f"{c}|{r}|{e}"] = res | {'n_benign': int(nb), 'n_dga_used': int(len(gm)),
                                   'n_sessions': int(sub.file_name.nunique())}
    print(f"   {c:<12}{r:<11}{e:<5} BA={res['BA']:.3f} AUC={res['AUC']:.3f}  (ben={nb} dga={len(gm)} sess={sub.file_name.nunique()})")
bas = [v['BA'] for v in cells.values()]; aucs = [v['AUC'] for v in cells.values()]
R['E15_factorial'] = {'cells': cells,
                      'summary': {'n_cells': len(cells),
                                  'BA_mean': round(float(np.mean(bas)), 4), 'BA_sd': round(float(np.std(bas)), 4),
                                  'BA_min': round(float(np.min(bas)), 4), 'BA_max': round(float(np.max(bas)), 4),
                                  'AUC_mean': round(float(np.mean(aucs)), 4), 'AUC_sd': round(float(np.std(aucs)), 4),
                                  'cells_BA_above_0.6': int(sum(b > 0.6 for b in bas))}}
print("   summary:", R['E15_factorial']['summary'])

# Hierarchical conditioning: pooled, client only / client+resolver / client+resolver+encoding
# (balanced within stratum, grouped CV on the pooled set)
def stratified_balanced(cols):
    parts = []
    for _, g in cli.groupby(cols):
        nb, nm = (g.mdoh == 0).sum(), (g.mdoh == 1).sum()
        if nb < 30 or nm < 30: continue
        k = min(nb, nm)
        parts += [g[g.mdoh == 0].sample(n=k, random_state=42), g[g.mdoh == 1].sample(n=k, random_state=42)]
    return pd.concat(parts, ignore_index=True)

R['E15_hierarchical'] = {}
for label, cols in [('client', ['p_name']), ('client+resolver', ['p_name', 'doh_server']),
                    ('client+resolver+encoding', ['p_name', 'doh_server', 'doh_method'])]:
    sub = stratified_balanced(cols)
    R['E15_hierarchical'][label] = grouped_eval(sub, 5) | {'n': int(len(sub))}
    print(f"   conditioned on {label:<26}", R['E15_hierarchical'][label])

# ═══════════════════════════════════════════════════════════════════════
# E16  Nested grouped CV — Model-B
# ═══════════════════════════════════════════════════════════════════════
print("\n[E16] Nested session-grouped CV, Model-B")
d2 = pd.concat([df_browser, df_mal], ignore_index=True)
X2, y2, g2 = d2[F6].fillna(0), d2.mdoh.astype(int), d2.file_name
GRID = [dict(num_leaves=nl, n_estimators=ne, learning_rate=lr)
        for nl in (15, 31, 63, 127) for ne in (100, 300) for lr in (0.05, 0.1)]
outer = []
for k, (tr, te) in enumerate(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(X2, y2, groups=g2)):
    Xtr, ytr, gtr = X2.iloc[tr], y2.iloc[tr], g2.iloc[tr]
    best, best_f1 = None, -1
    for hp in GRID:
        inner = []
        for itr, ite in StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=k).split(Xtr, ytr, groups=gtr):
            m, sc = fit(Xtr.iloc[itr], ytr.iloc[itr], **hp)
            inner.append(f1_score(ytr.iloc[ite], pred(m, sc, Xtr.iloc[ite])))
        if np.mean(inner) > best_f1:
            best_f1, best = np.mean(inner), hp
    m, sc = fit(Xtr, ytr, **best)
    f1o = f1_score(y2.iloc[te], pred(m, sc, X2.iloc[te]))
    outer.append({'fold': k, 'selected': best, 'inner_F1': round(float(best_f1), 4), 'outer_F1': round(float(f1o), 4)})
    print(f"   outer fold {k}: selected={best} inner={best_f1:.4f} outer={f1o:.4f}")
R['E16_nested'] = {'folds': outer,
                   'outer_F1_mean': round(float(np.mean([o['outer_F1'] for o in outer])), 4),
                   'outer_F1_std': round(float(np.std([o['outer_F1'] for o in outer])), 4),
                   'grid_size': len(GRID)}
print("   nested outer F1:", R['E16_nested']['outer_F1_mean'], "+/-", R['E16_nested']['outer_F1_std'])

# ═══════════════════════════════════════════════════════════════════════
# E17  Intervention: match Bpp_ab across classes
# ═══════════════════════════════════════════════════════════════════════
print("\n[E17] Intervention — Bpp_ab distribution matching")
bins = np.arange(40, 260, 10)
hb = np.histogram(df_browser.mean_Bpp_ab.clip(40, 259), bins)[0]
hm = np.histogram(df_mal.mean_Bpp_ab.clip(40, 259), bins)[0]
parts_b, parts_m = [], []
for i in range(len(bins) - 1):
    k = min(hb[i], hm[i])
    if k == 0: continue
    lo, hi = bins[i], bins[i + 1]
    parts_b.append(df_browser[(df_browser.mean_Bpp_ab >= lo) & (df_browser.mean_Bpp_ab < hi)].sample(n=k, random_state=42))
    parts_m.append(df_mal[(df_mal.mean_Bpp_ab >= lo) & (df_mal.mean_Bpp_ab < hi)].sample(n=k, random_state=42))
matched = pd.concat(parts_b + parts_m, ignore_index=True)
print(f"   matched set: n_benign={len(pd.concat(parts_b))} n_mal={len(pd.concat(parts_m))}")
res_m = grouped_eval(matched, 5, balanced=False)
# also: F1 and SHAP on matched set with a random split
Xm, ym = matched[F6].fillna(0), matched.mdoh.astype(int)
Xtr, Xte, ytr, yte = train_test_split(Xm, ym, test_size=.2, stratify=ym, random_state=42)
m, sc = fit(Xtr, ytr); p = pred(m, sc, Xte)
sv = shap.TreeExplainer(m).shap_values(pd.DataFrame(sc.transform(Xte), columns=F6))
sv = sv[1] if isinstance(sv, list) else sv
share = pd.Series(np.abs(sv).mean(0), index=F6); share = (share / share.sum()).round(4)
R['E17_bpp_matched'] = res_m | {'n_benign': int(len(pd.concat(parts_b))), 'n_malicious': int(len(pd.concat(parts_m))),
                                'F1_random_split': round(float(f1_score(yte, p)), 4),
                                'shap_share_after_matching': share.to_dict(),
                                'bpp_share_after_matching': float(share['mean_Bpp_ab'])}
print("   after matching Bpp_ab:", res_m, "F1=", R['E17_bpp_matched']['F1_random_split'])
print("   SHAP share after matching:", share.to_dict())

# ═══════════════════════════════════════════════════════════════════════
# E18  Leave-one-client-out (Model-T)
# ═══════════════════════════════════════════════════════════════════════
print("\n[E18] Leave-one-client-out, Model-T")
dT = pd.concat([df_browser, df_tools, df_mal], ignore_index=True)
loco = {}
for tool in sorted(df_tools.p_name.unique()):
    tr = dT[dT.p_name != tool]; te = dT[dT.p_name == tool]
    m, sc = fit(tr[F6].fillna(0), tr.mdoh.astype(int))
    p = pred(m, sc, te.fillna(0)); y = te.mdoh.astype(int)
    loco[tool] = {'F1': round(float(f1_score(y, p)), 4), 'BA': round(float(balanced_accuracy_score(y, p)), 4),
                  'FPR_heldout_tool_benign': round(float(p[y.values == 0].mean()), 4),
                  'recall_heldout_tool_dga': round(float(p[y.values == 1].mean()), 4),
                  'n_test': int(len(te))}
    print(f"   hold out {tool:<12}", loco[tool])
R['E18_loco'] = loco

# ═══════════════════════════════════════════════════════════════════════
# E19  Flow-size-matched cross-dataset check
# ═══════════════════════════════════════════════════════════════════════
print("\n[E19] Flow-size-matched cross-dataset check")
mB, scB = fit(*train_test_split(X2, y2, test_size=.2, stratify=y2, random_state=42)[0::2])
short_real = hkd[hkd.pkts_aggr <= 100]; long_real = hkd[hkd.pkts_aggr > 100]
long_gen = d2[d2.pkts_aggr >= 100]
E19 = {'real_short_le100': {'n': int(len(short_real)), 'recall_modelB': round(float(pred(mB, scB, short_real).mean()), 4),
                            'bpp_ab_mean': round(float(short_real.mean_Bpp_ab.mean()), 2),
                            'families': short_real.family.value_counts().to_dict()},
       'real_long_gt100': {'n': int(len(long_real)), 'recall_modelB': round(float(pred(mB, scB, long_real).mean()), 4),
                           'bpp_ab_mean': round(float(long_real.mean_Bpp_ab.mean()), 2)},
       'generated_long_ge100': {'n': int(len(long_gen)),
                                'bpp_ab_browser': round(float(long_gen[long_gen.mdoh == 0].mean_Bpp_ab.mean()), 2),
                                'bpp_ab_dga': round(float(long_gen[long_gen.mdoh == 1].mean_Bpp_ab.mean()), 2),
                                'n_browser': int((long_gen.mdoh == 0).sum()), 'n_dga': int((long_gen.mdoh == 1).sum())}}
# Model-B trained ONLY on long generated flows, tested on long real flows
Xl, yl = long_gen[F6].fillna(0), long_gen.mdoh.astype(int)
Xltr, Xlte, yltr, ylte = train_test_split(Xl, yl, test_size=.2, stratify=yl, random_state=42)
mL, scL = fit(Xltr, yltr)
E19['modelB_long_only'] = {'in_domain_F1': round(float(f1_score(ylte, pred(mL, scL, Xlte))), 4),
                           'recall_real_long': round(float(pred(mL, scL, long_real).mean()), 4),
                           'recall_real_all': round(float(pred(mL, scL, hkd).mean()), 4)}
R['E19_size_matched'] = E19
for k, v in E19.items(): print(f"   {k}: {v}")

# ═══════════════════════════════════════════════════════════════════════
# E20  Probe 2b at realistic prevalence
# ═══════════════════════════════════════════════════════════════════════
print("\n[E20] Probe 2b pooled CLI — PR-AUC and FPR at fixed recall")
sub = pd.concat([df_tools, df_mal.sample(n=len(df_tools), random_state=42)], ignore_index=True)
X, y, g = sub[F6].fillna(0), sub.mdoh.astype(int), sub.file_name
scores, ys = [], []
for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(X, y, groups=g):
    m, sc = fit(X.iloc[tr], y.iloc[tr], balanced=True)
    scores.append(proba(m, sc, X.iloc[te])); ys.append(y.iloc[te].values)
s, yy = np.concatenate(scores), np.concatenate(ys)
from sklearn.metrics import roc_curve
fpr, tpr, _ = roc_curve(yy, s)
def fpr_at(rec): return float(fpr[np.searchsorted(tpr, rec)])
R['E20_prevalence'] = {'PR_AUC_balanced': round(float(average_precision_score(yy, s)), 4),
                       'PR_AUC_chance_balanced': 0.5,
                       'FPR_at_recall_0.5': round(fpr_at(0.5), 4),
                       'FPR_at_recall_0.9': round(fpr_at(0.9), 4)}
print("  ", R['E20_prevalence'])

# ═══════════════════════════════════════════════════════════════════════
# Figure — factorial cells
# ═══════════════════════════════════════════════════════════════════════
plt.rcParams.update({'font.size': 9, 'figure.dpi': 200})
fig, ax = plt.subplots(1, 2, figsize=(7.16, 2.5), gridspec_kw={'width_ratios': [2.2, 1]})
keys = sorted(cells); vals = [cells[k]['BA'] for k in keys]; sds = [cells[k]['BA_std'] for k in keys]
cols = {'curl': '#1565C0', 'h2': '#2E7D32', 'h2dnspython': '#6A1B9A', 'kdig': '#C62828'}
ax[0].bar(range(len(keys)), [v * 100 for v in vals], yerr=[v * 100 for v in sds], capsize=1.5,
          color=[cols[k.split('|')[0]] for k in keys], edgecolor='k', linewidth=.3, width=.75)
ax[0].axhline(50, color='k', ls='--', lw=1); ax[0].set_ylim(0, 100)
ax[0].set_xticks(range(len(keys)))
ax[0].set_xticklabels([k.split('|')[1][:3] + '/' + k.split('|')[2] for k in keys], rotation=90, fontsize=5.5)
ax[0].set_ylabel('balanced accuracy (%)')
ax[0].set_title('(a) Benign vs DGA in each client x resolver x encoding cell', fontweight='bold', fontsize=8)
from matplotlib.patches import Patch
ax[0].legend(handles=[Patch(color=c, label=t) for t, c in cols.items()], fontsize=6, ncol=4,
             loc='upper center', frameon=False)
lv = ['client', 'client+resolver', 'client+resolver+encoding']
hv = [R['E15_hierarchical'][l]['BA'] * 100 for l in lv]; hs = [R['E15_hierarchical'][l]['BA_std'] * 100 for l in lv]
ax[1].bar(range(3), hv, yerr=hs, capsize=2.5, color='#455A64', edgecolor='k', linewidth=.4, width=.6)
ax[1].axhline(50, color='k', ls='--', lw=1); ax[1].set_ylim(0, 100)
ax[1].set_xticks(range(3)); ax[1].set_xticklabels(['client', '+resolver', '+encoding'], fontsize=7)
ax[1].set_title('(b) Pooled, conditioned on', fontweight='bold', fontsize=8)
for i, v in enumerate(hv): ax[1].text(i, v + hs[i] + 2, f'{v:.0f}', ha='center', fontsize=7)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig_factorial.pdf", bbox_inches='tight'); plt.savefig(f"{FIG_DIR}/fig_factorial.png", bbox_inches='tight')

with open(f"{RES_DIR}/ieee_results_round3.json", 'w') as fh:
    json.dump(R, fh, indent=2, default=str)
print("\nSaved.")
