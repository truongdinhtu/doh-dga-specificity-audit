"""
ieee_access_revision.py — experiments added in response to peer review.

  E11  Grouped evaluation: StratifiedGroupKFold by capture session, vs random split
  E12  Conditional probe (Probe 2b): benign vs DGA with the DoH client held fixed
  E13  Uncertainty: group-level bootstrap CIs + repeated seeds for headline metrics
  E14  Detector-family audit: 6-feature vs 18-feature NetFlow sets x 5 model families

Appends to results/ieee_results_revision.json; figures into paper_figures_ieee/.
"""

import warnings; warnings.filterwarnings('ignore')
import os, glob, json
import numpy as np
import pandas as pd
import lightgbm as lgb
import shap
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split, StratifiedGroupKFold
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             balanced_accuracy_score, roc_auc_score)

ROOT     = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA_DIR = f"{ROOT}/Code/data/csv/generated"
HKD_DIR  = f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD"
FIG_DIR  = f"{ROOT}/Code/machine_learning/paper_figures_ieee"
RES_DIR  = f"{ROOT}/Code/machine_learning/results"
os.makedirs(FIG_DIR, exist_ok=True); os.makedirs(RES_DIR, exist_ok=True)

F6 = ["mean_Bpp_ab", "mean_Bpp_ba", "mean_pps_ab", "mean_pps_ba",
      "mean_pkts_asm", "mean_bytes_asm"]
# Extended set: every numeric field a standard IPFIX exporter can supply.
F18 = ["duration", "pkts_aggr", "bytes_aggr", "mean_Bpp", "mean_pps", "mean_Bps",
       "pkts_ab", "pkts_ba", "bytes_ab", "bytes_ba",
       "mean_Bpp_ab", "mean_Bpp_ba", "mean_pps_ab", "mean_pps_ba",
       "mean_Bps_ab", "mean_Bps_ba", "mean_pkts_asm", "mean_bytes_asm"]
R = {}
SEEDS = list(range(10))

# ═══════════════════════════════════════════════════════════════════════
print("Loading ...")
d = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
df_browser = d[d.p_type == 'browser'].copy()
df_tools   = d[d.p_type.isin(['tool_1', 'tool_2'])].copy()
df_mal     = d[d.mdoh == 1].copy()


def load_hkd():
    """Map the real-malware NetExP exports onto both feature sets."""
    out = []
    for f in sorted(glob.glob(f"{HKD_DIR}/*.csv")):
        h = pd.read_csv(f)
        h = h[(h.dport == 443) | (h.sport == 443)]
        B_ab = h.sum_paysize_ab + h.sum_ip_header_len_ab + h.sum_trans_header_len_ab
        B_ba = h.sum_paysize_ba + h.sum_ip_header_len_ba + h.sum_trans_header_len_ba
        dur  = h.duration / 1e6                    # NetExP exports microseconds
        pk   = h.num_packets_ab + h.num_packets_ba
        By   = B_ab + B_ba
        o = pd.DataFrame({
            'duration': dur, 'pkts_aggr': pk, 'bytes_aggr': By,
            'mean_Bpp': By / pk, 'mean_pps': pk / dur, 'mean_Bps': By / dur,
            'pkts_ab': h.num_packets_ab, 'pkts_ba': h.num_packets_ba,
            'bytes_ab': B_ab, 'bytes_ba': B_ba,
            'mean_Bpp_ab': B_ab / h.num_packets_ab,
            'mean_Bpp_ba': B_ba / h.num_packets_ba,
            'mean_pps_ab': h.num_packets_ab / dur,
            'mean_pps_ba': h.num_packets_ba / dur,
            'mean_Bps_ab': B_ab / dur, 'mean_Bps_ba': B_ba / dur,
            'mean_pkts_asm': h.num_packets_ba / pk,
            'mean_bytes_asm': B_ba / By})
        o['family'] = os.path.basename(f).split('-')[0]
        out.append(o)
    r = pd.concat(out, ignore_index=True)
    return r.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)

hkd = load_hkd()
print(f"  real-malware flows: {len(hkd)}")


def make_model(name, seed=42, balanced=False):
    cw = 'balanced' if balanced else None
    if name == 'LightGBM':
        return lgb.LGBMClassifier(objective='binary', num_leaves=63, n_estimators=300,
                                  learning_rate=0.05, random_state=seed,
                                  verbosity=-1, class_weight=cw)
    if name == 'RandomForest':
        return RandomForestClassifier(n_estimators=200, random_state=seed,
                                      n_jobs=-1, class_weight=cw)
    if name == 'ExtraTrees':
        return ExtraTreesClassifier(n_estimators=200, random_state=seed,
                                    n_jobs=-1, class_weight=cw)
    if name == 'LogisticReg':
        return LogisticRegression(max_iter=2000, random_state=seed, class_weight=cw)
    if name == 'kNN':
        return KNeighborsClassifier(n_neighbors=15, n_jobs=-1)
    raise ValueError(name)


def fit_eval(Xtr, ytr, Xte, yte, feats, model='LightGBM', seed=42, balanced=False):
    sc = RobustScaler(quantile_range=(5, 95))
    Xtr_s = pd.DataFrame(sc.fit_transform(Xtr[feats]), columns=feats)
    m = make_model(model, seed, balanced).fit(Xtr_s, ytr)
    p = m.predict(pd.DataFrame(sc.transform(Xte[feats]), columns=feats))
    return m, sc, p


def apply(m, sc, X, feats):
    return m.predict(pd.DataFrame(sc.transform(X[feats]), columns=feats))


# ═══════════════════════════════════════════════════════════════════════
# E11  Grouped evaluation by capture session
# ═══════════════════════════════════════════════════════════════════════
print("\n[E11] Grouped evaluation (capture session)")
E11 = {}
configs = {
    'Model-B': pd.concat([df_browser, df_mal], ignore_index=True),
    'Model-T': pd.concat([df_browser, df_tools, df_mal], ignore_index=True),
}
for name, dd in configs.items():
    X, y, g = dd[F6].fillna(0), dd.mdoh.astype(int), dd.file_name
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.2, stratify=y, random_state=42)
    _, _, p = fit_eval(Xtr, ytr, Xte, yte, F6)
    rnd = {'F1': round(f1_score(yte, p), 4), 'Precision': round(precision_score(yte, p), 4),
           'Recall': round(recall_score(yte, p), 4), 'BA': round(balanced_accuracy_score(yte, p), 4)}
    folds = []
    for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(X, y, groups=g):
        _, _, pf = fit_eval(X.iloc[tr], y.iloc[tr], X.iloc[te], y.iloc[te], F6)
        folds.append({'F1': f1_score(y.iloc[te], pf),
                      'Precision': precision_score(y.iloc[te], pf),
                      'Recall': recall_score(y.iloc[te], pf),
                      'BA': balanced_accuracy_score(y.iloc[te], pf)})
    grp = {k: round(float(np.mean([f[k] for f in folds])), 4) for k in folds[0]}
    grp_sd = {k: round(float(np.std([f[k] for f in folds])), 4) for k in folds[0]}
    E11[name] = {'random_split': rnd, 'grouped_mean': grp, 'grouped_std': grp_sd,
                 'n_groups': int(g.nunique())}
    print(f"   {name}: random F1={rnd['F1']}  grouped F1={grp['F1']}+/-{grp_sd['F1']} "
          f"({g.nunique()} sessions)")
R['E11_grouped'] = E11

# ═══════════════════════════════════════════════════════════════════════
# E12  Probe 2b — conditional test with the DoH client held fixed
# ═══════════════════════════════════════════════════════════════════════
print("\n[E12] Probe 2b — conditional (client held fixed), class-balanced")


def conditional(sub, nsplit=4, feats=F6, model='LightGBM'):
    X, y, g = sub[feats].fillna(0), sub.mdoh.astype(int), sub.file_name
    BA, AUC, F1 = [], [], []
    for tr, te in StratifiedGroupKFold(n_splits=nsplit, shuffle=True,
                                       random_state=42).split(X, y, groups=g):
        sc = RobustScaler(quantile_range=(5, 95))
        Xtr_s = pd.DataFrame(sc.fit_transform(X.iloc[tr]), columns=feats)
        m = make_model(model, 42, balanced=(model != 'kNN')).fit(Xtr_s, y.iloc[tr])
        Xte_s = pd.DataFrame(sc.transform(X.iloc[te]), columns=feats)
        pr = m.predict(Xte_s)
        BA.append(balanced_accuracy_score(y.iloc[te], pr))
        AUC.append(roc_auc_score(y.iloc[te], m.predict_proba(Xte_s)[:, 1]))
        F1.append(f1_score(y.iloc[te], pr, zero_division=0))
    return {'BA': round(float(np.mean(BA)), 4), 'BA_std': round(float(np.std(BA)), 4),
            'AUC': round(float(np.mean(AUC)), 4), 'AUC_std': round(float(np.std(AUC)), 4),
            'F1': round(float(np.mean(F1)), 4),
            'n_benign': int((y == 0).sum()), 'n_malicious': int((y == 1).sum())}

E12 = {'reference_browser_vs_dga': conditional(
    pd.concat([df_browser, df_mal], ignore_index=True), 5)}
print("   reference (browser benign vs DGA):", E12['reference_browser_vs_dga'])
E12['per_client'] = {}
for tool in sorted(df_tools.p_name.unique()):
    tb = df_tools[df_tools.p_name == tool]
    tm = df_mal[df_mal.p_name == tool].sample(n=min(len(df_mal[df_mal.p_name == tool]),
                                                    len(tb)), random_state=42)
    E12['per_client'][tool] = conditional(pd.concat([tb, tm], ignore_index=True))
    print(f"   {tool:<12}", E12['per_client'][tool])
E12['pooled_cli'] = conditional(
    pd.concat([df_tools, df_mal.sample(n=len(df_tools), random_state=42)], ignore_index=True), 5)
print("   pooled CLI:", E12['pooled_cli'])
R['E12_conditional'] = E12

# ═══════════════════════════════════════════════════════════════════════
# E13  Uncertainty — group bootstrap + repeated seeds
# ═══════════════════════════════════════════════════════════════════════
print("\n[E13] Uncertainty quantification")
d2 = pd.concat([df_browser, df_mal], ignore_index=True)
X2, y2, g2 = d2[F6].fillna(0), d2.mdoh.astype(int), d2.file_name
X2tr, X2te, y2tr, y2te, g2tr, g2te = train_test_split(
    X2, y2, g2, test_size=.2, stratify=y2, random_state=42)
mB, scB, p2 = fit_eval(X2tr, y2tr, X2te, y2te, F6)


def group_bootstrap_ci(y_true, y_pred, groups, fn, n=2000, seed=0):
    """Resample whole capture sessions with replacement."""
    rng = np.random.default_rng(seed)
    y_true = np.asarray(y_true); y_pred = np.asarray(y_pred)
    groups = np.asarray(groups); uniq = np.unique(groups)
    idx_by_g = {u: np.where(groups == u)[0] for u in uniq}
    vals = []
    for _ in range(n):
        pick = rng.choice(uniq, size=len(uniq), replace=True)
        idx = np.concatenate([idx_by_g[u] for u in pick])
        try:
            v = fn(y_true[idx], y_pred[idx])
            if not np.isnan(v):
                vals.append(v)
        except Exception:
            pass
    return (round(float(np.percentile(vals, 2.5)), 4),
            round(float(np.percentile(vals, 97.5)), 4))

E13 = {'stage2_test_set': {}}
for mname, fn in [('F1', f1_score), ('Precision', precision_score),
                  ('Recall', recall_score), ('BA', balanced_accuracy_score)]:
    lo, hi = group_bootstrap_ci(y2te, p2, g2te, fn)
    E13['stage2_test_set'][mname] = {'point': round(float(fn(y2te, p2)), 4), 'ci95': [lo, hi]}
print("   Model-B test-set CIs:", E13['stage2_test_set'])

# FPR on tools, bootstrapped over tool capture sessions
pt = apply(mB, scB, df_tools.fillna(0), F6)
lo, hi = group_bootstrap_ci(np.zeros(len(pt)), pt, df_tools.file_name.values,
                            lambda a, b: b.mean())
E13['fpr_tools'] = {'point': round(float(pt.mean()), 4), 'ci95': [lo, hi]}
print("   FPR tools:", E13['fpr_tools'])

# Real-malware recall: only one capture per family, so bootstrap flows within family
ph = apply(mB, scB, hkd.fillna(0), F6)
rng = np.random.default_rng(0)
E13['real_malware_recall'] = {}
for fam, v in hkd.assign(p=ph).groupby('family'):
    arr = v.p.values
    bs = [rng.choice(arr, len(arr), replace=True).mean() for _ in range(2000)]
    E13['real_malware_recall'][fam] = {
        'point': round(float(arr.mean()), 4), 'n': int(len(arr)),
        'ci95': [round(float(np.percentile(bs, 2.5)), 4),
                 round(float(np.percentile(bs, 97.5)), 4)]}
bs = [rng.choice(ph, len(ph), replace=True).mean() for _ in range(2000)]
E13['real_malware_recall']['overall'] = {
    'point': round(float(ph.mean()), 4), 'n': int(len(ph)),
    'ci95': [round(float(np.percentile(bs, 2.5)), 4),
             round(float(np.percentile(bs, 97.5)), 4)]}
print("   real-malware recall:", E13['real_malware_recall']['overall'])

# Repeated seeds for Model-B and the SHAP share
seed_f1, seed_share = [], []
for s in SEEDS:
    Xa, Xb, ya, yb = train_test_split(X2, y2, test_size=.2, stratify=y2, random_state=s)
    sc = RobustScaler(quantile_range=(5, 95))
    Xa_s = pd.DataFrame(sc.fit_transform(Xa[F6]), columns=F6)
    m = make_model('LightGBM', s).fit(Xa_s, ya)
    Xb_s = pd.DataFrame(sc.transform(Xb[F6]), columns=F6)
    seed_f1.append(f1_score(yb, m.predict(Xb_s)))
    sv = shap.TreeExplainer(m).shap_values(Xb_s)
    sv = sv[1] if isinstance(sv, list) else sv
    ms = np.abs(sv).mean(0)
    seed_share.append(ms[F6.index('mean_Bpp_ab')] / ms.sum())
E13['seeds'] = {'n': len(SEEDS),
                'F1_mean': round(float(np.mean(seed_f1)), 4),
                'F1_std': round(float(np.std(seed_f1)), 4),
                'shap_top_share_mean': round(float(np.mean(seed_share)), 4),
                'shap_top_share_std': round(float(np.std(seed_share)), 4)}
print("   10 seeds:", E13['seeds'])
R['E13_uncertainty'] = E13

# ═══════════════════════════════════════════════════════════════════════
# E14  Detector-family audit
# ═══════════════════════════════════════════════════════════════════════
print("\n[E14] Detector-family audit (feature set x model family)")
E14 = {}
s3 = pd.read_csv(f"{DATA_DIR}/s3_dga.csv")
s3['fam'] = s3.p_type.astype(str).str.replace(r'_\d+$', '', regex=True)

for fs_name, feats in [('NetFlow-6', F6), ('NetFlow-18', F18)]:
    for mdl in ['LightGBM', 'RandomForest', 'ExtraTrees', 'LogisticReg', 'kNN']:
        key = f"{fs_name} / {mdl}"
        dd = pd.concat([df_browser, df_mal], ignore_index=True)
        X, y, g = dd[feats].fillna(0), dd.mdoh.astype(int), dd.file_name
        # grouped headline F1
        f1s = []
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True,
                                           random_state=42).split(X, y, groups=g):
            _, _, pf = fit_eval(X.iloc[tr], y.iloc[tr], X.iloc[te], y.iloc[te], feats, mdl)
            f1s.append(f1_score(y.iloc[te], pf))
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.2, stratify=y, random_state=42)
        m, sc, _ = fit_eval(Xtr, ytr, Xte, yte, feats, mdl)
        fpr_t = float(apply(m, sc, df_tools[feats].fillna(0), feats).mean())
        rec_r = float(apply(m, sc, hkd[feats].fillna(0), feats).mean())
        # Probe 2: client-tool identification on the malicious flows
        Xc, yc = s3[feats].fillna(0), s3.p_name
        Xct, Xcv, yct, ycv = train_test_split(Xc, yc, test_size=.2, stratify=yc, random_state=42)
        scc = RobustScaler(quantile_range=(5, 95))
        mc = make_model(mdl if mdl != 'LightGBM' else 'LightGBM', 42)
        if mdl == 'LightGBM':
            mc = lgb.LGBMClassifier(objective='multiclass', num_leaves=63, n_estimators=300,
                                    learning_rate=0.05, random_state=42, verbosity=-1)
        mc.fit(pd.DataFrame(scc.fit_transform(Xct), columns=feats), yct)
        tool_f1 = f1_score(ycv, mc.predict(pd.DataFrame(scc.transform(Xcv), columns=feats)),
                           average='macro')
        # family identification, same features
        yf = s3.fam
        Xft, Xfv, yft, yfv = train_test_split(Xc, yf, test_size=.2, stratify=yf, random_state=42)
        mf = (lgb.LGBMClassifier(objective='multiclass', num_leaves=63, n_estimators=300,
                                 learning_rate=0.05, random_state=42, verbosity=-1)
              if mdl == 'LightGBM' else make_model(mdl, 42))
        scf = RobustScaler(quantile_range=(5, 95))
        mf.fit(pd.DataFrame(scf.fit_transform(Xft), columns=feats), yft)
        fam_f1 = f1_score(yfv, mf.predict(pd.DataFrame(scf.transform(Xfv), columns=feats)),
                          average='macro')
        # Probe 2b conditional
        cond = conditional(pd.concat(
            [df_tools, df_mal.sample(n=len(df_tools), random_state=42)], ignore_index=True),
            5, feats, mdl)
        E14[key] = {'grouped_F1': round(float(np.mean(f1s)), 4),
                    'grouped_F1_std': round(float(np.std(f1s)), 4),
                    'fpr_tools': round(fpr_t, 4), 'real_malware_recall': round(rec_r, 4),
                    'tool_macroF1': round(float(tool_f1), 4),
                    'family_macroF1': round(float(fam_f1), 4),
                    'conditional_BA': cond['BA'], 'conditional_AUC': cond['AUC']}
        print(f"   {key:<28} F1={E14[key]['grouped_F1']:.4f} tool={tool_f1:.4f} "
              f"fam={fam_f1:.4f} FPRt={fpr_t:.4f} real={rec_r:.4f} condBA={cond['BA']:.4f}")
R['E14_detector_family'] = E14

# ═══════════════════════════════════════════════════════════════════════
# Figure — conditional probe
# ═══════════════════════════════════════════════════════════════════════
plt.rcParams.update({'font.size': 9, 'figure.dpi': 200})
fig, ax = plt.subplots(1, 2, figsize=(7.16, 2.4))
labels = ['browser\nvs DGA'] + [t for t in sorted(E12['per_client'])] + ['pooled\nCLI']
bas = ([E12['reference_browser_vs_dga']['BA']] +
       [E12['per_client'][t]['BA'] for t in sorted(E12['per_client'])] +
       [E12['pooled_cli']['BA']])
sds = ([E12['reference_browser_vs_dga']['BA_std']] +
       [E12['per_client'][t]['BA_std'] for t in sorted(E12['per_client'])] +
       [E12['pooled_cli']['BA_std']])
cols = ['#C62828'] + ['#1565C0'] * len(E12['per_client']) + ['#0D47A1']
b = ax[0].bar(range(len(labels)), [v * 100 for v in bas],
              yerr=[v * 100 for v in sds], capsize=2.5,
              color=cols, edgecolor='k', linewidth=.4, width=.62)
ax[0].axhline(50, color='k', ls='--', lw=1)
ax[0].text(len(labels) - .4, 52, 'chance', fontsize=6.5, ha='right')
ax[0].set_xticks(range(len(labels)))
ax[0].set_xticklabels(labels, fontsize=6.5)
ax[0].set_ylabel('balanced accuracy (%)'); ax[0].set_ylim(0, 108)
ax[0].set_title('(a) Benign vs DGA, client held fixed', fontweight='bold', fontsize=8)
for bi, v in zip(b, bas):
    ax[0].text(bi.get_x() + bi.get_width() / 2, v * 100 + 3, f'{v*100:.0f}',
               ha='center', fontsize=6.5, fontweight='bold')

names = list(E11)
x = np.arange(len(names)); w = .35
ax[1].bar(x - w / 2, [E11[n]['random_split']['F1'] * 100 for n in names], w,
          label='random flow split', color='#B0BEC5', edgecolor='k', linewidth=.4)
ax[1].bar(x + w / 2, [E11[n]['grouped_mean']['F1'] * 100 for n in names], w,
          yerr=[E11[n]['grouped_std']['F1'] * 100 for n in names], capsize=2.5,
          label='grouped by session', color='#455A64', edgecolor='k', linewidth=.4)
ax[1].set_xticks(x); ax[1].set_xticklabels(names); ax[1].set_ylabel('F1 (%)')
ax[1].set_ylim(80, 104); ax[1].legend(fontsize=6.5, frameon=False)
ax[1].set_title('(b) Session-level leakage control', fontweight='bold', fontsize=8)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig_conditional.pdf", bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig_conditional.png", bbox_inches='tight'); plt.close()

out = f"{RES_DIR}/ieee_results_revision.json"
with open(out, 'w') as fh:
    json.dump(R, fh, indent=2, default=str)
print(f"\nSaved {out}")
