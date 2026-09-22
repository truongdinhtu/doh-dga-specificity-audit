"""
ieee_access_experiments.py — experiment suite for the IEEE Access resubmission.

Reframes the study around the client-implementation confound:
  E1  Stage 1 (DoH vs. general HTTPS)
  E2  Stage 2 baseline (browser benign vs. simulated DGA) + TreeSHAP
  E3  Confound evidence A: SHAP concentration
  E4  Confound evidence B: FPR on tool-based legitimate DoH
  E5  Confound evidence C: recall on REAL malware DoH captures  <-- headline
  E6  Adversarial evasion (4 strategies) + SHAP-guided adversarial training
  E7  Remediation: Model-R (tool benign + real malware), leave-one-family-out
  E8  Scaler ablation
  E9  Leave-one-resolver-out cross-resolver validation
  E10 Stage 3 DGA-family attribution diagnostic + per-family SHAP

Writes results/ieee_results.json and figures into paper_figures_ieee/.
"""

import warnings; warnings.filterwarnings('ignore')
import os, glob, json
import numpy as np
import pandas as pd
import lightgbm as lgb
import shap
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler, StandardScaler, MinMaxScaler
from sklearn.metrics import (f1_score, precision_score, recall_score,
                             balanced_accuracy_score, confusion_matrix,
                             classification_report)

ROOT     = "/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
DATA_DIR = f"{ROOT}/Code/data/csv/generated"
HKD_DIR  = f"{ROOT}/Code/data/csv_from_pcap/malicious/HKD"
FIG_DIR  = f"{ROOT}/Code/machine_learning/paper_figures_ieee"
os.makedirs(FIG_DIR, exist_ok=True)

F6 = ["mean_Bpp_ab", "mean_Bpp_ba", "mean_pps_ab", "mean_pps_ba",
      "mean_pkts_asm", "mean_bytes_asm"]
LBL = {"mean_Bpp_ab": r"$\overline{B^{pp}_{ab}}$",
       "mean_Bpp_ba": r"$\overline{B^{pp}_{ba}}$",
       "mean_pps_ab": r"$\overline{pps}_{ab}$",
       "mean_pps_ba": r"$\overline{pps}_{ba}$",
       "mean_pkts_asm": r"$\overline{A}_{pkt}$",
       "mean_bytes_asm": r"$\overline{A}_{byte}$"}
FAMS = ['pitou', 'qsnatch', 'ramnit', 'zloader']
R = {}
np.random.seed(42)

def lgbm(seed=42, **kw):
    return lgb.LGBMClassifier(objective=kw.pop('objective', 'binary'),
                              num_leaves=63, n_estimators=300, learning_rate=0.05,
                              random_state=seed, verbosity=-1, **kw)

def fit_scaled(X, y, model=None, scaler=None, seed=42):
    if scaler is None:
        scaler = RobustScaler(quantile_range=(5, 95))
    Xs = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    if model is None:
        model = lgbm(seed)
    model.fit(Xs, y)
    return model, scaler

def pred(model, scaler, X):
    return model.predict(pd.DataFrame(scaler.transform(X[F6]), columns=F6))

def binmetrics(y, p):
    return {'F1': round(f1_score(y, p), 4),
            'Precision': round(precision_score(y, p), 4),
            'Recall': round(recall_score(y, p), 4),
            'BA': round(balanced_accuracy_score(y, p), 4)}

# ═══════════════════════════════════════════════════════════════════════
# Load
# ═══════════════════════════════════════════════════════════════════════
print("Loading data ...")
d = pd.read_csv(f"{DATA_DIR}/s2_mdoh.csv")
df_browser = d[d.p_type == 'browser'].copy()
df_tools   = d[d.p_type.isin(['tool_1', 'tool_2'])].copy()
df_mal     = d[d.mdoh == 1].copy()


def load_hkd():
    """Map NetExP per-flow statistics of the real-malware DoH captures onto F6."""
    out = []
    for f in sorted(glob.glob(f"{HKD_DIR}/*.csv")):
        h = pd.read_csv(f)
        h = h[(h.dport == 443) | (h.sport == 443)]
        B_ab = h.sum_paysize_ab + h.sum_ip_header_len_ab + h.sum_trans_header_len_ab
        B_ba = h.sum_paysize_ba + h.sum_ip_header_len_ba + h.sum_trans_header_len_ba
        dur_s = h.duration / 1e6          # NetExP exports flow duration in microseconds
        o = pd.DataFrame({
            'mean_Bpp_ab': B_ab / h.num_packets_ab,
            'mean_Bpp_ba': B_ba / h.num_packets_ba,
            'mean_pps_ab': h.num_packets_ab / dur_s,
            'mean_pps_ba': h.num_packets_ba / dur_s,
            'mean_pkts_asm': h.num_packets_ba / (h.num_packets_ab + h.num_packets_ba),
            'mean_bytes_asm': B_ba / (B_ab + B_ba)})
        o['family'] = os.path.basename(f).split('-')[0]
        out.append(o)
    r = pd.concat(out, ignore_index=True)
    return r.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)

hkd = load_hkd()
R['hkd_stats'] = {'n_flows': len(hkd),
                  'per_family': hkd.groupby('family').size().to_dict(),
                  'feature_means': hkd.groupby('family')[F6].mean().round(3).to_dict('index')}
print(f"  real-malware flows: {len(hkd)}  {hkd.groupby('family').size().to_dict()}")

R['bpp_reference'] = {
    'benign_browser': round(float(df_browser.mean_Bpp_ab.mean()), 2),
    'benign_tools':   round(float(df_tools.mean_Bpp_ab.mean()), 2),
    'simulated_dga':  round(float(df_mal.mean_Bpp_ab.mean()), 2),
    'real_malware':   round(float(hkd.mean_Bpp_ab.mean()), 2)}
print("  Bpp_ab reference:", R['bpp_reference'])

# ═══════════════════════════════════════════════════════════════════════
# E1  Stage 1 — DoH vs. general HTTPS
# ═══════════════════════════════════════════════════════════════════════
print("\n[E1] Stage 1 — DoH vs. general HTTPS")
s1 = pd.read_csv(f"{DATA_DIR}/s1_doh.csv")
X1, y1 = s1[F6].fillna(0), s1['doh'].astype(int)
X1tr, X1te, y1tr, y1te = train_test_split(X1, y1, test_size=.2, stratify=y1, random_state=42)
m1, sc1 = fit_scaled(X1tr, y1tr, model=RandomForestClassifier(
    n_estimators=200, max_depth=None, random_state=42, n_jobs=-1))
p1 = m1.predict(pd.DataFrame(sc1.transform(X1te), columns=F6))
R['stage1'] = binmetrics(y1te, p1) | {'n_train': len(X1tr), 'n_test': len(X1te),
                                      'n_pos': int(y1.sum()), 'n_neg': int((y1 == 0).sum())}
print("  ", R['stage1'])

# ═══════════════════════════════════════════════════════════════════════
# E2  Stage 2 baseline (Model-B) + TreeSHAP
# ═══════════════════════════════════════════════════════════════════════
print("\n[E2] Stage 2 baseline (Model-B: browser benign vs. simulated DGA)")
d2 = pd.concat([df_browser, df_mal], ignore_index=True)
X2, y2 = d2[F6].fillna(0), d2.mdoh.astype(int)
X2tr, X2te, y2tr, y2te = train_test_split(X2, y2, test_size=.2, stratify=y2, random_state=42)
mB, scB = fit_scaled(X2tr, y2tr)
X2te_s = pd.DataFrame(scB.transform(X2te), columns=F6)
p2 = mB.predict(X2te_s)
tn, fp, fn, tp = confusion_matrix(y2te, p2).ravel()
R['stage2_baseline'] = binmetrics(y2te, p2) | {
    'FPR': round(fp / (fp + tn), 4), 'FNR': round(fn / (fn + tp), 4),
    'n_train': len(X2tr), 'n_test': len(X2te),
    'n_benign': int((y2 == 0).sum()), 'n_malicious': int(y2.sum())}
print("  ", R['stage2_baseline'])

print("  TreeSHAP ...")
sv = shap.TreeExplainer(mB).shap_values(X2te_s)
sv = sv[1] if isinstance(sv, list) else sv
msh = pd.Series(np.abs(sv).mean(0), index=F6).sort_values(ascending=False)
R['shap_s2'] = {'mean_abs': msh.round(4).to_dict(),
                'share': (msh / msh.sum()).round(4).to_dict(),
                'top_share': round(float(msh.iloc[0] / msh.sum()), 4),
                'ratio_top_to_second': round(float(msh.iloc[0] / msh.iloc[1]), 2)}
print("   share:", R['shap_s2']['share'], "top:", R['shap_s2']['top_share'])

# ═══════════════════════════════════════════════════════════════════════
# E4  Confound B — FPR on tool-based legitimate DoH
# ═══════════════════════════════════════════════════════════════════════
print("\n[E4] FPR on tool-based legitimate DoH")
pt = pred(mB, scB, df_tools)
R['fpr_tools'] = {'n': len(df_tools), 'fpr': round(float(pt.mean()), 4),
                  'bpp_ab': round(float(df_tools.mean_Bpp_ab.mean()), 2),
                  'per_tool': {t: {'n': int((df_tools.p_name == t).sum()),
                                   'fpr': round(float(pred(mB, scB, df_tools[df_tools.p_name == t]).mean()), 4),
                                   'bpp_ab': round(float(df_tools[df_tools.p_name == t].mean_Bpp_ab.mean()), 2)}
                               for t in sorted(df_tools.p_name.unique())}}
print("  ", R['fpr_tools']['fpr'], R['fpr_tools']['per_tool'])

# ═══════════════════════════════════════════════════════════════════════
# E5  Confound C — recall on REAL malware  (headline)
# ═══════════════════════════════════════════════════════════════════════
print("\n[E5] Model-B recall on REAL malware DoH captures")
ph = pred(mB, scB, hkd)
hkd_pred = hkd.assign(pred=ph)
R['real_malware_modelB'] = {
    'overall_recall': round(float(ph.mean()), 4), 'n': len(hkd),
    'per_family': {k: {'n': int(v['pred'].size), 'recall': round(float(v['pred'].mean()), 4),
                       'bpp_ab': round(float(v['mean_Bpp_ab'].mean()), 2)}
                   for k, v in hkd_pred.groupby('family')}}
print("  ", R['real_malware_modelB'])

# E5b — robustness of the finding to the capture-duration artefact.
# Real captures are 24 h sessions with HTTP/2 connection reuse, so flow duration and
# flow size differ structurally from the generated short flows.  Re-run Model-B on the
# four duration-independent features to show the result is not a rate artefact.
F4 = ["mean_Bpp_ab", "mean_Bpp_ba", "mean_pkts_asm", "mean_bytes_asm"]
X4tr, X4te = X2tr[F4], X2te[F4]
m4, sc4 = fit_scaled(X4tr, y2tr)
p4 = m4.predict(pd.DataFrame(sc4.transform(X4te), columns=F4))
rec4 = float(m4.predict(pd.DataFrame(sc4.transform(hkd[F4]), columns=F4)).mean())
R['real_malware_no_rate_features'] = binmetrics(y2te, p4) | {'real_malware_recall': round(rec4, 4)}
print("   4-feature (no pps) control:", R['real_malware_no_rate_features'])

R['flow_structure'] = {
    'real_pkts_per_flow_median': float(np.median(
        pd.concat([pd.read_csv(f).num_packets for f in sorted(glob.glob(f"{HKD_DIR}/*.csv"))]))),
    'generated_pkts_per_flow_median': float(d.pkts_aggr.median()),
    'real_duration_s_median': round(float(np.median(
        pd.concat([pd.read_csv(f).duration for f in sorted(glob.glob(f"{HKD_DIR}/*.csv"))]) / 1e6)), 2),
    'generated_duration_s_median': round(float(d.duration.median()), 2)}
print("   flow structure:", R['flow_structure'])

# ═══════════════════════════════════════════════════════════════════════
# E6  Adversarial evasion + SHAP-guided adversarial training
# ═══════════════════════════════════════════════════════════════════════
print("\n[E6] Adversarial evasion")
ev_files = {'Mimic-AsyncProb': 's2_mdoh_evasion_mimic_async_proba.csv',
            'Mimic-AsyncRand': 's2_mdoh_evasion_mimic_async_random.csv',
            'Mimic-SyncRand':  's2_mdoh_evasion_mimic_sync_random.csv'}
evres = {}
for name, fn in ev_files.items():
    dv = pd.read_csv(f"{DATA_DIR}/{fn}")
    pv = pred(mB, scB, dv.fillna(0))
    evres[name] = {'detection_rate': round(float(pv.mean()), 4),
                   'evasion_rate': round(1 - float(pv.mean()), 4),
                   'n': len(pv), 'bpp_ab': round(float(dv.mean_Bpp_ab.mean()), 2)}

rng = np.random.default_rng(99)
d_sa = df_mal.sample(n=3100, random_state=99).copy()
bpp_t, bpp_s = df_browser.mean_Bpp_ab.mean(), df_browser.mean_Bpp_ab.std() * .5
d_sa['mean_Bpp_ab'] = rng.normal(bpp_t, bpp_s, len(d_sa)).clip(80, 400)
Bab = d_sa.mean_Bpp_ab * d_sa.pkts_ab
d_sa['mean_bytes_asm'] = d_sa.bytes_ba / (Bab + d_sa.bytes_ba)
psa = pred(mB, scB, d_sa.fillna(0))
evres['Mimic-SHAP-Aware'] = {'detection_rate': round(float(psa.mean()), 4),
                             'evasion_rate': round(1 - float(psa.mean()), 4),
                             'n': len(psa), 'bpp_ab': round(float(d_sa.mean_Bpp_ab.mean()), 2)}
R['evasion'] = evres
for k, v in evres.items():
    print(f"   {k:<18} evasion={v['evasion_rate']:.4f} Bpp_ab={v['bpp_ab']}")

print("  SHAP-guided adversarial training ...")
tr_ben_bpp = X2tr.loc[y2tr.values == 0, 'mean_Bpp_ab']
BM, BS = tr_ben_bpp.mean(), tr_ben_bpp.std()

def augment(target, seed=42):
    r = np.random.default_rng(seed)
    mal_tr = d2.loc[X2tr.index[y2tr.values == 1]].copy()
    mal_tr['mean_Bpp_ab'] = r.normal(target, BS * .5, len(mal_tr)).clip(80, 400)
    Ba = mal_tr.mean_Bpp_ab * mal_tr.pkts_ab
    mal_tr['mean_bytes_asm'] = mal_tr.bytes_ba / (Ba + mal_tr.bytes_ba)
    Xa = pd.concat([X2tr, mal_tr[F6].fillna(0)], ignore_index=True)
    ya = pd.concat([y2tr, pd.Series(np.ones(len(mal_tr), int))], ignore_index=True)
    return Xa, ya

Xa, ya = augment(BM)
mA, scA = fit_scaled(Xa, ya)
pA = pred(mA, scA, X2te)
R['adv_defense'] = {
    'baseline': binmetrics(y2te, p2) | {'evasion': evres['Mimic-SHAP-Aware']['evasion_rate']},
    'hardened': binmetrics(y2te, pA) | {'evasion': round(1 - float(pred(mA, scA, d_sa.fillna(0)).mean()), 4)},
    'adaptive_targets': {}}
for t in [120, 130, 155, 180, 200]:
    da = df_mal.sample(n=3100, random_state=7).copy()
    da['mean_Bpp_ab'] = np.random.default_rng(t).normal(t, BS * .5, len(da)).clip(60, 500)
    Ba = da.mean_Bpp_ab * da.pkts_ab
    da['mean_bytes_asm'] = da.bytes_ba / (Ba + da.bytes_ba)
    R['adv_defense']['adaptive_targets'][t] = {
        'baseline_evasion': round(1 - float(pred(mB, scB, da.fillna(0)).mean()), 4),
        'hardened_evasion': round(1 - float(pred(mA, scA, da.fillna(0)).mean()), 4)}
print("  ", R['adv_defense']['baseline'], "->", R['adv_defense']['hardened'])

# ═══════════════════════════════════════════════════════════════════════
# E7  Remediation — Model-T (tool benign) and Model-R (+ real malware)
# ═══════════════════════════════════════════════════════════════════════
print("\n[E7] Remediation")
dT = pd.concat([df_browser, df_tools, df_mal], ignore_index=True)
XT, yT = dT[F6].fillna(0), dT.mdoh.astype(int)
XTtr, XTte, yTtr, yTte = train_test_split(XT, yT, test_size=.2, stratify=yT, random_state=42)
mT, scT = fit_scaled(XTtr, yTtr)
pT = mT.predict(pd.DataFrame(scT.transform(XTte), columns=F6))
R['model_T'] = binmetrics(yTte, pT) | {
    'fpr_browser': round(float(pred(mT, scT, df_browser).mean()), 4),
    'fpr_tools':   round(float(pred(mT, scT, df_tools).mean()), 4),
    'real_malware_recall': round(float(pred(mT, scT, hkd).mean()), 4)}
print("   Model-T:", R['model_T'])

print("   Model-R leave-one-real-family-out ...")
lofo = {}
for fam in sorted(hkd.family.unique()):
    tr_r, te_r = hkd[hkd.family != fam], hkd[hkd.family == fam]
    Xr = pd.concat([XT, tr_r[F6]], ignore_index=True)
    yr = pd.concat([yT, pd.Series(np.ones(len(tr_r), int))], ignore_index=True)
    Xrtr, Xrte, yrtr, yrte = train_test_split(Xr, yr, test_size=.2, stratify=yr, random_state=42)
    mR, scR = fit_scaled(Xrtr, yrtr)
    pr = mR.predict(pd.DataFrame(scR.transform(Xrte), columns=F6))
    lofo[fam] = binmetrics(yrte, pr) | {
        'heldout_family_recall': round(float(pred(mR, scR, te_r).mean()), 4),
        'n_heldout': len(te_r),
        'fpr_browser': round(float(pred(mR, scR, df_browser).mean()), 4),
        'fpr_tools': round(float(pred(mR, scR, df_tools).mean()), 4)}
    print(f"     hold-out {fam:<9} F1={lofo[fam]['F1']:.4f} "
          f"recall_heldout={lofo[fam]['heldout_family_recall']:.4f}")
R['model_R_lofo'] = lofo
R['model_R_lofo_summary'] = {
    'mean_heldout_recall': round(float(np.mean([v['heldout_family_recall'] for v in lofo.values()])), 4),
    'mean_in_domain_F1': round(float(np.mean([v['F1'] for v in lofo.values()])), 4)}

# Model-R full (all real families in training) + SHAP
Xrf = pd.concat([XT, hkd[F6]], ignore_index=True)
yrf = pd.concat([yT, pd.Series(np.ones(len(hkd), int))], ignore_index=True)
src = pd.concat([pd.Series(['generated'] * len(XT)), hkd.family], ignore_index=True)
Xrftr, Xrfte, yrftr, yrfte, _, srcte = train_test_split(
    Xrf, yrf, src, test_size=.2, stratify=src.astype(str) + yrf.astype(str), random_state=42)
mRF, scRF = fit_scaled(Xrftr, yrftr)
Xrfte_s = pd.DataFrame(scRF.transform(Xrfte), columns=F6)
R['model_R_full'] = binmetrics(yrfte, mRF.predict(Xrfte_s))
svR = shap.TreeExplainer(mRF).shap_values(Xrfte_s)
svR = svR[1] if isinstance(svR, list) else svR
mshR = pd.Series(np.abs(svR).mean(0), index=F6).sort_values(ascending=False)
R['shap_model_R'] = {'share': (mshR / mshR.sum()).round(4).to_dict(),
                     'top_share': round(float(mshR.iloc[0] / mshR.sum()), 4)}
R['model_R_full']['evasion_shap_aware'] = round(1 - float(pred(mRF, scRF, d_sa.fillna(0)).mean()), 4)
pRF = mRF.predict(Xrfte_s)
_rf = pd.DataFrame({'src': srcte.values, 'y': yrfte.values, 'p': pRF})
R['model_R_full']['per_family_recall_in_domain'] = {
    k: {'n': int(len(v)), 'recall': round(float(v.p.mean()), 4)}
    for k, v in _rf[_rf.src != 'generated'].groupby('src')}
print("   Model-R full:", R['model_R_full'], "SHAP:", R['shap_model_R']['share'])

# ═══════════════════════════════════════════════════════════════════════
# E8  Scaler ablation
# ═══════════════════════════════════════════════════════════════════════
print("\n[E8] Scaler ablation")
scalers = {'Robust (5,95)': RobustScaler(quantile_range=(5, 95)),
           'Robust (10,90)': RobustScaler(quantile_range=(10, 90)),
           'Robust (25,75)': RobustScaler(quantile_range=(25, 75)),
           'Standard': StandardScaler(), 'MinMax': MinMaxScaler(), 'None': None}
abl = {}
for name, s in scalers.items():
    if s is None:
        mm = lgbm(); mm.fit(X2tr, y2tr); pp = mm.predict(X2te)
        ev4 = 1 - float(mm.predict(d_sa[F6].fillna(0)).mean())
    else:
        mm, ss = fit_scaled(X2tr, y2tr, scaler=s)
        pp = mm.predict(pd.DataFrame(ss.transform(X2te), columns=F6))
        ev4 = 1 - float(pred(mm, ss, d_sa.fillna(0)).mean())
    abl[name] = binmetrics(y2te, pp) | {'evasion_shap_aware': round(ev4, 4)}
    print(f"   {name:<16} F1={abl[name]['F1']:.4f} evasion={ev4:.4f}")
R['scaler_ablation'] = abl

# ═══════════════════════════════════════════════════════════════════════
# E9  Leave-one-resolver-out
# ═══════════════════════════════════════════════════════════════════════
print("\n[E9] Leave-one-resolver-out")
loro = {}
for rsv in ['adguard', 'cloudflare', 'google', 'quad9']:
    tr, te = d2[d2.doh_server != rsv], d2[d2.doh_server == rsv]
    if te.mdoh.nunique() < 2:
        continue
    mm, ss = fit_scaled(tr[F6].fillna(0), tr.mdoh.astype(int))
    loro[rsv] = binmetrics(te.mdoh.astype(int), pred(mm, ss, te.fillna(0))) | {'n_test': len(te)}
    print(f"   hold-out {rsv:<11} F1={loro[rsv]['F1']:.4f} R={loro[rsv]['Recall']:.4f}")
R['loro'] = loro
R['loro_summary'] = {'F1_mean': round(float(np.mean([v['F1'] for v in loro.values()])), 4),
                     'F1_std': round(float(np.std([v['F1'] for v in loro.values()])), 4)}

# ═══════════════════════════════════════════════════════════════════════
# E10  Stage 3 — DGA family attribution diagnostic
# ═══════════════════════════════════════════════════════════════════════
print("\n[E10] Stage 3 — family attribution diagnostic")
s3 = pd.read_csv(f"{DATA_DIR}/s3_dga.csv")
labcol = 'dga_family' if 'dga_family' in s3.columns else (
    'family' if 'family' in s3.columns else 'p_type')
s3['fam'] = s3[labcol].astype(str).str.replace(r'_\d+$', '', regex=True)
s3 = s3[s3.fam.isin(FAMS)]
X3, y3 = s3[F6].fillna(0), s3.fam
X3tr, X3te, y3tr, y3te = train_test_split(X3, y3, test_size=.2, stratify=y3, random_state=42)
m3, sc3 = fit_scaled(X3tr, y3tr, model=lgbm(objective='multiclass'))
X3te_s = pd.DataFrame(sc3.transform(X3te), columns=F6)
p3 = m3.predict(X3te_s)
rep = classification_report(y3te, p3, output_dict=True, zero_division=0)
R['stage3'] = {'macro_F1': round(rep['macro avg']['f1-score'], 4),
               'accuracy': round(rep['accuracy'], 4),
               'per_family': {f: {k: round(rep[f][k], 4) for k in ['precision', 'recall', 'f1-score']}
                              for f in FAMS if f in rep},
               'n_train': len(X3tr), 'n_test': len(X3te)}
print("  ", R['stage3']['macro_F1'], R['stage3']['per_family'])

# tool-vs-family confound: predict the DoH client tool from the same 6 features
if 'p_name' in s3.columns:
    yt = s3.p_name
    Xt_tr, Xt_te, yt_tr, yt_te = train_test_split(X3, yt, test_size=.2, stratify=yt, random_state=42)
    mt, sct = fit_scaled(Xt_tr, yt_tr, model=lgbm(objective='multiclass'))
    pt2 = mt.predict(pd.DataFrame(sct.transform(Xt_te), columns=F6))
    rt = classification_report(yt_te, pt2, output_dict=True, zero_division=0)
    R['stage3_tool_probe'] = {'macro_F1': round(rt['macro avg']['f1-score'], 4),
                              'accuracy': round(rt['accuracy'], 4),
                              'n_classes': int(yt.nunique())}
    print("   tool probe (same features -> DoH client):", R['stage3_tool_probe'])

# ═══════════════════════════════════════════════════════════════════════
# FIGURES
# ═══════════════════════════════════════════════════════════════════════
print("\nFigures ...")
plt.rcParams.update({'font.size': 9, 'axes.titlesize': 9.5, 'axes.labelsize': 9,
                     'legend.fontsize': 8, 'figure.dpi': 200})
C = {'browser': '#2E7D32', 'tools': '#1565C0', 'sim': '#C62828', 'real': '#6A1B9A'}

# Fig 1 — the confound, in one panel set
fig, ax = plt.subplots(1, 3, figsize=(7.16, 2.5))
groups = [('Benign\nbrowser', df_browser.mean_Bpp_ab, C['browser']),
          ('Benign\ntools', df_tools.mean_Bpp_ab, C['tools']),
          ('Simulated\nDGA', df_mal.mean_Bpp_ab, C['sim']),
          ('Real\nmalware', hkd.mean_Bpp_ab, C['real'])]
bp = ax[0].boxplot([g[1].clip(0, 400) for g in groups], labels=[g[0] for g in groups],
                   patch_artist=True, showfliers=False,
                   medianprops=dict(color='k', linewidth=1.2), widths=.6)
for patch, g in zip(bp['boxes'], groups):
    patch.set_facecolor(g[2]); patch.set_alpha(.65)
ax[0].axhspan(60, 100, color='grey', alpha=.12)
ax[0].set_ylabel(r'$\overline{B^{pp}_{ab}}$  (B/pkt)')
ax[0].set_title('(a) Dominant feature', fontweight='bold', fontsize=8)
ax[0].tick_params(axis='x', labelsize=7)

sh = pd.Series(R['shap_s2']['share'])[F6]
ax[1].barh([LBL[f] for f in F6][::-1], sh.values[::-1] * 100,
           color=['#B0BEC5'] * 5 + [C['sim']], edgecolor='k', linewidth=.4)
ax[1].set_xlabel('share of mean $|\\phi_i|$  (%)', fontsize=8)
ax[1].set_title('(b) SHAP concentration', fontweight='bold', fontsize=8)
for i, v in enumerate(sh.values[::-1]):
    ax[1].text(v * 100 + 1, i, f'{v*100:.1f}', va='center', fontsize=7)
ax[1].set_xlim(0, 85)

bars = ['Simulated\nDGA (test)', 'Benign tools\n(false pos.)', 'Real malware\n(recall)']
vals = [R['stage2_baseline']['Recall'], R['fpr_tools']['fpr'], R['real_malware_modelB']['overall_recall']]
bb = ax[2].bar(bars, [v * 100 for v in vals], color=[C['sim'], C['tools'], C['real']],
               edgecolor='k', linewidth=.4, width=.6)
for b, v in zip(bb, vals):
    ax[2].text(b.get_x() + b.get_width() / 2, v * 100 + 2, f'{v*100:.1f}%',
               ha='center', fontsize=7.5, fontweight='bold')
ax[2].set_ylabel('classified as malicious (%)'); ax[2].set_ylim(0, 115)
ax[2].set_title('(c) Model-B by source', fontweight='bold', fontsize=8)
ax[2].tick_params(axis='x', labelsize=7)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig_confound.pdf", bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig_confound.png", bbox_inches='tight'); plt.close()

# Fig 2 — SHAP beeswarm, Model-B
plt.figure(figsize=(3.5, 2.6))
shap.summary_plot(sv, X2te_s, feature_names=[LBL[f] for f in F6], show=False,
                  plot_size=None, max_display=6)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig_shap_beeswarm.pdf", bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig_shap_beeswarm.png", bbox_inches='tight'); plt.close()

# Fig 3 — evasion + defense
fig, ax = plt.subplots(1, 2, figsize=(7.16, 2.4))
names = ['Mimic-AsyncProb', 'Mimic-AsyncRand', 'Mimic-SyncRand', 'Mimic-SHAP-Aware']
short = ['Async-P', 'Async-R', 'Sync-R', 'SHAP-aware']
bp_v = [evres[n]['bpp_ab'] for n in names]
ax[0].bar(short, bp_v, color=['#90A4AE'] * 3 + ['#6A1B9A'], edgecolor='k', linewidth=.4, width=.6)
ax[0].axhline(R['bpp_reference']['benign_browser'], color=C['browser'], ls='--', lw=1,
              label=f"benign browser ({R['bpp_reference']['benign_browser']:.0f})")
ax[0].axhline(R['bpp_reference']['simulated_dga'], color=C['sim'], ls='--', lw=1,
              label=f"simulated DGA ({R['bpp_reference']['simulated_dga']:.0f})")
ax[0].set_ylabel(r'$\overline{B^{pp}_{ab}}$  (B/pkt)'); ax[0].legend(fontsize=6.5)
ax[0].set_title('(a) Feature displacement achieved', fontweight='bold', fontsize=8)
x = np.arange(4); w = .36
eb = [evres[n]['evasion_rate'] for n in names]
eh = [R['adv_defense']['hardened']['evasion'] if n == 'Mimic-SHAP-Aware' else evres[n]['evasion_rate']
      for n in names]
ax[1].bar(x - w / 2, [v * 100 for v in eb], w, label='Model-B', color='#C62828', edgecolor='k', linewidth=.4)
ax[1].bar(x + w / 2, [v * 100 for v in eh], w, label='+ adv. training', color='#2E7D32', edgecolor='k', linewidth=.4)
ax[1].set_xticks(x); ax[1].set_xticklabels(short); ax[1].set_ylabel('evasion rate (%)')
ax[1].legend(fontsize=7); ax[1].set_ylim(0, 110)
for i, v in enumerate(eb):
    ax[1].text(i - w / 2, v * 100 + 2, f'{v*100:.1f}', ha='center', fontsize=6.5)
ax[1].set_title('(b) Evasion before and after defense', fontweight='bold', fontsize=8)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig_evasion.pdf", bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig_evasion.png", bbox_inches='tight'); plt.close()

# Fig 4 — remediation
fig, ax = plt.subplots(1, 2, figsize=(7.16, 2.4))
mods = ['Model-B', 'Model-T', 'Model-R']
_rrf = float(np.mean([v['recall'] for v in R['model_R_full']['per_family_recall_in_domain'].values()]))
rm = [R['real_malware_modelB']['overall_recall'], R['model_T']['real_malware_recall'], _rrf]
ft = [R['fpr_tools']['fpr'], R['model_T']['fpr_tools'],
      float(np.mean([v['fpr_tools'] for v in lofo.values()]))]
f1 = [R['stage2_baseline']['F1'], R['model_T']['F1'], R['model_R_full']['F1']]
x = np.arange(3); w = .26
for off, vals, lab, col in [(-w, f1, 'in-domain F1', '#455A64'),
                            (0, rm, 'real-malware recall', C['real']),
                            (w, ft, 'FPR on benign tools', C['tools'])]:
    b = ax[0].bar(x + off, [v * 100 for v in vals], w, label=lab, color=col, edgecolor='k', linewidth=.4)
    for bi, v in zip(b, vals):
        ax[0].text(bi.get_x() + bi.get_width() / 2, v * 100 + 2, f'{v*100:.0f}', ha='center', fontsize=6)
ax[0].set_xticks(x); ax[0].set_xticklabels(mods); ax[0].set_ylabel('%'); ax[0].set_ylim(0, 138)
ax[0].legend(fontsize=6.5, ncol=3, loc='upper center', frameon=False,
             columnspacing=.8, handlelength=1.1, handletextpad=.4)
ax[0].set_title('(a) Effect of training-set composition', fontweight='bold', fontsize=8)
fams = sorted(lofo)
ax[1].bar(fams, [lofo[f]['heldout_family_recall'] * 100 for f in fams],
          color=C['real'], alpha=.8, edgecolor='k', linewidth=.4, width=.6, label='Model-R')
ax[1].bar(fams, [R['real_malware_modelB']['per_family'][f]['recall'] * 100 for f in fams],
          color=C['sim'], alpha=.9, edgecolor='k', linewidth=.4, width=.3, label='Model-B')
ax[1].set_ylabel('recall on held-out real family (%)'); ax[1].set_ylim(0, 112)
ax[1].legend(fontsize=7, frameon=False); ax[1].set_title('(b) Leave-one-real-family-out', fontweight='bold', fontsize=8)
ax[1].tick_params(axis='x', labelsize=7)
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig_remediation.pdf", bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig_remediation.png", bbox_inches='tight'); plt.close()

# Fig 5 — feature distributions, four sources
fig, axes = plt.subplots(2, 3, figsize=(7.16, 3.6))
for a, f in zip(axes.ravel(), F6):
    for lab, s, c in [('browser', df_browser[f], C['browser']), ('tools', df_tools[f], C['tools']),
                      ('sim. DGA', df_mal[f], C['sim']), ('real mal.', hkd[f], C['real'])]:
        v = s.replace([np.inf, -np.inf], np.nan).dropna()
        lo, hi = np.percentile(v, [1, 99])
        a.hist(v.clip(lo, hi), bins=40, density=True, histtype='step', lw=1.1, color=c, label=lab)
    a.set_title(LBL[f], fontsize=8); a.set_yticks([]); a.tick_params(labelsize=6)
axes[0, 0].legend(fontsize=5.5, loc='upper right')
plt.tight_layout()
plt.savefig(f"{FIG_DIR}/fig_feature_dist.pdf", bbox_inches='tight')
plt.savefig(f"{FIG_DIR}/fig_feature_dist.png", bbox_inches='tight'); plt.close()

os.makedirs(f"{ROOT}/Code/machine_learning/results", exist_ok=True)
out = f"{ROOT}/Code/machine_learning/results/ieee_results.json"
with open(out, 'w') as fh:
    json.dump(R, fh, indent=2, default=str)
print(f"\nSaved {out}\nFigures -> {FIG_DIR}")
