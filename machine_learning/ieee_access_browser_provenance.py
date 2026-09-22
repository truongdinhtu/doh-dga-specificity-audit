"""
ieee_access_browser_provenance.py — provenance-complete browser check.
Eight retained browser captures (4 Chrome, 4 Firefox; separate, shorter runs of the same
generation scripts as the training sessions, NOT the training captures themselves) are
re-extracted with the Tranalyzer2 container under both byte layers, aggregated with
t2_aggregate.py, and scored by the FIXED Model-B (and Model-T). This gives browser flows
whose packet-to-row provenance is complete, evaluated by the detector as trained.
Writes results/ieee_results_browser_provenance.json.

DoH selection: the training browser rows contain only flows whose destination is a
resolver address (Cloudflare 104.16.248.249/104.16.249.249, Google 8.8.8.8/8.8.4.4,
Quad9 9.9.9.9/149.112.112.112, AdGuard 94.140.14.14/94.140.15.15, AliDNS 223.5.5.5).
The same rule is applied here: of all bidirectional port-443 flows in a capture, only
those to a resolver address are DoH; the remainder are page-load HTTPS and are reported
separately, never as benign DoH.
"""
import sys, json, numpy as np, pandas as pd, lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
sys.path.insert(0,'machine_learning'); from t2_aggregate import read_t2, aggregate
ROOT='/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code'
V=f'{ROOT}/data/csv_from_pcap/benign/browser_verification/result'
F6=["mean_Bpp_ab","mean_Bpp_ba","mean_pps_ab","mean_pps_ba","mean_pkts_asm","mean_bytes_asm"]
d=pd.read_csv(f"{ROOT}/data/csv/generated/s2_mdoh.csv"); br=d[d.p_type=='browser']; tools=d[d.p_type.isin(['tool_1','tool_2'])]; mal=d[d.mdoh==1]
def fit(df,seed=42):
    X,y=df[F6].fillna(0),df.mdoh.astype(int)
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42)
    sc=RobustScaler(quantile_range=(5,95)); m=lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,random_state=seed,verbosity=-1).fit(pd.DataFrame(sc.fit_transform(Xtr),columns=F6),ytr)
    return lambda Z: m.predict(pd.DataFrame(sc.transform(Z[F6].fillna(0)),columns=F6))
PB=fit(pd.concat([br,mal])); PT=fit(pd.concat([br,tools,mal]))
caps=['chrome_20_post_cloudflare','chrome_22_get_google','chrome_23_get_google','chrome_25_post_quad9','firefox_1_post_adguard','firefox_5_post_cloudflare','firefox_13_post_quad9','firefox_14_get_quad9']
RESOLVER_IPS=sorted(set(br.dst_ip.unique())); R={'doh_selection_rule':'dst_ip in resolver address set observed in training browser rows','resolver_ips':RESOLVER_IPS,'per_capture':[]}; frames={}
for layer in ['L7','L3']:
    parts=[]
    for c in caps:
        a=aggregate(read_t2(f'{V}/{c}_decrypted_{layer}.csv')); a['capture']=c; a['browser']=c.split('_')[0]
        a=a[(a.pkts_ab>0)&(a.pkts_ba>0)&(a.duration>0)]; a['is_doh']=a.dst_ip.isin(RESOLVER_IPS); parts.append(a)
    frames[layer]=pd.concat(parts,ignore_index=True)
ALL7=frames['L7']; ALL3=frames['L3']
L7=ALL7[ALL7.is_doh].reset_index(drop=True); L3=ALL3[ALL3.is_doh].reset_index(drop=True)
NON=ALL7[~ALL7.is_doh]
R['selection_counts']={'port443_bidirectional_all':int(len(ALL7)),'doh_to_resolver':int(len(L7)),'non_doh_https_excluded':int(len(NON))}
R['non_doh_https_reference']={'n':int(len(NON)),'modelB_flagged_rate':round(float(PB(NON).mean()),4),'note':'page-load HTTPS, outside the DoH audit; reported only to document what was excluded'}
ALL7[['capture','browser','src_ip','dst_ip','src_port','dst_port','is_doh']+F6].assign(pred_modelB=lambda x: PB(x),pred_modelT=lambda x: PT(x)).to_csv(f'{ROOT}/data/csv_from_pcap/benign/browser_verification/browser_provenance_predictions_manifest.csv',index=False)
for c in caps:
    g=L7[L7.capture==c]; g3=L3[L3.capture==c]
    R['per_capture'].append({'capture':c,'n_port443_all':int((ALL7.capture==c).sum()),'n_flows':int(len(g)),'resolver_ips':g.dst_ip.value_counts().to_dict(),'Bpp_ab_median':round(float(g.mean_Bpp_ab.median()),1),
        'modelB_FPR_payload':round(float(PB(g).mean()),4),'modelB_fp_count':int(PB(g).sum()),'modelT_FPR_payload':round(float(PT(g).mean()),4),'modelT_fp_count':int(PT(g).sum()),
        'modelB_FPR_network_layer':round(float(PB(g3).mean()),4)})
for br_ in ['chrome','firefox']:
    g=L7[L7.browser==br_]; R[f'{br_}_pooled']={'n':int(len(g)),'modelB_FPR_payload':round(float(PB(g).mean()),4),'modelT_FPR_payload':round(float(PT(g).mean()),4)}
R['equal_weight_mean_of_runs_modelB_FPR']=round(float(np.mean([r['modelB_FPR_payload'] for r in R['per_capture']])),4)
R['all_pooled']={'n':int(len(L7)),'n_captures':len(caps),'modelB_FPR_payload':round(float(PB(L7).mean()),4),'modelT_FPR_payload':round(float(PT(L7).mean()),4),
                 'modelB_FPR_network_layer':round(float(PB(L3).mean()),4),'Bpp_ab_median_payload':round(float(L7.mean_Bpp_ab.median()),1),
                 'Bpp_ab_median_training_browser':round(float(br.mean_Bpp_ab.median()),1)}
# in-domain reference: Model-B browser FPR on the conventional split and under session-grouped CV
from sklearn.model_selection import StratifiedGroupKFold
dB=pd.concat([br,mal],ignore_index=True); X=dB[F6].fillna(0); y=dB.mdoh.astype(int).values; g=dB.file_name.values
def mk(): return lgb.LGBMClassifier(objective='binary',num_leaves=63,n_estimators=300,learning_rate=0.05,random_state=42,verbosity=-1)
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42)
sc=RobustScaler(quantile_range=(5,95)); m=mk().fit(pd.DataFrame(sc.fit_transform(Xtr),columns=F6),ytr); pc=m.predict(pd.DataFrame(sc.transform(Xte),columns=F6))
fpr=[]; per_sess={}; fp_tot=0; n_tot=0
for tr,te in StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42).split(X,y,groups=g):
    sc=RobustScaler(quantile_range=(5,95)); m=mk().fit(pd.DataFrame(sc.fit_transform(X.iloc[tr]),columns=F6),y[tr]); pg=m.predict(pd.DataFrame(sc.transform(X.iloc[te]),columns=F6))
    b=(y[te]==0); fpr.append(float(pg[b].mean())); fp_tot+=int(pg[b].sum()); n_tot+=int(b.sum())
    for s_ in np.unique(g[te][b]): per_sess[s_]=float(pg[b&(g[te]==s_)].mean())
R['in_domain_browser_FPR_reference']={'conventional_split_browser_FPR':round(float(pc[yte==0].mean()),4),
    'session_grouped_browser_FPR_pooled_by_fold':[round(x,4) for x in fpr],'session_grouped_browser_FPR_mean_of_folds':round(float(np.mean(fpr)),4),'session_grouped_browser_FPR_pooled_all_flows':round(fp_tot/n_tot,4),'session_grouped_browser_fp_count':fp_tot,'session_grouped_browser_n':n_tot,
    'per_session_browser_FPR_min':round(min(per_sess.values()),4),'per_session_browser_FPR_max':round(max(per_sess.values()),4),
    'per_session_browser_FPR_median':round(float(np.median(list(per_sess.values()))),4),'n_browser_sessions':len(per_sess)}
R['note']='These eight captures are separate runs sharing session names with training sessions; row-level matching to s2_mdoh.csv fails (see browser_pcap_verification.json), so they are an independent, provenance-complete browser sample, not the training captures.'
json.dump(R,open(f'{ROOT}/machine_learning/results/ieee_results_browser_provenance.json','w'),indent=1)
print(json.dumps(R,indent=1))
