"""
verify_manuscript_numbers.py — checks that the headline numbers printed in the manuscript
are the numbers stored in machine_learning/results/*.json and data/. Run from the
artifact root:  python verify_manuscript_numbers.py
Exit status 0 means every check passed.
"""
import json, sys, pandas as pd
R='machine_learning/results/'
def J(f): return json.load(open(R+f))
checks=[]
def chk(name,got,exp,tol=5e-5):
    ok=abs(float(got)-float(exp))<=tol; checks.append((name,got,exp,ok))

os_=J('ieee_results_os_doh_client.json')
chk('Probe5 pooled FPR 70.68%',os_['E35_modelB']['FPR_benign'],0.7068)
chk('Probe5 pooled recall 73.01%',os_['E35_modelB']['recall_dga'],0.7301)
chk('Probe5 Model-B within-client AUC 0.509',os_['E35_modelB']['AUC_benign_vs_dga_within_client'],0.5093)
chk('Probe5 Model-T within-client AUC 0.515',os_['E36_modelT']['AUC_benign_vs_dga_within_client'],0.5154)
e38=os_['E38_within_client']['estimators']
chk('Probe5 LGBM paper cfg AUC 0.657',e38['LGBM_paper_cfg']['AUC_pooled'],0.6575)
chk('Probe5 LGBM small AUC 0.680',e38['LGBM_small']['AUC_pooled'],0.6799)
chk('Probe5 n label-pure 475',os_['data']['n_label_pure'],475,0)
df=pd.read_csv('data/csv_from_pcap/os_doh_client/os_doh_client_L7_flows.csv'); pure=df[~df.label_contaminated]
ct=pd.crosstab(pure.session,pure.label)
for s_,b,d in [('cloudflare_1',9,7),('google_1',7,7),('quad9_1',233,212)]:
    chk(f'Probe5 {s_} benign {b}',ct.loc[s_,'benign'],b,0); chk(f'Probe5 {s_} dga {d}',ct.loc[s_,'dga'],d,0)

m=pd.read_csv('data/csv_from_pcap/os_doh_client/os_doh_client_predictions_manifest.csv'); mp=m[~m.label_contaminated]
chk('Probe5 manifest rows 478',len(m),478,0); chk('Probe5 manifest pure 475',len(mp),475,0)
for r,l,n,f in [('cloudflare','benign',9,9),('cloudflare','dga',7,7),('google','benign',7,7),('google','dga',7,7),('quad9','benign',233,160),('quad9','dga',212,151)]:
    q=mp[(mp.resolver==r)&(mp.label==l)]; chk(f'Table12 {r}/{l} n={n}',len(q),n,0); chk(f'Table12 {r}/{l} flagged={f}',q.pred_modelB.sum(),f,0)
a=J('ieee_results_probe2b_audit.json')
chk('Probe2b classes_ always [0,1]',a['classes_always_[0,1]'],True,0)
chk('Probe2b combos 108',a['n_fold_cell_combos'],108,0); chk('Probe2b uncovered 5',a['n_uncovered'],5,0)
chk('Probe2b uncovered flows 857',a['uncovered_flows'],857,0)
chk('Probe2b single-class test 70',a['test_combos_single_class'],70,0)
chk('Probe2b test AUCs 35',a['test_combos_two_class_and_covered'],35,0)
chk('Probe2b cells with AUC 19',a['cells_with_any_two_class_test'],19,0)
chk('Probe2b oriented AUC 0.6215',a['oriented_by_evaluation_set']['all_7248']['AUC_oriented'],0.6215)
chk('Probe2b oriented BA 0.5715',a['oriented_by_evaluation_set']['all_7248']['BA_oriented'],0.5715)
chk('Probe2b common raw AUC 0.3822',a['oriented_by_evaluation_set']['common_6391']['AUC_raw'],0.3822)
chk('Probe2b common oriented AUC 0.6178',a['oriented_by_evaluation_set']['common_6391']['AUC_oriented'],0.6178)

c=J('ieee_results_probe2b_common.json')
chk('Probe2b common n 6391',c['n_common'],6391,0)
chk('Probe2b per-cell BA 0.3494',c['common_set']['percell']['BA'],0.3494)
chk('Probe2b pooled BA 0.4290',c['common_set']['pooled']['BA'],0.4290)
chk('Probe2b pooled+factors BA 0.3684',c['common_set']['pooled_factors']['BA'],0.3684)

r6=J('ieee_results_round6.json'); e33=r6['E33_adversarial_fair']
chk('DFR uniform+60 98.84%',e33['uniform_+60B']['ASR_conditional'],0.9884)
chk('DFR block approx 93.45%',e33['block_padding_128']['ASR_conditional'],0.9345)
chk('DFR gaussian155 (seed 99) 96.45%',e33['shap_aware_gaussian_155']['ASR_conditional'],0.9645)
r4=J('ieee_results_round4.json')
def find(o,k):
    if isinstance(o,dict):
        if k in o: return o[k]
        for v in o.values():
            r=find(v,k)
            if r is not None: return r
chk('Hardened gaussian155 (seed 99) 1.66%',find(r4,'hardened_shap_aware')['ASR_conditional'],0.0166)
ad=find(r4,'adaptive'); chk('Sweep 155 Model-B (seed 155) 96.24%',ad['155']['modelB'],0.9624); chk('Sweep 155 hardened 1.56%',ad['155']['hardened'],0.0156)
chk('Sweep 120 hardened 7.98%',ad['120']['hardened'],0.0798)

blob=''.join(open(R+f).read() for f in ['ieee_results.json','ieee_results_revision.json','ieee_results_round3.json','ieee_results_round4.json','ieee_results_round6.json','ieee_results_phaseB.json'])
for name,tok in [('Model-B F1 0.9937','0.9937'),('nested grouped F1 0.9881','0.9881'),('CLI FPR 0.9713','0.9713'),('SHAP share 0.6946','0.6946'),
                 ('aux client F1 0.9612','0.9612'),('aux family F1 0.5185','0.5185'),('metadata rule 0.9296','0.9296'),('same-flow L3 recall 0.2259','0.2259'),
                 ('NetExP L3 recall 0.0781','0.0781'),('T2 L3 recall 0.2853','0.2853'),('NetExP payload recall 0.9911','0.9911')]:
    checks.append((name+' present in results',tok in blob,True,tok in blob))

bp=J('ieee_results_browser_provenance.json')
chk('Provenance: port-443 flows 1521',bp['selection_counts']['port443_bidirectional_all'],1521,0); chk('Provenance: DoH flows 200',bp['selection_counts']['doh_to_resolver'],200,0)
chk('Provenance browser DoH pooled FPR 6.5%',bp['all_pooled']['modelB_FPR_payload'],0.065); chk('Provenance Model-T FPR 0%',bp['all_pooled']['modelT_FPR_payload'],0.0)
chk('Provenance chrome FPR 8.39%',bp['chrome_pooled']['modelB_FPR_payload'],0.0839); chk('Provenance firefox FPR 0%',bp['firefox_pooled']['modelB_FPR_payload'],0.0)
chk('Provenance non-DoH excluded 1321',bp['selection_counts']['non_doh_https_excluded'],1321,0)
pm=pd.read_csv('data/csv_from_pcap/benign/browser_verification/browser_provenance_predictions_manifest.csv')
chk('Provenance equal-weight mean 4.26%',bp['equal_weight_mean_of_runs_modelB_FPR'],0.0426)
chk('In-domain grouped pooled 0.40%',bp['in_domain_browser_FPR_reference']['session_grouped_browser_FPR_pooled_all_flows'],0.0040)
chk('In-domain grouped fp 253',bp['in_domain_browser_FPR_reference']['session_grouped_browser_fp_count'],253,0)
pc=json.load(open(R+'browser_doh_protocol_check.json'))
chk('Protocol check: confirmed 96',sum(r['confirmed_n'] for r in pc),96,0); chk('Protocol check: confirmed FP 1',sum(r['confirmed_fp'] for r in pc),1,0)
chk('Protocol check: handshake-only 104',sum(r['handshake_only_n'] for r in pc),104,0); chk('Protocol check: handshake-only FP 12',sum(r['handshake_only_fp'] for r in pc),12,0)
chk('Protocol check: decrypted-HTTP2-no-DNS 58',sum(r['unconfirmed_with_decrypted_http2'] for r in pc),58,0); chk('Protocol check: handshake-only 46',sum(r['unconfirmed_handshake_only'] for r in pc),46,0)
chk('Protocol check: undecrypted app-data 0',sum(r['unconfirmed_undecrypted_appdata'] for r in pc),0,0)
chk('Protocol check: FP on handshake-only 12',int(pm[pm.is_doh&~pm.dns_confirmed&~pm.decrypted_http2_no_dns].pred_modelB.sum()),12,0)
chk('Protocol check: excluded-but-DNS 1',sum(r['excluded_but_dns_confirmed'] for r in pc),1,0)
chk('Provenance manifest rows 1521',len(pm),1521,0); chk('Provenance manifest DoH rows 200',int(pm.is_doh.sum()),200,0); chk('Provenance manifest flagged DoH 13',int(pm[pm.is_doh].pred_modelB.sum()),13,0)
chk('In-domain grouped browser FPR mean-of-folds 0.39%',bp['in_domain_browser_FPR_reference']['session_grouped_browser_FPR_mean_of_folds'],0.0039)
chk('In-domain per-session max 2.88%',bp['in_domain_browser_FPR_reference']['per_session_browser_FPR_max'],0.0288)
bv=json.load(open(R+'browser_pcap_verification.json')); c20=[x for x in bv if x['capture']=='chrome_20_post_cloudflare'][0]
chk('Browser PCAP 20 ref rows 3940',c20['ref_rows'],3940,0); chk('Browser PCAP 20 t2 flows 329',c20['L7']['t2_bidir_flows'],329,0)
chk('Browser PCAP no exact byte match',max(x['L7']['bytes_ab']['exact'] or 0 for x in bv),0.0,0)
bad=[c for c in checks if not c[3]]
for n,g,e,ok in checks: print(('PASS ' if ok else 'FAIL ')+n+f'  got={g} expected={e}')
print(f'\n{len(checks)-len(bad)}/{len(checks)} checks passed'); sys.exit(1 if bad else 0)
