"""
browser_pcap_verification.py — packet-to-row verification for the BROWSER class.
Eight retained browser captures (4 Chrome, 4 Firefox) whose session names appear in
s2_mdoh.csv are re-extracted with the same Tranalyzer2 container (both byte layers),
aggregated with t2_aggregate.py, and matched to the training rows on (src_port, dst_port).
Writes results/browser_pcap_verification.json.
"""
import sys, json, numpy as np, pandas as pd
sys.path.insert(0,'machine_learning'); from t2_aggregate import read_t2, aggregate
ROOT='/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code'
V=f'{ROOT}/data/csv_from_pcap/benign/browser_verification/result'
ref_all=pd.read_csv(f'{ROOT}/data/csv/generated/s2_mdoh.csv')
caps={'chrome_20_post_cloudflare':'20_post_cloudflare','chrome_22_get_google':'22_get_google','chrome_23_get_google':'23_get_google','chrome_25_post_quad9':'25_post_quad9',
      'firefox_1_post_adguard':'1_post_adguard','firefox_5_post_cloudflare':'5_post_cloudflare','firefox_13_post_quad9':'13_post_quad9','firefox_14_get_quad9':'14_get_quad9'}
F=['pkts_ab','pkts_ba','bytes_ab','bytes_ba','duration','mean_Bpp_ab','mean_Bpp_ba','mean_pps_ab','mean_pps_ba','mean_pkts_asm','mean_bytes_asm']
out=[]
for cap,fn in caps.items():
    br=cap.split('_')[0]
    ref=ref_all[(ref_all.file_name==fn)&(ref_all.p_name==br)]
    r={'capture':cap,'browser':br,'session':fn,'ref_rows':int(len(ref)),'ref_rows_port443':int((ref.dst_port==443).sum())}
    for layer in ['L3','L7']:
        t2=read_t2(f'{V}/{cap}_decrypted_{layer}.csv'); agg=aggregate(t2)
        m=agg.merge(ref,on=['src_port','dst_port'],suffixes=('_t2','_ref'))
        rr={'t2_dir_rows':int(len(t2)),'t2_bidir_flows':int(len(agg)),'matched':int(len(m))}
        for c in F:
            x,y=m[f'{c}_t2'].astype(float),m[f'{c}_ref'].astype(float)
            rr[c]=({'exact':round(float(np.isclose(x,y,rtol=1e-6,equal_nan=True).mean()),4),
                    'median_abs_diff':round(float(np.nanmedian(np.abs(x-y))),4),'max_abs_diff':round(float(np.nanmax(np.abs(x-y))),4)}
                   if len(m) else {'exact':None,'median_abs_diff':None,'max_abs_diff':None})
        rr['Bpp_ab_t2_minus_ref_mean']=round(float((m.mean_Bpp_ab_t2-m.mean_Bpp_ab_ref).mean()),3) if len(m) else None
        r[layer]=rr
    out.append(r); print(json.dumps(r,indent=1))
json.dump(out,open(f'{ROOT}/machine_learning/results/browser_pcap_verification.json','w'),indent=1)
