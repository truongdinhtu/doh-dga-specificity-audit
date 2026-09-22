"""
ieee_access_label_purity.py — verify that every Probe 5 flow scored in the paper is
"pure": its packets fall entirely within one block's query-generation window, or spill
only into the inter-block gap (during which no queries of either label are issued), and
never reach the *next* block's window where a different label's queries begin.

This does not require a new capture; it uses the deposited flows and block schedules.
"""
import json
import numpy as np, pandas as pd

ROOT="/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS"
OUT=f"{ROOT}/Code/data/csv_from_pcap/os_doh_client"

SESSIONS=[
    ('cloudflare_1', f"{OUT}/pcap/blocks_20260920_024034.json"),
    ('google_1',     f"{OUT}/pcap/blocks_20260920_205445.json"),
]

OS=pd.read_csv(f"{OUT}/os_doh_client_L7_flows.csv")
OS['time_last']=OS.time_first+OS.duration

report={}
for sid,blocks_json in SESSIONS:
    meta=json.load(open(blocks_json)); blocks=meta['blocks']
    s=OS[OS.session==sid].copy()
    rows=[]
    for _,f in s.iterrows():
        bi=int(f.block_local)
        this_block=blocks[bi]
        next_start = blocks[bi+1]['t_start'] if bi+1 < len(blocks) else np.inf
        prev_end   = blocks[bi-1]['t_end']   if bi-1 >= 0 else -np.inf
        spills_into_next = f.time_last  > next_start
        starts_before_prev_end = f.time_first < prev_end  # shouldn't happen given label() logic, checked anyway
        margin_to_next = next_start - f.time_last          # seconds of gap remaining when flow ends
        rows.append({'flowInd':f.flowInd,'block_local':bi,'block_label':f.block_label,
                     'time_first':f.time_first,'time_last':f.time_last,'duration':f.duration,
                     'this_block_t_start':this_block['t_start'],'this_block_t_end':this_block['t_end'],
                     'next_block_t_start':next_start,
                     'spills_into_next_block':bool(spills_into_next),
                     'starts_before_prev_block_end':bool(starts_before_prev_end),
                     'margin_to_next_block_s':round(float(margin_to_next),2) if np.isfinite(margin_to_next) else None,
                     'ends_within_own_window':bool(f.time_last<=this_block['t_end'])})
    r=pd.DataFrame(rows)
    n_contaminated=int(r.spills_into_next_block.sum())
    print(f"[{sid}] n_flows={len(r)}  spill_into_next_block={n_contaminated}  "
          f"starts_before_prev_end={int(r.starts_before_prev_block_end.sum())}  "
          f"ends_within_own_window={int(r.ends_within_own_window.sum())}/{len(r)}")
    print(f"   margin to next block when flow ends: min={r.margin_to_next_block_s.min():.1f}s "
          f"median={r.margin_to_next_block_s.median():.1f}s max={r.margin_to_next_block_s.max():.1f}s")
    report[sid]={'n_flows':len(r),'n_spill_into_next_block':n_contaminated,
                 'n_starts_before_prev_end':int(r.starts_before_prev_block_end.sum()),
                 'margin_to_next_block_s':{'min':round(float(r.margin_to_next_block_s.min()),2),
                                            'median':round(float(r.margin_to_next_block_s.median()),2),
                                            'max':round(float(r.margin_to_next_block_s.max()),2)}}
    r.to_csv(f"{OUT}/label_purity_{sid}.csv",index=False)

total_flows=sum(v['n_flows'] for v in report.values())
total_contam=sum(v['n_spill_into_next_block'] for v in report.values())
print(f"\nTOTAL: {total_flows} flows, {total_contam} spill into the next block's window "
      f"({total_contam/total_flows*100:.1f}%).")
json.dump({'per_session':report,'total_flows':total_flows,'total_contaminated':total_contam},
          open(f"{ROOT}/Code/machine_learning/results/ieee_results_label_purity.json",'w'),indent=1)
print("Saved ieee_results_label_purity.json and per-session per-flow CSVs.")
