"""
t2_aggregate.py — turn Tranalyzer2 per-direction flow rows (%dir A/B, same flowInd)
into the bidirectional schema used by s2_mdoh.csv, and validate the mapping on a
generated PCAP whose rows already exist in s2_mdoh.csv.

Usage:
  python t2_aggregate.py <t2_L3.csv> <out.csv> [--validate <file_name in s2_mdoh.csv>]
"""
import sys, argparse
import numpy as np, pandas as pd

F6 = ["mean_Bpp_ab", "mean_Bpp_ba", "mean_pps_ab", "mean_pps_ba", "mean_pkts_asm", "mean_bytes_asm"]


def read_t2(path):
    with open(path) as fh:
        first = fh.readline()
    sep = '\t' if first.count('\t') > first.count(',') else ','
    df = pd.read_csv(path, sep=sep)
    df.columns = [c.lstrip('%') for c in df.columns]
    return df


def aggregate(df):
    a = df[df.dir == 'A'].set_index('flowInd')
    b = df[df.dir == 'B'].set_index('flowInd')
    idx = a.index.intersection(b.index)          # bidirectional flows only
    a, b = a.loc[idx], b.loc[idx]
    o = pd.DataFrame(index=idx)
    o['time_first'] = np.minimum(a.timeFirst, b.timeFirst)
    o['time_last'] = np.maximum(a.timeLast, b.timeLast)
    o['duration'] = o.time_last - o.time_first
    o['src_ip'], o['dst_ip'] = a.srcIP, a.dstIP
    o['src_port'], o['dst_port'] = a.srcPort, a.dstPort
    o['pkts_ab'], o['pkts_ba'] = a.pktsSnt, b.pktsSnt
    bcol = 'l3BytesSnt' if 'l3BytesSnt' in a.columns else 'l7BytesSnt'
    o['bytes_ab'], o['bytes_ba'] = a[bcol], b[bcol]
    o['pkts_aggr'] = o.pkts_ab + o.pkts_ba
    o['bytes_aggr'] = o.bytes_ab + o.bytes_ba
    d = o.duration.replace(0, np.nan)
    o['mean_Bpp_ab'] = o.bytes_ab / o.pkts_ab
    o['mean_Bpp_ba'] = o.bytes_ba / o.pkts_ba
    o['mean_pps_ab'] = o.pkts_ab / d
    o['mean_pps_ba'] = o.pkts_ba / d
    o['mean_pkts_asm'] = o.pkts_ba / o.pkts_aggr
    o['mean_bytes_asm'] = o.bytes_ba / o.bytes_aggr
    o['t2_pktAsm_A'], o['t2_bytAsm_A'] = a.pktAsm, a.bytAsm   # keep tranalyzer's own asymmetry for checking
    o['unidirectional_dropped'] = len(df[df.dir == 'A']) - len(idx)
    return o.reset_index()


def validate(agg, ref_path, file_name):
    ref = pd.read_csv(ref_path)
    ref = ref[ref.file_name == file_name]
    print(f"reference rows for {file_name}: {len(ref)}   aggregated rows: {len(agg)}")
    key = ['src_port', 'dst_port']
    m = agg.merge(ref, on=key, suffixes=('_t2', '_ref'))
    print(f"matched on (src_port,dst_port): {len(m)}")
    for c in ['pkts_ab', 'pkts_ba', 'bytes_ab', 'bytes_ba', 'duration'] + F6:
        x, y = m[f'{c}_t2'], m[f'{c}_ref']
        rel = (np.abs(x - y) / np.maximum(np.abs(y), 1e-9))
        print(f"  {c:16} exact={np.isclose(x, y, rtol=1e-6).mean():.4f}  median_rel_err={rel.median():.2e}  max_rel_err={rel.max():.2e}")
    # asymmetry convention check
    print("  tranalyzer pktAsm(A) vs ref mean_pkts_asm:",
          "corr=%.4f" % np.corrcoef(m.t2_pktAsm_A, m.mean_pkts_asm_ref)[0, 1])
    return m


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('t2csv'); ap.add_argument('out')
    ap.add_argument('--validate', default=None)
    ap.add_argument('--ref', default='/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code/data/csv/generated/s2_mdoh.csv')
    args = ap.parse_args()
    df = read_t2(args.t2csv)
    agg = aggregate(df)
    agg.to_csv(args.out, index=False)
    print(f"{args.t2csv}: {len(df)} direction rows -> {len(agg)} bidirectional flows -> {args.out}")
    if args.validate:
        validate(agg, args.ref, args.validate)
