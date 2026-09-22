"""
browser_doh_protocol_check.py — protocol-level confirmation of the DoH selection used in
ieee_access_browser_provenance.py. The eight browser pcapng files embed TLS secrets
(pcapng Decryption Secrets Block), so tshark can dissect DNS messages inside HTTP/2 over
TLS. For every capture we list the (client port, server address) pairs of TCP connections
in which tshark dissects at least one DNS message, and compare with the flows selected by
the resolver-address rule. Writes results/browser_doh_protocol_check.json.
Requires tshark (Wireshark 4.x) on PATH.
"""
import subprocess, json, pandas as pd, collections
ROOT='/Users/tutruong/Desktop/Paper03-DNS-over-HTTPS/Code'
D=f'{ROOT}/data/csv_from_pcap/benign/browser_verification'
man=pd.read_csv(f'{D}/browser_provenance_predictions_manifest.csv')
out=[]; man['dns_confirmed']=False; man['decrypted_http2_no_dns']=False
for cap,g in man.groupby('capture'):
    pc=f'{D}/data/{cap}_decrypted.pcapng'
    # DNS frames from server to client: client port = tcp.dstport, server = ip.src
    r=subprocess.run(['tshark','-r',pc,'-Y','dns && tcp','-T','fields','-e','ip.src','-e','ip.dst','-e','tcp.srcport','-e','tcp.dstport'],capture_output=True,text=True).stdout
    # decryption completeness: per client port, count decrypted HTTP/2 frames and TLS application-data records
    r2=subprocess.run(['tshark','-r',pc,'-Y','tcp.port==443','-T','fields','-e','tcp.srcport','-e','tcp.dstport','-e','ip.src','-e','http2.type','-e','tls.record.content_type'],capture_output=True,text=True).stdout
    h2=collections.Counter(); app=collections.Counter()
    for line in r2.splitlines():
        f=line.split('\t'); cp=int(f[0]) if f[2].startswith('10.') else int(f[1])
        if f[3]: h2[cp]+=1
        if len(f)>4 and f[4] and '23' in f[4].split(','): app[cp]+=1
    pairs=set(); n_dns=0
    for line in r.splitlines():
        s,d,sp,dp=line.split('\t'); n_dns+=1
        if s.startswith('10.'): pairs.add((int(sp),d))      # client -> server (request)
        else: pairs.add((int(dp),s))                        # server -> client (response)
    sel=g[g.is_doh]; nonsel=g[~g.is_doh]
    sel_pairs=set(zip(sel.src_port.astype(int),sel.dst_ip)); non_pairs=set(zip(nonsel.src_port.astype(int),nonsel.dst_ip))
    conf_ports={p_[0] for p_ in sel_pairs&pairs}
    man.loc[(man.capture==cap)&man.is_doh&man.src_port.astype(int).isin(conf_ports),'dns_confirmed']=True
    sc=sel[sel.src_port.astype(int).isin(conf_ports)]; su=sel[~sel.src_port.astype(int).isin(conf_ports)]
    su_ports=su.src_port.astype(int)
    n_settings_only=int(sum(1 for p_ in su_ports if h2[p_]>0)); n_hs_only=int(sum(1 for p_ in su_ports if h2[p_]==0 and app[p_]==0)); n_undecrypted=int(sum(1 for p_ in su_ports if h2[p_]==0 and app[p_]>0))
    man.loc[(man.capture==cap)&man.is_doh&man.src_port.astype(int).isin([p_ for p_ in su_ports if h2[p_]>0]),'decrypted_http2_no_dns']=True
    rec={'capture':cap,'unconfirmed_with_decrypted_http2':n_settings_only,'unconfirmed_handshake_only':n_hs_only,'unconfirmed_undecrypted_appdata':n_undecrypted,'confirmed_n':int(len(sc)),'confirmed_fp':int(sc.pred_modelB.sum()),'handshake_only_n':int(len(su)),'handshake_only_fp':int(su.pred_modelB.sum()),'tshark_dns_frames':n_dns,'tcp_connections_with_dns':len(pairs),
         'selected_flows':len(sel),'selected_with_dns_confirmed':len(sel_pairs&pairs),'selected_without_dns_frames':len(sel_pairs-pairs),
         'excluded_flows':len(nonsel),'excluded_but_dns_confirmed':len(non_pairs&pairs),
         'resolver_addresses_selected':sorted(sel.dst_ip.unique().tolist()),
         'dns_servers_seen_by_tshark':sorted({p[1] for p in pairs})}
    out.append(rec); print(rec)
json.dump(out,open(f'{ROOT}/machine_learning/results/browser_doh_protocol_check.json','w'),indent=1)
tot=lambda k: sum(r[k] for r in out)
json.dump(out,open(f'{ROOT}/machine_learning/results/browser_doh_protocol_check.json','w'),indent=1)
man.to_csv(f'{D}/browser_provenance_predictions_manifest.csv',index=False)
print('unconfirmed split: decrypted-HTTP/2-no-DNS',tot('unconfirmed_with_decrypted_http2'),'| handshake-only',tot('unconfirmed_handshake_only'),'| undecrypted app-data',tot('unconfirmed_undecrypted_appdata'))
print('confirmed n/fp',tot('confirmed_n'),tot('confirmed_fp'),'| handshake-only n/fp',tot('handshake_only_n'),tot('handshake_only_fp'))
print('TOTAL selected',tot('selected_flows'),'confirmed',tot('selected_with_dns_confirmed'),'unconfirmed',tot('selected_without_dns_frames'),'| excluded',tot('excluded_flows'),'excluded-but-DoH',tot('excluded_but_dns_confirmed'))
