#!/bin/bash
# Export L3 (+L7) flow CSVs for every pcap/pcapng in /data using the same
# tranalyzer configuration as the generated dataset (PACKETLENGTH=1, FDURLIMIT=180,
# FLOW_TIMEOUT=65).  Output: /result/<name>_L3.csv (per-direction rows).
shopt -s extglob nullglob
cd /data
for file in *.pcap *.pcapng; do
    base="${file%.@(pcap|pcapng)}"
    echo "[t2] $file"
    TFS_FLOWS_TXT_SUFFIX="_L3.csv" TFS_HEADER_SUFFIX="_L3_header.txt" \
      "$T2HOME"/tranalyzer2/build/tranalyzer -l -r "$file" -w /result/ \
      "(tcp port 443) or (vlan and tcp port 443)" > "/result/${base}_L3_t2stdout.txt" 2>&1
    echo "[t2] done $file -> $(wc -l < "/result/${base}_L3.csv") lines"
done
