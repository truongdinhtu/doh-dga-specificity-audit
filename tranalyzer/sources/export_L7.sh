#!/bin/bash
# Reconfigure tranalyzer for L7 (payload-only) byte accounting, as in the original
# export_L3_L7.sh, then export every pcap in /data to /result/<name>_L7.csv
shopt -s extglob nullglob
"$T2HOME"/scripts/t2conf/t2conf tranalyzer2 -D PACKETLENGTH=3 >/dev/null
"$T2HOME"/scripts/t2conf/t2conf basicStats -D BS_PAD=0 -D BS_IAT_STATS=0 >/dev/null
"$T2HOME"/autogen.sh -y tranalyzer2 basicStats > /result/_rebuild_L7.log 2>&1 || { echo "rebuild failed"; tail -20 /result/_rebuild_L7.log; exit 1; }
"$T2HOME"/scripts/t2conf/t2conf tranalyzer2 -G PACKETLENGTH
cd /data
for file in *.pcap *.pcapng; do
    base="${file%.@(pcap|pcapng)}"
    echo "[t2-L7] $file"
    TFS_FLOWS_TXT_SUFFIX="_L7.csv" TFS_HEADER_SUFFIX="_L7_header.txt" \
      "$T2HOME"/tranalyzer2/build/tranalyzer -l -r "$file" -w /result/ \
      "(tcp port 443) or (vlan and tcp port 443)" > "/result/${base}_L7_t2stdout.txt" 2>&1
    echo "[t2-L7] done $file -> $(wc -l < "/result/${base}_L7.csv") lines"
done
