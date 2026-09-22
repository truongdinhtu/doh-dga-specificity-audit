#!/bin/bash

# Export csv
shopt -s extglob

if [[ $("$T2HOME"/scripts/t2conf/t2conf tranalyzer2 -G FDURLIMIT | grep -P -o [0-9]+) != "$FDURLIMIT" ]]
then
    "$T2HOME"/scripts/t2conf/t2conf tranalyzer2 -D FDURLIMIT=$FDURLIMIT;
    "$T2HOME"/autogen.sh -y tranalyzer2;
fi

if [[ "$ADD_FDURLIMIT_SUFFIX" == "false" ]]
then
    SUFFIXES=( "L3" "L7" );
else
    SUFFIXES=( "L3_$FDURLIMIT" "L7_$FDURLIMIT" );
fi
PACKETLENGTHS=( 1 3 );

for ind in "${!SUFFIXES[@]}";
do
    # check when current build PACKETLENGTHS != 1
    #if [[ $("$T2HOME"/scripts/t2conf/t2conf tranalyzer2 -G PACKETLENGTH) != "PACKETLENGTH = ${PACKETLENGTHS[$ind]}" ]];
    if [[ "${PACKETLENGTHS[$ind]}" == 3 ]];
    then
        # reconfig and rebuild for L7
        "$T2HOME"/scripts/t2conf/t2conf tranalyzer2 -D PACKETLENGTH="${PACKETLENGTHS[$ind]}";
        "$T2HOME"/scripts/t2conf/t2conf basicStats -D BS_PAD=0 -D BS_IAT_STATS=0;
        #"$T2HOME"/autogen.sh -y -u tcpFlags;
        "$T2HOME"/autogen.sh -y -u basicFlow tcpFlags; # export the same number of flows and packets so no need to match flow key
        "$T2HOME"/autogen.sh -y tranalyzer2 basicStats;
    fi
    
    #for file in *.pcap{,ng};
    #for file in *.@(pcap|pcapng);
    for file in "DoH-17072021-48h_41.83.179.18_46852 (long DoH).pcap";
    do
        TFS_FLOWS_TXT_SUFFIX="_"${SUFFIXES[$ind]}".csv" TFS_HEADER_SUFFIX="_"${SUFFIXES[$ind]}"_header.txt" "$T2HOME"/tranalyzer2/build/tranalyzer -l -r "$file" -w /result/ "(tcp port 443) or (vlan and tcp port 443)";
        mv /result/"${file%.@(pcap|pcapng)}"_log.txt /result/"${file%.@(pcap|pcapng)}"_${SUFFIXES[$ind]}_log.txt;
    done
done

# Combine csv (or using %dir, flowInd and pktsSnt (and pktps/pktAsm))
#for file in /result/*_L3?(_180).csv;
#for file in /result/*_L3?(_$("$T2HOME"/scripts/t2conf/t2conf tranalyzer2 -G FDURLIMIT | grep -P -o [0-9]+)).csv;
for file in /result/*_L3?(_"$FDURLIMIT").csv;
do
    python3 /sources/combine_L3_L7.py "$file" "${file/"L3"/"L7"}";
    rm "$file" "${file/"L3"/"L7"}";
done
