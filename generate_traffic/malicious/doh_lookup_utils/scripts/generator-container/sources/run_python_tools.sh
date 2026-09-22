#!/usr/bin/env bash

NAME="${NAME/"python_tools"/""}" # remove generic name

OUTPUT_PCAP_FILE1=$NAME"dnspython.pcap" # add DoH RFC tool name
OUTPUT_PCAP_FILE2="${NAME/"quad9"/"alidns"}""httpx.pcap" # add DoH JSON tool name and substitute quad9 resolver with alidns

# OUTPUT_SSL_KEYLOG_FILE1=$NAME"dnspython_ssl_key.log"
# OUTPUT_SSL_KEYLOG_FILE2="${NAME/"quad9"/"alidns"}""httpx_ssl_key.log" # substitute quad9 resolver with alidns
# touch $OUTPUT_SSL_KEYLOG_FILE1 OUTPUT_SSL_KEYLOG_FILE2
# chmod o+wr $OUTPUT_SSL_KEYLOG_FILE1 OUTPUT_SSL_KEYLOG_FILE2

# https://unix.stackexchange.com/questions/47407/cat-line-x-to-line-y-on-a-huge-file
onethird_line_count=$(($(grep -vc "^$" "$1") / 3)) # empty line ignored
#echo $onethird_line_count

# https://askubuntu.com/questions/746029/how-to-start-and-kill-tcpdump-within-a-script
# starting tcpdump
sudo tcpdump -U -n -i tap0 -B 4096 -w $OUTPUT_PCAP_FILE1 &
sleep 5

# pass each .csv file to the first argument
IFS=$'\n' # set word boundaries to \n
set -f # disable pathname expansion

echo "DOH POST" | tee /dev/stderr
# start from the begining to one-third of the file
for domain in $(head -n $onethird_line_count "$1"); do
    echo "$domain"
    sudo -H -u diguser bash -c "python3 python_lookup.py $domain --uri $URI --doh_method DOH_POST 2>&1";
    #sudo -H -u diguser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE1 && python3 python_lookup.py $domain --uri $URI --doh_method DOH_POST 2>&1";
    #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE1 && python3 python_lookup.py $domain --uri $URI --doh_method DOH_POST 2>&1";
    echo ""

    sleep 3
done

sleep 5

echo "DOH GET" | tee /dev/stderr
# start from the one-third+1 of the file to two-third 
for domain in $(tail -n +$(($onethird_line_count+1)) "$1" | head -n +$(($onethird_line_count+$onethird_line_count - $onethird_line_count))); do
    echo "$domain"
    sudo -H -u diguser bash -c "python3 python_lookup.py $domain --uri $URI --doh_method DOH_GET 2>&1";
    #sudo -H -u diguser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE1 && python3 python_lookup.py $domain --uri $URI --doh_method DOH_GET 2>&1";
    #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE1 && python3 python_lookup.py $domain --uri $URI --doh_method DOH_GET 2>&1";
    echo ""

    sleep 3
done

# stopping tcpdump
TCPDUMP_PID=$(ps -e | pgrep tcpdump) # $(pidof tcpdump)

ping 8.8.8.8 -i 0.1 -c 100 # wait 0.1 sec before each ping, default 1 sec

kill -2 $TCPDUMP_PID

sleep 5

echo ""

################################## JSON API ##################################

if [[ $URI == *"cloudflare"* ]] # same URI path as RFC 8484
then
    : # do nothing
elif [[ $URI == *"quad9"* ]] # substitute quad9 URI with alidns
then
    URI="https://dns.alidns.com/resolve"
else
    URI="${URI/dns-query/resolve}" # substitute URI path /dns-query with /resolve
fi

# starting tcpdump
sudo tcpdump -U -n -i tap0 -B 4096 -w $OUTPUT_PCAP_FILE2 &
sleep 5

# pass each .csv file to the first argument
IFS=$'\n' # set word boundaries to \n
set -f # disable pathname expansion

echo "DOH JSON" | tee /dev/stderr
# start from two-third+1 of the file
for domain in $(tail -n +$(($onethird_line_count+$onethird_line_count+1)) "$1"); do
    echo "$domain"
    sudo -H -u diguser bash -c "python3 python_lookup.py $domain --uri $URI --doh_method DOH_JSON 2>&1";
    #sudo -H -u diguser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE2 && python3 python_lookup.py $domain --uri $URI --doh_method DOH_JSON 2>&1";
    #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE2 && python3 python_lookup.py $domain --uri $URI --doh_method DOH_JSON 2>&1";
    echo ""

    sleep 3
done

# stopping tcpdump
TCPDUMP_PID=$(ps -e | pgrep tcpdump) # $(pidof tcpdump)

ping 8.8.8.8 -i 0.1 -c 100 # wait 0.1 sec before each ping, default 1 sec

kill -2 $TCPDUMP_PID

sleep 5
