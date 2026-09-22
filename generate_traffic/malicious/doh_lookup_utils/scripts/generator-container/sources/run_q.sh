#!/usr/bin/env bash

OUTPUT_PCAP_FILE=$NAME".pcap"

# OUTPUT_SSL_KEYLOG_FILE=$NAME"_ssl_key.log"
# touch $OUTPUT_SSL_KEYLOG_FILE
# chmod o+wr $OUTPUT_SSL_KEYLOG_FILE

half_line_count=$(($(grep -vc "^$" "$1") / 2)) # empty line ignored
#echo $half_line_count

# https://askubuntu.com/questions/746029/how-to-start-and-kill-tcpdump-within-a-script
# starting tcpdump
sudo tcpdump -U -n -i tap0 -B 4096 -w $OUTPUT_PCAP_FILE &
sleep 5

# pass each .csv file to the first argument
IFS=$'\n' # set word boundaries to \n
set -f # disable pathname expansion

echo "DOH POST" | tee /dev/stderr
for domain in $(head -n $half_line_count "$1"); do
    echo "$domain"
    sudo -H -u diguser bash -c "q A $domain @$URI --http2 --http-method=POST --pad --reuse-conn=false --timeout=5s --short --stats 2>&1";
    #sudo -H -u diguser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && q A $domain @$URI --http2 --http-method=POST --pad --reuse-conn=false --timeout=5s --short --stats 2>&1";
    #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && q A $domain @$URI --http2 --http-method=POST --pad --reuse-conn=false --timeout=5s --short --stats 2>&1";
    echo ""

    sleep 3
done

sleep 5

echo "DOH GET" | tee /dev/stderr
# start from the middle of the file
for domain in $(tail -n +$(($half_line_count+1)) "$1"); do
    echo "$domain"
    sudo -H -u diguser bash -c "q A $domain @$URI --http2 --http-method=GET --pad --reuse-conn=false --timeout=5s --short --stats 2>&1";
    #sudo -H -u diguser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && q A $domain @$URI --http2 --http-method=GET --pad --reuse-conn=false --timeout=5s --short --stats 2>&1";
    #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && q A $domain @$URI --http2 --http-method=GET --pad --reuse-conn=false --timeout=5s --short --stats 2>&1";
    echo ""

    sleep 3
done


# stopping tcpdump
TCPDUMP_PID=$(ps -e | pgrep tcpdump) # $(pidof tcpdump)

ping 8.8.8.8 -i 0.1 -c 100 # wait 0.1 sec before each ping, default 1 sec

kill -2 $TCPDUMP_PID

sleep 5
