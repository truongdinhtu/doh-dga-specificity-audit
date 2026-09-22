#!/usr/bin/env bash

OUTPUT_PCAP_FILE=$NAME".pcap"

# OUTPUT_SSL_KEYLOG_FILE=$NAME"_ssl_key.log"
# touch $OUTPUT_SSL_KEYLOG_FILE
# chmod o+wr $OUTPUT_SSL_KEYLOG_FILE

# https://askubuntu.com/questions/746029/how-to-start-and-kill-tcpdump-within-a-script
# starting tcpdump
sudo tcpdump -U -n -i tap0 -B 4096 -w $OUTPUT_PCAP_FILE &
sleep 5

IFS=$'\n' # set word boundaries to \n
set -f # disable pathname expansion

# pass each .csv file to the first argument
# https://stackoverflow.com/questions/18215389/how-do-i-measure-request-and-response-times-at-once-using-curl
for domain in $(cat "$1"); do
    echo "$domain"
    # DNS, Connect, Total timings in seconds
    sudo -H -u diguser bash -c "curl -w '\n%{time_namelookup},%{time_connect},%{time_total}\n' --silent --show-error --fail --max-time 10 --retry 0 --header 'Accept: application/dns-json' '$URI?name=$domain&type=A' 2>&1";
    #sudo -H -u diguser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && curl -w '\n%{time_namelookup},%{time_connect},%{time_total}\n' --silent --show-error --fail --max-time 10 --retry 0 --header 'Accept: application/dns-json' '$URI?name=$domain&type=A' 2>&1";
    #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && curl -w '\n%{time_namelookup},%{time_connect},%{time_total}\n' --silent --show-error --fail --max-time 10 --retry 0 --header 'Accept: application/dns-json' '$URI?name=$domain&type=A' 2>&1";
    echo ""

    sleep 3
done

# stopping tcpdump
TCPDUMP_PID=$(ps -e | pgrep tcpdump) # $(pidof tcpdump)

ping 8.8.8.8 -i 0.1 -c 100 # wait 0.1 sec before each ping, default 1 sec

kill -2 $TCPDUMP_PID

sleep 5
