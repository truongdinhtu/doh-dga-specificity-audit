#!/usr/bin/env bash

OUTPUT_PCAP_FILE=$NAME".pcap"

# OUTPUT_SSL_KEYLOG_FILE=$NAME"_ssl_key.log"
# touch $OUTPUT_SSL_KEYLOG_FILE
# chmod o+wr $OUTPUT_SSL_KEYLOG_FILE

# https://askubuntu.com/questions/746029/how-to-start-and-kill-tcpdump-within-a-script
# starting tcpdump
sudo tcpdump -U -n -i tap0 -B 4096 -w $OUTPUT_PCAP_FILE &
sleep 5

# pass each .csv file to the first argument
IFS=$'\n' # set word boundaries to \n
set -f # disable pathname expansion

if [[ "$NO_TELEMETRY" == "true" ]]
then
    for domain in $(cat < "$1"); do # for domain in $(cat "$1"); do
        # run as seluser
        sudo -H -u seluser bash -c "python3 /sources/selenium_firefox.py $domain --resolver $URI --doh_method $DOH_REQUEST_PROTO --no_telemetry"
        #sudo -H -u seluser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && python3 /sources/selenium_firefox.py $domain --resolver $URI --doh_method $DOH_REQUEST_PROTO --no_telemetry"
        #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && python3 /sources/selenium_firefox.py $domain --resolver $URI --doh_method $DOH_REQUEST_PROTO --no_telemetry"
        
        sleep 5
    done
else
    for domain in $(cat < "$1"); do # for domain in $(cat "$1"); do
        sudo -H -u seluser bash -c "python3 /sources/selenium_firefox.py $domain --resolver $URI --doh_method $DOH_REQUEST_PROTO"
        #sudo -H -u seluser bash -c "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && python3 /sources/selenium_firefox.py $domain --resolver $URI --doh_method $DOH_REQUEST_PROTO"
        #sudo -H -u seluser bash -c "python3 /sources/selenium_firefox.py $domain --resolver $URI --doh_method $DOH_REQUEST_PROTO --vnc"
        #echo "export SSLKEYLOGFILE=$OUTPUT_SSL_KEYLOG_FILE && python3 /sources/selenium_firefox.py $domain --resolver $URI --doh_method $DOH_REQUEST_PROTO"

        sleep 5
    done
fi

# stopping tcpdump
TCPDUMP_PID=$(ps -e | pgrep tcpdump) # $(pidof tcpdump)

ping 8.8.8.8 -i 0.1 -c 100 # wait 0.1 sec before each ping, default 1 sec

kill -2 $TCPDUMP_PID

sleep 5
