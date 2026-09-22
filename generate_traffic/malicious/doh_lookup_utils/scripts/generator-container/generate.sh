#!/bin/bash

DOH_URIS=(
	"https://dns.adguard.com/dns-query adguard"
	"https://cloudflare-dns.com/dns-query cloudflare"
	"https://dns.google/dns-query google"
	"https://dns.quad9.net/dns-query quad9"
	#"https://dns.nextdns.io/dns-query nextdns"
)

DGA_BOTS=(
	"bazarbackdoor"
	"flubot"
	"qsnatch"
	"zloader"
)


for bot in "${DGA_BOTS[@]}";
do
	# .csv array
	shopt -s nullglob;
	csv_glob=("$bot"*.csv)
	shopt -u nullglob
	# https://www.baeldung.com/linux/sort-bash-arrays
	readarray -td '' files < <(printf '%s\0' "${csv_glob[@]}" | sort -z -V)
	#echo "${files[@]}"

	i=0
	printf "**********$bot**********\n"
	for item in "${DOH_URIS[@]}";
	do
		uris=($(echo "$item" | tr ' ' '\n'));
		echo "${uris[0]}";
		echo "${uris[1]}";

		for tool in q kdig dig pydig;
		do	
			OUTNAME="${files[$i]%.csv}"_"${uris[1]}"_$tool;
			echo $OUTNAME
			podman run --cpus=4 --memory=4g --dns=1.1.1.1 --network slirp4netns:mtu=1500 --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env TOOL=$tool --env URI="${uris[0]}" -it doh_lookup:latest;
			i=$((i+1))
		done;

		# TOOL=q
		# OUTNAME="${files[$i]%.csv}"_"${uris[1]}"_$TOOL;
		# echo $TOOL
		# podman run --cpus=4 --memory=4g --dns=1.1.1.1 --network slirp4netns:mtu=1500 --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env TOOL=$TOOL --env URI="${uris[0]}" -it doh_lookup:latest;
		# i=$((i+1))
        
        # TOOL=kdig
		# echo $TOOL
		# OUTNAME="${files[$i]%.csv}"_"${uris[1]}"_$TOOL;
		# podman run --cpus=4 --memory=4g --dns=1.1.1.1 --network slirp4netns:mtu=1500 --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env TOOL=$TOOL --env URI="${uris[0]}" -it doh_lookup:latest;
		# i=$((i+1))
        
        # TOOL=dig
		# echo $TOOL
		# OUTNAME="${files[$i]%.csv}"_"${uris[1]}"_$TOOL;
		# podman run --cpus=4 --memory=4g --dns=1.1.1.1 --network slirp4netns:mtu=1500 --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env TOOL=$TOOL --env URI="${uris[0]}" -it doh_lookup:latest;
		# i=$((i+1))
        
        # TOOL=pydig
		# echo $TOOL
		# OUTNAME="${files[$i]%.csv}"_"${uris[1]}"_$TOOL;
		# podman run --cpus=4 --memory=4g --dns=1.1.1.1 --network slirp4netns:mtu=1500 --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env TOOL=$TOOL --env URI="${uris[0]}" -it doh_lookup:latest;
		# i=$((i+1))

		printf "\n"
	done;

	printf "\n\n"
done;
