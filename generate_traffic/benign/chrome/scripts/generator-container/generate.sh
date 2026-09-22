#!/bin/bash

DOH_URIS=(
	"https://dns.adguard-dns.com/dns-query adguard"
	"https://cloudflare-dns.com/dns-query cloudflare"
	"https://dns.google/dns-query google"
	"https://dns.quad9.net/dns-query quad9"
	#"https://dns.nextdns.io/dns-query nextdns"
)


# .csv array
shopt -s nullglob;
csv_glob=(*.csv)
shopt -u nullglob
# https://www.baeldung.com/linux/sort-bash-arrays
readarray -td '' files < <(printf '%s\0' "${csv_glob[@]}" | sort -z -V)
#echo "${files[@]}"

i=0
for item in "${DOH_URIS[@]}";
do
	uris=($(echo "$item" | tr ' ' '\n'));
	echo "${uris[0]}";
	echo "${uris[1]}";
		
	# 4gb memory and 2gb of fast shared process memory; -v=mount volume; -e=set env variable; -it=interactive terminal with chrome to further execute run.sh;
	# https://datawookie.dev/blog/2021/11/shared-memory-docker/
	# https://github.com/SeleniumHQ/docker-selenium#--shm-size2g
	# https://docs.docker.com/engine/storage/bind-mounts/#start-a-container-with-a-bind-mount
	# bind mount host /dev/shm to container /dev/shm
	# bind mount host working dir (sources, contains run.sh & chrome-run-selenium.py) to container /capture # only on deploy !!!!
	# bind mount host scripts/ (contains .csv) to container /capture; sources (contains run.sh and visit_websites_chrome.py) already copied in during build # when coding
	
	#podman run --cpus=4 --memory=4g --shm-size=2g --dns=1.1.1.1 -v /dev/shm:/dev/shm -v $(pwd):/capture -e DNS_REQUEST_PROTO=DOH_POST -e INPUT_FILE_PATH=/capture/$i.csv -e OUTPUT_FILE_NAME=$OUTNAME -e URI="${uris[0]}" -it chrome_advanced:latest;
	
	#podman run --cpus=4 --memory=4g --shm-size=2g --dns=1.1.1.1 --mount type=bind,source=/dev/shm,target=/dev/shm --mount type=bind,source=$(pwd),target=/capture --env DOH_REQUEST_PROTO=DOH_POST --env INPUT_FILE_PATH=/capture/$i.csv --env OUTPUT_FILE_NAME=$OUTNAME --env URI="${uris[0]}" -it chrome_advanced:latest;

	# development, generate.sh same dir as sources
	#podman run --cpus=4 --memory=4g --shm-size=2g --dns=1.1.1.1 --network slirp4netns:mtu=1500 -p 4445:4444 -p 7902:7900 --add-host=www.gstatic.com:0.0.0.0 --mount type=bind,source=/dev/shm,target=/dev/shm --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env SE_ENABLE_TRACING=false --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env URI="${uris[0]}" --env DOH_REQUEST_PROTO=DOH_POST -it chrome_advanced:latest;

	# deployment, generate.sh is in the parent dir of sources
	#podman run --cpus=4 --memory=4g --shm-size=2g --dns=1.1.1.1 --network slirp4netns:mtu=1500 -p 4445:4444 -p 7902:7900 --add-host=www.gstatic.com:0.0.0.0 --mount type=bind,source=/dev/shm,target=/dev/shm --mount type=bind,source=$(pwd),target=/capture --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env SE_ENABLE_TRACING=false --env DOH_REQUEST_PROTO=DOH_POST --env INPUT_FILE_PATH=/capture/$i.csv --env OUTPUT_FILE_NAME=$OUTNAME --env URI="${uris[0]}" -it chrome_advanced:latest;
	#--security-opt label=disable
	
	# GET and POST with telemetry
	for j in {1..2}
	do
		if [[ ${uris[1]} == "google" ]]
		then
			OUTNAME="${files[$i]%.csv}"_get_"${uris[1]}";
			echo $OUTNAME
			podman run --cpus=4 --memory=4g --shm-size=2g --dns=1.1.1.1 --network slirp4netns:mtu=1500 -p 4445:4444 -p 7902:7900 --mount type=bind,source=/dev/shm,target=/dev/shm --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env SE_ENABLE_TRACING=false --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env URI="${uris[0]}" --env DOH_REQUEST_PROTO=DOH_GET -it chrome_advanced:latest;
		else
			OUTNAME="${files[$i]%.csv}"_post_"${uris[1]}";
			echo $OUTNAME
			podman run --cpus=4 --memory=4g --shm-size=2g --dns=1.1.1.1 --network slirp4netns:mtu=1500 -p 4445:4444 -p 7902:7900 --mount type=bind,source=/dev/shm,target=/dev/shm --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env SE_ENABLE_TRACING=false --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env URI="${uris[0]}" --env DOH_REQUEST_PROTO=DOH_POST -it chrome_advanced:latest;
		fi

		i=$((i+1))
		printf "\n"
	done

	# POST without telemetry
	OUTNAME="${files[$i]%.csv}"_post_no_telemetry_"${uris[1]}";
	echo $OUTNAME
	podman run --cpus=4 --memory=4g --shm-size=2g --dns=1.1.1.1 --network slirp4netns:mtu=1500 -p 4445:4444 -p 7902:7900 --add-host=www.gstatic.com:0.0.0.0 --mount type=bind,source=/dev/shm,target=/dev/shm --mount type=bind,source=$(pwd),target=/capture --mount type=bind,source=./sources,target=/sources --tz=local --ulimit nofile=32768 --cap-add=NET_RAW --env SE_ENABLE_TRACING=false --env INPUT_FILE_PATH=/capture/"${files[$i]}" --env OUTPUT_FILE_NAME=$OUTNAME --env URI="${uris[0]}" --env DOH_REQUEST_PROTO=DOH_POST --env NO_TELEMETRY="true" -it chrome_advanced:latest;

	i=$((i+1))


	printf "\n\n"
done;
