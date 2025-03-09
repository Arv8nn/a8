#!/bin/bash
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
HOSTNAME=$(hostname)
WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs"
snb=$(hostname | awk -F '.' '{print $1}')
nb=$(hostname | cut -d '.' -f 1 | tr -d 's')
devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"
keep_path="${HOME}/domains/${snb}.${USERNAME}.serv00.net/public_nodejs"
[ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
[ -d "$keep_path" ] || mkdir -p "$keep_path"
[ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
devil binexec on >/dev/null 2>&1

read_ip() {
cat ip.txt
reading "Please enter the above threeIPAny one of (It is recommended to select the default carriage return automaticallyIP): " IP
if [[ -z "$IP" ]]; then
IP=$(grep -m 1 "Available" ip.txt | awk -F ':' '{print $1}')
if [ -z "$IP" ]; then
IP=$(okip)
if [ -z "$IP" ]; then
IP=$(head -n 1 ip.txt | awk -F ':' '{print $1}')
fi
fi
fi
green "Your choiceIPfor: $IP"
}

read_uuid() {
        reading "Please enter a unifieduuidpassword (It is recommended to enter the carriage randomly by default): " UUID
        if [[ -z "$UUID" ]]; then
	   UUID=$(uuidgen -r)
        fi
	green "youruuidfor: $UUID"
}

read_reym() {
	yellow "Method one：(recommend)useServ00Bring your own domain name，Not supportedproxyipFunction：Enter Enter"
        yellow "Method 2：useCFdomain name(www.speedtest.net)，supportproxyip+Non-standard port anti-generationipFunction：enters"
        yellow "Method Three：Support other domain names，Be careful to meetrealityDomain Name Rules：Enter the domain name"
        reading "Please enterrealitydomain name 【Please select Enter or s or Enter the domain name]: " reym
        if [[ -z "$reym" ]]; then
	    reym=$USERNAME.serv00.net
	elif [[ "$reym" == "s" || "$reym" == "S" ]]; then
	    reym=www.speedtest.net
        fi
	green "yourrealityThe domain name is: $reym"
}

resallport(){
portlist=$(devil port list | grep -E '^[0-9]+[[:space:]]+[a-zA-Z]+' | sed 's/^[[:space:]]*//')
if [[ -z "$portlist" ]]; then
yellow "No port"
else
while read -r line; do
port=$(echo "$line" | awk '{print $1}')
port_type=$(echo "$line" | awk '{print $2}')
yellow "Delete the port $port ($port_type)"
devil port del "$port_type" "$port"
done <<< "$portlist"
fi
check_port
if [[ -e $WORKDIR/config.json ]]; then
hyp=$(jq -r '.inbounds[0].listen_port' $WORKDIR/config.json)
vlp=$(jq -r '.inbounds[3].listen_port' $WORKDIR/config.json)
vmp=$(jq -r '.inbounds[4].listen_port' $WORKDIR/config.json)
purple "DetectedServ00-sb-ygThe script is installed，Perform port replacement，Please wait……"
sed -i '' "12s/$hyp/$hy2_port/g" $WORKDIR/config.json
sed -i '' "33s/$hyp/$hy2_port/g" $WORKDIR/config.json
sed -i '' "54s/$hyp/$hy2_port/g" $WORKDIR/config.json
sed -i '' "75s/$vlp/$vless_port/g" $WORKDIR/config.json
sed -i '' "102s/$vmp/$vmess_port/g" $WORKDIR/config.json
sed -i '' -e "17s|'$vlp'|'$vless_port'|" serv00keep.sh
sed -i '' -e "18s|'$vmp'|'$vmess_port'|" serv00keep.sh
sed -i '' -e "19s|'$hyp'|'$hy2_port'|" serv00keep.sh
bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
sleep 1
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
sleep 5
green "Port replacement is completed！"
ps aux | grep '[r]un -c con' > /dev/null && green "The main process started successfully，Single node user modify the client three-protocol port，Subscribe to the user update" || yellow "Sing-boxThe main process failed to start，Reset the port again or brush the web page several times more，May be automatically restored"
if [ -f "$WORKDIR/boot.log" ]; then
ps aux | grep '[t]unnel --u' > /dev/null && green "ArgoTemporary tunnel started successfully，Single node user on clienthost/sniChange the temporary domain name，Subscribe to the user update" || yellow "ArgoTemporary tunnel startup failed，Reset the port again or brush the web page several times more，May be automatically restored"
else
ps aux | grep '[t]unnel --n' > /dev/null && green "ArgoThe fixed tunnel started successfully" || yellow "ArgoFixed tunnel startup failed，PleaseCFChange the tunnel port：$vmess_port，A few more times to keep alive web pages may be automatically restored"
fi
fi
}

check_port () {
port_list=$(devil port list)
tcp_ports=$(echo "$port_list" | grep -c "tcp")
udp_ports=$(echo "$port_list" | grep -c "udp")

if [[ $tcp_ports -ne 2 || $udp_ports -ne 1 ]]; then
    red "The number of ports does not meet the requirements，Adjusting..."

    if [[ $tcp_ports -gt 2 ]]; then
        tcp_to_delete=$((tcp_ports - 2))
        echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
            devil port del $type $port
            green "DeletedTCPport: $port"
        done
    fi

    if [[ $udp_ports -gt 1 ]]; then
        udp_to_delete=$((udp_ports - 1))
        echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
            devil port del $type $port
            green "DeletedUDPport: $port"
        done
    fi

    if [[ $tcp_ports -lt 2 ]]; then
        tcp_ports_to_add=$((2 - tcp_ports))
        tcp_ports_added=0
        while [[ $tcp_ports_added -lt $tcp_ports_to_add ]]; do
            tcp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add tcp $tcp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "AddedTCPport: $tcp_port"
                if [[ $tcp_ports_added -eq 0 ]]; then
                    tcp_port1=$tcp_port
                else
                    tcp_port2=$tcp_port
                fi
                tcp_ports_added=$((tcp_ports_added + 1))
            else
                yellow "port $tcp_port Not available，Try another port..."
            fi
        done
    fi

    if [[ $udp_ports -lt 1 ]]; then
        while true; do
            udp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add udp $udp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "AddedUDPport: $udp_port"
                break
            else
                yellow "port $udp_port Not available，Try another port..."
            fi
        done
    fi
    #green "Port adjustment completed,Will be disconnectedsshconnect,Please reconnectshhRe-execute the script"
    #devil binexec on >/dev/null 2>&1
    #kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
    sleep 3
else
    tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
    tcp_port1=$(echo "$tcp_ports" | sed -n '1p')
    tcp_port2=$(echo "$tcp_ports" | sed -n '2p')
    udp_port=$(echo "$port_list" | awk '/udp/ {print $1}')

    purple "currentTCPport: $tcp_port1 and $tcp_port2"
    purple "currentUDPport: $udp_port"
fi
export vless_port=$tcp_port1
export vmess_port=$tcp_port2
export hy2_port=$udp_port
green "yourvless-realityport: $vless_port"
green "yourvmess-wsport(set upArgoFixed domain name port): $vmess_port"
green "yourhysteria2port: $hy2_port"
}

install_singbox() {
if [[ -e $WORKDIR/list.txt ]]; then
yellow "Installedsing-box，Please select first2uninstall，Execute the installation again" && exit
fi
sleep 2
        cd $WORKDIR
	echo
	read_ip
 	echo
        read_reym
	echo
	read_uuid
        echo
        check_port
	echo
        sleep 2
        argo_configure
	echo
        download_and_run_singbox
	cd
        fastrun
	green "Create a shortcut：sb"
	echo
	servkeep
        cd $WORKDIR
        echo
        get_links
	cd
        purple "************************************************************"
        purple "Serv00-sb-ygThe script installation ends！When entering the script again，Please enter a shortcut：sb"
	purple "************************************************************"
}

uninstall_singbox() {
  reading "\nAre you sure you want to uninstall？y/n: " choice
    case "$choice" in
       [Yy])
	  bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
          rm -rf domains bin serv00keep.sh webport.sh
          sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' "${HOME}/.bashrc" >/dev/null 2>&1
          source "${HOME}/.bashrc" >/dev/null 2>&1
	  #crontab -l | grep -v "serv00keep" >rmcron
          #crontab rmcron >/dev/null 2>&1
          #rm rmcron
          purple "************************************************************"
          purple "Serv00-sb-ygUninstall complete！"
          purple "Welcome to continue using scripts：bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00.sh)"
          purple "************************************************************"
          ;;
        [Nn]) exit 0 ;;
    	*) red "Invalid selection，Please enteryorn" && menu ;;
    esac
}

kill_all_tasks() {
reading "\nClean all processes and clear all installation content，Will exitsshconnect，Are you sure to continue cleaning?？y/n: " choice
  case "$choice" in
    [Yy]) 
    bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
    devil www del ${snb}.${USERNAME}.serv00.net > /dev/null 2>&1
    devil www del ${USERNAME}.serv00.net > /dev/null 2>&1
    sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' "${HOME}/.bashrc" >/dev/null 2>&1
    source "${HOME}/.bashrc" >/dev/null 2>&1 
    #crontab -l | grep -v "serv00keep" >rmcron
    #crontab rmcron >/dev/null 2>&1
    #rm rmcron
    purple "************************************************************"
    purple "Serv00-sb-ygCleaning and resetting completed！"
    purple "Welcome to continue using scripts：bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00.sh)"
    purple "************************************************************"
    find ~ -type f -exec chmod 644 {} \; 2>/dev/null
    find ~ -type d -exec chmod 755 {} \; 2>/dev/null
    find ~ -type f -exec rm -f {} \; 2>/dev/null
    find ~ -type d -empty -exec rmdir {} \; 2>/dev/null
    find ~ -exec rm -rf {} \; 2>/dev/null
    killall -9 -u $(whoami)
    ;;
    *) menu ;;
  esac
}

# Generating argo Config
argo_configure() {
  while true; do
    yellow "Method one：(recommend)No domain name requiredArgoTemporary tunnel：Enter Enter"
    yellow "Method 2：Need a domain nameArgoFixed tunnel(needCFSet up extractionToken)：enterg"
    reading "【Please select g or Enter】: " argo_choice
    if [[ "$argo_choice" != "g" && "$argo_choice" != "G" && -n "$argo_choice" ]]; then
        red "Invalid selection，Please enter g Or return"
        continue
    fi
    if [[ "$argo_choice" == "g" || "$argo_choice" == "G" ]]; then
        reading "Please enterargoFixed tunnel domain name: " ARGO_DOMAIN
        green "yourargoThe fixed tunnel domain name is: $ARGO_DOMAIN"
        reading "Please enterargoFixed tunnel key（When you pasteTokenhour，Must beeybeginning）: " ARGO_AUTH
        green "yourargoThe fixed tunnel key is: $ARGO_AUTH"
    else
        green "useArgoTemporary tunnel"
    fi
    break
done
}

# Download Dependency Files
download_and_run_singbox() {
DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
FILE_INFO=("https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/sb web" "https://github.com/yonggekkk/Cloudflare_vless_trojan/releases/download/serv00/server bot")
declare -A FILE_MAP
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

download_with_fallback() {
    local URL=$1
    local NEW_FILENAME=$2

    curl -L -sS --max-time 2 -o "$NEW_FILENAME" "$URL" &
    CURL_PID=$!
    CURL_START_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    sleep 1
    CURL_CURRENT_SIZE=$(stat -c%s "$NEW_FILENAME" 2>/dev/null || echo 0)
    
    if [ "$CURL_CURRENT_SIZE" -le "$CURL_START_SIZE" ]; then
        kill $CURL_PID 2>/dev/null
        wait $CURL_PID 2>/dev/null
        wget -q -O "$NEW_FILENAME" "$URL"
        echo -e "\e[1;32mDownloading $NEW_FILENAME by wget\e[0m"
    else
        wait $CURL_PID
        echo -e "\e[1;32mDownloading $NEW_FILENAME by curl\e[0m"
    fi
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
    
    if [ -e "$NEW_FILENAME" ]; then
        echo -e "\e[1;32m$NEW_FILENAME already exists, Skipping download\e[0m"
    else
        download_with_fallback "$URL" "$NEW_FILENAME"
    fi
    
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
done
wait

output=$(./"$(basename ${FILE_MAP[web]})" generate reality-keypair)
private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
echo "${private_key}" > private_key.txt
echo "${public_key}" > public_key.txt
openssl ecparam -genkey -name prime256v1 -out "private.key"
openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"
  cat > config.json << EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
    "inbounds": [
    {
       "tag": "hysteria-in1",
       "type": "hysteria2",
       "listen": "$(dig @8.8.8.8 +time=5 +short "web$nb.serv00.com" | sort -u)",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://www.bing.com",
     "ignore_client_bandwidth":false,
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
        {
       "tag": "hysteria-in2",
       "type": "hysteria2",
       "listen": "$(dig @8.8.8.8 +time=5 +short "$HOSTNAME" | sort -u)",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://www.bing.com",
     "ignore_client_bandwidth":false,
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
        {
       "tag": "hysteria-in3",
       "type": "hysteria2",
       "listen": "$(dig @8.8.8.8 +time=5 +short "cache$nb.serv00.com" | sort -u)",
       "listen_port": $hy2_port,
       "users": [
         {
             "password": "$UUID"
         }
     ],
     "masquerade": "https://www.bing.com",
     "ignore_client_bandwidth":false,
     "tls": {
         "enabled": true,
         "alpn": [
             "h3"
         ],
         "certificate_path": "cert.pem",
         "key_path": "private.key"
        }
    },
    {
        "tag": "vless-reality-vesion",
        "type": "vless",
        "listen": "::",
        "listen_port": $vless_port,
        "users": [
            {
              "uuid": "$UUID",
              "flow": "xtls-rprx-vision"
            }
        ],
        "tls": {
            "enabled": true,
            "server_name": "$reym",
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": "$reym",
                    "server_port": 443
                },
                "private_key": "$private_key",
                "short_id": [
                  ""
                ]
            }
        }
    },
{
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": $vmess_port,
      "users": [
      {
        "uuid": "$UUID"
      }
    ],
    "transport": {
      "type": "ws",
      "path": "$UUID-vm",
      "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    }
 ],
     "outbounds": [
     {
        "type": "wireguard",
        "tag": "wg",
        "server": "162.159.192.200",
        "server_port": 4500,
        "local_address": [
                "172.16.0.2/32",
                "2606:4700:110:8f77:1ca9:f086:846c:5f9e/128"
        ],
        "private_key": "wIxszdR2nMdA7a2Ul3XQcniSfSZqdqjPb6w6opvf5AU=",
        "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "reserved": [
            126,
            246,
            173
        ]
    },
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
   "route": {
       "rule_set": [
      {
        "tag": "google-gemini",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google-gemini.srs",
        "download_detour": "direct"
      }
    ],
EOF
if [[ "$nb" =~ (14|15|16) ]]; then
cat >> config.json <<EOF 
    "rules": [
    {
     "domain": [
     "jnn-pa.googleapis.com"
      ],
     "outbound": "wg"
     },
     {
     "rule_set":[
     "google-gemini"
     ],
     "outbound": "wg"
    }
    ],
    "final": "direct"
    }  
}
EOF
else
  cat >> config.json <<EOF
    "final": "direct"
    }  
}
EOF
fi

if [ -e "$(basename "${FILE_MAP[web]}")" ]; then
   echo "$(basename "${FILE_MAP[web]}")" > sb.txt
   sbb=$(cat sb.txt)
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 5
if pgrep -x "$sbb" > /dev/null; then
    green "$sbb The main process has been started"
else
for ((i=1; i<=5; i++)); do
    red "$sbb The main process has not started, Restarting... (Number of attempts: $i)"
    pkill -x "$sbb"
    nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
    sleep 5
    if pgrep -x "$sbb" > /dev/null; then
        purple "$sbb The main process has been successfully restarted"
        break
    fi
    if [[ $i -eq 5 ]]; then
        red "$sbb The main process failed to restart"
    fi
done
fi
fi
if [ -e "$(basename "${FILE_MAP[bot]}")" ]; then
   echo "$(basename "${FILE_MAP[bot]}")" > ag.txt
   agg=$(cat ag.txt)
    rm -rf boot.log
    if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
      #args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
      args="tunnel --no-autoupdate run --token ${ARGO_AUTH}"
    else
     #args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile boot.log --loglevel info --url http://localhost:$vmess_port"
     args="tunnel --url http://localhost:$vmess_port --no-autoupdate --logfile boot.log --loglevel info"
    fi    
    nohup ./"$agg" $args >/dev/null 2>&1 &
    sleep 10
if pgrep -x "$agg" > /dev/null; then
    green "$agg ArgoThe process has started"
else
for ((i=1; i<=5; i++)); do
    red "$agg ArgoThe process has not started, Restarting...(Number of attempts: $i)"
    pkill -x "$agg"
    nohup ./"$agg" "${args}" >/dev/null 2>&1 &
    sleep 5
    if pgrep -x "$agg" > /dev/null; then
        purple "$agg ArgoThe process has been successfully restarted"
        break
    fi
    if [[ $i -eq 5 ]]; then
        red "$agg ArgoProcess restart failed，ArgoNode is currently unavailable(It will automatically resume during the maintenance process)，Other nodes are still available"
    fi
done
fi
fi
sleep 2
if ! pgrep -x "$(cat sb.txt)" > /dev/null; then
red "The main process has not started，Check one by one according to the following situations"
yellow "1,choose7Reset the port，Automatically generate random available ports（important）"
yellow "2,choose8Reset"
yellow "3,currentServ00The server exploded？Try again later"
red "4, tried all the above，Brother lie down straight，Leave it to the process to keep alive，See you later"
sleep 6
fi
}

get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN" > gdym.log
    echo "$ARGO_DOMAIN"
  else
    local retry=0
    local max_retries=6
    local argodomain=""
    while [[ $retry -lt $max_retries ]]; do
    ((retry++)) 
    argodomain=$(cat boot.log 2>/dev/null | grep -a trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
      if [[ -n $argodomain ]]; then
        break
      fi
      sleep 2
    done  
    if [ -z ${argodomain} ]; then
    argodomain="ArgoTemporary domain name temporary acquisition failed，ArgoNode is currently unavailable(It will automatically resume during the maintenance process)，Other nodes are still available"
    fi
    echo "$argodomain"
  fi
}

get_links(){
argodomain=$(get_argodomain)
echo -e "\e[1;32mArgodomain name：\e[1;35m${argodomain}\e[0m\n"
vl_link="vless://$UUID@$IP:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reym&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$snb-reality"
echo "$vl_link" > jh.txt
vmws_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$snb-vmess-ws\", \"add\": \"$IP\", \"port\": \"$vmess_port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
echo "$vmws_link" >> jh.txt
vmatls_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$snb-vmess-ws-tls-argo\", \"add\": \"icook.hk\", \"port\": \"8443\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)"
echo "$vmatls_link" >> jh.txt
vma_link="vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$snb-vmess-ws-argo\", \"add\": \"icook.hk\", \"port\": \"8880\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)"
echo "$vma_link" >> jh.txt
hy2_link="hysteria2://$UUID@$IP:$hy2_port?sni=www.bing.com&alpn=h3&insecure=1#$snb-hy2"
echo "$hy2_link" >> jh.txt
baseurl=$(base64 -w 0 < jh.txt)

cat > sing_box.json <<EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "",
      "external_ui_download_detour": "",
      "secret": "",
      "default_mode": "Rule"
       },
      "cache_file": {
            "enabled": true,
            "path": "cache.db",
            "store_fakeip": true
        }
    },
    "dns": {
        "servers": [
            {
                "tag": "proxydns",
                "address": "tls://8.8.8.8/dns-query",
                "detour": "select"
            },
            {
                "tag": "localdns",
                "address": "h3://223.5.5.5/dns-query",
                "detour": "direct"
            },
            {
                "tag": "dns_fakeip",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "localdns",
                "disable_cache": true
            },
            {
                "clash_mode": "Global",
                "server": "proxydns"
            },
            {
                "clash_mode": "Direct",
                "server": "localdns"
            },
            {
                "rule_set": "geosite-cn",
                "server": "localdns"
            },
            {
                 "rule_set": "geosite-geolocation-!cn",
                 "server": "proxydns"
            },
             {
                "rule_set": "geosite-geolocation-!cn",         
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "dns_fakeip"
            }
          ],
           "fakeip": {
           "enabled": true,
           "inet4_range": "198.18.0.0/15",
           "inet6_range": "fc00::/18"
         },
          "independent_cache": true,
          "final": "proxydns"
        },
      "inbounds": [
    {
      "type": "tun",
           "tag": "tun-in",
	  "address": [
      "172.19.0.1/30",
	  "fd00::1/126"
      ],
      "auto_route": true,
      "strict_route": true,
      "sniff": true,
      "sniff_override_destination": true,
      "domain_strategy": "prefer_ipv4"
    }
  ],
  "outbounds": [
    {
      "tag": "select",
      "type": "selector",
      "default": "auto",
      "outbounds": [
        "auto",
        "vless-$snb",
        "vmess-$snb",
        "hy2-$snb",
"vmess-tls-argo-$snb",
"vmess-argo-$snb"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-$snb",
      "server": "$IP",
      "server_port": $vless_port,
      "uuid": "$UUID",
      "packet_encoding": "xudp",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "$reym",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
      "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": ""
        }
      }
    },
{
            "server": "$IP",
            "server_port": $vmess_port,
            "tag": "vmess-$snb",
            "tls": {
                "enabled": false,
                "server_name": "www.bing.com",
                "insecure": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "packet_encoding": "packetaddr",
            "transport": {
                "headers": {
                    "Host": [
                        "www.bing.com"
                    ]
                },
                "path": "/$UUID-vm",
                "type": "ws"
            },
            "type": "vmess",
            "security": "auto",
            "uuid": "$UUID"
        },

    {
        "type": "hysteria2",
        "tag": "hy2-$snb",
        "server": "$IP",
        "server_port": $hy2_port,
        "password": "$UUID",
        "tls": {
            "enabled": true,
            "server_name": "www.bing.com",
            "insecure": true,
            "alpn": [
                "h3"
            ]
        }
    },
{
            "server": "icook.hk",
            "server_port": 8443,
            "tag": "vmess-tls-argo-$snb",
            "tls": {
                "enabled": true,
                "server_name": "$argodomain",
                "insecure": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "packet_encoding": "packetaddr",
            "transport": {
                "headers": {
                    "Host": [
                        "$argodomain"
                    ]
                },
                "path": "/$UUID-vm",
                "type": "ws"
            },
            "type": "vmess",
            "security": "auto",
            "uuid": "$UUID"
        },
{
            "server": "icook.hk",
            "server_port": 8880,
            "tag": "vmess-argo-$snb",
            "tls": {
                "enabled": false,
                "server_name": "$argodomain",
                "insecure": false,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "packet_encoding": "packetaddr",
            "transport": {
                "headers": {
                    "Host": [
                        "$argodomain"
                    ]
                },
                "path": "/$UUID-vm",
                "type": "ws"
            },
            "type": "vmess",
            "security": "auto",
            "uuid": "$UUID"
        },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "vless-$snb",
        "vmess-$snb",
        "hy2-$snb",
        "vmess-tls-argo-$snb",
        "vmess-argo-$snb"
      ],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    }
  ],
  "route": {
      "rule_set": [
            {
                "tag": "geosite-geolocation-!cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            },
            {
                "tag": "geosite-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            },
            {
                "tag": "geoip-cn",
                "type": "remote",
                "format": "binary",
                "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
                "download_detour": "select",
                "update_interval": "1d"
            }
        ],
    "auto_detect_interface": true,
    "final": "select",
    "rules": [
      {
      "inbound": "tun-in",
      "action": "sniff"
      },
      {
      "protocol": "dns",
      "action": "hijack-dns"
      },
      {
      "port": 443,
      "network": "udp",
      "action": "reject"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "outbound": "select"
      },
      {
        "rule_set": "geoip-cn",
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-cn",
        "outbound": "direct"
      },
      {
      "ip_is_private": true,
      "outbound": "direct"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "outbound": "select"
      }
    ]
  },
    "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}
EOF

cat > clash_meta.yaml <<EOF
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: vless-reality-vision-$snb               
  type: vless
  server: $IP                           
  port: $vless_port                                
  uuid: $UUID   
  network: tcp
  udp: true
  tls: true
  flow: xtls-rprx-vision
  servername: $reym                 
  reality-opts: 
    public-key: $public_key                      
  client-fingerprint: chrome                  

- name: vmess-ws-$snb                         
  type: vmess
  server: $IP                       
  port: $vmess_port                                     
  uuid: $UUID       
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  network: ws
  servername: www.bing.com                    
  ws-opts:
    path: "/$UUID-vm"                             
    headers:
      Host: www.bing.com                     

- name: hysteria2-$snb                            
  type: hysteria2                                      
  server: $IP                               
  port: $hy2_port                                
  password: $UUID                          
  alpn:
    - h3
  sni: www.bing.com                               
  skip-cert-verify: true
  fast-open: true

- name: vmess-tls-argo-$snb                         
  type: vmess
  server: icook.hk                        
  port: 8443                                     
  uuid: $UUID       
  alterId: 0
  cipher: auto
  udp: true
  tls: true
  network: ws
  servername: $argodomain                    
  ws-opts:
    path: "/$UUID-vm"                             
    headers:
      Host: $argodomain

- name: vmess-argo-$snb                         
  type: vmess
  server: icook.hk                        
  port: 8880                                     
  uuid: $UUID       
  alterId: 0
  cipher: auto
  udp: true
  tls: false
  network: ws
  servername: $argodomain                   
  ws-opts:
    path: "/$UUID-vm"                             
    headers:
      Host: $argodomain 

proxy-groups:
- name: Balance
  type: load-balance
  url: https://www.gstatic.com/generate_204
  interval: 300
  strategy: round-robin
  proxies:
    - vless-reality-vision-$snb                              
    - vmess-ws-$snb
    - hysteria2-$snb
    - vmess-tls-argo-$snb
    - vmess-argo-$snb

- name: Auto
  type: url-test
  url: https://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - vless-reality-vision-$snb                             
    - vmess-ws-$snb
    - hysteria2-$snb
    - vmess-tls-argo-$snb
    - vmess-argo-$snb
    
- name: Select
  type: select
  proxies:
    - Balance                                         
    - Auto
    - DIRECT
    - vless-reality-vision-$snb                              
    - vmess-ws-$snb
    - hysteria2-$snb
    - vmess-tls-argo-$snb
    - vmess-argo-$snb
rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Select
  
EOF

sleep 2
v2sub=$(cat jh.txt)
echo "$v2sub" > ${FILE_PATH}/${UUID}_v2sub.txt
cat clash_meta.yaml > ${FILE_PATH}/${UUID}_clashmeta.txt
cat sing_box.json > ${FILE_PATH}/${UUID}_singbox.txt
V2rayN_LINK="https://${USERNAME}.serv00.net/${UUID}_v2sub.txt"
Clashmeta_LINK="https://${USERNAME}.serv00.net/${UUID}_clashmeta.txt"
Singbox_LINK="https://${USERNAME}.serv00.net/${UUID}_singbox.txt"
cat > list.txt <<EOF
=================================================================================================

The current client is usingIP：$IP
As default nodeIPBeing walled，The following other can be replaced at the client addressIP
$(dig @8.8.8.8 +time=5 +short "web$nb.serv00.com" | sort -u)
$(dig @8.8.8.8 +time=5 +short "$HOSTNAME" | sort -u)
$(dig @8.8.8.8 +time=5 +short "cache$nb.serv00.com" | sort -u)
-------------------------------------------------------------------------------------------------

one,Vless-realityShare links are as follows：
$vl_link

Notice：If entered earlierrealityThe domain name isCFdomain name，The following functions will be activated：
Can be applied in https://github.com/yonggekkk/Cloudflare_vless_trojan Created in a projectCF vless/trojan node
1,Proxyip(With port)The information is as follows：
Method one global application：Set variable name：proxyip    Set variable value：$IP:$vless_port  
Method 2 single node application：pathChange the path to：/pyip=$IP:$vless_port
CFNode'sTLSCan be turned on or off
CFThe node lands atCFThe area of ​​the website is：$IPArea

2, non-standard port anti-generationIPThe information is as follows：
Client preferredIPAddress is：$IP，port：$vless_port
CFNode'sTLSMust be turned on
CFNode landed to nonCFThe area of ​​the website is：$IPArea

Note：ifServ00ofIPBeing walled，proxyipStill effective，But non-standard port anti-generation used for client addresses and portsIPWill not be available
Note：Maybe some guys can scanServ00Anti-generationIPShare as itsIPLibrary or for sale，Please be carefulrealityThe domain name is set toCFdomain name
-------------------------------------------------------------------------------------------------


two,Vmess-wsThe three forms of sharing links are as follows：

1,Vmess-wsThe main node sharing link is as follows：
(This node does not support it by defaultCDN，If set toCDNReturn to source(Domain name required)：Client address can be modified by itselfIP/domain name，7indivual80Change the port at will，It can still be used by wall！)
$vmws_link

Argodomain name：${argodomain}
If aboveArgoTemporary domain name not generated，the following 2 and 3 ofArgoThe node will not be available (OpenArgofixed/Temporary domain name page，showHTTP ERROR 404Instructions are available normally)

2,Vmess-ws-tls_ArgoShare links are as follows： 
(This node isCDNPreferredIPnode，Client address can be modified by itselfIP/domain name，6indivual443Change the port at will，It can still be used by wall！)
$vmatls_link

3,Vmess-ws_ArgoShare links are as follows：
(This node isCDNPreferredIPnode，Client address can be modified by itselfIP/domain name，7indivual80Change the port at will，It can still be used by wall！)
$vma_link
-------------------------------------------------------------------------------------------------


three,HY2Share links are as follows：
$hy2_link
-------------------------------------------------------------------------------------------------


4. The aggregation of the above five nodes is as follows：
$V2rayN_LINK

The above five nodes aggregate universal sharing code：
$baseurl
-------------------------------------------------------------------------------------------------


5. Check itSing-boxandClash-metaSubscription configuration file，Please enter the main menu to select4

Clash-metaSubscribe to share link：
$Clashmeta_LINK

Sing-boxSubscribe to share link：
$Singbox_LINK
-------------------------------------------------------------------------------------------------

=================================================================================================

EOF
cat list.txt
sleep 2
rm -rf sb.log core tunnel.yml tunnel.json fake_useragent_0.2.0.json
}

showlist(){
if [[ -e $WORKDIR/list.txt ]]; then
green "View nodes, subscriptions, anti-generationIP,ProxyIPWait for information！Updating，Please wait……"
sleep 3
cat $WORKDIR/list.txt
else
red "Script not installed，Please select1Carry out installation" && exit
fi
}

showsbclash(){
if [[ -e $WORKDIR/sing_box.json ]]; then
green "CheckclashandsingboxConfiguration plaintext！Updating，Please wait……"
sleep 3
green "Sing_boxThe configuration file is as follows，Can be uploaded to the subscription client for use："
yellow "inArgoThe node isCDNPreferredIPnode，serverThe address can be modified by yourselfIP/domain name，It can still be used by wall！"
sleep 2
cat $WORKDIR/sing_box.json 
echo
echo
green "Clash_metaThe configuration file is as follows，Can be uploaded to the subscription client for use："
yellow "inArgoThe node isCDNPreferredIPnode，serverThe address can be modified by yourselfIP/domain name，It can still be used by wall！"
sleep 2
cat $WORKDIR/clash_meta.yaml
echo
else
red "Script not installed，Please select1Carry out installation" && exit
fi
}

servkeep() {
sed -i '' -e "14s|''|'$UUID'|" serv00keep.sh
sed -i '' -e "17s|''|'$vless_port'|" serv00keep.sh
sed -i '' -e "18s|''|'$vmess_port'|" serv00keep.sh
sed -i '' -e "19s|''|'$hy2_port'|" serv00keep.sh
sed -i '' -e "20s|''|'$IP'|" serv00keep.sh
sed -i '' -e "21s|''|'$reym'|" serv00keep.sh
if [ ! -f "$WORKDIR/boot.log" ]; then
sed -i '' -e "15s|''|'${ARGO_DOMAIN}'|" serv00keep.sh
sed -i '' -e "16s|''|'${ARGO_AUTH}'|" serv00keep.sh
fi
echo '#!/bin/bash
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
USERNAME=$(whoami | tr '\''[:upper:]'\'' '\''[:lower:]'\'')
WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs"
snb=$(hostname | awk -F '\''.'\'' '\''{print $1}'\'')
' > webport.sh
declare -f resallport >> webport.sh
declare -f check_port >> webport.sh
echo 'resallport' >> webport.sh
chmod +x webport.sh
#if ! crontab -l 2>/dev/null | grep -q 'serv00keep'; then
#if [ -f "$WORKDIR/boot.log" ] || grep -q "trycloudflare.com" "$WORKDIR/boot.log" 2>/dev/null; then
#check_process="! ps aux | grep '[c]onfig' > /dev/null || ! ps aux | grep [l]ocalhost > /dev/null"
#else
#check_process="! ps aux | grep '[c]onfig' > /dev/null || ! ps aux | grep [t]oken > /dev/null"
#fi
#(crontab -l 2>/dev/null; echo "*/10 * * * * if $check_process; then /bin/bash serv00keep.sh; fi") | crontab -
#fi
#green "Installation completed，Default per10Execute once in minutes，run crontab -e Can modify the keep-alive execution interval by yourself" && sleep 2
#echo
green "Start installing the multi-function homepage，Please wait……"
devil www del ${snb}.${USERNAME}.serv00.net > /dev/null 2>&1
devil www add ${USERNAME}.serv00.net php > /dev/null 2>&1
devil www add ${snb}.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1
ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
rm -rf $HOME/.npmrc > /dev/null 2>&1
cd "$keep_path"
npm install basic-auth express dotenv axios --silent > /dev/null 2>&1
rm $HOME/domains/${snb}.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
devil www restart ${snb}.${USERNAME}.serv00.net
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
green "Installation completed，Multifunction homepage address：http://${snb}.${USERNAME}.serv00.net" && sleep 2
}

okip(){
    IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))
    API_URL="https://status.eooce.com/api"
    IP=""
    THIRD_IP=${IP_LIST[2]}
    RESPONSE=$(curl -s --max-time 2 "${API_URL}/${THIRD_IP}")
    if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
        IP=$THIRD_IP
    else
        FIRST_IP=${IP_LIST[0]}
        RESPONSE=$(curl -s --max-time 2 "${API_URL}/${FIRST_IP}")
        
        if [[ $(echo "$RESPONSE" | jq -r '.status') == "Available" ]]; then
            IP=$FIRST_IP
        else
            IP=${IP_LIST[1]}
        fi
    fi
    echo "$IP"
    }

fastrun(){
if [[ -e $WORKDIR/config.json ]]; then
  COMMAND="sb"
  SCRIPT_PATH="$HOME/bin/$COMMAND"
  mkdir -p "$HOME/bin"
  curl -Ls https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00.sh > "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
      echo "export PATH=\"\$HOME/bin:\$PATH\"" >> "$HOME/.bashrc"
      source "$HOME/.bashrc"
  fi
curl -sL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/app.js -o "$keep_path"/app.js
sed -i '' "15s/name/$snb/g" "$keep_path"/app.js
sed -i '' "60s/key/$UUID/g" "$keep_path"/app.js
sed -i '' "75s/name/$USERNAME/g" "$keep_path"/app.js
sed -i '' "75s/where/$snb/g" "$keep_path"/app.js
curl -sSL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00keep.sh -o serv00keep.sh && chmod +x serv00keep.sh
curl -sL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/index.html -o "$FILE_PATH"/index.html
curl -sL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/sversion | awk -F "Update content" '{print $1}' | head -n 1 > $WORKDIR/v
else
red "Script not installed，Please select1Carry out installation" && exit
fi
}

resservsb(){
if [[ -e $WORKDIR/config.json ]]; then
yellow "Restarting……Please wait……"
cd $WORKDIR
ps aux | grep '[r]un -c con' | awk '{print $2}' | xargs -r kill -9 > /dev/null 2>&1
sbb=$(cat sb.txt)
nohup ./"$sbb" run -c config.json >/dev/null 2>&1 &
sleep 1
curl -sk "http://${snb}.${USERNAME}.serv00.net/up" > /dev/null 2>&1
sleep 5
if pgrep -x "$sbb" > /dev/null; then
green "$sbb The main process restarted successfully"
else
red "$sbb The main process failed to restart"
fi
cd
else
red "Script not installed，Please select1Carry out installation" && exit
fi
}

menu() {
   clear
   echo "============================================================"
   green "Brother YongGithubproject  ：github.com/yonggekkk"
   green "Brother YongBloggerblog ：ygkkk.blogspot.com"
   green "Brother YongYouTubeChannel ：www.youtube.com/@ygkkk"
   green "Serv00-sb-ygThree agreements coexist：vless-reality,Vmess-ws(Argo),Hy2"
   green "Script shortcuts：sb"
   echo   "============================================================"
   green  "1. One-click installation Serv00-sb-yg"
   echo   "------------------------------------------------------------"
   red    "2. Uninstall and delete Serv00-sb-yg"
   echo   "------------------------------------------------------------"
   green  "3. Restart the main process (Repair nodes)"
   echo   "------------------------------------------------------------"
   green  "4. Update script"
   echo   "------------------------------------------------------------"
   green  "5. View sharing of each node/sing-boxandclashSubscription link/Anti-generationIP/ProxyIP"
   echo   "------------------------------------------------------------"
   green  "6. Checksing-boxandclashConfiguration File"
   echo   "------------------------------------------------------------"
   yellow "7. Reset and randomly generate new ports (The script can be executed before and after installation)"
   echo   "------------------------------------------------------------"
   yellow "8. Clean up all service processes and files (System initialization)"
   echo   "------------------------------------------------------------"
   red    "0. Exit script"
   echo   "============================================================"
ym=("$HOSTNAME" "cache$nb.serv00.com" "web$nb.serv00.com")
rm -rf ip.txt
for host in "${ym[@]}"; do
response=$(curl -sL --connect-timeout 5 --max-time 7 "https://ss.fkj.pp.ua/api/getip?host=$host")
if [[ "$response" =~ (unknown|not|error) ]]; then
dig @8.8.8.8 +time=5 +short $host | sort -u >> $WORKDIR/ip.txt
sleep 1  
else
while IFS='|' read -r ip status; do
if [[ $status == "Accessible" ]]; then
echo "$ip: Available" >> $WORKDIR/ip.txt
else
echo "$ip: Being walled (ArgoandCDNReturn to source node,proxyipStill effective)" >> $WORKDIR/ip.txt
fi	
done <<< "$response"
fi
done
if [[ ! "$response" =~ (unknown|not|error) ]]; then
grep ':' $WORKDIR/ip.txt | sort -u -o $WORKDIR/ip.txt
fi
green "Serv00Server name：${snb}"
echo
green "Currently availableIPas follows："
cat $WORKDIR/ip.txt
if [[ -e $WORKDIR/config.json ]]; then
echo "As default nodeIPBeing walled，You can change any of the above at the client address to display the available onesIP"
fi
echo
portlist=$(devil port list | grep -E '^[0-9]+[[:space:]]+[a-zA-Z]+' | sed 's/^[[:space:]]*//')
if [[ -n $portlist ]]; then
green "The configured ports are as follows："
echo -e "$portlist"
else
yellow "No port is set"
fi
echo
insV=$(cat $WORKDIR/v 2>/dev/null)
latestV=$(curl -sL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/sversion | awk -F "Update content" '{print $1}' | head -n 1)
if [ -f $WORKDIR/v ]; then
if [ "$insV" = "$latestV" ]; then
echo -e "current Serv00-sb-yg The latest version of the script：${purple}${insV}${re} (Installed)"
else
echo -e "current Serv00-sb-yg Script version number：${purple}${insV}${re}"
echo -e "Latest detected Serv00-sb-yg Script version number：${yellow}${latestV}${re} (Available4Make updates)"
echo -e "${yellow}$(curl -sL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/sversion)${re}"
fi
echo -e "========================================================="
sbb=$(cat $WORKDIR/sb.txt 2>/dev/null)
showuuid=$(jq -r '.inbounds[0].users[0].password' $WORKDIR/config.json 2>/dev/null)
if pgrep -x "$sbb" > /dev/null; then
green "Sing-boxThe main process is running normally"
green "UUIDpassword：$showuuid" 
else
yellow "Sing-boxThe main process failed to start，Try running the page to keep alive, restart, and reset the port"
fi
if [ -f "$WORKDIR/boot.log" ] && grep -q "trycloudflare.com" "$WORKDIR/boot.log"; then
argosl=$(cat "$WORKDIR/boot.log" 2>/dev/null | grep -a trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
checkhttp=$(curl -o /dev/null -s -w "%{http_code}\n" "https://$argosl")
[ "$checkhttp" -eq 404 ] && check="Domain name valid" || check="Domain name may be invalid"
green "ArgoTemporary domain name：$argosl  $check"
fi
if [ -f "$WORKDIR/boot.log" ] && ! grep -q "trycloudflare.com" "$WORKDIR/boot.log"; then
yellow "ArgoTemporary domain names do not exist yet，It will automatically resume during the maintenance process"
fi
if [ ! -f "$WORKDIR/boot.log" ]; then
argogd=$(cat $WORKDIR/gdym.log 2>/dev/null)
checkhttp=$(curl --max-time 2 -o /dev/null -s -w "%{http_code}\n" "https://$argogd")
[ "$checkhttp" -eq 404 ] && check="Domain name valid" || check="Domain name may be invalid"
green "ArgoFixed domain name：$argogd $check"
fi
green "The multi-function homepage is as follows (Support keep alive, restart, reset ports, and node query)"
purple "http://${snb}.${USERNAME}.serv00.net"
#if ! crontab -l 2>/dev/null | grep -q 'serv00keep'; then
#if [ -f "$WORKDIR/boot.log" ] || grep -q "trycloudflare.com" "$WORKDIR/boot.log" 2>/dev/null; then
#check_process="! ps aux | grep '[c]onfig' > /dev/null || ! ps aux | grep [l]ocalhost > /dev/null"
#else
#check_process="! ps aux | grep '[c]onfig' > /dev/null || ! ps aux | grep [t]oken > /dev/null"
#fi
#(crontab -l 2>/dev/null; echo "*/2 * * * * if $check_process; then /bin/bash serv00keep.sh; fi") | crontab -
#purple "DiscoverServ00Take the ultimate move，CronKeep alive has been reset and cleared"
#purple "at presentCronKeepaway has been repaired successfully. Open http://${USERNAME}.${USERNAME}.serv00.net/up Can also be kept alive in real time"
#purple "Main process andArgoProcess is starting…………1You can enter the script again in minutes"
#else
#green "CronKeep alive and run normally. Open http://${USERNAME}.${USERNAME}.serv00.net/up Can also be kept alive in real time"
#fi
else
echo -e "current Serv00-sb-yg Script version number：${purple}${latestV}${re}"
yellow "Not installed Serv00-sb-yg script！Please select 1 Install"
fi
#curl -sSL https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00.sh -o serv00.sh && chmod +x serv00.sh
   echo -e "========================================================="
   reading "Please enter the selection0-8: " choice
   echo
    case "${choice}" in
        1) install_singbox ;;
        2) uninstall_singbox ;; 
	3) resservsb ;;
	4) fastrun && green "The script has been updated successfully" && sleep 2 && sb ;; 
        5) showlist ;;
	6) showsbclash ;;
        7) resallport ;;
        8) kill_all_tasks ;;
	0) exit 0 ;;
        *) red "Invalid option，Please enter 0 arrive 8" ;;
    esac
}
menu
