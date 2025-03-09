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
export LC_ALL=C
HOSTNAME=$(hostname)
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
export UUID=${UUID:-$(uuidgen -r)}  
export NEZHA_SERVER=${NEZHA_SERVER:-''}  # v1Nezha Form：nezha.abc.com:8008,v0Nezha Form：nezha.abc.com
export NEZHA_PORT=${NEZHA_PORT:-''}      # v1Nezha does not need this variable
export NEZHA_KEY=${NEZHA_KEY:-''}        # v1ofNZ_CLIENT_SECRETorv0ofagentKey
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}   
export ARGO_AUTH=${ARGO_AUTH:-''}
export CFIP=${CFIP:-'www.visa.com.tw'} 
export CFPORT=${CFPORT:-'443'}
export SUB_TOKEN=${SUB_TOKEN:-${UUID:0:8}}
export UPLOAD_URL=${UPLOAD_URL:-''}  # Subscriptions are automatically added to the aggregation subscriber，Need to deploy firstMerge-subproject,Fill in the deployment homepage address,For example: SUB_URL=https://merge.serv00.net

[[ "$HOSTNAME" == "s1.ct8.pl" ]] && WORKDIR="${HOME}/domains/${USERNAME}.ct8.pl/logs" && FILE_PATH="${HOME}/domains/${USERNAME}.ct8.pl/public_html" || WORKDIR="${HOME}/domains/${USERNAME}.serv00.net/logs" && FILE_PATH="${HOME}/domains/${USERNAME}.serv00.net/public_html"
rm -rf "$WORKDIR" && mkdir -p "$WORKDIR" "$FILE_PATH" && chmod 777 "$WORKDIR" "$FILE_PATH" >/dev/null 2>&1
command -v curl &>/dev/null && COMMAND="curl -so" || command -v wget &>/dev/null && COMMAND="wget -qO" || { red "Error: neither curl nor wget found, please install one of them." >&2; exit 1; }

check_port () {
port_list=$(devil port list)
tcp_ports=$(echo "$port_list" | grep -c "tcp")
udp_ports=$(echo "$port_list" | grep -c "udp")

if [[ $tcp_ports -ne 1 || $udp_ports -ne 2 ]]; then
    red "Port rules do not meet the requirements，Adjusting..."

    if [[ $tcp_ports -gt 1 ]]; then
        tcp_to_delete=$((tcp_ports - 1))
        echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
            devil port del $type $port >/dev/null 2>&1
            green "DeletedTCPport: $port"
        done
    fi

    if [[ $udp_ports -gt 2 ]]; then
        udp_to_delete=$((udp_ports - 2))
        echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
            devil port del $type $port >/dev/null 2>&1
            green "DeletedUDPport: $port"
        done
    fi

    if [[ $tcp_ports -lt 1 ]]; then
        while true; do
            tcp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add tcp $tcp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "AddedTCPport: $tcp_port"
                break
            else
                yellow "port $tcp_port Not available，Try another port..."
            fi
        done
    fi

    if [[ $udp_ports -lt 2 ]]; then
        udp_ports_to_add=$((2 - udp_ports))
        udp_ports_added=0
        while [[ $udp_ports_added -lt $udp_ports_to_add ]]; do
            udp_port=$(shuf -i 10000-65535 -n 1) 
            result=$(devil port add udp $udp_port 2>&1)
            if [[ $result == *"succesfully"* ]]; then
                green "AddedUDPport: $udp_port"
                if [[ $udp_ports_added -eq 0 ]]; then
                    udp_port1=$udp_port
                else
                    udp_port2=$udp_port
                fi
                udp_ports_added=$((udp_ports_added + 1))
            else
                yellow "port $udp_port Not available，Try another port..."
            fi
        done
    fi
    green "Port adjustment completed,Will be disconnectedsshconnect,Please reconnectshhRe-execute the script"
    quick_command
    devil binexec on >/dev/null 2>&1
    kill -9 $(ps -o ppid= -p $$) >/dev/null 2>&1
else
    tcp_port=$(echo "$port_list" | awk '/tcp/ {print $1}')
    udp_ports=$(echo "$port_list" | awk '/udp/ {print $1}')
    udp_port1=$(echo "$udp_ports" | sed -n '1p')
    udp_port2=$(echo "$udp_ports" | sed -n '2p')

    purple "currentTCPport: $tcp_port"
    purple "currentUDPport: $udp_port1 and $udp_port2"
fi

export VMESS_PORT=$tcp_port
export TUIC_PORT=$udp_port1
export HY2_PORT=$udp_port2
}

changge_ports() {
reading "All ports will be deleted and then opened randomly1indivualtcpPorts and2indivualudpport,Are you sure to continue?(Enter directly to confirm the replacement)y/n: " choice

if [[ -z "$choice" || "$choice" == "y" || "$choice" == "Y" ]]; then
    devil port list | grep -E "^\s*[0-9]+" | while read -r line; do
        port=$(echo "$line" | awk '{print $1}')
        proto=$(echo "$line" | awk '{print $2}')

        if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
            continue
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            continue
        fi

        if devil port del "${proto}" "${port}" > /dev/null 2>&1; then
            green "Port ${port}/${proto} has been removed successfully"
        else
            red "Failed to remove port ${port}/${proto}"
        fi
    done
    check_port
else
    menu  
fi
}

check_website() {
CURRENT_SITE=$(devil www list | awk -v username="${USERNAME}" '$1 == username".serv00.net" && $2 == "php" {print $0}')
if [ -n "$CURRENT_SITE" ]; then
    green "Detected existing${USERNAME}.serv00.netofphpSite,No modification required"
else
    EXIST_SITE=$(devil www list | awk -v username="${USERNAME}" '$1 == username".serv00.net" {print $0}')
    if [ -n "$EXIST_SITE" ]; then
        red "Does not exist${USERNAME}.serv00.netofphpSite,Adjusting for you..."
        devil www del "${USERNAME}.serv00.net" > /dev/null 2>&1
        devil www add "${USERNAME}.serv00.net" php "$HOME/domains/${USERNAME}.serv00.net" > /dev/null 2>&1
        green "Deleted the old site and created a new onephpSite"
    else
        devil www add "${USERNAME}.serv00.net" php "$HOME/domains/${USERNAME}.serv00.net" > /dev/null 2>&1
        green "phpSite creation is completed"
    fi
fi
index_url="https://github.com/eooce/Sing-box/releases/download/00/index.html"
[ -f "${FILE_PATH}/index.html" ] || $COMMAND "${FILE_PATH}/index.html" "$index_url"
}

read_nz_variables() {
  if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_KEY" ]; then
      green "Running Nezha Probe with custom variable Nezha"
      return
  else
      reading "Is it necessary to install Nezha probe?？(Directly press the car and no installation)y/n: " nz_choice
      [[ -z $nz_choice ]] && return
      [[ "$nz_choice" != "y" && "$nz_choice" != "Y" ]] && return
      reading "\nPlease enter the domain name of Nezha probe orip\nv1Nezha Form：nezha.abc.com:8008,v0Nezha Form：nezha.abc.com :" NEZHA_SERVER
      green "Your Nezha domain name is: $NEZHA_SERVER"
      if [[ "$NEZHA_SERVER" != *":"* ]]; then
      	reading "Please enter Nezhav0Probe port(Direct Enter will set to5555)：" NEZHA_PORT
      	[[ -z $NEZHA_PORT ]] && NEZHA_PORT="5555"
      	green "Your Nezha port is: $NEZHA_PORT"
      else
      	  NEZHA_PORT=""
      fi
      reading "Please enterv0ofagentKey orv1ofNZ_CLIENT_SECRET：" NEZHA_KEY
      green "Your Nezha key is: $NEZHA_KEY"
  fi
}

install_singbox() {
bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
echo -e "${yellow}This script coexists at the same time.${purple}(vmess-ws,vmess-ws-tls(argo),hysteria2,tuic)${re}"
reading "\nAre you sure to continue installing?？(Enter directly to confirm the installation)y/n: " choice
  case "${choice:-y}" in
    [Yy]|"")
    	clear
        cd $WORKDIR
        check_port
        check_website
        read_nz_variables
        argo_configure
        generate_config
        download_singbox
        get_links
      ;;
    [Nn]) exit 0 ;;
    *) red "Invalid selection，Please enteryorn" && menu ;;
  esac
}


uninstall_singbox() {
  reading "\nAre you sure you want to uninstall？y/n: " choice
    case "$choice" in
        [Yy])
	    bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
       	    rm -rf $WORKDIR && find ${FILE_PATH} -mindepth 1 ! -name 'index.html' -exec rm -rf {} +
            devil www del keep.${USERNAME}.serv00.net nodejs 2>/dev/null || true
            rm -rf ${HOME}/domains/${USERNAME}.serv00.net/public_nodejs 2 >/dev/null || true
            rm -rf "${HOME}/bin/00" >/dev/null 2>&1
            [ -d "${HOME}/bin" ] && [ -z "$(ls -A "${HOME}/bin")" ] && rmdir "${HOME}/bin"
            sed -i '/export PATH="\$HOME\/bin:\$PATH"/d' "${HOME}/.bashrc" >/dev/null 2>&1
            source "${HOME}/.bashrc"
	    clear
       	    green "Sing-boxFour-in-one has been completely uninstalled"
          ;;
        [Nn]) exit 0 ;;
    	  *) red "Invalid selection,Please enteryorn" && menu ;;
    esac
}

reset_system() {
reading "\nAre you sure to reset the system?？y/n: " choice
  case "$choice" in
    [Yy]) bash -c 'ps aux | grep $(whoami) | grep -v "sshd\|bash\|grep" | awk "{print \$2}" | xargs -r kill -9 >/dev/null 2>&1' >/dev/null 2>&1
          find "${HOME}" -mindepth 1 ! -name "domains" ! -name "mail" ! -name "repo" ! -name "backups" ! -name ".*" -exec rm -rf {} + > /dev/null 2>&1
          devil www del $USERNAME.serv00.net > /dev/null 2>&1
          devil www del keep.$USERNAME.serv00.net > /dev/null 2>&1
          rm -rf $HOME/domains/* > /dev/null 2>&1
          green "\nInitialization system is completed!\n"
         ;;
       *) menu ;;
  esac
}

argo_configure() {
  if [[ -z $ARGO_AUTH || -z $ARGO_DOMAIN ]]; then
      reading "Is it necessary to use fixedargotunnel？(Directly enter the car to use a temporary tunnel)y/n: " argo_choice
      [[ -z $argo_choice ]] && return
      [[ "$argo_choice" != "y" && "$argo_choice" != "Y" && "$argo_choice" != "n" && "$argo_choice" != "N" ]] && { red "Invalid selection，Please enteryorn"; return; }
      if [[ "$argo_choice" == "y" || "$argo_choice" == "Y" ]]; then
          reading "Please enterargoFixed tunnel domain name: " ARGO_DOMAIN
          green "yourargoThe fixed tunnel domain name is: $ARGO_DOMAIN"
          reading "Please enterargoFixed tunnel key（JsonorToken）: " ARGO_AUTH
          green "yourargoThe fixed tunnel key is: $ARGO_AUTH"
	        echo -e "${red}Notice：${purple}usetoken，Need to be incloudflareThe tunnel port and panel are open in the backgroundtcpConsistent port${re}"
      else
          green "ARGOTunnel variable not set，Temporary tunnel will be used"
          return
      fi
  fi

  if [[ $ARGO_AUTH =~ TunnelSecret ]]; then
    echo $ARGO_AUTH > tunnel.json
    cat > tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$ARGO_AUTH")
credentials-file: tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$VMESS_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
  else
    green "ARGO_AUTH mismatch TunnelSecret,use token connect to tunnel"
  fi
}

generate_config() {

  openssl ecparam -genkey -name prime256v1 -out "private.key"
  openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=$USERNAME.serv00.net"
  
  yellow "Get AvailableIPmiddle，Please wait..."
  available_ip=$(get_ip)
  purple "Current selectionIPfor：$available_ip If the node does not work after installation, try reinstalling"
  
cat > config.json <<EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
   "dns": {
    "servers": [
      {
        "address": "8.8.8.8",
        "address_resolver": "local"
      },
      {
        "tag": "local",
        "address": "local"
      }
    ]
  },
  "inbounds": [
    {
      "tag": "hysteria-in",
      "type": "hysteria2",
      "listen": "$available_ip",
      "listen_port": $HY2_PORT,
      "users": [
        {
          "password": "$UUID"
        }
      ],
      "masquerade": "https://bing.com",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "cert.pem",
        "key_path": "private.key"
      }
    },
    {
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": $VMESS_PORT,
      "users": [
        {
          "uuid": "$UUID"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess-argo",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    },
    {
      "tag": "tuic-in",
      "type": "tuic",
      "listen": "$available_ip",
      "listen_port": $TUIC_PORT,
      "users": [
        {
          "uuid": "$UUID",
          "password": "admin123"
        }
      ],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "cert.pem",
        "key_path": "private.key"
      }
    }
  ],
EOF

# in the case ofs14/s15/s16,googleandyoutubeRelated serviceswarpExit
if [[ "$HOSTNAME" =~ s14|s15|s16 ]]; then
  cat >> config.json <<EOF
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "162.159.192.200",
      "server_port": 4500,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:8f77:1ca9:f086:846c:5f9e/128"
      ],
      "private_key": "wIxszdR2nMdA7a2Ul3XQcniSfSZqdqjPb6w6opvf5AU=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [126, 246, 173]
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/youtube.srs",
        "download_detour": "direct"
      },
      {
        "tag": "google",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/google.srs",
        "download_detour": "direct"
      },
      {
        "tag": "spotify",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/spotify.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": ["google", "youtube", "spotify"],
        "outbound": "wireguard-out"
      }
    ],
    "final": "direct"
  }
}
EOF
else
  cat >> config.json <<EOF
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
fi
}

download_singbox() {
ARCH=$(uname -m) && DOWNLOAD_DIR="." && mkdir -p "$DOWNLOAD_DIR" && FILE_INFO=()
if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
elif [ "$ARCH" == "amd64" ] || [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "x86" ]; then
    BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi
FILE_INFO=("$BASE_URL/sb web" "$BASE_URL/server bot")
if [ -n "$NEZHA_PORT" ]; then
    FILE_INFO+=("$BASE_URL/npm npm")
else
    FILE_INFO+=("$BASE_URL/v1 php")
    cat > "${WORKDIR}/config.yaml" << EOF
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 1
server: ${NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: false
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}
EOF
fi
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
        green "Downloading $NEW_FILENAME by wget"
    else
        wait $CURL_PID
        green "Downloading $NEW_FILENAME by curl"
    fi
}

for entry in "${FILE_INFO[@]}"; do
    URL=$(echo "$entry" | cut -d ' ' -f 1)
    RANDOM_NAME=$(generate_random_name)
    NEW_FILENAME="$DOWNLOAD_DIR/$RANDOM_NAME"
    
    download_with_fallback "$URL" "$NEW_FILENAME"
    
    chmod +x "$NEW_FILENAME"
    FILE_MAP[$(echo "$entry" | cut -d ' ' -f 2)]="$NEW_FILENAME"
done
wait

if [ -e "$(basename ${FILE_MAP[web]})" ]; then
    nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[web]})" > /dev/null && green "$(basename ${FILE_MAP[web]}) is running" || { red "$(basename ${FILE_MAP[web]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[web]})" && nohup ./"$(basename ${FILE_MAP[web]})" run -c config.json >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[web]}) restarted"; }
fi

if [ -e "$(basename ${FILE_MAP[bot]})" ]; then
    if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${ARGO_AUTH}"
    elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
      args="tunnel --edge-ip-version auto --config tunnel.yml run"
    else
      args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile boot.log --loglevel info --url http://localhost:$VMESS_PORT"
    fi
    nohup ./"$(basename ${FILE_MAP[bot]})" $args >/dev/null 2>&1 &
    sleep 2
    pgrep -x "$(basename ${FILE_MAP[bot]})" > /dev/null && green "$(basename ${FILE_MAP[bot]}) is running" || { red "$(basename ${FILE_MAP[bot]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[bot]})" && nohup ./"$(basename ${FILE_MAP[bot]})" "${args}" >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[bot]}) restarted"; }
fi

if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_PORT" ] && [ -n "$NEZHA_KEY" ]; then
    if [ -e "$(basename ${FILE_MAP[npm]})" ]; then
	  tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
      [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]] && NEZHA_TLS="--tls" || NEZHA_TLS=""
      export TMPDIR=$(pwd)
      nohup ./"$(basename ${FILE_MAP[npm]})" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
      sleep 2
      pgrep -x "$(basename ${FILE_MAP[npm]})" > /dev/null && green "$(basename ${FILE_MAP[npm]}) is running" || { red "$(basename ${FILE_MAP[npm]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[npm]})" && nohup ./"$(basename ${FILE_MAP[npm]})" -s "${NEZHA_SERVER}:${NEZHA_PORT}" -p "${NEZHA_KEY}" ${NEZHA_TLS} >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[npm]}) restarted"; }
    fi
elif [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_KEY" ]; then
    if [ -e "$(basename ${FILE_MAP[php]})" ]; then
      nohup ./"$(basename ${FILE_MAP[php]})" -c "${WORKDIR}/config.yaml" >/dev/null 2>&1 &
      sleep 2
      pgrep -x "$(basename ${FILE_MAP[php]})" > /dev/null && green "$(basename ${FILE_MAP[php]}) is running" || { red "$(basename ${FILE_MAP[php]}) is not running, restarting..."; pkill -x "$(basename ${FILE_MAP[php]})" && nohup ./"$(basename ${FILE_MAP[php]})" -s -c "${WORKDIR}/config.yaml" >/dev/null 2>&1 & sleep 2; purple "$(basename ${FILE_MAP[php]}) restarted"; }
    fi
else
    purple "NEZHA variable is empty, skipping running"
fi

for key in "${!FILE_MAP[@]}"; do
    if [ -e "$(basename ${FILE_MAP[$key]})" ]; then
        rm -rf "$(basename ${FILE_MAP[$key]})" >/dev/null 2>&1
    fi
done

}

get_argodomain() {
  if [[ -n $ARGO_AUTH ]]; then
    echo "$ARGO_DOMAIN"
  else
    local retry=0
    local max_retries=6
    local argodomain=""
    while [[ $retry -lt $max_retries ]]; do
      ((retry++))
      argodomain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' boot.log | sed 's@https://@@') 
      if [[ -n $argodomain ]]; then
        break
      fi
      sleep 1
    done
    echo "$argodomain"
  fi
}

get_ip() {
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

generate_sub_link () {
echo ""
rm -rf ${FILE_PATH}/.htaccess
base64 -w0 ${FILE_PATH}/list.txt > ${FILE_PATH}/v2.log
V2rayN_LINK="https://${USERNAME}.serv00.net/v2.log"
PHP_URL="https://00.ssss.nyc.mn/sub.php"
QR_URL="https://00.ssss.nyc.mn/qrencode"  
$COMMAND "${FILE_PATH}/${SUB_TOKEN}.php" "$PHP_URL" 
$COMMAND "${WORKDIR}/qrencode" "$QR_URL" && chmod +x "${WORKDIR}/qrencode"
curl -sS "https://sublink.eooce.com/clash?config=${V2rayN_LINK}" -o ${FILE_PATH}/clash.yaml
curl -sS "https://sublink.eooce.com/singbox?config=${V2rayN_LINK}" -o ${FILE_PATH}/singbox.yaml
"${WORKDIR}/qrencode" -m 2 -t UTF8 "https://${USERNAME}.serv00.net/${SUB_TOKEN}"
purple "\nAdaptive node subscription link: https://${USERNAME}.serv00.net/${SUB_TOKEN}\n"
green "QR code and node subscription links are suitable for V2rayN/Nekoray/ShadowRocket/Clash/Mihomo/Sing-box/karing/Loon/sterisand wait\n\n"
cat > ${FILE_PATH}/.htaccess << EOF
RewriteEngine On
RewriteRule ^${SUB_TOKEN}$ ${SUB_TOKEN}.php [L]
<FilesMatch "^(clash\.yaml|singbox\.yaml|list\.txt|v2\.log||sub\.php)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
<Files "${SUB_TOKEN}.php">
    Order Allow,Deny
    Allow from all
</Files>
EOF
}

get_links(){
argodomain=$(get_argodomain)
echo -e "\e[1;32mArgoDomain:\e[1;35m${argodomain}\e[0m\n"
ISP=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26}' | sed -e 's/ /_/g' || echo "0")
get_name() { if [ "$HOSTNAME" = "s1.ct8.pl" ]; then SERVER="CT8"; else SERVER=$(echo "$HOSTNAME" | cut -d '.' -f 1); fi; echo "$SERVER"; }
NAME="$ISP-$(get_name)"
yellow "Notice：v2rayOr other software's skip certificate verification needs to be set totrue,otherwisehy2ortuicThe node may not work\n"
cat > ${FILE_PATH}/list.txt <<EOF
vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess\", \"add\": \"$available_ip\", \"port\": \"$VMESS_PORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/vmess-argo?ed=2048\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)

vmess://$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-argo\", \"add\": \"$CFIP\", \"port\": \"$CFPORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$argodomain\", \"path\": \"/vmess-argo?ed=2048\", \"tls\": \"tls\", \"sni\": \"$argodomain\", \"alpn\": \"\", \"fp\": \"\"}" | base64 -w0)

hysteria2://$UUID@$available_ip:$HY2_PORT/?sni=www.bing.com&alpn=h3&insecure=1#$NAME-hysteria2

tuic://$UUID:admin123@$available_ip:$TUIC_PORT?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$NAME-tuic
EOF
cat ${FILE_PATH}/list.txt
generate_sub_link
rm -rf boot.log config.json sb.log core tunnel.yml tunnel.json fake_useragent_0.2.0.json
quick_command
green "Running done!\n"

}

install_keepalive () {
    clear
    reading "Need or notTelegramnotify？(Directly press the car and it will not be enabled)y/n: " tg_notification
    if [[ "$tg_notification" == "y" || "$tg_notification" == "Y" ]]; then

        reading "Please enterTelegram chat ID (tgsuperior@laowang_serv00_botGet): " tg_chat_id
        [[ -z $tg_chat_id ]] && { red "Telegram chat IDCan't be empty"; return; }
        green "You setTelegram chat_idfor: ${tg_chat_id}"

        reading "Please enterTelegram Bot Token (Enter the car directly to use Lao Wang'sbotNotify or fill in your own): " tg_token
        [[ -z $tg_token ]] && tg_token=""
        green "You setTelegram bot tokenfor: ${tg_token}"
    fi

    reading "Is it necessary to keep Nezha probe？(Directly press the car and it will not be enabled)y/n: " keep_nezha
    if [[ "$keep_nezha" == "y" || "$keep_nezha" == "Y" ]]; then
        reading "Please enter the domain name of Nezha panel [v1Must have panel port]：" nezha_server
        green "Your Nezha panel domain name is: $nezha_server"

        if [[ "$nezha_server" != *":"* ]]; then
          reading "Please enter Nezhaagentport(v1Please go directly to the car and leave it empty): " nezha_port
          [[ -z $nezha_port ]] && nezha_port="5555"
          green "Your NezhaagentThe port is: $nezha_port"
        else
          nezha_port=""
        fi

        reading "Please enter Nezhav0ofagentKey orv1ofNZ_CLIENT_SECRET: " nezha_key
        [[ -z $nezha_key ]] && { red "NezhaagentThe key cannot be empty"; return; }
        green "Your NezhaagentThe key is: $nezha_key"
    fi

    reading "Is it necessary to set it upArgoFixed tunnel？(Directly enter the car to use a temporary tunnel)y/n: " argo
    if [[ "$argo" == "y" || "$argo" == "Y" ]]; then

        reading "Please enterArgoFixed tunnel domain name: " argo_domain
        [[ -z $argo_domain ]] && { red "ArgoThe fixed tunnel domain name cannot be empty"; return; }
        green "yourArgoThe fixed tunnel domain name is: $argo_domain"

        reading "Please enterArgoFixed tunnel key(jsonortoken): " argo_key
        [[ -z $argo_key ]] && { red "ArgoFixed tunnel key cannot be empty"; return; }
        green "yourArgoThe fixed tunnel key is: $argo_key"
    fi

    purple "Installing the keep-alive service,Please wait......"
    keep_path="$HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs"
    [ -d "$keep_path" ] || mkdir -p "$keep_path"
    app_file_url="https://00.ssss.nyc.mn/app.js"
    $COMMAND "${keep_path}/app.js" "$app_file_url"

    cat > ${keep_path}/.env <<EOF
UUID=${UUID}
CFIP=${CFIP}
CFPORT=${CFPORT}
SUB_TOKEN=${UUID:0:8}
${UPLOAD_URL:+API_SUB_URL=$UPLOAD_URL}
${tg_chat_id:+TELEGRAM_CHAT_ID=$tg_chat_id}
${tg_token:+TELEGRAM_BOT_TOKEN=$tg_token}
${nezha_server:+NEZHA_SERVER=$nezha_server}
${nezha_port:+NEZHA_PORT=$nezha_port}
${nezha_key:+NEZHA_KEY=$nezha_key}
ARGO_DOMAIN=$argo_domain
ARGO_AUTH=$([[ -z "$argo_key" ]] && echo "" || ([[ "$argo_key" =~ ^\{.* ]] && echo "'$argo_key'" || echo "$argo_key"))
EOF

cat > ${FILE_PATH}/.htaccess << EOF
RewriteEngine On
RewriteRule ^${SUB_TOKEN}$ ${SUB_TOKEN}.php [L]
<FilesMatch "^(clash\.yaml|singbox\.yaml|list\.txt|v2\.log||sub\.php)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
<Files "${SUB_TOKEN}.php">
    Order Allow,Deny
    Allow from all
</Files>
EOF
    devil www add keep.${USERNAME}.serv00.net nodejs /usr/local/bin/node18 > /dev/null 2>&1
    # devil ssl www add $available_ip le le keep.${USERNAME}.serv00.net > /dev/null 2>&1
    ln -fs /usr/local/bin/node18 ~/bin/node > /dev/null 2>&1
    ln -fs /usr/local/bin/npm18 ~/bin/npm > /dev/null 2>&1
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    echo 'export PATH=~/.npm-global/bin:~/bin:$PATH' >> $HOME/.bash_profile && source $HOME/.bash_profile
    rm -rf $HOME/.npmrc > /dev/null 2>&1
    cd ${keep_path} && npm install dotenv axios --silent > /dev/null 2>&1
    rm $HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs/public/index.html > /dev/null 2>&1
    # devil www options keep.${USERNAME}.serv00.net sslonly on > /dev/null 2>&1
    devil www restart keep.${USERNAME}.serv00.net > /dev/null 2>&1
    generate_sub_link
    if curl -skL "http://keep.${USERNAME}.serv00.net/start" | grep -q "running"; then
        green "\nFully automatic maintenance service installation successfully\n"
	green "All services are running normally,Automatically keep-alive task added successfully\n\n"
        purple "access http://keep.${USERNAME}.serv00.net/stop End the process\n"
        purple "access http://keep.${USERNAME}.serv00.net/list All process list\n"
        yellow "access http://keep.${USERNAME}.serv00.net/start Reset the keep-alive procedure\n"
        purple "access http://keep.${USERNAME}.serv00.net/status Check the process status\n\n"
        purple "If neededTGnotify,exist${yellow}https://t.me/laowang_serv00_bot${re}${purple}GetCHAT_ID,WithCHAT_IDEnvironment variables run${re}\n\n"
        quick_command
    else
        red "\nInstallation of fully automatic keep-alive service failed,There is an unrunning process,Please execute the following command and reinstall: \n\ndevil www del ${USERNAME}.serv00.net\ndevil www del keep.${USERNAME}.serv00.net\nrm -rf $HOME/domains/*\nshopt -s extglob dotglob\nrm -rf $HOME/!(domains|mail|repo|backups)\n\n"
    fi
}

quick_command() {
  COMMAND="00"
  SCRIPT_PATH="$HOME/bin/$COMMAND"
  mkdir -p "$HOME/bin"
  echo "#!/bin/bash" > "$SCRIPT_PATH"
  echo "bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_serv00.sh)" >> "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
      echo "export PATH=\"\$HOME/bin:\$PATH\"" >> "$HOME/.bashrc"
      source "$HOME/.bashrc"
  fi
  green "Shortcut command00Created successfully,Next time you run the input00Quickly enter the menu\n"
}

get_url_info() {
  if devil www list 2>&1 | grep -q "keep.${USERNAME}.serv00.net"; then
    purple "\n-------------------Related links for keep alive------------------\n\n"
    purple "http://keep.${USERNAME}.serv00.net/stop End the process\n"
    purple "http://keep.${USERNAME}.serv00.net/list All process list\n"
    yellow "http://keep.${USERNAME}.serv00.net/start Reset the keep-alive procedure\n"
    purple "http://keep.${USERNAME}.serv00.net/status Check the process status\n\n"
  else 
    red "Automatic maintenance service has not been installed yet\n" && sleep 2 && menu
  fi
}

get_nodes(){
cat ${FILE_PATH}/list.txt
TOKEN=$(sed -n 's/^SUB_TOKEN=\(.*\)/\1/p' $HOME/domains/keep.${USERNAME}.serv00.net/public_nodejs/.env)
yellow "\nAdaptive node subscription link: https://${USERNAME}.serv00.net/${TOKEN}\nQR code and node subscription links are suitable forV2rayN/Nekoray/ShadowRocket/Clash/Sing-box/karing/Loon/sterisand wait\n"
}

menu() {
  clear
  echo ""
  purple "=== Serv00|ct8Old Kingsing-boxOne-click four-in-one installation script ===\n"
  echo -e "${green}Script address：${re}${yellow}https://github.com/eooce/Sing-box${re}\n"
  echo -e "${green}Feedback Forum：${re}${yellow}https://bbs.vps8.me${re}\n"
  echo -e "${green}TGFeedback Group：${re}${yellow}https://t.me/vps888${re}\n"
  purple "Please be famous for reprinting，Please do not abuse\n"
  yellow "Quick Start Command00\n"
  green "1. Installsing-box"
  echo  "==============="
  green "2. Installation automatically keeps active"
  echo  "==============="
  red "3. uninstallsing-box"
  echo  "==============="
  green "4. View node information"
  echo  "==============="
  green "5. Check the Keep Live Link"
  echo  "==============="
  yellow "6. Replace the node port"
  echo  "==============="
  yellow "7. Initialize the system"
  echo  "==============="
  red "0. Exit script"
  echo "==========="
  reading "Please enter a selection(0-7): " choice
  echo ""
  case "${choice}" in
      1) install_singbox ;;
      2) install_keepalive ;;
      3) uninstall_singbox ;; 
      4) get_nodes ;; 
      5) get_url_info ;;
      6) changge_ports ;;
      7) reset_system ;;
      0) exit 0 ;;
      *) red "Invalid option，Please enter 0 arrive 7" ;;
  esac
}
menu
