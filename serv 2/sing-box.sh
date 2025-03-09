#!/bin/bash

# Define the color
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skybule="\e[1;36m"
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# Define constants
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
export vless_port=${PORT:-$(shuf -i 1000-65000 -n 1)}
export CFIP=${CFIP:-'www.visa.com.tw'} 
export CFPORT=${CFPORT:-'443'} 

# Check if it isrootRun down
[[ $EUID -ne 0 ]] && red "PleaserootRun the script under the user" && exit 1

# examine sing-box Is it installed
check_singbox() {
if [ -f "${work_dir}/${server_name}" ]; then
    if [ -f /etc/alpine-release ]; then
        rc-service sing-box status | grep -q "started" && green "running" && return 0 || yellow "not running" && return 1
    else 
        [ "$(systemctl is-active sing-box)" = "active" ] && green "running" && return 0 || yellow "not running" && return 1
    fi
else
    red "not installed"
    return 2
fi
}

# examine argo Is it installed
check_argo() {
if [ -f "${work_dir}/argo" ]; then
    if [ -f /etc/alpine-release ]; then
        rc-service argo status | grep -q "started" && green "running" && return 0 || yellow "not running" && return 1
    else 
        [ "$(systemctl is-active argo)" = "active" ] && green "running" && return 0 || yellow "not running" && return 1
    fi
else
    red "not installed"
    return 2
fi
}

# examine nginx Is it installed
check_nginx() {
if command -v nginx &>/dev/null; then
    if [ -f /etc/alpine-release ]; then
        rc-service nginx status | grep -q "stoped" && yellow "not running" && return 1 || green "running" && return 0
    else 
        [ "$(systemctl is-active nginx)" = "active" ] && green "running" && return 0 || yellow "not running" && return 1
    fi
else
    red "not installed"
    return 2
fi
}

#Install and uninstall dependencies according to system type
manage_packages() {
    if [ $# -lt 2 ]; then
        red "Unspecified package name or action" 
        return 1
    fi

    action=$1
    shift

    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command -v "$package" &>/dev/null; then
                green "${package} already installed"
                continue
            fi
            yellow "Installing ${package}..."
            if command -v apt &>/dev/null; then
                apt install -y "$package"
            elif command -v dnf &>/dev/null; then
                dnf install -y "$package"
            elif command -v yum &>/dev/null; then
                yum install -y "$package"
            elif command -v apk &>/dev/null; then
                apk update
                apk add "$package"
            else
                red "Unknown system!"
                return 1
            fi
        elif [ "$action" == "uninstall" ]; then
            if ! command -v "$package" &>/dev/null; then
                yellow "${package} is not installed"
                continue
            fi
            yellow "Uninstalling ${package}..."
            if command -v apt &>/dev/null; then
                apt remove -y "$package" && apt autoremove -y
            elif command -v dnf &>/dev/null; then
                dnf remove -y "$package" && dnf autoremove -y
            elif command -v yum &>/dev/null; then
                yum remove -y "$package" && yum autoremove -y
            elif command -v apk &>/dev/null; then
                apk del "$package"
            else
                red "Unknown system!"
                return 1
            fi
        else
            red "Unknown action: $action"
            return 1
        fi
    done

    return 0
}

# Getip
get_realip() {
  ip=$(curl -s --max-time 2 ipv4.ip.sb)
  if [ -z "$ip" ]; then
      ipv6=$(curl -s --max-time 1 ipv6.ip.sb)
      echo "[$ipv6]"
  else
      if echo "$(curl -s http://ipinfo.io/org)" | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then
          ipv6=$(curl -s --max-time 1 ipv6.ip.sb)
          echo "[$ipv6]"
      else
          echo "$ip"
      fi
  fi
}

# Download and install sing-box,cloudflared
install_singbox() {
    clear
    purple "Installingsing-boxmiddle，Please wait..."
    # Judge system architecture
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) red "Unsupported architectures: ${ARCH_RAW}"; exit 1 ;;
    esac

    # downloadsing-box,cloudflared
    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    # latest_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name | sub("^v"; "")')
    # curl -sLo "${work_dir}/${server_name}.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-${ARCH}.tar.gz"
    # curl -sLo "${work_dir}/qrencode" "https://github.com/eooce/test/releases/download/${ARCH}/qrencode-linux-${ARCH}"
    curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    # tar -xzvf "${work_dir}/${server_name}.tar.gz" -C "${work_dir}/" && \
    # mv "${work_dir}/sing-box-${latest_version}-linux-${ARCH}/sing-box" "${work_dir}/" && \
    # rm -rf "${work_dir}/${server_name}.tar.gz" "${work_dir}/sing-box-${latest_version}-linux-${ARCH}"
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo ${work_dir}/qrencode

   # Generate random ports and passwords
    nginx_port=$(($vless_port + 1)) 
    tuic_port=$(($vless_port + 2))
    hy2_port=$(($vless_port + 3)) 
    uuid=$(cat /proc/sys/kernel/random/uuid)
    password=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 24)
    output=$(/etc/sing-box/sing-box generate reality-keypair)
    private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')

    iptables -F > /dev/null 2>&1 && iptables -P INPUT ACCEPT > /dev/null 2>&1 && iptables -P FORWARD ACCEPT > /dev/null 2>&1 && iptables -P OUTPUT ACCEPT > /dev/null 2>&1
    command -v ip6tables &> /dev/null && ip6tables -F > /dev/null 2>&1 && ip6tables -P INPUT ACCEPT > /dev/null 2>&1 && ip6tables -P FORWARD ACCEPT > /dev/null 2>&1 && ip6tables -P OUTPUT ACCEPT > /dev/null 2>&1
    
    manage_packages uninstall ufw firewalld > /dev/null 2>&1

    # Generate a self-signed certificate
    openssl ecparam -genkey -name prime256v1 -out "${work_dir}/private.key"
    openssl req -new -x509 -days 3650 -key "${work_dir}/private.key" -out "${work_dir}/cert.pem" -subj "/CN=bing.com"

   # Generate configuration files
cat > "${config_dir}" << EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "output": "$work_dir/sb.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "google",
        "address": "tls://8.8.8.8"
      }
    ]
  },
  "inbounds": [
    {
        "tag": "vless-reality-vesion",
        "type": "vless",
        "listen": "::",
        "listen_port": $vless_port,
        "users": [
            {
              "uuid": "$uuid",
              "flow": "xtls-rprx-vision"
            }
        ],
        "tls": {
            "enabled": true,
            "server_name": "www.iij.ad.jp",
            "reality": {
                "enabled": true,
                "handshake": {
                    "server": "www.iij.ad.jp",
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
        "tag": "vmess-ws",
        "type": "vmess",
        "listen": "::",
        "listen_port": 8001,
        "users": [
        {
            "uuid": "$uuid"
        }
    ],
    "transport": {
        "type": "ws",
        "path": "/vmess-argo",
        "early_data_header_name": "Sec-WebSocket-Protocol"
        }
    },
    {
        "tag": "hysteria2",
        "type": "hysteria2",
        "listen": "::",
        "listen_port": $hy2_port,
        "sniff": true,
        "sniff_override_destination": false,
        "users": [
            {
                "password": "$uuid"
            }
        ],
        "ignore_client_bandwidth":false,
        "masquerade": "https://bing.com",
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "min_version":"1.3",
            "max_version":"1.3",
            "certificate_path": "$work_dir/cert.pem",
            "key_path": "$work_dir/private.key"
        }

    },
    {
        "tag": "tuic",
        "type": "tuic",
        "listen": "::",
        "listen_port": $tuic_port,
        "users": [
          {
            "uuid": "$uuid",
            "password": "$password"
          }
        ],
        "congestion_control": "bbr",
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/private.key"
       }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "direct",
      "tag": "direct-ipv4-prefer-out",
      "domain_strategy": "prefer_ipv4"
    },
    {
      "type": "direct",
      "tag": "direct-ipv4-only-out",
      "domain_strategy": "ipv4_only"
    },
    {
      "type": "direct",
      "tag": "direct-ipv6-prefer-out",
      "domain_strategy": "prefer_ipv6"
    },
    {
      "type": "direct",
      "tag": "direct-ipv6-only-out",
      "domain_strategy": "ipv6_only"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "engage.cloudflareclient.com",
      "server_port": 2408,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:812a:4929:7d2a:af62:351c/128"
      ],
      "private_key": "gBthRjevHDGyV0KvYwYE52NIPy29sSrVr6rcQtYNcXA=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [
        6,
        146,
        6
      ]
    },
    {
      "type": "direct",
      "tag": "wireguard-ipv4-prefer-out",
      "detour": "wireguard-out",
      "domain_strategy": "prefer_ipv4"
    },
    {
      "type": "direct",
      "tag": "wireguard-ipv4-only-out",
      "detour": "wireguard-out",
      "domain_strategy": "ipv4_only"
    },
    {
      "type": "direct",
      "tag": "wireguard-ipv6-prefer-out",
      "detour": "wireguard-out",
      "domain_strategy": "prefer_ipv6"
    },
    {
      "type": "direct",
      "tag": "wireguard-ipv6-only-out",
      "detour": "wireguard-out",
      "domain_strategy": "ipv6_only"
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
        "update_interval": "1d"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-netflix"
        ],
        "outbound": "wireguard-ipv6-only-out"
      },
      {
        "domain": [
          "api.statsig.com",
          "browser-intake-datadoghq.com",
          "cdn.openai.com",
          "chat.openai.com",
          "auth.openai.com",
          "chat.openai.com.cdn.cloudflare.net",
          "ios.chat.openai.com",
          "o33249.ingest.sentry.io",
          "openai-api.arkoselabs.com",
          "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
          "openaicomproductionae4b.blob.core.windows.net",
          "production-openaicom-storage.azureedge.net",
          "static.cloudflareinsights.com"
        ],
        "domain_suffix": [
          ".algolia.net",
          ".auth0.com",
          ".chatgpt.com",
          ".challenges.cloudflare.com",
          ".client-api.arkoselabs.com",
          ".events.statsigapi.net",
          ".featuregates.org",
          ".identrust.com",
          ".intercom.io",
          ".intercomcdn.com",
          ".launchdarkly.com",
          ".oaistatic.com",
          ".oaiusercontent.com",
          ".observeit.net",
          ".openai.com",
          ".openaiapi-site.azureedge.net",
          ".openaicom.imgix.net",
          ".segment.io",
          ".sentry.io",
          ".stripe.com"
        ],
        "domain_keyword": [
          "openaicom-api"
        ],
        "outbound": "wireguard-ipv6-prefer-out"
      }
    ],
    "final": "direct"
   },
   "experimental": {
      "cache_file": {
      "enabled": true,
      "path": "$work_dir/cache.db",
      "cache_id": "mycacheid",
      "store_fakeip": true
    }
  }
}
EOF
}
# debian/ubuntu/centos Daemon
main_systemd_services() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    if [ -f /etc/centos-release ]; then
        yum install -y chrony
        systemctl start chronyd
        systemctl enable chronyd
        chronyc -a makestep
        yum update -y ca-certificates
        bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    fi
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl enable argo
    systemctl start argo
}
# adaptationalpine Daemon
alpine_openrc_services() {
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run

description="sing-box service"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF

    cat > /etc/init.d/argo << 'EOF'
#!/sbin/openrc-run

description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:8001 --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF

    chmod +x /etc/init.d/sing-box
    chmod +x /etc/init.d/argo

    rc-update add sing-box default
    rc-update add argo default

}

get_info() {  
  clear
  server_ip=$(get_realip)

  isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")

  if [ -f "${work_dir}/argo.log" ]; then
      for i in {1..5}; do
          purple "The $i Try to getArgoDoaminmiddle..."
          argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
          [ -n "$argodomain" ] && break
          sleep 2
      done
  else
      restart_argo
      sleep 6
      argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
  fi

  green "\nArgoDomain：${purple}$argodomain${re}\n"

  VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2048\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"randomized\", \"allowlnsecure\": \"flase\"}"

  cat > ${work_dir}/url.txt <<EOF
vless://${uuid}@${server_ip}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=${public_key}&type=tcp&headerType=none#${isp}

vmess://$(echo "$VMESS" | base64 -w0)

hysteria2://${uuid}@${server_ip}:${hy2_port}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${isp}

tuic://${uuid}:${password}@${server_ip}:${tuic_port}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${isp}
EOF
echo ""
while IFS= read -r line; do echo -e "${purple}$line"; done < ${work_dir}/url.txt
base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
yellow "\nWarm reminder：Need to openV2rayNOr in other software “Skip certificate verification”，Or turn the node'sInsecureorTLSSet as“true”\n"
green "Node subscription link：http://${server_ip}:${nginx_port}/${password}\n\nSubscription link is applicable toV2rayN,Nekbox,Sterisand,Loon,Little Rocket,lock upXwait\n"
green "Subscribe to QR code"
$work_dir/qrencode "http://${server_ip}:${nginx_port}/${password}"
echo ""
}

# repairnginxbecausehostProblem of not installing
fix_nginx() {
    HOSTNAME=$(hostname)
    NGINX_CONFIG_FILE="/etc/nginx/nginx.conf"
    grep -q "127.0.1.1 $HOSTNAME" /etc/hosts || echo "127.0.1.1 $HOSTNAME" | tee -a /etc/hosts >/dev/null
    id -u nginx >/dev/null 2>&1 || useradd -r -d /var/www -s /sbin/nologin nginx >/dev/null 2>&1
    grep -q "^user nginx;" $NGINX_CONFIG_FILE || sed -i "s/^user .*/user nginx;/" $NGINX_CONFIG_FILE >/dev/null 2>&1
}

# nginxSubscribe to configuration
add_nginx_conf() {
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    cat > /etc/nginx/nginx.conf << EOF
# nginx_conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    server {
      listen $nginx_port;
      listen [::]:$nginx_port;

    location /$password {
      alias /etc/sing-box/sub.txt;
      default_type 'text/plain; charset=utf-8';
    }
  }
}
EOF

nginx -t > /dev/null

if [ $? -eq 0 ]; then
    if [ -f /etc/alpine-release ]; then
     	pkill -f '[n]ginx'
        touch /run/nginx.pid
        nginx -s reload
        rc-service nginx restart
    else
        rm /run/nginx.pid
        systemctl daemon-reload
        systemctl restart nginx
    fi
fi
}

# start up sing-box
start_singbox() {
if [ ${check_singbox} -eq 1 ]; then
    yellow "Starting ${server_name} Serve\n"
    if [ -f /etc/alpine-release ]; then
        rc-service sing-box start
    else
        systemctl daemon-reload
        systemctl start "${server_name}"
    fi
   if [ $? -eq 0 ]; then
       green "${server_name} The service has been started successfully\n"
   else
       red "${server_name} Service startup failed\n"
   fi
elif [ ${check_singbox} -eq 0 ]; then
    yellow "sing-box Running\n"
    sleep 1
    menu
else
    yellow "sing-box Not installed yet!\n"
    sleep 1
    menu
fi
}

# stop sing-box
stop_singbox() {
if [ ${check_singbox} -eq 0 ]; then
   yellow "Stopping ${server_name} Serve\n"
    if [ -f /etc/alpine-release ]; then
        rc-service sing-box stop
    else
        systemctl stop "${server_name}"
    fi
   if [ $? -eq 0 ]; then
       green "${server_name} Service has been successfully stopped\n"
   else
       red "${server_name} Service stop failed\n"
   fi

elif [ ${check_singbox} -eq 1 ]; then
    yellow "sing-box Not running\n"
    sleep 1
    menu
else
    yellow "sing-box Not installed yet！\n"
    sleep 1
    menu
fi
}

# Restart sing-box
restart_singbox() {
if [ ${check_singbox} -eq 0 ]; then
   yellow "Restarting ${server_name} Serve\n"
    if [ -f /etc/alpine-release ]; then
        rc-service ${server_name} restart
    else
        systemctl daemon-reload
        systemctl restart "${server_name}"
    fi
    if [ $? -eq 0 ]; then
        green "${server_name} Service has been restarted successfully\n"
    else
        red "${server_name} Service restart failed\n"
    fi
elif [ ${check_singbox} -eq 1 ]; then
    yellow "sing-box Not running\n"
    sleep 1
    menu
else
    yellow "sing-box Not installed yet！\n"
    sleep 1
    menu
fi
}

# start up argo
start_argo() {
if [ ${check_argo} -eq 1 ]; then
    yellow "Starting Argo Serve\n"
    if [ -f /etc/alpine-release ]; then
        rc-service argo start
    else
        systemctl daemon-reload
        systemctl start argo
    fi
    if [ $? -eq 0 ]; then
        green "Argo Service has been restarted successfully\n"
    else
        red "Argo Service restart failed\n"
    fi
elif [ ${check_argo} -eq 0 ]; then
    green "Argo The service is running\n"
    sleep 1
    menu
else
    yellow "Argo Not installed yet！\n"
    sleep 1
    menu
fi
}

# stop argo
stop_argo() {
if [ ${check_argo} -eq 0 ]; then
    yellow "Stopping Argo Serve\n"
    if [ -f /etc/alpine-release ]; then
        rc-service stop start
    else
        systemctl daemon-reload
        systemctl stop argo
    fi
    if [ $? -eq 0 ]; then
        green "Argo Service has been successfully stopped\n"
    else
        red "Argo Service stop failed\n"
    fi
elif [ ${check_argo} -eq 1 ]; then
    yellow "Argo The service is not running\n"
    sleep 1
    menu
else
    yellow "Argo Not installed yet！\n"
    sleep 1
    menu
fi
}

# Restart argo
restart_argo() {
if [ ${check_argo} -eq 0 ]; then
    yellow "Restarting Argo Serve\n"
    if [ -f /etc/alpine-release ]; then
        rc-service argo restart
    else
        systemctl daemon-reload
        systemctl restart argo
    fi
    if [ $? -eq 0 ]; then
        green "Argo Service has been restarted successfully\n"
    else
        red "Argo Service restart failed\n"
    fi
elif [ ${check_argo} -eq 1 ]; then
    yellow "Argo The service is not running\n"
    sleep 1
    menu
else
    yellow "Argo Not installed yet！\n"
    sleep 1
    menu
fi
}

# start up nginx
start_nginx() {
if command -v nginx &>/dev/null; then
    yellow "Starting nginx Serve\n"
    if [ -f /etc/alpine-release ]; then
        rc-service nginx start
    else
        systemctl daemon-reload
        systemctl start nginx
    fi
    if [ $? -eq 0 ]; then
        green "Nginx The service has been started successfully\n"
    else
        red "Nginx Startup failed\n"
    fi
else
    yellow "Nginx Not installed yet！\n"
    sleep 1
    menu
fi
}

# Restart nginx
restart_nginx() {
if command -v nginx &>/dev/null; then
    yellow "Restarting nginx Serve\n"
    if [ -f /etc/alpine-release ]; then
     	pkill -f '[n]ginx'
        touch /run/nginx.pid
        nginx -s reload
        rc-service nginx restart
    else
        systemctl restart nginx
    fi
    if [ $? -eq 0 ]; then
        green "Nginx Service has been restarted successfully\n"
    else
        red "Nginx Restart failed\n"
    fi
else
    yellow "Nginx Not installed yet！\n"
    sleep 1
    menu
fi
}

# uninstall sing-box
uninstall_singbox() {
   reading "Confirm to uninstall sing-box Is it? (y/n): " choice
   case "${choice}" in
       y|Y)
           yellow "Uninstalling sing-box"
           if [ -f /etc/alpine-release ]; then
                rc-service sing-box stop
                rc-service argo stop
                rm /etc/init.d/sing-box /etc/init.d/argo
                rc-update del sing-box default
                rc-update del argo default
           else
                # stop sing-boxand argo Serve
                systemctl stop "${server_name}"
                systemctl stop argo
                # Disabled sing-box Serve
                systemctl disable "${server_name}"
                systemctl disable argo

                # Reload systemd
                systemctl daemon-reload || true
            fi
           # Delete configuration files and logs
           rm -rf "${work_dir}" || true
           rm -f "${log_dir}" || true
	   rm -rf /etc/systemd/system/sing-box.service /etc/systemd/system/argo.service > /dev/null 2>&1
           
           # uninstallNginx
           reading "\nWhether to uninstall Nginx？${green}(Please enter to uninstall ${yellow}y${re} ${green}Enter will skip uninstallNginx) (y/n): ${re}" choice
            case "${choice}" in
                y|Y)
                    manage_packages uninstall nginx
                    ;;
                 *) 
                    yellow "Cancel uninstallNginx\n\n"
                    ;;
            esac

            green "\nsing-box Uninstall successfully\n\n" && exit 0
           ;;
       *)
           purple "Uninstall operation cancelled\n\n"
           ;;
   esac
}

# Create shortcuts
create_shortcut() {
  cat > "$work_dir/sb.sh" << EOF
#!/usr/bin/env bash

bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sing-box.sh) \$1
EOF
  chmod +x "$work_dir/sb.sh"
  ln -sf "$work_dir/sb.sh" /usr/bin/sb
  if [ -s /usr/bin/sb ]; then
    green "\nShortcut command sb Created successfully\n"
  else
    red "\nFailed to create a shortcut command\n"
  fi
}

# adaptationalpinerunargoReport an error user group anddnsThe problem
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# Change configuration
change_config() {
if [ ${check_singbox} -eq 0 ]; then
    clear
    echo ""
    green "1. Modify the port"
    skyblue "------------"
    green "2. ReviseUUID"
    skyblue "------------"
    green "3. ReviseRealityDisguised domain name"
    skyblue "------------"
    green "4. Add tohysteria2Port jump"
    skyblue "------------"
    green "5. deletehysteria2Port jump"
    skyblue "------------"
    purple "${purple}6. Return to main menu"
    skyblue "------------"
    reading "Please enter a selection: " choice
    case "${choice}" in
        1)
            echo ""
            green "1. Revisevless-realityport"
            skyblue "------------"
            green "2. Revisehysteria2port"
            skyblue "------------"
            green "3. Revisetuicport"
            skyblue "------------"
            purple "4. Return to the previous menu"
            skyblue "------------"
            reading "Please enter a selection: " choice
            case "${choice}" in
                1)
                    reading "\nPlease entervless-realityport (Enter skip will use random ports): " new_port
                    [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
                    sed -i '/"type": "vless"/,/listen_port/ s/"listen_port": [0-9]\+/"listen_port": '"$new_port"'/' $config_dir
                    restart_singbox
                    sed -i 's/\(vless:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
                    base64 -w0 /etc/sing-box/url.txt > /etc/sing-box/sub.txt
                    while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
                    green "\nvless-realityThe port has been modified to：${purple}$new_port${re} ${green}Please update your subscription or change it manuallyvless-realityport${re}\n"
                    ;;
                2)
                    reading "\nPlease enterhysteria2port (Enter skip will use random ports): " new_port
                    [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
                    sed -i '/"type": "hysteria2"/,/listen_port/ s/"listen_port": [0-9]\+/"listen_port": '"$new_port"'/' $config_dir
                    restart_singbox
                    sed -i 's/\(hysteria2:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
                    base64 -w0 $client_dir > /etc/sing-box/sub.txt
                    while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
                    green "\nhysteria2The port has been modified to：${purple}${new_port}${re} ${green}Please update your subscription or change it manuallyhysteria2port${re}\n"
                    ;;
                3)
                    reading "\nPlease entertuicport (Enter skip will use random ports): " new_port
                    [ -z "$new_port" ] && new_port=$(shuf -i 2000-65000 -n 1)
                    sed -i '/"type": "tuic"/,/listen_port/ s/"listen_port": [0-9]\+/"listen_port": '"$new_port"'/' $config_dir
                    restart_singbox
                    sed -i 's/\(tuic:\/\/[^@]*@[^:]*:\)[0-9]\{1,\}/\1'"$new_port"'/' $client_dir
                    base64 -w0 $client_dir > /etc/sing-box/sub.txt
                    while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
                    green "\ntuicThe port has been modified to：${purple}${new_port}${re} ${green}Please update your subscription or change it manuallytuicport${re}\n"
                    ;;
                4)  change_config ;;
                *)  red "Invalid option，Please enter 1 arrive 4" ;;
            esac
            ;;
        2)
            reading "\nPlease enter a new oneUUID: " new_uuid
            [ -z "$new_uuid" ] && new_uuid=$(cat /proc/sys/kernel/random/uuid)
            sed -i -E '
                s/"uuid": "([a-f0-9-]+)"/"uuid": "'"$new_uuid"'"/g;
                s/"uuid": "([a-f0-9-]+)"$/\"uuid\": \"'$new_uuid'\"/g;
                s/"password": "([a-f0-9-]+)"/"password": "'"$new_uuid"'"/g
            ' $config_dir

            restart_singbox
            sed -i -E 's/(vless:\/\/|hysteria2:\/\/)[^@]*(@.*)/\1'"$new_uuid"'\2/' $client_dir
            sed -i "s/tuic:\/\/[0-9a-f\-]\{36\}/tuic:\/\/$new_uuid/" /etc/sing-box/url.txt
            isp=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g')
            argodomain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' "${work_dir}/argo.log" | sed 's@https://@@')
            VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"www.visa.com.tw\", \"port\": \"443\", \"id\": \"${new_uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2048\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"\", \"allowlnsecure\": \"flase\"}"
            encoded_vmess=$(echo "$VMESS" | base64 -w0)
            sed -i -E '/vmess:\/\//{s@vmess://.*@vmess://'"$encoded_vmess"'@}' $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
            green "\nUUIDModified to：${purple}${new_uuid}${re} ${green}Please update the subscription or manually change all nodes'UUID${re}\n"
            ;;
        3)  
            clear
            green "\n1. www.joom.com\n\n2. www.stengg.com\n\n3. www.wedgehr.com\n\n4. www.cerebrium.ai\n\n5. www.nazhumi.com\n"
            reading "\nPlease enter a new oneRealityDisguised domain name(Customizable input,Enter to leave blank will use the default1): " new_sni
                if [ -z "$new_sni" ]; then    
                    new_sni="www.joom.com"
                elif [[ "$new_sni" == "1" ]]; then
                    new_sni="www.joom.com"
                elif [[ "$new_sni" == "2" ]]; then
                    new_sni="www.stengg.com"
                elif [[ "$new_sni" == "3" ]]; then
                    new_sni="www.wedgehr.com"
                elif [[ "$new_sni" == "4" ]]; then
                    new_sni="www.cerebrium.ai"
	        elif [[ "$new_sni" == "5" ]]; then
                    new_sni="www.nazhumi.com"
                else
                    new_sni="$new_sni"
                fi
                jq --arg new_sni "$new_sni" '
                (.inbounds[] | select(.type == "vless") | .tls.server_name) = $new_sni |
                (.inbounds[] | select(.type == "vless") | .tls.reality.handshake.server) = $new_sni
                ' "$config_dir" > "$config_file.tmp" && mv "$config_file.tmp" "$config_dir"
                restart_singbox
                sed -i "s/\(vless:\/\/[^\?]*\?\([^\&]*\&\)*sni=\)[^&]*/\1$new_sni/" $client_dir
                base64 -w0 $client_dir > /etc/sing-box/sub.txt
                while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
                echo ""
                green "\nReality sniModified to：${purple}${new_sni}${re} ${green}Please update your subscription or change it manuallyrealityNode'ssnidomain name${re}\n"
            ;; 
        4)  
            purple "Port jumping must ensure that the port in the jump interval is not occupied.，natPlease note the available port range，Otherwise, the node may be blocked\n"
            reading "Please enter the jump start port (Enter skip will use random ports): " min_port
            [ -z "$min_port" ] && min_port=$(shuf -i 50000-65000 -n 1)
            yellow "Your starting port is：$min_port"
            reading "\nPlease enter the jump end port (Need to be greater than the starting port): " max_port
            [ -z "$max_port" ] && max_port=$(($min_port + 100)) 
            yellow "Your end port is：$max_port\n"
            purple "Installing dependencies，And set the port jump rule，Please wait...\n"
            listen_port=$(sed -n '/"tag": "hysteria2"/,/}/s/.*"listen_port": \([0-9]*\).*/\1/p' $config_dir)
            iptables -t nat -A PREROUTING -p udp --dport $min_port:$max_port -j DNAT --to-destination :$listen_port > /dev/null
            command -v ip6tables &> /dev/null && ip6tables -t nat -A PREROUTING -p udp --dport $min_port:$max_port -j DNAT --to-destination :$listen_port > /dev/null
            if [ -f /etc/alpine-release ]; then
                iptables-save > /etc/iptables/rules.v4
                command -v ip6tables &> /dev/null && ip6tables-save > /etc/iptables/rules.v6

                cat << 'EOF' > /etc/init.d/iptables
#!/sbin/openrc-run

depend() {
    need net
}

start() {
    [ -f /etc/iptables/rules.v4 ] && iptables-restore < /etc/iptables/rules.v4
    command -v ip6tables &> /dev/null && [ -f /etc/iptables/rules.v6 ] && ip6tables-restore < /etc/iptables/rules.v6
}
EOF

                chmod +x /etc/init.d/iptables && rc-update add iptables default && /etc/init.d/iptables start
            elif [ -f /etc/debian_version ]; then
                DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent > /dev/null 2>&1 && netfilter-persistent save > /dev/null 2>&1 
                systemctl enable netfilter-persistent > /dev/null 2>&1 && systemctl start netfilter-persistent > /dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                manage_packages install iptables-services > /dev/null 2>&1 && service iptables save > /dev/null 2>&1
                systemctl enable iptables > /dev/null 2>&1 && systemctl start iptables > /dev/null 2>&1
                command -v ip6tables &> /dev/null && service ip6tables save > /dev/null 2>&1
                systemctl enable ip6tables > /dev/null 2>&1 && systemctl start ip6tables > /dev/null 2>&1
            else
                red "Unknown system,Please forward the jump port to the main port by yourself" && exit 1
            fi            
            restart_singbox
            ip=$(get_realip)
            uuid=$(sed -n 's/.*hysteria2:\/\/\([^@]*\)@.*/\1/p' $client_dir)
            line_number=$(grep -n 'hysteria2://' $client_dir | cut -d':' -f1)
            isp=$(curl -s --max-time 2 https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18}' | sed -e 's/ /_/g' || echo "vps")
            sed -i.bak "/hysteria2:/d" $client_dir
            sed -i "${line_number}i hysteria2://$uuid@$ip:$listen_port?peer=www.bing.com&insecure=1&alpn=h3&obfs=none&mport=$listen_port,$min_port-$max_port#$isp" $client_dir
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            while IFS= read -r line; do yellow "$line"; done < ${work_dir}/url.txt
            green "\nhysteria2Port jump is enabled,The jump port is：${purple}$min_port-$max_port${re} ${green}Please update the subscription or manually copy the abovehysteria2node${re}\n"
            ;;
        5)  
            iptables -t nat -F PREROUTING  > /dev/null 2>&1
            command -v ip6tables &> /dev/null && ip6tables -t nat -F PREROUTING  > /dev/null 2>&1
            if [ -f /etc/alpine-release ]; then
                rc-update del iptables default && rm -rf /etc/init.d/iptables 
            elif [ -f /etc/redhat-release ]; then
                netfilter-persistent save > /dev/null 2>&1
            elif [ -f /etc/redhat-release ]; then
                service iptables save > /dev/null 2>&1
                command -v ip6tables &> /dev/null && service ip6tables save > /dev/null 2>&1
            else
                manage_packages uninstall iptables ip6tables iptables-persistent iptables-service > /dev/null 2>&1
            fi
            sed -i '/hysteria2/s/&mport=[^#&]*//g' /etc/sing-box/url.txt
            base64 -w0 $client_dir > /etc/sing-box/sub.txt
            green "\nPort jump deleted\n"
            ;;
        6)  menu ;;
        *)  read "Invalid option！" ;; 
    esac
else
    yellow "sing-box Not installed yet！"
    sleep 1
    menu
fi
}

disable_open_sub() {
if [ ${check_singbox} -eq 0 ]; then
    clear
    echo ""
    green "1. Close node subscription"
    skyblue "------------"
    green "2. Enable node subscription"
    skyblue "------------"
    green "3. Replace the subscription port"
    skyblue "------------"
    purple "4. Return to main menu"
    skyblue "------------"
    reading "Please enter a selection: " choice
    case "${choice}" in
        1)
            if command -v nginx &>/dev/null; then
                if [ -f /etc/alpine-release ]; then
                    rc-service nginx status | grep -q "started" && rc-service nginx stop || red "nginx not running"
                else 
                    [ "$(systemctl is-active nginx)" = "active" ] && systemctl stop nginx || red "ngixn not running"
                fi
            else
                yellow "Nginx is not installed"
            fi

            green "\nNode subscription closed\n"     
            ;; 
        2)
            green "\nNode subscription enabled\n"
            server_ip=$(get_realip)
            password=$(tr -dc A-Za-z < /dev/urandom | head -c 32) 
            sed -i -E "s/(location \/)[^ ]+/\1${password//\//\\/}/" /etc/nginx/nginx.conf
	    sub_port=$(port=$(grep -E 'listen [0-9]+;' /etc/nginx/nginx.conf | awk '{print $2}' | sed 's/;//'); if [ "$port" -eq 80 ]; then echo ""; else echo "$port"; fi)
            start_nginx
            (port=$(grep -E 'listen [0-9]+;' /etc/nginx/nginx.conf | awk '{print $2}' | sed 's/;//'); if [ "$port" -eq 80 ]; then echo ""; else green "Subscription port：$port"; fi); link=$(if [ -z "$sub_port" ]; then echo "http://$server_ip/$password"; else echo "http://$server_ip:$sub_port/$password"; fi); green "\nNew node subscription link：$link\n"
            ;; 

        3)
            reading "Please enter a new subscription port(1-65535):" sub_port
            [ -z "$sub_port" ] && sub_port=$(shuf -i 2000-65000 -n 1)
            until [[ -z $(netstat -tuln | grep -w tcp | awk '{print $4}' | sed 's/.*://g' | grep -w "$sub_port") ]]; do
                if [[ -n $(netstat -tuln | grep -w tcp | awk '{print $4}' | sed 's/.*://g' | grep -w "$sub_port") ]]; then
                    echo -e "${red}${new_port}The port has been occupied by other programs，Please change the port and try again${re}"
                    reading "Please enter a new subscription port(1-65535):" sub_port
                    [[ -z $sub_port ]] && sub_port=$(shuf -i 2000-65000 -n 1)
                fi
            done
            sed -i 's/listen [0-9]\+;/listen '$sub_port';/g' /etc/nginx/nginx.conf
            path=$(sed -n 's/.*location \/\([^ ]*\).*/\1/p' /etc/nginx/nginx.conf)
            server_ip=$(get_realip)
            restart_nginx
            green "\nSubscription port replacement successfully\n"
            green "The new subscription link is：http://$server_ip:$sub_port/$path\n"
            ;; 
        4)  menu ;; 
        *)  red "Invalid option！" ;;
    esac
else
    yellow "sing-box Not installed yet！"
    sleep 1
    menu
fi
}

# singbox manage
manage_singbox() {
    green "1. start upsing-boxServe"
    skyblue "-------------------"
    green "2. stopsing-boxServe"
    skyblue "-------------------"
    green "3. Restartsing-boxServe"
    skyblue "-------------------"
    purple "4. Return to main menu"
    skyblue "------------"
    reading "\nPlease enter a selection: " choice
    case "${choice}" in
        1) start_singbox ;;  
        2) stop_singbox ;;
        3) restart_singbox ;;
        4) menu ;;
        *) red "Invalid option！" ;;
    esac
}

# Argo manage
manage_argo() {
if [ ${check_argo} -eq 2 ]; then
    yellow "Argo Not installed yet！"
    sleep 1
    menu
else
    clear
    echo ""
    green "1. start upArgoServe"
    skyblue "------------"
    green "2. stopArgoServe"
    skyblue "------------"
    green "3. RestartArgoServe"
    skyblue "------------"
    green "4. Add toArgoFixed tunnel"
    skyblue "----------------"
    green "5. Switch backArgoTemporary tunnel"
    skyblue "------------------"
    green "6. Re-acquireArgoTemporary domain name"
    skyblue "-------------------"
    purple "7. Return to main menu"
    skyblue "-----------"
    reading "\nPlease enter a selection: " choice
    case "${choice}" in
        1)  start_argo ;;
        2)  stop_argo ;; 
        3)  clear
            if [ -f /etc/alpine-release ]; then
                grep -Fq -- '--url http://localhost:8001' /etc/init.d/argo && get_quick_tunnel && change_argo_domain || { green "\nFixed tunnel is currently used,No need to obtain temporary domain names"; sleep 2; menu; }
            else
                grep -q 'ExecStart=.*--url http://localhost:8001' /etc/systemd/system/argo.service && get_quick_tunnel && change_argo_domain || { green "\nFixed tunnel is currently used,No need to obtain temporary domain names"; sleep 2; menu; }
            fi
         ;; 
        4)
            clear
            yellow "\nFixed tunnels can bejsonortoken，The fixed tunnel port is8001，Be on your owncfBackground settings\n\njsonexistfGet it from the site maintained by the guy，Get the address：${purple}https://fscarmen.cloudflare.now.cc${re}\n"
            reading "\nPlease enter yoursargodomain name: " argo_domain
            ArgoDomain=$argo_domain
            reading "\nPlease enter yoursargoKey(tokenorjson): " argo_auth
            if [[ $argo_auth =~ TunnelSecret ]]; then
                echo $argo_auth > ${work_dir}/tunnel.json
                cat > ${work_dir}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$argo_auth")
credentials-file: ${work_dir}/tunnel.json
protocol: http2
                                           
ingress:
  - hostname: $ArgoDomain
    service: http://localhost:8001
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF

                if [ -f /etc/alpine-release ]; then
                    sed -i '/^command_args=/c\command_args="-c '\''/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1'\''"' /etc/init.d/argo
                else
                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo
                sleep 1 
                change_argo_domain

            elif [[ $argo_auth =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
                if [ -f /etc/alpine-release ]; then
                    sed -i "/^command_args=/c\command_args=\"-c '/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'\"" /etc/init.d/argo
                else

                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token '$argo_auth' 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo
                sleep 1 
                change_argo_domain
            else
                yellow "You enteredargoDomain name ortokenMissing，Please re-enter"
                manage_argo            
            fi
            ;; 
        5)
            clear
            if [ -f /etc/alpine-release ]; then
                alpine_openrc_services
            else
                main_systemd_services
            fi
            get_quick_tunnel
            change_argo_domain 
            ;; 

        6)  
            if [ -f /etc/alpine-release ]; then
                if grep -Fq -- '--url http://localhost:8001' /etc/init.d/argo; then
                    get_quick_tunnel
                    change_argo_domain 
                else
                    yellow "Fixed tunnel is currently used，Unable to obtain temporary tunnel"
                    sleep 2
                    menu
                fi
            else
                if grep -q 'ExecStart=.*--url http://localhost:8001' /etc/systemd/system/argo.service; then
                    get_quick_tunnel
                    change_argo_domain 
                else
                    yellow "Fixed tunnel is currently used，Unable to obtain temporary tunnel"
                    sleep 2
                    menu
                fi
            fi 
            ;; 
        7)  menu ;; 
        *)  red "Invalid option！" ;;
    esac
fi
}

# GetargoTemporary tunnel
get_quick_tunnel() {
restart_argo
yellow "Get temporaryargoIn the domain name，Please wait...\n"
sleep 3
if [ -f /etc/sing-box/argo.log ]; then
  for i in {1..5}; do
      purple "The $i Try to getArgoDoaminmiddle..."
      get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' /etc/sing-box/argo.log)
      [ -n "$get_argodomain" ] && break
      sleep 2
  done
else
  restart_argo
  sleep 6
  get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' /etc/sing-box/argo.log)
fi
green "ArgoDomain：${purple}$get_argodomain${re}\n"
ArgoDomain=$get_argodomain
}

# renewArgoDomain to subscription
change_argo_domain() {
content=$(cat "$client_dir")
vmess_url=$(grep -o 'vmess://[^ ]*' "$client_dir")
vmess_prefix="vmess://"
encoded_vmess="${vmess_url#"$vmess_prefix"}"
decoded_vmess=$(echo "$encoded_vmess" | base64 --decode)
updated_vmess=$(echo "$decoded_vmess" | jq --arg new_domain "$ArgoDomain" '.host = $new_domain | .sni = $new_domain')
encoded_updated_vmess=$(echo "$updated_vmess" | base64 | tr -d '\n')
new_vmess_url="$vmess_prefix$encoded_updated_vmess"
new_content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
echo "$new_content" > "$client_dir"
base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
green "vmessNode updated,Update subscription or manually copy the followingvmess-argonode\n"
purple "$new_vmess_url\n" 
}

# View node information and subscription links
check_nodes() {
if [ ${check_singbox} -eq 0 ]; then
    while IFS= read -r line; do purple "${purple}$line"; done < ${work_dir}/url.txt
    server_ip=$(get_realip)
    lujing=$(sed -n 's|.*location /||p' /etc/nginx/nginx.conf | awk '{print $1}')
    sub_port=$(sed -n 's/^\s*listen \([0-9]\+\);/\1/p' /etc/nginx/nginx.conf)
    green "\nNode subscription link：http://${server_ip}:${sub_port}/${lujing}\n"
else 
    yellow "sing-box Not installed or not running,Please install or start firstsing-box"
    sleep 1
    menu
fi
}

# Main Menu
menu() {
   check_singbox &>/dev/null; check_singbox=$?
   check_nginx &>/dev/null; check_nginx=$?
   check_argo &>/dev/null; check_argo=$?
   check_singbox_status=$(check_singbox) > /dev/null 2>&1
   check_nginx_status=$(check_nginx) > /dev/null 2>&1
   check_argo_status=$(check_argo) > /dev/null 2>&1
   clear
   echo ""
   purple "=== Old Kingsing-boxOne-click installation script ===\n"
   purple "---Argo state: ${check_argo_status}"   
   purple "--Nginx state: ${check_nginx_status}"
   purple "singbox state: ${check_singbox_status}\n"
   green "1. Installsing-box"
   red "2. uninstallsing-box"
   echo "==============="
   green "3. sing-boxmanage"
   green "4. ArgoTunnel Management"
   echo  "==============="
   green  "5. View node information"
   green  "6. Modify node configuration"
   green  "7. Manage node subscriptions"
   echo  "==============="
   purple "8. sshComprehensive toolbox"
   echo  "==============="
   red "0. Exit script"
   echo "==========="
   reading "Please enter a selection(0-8): " choice
   echo ""
}

# capture Ctrl+C Signal
trap 'red "Operation cancelled"; exit' INT

# Main loop
while true; do
   menu
   case "${choice}" in
        1)  
            if [ ${check_singbox} -eq 0 ]; then
                yellow "sing-box Already installed！"
            else
                fix_nginx
                manage_packages install nginx jq tar openssl iptables coreutils
                [ -n "$(curl -s --max-time 2 ipv6.ip.sb)" ] && manage_packages install ip6tables
                install_singbox

                if [ -x "$(command -v systemctl)" ]; then
                    main_systemd_services
                elif [ -x "$(command -v rc-update)" ]; then
                    alpine_openrc_services
                    change_hosts
                    rc-service sing-box restart
                    rc-service argo restart
                else
                    echo "Unsupported init system"
                    exit 1 
                fi

                sleep 5
                get_info
                add_nginx_conf
                create_shortcut
            fi
           ;;
        2) uninstall_singbox ;;
        3) manage_singbox ;;
        4) manage_argo ;;
        5) check_nodes ;;
        6) change_config ;;
        7) disable_open_sub ;;
        8) 
           clear
           curl -fsSL https://raw.githubusercontent.com/eooce/ssh_tool/main/ssh_tool.sh -o ssh_tool.sh && chmod +x ssh_tool.sh && ./ssh_tool.sh
           ;;           
        0) exit 0 ;;
        *) red "Invalid option，Please enter 0 arrive 8" ;; 
   esac
   read -n 1 -s -r -p $'\033[1;91mPress any key to continue...\033[0m'
done
