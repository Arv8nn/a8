#!/bin/bash
# Timed settings：*/10 * * * * /bin/bash /root/kp.sh Every10Run once in minutes
# serv00Variable Add Rules：
# recommend:To ensure node availability，It is recommended to beServ00The web page does not have a port，The script will randomly generate valid ports，The first run will be interruptedSSH，PleaseRESSet asnJust execute it again
# RES(Required)：nIndicates that no deployment is reset every time，yIndicates each reset deployment.REP(Required)：nIndicates that the random port is not reset(Three ports are left empty)，yIndicates resetting the port(Three ports are left empty).SSH_USER(Required)expressserv00Account name.SSH_PASS(Required)expressserv00password.REALITYexpressrealitydomain name(Leave blank to indicateserv00Official domain name：youserv00Account name.serv00.net).SUUIDexpressuuid(Leave blank to indicate randomuuid).TCP1_PORTexpressvlessoftcpport(Leave blank to indicate randomtcpport).TCP2_PORTexpressvmessoftcpport(Leave blank to indicate randomtcpport).UDP_PORTexpresshy2ofudpport(Leave blank to indicate randomudpport).HOST(Required)Indicates loginserv00Server domain name.ARGO_DOMAINexpressargoFixed domain name(Leave blank to indicate temporary domain name).ARGO_AUTHexpressargoFixed domain nametoken(Leave blank to indicate temporary domain name).
# Required variables：RES,REP,SSH_USER,SSH_PASS,HOST
# Notice[]"",:Don't delete these symbols，Align according to the rules
# One per line{serv00server}，A service is also available，Use at the end,interval，No need to use the last server at the end,interval
ACCOUNTS='[
{"RES":"n", "REP":"n", "SSH_USER":"yourserv00Account name", "SSH_PASS":"yourserv00Account Password", "REALITY":"youserv00Account name.serv00.net", "SUUID":"Set up by yourselfUUID", "TCP1_PORT":"vlessoftcpport", "TCP2_PORT":"vmessoftcpport", "UDP_PORT":"hy2ofudpport", "HOST":"s1.serv00.com", "ARGO_DOMAIN":"", "ARGO_AUTH":""},
{"RES":"y", "REP":"y", "SSH_USER":"123456", "SSH_PASS":"7890000", "REALITY":"time.is", "SUUID":"73203ee6-b3fa-4a3d-b5df-6bb2f55073ad", "TCP1_PORT":"", "TCP2_PORT":"", "UDP_PORT":"", "HOST":"s16.serv00.com", "ARGO_DOMAIN":"yourargoFixed domain name", "ARGO_AUTH":"eyJhIjoiOTM3YzFjYWI88552NTFiYTM4ZTY0ZDQzRmlNelF0TkRBd1pUQTRNVEJqTUdVeCJ9"}
]'
run_remote_command() {
local RES=$1
local REP=$2
local SSH_USER=$3
local SSH_PASS=$4
local REALITY=${5}
local SUUID=$6
local TCP1_PORT=$7
local TCP2_PORT=$8
local UDP_PORT=$9
local HOST=${10}
local ARGO_DOMAIN=${11}
local ARGO_AUTH=${12}
  if [ -z "${ARGO_DOMAIN}" ]; then
    echo "ArgoDomain name is empty，ApplyArgoTemporary domain name"
  else
    echo "ArgoFixed domain name has been set：${ARGO_DOMAIN}"
  fi
  remote_command="export reym=$REALITY UUID=$SUUID vless_port=$TCP1_PORT vmess_port=$TCP2_PORT hy2_port=$UDP_PORT reset=$RES resport=$REP ARGO_DOMAIN=${ARGO_DOMAIN} ARGO_AUTH=${ARGO_AUTH} && bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00keep.sh)"
  echo "Executing remote command on $HOST as $SSH_USER with command: $remote_command"
  sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_USER@$HOST" "$remote_command"
}
if  cat /etc/issue /proc/version /etc/os-release 2>/dev/null | grep -q -E -i "openwrt"; then
opkg update
opkg install sshpass curl jq
else
    if [ -f /etc/debian_version ]; then
        package_manager="apt-get install -y"
        apt-get update >/dev/null 2>&1
    elif [ -f /etc/redhat-release ]; then
        package_manager="yum install -y"
    elif [ -f /etc/fedora-release ]; then
        package_manager="dnf install -y"
    elif [ -f /etc/alpine-release ]; then
        package_manager="apk add"
    fi
    $package_manager sshpass curl jq cron >/dev/null 2>&1 &
fi
echo "*****************************************************"
echo "*****************************************************"
echo "Brother YongGithubproject  ：github.com/yonggekkk"
echo "Brother YongBloggerblog ：ygkkk.blogspot.com"
echo "Brother YongYouTubeChannel ：www.youtube.com/@ygkkk"
echo "Automatic remote deploymentServ00Three-in-one protocol script【VPS+Soft Routing]"
echo "Version：V25.2.26"
echo "*****************************************************"
echo "*****************************************************"
              count=0  
           for account in $(echo "${ACCOUNTS}" | jq -c '.[]'); do
              count=$((count+1))
              RES=$(echo $account | jq -r '.RES')
              REP=$(echo $account | jq -r '.REP')              
              SSH_USER=$(echo $account | jq -r '.SSH_USER')
              SSH_PASS=$(echo $account | jq -r '.SSH_PASS')
              REALITY=$(echo $account | jq -r '.REALITY')
              SUUID=$(echo $account | jq -r '.SUUID')
              TCP1_PORT=$(echo $account | jq -r '.TCP1_PORT')
              TCP2_PORT=$(echo $account | jq -r '.TCP2_PORT')
              UDP_PORT=$(echo $account | jq -r '.UDP_PORT')
              HOST=$(echo $account | jq -r '.HOST')
              ARGO_DOMAIN=$(echo $account | jq -r '.ARGO_DOMAIN')
              ARGO_AUTH=$(echo $account | jq -r '.ARGO_AUTH') 
          if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_USER@$HOST" -q exit; then
            echo "🎉Congratulations！✅Chapter 【$count】The server connection is successful！🚀Server address：$HOST ，Account name：$SSH_USER"   
          if [ -z "${ARGO_DOMAIN}" ]; then
           check_process="ps aux | grep '[c]onfig' > /dev/null && ps aux | grep [l]ocalhost:$TCP2_PORT > /dev/null"
            else
           check_process="ps aux | grep '[c]onfig' > /dev/null && ps aux | grep '[t]oken $ARGO_AUTH' > /dev/null"
           fi
          if ! sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_USER@$HOST" "$check_process" || [[ "$RES" =~ ^[Yy]$ ]]; then
            echo "⚠️The main process was detected orargoThe process has not started，Or perform a reset"
             echo "⚠️Start repairing or resetting deployment now……Please wait"
             output=$(run_remote_command "$RES" "$REP" "$SSH_USER" "$SSH_PASS" "${REALITY}" "$SUUID" "$TCP1_PORT" "$TCP2_PORT" "$UDP_PORT" "$HOST" "${ARGO_DOMAIN}" "${ARGO_AUTH}")
            echo "Remote command execution results：$output"
          else
            echo "🎉Congratulations！✅All processes are running normally "
            SSH_USER_LOWER=$(echo "$SSH_USER" | tr '[:upper:]' '[:lower:]')
            sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_USER@$HOST" "
            echo \"The configuration is displayed as follows：\"
            cat domains/${SSH_USER_LOWER}.serv00.net/logs/list.txt
            echo \"====================================================\""
            fi
           else
            echo "===================================================="
            echo "💥Cup！❌Chapter 【$count】Taiwan server connection failed！🚀Server address：$HOST ，Account name：$SSH_USER"
            echo "⚠️Possible errors in the account name, password, and server name，Or the current server is under maintenance"  
            echo "===================================================="
           fi
            done
