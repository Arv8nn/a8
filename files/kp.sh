#!/bin/bash
# Regular settings：*/10 * * * * /bin/bash /root/kp.sh Every10Run once in minutes
# serv00Variable adding rules：
# recommend:To ensure node usability，ProposeServ00The webpage does not have a port，The script will be randomly generated，The first operation will be interruptedSSH，PleaseRESSet tonJust execute
# RES(Must -have)：nIt means that no deployment is not reset each time，yIndicates each reset deployment。SSH_USER(Must -have)expressserv00Account name。SSH_PASS(Must -have)expressserv00password。REALITYexpressrealitydomain name(留空expressserv00官方domain name：youserv00Account name.serv00.net)。SUUIDexpressuuid(留空express随机uuid)。TCP1_PORTexpressvlessoftcpport(留空express随机tcpport)。TCP2_PORTexpressvmessoftcpport(留空express随机tcpport)。UDP_PORTexpresshy2ofudpport(留空express随机udpport)。HOST(Must -have)express登录serv00服务器domain name。ARGO_DOMAINexpressargo固定domain name(留空express临时domain name)。ARGO_AUTHexpressargo固定domain nametoken(留空express临时domain name)。
# Must -fill variable：RES、SSH_USER、SSH_PASS、HOST
# Notice[]"",:Don't delete these symbols randomly，Alignment according to laws
# One line{serv00server}，A service can also，Use,interval，最后一个server末尾无需用,interval
ACCOUNTS='[
{"RES":"n", "SSH_USER":"yourserv00Account name", "SSH_PASS":"yourserv00Account password", "REALITY":"youserv00Account name.serv00.net", "SUUID":"Self -setUUID", "TCP1_PORT":"vlessoftcpport", "TCP2_PORT":"vmessoftcpport", "UDP_PORT":"hy2ofudpport", "HOST":"s1.serv00.com", "ARGO_DOMAIN":"", "ARGO_AUTH":""},
{"RES":"y", "SSH_USER":"123456", "SSH_PASS":"7890000", "REALITY":"time.is", "SUUID":"73203ee6-b3fa-4a3d-b5df-6bb2f55073ad", "TCP1_PORT":"55254", "TCP2_PORT":"55255", "UDP_PORT":"55256", "HOST":"s16.serv00.com", "ARGO_DOMAIN":"yourargoFixed domain name", "ARGO_AUTH":"eyJhIjoiOTM3YzFjYWI88552NTFiYTM4ZTY0ZDQzRmlNelF0TkRBd1pUQTRNVEJqTUdVeCJ9"}
]'
run_remote_command() {
  local RES=$1
  local SSH_USER=$2
  local SSH_PASS=$3
  local REALITY=$4
  local SUUID=$5
  local TCP1_PORT=$6
  local TCP2_PORT=$7
  local UDP_PORT=$8
  local HOST=$9
  local ARGO_DOMAIN=${10}
  local ARGO_AUTH=${11}
  if [ -z "${ARGO_DOMAIN}" ]; then
    echo "ArgoDomain name is empty，ApplyArgoTemporary domain name"
  else
    echo "ArgoA fixed domain name has been set：${ARGO_DOMAIN}"
  fi
  remote_command="export reym=$REALITY UUID=$SUUID vless_port=$TCP1_PORT vmess_port=$TCP2_PORT hy2_port=$UDP_PORT reset=$RES ARGO_DOMAIN=${ARGO_DOMAIN} ARGO_AUTH=${ARGO_AUTH} && bash <(curl -Ls https://raw.githubusercontent.com/yonggekkk/sing-box-yg/main/serv00keep.sh)"
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

echo "*******************ARV8N************************"
              count=0  
           for account in $(echo "${ACCOUNTS}" | jq -c '.[]'); do
              count=$((count+1))
              RES=$(echo $account | jq -r '.RES')
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
            echo "🎉Congratulations！✅First【$count】Taiwan server connection successfully！🚀Server address：$HOST ，Account name：$SSH_USER"   
          if [ -z "${ARGO_DOMAIN}" ]; then
           check_process="ps aux | grep '[c]onfig' > /dev/null && ps aux | grep [l]ocalhost:$TCP2_PORT > /dev/null"
            else
           check_process="ps aux | grep '[c]onfig' > /dev/null && ps aux | grep '[t]oken $ARGO_AUTH' > /dev/null"
           fi
          if ! sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_USER@$HOST" "$check_process" || [[ "$RES" =~ ^[Yy]$ ]]; then
            echo "⚠️Detect the main process orargoThe process is not started，Or execute reset"
             echo "⚠️Start repair or reset the deployment now……Please wait"
             echo "⚠️Interrupt exit，Explain that the random port is completed for the first time，PleaseRESSet tonJust execute"
             output=$(run_remote_command "$RES" "$SSH_USER" "$SSH_PASS" "${REALITY}" "$SUUID" "$TCP1_PORT" "$TCP2_PORT" "$UDP_PORT" "$HOST" "${ARGO_DOMAIN}" "${ARGO_AUTH}")
            echo "Remote command execution results：$output"
          else
            echo "🎉Congratulations！✅The normal operation of all processes was detected "
            echo "The configuration display is as follows："
          sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_USER@$HOST" \
             "cat domains/\$(whoami).serv00.net/logs/list.txt; \
              echo '===================================================='" 
            fi
           else
            echo "===================================================="
            echo "💥Cup！❌First【$count】Taiwan server connection fails！🚀Server address：$HOST ，Account name：$SSH_USER"
            echo "⚠️Possible account name、password、Server name input error，Or the current server is in maintenance"  
            echo "===================================================="
           fi
            done
