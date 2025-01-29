#!/bin/bash 

# This version has no Nezha，Only keep the node,Put this filevps，After filling in the following server configurationbash keep.shJust run
# If you need to run on the Qinglong panel，Note or delete this file35to74OK,Keep the middle of the middle56OK
# TelegramMessage reminder configuration(Optional，You don't need to leave empty)
TG_CHAT_ID="12345678"                        # Replace it with youTG chat_id
TG_BOT_TOKEN=""                              # Replace it with youTGrobottoken

# The following configuration does not need to be empty or defaults to the default
export UUID=${UUID:-'bc97f674-c578-4940-9234-0a1da46041b0'}  # UUID
export CFIP=${CFIP:-'www.visa.com.tw'}       # Preferred domain name or preferredip
export CFPORT=${CFIPPORT:-'443'}             # Preferred domain name or preferredipCorresponding port
export SUB_TOKEN=${SUB_TOKEN:-'sub'}         # subscriptiontoken

# serv00orct8Server and port configuration,Please fill in in the following format,Each variable is separated by the colon in an English input method
declare -A servers=(  # account:password:tcpport:udp1port:udp2port:argodomain name:Argotunneljsonortoken 
    ["s0.serv00.com"]='abcd:abd12345678:1234:2345:3455:s0.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s1.serv00.com"]='abcd:dbc12345678:1234:2345:3455:s1.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s2.serv00.com"]='abcd:avd12345678:1234:2345:3455:s2.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s3.serv00.com"]='abcd:dss12345678:1234:2345:3455:s3.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PfRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s4.serv00.com"]='abcd:sds12345678:1234:2345:3455:s4.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s5.serv00.com"]='abcd:dsd12345678:1234:2345:3455:s5.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s6.serv00.com"]='abcd:dsd12345678:1234:2345:3455:s6.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s7.serv00.com"]='abcd:dsd12345678:1234:2345:3455:s7.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s8.serv00.com"]='abcd:dss12345678:1234:2345:3455:s8.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    # Add more server......
)

# Define color
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }

export TERM=xterm
export DEBIAN_FRONTEND=noninteractive
install_packages() {
    if [ -f /etc/debian_version ]; then
        package_manager="apt-get install -y"
    elif [ -f /etc/redhat-release ]; then
        package_manager="yum install -y"
    elif [ -f /etc/fedora-release ]; then
        package_manager="dnf install -y"
    elif [ -f /etc/alpine-release ]; then
        package_manager="apk add"
    else
        red "Unwilling system architecture！"
        exit 1
    fi
    $package_manager sshpass curl netcat-openbsd jq cron >/dev/null 2>&1 &
}
install_packages
clear

# End the residue process of the last operation（Exclude the current process）
bash -c 'ps aux | grep -E "/bin/bash /root/keep.sh|sshpass|ssh|curl" | grep -v "pts/" | awk "\$2 != \"'$$'\" {print \$2}" | xargs kill -9 > /dev/null 2>&1' >/dev/null 2>&1 &

# Add timing task
add_cron_job() {
    if [ -f /etc/alpine-release ]; then
        if ! command -v crond >/dev/null 2>&1; then
            apk add --no-cache cronie bash >/dev/null 2>&1 &
            rc-update add crond && rc-service crond start
        fi
    fi
    # Check whether the timing task already exists
    if ! crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
        (crontab -l 2>/dev/null; echo "*/2 * * * * /bin/bash $SCRIPT_PATH >> /root/keep_00.log 2>&1") | crontab -
        green "Planning task has been added，Execute every two minutes"
    else
        purple "The planned task already exists，Skip the additional plan task"
    fi
}
add_cron_job

# examine TCP Whether the port is unobstructed
check_tcp_port() {
    local host=$1
    local port=$2
    nc -z -w 3 "$host" "$port" &> /dev/null
    return $?
}

# examine Argo Whether the tunnel is online
check_argo_tunnel() {
    local argo_domain=$1
    if [ -z "$argo_domain" ]; then
        return 1
    else
        http_code=$(curl -o /dev/null -s -w "%{http_code}\n" "https://$argo_domain")
        if [ "$http_code" -eq 404 ]; then
            return 0
        else
            return 1
        fi
    fi
}

# Send reminder messageTG
send_telegram_message() {
    local message="$1"
    if [ -n "$TG_BOT_TOKEN" ] && [ -n "$TG_CHAT_ID" ]; then
        curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" \
            -d "chat_id=$TG_CHAT_ID" \
            -d "text=$message" \
            -d "parse_mode=HTML" > /dev/null
    fi
}

# Execute remote commands
run_remote_command() {
    local host=$1
    local ssh_user=$2
    local ssh_pass=$3
    local tcp_port=$4
    local udp1_port=$5
    local udp2_port=$6
    local argo_domain=${7}
    local argo_auth=${8}

    remote_command="SUB_TOKEN=$SUB_TOKEN UUID=$UUID ARGO_DOMAIN=$argo_domain ARGO_AUTH='$argo_auth' CFIP=$CFIP CFPORT=$CFPORT bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_00.sh)"
    
    sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=60 "$ssh_user@$host" "$remote_command"
}

# if3Sub -test failed，Send a message toTG，connect SSH And execute remote commands
connect_ssh() {
    if [ $tcp_attempt -ge 3 ] || [ $argo_attempt -ge 3 ]; then
        local alert_message="⚠️ Serv00Abnormal alert

📅 time: $time
👤 Account: $ssh_user
🖥️ server: $host"

        if [ $tcp_attempt -ge 3 ]; then
            alert_message="$alert_message
❌ DetectTCPport $tcp_port Unprepared"
        fi
        if [ $argo_attempt -ge 3 ]; then
            alert_message="$alert_message
❌ DetectArgotunnel $argo_domain Line"
        fi

        # Send an alarm message
        send_telegram_message "$alert_message"
        
        yellow "$time Multiple test failure，Try to passSSHConnect and remotely execute commands  server: $host  Account: $ssh_user"
        
        ssh_output=$(sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=60 "$ssh_user@$host" -q exit 2>&1)
        
        # Check whether the account is blocked
        if echo "$ssh_output" | grep -q "HAS BEEN BLOCKED"; then
            red "$time  The account has been banned server: $host  Account: $ssh_user"
            # Send an account ban reminder reminder
            send_telegram_message "🚫 The account has been blocked

👤 Account: $ssh_user
🖥️ server: $host
⚠️ Please remove as soon as possiblekeepAccount banned in the file"
            return 0
        fi

        # examine SSH Whether the connection is successful
        if [ $? -eq 0 ]; then
            green "$time  SSHRemote connection successfully server: $host  Account : $ssh_user"
            output=$(run_remote_command "$host" "$ssh_user" "$ssh_pass" "$tcp_port" "$udp1_port" "$udp2_port" "$argo_domain" "$argo_auth")
            yellow "Remote command execution results：\n"
            echo "$output"

            # Send service recovery message
            send_telegram_message "✅ Serv00The service has been restored

👤 Account: $ssh_user
🖥️ server: $host
📡 Node subscription：
V2rayN: https://$ssh_user.serv00.net/${SUB_TOKEN}_v2.log
Clash: https://$ssh_user.serv00.net/get_sub.php?file=${SUB_TOKEN}_clash.yaml
Sing-box: https://$ssh_user.serv00.net/get_sub.php?file=${SUB_TOKEN}_singbox.yaml"
            return 0
        else
            red "$time  Failed to connect，Please check your account password server: $host  Account: $ssh_user"
            # Notice of sending failure
            send_telegram_message "❌ SSHFailed to connect

👤 Account: $ssh_user
🖥️ server: $host
⚠️ Please check your account password"
            return 0
        fi
    fi
}

# Circulation of the server list detection
for host in "${!servers[@]}"; do
    IFS=':' read -r ssh_user ssh_pass tcp_port udp1_port udp2_port argo_domain argo_auth <<< "${servers[$host]}"

    tcp_attempt=0
    argo_attempt=0
    max_attempts=3
    time=$(TZ="Asia/Hong_Kong" date +"%Y-%m-%d %H:%M")

    # examine TCP port
    while [ $tcp_attempt -lt $max_attempts ]; do
        if check_tcp_port "$host" "$tcp_port"; then
            green "$time  TCPport${tcp_port}unobstructed server: $host  Account: $ssh_user"
            tcp_attempt=0
            break
        else
            red "$time  TCPport${tcp_port}Unprepared server: $host  Account: $ssh_user"
            sleep 5
            tcp_attempt=$((tcp_attempt+1))
            connect_ssh
        fi
    done

    # # examine Argo tunnel
    while [ $argo_attempt -lt $max_attempts ]; do
        if check_argo_tunnel "$argo_domain"; then
            green "$time  Argo Tunnel online Argodomain name: $argo_domain   Account: $ssh_user\n"
            argo_attempt=0
            break
        else
            red "$time  Argo Tunnel offline Argodomain name: $argo_domain   Account: $ssh_user"
            sleep 5
            argo_attempt=$((argo_attempt+1))
            connect_ssh
        fi
    done
   
done
