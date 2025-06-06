#!/bin/bash
# Put this file invps，After filling in the following server configurationbash keep_00.shJust run,If you need to run it on the Qinglong panel，Comment or delete the31to76OK,Keep the middle58OK
# Please put Nezha panel onagentName with：S1,S2,S3,S4....Form naming, Can also be modified112Caps in the lineSFor other prefixes
SCRIPT_PATH="/root/keep_00.sh"                  # Script path
NEZHA_URL="http://nezha.abcgefg.com"            # Nezha Panel Address 
API_TOKEN="RtzwTHlXjG2RXHaVW5JUBMcO2DR9OI123"   # Nezha Panelapi token

# TelegramMessage reminder configuration(Optional，No need to leave empty)
TG_CHAT_ID="12345678"                        # Replace with yoursTG chat_id
TG_BOT_TOKEN=""                              # Replace with yoursTGrobottoken
# The following configurations are not required to be left blank or left to default
export UUID=${UUID:-'bc97f674-c578-4940-9234-0a1da46041b0'}  # UUID
export CFIP=${CFIP:-'www.visa.com.tw'}       # Preferred domain name or preferredip
export CFPORT=${CFIPPORT:-'443'}             # Preferred domain name or preferredipCorresponding port
export SUB_TOKEN=${SUB_TOKEN:-${UUID:0:8}}   # subscriptiontoken

# serv00orct8Server and port configuration,Please fill in the following format,Each variable is separated by a colon in English input state
declare -A servers=(  # account:password:tcpport:udp1port:udp2port:Nezha client domain name:Nezhaagentport:Nezha Key:argodomain name:Argotunneljsonortoken 
    ["s0.serv00.com"]='abcd:abd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s0.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s1.serv00.com"]='abcd:dbc12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s1.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s2.serv00.com"]='abcd:avd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s2.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s3.serv00.com"]='abcd:dss12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s3.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PfRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s4.serv00.com"]='abcd:sds12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s4.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s5.serv00.com"]='abcd:dsd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s5.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s6.serv00.com"]='abcd:dsd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s6.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s7.serv00.com"]='abcd:dsd12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s7.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    ["s8.serv00.com"]='abcd:dss12345678:1234:2345:3455:nezha.abcd.com:5555:c234dfddsddd:s8.2go.com:{"AccountTag":"8b9724080e55e70370fb74287922f31b","TunnelSecret":"C+OA5/LjJz9UHZ0vOkCC5PVRkvXiPhrWNcnxJBrfTPc=","TunnelID":"28125b91-34309-44d2-94be-b5e718944dad"}'
    # Add more servers......
)

# Define the color
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
        red "Unsupported system architecture！"
        exit 1
    fi
    $package_manager sshpass curl netcat-openbsd jq cron >/dev/null 2>&1 &
}
install_packages
clear

# End the residual process that was last run（Exclude the current process）
bash -c 'ps aux | grep -E "/bin/bash /root/keep.sh|sshpass|ssh|curl" | grep -v "pts/" | awk "\$2 != \"'$$'\" {print \$2}" | xargs kill -9 > /dev/null 2>&1' >/dev/null 2>&1 &

# Add timed tasks
add_cron_job() {
    if [ -f /etc/alpine-release ]; then
        if ! command -v crond >/dev/null 2>&1; then
            apk add --no-cache cronie bash >/dev/null 2>&1 &
            rc-update add crond && rc-service crond start
        fi
    fi
    # Check if the timing task already exists
    if ! crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
        (crontab -l 2>/dev/null; echo "*/2 * * * * /bin/bash $SCRIPT_PATH >> /root/keep.log 2>&1") | crontab -
        green "Scheduled tasks added，Perform every two minutes"
    else
        purple "The planned task already exists，Skip to add scheduled tasks"
    fi
}
add_cron_job

# examine TCP Is the port smooth?
check_tcp_port() {
    local host=$1
    local port=$2
    nc -z -w 3 "$host" "$port" &> /dev/null
    return $?
}

# examine Argo Is the tunnel online?
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

# Check Nezha agent Is it online or not
check_nezha_agent() {
    NEZHA_API="$NEZHA_URL/api/v1/server/list"
    response=$(curl -s -H "Authorization: $API_TOKEN" "$NEZHA_API")
    
    if [ $? -ne 0 ]; then
        red "Request failed，Please check your NezhaURLorapi_token"
        return 1
    fi
    
    local current_time=$(date +%s)
    local target_agent="S${1}"
    local agent_found=false
    local agent_online=false

    while read -r server; do
        server_name=$(echo "$server" | jq -r '.name')
        last_active=$(echo "$server" | jq -r '.last_active')

        if [[ $server_name == $target_agent ]]; then
            agent_found=true
            if [ $(( current_time - last_active )) -le 30 ]; then
                agent_online=true
                break
            fi
        fi
    done < <(echo "$response" | jq -c '.result[]')

    if ! $agent_found; then
        red "not found agent: $target_agent"
        return 1
    elif $agent_online; then
        return 0
    else
        return 1
    fi
}

# Send a reminder message toTG
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
    local nezha_server=$7
    local nezha_port=$8
    local nezha_key=$9
    local argo_domain=${10}
    local argo_auth=${11}

    remote_command="SUB_TOKEN=$SUB_TOKEN UUID=$UUID NEZHA_SERVER=$nezha_server NEZHA_PORT=$nezha_port NEZHA_KEY=$nezha_key ARGO_DOMAIN=$argo_domain ARGO_AUTH='$argo_auth' CFIP=$CFIP CFPORT=$CFPORT bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_00.sh)"
    
    sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=60 "$ssh_user@$host" "$remote_command"
}

# if3The test failed，Send a message toTG，connect SSH and execute remote commands
connect_ssh() {
    if [ $tcp_attempt -ge 3 ] || [ $argo_attempt -ge 3 ] || [ $nezha_attempt -ge 3 ]; then
        # Build an alarm message
        local alert_message="⚠️ Serv00Exception alarm

📅 time: $time
👤 Account: $ssh_user
🖥️ server: $host"

        if [ $tcp_attempt -ge 3 ]; then
            alert_message="$alert_message
❌ DetectedTCPport $tcp_port Not working"
        fi
        if [ $argo_attempt -ge 3 ]; then
            alert_message="$alert_message
❌ DetectedArgotunnel $argo_domain Offline"
        fi
        if [ $nezha_attempt -ge 3 ]; then
            alert_message="$alert_message
❌ Nezha was detectedAgentOffline"
        fi

        # Send an alarm message
        send_telegram_message "$alert_message"
        
        yellow "$time Multiple tests failed，Try to passSSHConnect and execute commands remotely  server: $host  Account: $ssh_user"
        
        ssh_output=$(sshpass -p "$ssh_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=60 "$ssh_user@$host" -q exit 2>&1)
        
        # Check whether the account has been blocked
        if echo "$ssh_output" | grep -q "HAS BEEN BLOCKED"; then
            red "$time  Account has been banned server: $host  Account: $ssh_user"
            # Send account block reminder
            send_telegram_message "🚫 Account has been blocked

👤 Account: $ssh_user
🖥️ server: $host
⚠️ Please remove it as soon as possiblekeepAccount blocked in the file"
            return 0
        fi

        # examine SSH Is the connection successful?
        if [ $? -eq 0 ]; then
            green "$time  SSHRemote connection is successful server: $host  Account : $ssh_user"
            output=$(run_remote_command "$host" "$ssh_user" "$ssh_pass" "$tcp_port" "$udp1_port" "$udp2_port" "$nezha_server" "$nezha_port" "$nezha_key" "$argo_domain" "$argo_auth")
            yellow "Remote command execution results：\n"
            echo "$output"

            # Send service recovery message
            send_telegram_message "✅ Serv00Service has been restored

👤 Account: $ssh_user
🖥️ server: $host
📡 Adaptive node subscription link：
https://${ssh_user}.serv00.net/${SUB_TOKEN}"
            return 0
        else
            red "$time  Connection failed，Please check your account password server: $host  Account: $ssh_user"
            # Send a failure notification
            send_telegram_message "❌ SSHConnection failed

👤 Account: $ssh_user
🖥️ server: $host
⚠️ Please check your account password"
            return 0
        fi
    fi
}


# Looping through server list detection
for host in "${!servers[@]}"; do
    IFS=':' read -r ssh_user ssh_pass tcp_port udp1_port udp2_port nezha_server nezha_port nezha_key argo_domain argo_auth <<< "${servers[$host]}"

    nezha_agent_name=${host%%.*}
    nezha_index=${nezha_agent_name:1}

    tcp_attempt=0
    argo_attempt=0
    nezha_attempt=0
    max_attempts=3
    time=$(TZ="Asia/Hong_Kong" date +"%Y-%m-%d %H:%M")

    # examine Nezha agent
    while [ $nezha_attempt -lt $max_attempts ]; do
        if check_nezha_agent "$nezha_index"; then
            green "$time  Nezha agentOnline server: $host  Account: $ssh_user"
            nezha_attempt=0
            break
        else
            red "$time  Nezha agentOffline server: $host  Account: $ssh_user"
            sleep 5
            nezha_attempt=$((nezha_attempt+1))
            connect_ssh
        fi
    done

    # examine TCP port
    while [ $tcp_attempt -lt $max_attempts ]; do
        if check_tcp_port "$host" "$tcp_port"; then
            green "$time  TCPport${tcp_port}unobstructed server: $host  Account: $ssh_user"
            tcp_attempt=0
            break
        else
            red "$time  TCPport${tcp_port}Not working server: $host  Account: $ssh_user"
            sleep 5
            tcp_attempt=$((tcp_attempt+1))
            connect_ssh
        fi
    done

    # # examine Argo tunnel
    while [ $argo_attempt -lt $max_attempts ]; do
        if check_argo_tunnel "$argo_domain"; then
            green "$time  Argo Tunnel Online Argodomain name: $argo_domain   Account: $ssh_user\n"
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
