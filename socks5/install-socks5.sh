#!/bin/bash

# Introduce information
echo -e "\e[32m
  ____   ___   ____ _  ______ ____  
 / ___| / _ \ / ___| |/ / ___| ___|  
 \___ \| | | | |   | ' /\___ \___ \ 
  ___) | |_| | |___| . \ ___) |__) |           Don't directly connect
 |____/ \___/ \____|_|\_\____/____/            No after -sales   
 Suture：cmliu Original author：RealNeoMan、k0baya、eooce , translated by ARV8N
\e[0m"

# Get the current username
USER=$(whoami)
WORKDIR="/home/${USER}/.nezha-agent"
FILE_PATH="/home/${USER}/.s5"

###################################################

socks5_config(){
# Prompt user inputsocks5Port number
read -p "Please entersocks5Port number: " SOCKS5_PORT

# Prompt that users enter the username and password
read -p "Please entersocks5username: " SOCKS5_USER

while true; do
  read -p "Please entersocks5password（Cannot include@and:）：" SOCKS5_PASS
  echo
  if [[ "$SOCKS5_PASS" == *"@"* || "$SOCKS5_PASS" == *":"* ]]; then
    echo "The password cannot be included@and:symbol，Please re -enter。"
  else
    break
  fi
done

# config.jsdocument
  cat > ${FILE_PATH}/config.json << EOF
{
  "log": {
    "access": "/dev/null",
    "error": "/dev/null",
    "loglevel": "none"
  },
  "inbounds": [
    {
      "port": "$SOCKS5_PORT",
      "protocol": "socks",
      "tag": "socks",
      "settings": {
        "auth": "password",
        "udp": false,
        "ip": "0.0.0.0",
        "userLevel": 0,
        "accounts": [
          {
            "user": "$SOCKS5_USER",
            "pass": "$SOCKS5_PASS"
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
EOF
}

install_socks5(){
  socks5_config
  if [ ! -e "${FILE_PATH}/s5" ]; then
    curl -L -sS -o "${FILE_PATH}/s5" "https://github.com/eooce/test/releases/download/freebsd/web"
  else
    read -p "socks5 Program already exists，Whether to download it again？(Y/N ReturnN)" downsocks5
    downsocks5=${downsocks5^^} # Converted to uppercase
    if [ "$downsocks5" == "Y" ]; then
      if pgrep s5 > /dev/null; then
        pkill s5
        echo "socks5 The process has been terminated"
      fi
      curl -L -sS -o "${FILE_PATH}/s5" "https://github.com/eooce/test/releases/download/freebsd/web"
    else
      echo "Existing socks5 program"
    fi
  fi

  if [ -e "${FILE_PATH}/s5" ]; then
    chmod 777 "${FILE_PATH}/s5"
    nohup ${FILE_PATH}/s5 -c ${FILE_PATH}/config.json >/dev/null 2>&1 &
	  sleep 2
    pgrep -x "s5" > /dev/null && echo -e "\e[1;32ms5 is running\e[0m" || { echo -e "\e[1;35ms5 is not running, restarting...\e[0m"; pkill -x "s5" && nohup "${FILE_PATH}/s5" -c ${FILE_PATH}/config.json >/dev/null 2>&1 & sleep 2; echo -e "\e[1;32ms5 restarted\e[0m"; }
    CURL_OUTPUT=$(curl -s 4.ipw.cn --socks5 $SOCKS5_USER:$SOCKS5_PASS@localhost:$SOCKS5_PORT)
    if [[ $CURL_OUTPUT =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "Acting successful creation，ReturnIPyes: $CURL_OUTPUT"
      SERV_DOMAIN=$CURL_OUTPUT
      # Find the folder containing the user name
      found_folders=$(find "/home/${USER}/domains" -type d -name "*${USER,,}*")
      if [ -n "$found_folders" ]; then
          if echo "$found_folders" | grep -q "serv00.net"; then
              #echo "Find 'serv00.net' Folder。"
              SERV_DOMAIN="${USER,,}.serv00.net"
          elif echo "$found_folders" | grep -q "ct8.pl"; then
              #echo "No included 'ct8.pl' Folder。"
              SERV_DOMAIN="${USER,,}.ct8.pl"
          fi
      fi

      echo "socks://${SOCKS5_USER}:${SOCKS5_PASS}@${SERV_DOMAIN}:${SOCKS5_PORT}"
    else
      echo "Agent failed to create，Please check the content you entered。"
    fi
  fi
}

download_agent() {
    echo "Choose nezha-agent Charged version："
    echo "1. release Latest version"
    echo "2. v0.20.5 Compatible version"
    read -p "Choose(Enter the latest version)：" nezhaAgentVersion
    nezhaAgentVersion=${nezhaAgentVersion:-1}
    
    # Set up the download link according to the user
    if [ "$nezhaAgentVersion" = "1" ]; then
        DOWNLOAD_LINK="https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_freebsd_amd64.zip"
    elif [ "$nezhaAgentVersion" = "2" ]; then
        DOWNLOAD_LINK="https://github.com/nezhahq/agent/releases/download/v0.20.5/nezha-agent_freebsd_amd64.zip"
    else
        echo "Input invalid,Will use the latest version"
        DOWNLOAD_LINK="https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_freebsd_amd64.zip"
    fi
    # usewgetdownload,If the download fails, do the following:
    if ! wget -qO "$ZIP_FILE" "$DOWNLOAD_LINK"; then
        echo 'mistake: Download failure! Please check your network connection or try it later。'
        return 1
    fi
    return 0
}

decompression() {
    unzip "$1" -d "$TMP_DIRECTORY"
    EXIT_CODE=$?
    if [ ${EXIT_CODE} -ne 0 ]; then
        rm -r "$TMP_DIRECTORY"
        echo "removed: $TMP_DIRECTORY"
        exit 1
    fi
}

install_agent() {
    install -m 755 ${TMP_DIRECTORY}/nezha-agent ${WORKDIR}/nezha-agent
}

generate_run_agent(){
    echo "About the three variables that need to be input next，Please pay attention："
    echo "Dashboard The site address can be written IP Can also write a domain name（Domain name is not set CDN）;But don't add http:// or https:// Equal prefix，Write directly IP or domain name；"
    echo "panel RPC Port for you Dashboard Set up for installation Agent Accessible RPC port（default 5555）；"
    echo "Agent The key needs to be added to the management panel first Agent Obtain。"
    printf "Please enter Dashboard Site address："
    read -r NZ_DASHBOARD_SERVER
    printf "Please enter the panel RPC port："
    read -r NZ_DASHBOARD_PORT
    printf "Please enter Agent Key: "
    read -r NZ_DASHBOARD_PASSWORD
    printf "Whether to open gRPC Port SSL/TLSencryption (--tls)，Please press [Y]，No need to default，Users who do not understand can return to the car and skip: "
    read -r NZ_GRPC_PROXY
    echo "${NZ_GRPC_PROXY}" | grep -qiw 'Y' && ARGS='--tls'

    if [ -z "${NZ_DASHBOARD_SERVER}" ] || [ -z "${NZ_DASHBOARD_PASSWORD}" ]; then
        echo "error! All options cannot be empty"
        return 1
        rm -rf ${WORKDIR}
        exit
    fi

    cat > ${WORKDIR}/start.sh << EOF
#!/bin/bash
pgrep -f 'nezha-agent' | xargs -r kill
cd ${WORKDIR}
TMPDIR="${WORKDIR}" exec ${WORKDIR}/nezha-agent -s ${NZ_DASHBOARD_SERVER}:${NZ_DASHBOARD_PORT} -p ${NZ_DASHBOARD_PASSWORD} --report-delay 4 --disable-auto-update --disable-force-update ${ARGS} >/dev/null 2>&1
EOF
    chmod +x ${WORKDIR}/start.sh
}

run_agent(){
    nohup ${WORKDIR}/start.sh >/dev/null 2>&1 &
    printf "nezha-agentI'm ready，Please press Enter the car to start\n"
    read
    printf "Startnezha-agent，Please wait...\n"
    sleep 3
    if pgrep -f "nezha-agent -s" > /dev/null; then
        echo "nezha-agent Have started！"
        echo "If the panel is not online，Please check whether the parameter is filled in correctly，Stop agent process，Delete the installed agent Re -installation！"
        echo "stop agent The command of the process：pgrep -f 'nezha-agent' | xargs -r kill"
        echo "Delete the installed agent Command：rm -rf ~/.nezha-agent"
    else
        rm -rf "${WORKDIR}"
        echo "nezha-agent Start failure，Please check whether the parameters are correct，And reinstall！"
    fi
}

install_nezha_agent(){
  mkdir -p ${WORKDIR}
  cd ${WORKDIR}
  TMP_DIRECTORY="$(mktemp -d)"
  ZIP_FILE="${TMP_DIRECTORY}/nezha-agent_freebsd_amd64.zip"

  # if start.sh The file does not exist，The script of the running agent is generated
  if [ ! -e "${WORKDIR}/start.sh" ]; then
    generate_run_agent
  else
    read -p "nezha-agent Configuration information already exists，Whether to reconcile？(Y/N ReturnN)" nezhaagentyn
    nezhaagentyn=${nezhaagentyn^^} # Converted to uppercase
    if [ "$nezhaagentyn" == "Y" ]; then
      generate_run_agent
    fi
  fi

  # if nezha-agent The file does not exist，Then download and decompress the proxy file，Then install
  if [ ! -e "${WORKDIR}/nezha-agent" ]; then
    download_agent
    decompression "${ZIP_FILE}"
    install_agent
  else
    read -p "nezha-agent File already exists，Whether to download the latest version again？(Y/N ReturnN)" nezhaagentd
    nezhaagentd=${nezhaagentd^^} # Converted to uppercase
    if [ "$nezhaagentd" == "Y" ]; then
      rm -rf "${ZIP_FILE}"
      if pgrep nezha-agent > /dev/null; then
        pkill nezha-agent
        echo "nezha-agent The process has been terminated"
      fi
      rm -rf "${WORKDIR}/nezha-agent"
      download_agent
      decompression "${ZIP_FILE}"
      install_agent
    fi
  fi

  # Delete the temporary directory
  rm -rf "${TMP_DIRECTORY}"

  # if start.sh File existence，Run the agent
  if [ -e "${WORKDIR}/start.sh" ]; then
      run_agent
  fi

}

########################Places where dreams start###########################

read -p "Whether to install socks5 (Y/N ReturnN): " socks5choice
socks5choice=${socks5choice^^} # Converted to uppercase
if [ "$socks5choice" == "Y" ]; then
  # examinesocks5Whether the directory exists
  if [ -d "$FILE_PATH" ]; then
    install_socks5
  else
    # createsocks5Table of contents
    echo "Be created socks5 Table of contents..."
    mkdir -p "$FILE_PATH"
    install_socks5
  fi
else
  echo "Not install socks5"
fi

read -p "Whether to install nezha-agent (Y/N ReturnN): " choice
choice=${choice^^} # Converted to uppercase
if [ "$choice" == "Y" ]; then
  echo "Install nezha-agent..."
  install_nezha_agent
else
  echo "Not install nezha-agent"
fi

read -p "Whether to add crontab Planning task of the Guardian process(Y/N ReturnN): " crontabgogogo
crontabgogogo=${crontabgogogo^^} # Converted to uppercase
if [ "$crontabgogogo" == "Y" ]; then
  echo "Add to crontab Planning task of the Guardian process"
  curl -s https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/socks5/check_cron.sh | bash
else
  echo "Not add crontab Plan task"
fi

echo "Script execution is completed。Thank you：RealNeoMan、k0baya、eooce"
