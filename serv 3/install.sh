#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cd ~
cur_dir=$(pwd)

uname_output=$(uname -a)

# check os
if echo "$uname_output" | grep -Eqi "freebsd"; then
    release="freebsd"
else
    echo -e "${red}The system version is not detected，Please contact the script author！${plain}\n" && exit 1
fi

arch="none"

if echo "$uname_output" | grep -Eqi 'x86_64|amd64|x64'; then
    arch="amd64"
elif echo "$uname_output" | grep -Eqi 'aarch64|arm64'; then
    arch="arm64"
else
    arch="amd64"
    echo -e "${red}The detection architecture failed，Use the default architecture: ${arch}${plain}"
fi

echo "Architecture: ${arch}"

#This function will be called when user installed x-ui out of sercurity
config_after_install() {
    echo -e "${yellow}Out of security considerations，Install/After the update is completed, you need to mandate the port and the account password${plain}"
    read -p "Confirm whether it continues?[y/n]": config_confirm
    if [[ x"${config_confirm}" == x"y" || x"${config_confirm}" == x"Y" ]]; then
        read -p "Please set your account name:" config_account
        echo -e "${yellow}Your account name will be set to:${config_account}${plain}"
        read -p "Please set your account password:" config_password
        echo -e "${yellow}Your account password will be set to:${config_password}${plain}"
        read -p "Please set the panel access port:" config_port
        echo -e "${yellow}Your panel access port will be set to:${config_port}${plain}"
        read -p "Please set the panel traffic monitoring port:" config_traffic_port
        echo -e "${yellow}Your panel traffic monitoring port will be set to:${config_traffic_port}${plain}"
        echo -e "${yellow}Confirm the settings,Set${plain}"
        ./x-ui setting -username ${config_account} -password ${config_password}
        echo -e "${yellow}Account password setting is complete${plain}"
        ./x-ui setting -port ${config_port}
        echo -e "${yellow}Panel access port settings are completed${plain}"
        ./x-ui setting -trafficport ${config_traffic_port}
        echo -e "${yellow}Panel traffic monitoring port settings are completed${plain}"
    else
        echo -e "${red}Cancel,All settings items are default settings,Please modify it in time${plain}"
        echo -e "If it is a new installation，The default web port is ${green}54321${plain}，The default flow monitoring port is ${green}54322${plain}，The username and password are default ${green}admin${plain}"
        echo -e "Please make sure that this port is not occupied by other programs，${yellow}Make sure 54321 and 54322 Port has been released${plain}"
        echo -e "If you want to 54321 and 54322 Modify to other ports，enter x-ui Command to modify，Also ensure that the port you modified is also released"
    fi
}
stop_x-ui() {
    # Set the one you want to killnohupThe order name of the process
    xui_com="./x-ui run"
    xray_com="bin/xray-$release-$arch -c bin/config.json"
 
    # usepgrepFind processID
    PID=$(pgrep -f "$xray_com")
 
    # Check whether the process is found
    if [ ! -z "$PID" ]; then
        # Find the process，Kill it
        kill $PID
    
        # Optional：Check whether the process has been killed
        if kill -0 $PID > /dev/null 2>&1; then
            kill -9 $PID
        fi
    fi
    # usepgrepFind processID
    PID=$(pgrep -f "$xui_com")
 
    # Check whether the process is found
    if [ ! -z "$PID" ]; then
        # Find the process，Kill it
        kill $PID
    
        # Optional：Check whether the process has been killed
        if kill -0 $PID > /dev/null 2>&1; then
            kill -9 $PID
        fi
    fi

}

install_x-ui() {
    stop_x-ui

    if [ $# == 0 ]; then
        last_version=$(curl -Ls "https://api.github.com/repos/amclubs/am-serv00-x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        wget -N --no-check-certificate -O x-ui-${release}-${arch}.tar.gz https://github.com/amclubs/am-serv00-x-ui/releases/latest/download/x-ui-${release}-${arch}.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${red}download x-ui fail，Please make sure your server can download Github File${plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/vaxilu/x-ui/releases/latest/download/x-ui-${release}-${arch}.tar.gz"
        echo -e "Start installation x-ui v$1"
        wget -N --no-check-certificate -O x-ui-${release}-${arch}.tar.gz ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}download x-ui v$1 fail，Please make sure this version exists${plain}"
            exit 1
        fi
    fi

    if [[ -e ./x-ui/ ]]; then
        rm ./x-ui/ -rf
    fi

    tar zxvf x-ui-${release}-${arch}.tar.gz
    rm -f x-ui-${release}-${arch}.tar.gz
    cd x-ui
    chmod +x x-ui bin/xray-${release}-${arch}
    #cp -f x-ui.service /etc/systemd/system/
    cp x-ui.sh ../x-ui.sh
    chmod +x ../x-ui.sh
    chmod +x x-ui.sh
    config_after_install
    #echo -e ""
    #echo -e "If it is updated panel，Then access the panel according to your previous way"
    #echo -e ""
    crontab -l > x-ui.cron
    sed -i "" "/x-ui.log/d" x-ui.cron
    echo "0 0 * * * cd $cur_dir/x-ui && cat /dev/null > x-ui.log" >> x-ui.cron
    echo "@reboot cd $cur_dir/x-ui && nohup ./x-ui run > ./x-ui.log 2>&1 &" >> x-ui.cron
    crontab x-ui.cron
    rm x-ui.cron
    nohup ./x-ui run > ./x-ui.log 2>&1 &
    echo -e "${green}x-ui v${last_version}${plain} Complete，The panel has been started，"
    echo -e ""
    echo -e "x-ui Management script usage: "
    echo -e "----------------------------------------------"
    echo -e "/home/${USER}/x-ui.sh               - Display management menu (More functional)"
    echo -e "/home/${USER}/x-ui.sh  start        - start up x-ui panel"
    echo -e "/home/${USER}/x-ui.sh  stop         - stop x-ui panel"
    echo -e "/home/${USER}/x-ui.sh  restart      - Restart x-ui panel"
    echo -e "/home/${USER}/x-ui.sh  status       - Check x-ui state"
    echo -e "/home/${USER}/x-ui.sh  enable       - set up x-ui Start self -starting"
    echo -e "/home/${USER}/x-ui.sh  disable      - Cancel x-ui Start self -starting"
    echo -e "/home/${USER}/x-ui.sh  update       - renew x-ui panel"
    echo -e "/home/${USER}/x-ui.sh  install      - Install x-ui panel"
    echo -e "/home/${USER}/x-ui.sh  uninstall    - uninstall x-ui panel"
    echo -e "----------------------------------------------"
}

echo -e "${green}Start installation${plain}"
#install_base
install_x-ui $1
