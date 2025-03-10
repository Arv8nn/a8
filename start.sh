#!/bin/env bash

reset="\033[0m"
bold="\033[1m"
red="\033[31m"
green="\033[32m"
yellow="\033[33m"
blue="\033[34m"
cyan="\033[36m"

yonggekkk_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/serv%201/serv00.sh"
eooce_script="https://raw.githubusercontent.com/eooce/sing-box/main/sb_serv00.sh"
socks5_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/socks5/install-socks5.sh"
mtproxy_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/mt.sh"

function yonggekkk () {
    clear
    bash <(curl -Ls "$yonggekkk_script") || echo "Error: Failed to execute script."
}

function eooce () {
    clear
    bash <(curl -Ls "$eooce_script") || echo "Error: Failed to execute script."
}

function socks5 () {
    clear
    bash <(curl -Ls "$socks5_script") || echo "Error: Failed to execute script."
}

function MTproxy () {
    clear
    bash <(curl -Ls "$mtproxy_script") || echo "Error: Failed to execute script."
}

function menu () {
    clear
    echo -e "${bold}this script made by :${reset}"
    echo -e "${bold}${cyan}"
    echo '           _______      _____  _   _ 
        /\   |  __ \ \    / / _ \| \ | |
       /  \  | |__) \ \  / / (_) |  \| |
      / /\ \ |  _  / \ \/ / > _ <| . ` |
     / ____ \| | \ \  \  / | (_) | |\  |
    /_/    \_\_|  \_\  \/   \___/|_| \_|
    '
    echo -e "$reset"
    echo -e "${bold}welcome ${green}`whoami`${reset}"
    echo "==================================================================="
    echo "==================================================================="
    echo -e "${bold}\ttranslated by ${green}ARV8N${reset}"
    echo -e "${bold}\t${blue}source${reset}${bold}= yonggekkk , eooce , mtg , cmliu${reset}"
    echo "==================================================================="
    echo "==================================================================="
    echo -e "${bold}${green}\t\t***** please select an option *****${reset}"
    echo -e "${yellow}\t1. yonggekkk serv00 script (vless , vmess , hy2 , tuic)\n"
    echo -e "\t2. eooce serv00 script (vless , vmess , hy2 , tuic)${reset}"
    echo -e "${red}\tthis script has problems whit other language so:"
    echo -e "\toption 1 for install. in the next steps just press enter"
    echo -e "\toption 2 for keepalive service"
    echo -e "\toption 3 for uninstall\n${reset}"
    echo -e "${yellow}\t3. serv00 socks5\n"
    echo -e "\t4. serv00 MTproxy\n"
    echo -e "\t5. Exit\n"
    read -p "select what you want [1-5] : " option
    echo -e "${reset}"
}
while true; do
    menu
    echo ""
    case $option in
        1) clear
            echo -e "${bold}${blue}runnig yonggekkk serv00 script${reset}"
            sleep 3
            yonggekkk
            echo -e "${bold}${red}return to menu (y | n)? 
            # read a
            # if [ a == y || a == Y ]; then
            #     continue
            # else
            #     break
            # fi 
            ;;
        2) clear
            echo -e "${bold}${blue}runnig eooce serv00 script${reset}"
            sleep 3
            eooce ;;
        3) clear
            echo -e "${bold}${blue}runnig socks5 serv00 script${reset}"
            sleep 3
            socks5 ;;
        4) clear
            echo -e "${bold}${blue}runnig MTproxy serv00 script${reset}"
            sleep 3
            MTproxy ;;
        5) echo -e "${bold}${green}exiting program${reset}"
            sleep 1
            exit ;;
        *) echo -e "${red}${bold}choose a valid option [1-5]${reset}"
            sleep 2
            break ;;
    esac
done
