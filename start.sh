#!/bin/env bash

yonggekkk_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/serv%201/serv00.sh"
eooce_script="https://raw.githubusercontent.com/eooce/sing-box/main/sb_serv00.sh"
socks5_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/socks5/install-socks5.sh"
mtproxy_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/mt.sh"

function yonggekkk () {
    clear
    echo "$(tput setaf 2)runnig yonggekkk script$(tput sgr0)"
    bash <(curl -Ls "$yonggekkk_script") || echo "Error: Failed to execute script."
}

function eooce () {
    clear
    echo "$(tput setaf 2)runnig eooce script$(tput sgr0)"
    bash <(curl -Ls "$eooce_script") || echo "Error: Failed to execute script."
}

function socks5 () {
    clear
    echo "$(tput setaf 2)runnig serv00 socks5 script$(tput sgr0)"
    bash <(curl -Ls "$socks5_script") || echo "Error: Failed to execute script."
}

function MTproxy () {
    clear
    echo "$(tput setaf 2)runnig serv00 MTproxy script$(tput sgr0)"
    bash <(curl -Ls "$mtproxy_script") || echo "Error: Failed to execute script."
}

function menu () {
    clear
    echo "$(tput bold)this script made by :"
    tput sgr0
    tput bold;tput blink;tput setaf 6
    echo '           _______      _____  _   _ 
        /\   |  __ \ \    / / _ \| \ | |
       /  \  | |__) \ \  / / (_) |  \| |
      / /\ \ |  _  / \ \/ / > _ <| . ` |
     / ____ \| | \ \  \  / | (_) | |\  |
    /_/    \_\_|  \_\  \/   \___/|_| \_|
    '
    tput sgr0
    echo "$(tput bold)welcome $(tput setaf 2)`whoami`"
    tput sgr0
    echo "==================================================================="
    echo "==================================================================="
    tput bold
    echo -e "\ttranslated by $(tput setaf 2)ARV8N$(tput sgr0)"
    tput bold
    echo -e "\t$(tput setaf 4)source$(tput sgr0) $(tput bold)= yonggekkk , eooce , mtg , cmliu"
    tput sgr0
    echo "==================================================================="
    echo "==================================================================="
    tput setaf 2
    echo -e "\t\t***** please select an option *****"
    tput sgr0
    tput setaf 3
    echo -e "\t1. yonggekkk serv00 script (vless , vmess , hy2 , tuic)\n"
    echo -e "\t2. eooce serv00 script (vless , vmess , hy2 , tuic)"
    tput setaf 1
    echo -e "\tthis script has problems whit other language so:"
    echo -e "\toption 1 for install. in the next steps just press enter"
    echo -e "\toption 2 for keepalive script"
    echo -e "\tfor uninstall select option 3\n"
    tput setaf 3 
    echo -e "\t3. serv00 socks5\n"
    echo -e "\t4. serv00 MTproxy\n"
    echo -e "\t5. Exit\n"
    read -p "select what you want [1-5] : " option
    tput sgr0
}
while true; do
    menu
    echo ""
    case $option in
        1) yonggekkk ;;
        2) eooce ;;
        3) socks5 ;;
        4) MTproxy ;;
        5) exit ;;
        *) echo "choose a valid option [5 for Exit]"
    esac
done
