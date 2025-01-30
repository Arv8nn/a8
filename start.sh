#!/bin/bash

clear
echo "==================================================================="
echo "==================================================================="
echo "made and translated by ARV8n"
echo "source = yonggekkk , eooce , mtg , cmliu"
echo "Please select an option:"
echo "==================================================================="
echo "==================================================================="

yonggekkk_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/serv%201/serv00.sh"
eooce_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/serv%202/sb_serv00.sh"
socks5_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/socks5/install-socks5.sh"
mtproxy_script="https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/mt.sh"

select option in \
    "yonggekkk serv00 script (vless , vmess , hy2 , tuic)" \
    "eooce serv00 script (vless , vmess , hy2 , tuic)" \
    "serv00 socks5" \
    "serv00 MTproxy" \
    "exit"
do
    case $option in
        "yonggekkk serv00 script (vless , vmess , hy2 , tuic)")
            echo "Running yonggekkk script..."
            bash <(curl -Ls "$yonggekkk_script") || echo "Error: Failed to execute script."
            ;;
        "eooce serv00 script (vless , vmess , hy2 , tuic)")
            echo "Running eooce script..."
            bash <(curl -Ls "$eooce_script") || echo "Error: Failed to execute script."
            ;;
        "serv00 socks5")
            echo "Installing socks5..."
            bash <(curl -Ls "$socks5_script") || echo "Error: Failed to execute script."
            ;;
        "serv00 MTproxy")
            echo "Installing MTproxy..."
            bash <(curl -Ls "$mtproxy_script") || echo "Error: Failed to execute script."
            ;;
        "exit")
            echo "Exiting the program"
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
done
