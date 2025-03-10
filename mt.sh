#!/bin/env bash

reset="\033[0m"
bold="\033[1m"
red="\033[31m"
green="\033[32m"
yellow="\033[33m"
blue="\033[34m"
cyan="\033[36m"

echo -e "${bold}${green}
____ ____ ____ _  _    _  _ ___ ___  ____ ____ _  _ _   _    ____ ____ ____
[__  |___ |__/ |  |    |\/|  |  |__] |__/ |  |  \/   \_/     |___ |  | |__/
___] |___ |  \  \/     |  |  |  |    |  \ |__| _/\_   |      |    |__| |  \
                                                                           
___ ____ _    ____ ____ ____ ____ _  _    ___  _   _    ____ ____ _  _ _  _
 |  |___ |    |___ | __ |__/ |__| |\/|    |__]  \_/     |__| |__/ |  | |\ |
 |  |___ |___ |___ |__] |  \ |  | |  |    |__]   |      |  | |  \  \/  | \|
${reset}"

FILE_URL="https://github.com/9seconds/mtg/releases/download/v2.1.7/mtg-2.1.7-freebsd-amd64.tar.gz"
DIR_NAME="mtg-2.1.7-freebsd-amd64"

echo -e "${blue}downloading mtg file...${reset}"
wget -q $FILE_URL -O mtg.tar.gz

echo -e "${blue}extracting...${reset}"
tar -xzf mtg.tar.gz
cd mtg-2.1.7-freebsd-amd64

read -p "enter your host name(ex:s1.serv00.com): " host
read -p "enter your port(1025-60000): " port

secret=$(./mtg generate-secret --hex $host)

mtproto_url="https://t.me/proxy?server=${host}&port=${port}&secret=${secret}"

echo -e "${blue}${bold}setting up service......${reset}"
nohup ./mtg simple-run -n 1.1.1.1 -t 30s -a 10MB 0.0.0.0:${port} ${secret} -c 8192 > mtg.log 2>&1 &

echo -e "${bold}${green}proxy is online${reset}"
echo -e "${bold}$mtproto_url${reset}"
echo -e "${bold}${green}use this link to accsess proxy in Telegram${reset}"
echo -e "${bold}${cyan}made by ARV8N, enjoy${reset}"
sleep 2
exit


