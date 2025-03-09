#!/bin/env bash
tput bold;tput setaf 2
echo '
____ ____ ____ _  _    _  _ ___ ___  ____ ____ _  _ _   _    ____ ____ ____
[__  |___ |__/ |  |    |\/|  |  |__] |__/ |  |  \/   \_/     |___ |  | |__/
___] |___ |  \  \/     |  |  |  |    |  \ |__| _/\_   |      |    |__| |  \
                                                                           
___ ____ _    ____ ____ ____ ____ _  _    ___  _   _    ____ ____ _  _ _  _
 |  |___ |    |___ | __ |__/ |__| |\/|    |__]  \_/     |__| |__/ |  | |\ |
 |  |___ |___ |___ |__] |  \ |  | |  |    |__]   |      |  | |  \  \/  | \|
'
tput sgr0

FILE_URL="https://github.com/9seconds/mtg/releases/download/v2.1.7/mtg-2.1.7-freebsd-amd64.tar.gz"
DIR_NAME="mtg-2.1.7-freebsd-amd64"


echo "downloading mtg file..."
wget -q $FILE_URL -O mtg.tar.gz

echo "extracting..."
tar -xzf mtg.tar.gz
cd mtg-2.1.7-freebsd-amd64


read -p "enter your host name(ex:s1.serv00.com): " host
read -p "enter your port(1025-60000): " port


secret=$(./mtg generate-secret --hex $host)

mtproto_url="https://t.me/proxy?server=${host}&port=${port}&secret=${secret}"

tput bold; tput setaf 2
echo "proxy online!"
echo "use this link to accsess proxy in telegram"
tput sgr0
echo "$mtproto_url"
tput bold; tput setaf 3
echo "wait"
tput sgr0
tput bold; tput setaf 2
echo "made by ARV8N"
echo "have fun"
tput sgr0
nohup ./mtg simple-run -n 1.1.1.1 -t 30s -a 1MB 0.0.0.0:${port} ${secret} -c 8192 > mtg.log 2>&1 &

