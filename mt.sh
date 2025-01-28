#!/bin/bash

echo "serv00 MTproxy for telegram by ARV8N"
echo "serv00 MTproxy for telegram by ARV8N"
echo "serv00 MTproxy for telegram by ARV8N"
echo "serv00 MTproxy for telegram by ARV8N"
echo "serv00 MTproxy for telegram by ARV8N"
echo "serv00 MTproxy for telegram by ARV8N"
echo "serv00 MTproxy for telegram by ARV8N"
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

#
echo "proxy online!"
echo "use this link to accsess proxy in telegram"
echo "$mtproto_url"
echo "wait"
echo "made by ARV8N"
echo "have fun"
nohup ./mtg simple-run -n 1.1.1.1 -t 30s -a 1MB 0.0.0.0:${port} ${secret} -c 8192 > mtg.log 2>&1 &

