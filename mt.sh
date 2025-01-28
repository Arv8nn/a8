#!/bin/bash

# مشخص کردن URL فایل برای دانلود
FILE_URL="https://github.com/9seconds/mtg/releases/download/v2.1.7/mtg-2.1.7-freebsd-amd64.tar.gz"
DIR_NAME="mtg"

# دانلود فایل و استخراج آن
echo "در حال دانلود فایل mtg..."
wget -q $FILE_URL -O mtg.tar.gz

echo "در حال استخراج فایل..."
tar -xzf mtg.tar.gz
cd $DIR_NAME

# درخواست از کاربر برای وارد کردن نام هاست و پورت
read -p "لطفا نام هاست را وارد کنید: " host
read -p "لطفا پورت را وارد کنید: " port

# تولید کلید مخفی
secret=$(./mtg generate-secret --hex "$host")

# اجرای دستور mtg
echo "در حال راه‌اندازی پروکسی..."
nohup ./mtg simple-run -n 1.1.1.1 -t 30s -a 1MB 0.0.0.0:${port} ${secret} -c 8192 &

# ساخت لینک تلگرام با مقادیر متغیرها
mtproto_url="https://t.me/proxy?server=${host}.serv00.com&port=${port}&secret=${secret}"

# نمایش لینک تلگرام
echo "پروکسی با موفقیت راه‌اندازی شد!"
echo "برای دسترسی به پروکسی، از لینک زیر استفاده کنید:"
echo "$mtproto_url"
