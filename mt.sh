#!/bin/bash

# تابعی برای چک کردن دانلود کردن mtg
checkDownload() {
  # می‌توانید این تابع را برای بررسی دانلود صحیح mtg تنظیم کنید.
  # فرض می‌کنیم که از دستور curl یا wget برای دانلود استفاده می‌شود.
  curl -LO https://github.com/9seconds/mtg/releases/download/v1.9.0/mtg-linux-amd64-v1.9.0.tar.gz
  if [ $? -eq 0 ]; then
    tar -xvzf mtg-linux-amd64-v1.9.0.tar.gz
    return 0
  else
    return 1
  fi
}

# تابع برای نصب mtg و پیکربندی آن
installMtg() {
  if [ ! -e "mtg" ]; then
    echo "mtg not found, downloading..."
    if ! checkDownload; then
      echo "Download failed!"
      return 1
    fi
  fi

  chmod +x ./mtg

  if [ -e "config.json" ]; then
    echo "The configuration is as follows:"
    cat config.json
    read -p "Do you want to regenerate the configuration? [y/n] [n]:" input
    input=${input:-n}
    if [ "$input" == "n" ]; then
      return 0
    fi
  fi

  # ایجاد کلید به طور خودکار
  head=$(hostname | cut -d '.' -f 1)
  no=${head#s}
  host="panel${no}.serv00.com"
  secret=$(./mtg generate-secret --hex $host)
  
  # پورت تصادفی برای mtg
  loadPort
  randomPort tcp mtg
  
  if [[ -n "$port" ]]; then
    mtpport="$port"
  fi

  # نوشتن پیکربندی جدید به فایل config.json
  cat >config.json <<EOF
  {
    "secret": "$secret",
    "port": "$mtpport"
  }
EOF

  # نمایش مشخصات پروکسی
  echo "Configuration complete! Your proxy details are as follows:"
  echo "Secret Key: $secret"
  echo "Proxy URL: $host:$mtpport"
  echo "You can now use the proxy at the URL: mtg://$host:$mtpport"
}

# فراخوانی تابع نصب
installMtg

