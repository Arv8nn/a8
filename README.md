# اسکریپت ترجمه شده نصب سینگ باکس بر روی هاست serv00

پروتکل ها

Hysteria2, TUIC5, VLESS-Reality, VMESS-WS/ARGO

automatic keep alive

# لینک اصلی پروژه های اسکریپت دریافت کانفیگ
https://github.com/yonggekkk/sing-box-yg

https://github.com/eooce/Sing-box

برای نصب سینگ باکس در اسکریپت yonggekk منتظر بمونید تا اسکریپت ipها را لیست کند سپس از ip های داده شده که در مرحله نصب نیاز است استفاده کنید. در مراحل بعدی با زدن enter بصورت پیش فرض مقادیر ست خواهند شد.

هر اسکریپتی که برای دریافت کانفیگ نصب می کنید از همان اسکریپت برای حذف استفاده کنید.

# socks5

https://github.com/cmliu/socks5-for-serv00

برای استفاده از socks5 ابتدا در DevilWEB webpanel لاگین کرده و در قسمت port reservation یک پورت tcp با مقدار 60000-1025 ایجاد کرده سپس اسکریپت serv00 socks5 اجرا کنید.

سایت بیشتر از 3 پورت باز ساپورت نمی کند. پس برای استفاده از socks5 در کنار کانفیگ ها می تونید به دلخواه یک پورت udp رو پاک کنید.

# پروکسی تلگرام

برای استفاده از پروکسی تلگرام ابتدا در DevilWEB webpanel لاگین کرده و در قسمت port reservation یک پورت tcp با مقدار 60000-1025 ایجاد کرده سپس اسکریپت serv00 MTproxy اجرا کنید.

سایت بیشتر از 3 پورت باز ساپورت نمی کند. پس برای استفاده از پروکسی تلگرام در کنار کانفیگ ها می تونید به دلخواه یک udp رو پاک کنید.

# نصب:

bash <(curl -Ls https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/start.sh)
# made by ARV8N
