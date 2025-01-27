#!/bin/bash
echo "=================================================================="
echo "=================================================================="
echo "serv00 اسکریپت ترجمه شده نصب سینگ باکس بر روی هاست"
echo "translated by ARV8n"
echo "suorce = yonggekkk"
echo "Please select an option:"
echo "==================================================================="
echo "==================================================================="

select option in "install script" "exit"
do
    case $option in
	"install script")
	echo "you selected install script"
	bash <(curl -Ls https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/files/serv00.sh)
	;;
	"exit")
	echo "Exiting the program"
            break
            ;;
	esac
done
