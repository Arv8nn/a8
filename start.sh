#!/bin/bash
echo "=================================================================="
echo "=================================================================="
echo "made and translated by ARV8n"
echo "suorce = yonggekkk , mtg"
echo "Please select an option:"
echo "==================================================================="
echo "==================================================================="

select option in "install script(translate from yonggekkk)" "serv00 MTproxy" "exit"
do
    case $option in
	"install script(translate from yonggekkk)")
	echo "you selected install script(translate from yonggekkk)"
	bash <(curl -Ls https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/files/serv00.sh)
	;;
 	"serv00 MTproxy")
  	echo "you selected serv00 MTproxy"
   	bash <(curl -Ls https://raw.githubusercontent.com/ambe2222/a8/refs/heads/main/mt.sh)
    	;;
	"exit")
	echo "Exiting the program"
            break
            ;;
	esac
done
