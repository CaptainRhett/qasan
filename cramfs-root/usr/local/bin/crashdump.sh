#Runlevel : 3 = S21
#Runlevel : 6 = K35
#Runlevel : 7 = K35
#Runlevel : 8 = K35

PATH=/bin:/usr/bin:/sbin:/usr/sbin

test -f /usr/local/bin/crashdump || exit 0

case "$1" in
	start)
		echo -n "Starting crashdump application"
		/usr/local/bin/crashdump &
		echo "."
		;;
	stop)
		echo -n "Stopping crashdump application ..."
		killall crashdump
		echo "."
		;;
	reload)
		$0 restart
		;;
	force-reload)
		$0 restart
		;;
	restart)
		echo -n "Restarting crashdump application ..."
		killall crashdump
		/usr/local/bin/crashdump &
		echo "."
		;;
	*)
		echo "Usage: /etc/init.d/crashdump.sh {start|stop|reload|restart|force-reload}"
		exit 1
esac

exit 0
