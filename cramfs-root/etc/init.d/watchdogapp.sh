#Runlevel : 3 = S11
#Runlevel : 6 = K38
#Runlevel : 7 = K38
#Runlevel : 8 = K38

PATH=/bin:/usr/bin:/sbin:/usr/sbin

test -f /usr/local/bin/watchdogapp || exit 0

case "$1" in
	start)
		echo -n "Starting watchdog application"
		/usr/local/bin/watchdogapp &
		echo "."
		;;
	stop)
		echo -n "Stopping watchdog application ..."
		killall watchdogapp
		rm /var/pipe/watchdogQ
		echo "."
		;;
	reload)
		$0 restart
		;;
	force-reload)
		$0 restart
		;;
	restart)
		echo -n "Restarting watchdog application ..."
		killall watchdogapp
		rm /var/pipe/watchdogQ
		/usr/local/bin/watchdogapp &
		echo "."
		;;
	*)
		echo "Usage: /etc/init.d/watchdogapp.sh {start|stop|reload|restart|force-reload}"
		exit 1
esac

exit 0
