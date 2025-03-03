#Runlevel : 3 = S90
#Runlevel : 6 = K90
# Restart the service on warm reboot
#Runlevel : 9 = K90
#Runlevel : 9 = S90

PATH=/bin:/usr/bin:/sbin:/usr/sbin

BKUPCONF_DIR="bkupconf"
check_bkupconf() {
      # Check if there is bkupconf in fstab
      VAL=`df | grep "/$BKUPCONF_DIR" | awk '{ printf $6 }'`
      if [ "$VAL" == "" ]; then
          return 0
      else
          #Found bkupconf
          return 1
      fi
  }

ca_file="/conf/ca.pem"
def_ca_file="/etc/defconfig/ca.pem"
if  test -f "$ca_file" 
then 
    echo "Lighttpd ca.pem exists"
else 
    echo "Copying ca.pem file"
    cp /etc/defconfig/ca.pem /conf/
    check_bkupconf
    if [ $? == 1 ]; then
      #If there is bkupconf in fstab, copy lighttpd.conf to /bkupconf/
      cp /etc/defconfig/ca.pem /bkupconf/
    fi
fi

#wwy_20220902++ 文件是初始conf文件，high是根据高安全要求改变安全插件的配置文件，conf是应用配置文件的路径<<
conf_lighttpd_file="/conf/lighttpd.conf"
def_lighttpd_file="/etc/defconfig/lighttpd.conf"
high_lighttpd_file="/etc/defconfig/lighttpd_security_high.conf"

#enable_TLS_1_2_file是一个标识符，判断是否启用高安全需求 20220825
enable_TLS_1_2_file="/var/enable_openssl_security_high"

if  test -f "$conf_lighttpd_file" #判断是否存在配置文件
then 
	echo "Lighttpd configurations exists"

	VAL=`diff $conf_lighttpd_file $def_lighttpd_file | grep "ssl.cipher-list"`
	if [ "$VAL" == "" ]; then
		if  test -f "$enable_TLS_1_2_file"
		then
			#和默认文件一样，启动了高安全需求（和高安全文件不一样）
			echo "Copying /etc/defconfig/lighttpd.conf to Lighttpd configurations "
			cp $high_lighttpd_file $conf_lighttpd_file
			#检查备份文件，如需要备份就将备份文件修改
			check_bkupconf
			if [ $? == 1 ]; then
				#If there is bkupconf in fstab, copy lighttpd.conf to /bkupconf/
				echo "Copying /etc/defconfig/lighttpd.conf to bkupconf Lighttpd configurations "
				cp $conf_lighttpd_file /bkupconf/lighttpd.conf
			fi
		else
			#和默认文件一样，未启动高安全需求（和高安全文件一样）
			echo "lighttpd.conf is same to default lighttpd.conf!"
		fi
	else
		if  test -f "$enable_TLS_1_2_file"
		then
			#和默认文件不一样，启动了高安全需求（和高安全文件一样）
			echo "lighttpd.conf is same to high lighttpd.conf!"
		else
			#和默认文件不一样，未启动高安全需求（和高安全文件不一样）
			echo "Copying default conf to Lighttpd configurations "
			cp $def_lighttpd_file $conf_lighttpd_file
			#检查备份文件，如需要备份就将备份文件修改
			check_bkupconf
			if [ $? == 1 ]; then
				#If there is bkupconf in fstab, copy lighttpd.conf to /bkupconf/
				echo "Copying /etc/defconfig/lighttpd.conf to bkupconf Lighttpd configurations "
				cp $conf_lighttpd_file /bkupconf/lighttpd.conf
			fi
		fi
	fi
else 
	echo "No lighttpd_conf Copying Lighttpd configurations"
	if test -f "$enable_TLS_1_2_file" #判断是否启用高安全模式
		then
		echo "Copying high.conf to conf "
		cp $high_lighttpd_file $conf_lighttpd_file
	else
		echo "Copying lighttpd.conf to conf "
		cp $def_lighttpd_file $conf_lighttpd_file
	fi
	check_bkupconf
	if [ $? == 1 ]; then
		#If there is bkupconf in fstab, copy lighttpd.conf to /bkupconf/
		echo "Copying /etc/defconfig/lighttpd.conf to bkupconf Lighttpd configurations "
		cp $conf_lighttpd_file /bkupconf/lighttpd.conf
	fi
fi

lighttpd_start() {
if [ -x /usr/local/sbin/lighttpd ]; then
    if ! `test -e /var/run/lighttpd.pid`; then
        /usr/local/sbin/lighttpd -f /conf/lighttpd.conf -m /usr/local/lib
        echo "Starting lighttpd"
    else
        /bin/ps ax | grep /usr/local/sbin/lighttpd | grep -v grep > /dev/null
        if [ $? == 1 ];then
           rm -f /var/run/lighttpd.pid
           /usr/local/sbin/lighttpd -f /conf/lighttpd.conf -m /usr/local/lib
        else
            echo "Lighttpd is already running!"
        fi
    fi
fi
}

lighttpd_stop() {
echo "Stopping lighttpd"
killall -15 lighttpd
}

lighttpd_restart() {
lighttpd_stop
sleep 3
lighttpd_start
}
test -f /var/tmp/licstat/lighttpd_nolicense && exit 0
case "$1" in
'start')
lighttpd_start
;;
'stop')
lighttpd_stop
;;
'restart')
lighttpd_restart
;;
*)
echo "usage $0 start|stop|restart"
;;
esac 
