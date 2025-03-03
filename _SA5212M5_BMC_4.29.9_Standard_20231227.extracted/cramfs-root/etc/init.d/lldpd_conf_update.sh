#! /bin/sh

LLDP_CONF_FILE="/var/run/lldpd/lldpd.conf"
LLDP_CONF_UPDATE_FLAG="/var/lldp_update_flag"

if [ -f $LLDP_CONF_FILE ];then
    rm $LLDP_CONF_FILE
fi

if [ ! -f $LLDP_CONF_UPDATE_FLAG ];then
    touch $LLDP_CONF_UPDATE_FLAG
fi

RetryCount=30
while true
do
    if [ -f $LLDP_CONF_FILE ] && [ ! -f $LLDP_CONF_UPDATE_FLAG ];then
        echo "lldp conf file has update success"
        exit 0
    elif [ ! -f $LLDP_CONF_FILE ] && [ ! -f $LLDP_CONF_UPDATE_FLAG ];then
        echo "lldp conf file update fail"
        exit 1
    fi
    if [ $RetryCount == 0 ];then
        break
    fi
    let RetryCount=RetryCount-1
    echo "Time left $RetryCount s"
    sleep 1
done

echo "lldp conf file update timeout"

exit 2