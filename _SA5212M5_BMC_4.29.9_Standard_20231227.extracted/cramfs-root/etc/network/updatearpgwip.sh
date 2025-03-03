#!/bin/sh
# updatearpgwip.sh: updates the arp table with gateway ip
#

IFACE=$1
delay=10
routeFile="/proc/net/route"
GatewayFlag="0003"

MASK1=0x000000FF
MASK2=0x0000FF00
MASK3=0x00FF0000
MASK4=0xFF000000


if [ -n "$2" ] ;then
	delay=$2
fi

sleep $delay

if [ -f $routeFile ]
then
	while read Line
	do
	    gtw=`echo $Line  |  awk '{ printf $4 }'`
	    #echo $gtw
	    if [ $gtw == $GatewayFlag ] ;then
		ifc=`echo $Line  |  awk '{ printf $1 }'`
		#echo $ifc
		if [ $ifc == $IFACE ] ;then
			ipint=0x`echo $Line  |  awk '{ printf $3 }'`
			break
		fi
	    fi
	done < $routeFile

	if [ $ipint ] ;then
                #convert int ip to string format
		byte1=$(( $ipint & $MASK1))
		byte2=$(( ($ipint & $MASK2) >> 8))
		byte3=$(( ($ipint & $MASK3) >> 16))
		byte4=$(( ($ipint & $MASK4)>>24))
		
		ipaddrs="$byte1.$byte2.$byte3.$byte4"
		#echo $ipaddrs
                ping -c 1 -s 8 $ipaddrs > /dev/null
	fi
fi
