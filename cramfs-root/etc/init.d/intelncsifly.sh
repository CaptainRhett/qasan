#!/bin/sh
# /etc/init.d/intelncsifly.sh: Intel WA processes for I350 NCSI transfer speed low
#
#Running at RCS.d
#Runlevel : S = S38

if ! `test -f /var/enable_intelncsifly`; then
    echo "Do not Enable NCSI Performance"
    exit
fi

echo "Enable NCSI Performance"
sysctl -w net.ipv4.tcp_rmem='4096 12288 12288' > /dev/null
sysctl -w net.ipv4.tcp_wmem='4096 16384 16384' > /dev/null
sysctl -w net.ipv4.route.flush=1 > /dev/null
