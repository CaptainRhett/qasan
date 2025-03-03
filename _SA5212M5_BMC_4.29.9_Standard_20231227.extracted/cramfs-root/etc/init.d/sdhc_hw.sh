#!/bin/sh
# /etc/init.d/sdhc_hw.sh: automatically mount SD partitions.
#
#Runlevel : S = S38

flag=0
if [ -e /dev/mmcblk0p1 ];
then
	mount  /dev/mmcblk0p1  /mnt/sdmmc0p1
	flag=1
fi
if [ -e /dev/mmcblk0p2 ];
then
	mount  /dev/mmcblk0p2  /mnt/sdmmc0p2
	flag=1
fi
if [ -e /dev/mmcblk0p3 ];
then
	mount  /dev/mmcblk0p3  /mnt/sdmmc0p3
	flag=1
fi
if [ -e /dev/mmcblk0p4 ];
then
	mount  /dev/mmcblk0p4  /mnt/sdmmc0p4
	flag=1
fi
if [ -e /dev/mmcblk0p5 ];
then
	mount  /dev/mmcblk0p5  /mnt/sdmmc0p5
	flag=1
fi
if [ -e /dev/mmcblk0p6 ];
then
	mount  /dev/mmcblk0p6  /mnt/sdmmc0p6
	flag=1
fi
if [ -e /dev/mmcblk0p7 ];
then
	mount  /dev/mmcblk0p7  /mnt/sdmmc0p7
	flag=1
fi

if [ $flag = 0 ];
then
	echo "INFO: No partition is mounted from SD card."
fi

#commenting the mounting of 2nd SD card block as no one is using both the SD controller.
#this is done to reduce the time taken for mouting the below paritions and thereby getting an error.
#mount  /dev/mmcblk1p1  /mnt/sdmmc1p1
#mount  /dev/mmcblk1p2  /mnt/sdmmc1p2
#mount  /dev/mmcblk1p3  /mnt/sdmmc1p3
#mount  /dev/mmcblk1p4  /mnt/sdmmc1p4
#mount  /dev/mmcblk1p5  /mnt/sdmmc1p5
#mount  /dev/mmcblk1p6  /mnt/sdmmc1p6
#mount  /dev/mmcblk1p7  /mnt/sdmmc1p7
