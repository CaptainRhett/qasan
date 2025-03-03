#!/bin/sh -f


usage ()
{

   echo "Usage:"
   echo "    sd_gptformat <SlotId PartitionID StartAddr EndAddr FileSystemType>"
   echo "    sd_gptformat <0/1 1 0 32768 3 (1=vfat,2=ext2,3=ext3,4=ext4)>"
   exit 0

}

s=$1
n=$2
o=$3
z=$4
f=$5
p=$2

if [ "$s" -ne "0" ] && [ "$s" -ne "1" ] ; then
    echo "   Invalid SlotID, valid range <0,1>"
    usage
fi

ConvertTokiloBytes()
{
    case $2 in
    "GB")
        Value=$(echo $1 \* 1024 \* 1024 | bc -l)
     ;;
    "MB")
        Value=$(echo $1 \* 1024 | bc -l)
     ;;
    *)
     ;;
    esac
    return 0
}


PC="0"
PS="0"
PE="0"
#Calculating Total Number of partitions
PC=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | tail -1 | awk '{print $1}') >/dev/null 2>/dev/null

#Calculating the total size of SD card 
SDSZ=$(parted /dev/mmcblk$1 print | grep mmcblk$1 | awk '{print $3}' | sed 's/[GB/MB/kb]*//g') >/dev/null 2>/dev/null
Unit=$(parted /dev/mmcblk$1 print | grep mmcblk$1 | awk '{print $3}' | sed 's/[0-9/.]*//g') >/dev/null 2>/dev/null
ConvertTokiloBytes $SDSZ $Unit
SDSZ=$Value

# Format SD Card 
if [ "$n" == "0" ] && [ "$o" == "0" ] && [ "$z" == "0" ] ; then

	echo "Formatting SD card on slot $1..."

	i="1"
	while [ $i -le $PC ]
	do
   		umount /dev/mmcblk$1p$i >/dev/null 2>/dev/null
   		i=$(( $i + 1 ))
	done
parted -s /dev/mmcblk$1  mklabel gpt <<EOF >/dev/null 2>/dev/null
EOF
exit 0
fi

# Delete Partition 
if [ "$o" == "-1" ] && [ "$z" == "-1" ] ; then
	if [ "$p" != "$PC" ] ; then
    	echo "   Invalid Partition Number...$p"
		exit 0
	fi
echo "Deleting SD Card partition $p..."
umount /dev/mmcblk$1p$p >/dev/null 2>/dev/null 
parted /dev/mmcblk$1 <<EOF >/dev/null 2>/dev/null
rm
$n
quit
EOF
exit 0
fi

if [ "$p" -gt "$(($PC + 1))" ] ; then
    echo "   Invalid Partition Number...$p"
    exit 0
fi


# Format Partitions 
if [ "$o" == "0" ] && [ "$z" == "0" ] ; then

	umount /dev/mmcblk$1p$p >/dev/null 2>/dev/null 
	if   [ "$f" == "1" ] ; then
    	mkdosfs     /dev/mmcblk$1p$p >/dev/null 2>/dev/null
	elif [ "$f" == "2" ] ; then
    	mkfs.ext2   /dev/mmcblk$1p$p >/dev/null 2>/dev/null
	elif [ "$f" == "3" ] ; then
    	mkfs.ext3   /dev/mmcblk$1p$p >/dev/null 2>/dev/null
	elif [ "$f" == "4" ] ; then
    	mkfs.ext4   /dev/mmcblk$1p$p >/dev/null 2>/dev/null
	fi

	mount /dev/mmcblk$1p$p /mnt/sdmmc$1p$p
	exit 0
fi


if [ "$p" -le "$PC" ] ; then
    echo "   Invalid Partition Number...$p"
    exit 0
fi

if [ "$PC" -ge "1" ] ; then
PStartSize=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $2}' | sed 's/[kB/MB/GB]*//g') >/dev/null 2>/dev/null
Unit=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $2}' | sed 's/[0-9/.]*//g') >/dev/null 2>/dev/null
ConvertTokiloBytes $PStartSize $Unit
PC=$Value

PEndSize=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $3}' | sed 's/[kB/MB/GB]*//g') >/dev/null 2>/dev/null
Unit=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $3}' | sed 's/[0-9/.]*//g') >/dev/null 2>/dev/null
ConvertTokiloBytes $PEndSize $Unit
PE=$Value
fi

u=$(parted /dev/mmcblk$1 print | grep "Sector size" | head -1 | awk '{print $4}' | cut -d 'B' -f1) >/dev/null 2>/dev/null

# unmount partition
i="1"
while [ $i -le $n ]
do
umount /dev/mmcblk$1p$i >/dev/null 2>/dev/null 
i=$(( $i + 1 ))
done

# create partition
echo "Creating partition on  mmblk$s..."

if   [ "$f" == "1" ] ; then
	FType=vfat
elif [ "$f" == "2" ] ; then
	FType=ext2
elif [ "$f" == "3" ] ; then
	FType=ext3
elif [ "$f" == "4" ] ; then
	FType=ext4
fi


parted /dev/mmcblk$1 <<EOF >/dev/null 2>/dev/null
mkpart
primary
$FType
$o
$z
quit
EOF

if   [ "$f" == "1" ] ; then
	mkdosfs   	/dev/mmcblk$1p$p >/dev/null 2>/dev/null
elif [ "$f" == "2" ] ; then 
	mkfs.ext2  	/dev/mmcblk$1p$p >/dev/null 2>/dev/null
elif [ "$f" == "3" ] ; then
	mkfs.ext3  	/dev/mmcblk$1p$p >/dev/null 2>/dev/null
elif [ "$f" == "4" ] ; then 
	mkfs.ext4  	/dev/mmcblk$1p$p >/dev/null 2>/dev/null
fi

flag=0
i="1"
while [ $i -le $p ]
do
if [ "$i" -ne "4" ] ; then
	if [ ! -d "/mnt/sdmmc$1p$i" ] ; then
		echo "directory do not exits"
		mkdir /mnt/sdmmc$1p$i
	fi
	if [ -e /dev/mmcblk$1p$i ];
	then
		mount /dev/mmcblk$1p$i /mnt/sdmmc$1p$i
		flag=1
	fi
fi
i=$(( $i + 1 ))
done

if [ $flag = 0 ];
then
	echo "INFO: No partition is mounted from SD card."
fi

