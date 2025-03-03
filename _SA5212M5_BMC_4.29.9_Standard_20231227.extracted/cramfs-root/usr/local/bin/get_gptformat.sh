#!/bin/sh -f



usage ()
{

   echo "Usage:"
   echo "    get_sdpart  <SlotId> <PartitionId>"
   echo "    get_sdpart  <0/1> <0..n>"
   exit 0

}

s=$1
n=$2


FILE="/var/ptable.txt"

hex_value=""

fwrite()
{
	echo -n $1 >> $FILE
	echo -n " " >> $FILE
}

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
  		Value=$1
     ;;
    esac
  	return 0	
}

#Getting the Number of Partitions
PCount=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | tail -1 | awk '{print $1}') >/dev/null 2>/dev/null
 
if [ -f $FILE ]; then
#   echo "File $FILE exist."
   rm -r $FILE 
fi

if [ "$2" == "0" ] ; then
    fwrite $PCount 
    exit 0
fi

if [ "$2" == "255" ] ; then
    SZ=$(parted /dev/mmcblk$1 print| grep mmcblk$1 | awk '{print $3}' | sed 's/[GB/MB/kb]*//g') >/dev/null 2>/dev/null
        #SZ=$(echo $SZ \* 1024 \* 1024 | bc -l)
		SZ=$(echo $SZ | awk '{print int($1+0.5)}')
       	echo -n $SZ >> $FILE
        exit 0
fi


fwrite $PCount

if [ "$2" -gt "$PCount" ] ; then
    echo "   Invalid Partition Number...$2"
    exit 0
fi

PARTED="/var/parted.txt"
 
parted /dev/mmcblk$1 print  | grep  -v -e  '^$' | sed -e '1,5d' > $PARTED
 
 
PStartSize=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $2}' | sed 's/[kB/MB/GB]*//g') >/dev/null 2>/dev/null
Unit=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $2}' | sed 's/[0-9/.]*//g') >/dev/null 2>/dev/null
ConvertTokiloBytes $PStartSize $Unit
Value=$(echo $Value | awk '{print int($1+0.5)}')
fwrite $Value
 
PEndSize=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $3}' | sed 's/[kB/MB/GB]*//g') >/dev/null 2>/dev/null
Unit=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $3}' | sed 's/[0-9/.]*//g') >/dev/null 2>/dev/null
ConvertTokiloBytes $PEndSize $Unit
Value=$(echo $Value | awk '{print int($1+0.5)}')
fwrite $Value

 
PSize=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $4}' | sed 's/[kB/MB/GB]*//g') >/dev/null 2>/dev/null 
Unit=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $4}' | sed 's/[0-9/.]*//g') >/dev/null 2>/dev/null
ConvertTokiloBytes $PSize $Unit
Value=$(echo $Value | awk '{print int($1+0.5)}')
fwrite $Value
 
PType=$(parted /dev/mmcblk$1 print | grep  -v -e  '^$' | sed -e '1,5d' | head -n $n | tail -1 | awk '{print $5}') >/dev/null 2>/dev/null
#fwrite $PType

if   [ "$PType" == "vfat" ]; then
    fwrite 1
elif [ "$PType" == "ext2" ]; then
    fwrite 2
elif [ "$PYype" == "ext3" ]; then
    fwrite 3
elif [ "$PType" == "ext4" ]; then
    fwrite 4
else
    fwrite 3
fi


exit 0

