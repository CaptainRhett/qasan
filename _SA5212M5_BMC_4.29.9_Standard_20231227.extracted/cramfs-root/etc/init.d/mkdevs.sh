#! /bin/sh

PATH=/sbin:/bin:/usr/bin:/usr/sbin


if ! [ -e /etc/udev/links.conf ]
then
	exit 0
fi

while read entry
do
	read TYPE NAME DEV MAJOR MINOR <<HERE
		$(echo $entry)
HERE
	if [ -e /dev/$NAME ]
	then
#		echo "/dev/$NAME exists. Skipping"
		continue
	fi
	
	if [ "$TYPE" == "D" ]
	then
		#echo "Creating Directory /dev/$NAME"
		mkdir -p /dev/$NAME
	fi

	if [ "$TYPE" == "M" ]
	then 
		#echo "Creating Device Node /dev/$NAME"
		mknod /dev/$NAME $DEV $MAJOR $MINOR
		chmod 777 /dev/$NAME
	fi
	
done < /etc/udev/links.conf

#changing permissions for ttyS* nodes

for file in /dev/[ttyS]*
do
	chmod 777 $file
done

#mkdir /dev/pts
exit 0
