#!/bin/sh
#group change file extend name
#useage: bin sourcefileextendname targetfileextendname
if [ $1 ]
then
	echo "Source File Extend Name $1"
else
	echo "Please Input Source File Extend Name"
	exit
fi
if [ $2 ]
then 
	echo "Target File Extend Name $2"
else
	echo "Please Input Target File Extend Name"
	exit
fi

for loop in $(ls)
do
	if echo "$loop" | grep -q "\.$1"
	then
		echo "rename $loop to $(echo $loop|sed "s/\.$1$/\.$2/")"
		mv $loop $(echo $loop |sed "s/\.$1$/\.$2/")
	fi
done
