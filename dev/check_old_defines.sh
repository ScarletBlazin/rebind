#!/bin/bash
#Script to check header files for unused #define's.

IFS=$'\n'
DIR=../src

cd $DIR

for DEFINE in $(grep -n ^#define *.h); do

	NAME=$(echo $DEFINE | awk '{print $2}' | sed -e 's/(.*//')

	if [ "$(grep $NAME *.c)" == "" ] ;then
		FILE=$(echo $DEFINE | cut -d':' -f1)
		LINE=$(echo $DEFINE | cut -d':' -f2)
		
		echo "$DIR/$FILE line $LINE: '$NAME' defined but not used!"
	fi
done
