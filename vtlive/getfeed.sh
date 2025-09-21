#!/bin/sh

#echo "Current time: "`date -u`

mytime=`date -u --date '-5 min' +%Y%m%dT%H%M`

echo $mytime

python vtfeeds.py url $mytime

