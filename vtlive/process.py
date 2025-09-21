#!/usr/bin/python

# to combine all dictionary in daily json into 1 single dictionary and then create vtlivefeed.json

from datetime import date, timedelta
from collections import Counter
import datetime
import time
import os
import json
import yaml

#_THIS_PATH = '/home/alanlee/scripts/VT/vtcharts'
_THIS_PATH = '/'

def getdate():
    nowtime = datetime.datetime.utcnow() - timedelta(1)
    yesterday = nowtime.strftime("%Y%m%d")
    return yesterday

# read daily json file and add up all the counts for each vendor
# then append the result to temp file
def readdailyjsonfile():
    yesterday = getdate()
    yesterdayfile = yesterday + ".temp"
    yesterdayfile = os.path.join(_THIS_PATH, yesterdayfile)

    with open(yesterdayfile, "r") as f:
        newdict = Counter({})
        counter = 0
        for eachdict in f:
	    eachdict = eachdict.strip()
            newdict += Counter(json.loads(eachdict))

    newdict["Timestamp"] = yesterday
    
    tempfile = os.path.join(_THIS_PATH, "vtlivefeed.pre")

    with open(tempfile, "ab") as t:
        t.write(json.dumps(newdict))
        t.write("\n")

    
    #read the entire vtlivefeed.pre file       
    with open(tempfile, "r") as tempfile:
        mylist = []
        for line in tempfile:
            line = line.strip()
            newline = yaml.safe_load(line)
            mylist.append(newline)


    outfile = os.path.join(_THIS_PATH, 'vtlivefeed.json')
    with open(outfile, "w+") as o:
        o.write(json.dumps(mylist))

 
def main():
    readdailyjsonfile()
    

if __name__ == '__main__':
  main()
