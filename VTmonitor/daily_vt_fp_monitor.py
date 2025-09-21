#!/usr/bin/python

# Require pip install requests


__author__ = 'alan.lee@sophos.com'


import argparse
import datetime
import os
import sys
import time
import requests
import json as simplejson
import json

_API_USER = 'alanlee'
_API_KEY = 'd8a3b280436173ab539d748127a0c3f22f8eda6a2ed0c41872a667dd943dabf8'
#_USER_ENGINES = ["Sophos", "Invincea"]


# session API Keys
session = requests.Session()
session.headers = {'X-Apikey': _API_KEY }

#queries

#FP Sophos detected
#url_Sophos = "https://www.virustotal.com/api/v3/monitor_partner/hashes"
#querystring = {"filter": "engine:Sophos"}
#response = session.get(url_Sophos, params=querystring)
#print(response.text)


#FP Invincea detected
#url_Invincea = "https://www.virustotal.com/api/v3/monitor_partner/hashes"
#querystring = {"filter": "engine:Invincea"}
#response = session.get(url_Invincea, params=querystring)
#print(response.text)



# OV detection of SHA256
# Note that samples used in Monitor Partner may not be available to public on VT therefore using VT will not return any results.
# Therefore need to use monitor partner api to get OV results
#url = "https://www.virustotal.com/api/v3/monitor_partner/hashes/19738c03e5710e3def3edef641bdc68c3bf8d272a15ea5494a16fc4efdc4c543/analyses"
#response = session.get(url)
#print(response.text)


# Retrieve metadata related to SHA256
#url = "https://www.virustotal.com/api/v3/monitor_partner/hashes/19738c03e5710e3def3edef641bdc68c3bf8d272a15ea5494a16fc4efdc4c543/items"
#response = session.get(url)
#print(response.text)


# Download sample
#url = "https://www.virustotal.com/api/v3/monitor_partner/files/19738c03e5710e3def3edef641bdc68c3bf8d272a15ea5494a16fc4efdc4c543/download"
#response = session.get(url)
#with open('sample', 'wb') as f:
#    f.write(response.content)


# Download CSV file for daily FP detections
#url = "https://www.virustotal.com/api/v3/monitor_partner/detections_bundle/Sophos/download"
#response = session.get(url)
#with open('fp.csv', 'wb') as f:
#    f.write(response.content)

# Statistics for FP 
# Stats for Sophos
url = "https://www.virustotal.com/api/v3/monitor_partner/statistics?filter=engine:Sophos&limit=1"

try:
    response = session.get(url, proxies={'http': 'http://proxy.labs.localsite.sophos:8080', 'https': 'http://proxy.labs.localsite.sophos:8080'})
    print (response.text)
    response_dict = simplejson.loads(response.text)
except requests.exceptions.RequestException as e:
    print e
    sys.exit(1)
total_hashes_count = response_dict.get("data", {})[0].get("attributes", {}).get("hashes_count")
sophos_hashes_detected_count = response_dict.get("data", {})[0].get("attributes", {}).get("hashes_detected_count")
sophos_engine = response_dict.get("data", {})[0].get("attributes", {}).get("engine")
scandate = response_dict.get("meta", {}).get("cursor")


# Stats for Invincea
url = "https://www.virustotal.com/api/v3/monitor_partner/statistics?filter=engine:Invincea&limit=1"

try:
    response = session.get(url, proxies={'http': 'http://proxy.labs.localsite.sophos:8080', 'https': 'http://proxy.labs.localsite.sophos:8080'})
    print (response.text)
    response_dict = simplejson.loads(response.text)
except requests.exceptions.RequestException as e:
    print e
    sys.exit(1)


invincea_hashes_detected_count = response_dict.get("data", {})[0].get("attributes", {}).get("hashes_detected_count")

csvstring=scandate+","+str(total_hashes_count)+","+str(sophos_hashes_detected_count)+","+str(invincea_hashes_detected_count)+"\n"

print csvstring

csvfile = open('daily_vt_fp_monitor.csv','a')
csvfile.write(csvstring)
csvfile.close()




