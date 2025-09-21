#!/usr/bin/env python3
# author: Alan Lee
# VTSearch.py - Searching VT for files/url


import urllib3
import sys
import argparse
import urllib
from urllib.parse import urlencode
#import postfile #requires postfile.py to be installed (get from http://code.activestate.com/recipes/146306/)
import time
import os
import requests
import logging
import asyncio
import json
import re


LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)

MYAPIKEY = 'd8a3b280436173ab539d748127a0c3f22f8eda6a2ed0c41872a667dd943dabf8'

BASEURL = 'https://www.virustotal.com/api/v3/intelligence/search'

PROXIES = { "http://proxy.labs.localsite.sophos:8080", "https://proxy.labs.localsite.sophos:8080" }

def main():

    parser = argparse.ArgumentParser(description='VTSearch for file and urls') 
    parser.add_argument("-q", "--query", help="VT query search string", type=str)

    args = parser.parse_args()
    
    if args.query:
        vtquery(args.query)


#searching using query string
def vtquery(query_string):

    
    logging.info('Starting VirusTotal Intelligence query')
    logging.info('* VirusTotal Intelligence search: %s', query_string) 

    encoded_query_string = urllib.parse.quote(query_string)
    formatted_query_string = '?query={}'.format(encoded_query_string)
    print(formatted_query_string)
    parameters = {"query": formatted_query_string, "apikey": MYAPIKEY, "proxies": PROXIES}
    data = urlencode(parameters)

    http = urllib3.PoolManager()

    req = http.request('GET', BASEURL, data)

    try:
        response = urllib3.urlopen(req)
        print(response)
    except Exception:
        print("Unknown error")
    json = response.read()
    # parse result from Virustotal
    #print json
    process_result(json)

    return;


async def queue_file_hashes(self, search):
    """Retrieve files from VT and enqueue them for being downloaded.
    Args:
    search: VT intelligence search query
    """

    client = await self.get_session()
    querystring = '?query={}'.format(search)
    endpoint = '/intelligence/search'
    enqueued_files = 0
    cursor = ''
    while enqueued_files < self.num_files and cursor != None:
        response = await client.get(
        '{}{}'.format(self.BASE_URL, endpoint),
        params={'query': search, 'cursor': cursor})
        if response.status == 200:
            json_response = json.loads(await response.content.read())
            cursor = json_response.get('meta', {}).get('cursor', None)
            files_retrieved = len(json_response.get('data', []))
            file_iterator = 0
            while enqueued_files < self.num_files and file_iterator < files_retrieved:
                file_hash = json_response['data'][file_iterator]['id']
                await self.queue.put(file_hash)
                file_iterator += 1
                enqueued_files += 1
        else:
            logging.info('There was an error getting files to be downloaded: %s', await response.content.read())
            cursor = None  # Exiting while loop



if __name__ == "__main__": 
    main()
