#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.

"""Simple example script to interact with VirusTotal's feeds APIs.

VirusTotal's feed APIs allow privileged users to download all reports for files/
urls/domains/ip addresses processed by VirusTotal in a given time window. These
reports allow users to access detailed information about the items and, in the
case of files, a link to download the pertinent sample is also provided. The API
is documented at:
https://www.virustotal.com/documentation/private-api/#file-feed
https://www.virustotal.com/documentation/private-api/#url-feed
"""

__author__ = 'emartinez@virustotal.com (Emiliano Martinez)'


import datetime
import json
import logging
import os
import Queue
import socket
import sys
import tarfile
import threading
from urlparse import urlparse

import requests


_FEEDS = [
    'file',
    'url',
    'domain',
    'ipaddress',
    'file-behaviour',
]
_FEEDS_URL = 'https://www.virustotal.com/vtapi/v2/%s/feed'
_MAX_DOWNLOAD_ATTEMPTS = 3
_DOWNLOAD_CHUNK_SIZE = 1024 * 1024
_NUM_CONCURRENT_DOWNLOADS = 20
_THIS_PATH = os.path.dirname(os.path.abspath(__file__))
_LOCAL_FILE_STORE = os.path.join(_THIS_PATH, 'vtfiles')
_LOCAL_PACKAGE_STORE = os.path.join(_THIS_PATH, 'vtpackages')
_HEX_CHARACTERS = 'abcdef0123456789'

_download_queue = Queue.Queue()

socket.setdefaulttimeout(10)

logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
LOGGING_LEVEL = logging.INFO  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    #format='%(asctime)s %(levelname)-8s %(message)s',
                    #datefmt='%Y-%m-%d %H:%M:%S',
                    format='%(message)s',
                    stream=sys.stdout)


def create_package_store(feed):
  """Directory to store feed time window packages retrieved from VirusTotal."""
  if not os.path.exists(_LOCAL_PACKAGE_STORE):
    os.mkdir(_LOCAL_PACKAGE_STORE)
  feed_package_path = os.path.join(_LOCAL_PACKAGE_STORE, feed)
  if not os.path.exists(feed_package_path):
    os.mkdir(feed_package_path)


def create_local_file_store():
  """3 level directory structure to store downloaded samples from file feed."""
  if not os.path.exists(_LOCAL_FILE_STORE):
    os.mkdir(_LOCAL_FILE_STORE)
  for char0 in _HEX_CHARACTERS:
    dir0 = os.path.join(_LOCAL_FILE_STORE, char0)
    if not os.path.exists(dir0):
      os.mkdir(dir0)
    for char1 in _HEX_CHARACTERS:
      dir1 = os.path.join(dir0, char1)
      if not os.path.exists(dir1):
        os.mkdir(dir1)
      for char2 in _HEX_CHARACTERS:
        dir2 = os.path.join(dir1, char2)
        if not os.path.exists(dir2):
          os.mkdir(dir2)


def download_to_file(url, destination):
  """Stream download the response of a given URL to a local file."""
  for _ in range(_MAX_DOWNLOAD_ATTEMPTS):
    try:
      response = requests.get(url, stream=True)
      if response.status_code != 200:
        logging.error(
            'Unable to download to %s, URL answered with status code: %s',
            destination, response.status_code)
        return
      with open(destination, 'wb') as destination_file:
        for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK_SIZE):
          if chunk:  # filter out keep-alive new chunks
            destination_file.write(chunk)
      return destination
    except:  # pylint: disable=bare-except
      continue


def file_feed_downloader():
  """Worker that downloads individual files found within the file feed."""
  while True:
    url, file_hash = _download_queue.get()
    destination = os.path.join(
        _LOCAL_FILE_STORE, file_hash[0], file_hash[1], file_hash[2],
        file_hash)
    success = download_to_file(url, destination)
    if success:
      logging.info('Successfully downloaded file %s', file_hash)
    else:
      logging.error('Unable to download file %s', file_hash)
    _download_queue.task_done()


def launch_file_feed_downloaders():
  """Set up file feed downloading threads."""
  threads = []
  for _ in range(_NUM_CONCURRENT_DOWNLOADS):
    thread = threading.Thread(target=file_feed_downloader)
    thread.daemon = True
    thread.start()
    threads.append(thread)
  return threads


def get_package(package, apikey, feed='file'):
  """Retrieve a time window feed reports package from VirusTotal."""
  # In order to retrieve a package we use the VirusTotal feeds APIs.
  package_url = _FEEDS_URL % (feed) + '?package=%s&apikey=%s' % (
      package, apikey)
  destination = os.path.join(
      _LOCAL_PACKAGE_STORE, feed, '%s.tar.bz2' % (package))
  return download_to_file(package_url, destination)


def get_item_type(item_report):
  """Given a feed item report induce whether it is a file, URL, domain, etc."""
  # For the time being we have only implemented the URL and file feed, domain,
  # ip address and file behaviour report feeds will follow in subsequent updates
  # of this script.
  permalink = item_report.get('permalink') or ''
  if '/file/' in permalink:
    return 'file'
  elif '/url/' in permalink:
    return 'url'


def process_feed_item(item_report):
  """Process an individual item report contained within a feed package."""
  # Logic to store this information in your dataset would probably go here,
  # you should think of doing this asyncrhonously in a thread as this function
  # gets called sequentially.
  global _MYCOUNT
  item_type = get_item_type(item_report)
  if item_type == 'file' and item_report.get(
      'positives', 0) > 45 and item_report.get('size') < 300 * 1024:
    # Example illustrating what we can do with file report items, here we
    # enqueue a task to download the file being reported if it has more than
    # 45 positives and is less than 300 KB in size.
    _download_queue.put([item_report.get('link'), item_report.get('sha256')])
  elif item_type == 'url' and item_report.get('positives', 0) > -1:
    url = item_report.get('url')
    url = url.replace(",","")
    _MYCOUNT = _MYCOUNT+1
    positives = item_report.get('positives')
    permalink = item_report.get('permalink')
    scan_date = item_report.get('scan_date')
    first_seen = item_report.get('first_seen')
    sophos_detect = item_report.get('scans').get('Sophos').get('detected')


    parsed_uri = urlparse(url)
    domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    domain = domain.replace("http://","")
    domain = domain.replace("https://","")
    domain = domain.replace("www.","")
    domain = domain.replace("/","")
    #logging.info('Processed URL %s with %s positives, mycount=%s', url, positives, _MYCOUNT)
    if sophos_detect:
        logging.info('%s,%s,%s,%s,%s', url, positives, permalink, scan_date, sophos_detect)


def process_package(package_path):
  """Process a time window feed package retrieved from VirusTotal."""
  # Packages pulled from VirusTotal are bzip2 compressed tarballs. Per minute
  # packages contain one unique file, one json per line, the json being a full
  # report on the item in the feed. Hourly packages contain 60 files, following
  # the same format, one per minute.
  with tarfile.open(package_path, mode='r:bz2') as compressed:
    for member in compressed.getmembers():
      member_file = compressed.extractfile(member)
      for line in member_file:
        item_json = line.strip('\n')
        if not item_json:
          continue
        item_report = json.loads(item_json)
        #print item_report
        process_feed_item(item_report)


def main():
  """Pipeline the entire feed processing logic."""
  if len(sys.argv) != 3:
    print '''Usage:
    %s <feed> <package> <apikey>\n''' % sys.argv[0]
    return
  feed = sys.argv[1]
  package = sys.argv[2]
  apikey = "d8a3b280436173ab539d748127a0c3f22f8eda6a2ed0c41872a667dd943dabf8"
  global _MYCOUNT  
  _MYCOUNT = 0
  # Check that the requested feed does indeed exist.
  if feed not in _FEEDS:
    logging.error(
        'Invalid feed requested, should be one of: %s', ', '.join(_FEEDS))
    return
  # Check that the package format provided is correct, VirusTotal produces
  # per minute and per hour report packages, containing all items processed by
  # a given interface.
  try:
    datetime.datetime.strptime(package, '%Y%m%dT%H')
  except ValueError:
    try:
      datetime.datetime.strptime(package, '%Y%m%dT%H%M')
    except ValueError:
      logging.error(
          'Invalid package format provided, should be %Y%M%dT%H or %Y%M%dT%H%M')
      return
  # The time window feed package is temporarily stored to a given directory, and
  # processed from there.
  create_package_store(feed)
  if feed == 'file':
    # The reports in the file feed contain a property with a link to download
    # the reported samples, we process those in a pool of workers to perform
    # parallel downloads. The logic to decide what gets downloaded can be found
    # in the process_fee_item() function.
    create_local_file_store()
    launch_file_feed_downloaders()
  # Download the compressed package with all the items processed by VirusTotal
  # during the time window being requested.
  package_path = get_package(package, apikey, feed=feed)
  if not package_path:
    logging.error('Failed to download feed package')
    return
  process_package(package_path)
  if feed == 'file':
    _download_queue.join()
  # We delete the time window feed package. If you need to keep these report
  # buckets you should comment out this line and rather store the packages in
  # a n-level directory structure or persistent storage.
  if package_path and os.path.exists(package_path):
    os.remove(package_path)


if __name__ == '__main__':
  main()
