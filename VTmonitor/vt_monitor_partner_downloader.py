#!/usr/bin/python
#
# Copyright 2018 VirusTotal. All Rights Reserved.

"""Download your Monitor Partner engine detections and generate a report.

The first time you run this script your apikey and engines will be populated,
by default your first engine will always be requested, if you have more than
one you can choose it calling the script with paramether --engine.
Detected binaries are going to be downloaded to vtmp.engine/path/hash, you can
configure path deep using -f (folder-levels param). Together with the binary
an owners text file with grepable company names and a json file with
monitor_hash metadata is created in the same directory.
Also, a report file on "vtmp.engine/report-[date].txt" will be generated.
There is one funcion "process_fn" that is called each time a binary is
downloaded, it is there for your own use.

Requirements:
$ pip install requests
"""

__author__ = 'fsantos@virustotal.com (Francisco Santos)'


import argparse
import base64
import datetime
import getpass
import json
import logging
import os
try:  # py3 compat
  import Queue
except ImportError:
  import queue as Queue
import signal
import sys
import threading
import time
import requests


_API_USER = 'alanlee'
_API_KEY = 'd8a3b280436173ab539d748127a0c3f22f8eda6a2ed0c41872a667dd943dabf8'
_USER_ENGINES = []
_DEFAULT_HOST = 'https://www.virustotal.com'
_DEFAULT_USER_AGENT = 'MonitorPartnerDownloaderV1'
_MONITOR_KEY_PREFIX = 'vtmonitor-v1://'
_SCRIPT_PATH = os.path.abspath(os.path.dirname(__file__))
_SCRIPT_CACHE_FILE = os.path.join(_SCRIPT_PATH, 'owners.cache')

# Logging
log = logging.getLogger('monitor-partner-downloader')
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',
                              datefmt='%b.%d/%H:%M:%S')
log.setLevel(logging.DEBUG)
_logging_stream_handler = logging.StreamHandler()
_logging_stream_handler.setFormatter(formatter)
log.addHandler(_logging_stream_handler)


try:  # py3 compat
  input = raw_input
except NameError:
  pass


def process_fn(monitor_hash, monitor_ids, organizations):
  # You can use this function to process each hash metadata, for ex introducing
  # it into a database
  pass


def autoupdate():
  print('This is the first time you run this script, we are going to obtain '
        'your VirusTotal user/APIKEY for you.')

  email = input('Insert your user email: ')
  password = getpass.getpass('Insert your password: ')
  session = requests.Session()
  session.headers.update({'User-Agent': _DEFAULT_USER_AGENT})

  user_data = {'data': {'user_id': email,
                        'password': password,
                        'forever': False}}
  response = session.post(
      _DEFAULT_HOST + '/ui/signin', data=json.dumps(user_data))
  if response.status_code != 200:
    print('API Error', response.status_code, response.url)
    print(response.text)
    return

  response_data = response.json().get('data')
  user_id = response_data.get('id')
  user_apikey = response_data.get('attributes', {}).get('apikey')

  privileges = response_data.get('attributes', {}).get('privileges', {})
  if not privileges.get('monitor-partner', {}).get('granted'):
    print('Your user does not have monitor-partner privileges, '
          'please contact support')
    return

  group_id = privileges.get('monitor-partner', {}).get('inherited_from')

  session.headers.update({'X-Apikey': user_apikey})
  response = session.get(_DEFAULT_HOST + '/api/v3/groups/' + group_id)
  if response.status_code != 200:
    print('API Error', response.status_code, response.url)
    print(response.text)
    return

  preferences = response.json().get(
      'data').get('attributes', {}).get('preferences', {})
  engines = preferences.get('monitor_partner', {}).get('engines', {})
  if not engines:
    print('Your group does not have any engines configured, '
          'please contact support')

  with open(__file__, 'r') as f_obj:
    content = f_obj.read()
  content = content.replace('[YOUR-USER-ID]', user_id, 1)
  content = content.replace('[YOUR-API-KEY]', user_apikey, 1)
  content = content.replace(
      '_USER_ENGINES = []', '_USER_ENGINES = ' + str(engines), 1)
  with open(__file__, 'w') as f_obj:
    f_obj.write(content)

  print('Script setup finished correctly, please run it again.')


def monitorid_ownerid(object_id):
  decoded_id = base64.urlsafe_b64decode(str(object_id)).decode('utf8')
  decoded_ownerpath = decoded_id.partition(_MONITOR_KEY_PREFIX)[2]
  return decoded_ownerpath.partition('/')[0]


class MonitorOwnerResolver(object):

  def __init__(self, resport_dst):
    self.session = requests.Session()
    self.session.headers.update({'X-Apikey': _API_KEY,
                                 'User-Agent': _DEFAULT_USER_AGENT})
    self._owners_cache = {}
    self._owners_hashes = {}
    self.mutex = threading.Lock()
    self._load_cache()
    date_str = datetime.datetime.utcnow().strftime('%Y%m%d')
    self.report_fn = os.path.join(
        resport_dst, 'owner-report-%s.txt' % date_str)

  def _load_cache(self):
    if not os.path.isfile(_SCRIPT_CACHE_FILE):
      return

    with open(_SCRIPT_CACHE_FILE, 'r') as cache_obj:
      self._owners_cache = json.loads(cache_obj.read())

  def _save_cache(self):
    with open(_SCRIPT_CACHE_FILE, 'w') as cache_obj:
      cache_obj.write(json.dumps(self._owners_cache))

  def _simplify(self, group):
    """Simplify group object to use less memory."""
    attributes = ['country', 'country_iso', 'domain_name', 'industry',
                  'organization', 'organization_legal_name']
    obj = {}
    for attribute in attributes:
      obj[attribute] = group.get(
          'data', {}).get('attributes', {}).get(attribute)
    return obj

  def resolve(self, owner_id):
    """Resolve and cache each owner_id."""
    self.mutex.acquire()  # Do not launch same request many times
    if owner_id not in self._owners_cache:
      log.info('Resolving owner_id "%s"', owner_id)
      response = self.session.get(_DEFAULT_HOST + '/api/v3/groups/' + owner_id)
      self._owners_cache[owner_id] = self._simplify(response.json())
      self._save_cache()
    self.mutex.release()
    return self._owners_cache[owner_id]

  def organization(self, owner_id):
    return self.resolve(owner_id).get('organization')

  def add_hash(self, owner_id, sha256):
    with open(self.report_fn, 'a') as report_obj:
      report_obj.write('"%s";%s;%s\n' % (
          self.organization(owner_id), owner_id, sha256))


class MonitorPartnerDownloader(object):

  def __init__(self, args):
    self.download_queue = Queue.Queue()
    self.threads_number = int(args.threads)
    self.host = _DEFAULT_HOST
    self.limit = args.limit
    self.engine = args.engine or _USER_ENGINES[0]
    if args.destination:
      self.destination = args.destination.encode('utf8')
    else:  # vtmp.engine folder
      self.destination = 'vtmp.%s' % self.engine
    self.resolver = MonitorOwnerResolver(self.destination)

    self.params = {'host': _DEFAULT_HOST,
                   'apikey': _API_KEY,
                   'user_agent': _DEFAULT_USER_AGENT,
                   'resolver': self.resolver,
                   'destination': self.destination,
                   'folder_levels': int(args.folder_levels)}
    if self.destination and not os.path.isdir(self.destination):
      log.info('Creating base folder "%s"', self.destination)
      os.mkdir(self.destination)

    self.session = requests.Session()
    self.session.headers.update({'X-Apikey': _API_KEY,
                                 'User-Agent': _DEFAULT_USER_AGENT})

  def monitor_api_hash_list(self, engine, cursor=None, limit=20):
    url = self.host + '/api/v3/monitor_partner/hashes'
    args = {'filter': 'engine:%s' % engine,
            'limit': limit,
            'cursor': cursor,
            'relationships': 'items'}

    for attempt in range(3):
      response = self.session.get(url, params=args)
      if response.status_code != 200:
        log.error('Response(api_hash_list) %d %s\n%s',
                  response.status_code, response.url, response.text)
      else:
        break

      if attempt == 3:
        log.error('Giving up on listing hashes for engine:"%s"', engine)
        return [], None

    cursor = response.json().get('meta', {}).get('cursor')
    return response.json().get('data', {}), cursor

  def enqueue(self, engine):
    cursor = None
    listing_number, hashes_number = 1, 0
    while self.running:
      log.info('Listing detected hashes engine:"%s" (page #%d)',
               engine, listing_number)
      data, cursor = self.monitor_api_hash_list(
          self.engine, cursor=cursor, limit=self.limit)

      if not data:
        break

      for monitor_hash in data:
        self.download_queue.put(monitor_hash)
        hashes_number += 1

      if not cursor:
        break

      listing_number += 1

      while self.running and self.download_queue.qsize() > 100:
        time.sleep(1)

    log.info('Enqueue finished %d hashes added', hashes_number)

  def run(self):
    if not self.engine:
      log.error('You have to provide an engine (param -e)')
      return

    self.running = True
    self.threads = []
    log.info('Starting %d parallel download threads', self.threads_number)
    for _ in range(self.threads_number):
      thread = FileDownloadThread(self.download_queue, **self.params)
      thread.daemon = True
      thread.start()
      self.threads.append({'thread': thread})

    self.enqueue(self.engine)

    while self.running:
      time.sleep(1)

      if (not self.download_queue.qsize() and
              not self.download_threads_processing()):
        break

  def download_threads_processing(self):
    for thread in self.threads:
      if thread['thread'].processing:
        return True
    return False

  def stop(self, unused_signum, unused_frame):
    self.running = False
    for thread in self.threads:
      thread['thread'].running = False


class FileDownloadThread(threading.Thread):

  def __init__(self, download_queue, **params):
    threading.Thread.__init__(self)
    self.download_queue = download_queue

    self.host = params.get('host')
    self.session = requests.Session()
    self.session.headers.update({
        'X-Apikey': params.get('apikey'),
        'User-Agent': params.get('user_agent')})
    self.destination = params.get('destination')
    self.resolver = params.get('resolver')
    self.folder_levels = params.get('folder_levels')

    self.running = True
    self.processing = False

    self.owner_hashes = {}

  def resolve(self, owner_id):
    return self.resolver.resolve(owner_id)

  def make_folders(self, base_folder, sha256):
    dst_path = base_folder
    for n in range(self.folder_levels):
      dst_path = os.path.join(dst_path, sha256[n])
    if not os.path.isdir(dst_path):
      try:
        os.makedirs(dst_path)
      except OSError:
        pass
    return os.path.join(dst_path, sha256)

  def download_hash(self, sha256, file_obj):
    sha256_download_url = (
        self.host + '/api/v3/monitor_partner/files/%s/download' % sha256)
    response = self.session.get(sha256_download_url, stream=True)
    for chunk in response.iter_content(chunk_size=100 * 1024):
      if chunk:
        file_obj.write(chunk)
    file_obj.flush()

  def run(self):
    while self.running:
      try:
        monitor_hash = self.download_queue.get(timeout=1)
      except Queue.Empty:
        continue

      self.processing = True
      sha256 = monitor_hash.get('attributes', {}).get('sha256')
      hash_destination = self.make_folders(self.destination, sha256)

      if not os.path.isfile(hash_destination):  # Hash do not need an update
        for _ in range(3):
          # log.info('Downloading hash "%s"', sha256)
          try:
            with open(hash_destination, 'wb') as file_obj:
              self.download_hash(sha256, file_obj)
          except:
            log.error('Failed download "%s"', sha256)
            continue
          finally:
            log.info('Finished hash "%s"', sha256)
          break

      organizations = []
      monitor_items = monitor_hash.get(
          'relationships', {}).get('items', {}).get('data', [])
      for item in monitor_items:
        owner_id = monitorid_ownerid(item['id'])
        organizations.append(self.resolver.organization(owner_id))
        self.resolver.add_hash(owner_id, sha256)

      with open(hash_destination + '.owners', 'w') as file_owners_obj:
        file_owners_obj.write(';'.join(organizations) + '\n')

      with open(hash_destination + '.json', 'w') as file_json_obj:
        file_json_obj.write(json.dumps(monitor_hash))

      process_fn(monitor_hash, monitor_items, organizations)

      time.sleep(0.1)
      self.processing = False


if __name__ == '__main__':
  if len(_API_KEY) < 64:
    autoupdate()
    sys.exit()

  parser = argparse.ArgumentParser(
      description='Monitor Partner file downloader')
  parser._action_groups.pop()
  required = parser.add_argument_group('Required arguments')
  optional = parser.add_argument_group('Optional arguments')
  required.add_argument(
      '-e', '--engine',
      help='Une engine name',
      dest='engine',
      action='store')
  optional.add_argument(
      '-d', '--destination',
      help=('Specify a directory where to store files, if not provided an '
            'vtmp.engine directory will be automatically created'),
      dest='destination',
      action='store')
  optional.add_argument(
      '-f', '--folder-levels',
      help=('Create file under FOLDER_LEVEL number of folders for example 2 '
            'equals /0/0/001234... path'),
      dest='folder_levels',
      action='store',
      default=1)
  optional.add_argument(
      '-t', '--threads',
      help='Use a number of threads to do simultaneous uploads',
      dest='threads',
      action='store',
      default=4)
  optional.add_argument(
      '-l', '--api-limit',
      help='Retrieve [LIMIT] results each time from API (Max: 100)',
      dest='limit',
      action='store',
      default=30)

  mp_downloader = MonitorPartnerDownloader(args=parser.parse_args())
  signal.signal(signal.SIGTERM, mp_downloader.stop)
  signal.signal(signal.SIGINT, mp_downloader.stop)
  mp_downloader.run()
