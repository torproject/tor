#!/usr/bin/python

# Usage: scripts/maint/updateFallbackDirs.py > src/or/fallback_dirs.inc
#
# Then read the generated list to ensure no-one slipped anything funny into
# their name or contactinfo

# Script by weasel, April 2015
# Portions by gsathya & karsten, 2013
# https://trac.torproject.org/projects/tor/attachment/ticket/8374/dir_list.2.py
# Modifications by teor, 2015

import StringIO
import string
import re
import datetime
import gzip
import os.path
import json
import math
import sys
import urllib
import urllib2
import hashlib
import dateutil.parser
# bson_lazy provides bson
#from bson import json_util

from stem.descriptor.remote import DescriptorDownloader

import logging
logging.basicConfig(level=logging.DEBUG)

## Top-Level Configuration

# Perform DirPort checks over IPv6?
# If you know IPv6 works for you, set this to True
PERFORM_IPV6_DIRPORT_CHECKS = False

# Output all candidate fallbacks, or only output selected fallbacks?
OUTPUT_CANDIDATES = False

## OnionOO Settings

ONIONOO = 'https://onionoo.torproject.org/'
#ONIONOO = 'https://onionoo.thecthulhu.com/'

# Don't bother going out to the Internet, just use the files available locally,
# even if they're very old
LOCAL_FILES_ONLY = False

## Whitelist / Blacklist Filter Settings

# The whitelist contains entries that are included if all attributes match
# (IPv4, dirport, orport, id, and optionally IPv6 and IPv6 orport)
# The blacklist contains (partial) entries that are excluded if any
# sufficiently specific group of attributes matches:
# IPv4 & DirPort
# IPv4 & ORPort
# ID
# IPv6 & DirPort
# IPv6 & IPv6 ORPort
# If neither port is included in the blacklist, the entire IP address is
# blacklisted.

# What happens to entries in neither list?
# When True, they are included, when False, they are excluded
INCLUDE_UNLISTED_ENTRIES = True if OUTPUT_CANDIDATES else False

# If an entry is in both lists, what happens?
# When True, it is excluded, when False, it is included
BLACKLIST_EXCLUDES_WHITELIST_ENTRIES = True

WHITELIST_FILE_NAME = 'scripts/maint/fallback.whitelist'
BLACKLIST_FILE_NAME = 'scripts/maint/fallback.blacklist'

# The number of bytes we'll read from a filter file before giving up
MAX_LIST_FILE_SIZE = 1024 * 1024

## Eligibility Settings

# Reduced due to a bug in tor where a relay submits a 0 DirPort when restarted
# This causes OnionOO to (correctly) reset its stability timer
# This issue is fixed in 0.2.7.7 and master.
# Until then, the CUTOFFs below ensure a decent level of stability.
ADDRESS_AND_PORT_STABLE_DAYS = 7
# What time-weighted-fraction of these flags must FallbackDirs
# Equal or Exceed?
CUTOFF_RUNNING = .95
CUTOFF_V2DIR = .95
CUTOFF_GUARD = .95
# What time-weighted-fraction of these flags must FallbackDirs
# Equal or Fall Under?
# .00 means no bad exits
PERMITTED_BADEXIT = .00

# Clients will time out after 30 seconds trying to download a consensus
# So allow fallback directories half that to deliver a consensus
# The exact download times might change based on the network connection
# running this script, but only by a few seconds
# There is also about a second of python overhead
CONSENSUS_DOWNLOAD_SPEED_MAX = 15.0
# If the relay fails a consensus check, retry the download
# This avoids delisting a relay due to transient network conditions
CONSENSUS_DOWNLOAD_RETRY = True

## List Length Limits

# The target for these parameters is 20% of the guards in the network
# This is around 200 as of October 2015
FALLBACK_PROPORTION_OF_GUARDS = None if OUTPUT_CANDIDATES else 0.2

# Limit the number of fallbacks (eliminating lowest by weight)
MAX_FALLBACK_COUNT = None if OUTPUT_CANDIDATES else 500
# Emit a C #error if the number of fallbacks is below
MIN_FALLBACK_COUNT = 50

## Fallback Weight Settings

# Any fallback with the Exit flag has its weight multipled by this fraction
EXIT_WEIGHT_FRACTION = 1.0

# If True, emit a C #error if we can't satisfy various constraints
# If False, emit a C comment instead
STRICT_FALLBACK_WEIGHTS = False

# Limit the proportional weight
# If a single fallback's weight is too high, it will see too many clients
# We reweight using a lower threshold to provide some leeway for:
# * elimination of low weight relays
# * consensus weight changes
# * fallback directory losses over time
# A relay weighted at 1 in 10 fallbacks will see about 10% of clients that
# use the fallback directories. (The 9 directory authorities see a similar
# proportion of clients.)
TARGET_MAX_WEIGHT_FRACTION = 1/10.0
REWEIGHTING_FUDGE_FACTOR = 0.8
MAX_WEIGHT_FRACTION = TARGET_MAX_WEIGHT_FRACTION * REWEIGHTING_FUDGE_FACTOR
# If a single fallback's weight is too low, it's pointless adding it.
# (Final weights may be slightly higher than this, due to low weight relays
# being excluded.)
# A relay weighted at 1 in 1000 fallbacks will see about 0.1% of clients.
MIN_WEIGHT_FRACTION = 0.0 if OUTPUT_CANDIDATES else 1/1000.0

## Other Configuration Parameters

# older entries' weights are adjusted with ALPHA^(age in days)
AGE_ALPHA = 0.99

# this factor is used to scale OnionOO entries to [0,1]
ONIONOO_SCALE_ONE = 999.

## Parsing Functions

def parse_ts(t):
  return datetime.datetime.strptime(t, "%Y-%m-%d %H:%M:%S")

def remove_bad_chars(raw_string, bad_char_list):
  # Remove each character in the bad_char_list
  escaped_string = raw_string
  for c in bad_char_list:
    escaped_string = escaped_string.replace(c, '')
  return escaped_string

def cleanse_whitespace(raw_string):
  # Replace all whitespace characters with a space
  escaped_string = raw_string
  for c in string.whitespace:
    escaped_string = escaped_string.replace(c, ' ')
  return escaped_string

def cleanse_c_multiline_comment(raw_string):
  # Prevent a malicious / unanticipated string from breaking out
  # of a C-style multiline comment
  # This removes '/*' and '*/'
  # To deal with '//', the end comment must be on its own line
  bad_char_list = '*'
  # Prevent a malicious string from using C nulls
  bad_char_list += '\0'
  # Be safer by removing bad characters entirely
  escaped_string = remove_bad_chars(raw_string, bad_char_list)
  # Embedded newlines should be removed by tor/onionoo, but let's be paranoid
  escaped_string = cleanse_whitespace(escaped_string)
  # Some compilers may further process the content of comments
  # There isn't much we can do to cover every possible case
  # But comment-based directives are typically only advisory
  return escaped_string

def cleanse_c_string(raw_string):
  # Prevent a malicious address/fingerprint string from breaking out
  # of a C-style string
  bad_char_list = '"'
  # Prevent a malicious string from using escapes
  bad_char_list += '\\'
  # Prevent a malicious string from using C nulls
  bad_char_list += '\0'
  # Be safer by removing bad characters entirely
  escaped_string = remove_bad_chars(raw_string, bad_char_list)
  # Embedded newlines should be removed by tor/onionoo, but let's be paranoid
  escaped_string = cleanse_whitespace(escaped_string)
  # Some compilers may further process the content of strings
  # There isn't much we can do to cover every possible case
  # But this typically only results in changes to the string data
  return escaped_string

## OnionOO Source Functions

# a dictionary of source metadata for each onionoo query we've made
fetch_source = {}

# register source metadata for 'what'
# assumes we only retrieve one document for each 'what'
def register_fetch_source(what, url, relays_published, version):
  fetch_source[what] = {}
  fetch_source[what]['url'] = url
  fetch_source[what]['relays_published'] = relays_published
  fetch_source[what]['version'] = version

# list each registered source's 'what'
def fetch_source_list():
  return sorted(fetch_source.keys())

# given 'what', provide a multiline C comment describing the source
def describe_fetch_source(what):
  desc = '/*'
  desc += '\n'
  desc += 'Onionoo Source: '
  desc += cleanse_c_multiline_comment(what)
  desc += ' Date: '
  desc += cleanse_c_multiline_comment(fetch_source[what]['relays_published'])
  desc += ' Version: '
  desc += cleanse_c_multiline_comment(fetch_source[what]['version'])
  desc += '\n'
  desc += 'URL: '
  desc += cleanse_c_multiline_comment(fetch_source[what]['url'])
  desc += '\n'
  desc += '*/'
  return desc

## File Processing Functions

def write_to_file(str, file_name, max_len):
  try:
    with open(file_name, 'w') as f:
      f.write(str[0:max_len])
  except EnvironmentError, error:
    logging.debug('Writing file %s failed: %d: %s'%
                  (file_name,
                   error.errno,
                   error.strerror)
                  )

def read_from_file(file_name, max_len):
  try:
    if os.path.isfile(file_name):
      with open(file_name, 'r') as f:
        return f.read(max_len)
  except EnvironmentError, error:
    logging.debug('Loading file %s failed: %d: %s'%
                  (file_name,
                   error.errno,
                   error.strerror)
                  )
  return None

def load_possibly_compressed_response_json(response):
    if response.info().get('Content-Encoding') == 'gzip':
      buf = StringIO.StringIO( response.read() )
      f = gzip.GzipFile(fileobj=buf)
      return json.load(f)
    else:
      return json.load(response)

def load_json_from_file(json_file_name):
    # An exception here may be resolved by deleting the .last_modified
    # and .json files, and re-running the script
    try:
      with open(json_file_name, 'r') as f:
        return json.load(f)
    except EnvironmentError, error:
      raise Exception('Reading not-modified json file %s failed: %d: %s'%
                    (json_file_name,
                     error.errno,
                     error.strerror)
                    )

## OnionOO Functions

def datestr_to_datetime(datestr):
  # Parse datetimes like: Fri, 02 Oct 2015 13:34:14 GMT
  if datestr is not None:
    dt = dateutil.parser.parse(datestr)
  else:
    # Never modified - use start of epoch
    dt = datetime.datetime.utcfromtimestamp(0)
  # strip any timezone out (in case they're supported in future)
  dt = dt.replace(tzinfo=None)
  return dt

def onionoo_fetch(what, **kwargs):
  params = kwargs
  params['type'] = 'relay'
  #params['limit'] = 10
  params['first_seen_days'] = '%d-'%(ADDRESS_AND_PORT_STABLE_DAYS,)
  params['last_seen_days'] = '-7'
  params['flag'] = 'V2Dir'
  url = ONIONOO + what + '?' + urllib.urlencode(params)

  # Unfortunately, the URL is too long for some OS filenames,
  # but we still don't want to get files from different URLs mixed up
  base_file_name = what + '-' + hashlib.sha1(url).hexdigest()

  full_url_file_name = base_file_name + '.full_url'
  MAX_FULL_URL_LENGTH = 1024

  last_modified_file_name = base_file_name + '.last_modified'
  MAX_LAST_MODIFIED_LENGTH = 64

  json_file_name = base_file_name + '.json'

  if LOCAL_FILES_ONLY:
    # Read from the local file, don't write to anything
    response_json = load_json_from_file(json_file_name)
  else:
    # store the full URL to a file for debugging
    # no need to compare as long as you trust SHA-1
    write_to_file(url, full_url_file_name, MAX_FULL_URL_LENGTH)

    request = urllib2.Request(url)
    request.add_header('Accept-encoding', 'gzip')

    # load the last modified date from the file, if it exists
    last_mod_date = read_from_file(last_modified_file_name,
                                   MAX_LAST_MODIFIED_LENGTH)
    if last_mod_date is not None:
      request.add_header('If-modified-since', last_mod_date)

    # Parse last modified date
    last_mod = datestr_to_datetime(last_mod_date)

    # Not Modified and still recent enough to be useful
    # Onionoo / Globe used to use 6 hours, but we can afford a day
    required_freshness = datetime.datetime.utcnow()
    # strip any timezone out (to match dateutil.parser)
    required_freshness = required_freshness.replace(tzinfo=None)
    required_freshness -= datetime.timedelta(hours=24)

    # Make the OnionOO request
    response_code = 0
    try:
      response = urllib2.urlopen(request)
      response_code = response.getcode()
    except urllib2.HTTPError, error:
      response_code = error.code
      if response_code == 304: # not modified
        pass
      else:
        raise Exception("Could not get " + url + ": "
                        + str(error.code) + ": " + error.reason)

    if response_code == 200: # OK
      last_mod = datestr_to_datetime(response.info().get('Last-Modified'))

    # Check for freshness
    if last_mod < required_freshness:
      if last_mod_date is not None:
        # This check sometimes fails transiently, retry the script if it does
        date_message = "Outdated data: last updated " + last_mod_date
      else:
        date_message = "No data: never downloaded "
      raise Exception(date_message + " from " + url)

    # Process the data
    if response_code == 200: # OK

      response_json = load_possibly_compressed_response_json(response)

      with open(json_file_name, 'w') as f:
        # use the most compact json representation to save space
        json.dump(response_json, f, separators=(',',':'))

      # store the last modified date in its own file
      if response.info().get('Last-modified') is not None:
        write_to_file(response.info().get('Last-Modified'),
                      last_modified_file_name,
                      MAX_LAST_MODIFIED_LENGTH)

    elif response_code == 304: # Not Modified

      response_json = load_json_from_file(json_file_name)

    else: # Unexpected HTTP response code not covered in the HTTPError above
      raise Exception("Unexpected HTTP response code to " + url + ": "
                      + str(response_code))

  register_fetch_source(what,
                        url,
                        response_json['relays_published'],
                        response_json['version'])

  return response_json

def fetch(what, **kwargs):
  #x = onionoo_fetch(what, **kwargs)
  # don't use sort_keys, as the order of or_addresses is significant
  #print json.dumps(x, indent=4, separators=(',', ': '))
  #sys.exit(0)

  return onionoo_fetch(what, **kwargs)

## Fallback Candidate Class

class Candidate(object):
  CUTOFF_ADDRESS_AND_PORT_STABLE = (datetime.datetime.utcnow()
                            - datetime.timedelta(ADDRESS_AND_PORT_STABLE_DAYS))

  def __init__(self, details):
    for f in ['fingerprint', 'nickname', 'last_changed_address_or_port',
              'consensus_weight', 'or_addresses', 'dir_address']:
      if not f in details: raise Exception("Document has no %s field."%(f,))

    if not 'contact' in details:
      details['contact'] = None
    if not 'flags' in details or details['flags'] is None:
      details['flags'] = []
    details['last_changed_address_or_port'] = parse_ts(
                                      details['last_changed_address_or_port'])
    self._data = details
    self._stable_sort_or_addresses()

    self._fpr = self._data['fingerprint']
    self._running = self._guard = self._v2dir = 0.
    self._split_dirport()
    self._compute_orport()
    if self.orport is None:
      raise Exception("Failed to get an orport for %s."%(self._fpr,))
    self._compute_ipv6addr()
    if self.ipv6addr is None:
      logging.debug("Failed to get an ipv6 address for %s."%(self._fpr,))
    # Reduce the weight of exits to EXIT_WEIGHT_FRACTION * consensus_weight
    if self.is_exit():
      current_weight = self._data['consensus_weight']
      exit_weight = current_weight * EXIT_WEIGHT_FRACTION
      self._data['original_consensus_weight'] = current_weight
      self._data['consensus_weight'] = exit_weight

  def _stable_sort_or_addresses(self):
    # replace self._data['or_addresses'] with a stable ordering,
    # sorting the secondary addresses in string order
    # leave the received order in self._data['or_addresses_raw']
    self._data['or_addresses_raw'] = self._data['or_addresses']
    or_address_primary = self._data['or_addresses'][:1]
    # subsequent entries in the or_addresses array are in an arbitrary order
    # so we stabilise the addresses by sorting them in string order
    or_addresses_secondaries_stable = sorted(self._data['or_addresses'][1:])
    or_addresses_stable = or_address_primary + or_addresses_secondaries_stable
    self._data['or_addresses'] = or_addresses_stable

  def get_fingerprint(self):
    return self._fpr

  # is_valid_ipv[46]_address by gsathya, karsten, 2013
  @staticmethod
  def is_valid_ipv4_address(address):
    if not isinstance(address, (str, unicode)):
      return False

    # check if there are four period separated values
    if address.count(".") != 3:
      return False

    # checks that each value in the octet are decimal values between 0-255
    for entry in address.split("."):
      if not entry.isdigit() or int(entry) < 0 or int(entry) > 255:
        return False
      elif entry[0] == "0" and len(entry) > 1:
        return False  # leading zeros, for instance in "1.2.3.001"

    return True

  @staticmethod
  def is_valid_ipv6_address(address):
    if not isinstance(address, (str, unicode)):
      return False

    # remove brackets
    address = address[1:-1]

    # addresses are made up of eight colon separated groups of four hex digits
    # with leading zeros being optional
    # https://en.wikipedia.org/wiki/IPv6#Address_format

    colon_count = address.count(":")

    if colon_count > 7:
      return False  # too many groups
    elif colon_count != 7 and not "::" in address:
      return False  # not enough groups and none are collapsed
    elif address.count("::") > 1 or ":::" in address:
      return False  # multiple groupings of zeros can't be collapsed

    found_ipv4_on_previous_entry = False
    for entry in address.split(":"):
      # If an IPv6 address has an embedded IPv4 address,
      # it must be the last entry
      if found_ipv4_on_previous_entry:
        return False
      if not re.match("^[0-9a-fA-f]{0,4}$", entry):
        if not Candidate.is_valid_ipv4_address(entry):
          return False
        else:
          found_ipv4_on_previous_entry = True

    return True

  def _split_dirport(self):
    # Split the dir_address into dirip and dirport
    (self.dirip, _dirport) = self._data['dir_address'].split(':', 2)
    self.dirport = int(_dirport)

  def _compute_orport(self):
    # Choose the first ORPort that's on the same IPv4 address as the DirPort.
    # In rare circumstances, this might not be the primary ORPort address.
    # However, _stable_sort_or_addresses() ensures we choose the same one
    # every time, even if onionoo changes the order of the secondaries.
    self._split_dirport()
    self.orport = None
    for i in self._data['or_addresses']:
      if i != self._data['or_addresses'][0]:
        logging.debug('Secondary IPv4 Address Used for %s: %s'%(self._fpr, i))
      (ipaddr, port) = i.rsplit(':', 1)
      if (ipaddr == self.dirip) and Candidate.is_valid_ipv4_address(ipaddr):
        self.orport = int(port)
        return

  def _compute_ipv6addr(self):
    # Choose the first IPv6 address that uses the same port as the ORPort
    # Or, choose the first IPv6 address in the list
    # _stable_sort_or_addresses() ensures we choose the same IPv6 address
    # every time, even if onionoo changes the order of the secondaries.
    self.ipv6addr = None
    self.ipv6orport = None
    # Choose the first IPv6 address that uses the same port as the ORPort
    for i in self._data['or_addresses']:
      (ipaddr, port) = i.rsplit(':', 1)
      if (port == self.orport) and Candidate.is_valid_ipv6_address(ipaddr):
        self.ipv6addr = ipaddr
        self.ipv6orport = port
        return
    # Choose the first IPv6 address in the list
    for i in self._data['or_addresses']:
      (ipaddr, port) = i.rsplit(':', 1)
      if Candidate.is_valid_ipv6_address(ipaddr):
        self.ipv6addr = ipaddr
        self.ipv6orport = port
        return

  @staticmethod
  def _extract_generic_history(history, which='unknown'):
    # given a tree like this:
    #   {
    #     "1_month": {
    #         "count": 187,
    #         "factor": 0.001001001001001001,
    #         "first": "2015-02-27 06:00:00",
    #         "interval": 14400,
    #         "last": "2015-03-30 06:00:00",
    #         "values": [
    #             999,
    #             999
    #         ]
    #     },
    #     "1_week": {
    #         "count": 169,
    #         "factor": 0.001001001001001001,
    #         "first": "2015-03-23 07:30:00",
    #         "interval": 3600,
    #         "last": "2015-03-30 07:30:00",
    #         "values": [ ...]
    #     },
    #     "1_year": {
    #         "count": 177,
    #         "factor": 0.001001001001001001,
    #         "first": "2014-04-11 00:00:00",
    #         "interval": 172800,
    #         "last": "2015-03-29 00:00:00",
    #         "values": [ ...]
    #     },
    #     "3_months": {
    #         "count": 185,
    #         "factor": 0.001001001001001001,
    #         "first": "2014-12-28 06:00:00",
    #         "interval": 43200,
    #         "last": "2015-03-30 06:00:00",
    #         "values": [ ...]
    #     }
    #   },
    # extract exactly one piece of data per time interval,
    # using smaller intervals where available.
    #
    # returns list of (age, length, value) dictionaries.

    generic_history = []

    periods = history.keys()
    periods.sort(key = lambda x: history[x]['interval'])
    now = datetime.datetime.utcnow()
    newest = now
    for p in periods:
      h = history[p]
      interval = datetime.timedelta(seconds = h['interval'])
      this_ts = parse_ts(h['last'])

      if (len(h['values']) != h['count']):
        logging.warn('Inconsistent value count in %s document for %s'
                     %(p, which))
      for v in reversed(h['values']):
        if (this_ts <= newest):
          agt1 = now - this_ts
          agt2 = interval
          agetmp1 = (agt1.microseconds + (agt1.seconds + agt1.days * 24 * 3600)
                     * 10**6) / 10**6
          agetmp2 = (agt2.microseconds + (agt2.seconds + agt2.days * 24 * 3600)
                     * 10**6) / 10**6
          generic_history.append(
            { 'age': agetmp1,
              'length': agetmp2,
              'value': v
            })
          newest = this_ts
        this_ts -= interval

      if (this_ts + interval != parse_ts(h['first'])):
        logging.warn('Inconsistent time information in %s document for %s'
                     %(p, which))

    #print json.dumps(generic_history, sort_keys=True,
    #                  indent=4, separators=(',', ': '))
    return generic_history

  @staticmethod
  def _avg_generic_history(generic_history):
    a = []
    for i in generic_history:
      if i['age'] > (ADDRESS_AND_PORT_STABLE_DAYS * 24 * 3600):
        continue
      if (i['length'] is not None
          and i['age'] is not None
          and i['value'] is not None):
        w = i['length'] * math.pow(AGE_ALPHA, i['age']/(3600*24))
        a.append( (i['value'] * w, w) )

    sv = math.fsum(map(lambda x: x[0], a))
    sw = math.fsum(map(lambda x: x[1], a))

    if sw == 0.0:
      svw = 0.0
    else:
      svw = sv/sw
    return svw

  def _add_generic_history(self, history):
    periods = r['read_history'].keys()
    periods.sort(key = lambda x: r['read_history'][x]['interval'] )

    print periods

  def add_running_history(self, history):
    pass

  def add_uptime(self, uptime):
    logging.debug('Adding uptime %s.'%(self._fpr,))

    # flags we care about: Running, V2Dir, Guard
    if not 'flags' in uptime:
      logging.debug('No flags in document for %s.'%(self._fpr,))
      return

    for f in ['Running', 'Guard', 'V2Dir']:
      if not f in uptime['flags']:
        logging.debug('No %s in flags for %s.'%(f, self._fpr,))
        return

    running = self._extract_generic_history(uptime['flags']['Running'],
                                            '%s-Running'%(self._fpr))
    guard = self._extract_generic_history(uptime['flags']['Guard'],
                                          '%s-Guard'%(self._fpr))
    v2dir = self._extract_generic_history(uptime['flags']['V2Dir'],
                                          '%s-V2Dir'%(self._fpr))
    if 'BadExit' in uptime['flags']:
      badexit = self._extract_generic_history(uptime['flags']['BadExit'],
                                              '%s-BadExit'%(self._fpr))

    self._running = self._avg_generic_history(running) / ONIONOO_SCALE_ONE
    self._guard = self._avg_generic_history(guard) / ONIONOO_SCALE_ONE
    self._v2dir = self._avg_generic_history(v2dir) / ONIONOO_SCALE_ONE
    self._badexit = None
    if 'BadExit' in uptime['flags']:
      self._badexit = self._avg_generic_history(badexit) / ONIONOO_SCALE_ONE

  def is_candidate(self):
    if (self._data['last_changed_address_or_port'] >
        self.CUTOFF_ADDRESS_AND_PORT_STABLE):
      logging.debug('%s not a candidate: changed address/port recently (%s)',
        self._fpr, self._data['last_changed_address_or_port'])
      return False
    if self._running < CUTOFF_RUNNING:
      logging.debug('%s not a candidate: running avg too low (%lf)',
                    self._fpr, self._running)
      return False
    if self._v2dir < CUTOFF_V2DIR:
      logging.debug('%s not a candidate: v2dir avg too low (%lf)',
                    self._fpr, self._v2dir)
      return False
    if self._badexit is not None and self._badexit > PERMITTED_BADEXIT:
      logging.debug('%s not a candidate: badexit avg too high (%lf)',
                    self._fpr, self._badexit)
      return False
    # if the relay doesn't report a version, also exclude the relay
    if (not self._data.has_key('recommended_version')
        or not self._data['recommended_version']):
      return False
    if self._guard < CUTOFF_GUARD:
      logging.debug('%s not a candidate: guard avg too low (%lf)',
                    self._fpr, self._guard)
      return False
    return True

  def is_in_whitelist(self, relaylist):
    """ A fallback matches if each key in the whitelist line matches:
          ipv4
          dirport
          orport
          id
          ipv6 address and port (if present)
        If the fallback has an ipv6 key, the whitelist line must also have
        it, and vice versa, otherwise they don't match. """
    for entry in relaylist:
      if entry['ipv4'] != self.dirip:
        continue
      if int(entry['dirport']) != self.dirport:
        continue
      if int(entry['orport']) != self.orport:
        continue
      if  entry['id'] != self._fpr:
        continue
      if (entry.has_key('ipv6')
          and self.ipv6addr is not None and self.ipv6orport is not None):
        # if both entry and fallback have an ipv6 address, compare them
        if entry['ipv6'] != self.ipv6addr + ':' + self.ipv6orport:
          continue
      # if the fallback has an IPv6 address but the whitelist entry
      # doesn't, or vice versa, the whitelist entry doesn't match
      elif entry.has_key('ipv6') and self.ipv6addr is None:
        continue
      elif not entry.has_key('ipv6') and self.ipv6addr is not None:
        continue
      return True
    return False

  def is_in_blacklist(self, relaylist):
    """ A fallback matches a blacklist line if a sufficiently specific group
        of attributes matches:
          ipv4 & dirport
          ipv4 & orport
          id
          ipv6 & dirport
          ipv6 & ipv6 orport
        If the fallback and the blacklist line both have an ipv6 key,
        their values will be compared, otherwise, they will be ignored.
        If there is no dirport and no orport, the entry matches all relays on
        that ip. """
    for entry in relaylist:
      for key in entry:
        value = entry[key]
        if key == 'ipv4' and value == self.dirip:
          # if the dirport is present, check it too
          if entry.has_key('dirport'):
            if int(entry['dirport']) == self.dirport:
              return True
          # if the orport is present, check it too
          elif entry.has_key('orport'):
            if int(entry['orport']) == self.orport:
              return True
          else:
            return True
        if key == 'id' and value == self._fpr:
          return True
        if (key == 'ipv6'
            and self.ipv6addr is not None and self.ipv6orport is not None):
        # if both entry and fallback have an ipv6 address, compare them,
        # otherwise, disregard ipv6 addresses
          if value == self.ipv6addr + ':' + self.ipv6orport:
            # if the dirport is present, check it too
            if entry.has_key('dirport'):
              if int(entry['dirport']) == self.dirport:
                return True
            # if the orport is present, check it too
            elif entry.has_key('orport'):
              if int(entry['orport']) == self.orport:
                return True
            else:
              return True
    return False

  def is_exit(self):
    return 'Exit' in self._data['flags']

  def is_guard(self):
    return 'Guard' in self._data['flags']

  def fallback_weight_fraction(self, total_weight):
    return float(self._data['consensus_weight']) / total_weight

  # return the original consensus weight, if it exists,
  # or, if not, return the consensus weight
  def original_consensus_weight(self):
    if self._data.has_key('original_consensus_weight'):
      return self._data['original_consensus_weight']
    else:
      return self._data['consensus_weight']

  def original_fallback_weight_fraction(self, total_weight):
    return float(self.original_consensus_weight()) / total_weight

  @staticmethod
  def fallback_consensus_dl_speed(dirip, dirport, nickname, max_time):
    downloader = DescriptorDownloader()
    start = datetime.datetime.utcnow()
    # there appears to be about 1 second of overhead when comparing stem's
    # internal trace time and the elapsed time calculated here
    downloader.get_consensus(endpoints = [(dirip, dirport)]).run()
    elapsed = (datetime.datetime.utcnow() - start).total_seconds()
    if elapsed > max_time:
      status = 'too slow'
    else:
      status = 'ok'
    logging.debug(('Consensus download: %0.2fs %s from %s (%s:%d), '
                   + 'max download time %0.2fs.') % (elapsed, status,
                                                     nickname, dirip, dirport,
                                                     max_time))
    return elapsed

  def fallback_consensus_dl_check(self):
    ipv4_speed = Candidate.fallback_consensus_dl_speed(self.dirip,
                                                self.dirport,
                                                self._data['nickname'],
                                                CONSENSUS_DOWNLOAD_SPEED_MAX)
    if self.ipv6addr is not None and PERFORM_IPV6_DIRPORT_CHECKS:
      # Clients assume the IPv6 DirPort is the same as the IPv4 DirPort
      ipv6_speed = Candidate.fallback_consensus_dl_speed(self.ipv6addr,
                                                self.dirport,
                                                self._data['nickname'],
                                                CONSENSUS_DOWNLOAD_SPEED_MAX)
    else:
      ipv6_speed = None
    # Now retry the relay if it took too long the first time
    if (ipv4_speed > CONSENSUS_DOWNLOAD_SPEED_MAX
        and CONSENSUS_DOWNLOAD_RETRY):
      ipv4_speed = Candidate.fallback_consensus_dl_speed(self.dirip,
                                                self.dirport,
                                                self._data['nickname'],
                                                CONSENSUS_DOWNLOAD_SPEED_MAX)
    if (self.ipv6addr is not None and PERFORM_IPV6_DIRPORT_CHECKS
        and ipv6_speed > CONSENSUS_DOWNLOAD_SPEED_MAX
        and CONSENSUS_DOWNLOAD_RETRY):
      ipv6_speed = Candidate.fallback_consensus_dl_speed(self.ipv6addr,
                                                self.dirport,
                                                self._data['nickname'],
                                                CONSENSUS_DOWNLOAD_SPEED_MAX)

    return (ipv4_speed <= CONSENSUS_DOWNLOAD_SPEED_MAX
            and (not PERFORM_IPV6_DIRPORT_CHECKS
                 or ipv6_speed <= CONSENSUS_DOWNLOAD_SPEED_MAX))

  def fallbackdir_line(self, total_weight, original_total_weight, dl_speed_ok):
    # /*
    # nickname
    # flags
    # weight / total (percentage)
    # [original weight / original total (original percentage)]
    # [contact]
    # */
    # "address:dirport orport=port id=fingerprint"
    # "[ipv6=addr:orport]"
    # "weight=num",
    #
    # Multiline C comment
    s = '/*'
    s += '\n'
    s += cleanse_c_multiline_comment(self._data['nickname'])
    s += '\n'
    s += 'Flags: '
    s += cleanse_c_multiline_comment(' '.join(sorted(self._data['flags'])))
    s += '\n'
    weight = self._data['consensus_weight']
    percent_weight = self.fallback_weight_fraction(total_weight)*100
    s += 'Fallback Weight: %d / %d (%.3f%%)'%(weight, total_weight,
                                              percent_weight)
    s += '\n'
    o_weight = self.original_consensus_weight()
    if o_weight != weight:
      o_percent_weight = self.original_fallback_weight_fraction(
                                                     original_total_weight)*100
      s += 'Consensus Weight: %d / %d (%.3f%%)'%(o_weight,
                                                 original_total_weight,
                                                 o_percent_weight)
      s += '\n'
    if self._data['contact'] is not None:
      s += cleanse_c_multiline_comment(self._data['contact'])
      s += '\n'
    s += '*/'
    s += '\n'
    # Comment out the fallback directory entry if it's too slow
    # See the debug output for which address and port is failing
    if not dl_speed_ok:
      s += '/* Consensus download failed or was too slow:\n'
    # Multi-Line C string with trailing comma (part of a string list)
    # This makes it easier to diff the file, and remove IPv6 lines using grep
    # Integers don't need escaping
    s += '"%s orport=%d id=%s"'%(
            cleanse_c_string(self._data['dir_address']),
            self.orport,
            cleanse_c_string(self._fpr))
    s += '\n'
    if self.ipv6addr is not None:
      s += '" ipv6=%s:%s"'%(
            cleanse_c_string(self.ipv6addr), cleanse_c_string(self.ipv6orport))
      s += '\n'
    s += '" weight=%d",'%(weight)
    if not dl_speed_ok:
      s += '\n'
      s += '*/'
    return s

## Fallback Candidate List Class

class CandidateList(dict):
  def __init__(self):
    pass

  def _add_relay(self, details):
    if not 'dir_address' in details: return
    c = Candidate(details)
    self[ c.get_fingerprint() ] = c

  def _add_uptime(self, uptime):
    try:
      fpr = uptime['fingerprint']
    except KeyError:
      raise Exception("Document has no fingerprint field.")

    try:
      c = self[fpr]
    except KeyError:
      logging.debug('Got unknown relay %s in uptime document.'%(fpr,))
      return

    c.add_uptime(uptime)

  def _add_details(self):
    logging.debug('Loading details document.')
    d = fetch('details',
        fields=('fingerprint,nickname,contact,last_changed_address_or_port,' +
                'consensus_weight,or_addresses,dir_address,' +
                'recommended_version,flags'))
    logging.debug('Loading details document done.')

    if not 'relays' in d: raise Exception("No relays found in document.")

    for r in d['relays']: self._add_relay(r)

  def _add_uptimes(self):
    logging.debug('Loading uptime document.')
    d = fetch('uptime')
    logging.debug('Loading uptime document done.')

    if not 'relays' in d: raise Exception("No relays found in document.")
    for r in d['relays']: self._add_uptime(r)

  def add_relays(self):
    self._add_details()
    self._add_uptimes()

  def count_guards(self):
    guard_count = 0
    for fpr in self.keys():
      if self[fpr].is_guard():
        guard_count += 1
    return guard_count

  # Find fallbacks that fit the uptime, stability, and flags criteria
  def compute_fallbacks(self):
    self.fallbacks = map(lambda x: self[x],
                      sorted(
                        filter(lambda x: self[x].is_candidate(),
                               self.keys()),
                        key=lambda x: self[x]._data['consensus_weight'],
                        reverse=True)
                      )

  @staticmethod
  def load_relaylist(file_name):
    """ Read each line in the file, and parse it like a FallbackDir line:
        an IPv4 address and optional port:
          <IPv4 address>:<port>
        which are parsed into dictionary entries:
          ipv4=<IPv4 address>
          dirport=<port>
        followed by a series of key=value entries:
          orport=<port>
          id=<fingerprint>
          ipv6=<IPv6 address>:<IPv6 orport>
        each line's key/value pairs are placed in a dictonary,
        (of string -> string key/value pairs),
        and these dictionaries are placed in an array.
        comments start with # and are ignored """
    relaylist = []
    file_data = read_from_file(file_name, MAX_LIST_FILE_SIZE)
    if file_data is None:
      return relaylist
    for line in file_data.split('\n'):
      relay_entry = {}
      # ignore comments
      line_comment_split = line.split('#')
      line = line_comment_split[0]
      # cleanup whitespace
      line = cleanse_whitespace(line)
      line = line.strip()
      if len(line) == 0:
        continue
      for item in line.split(' '):
        item = item.strip()
        if len(item) == 0:
          continue
        key_value_split = item.split('=')
        kvl = len(key_value_split)
        if kvl < 1 or kvl > 2:
          print '#error Bad %s item: %s, format is key=value.'%(
                                                 file_name, item)
        if kvl == 1:
          # assume that entries without a key are the ipv4 address,
          # perhaps with a dirport
          ipv4_maybe_dirport = key_value_split[0]
          ipv4_maybe_dirport_split = ipv4_maybe_dirport.split(':')
          dirl = len(ipv4_maybe_dirport_split)
          if dirl < 1 or dirl > 2:
            print '#error Bad %s IPv4 item: %s, format is ipv4:port.'%(
                                                        file_name, item)
          if dirl >= 1:
            relay_entry['ipv4'] = ipv4_maybe_dirport_split[0]
          if dirl == 2:
            relay_entry['dirport'] = ipv4_maybe_dirport_split[1]
        elif kvl == 2:
          relay_entry[key_value_split[0]] = key_value_split[1]
      relaylist.append(relay_entry)
    return relaylist

  # apply the fallback whitelist and blacklist
  def apply_filter_lists(self):
    excluded_count = 0
    logging.debug('Applying whitelist and blacklist.')
    # parse the whitelist and blacklist
    whitelist = self.load_relaylist(WHITELIST_FILE_NAME)
    blacklist = self.load_relaylist(BLACKLIST_FILE_NAME)
    filtered_fallbacks = []
    for f in self.fallbacks:
      in_whitelist = f.is_in_whitelist(whitelist)
      in_blacklist = f.is_in_blacklist(blacklist)
      if in_whitelist and in_blacklist:
        if BLACKLIST_EXCLUDES_WHITELIST_ENTRIES:
          # exclude
          excluded_count += 1
          logging.debug('Excluding %s: in both blacklist and whitelist.' %
                        f._fpr)
        else:
          # include
          filtered_fallbacks.append(f)
      elif in_whitelist:
        # include
        filtered_fallbacks.append(f)
      elif in_blacklist:
        # exclude
        excluded_count += 1
        logging.debug('Excluding %s: in blacklist.' %
                      f._fpr)
      else:
        if INCLUDE_UNLISTED_ENTRIES:
          # include
          filtered_fallbacks.append(f)
        else:
          # exclude
          excluded_count += 1
          logging.debug('Excluding %s: in neither blacklist nor whitelist.' %
                        f._fpr)
    self.fallbacks = filtered_fallbacks
    return excluded_count

  @staticmethod
  def summarise_filters(initial_count, excluded_count):
    return '/* Whitelist & blacklist excluded %d of %d candidates. */'%(
                                                excluded_count, initial_count)

  # Remove any fallbacks in excess of MAX_FALLBACK_COUNT,
  # starting with the lowest-weighted fallbacks
  # total_weight should be recalculated after calling this
  def exclude_excess_fallbacks(self):
    if MAX_FALLBACK_COUNT is not None:
      self.fallbacks = self.fallbacks[:MAX_FALLBACK_COUNT]

  # Clamp the weight of all fallbacks to MAX_WEIGHT_FRACTION * total_weight
  # fallbacks are kept sorted, but since excessive weights are reduced to
  # the maximum acceptable weight, these relays end up with equal weights
  def clamp_high_weight_fallbacks(self, total_weight):
    if MAX_WEIGHT_FRACTION * len(self.fallbacks) < 1.0:
      error_str  = 'Max Fallback Weight %.3f%% is unachievable'%(
                                                          MAX_WEIGHT_FRACTION)
      error_str += ' with Current Fallback Count %d.'%(len(self.fallbacks))
      if STRICT_FALLBACK_WEIGHTS:
        print '#error ' + error_str
      else:
        print '/* ' + error_str + ' */'
    relays_clamped = 0
    max_acceptable_weight = total_weight * MAX_WEIGHT_FRACTION
    for f in self.fallbacks:
      frac_weight = f.fallback_weight_fraction(total_weight)
      if frac_weight > MAX_WEIGHT_FRACTION:
        relays_clamped += 1
        current_weight = f._data['consensus_weight']
        # if we already have an original weight, keep it
        if (not f._data.has_key('original_consensus_weight')
            or f._data['original_consensus_weight'] == current_weight):
          f._data['original_consensus_weight'] = current_weight
        f._data['consensus_weight'] = max_acceptable_weight
    return relays_clamped

  # Remove any fallbacks with weights lower than MIN_WEIGHT_FRACTION
  # total_weight should be recalculated after calling this
  def exclude_low_weight_fallbacks(self, total_weight):
    self.fallbacks = filter(
            lambda x:
             x.fallback_weight_fraction(total_weight) >= MIN_WEIGHT_FRACTION,
             self.fallbacks)

  def fallback_weight_total(self):
    return sum(f._data['consensus_weight'] for f in self.fallbacks)

  def fallback_min_weight(self):
    if len(self.fallbacks) > 0:
      return self.fallbacks[-1]
    else:
      return None

  def fallback_max_weight(self):
    if len(self.fallbacks) > 0:
      return self.fallbacks[0]
    else:
      return None

  def summarise_fallbacks(self, eligible_count, eligible_weight,
                          relays_clamped, clamped_weight,
                          guard_count, target_count, max_count):
    # Report:
    #  the number of fallback directories (with min & max limits);
    #    #error if below minimum count
    #  the total weight, min & max fallback proportions
    #    #error if outside max weight proportion
    # Multiline C comment with #error if things go bad
    s = '/*'
    s += '\n'
    s += 'Fallback Directory Summary'
    s += '\n'
    # Integers don't need escaping in C comments
    fallback_count = len(self.fallbacks)
    if FALLBACK_PROPORTION_OF_GUARDS is None:
      fallback_proportion = ''
    else:
      fallback_proportion = ' (%d * %f)'%(guard_count,
                                          FALLBACK_PROPORTION_OF_GUARDS)
    s += 'Final Count:  %d (Eligible %d, Usable %d, Target %d%s'%(
            min(max_count, fallback_count),
            eligible_count,
            fallback_count,
            target_count,
            fallback_proportion)
    if MAX_FALLBACK_COUNT is not None:
      s += ', Clamped to %d'%(MAX_FALLBACK_COUNT)
    s += ')\n'
    if fallback_count < MIN_FALLBACK_COUNT:
      s += '*/'
      s += '\n'
      # We must have a minimum number of fallbacks so they are always
      # reachable, and are in diverse locations
      s += '#error Fallback Count %d is too low. '%(fallback_count)
      s += 'Must be at least %d for diversity. '%(MIN_FALLBACK_COUNT)
      s += 'Try adding entries to the whitelist, '
      s += 'or setting INCLUDE_UNLISTED_ENTRIES = True.'
      s += '\n'
      s += '/*'
      s += '\n'
    total_weight = self.fallback_weight_total()
    min_fb = self.fallback_min_weight()
    min_weight = min_fb._data['consensus_weight']
    min_percent = min_fb.fallback_weight_fraction(total_weight)*100.0
    max_fb = self.fallback_max_weight()
    max_weight = max_fb._data['consensus_weight']
    max_frac = max_fb.fallback_weight_fraction(total_weight)
    max_percent = max_frac*100.0
    s += 'Final Weight: %d (Eligible %d)'%(total_weight, eligible_weight)
    s += '\n'
    s += 'Max Weight:   %d (%.3f%%) (Clamped to %.3f%%)'%(
                                                max_weight,
                                                max_percent,
                                                TARGET_MAX_WEIGHT_FRACTION*100)
    s += '\n'
    s += 'Min Weight:   %d (%.3f%%) (Clamped to %.3f%%)'%(
                                                min_weight,
                                                min_percent,
                                                MIN_WEIGHT_FRACTION*100)
    s += '\n'
    if eligible_count != fallback_count:
      s += 'Excluded:     %d (Clamped, Below Target, or Low Weight)'%(
                                              eligible_count - fallback_count)
      s += '\n'
    if relays_clamped > 0:
      s += 'Clamped:   %d (%.3f%%) Excess Weight, '%(
                                    clamped_weight,
                                    (100.0 * clamped_weight) / total_weight)
      s += '%d High Weight Fallbacks (%.1f%%)'%(
                                    relays_clamped,
                                    (100.0 * relays_clamped) / fallback_count)
      s += '\n'
    s += '*/'
    if max_frac > TARGET_MAX_WEIGHT_FRACTION:
      s += '\n'
      # We must restrict the maximum fallback weight, so an adversary
      # at or near the fallback doesn't see too many clients
      error_str  = 'Max Fallback Weight %.3f%% is too high. '%(max_frac*100)
      error_str += 'Must be at most %.3f%% for client anonymity.'%(
                                              TARGET_MAX_WEIGHT_FRACTION*100)
      if STRICT_FALLBACK_WEIGHTS:
        s += '#error ' + error_str
      else:
        s += '/* ' + error_str + ' */'
    return s

## Main Function

def list_fallbacks():
  """ Fetches required onionoo documents and evaluates the
      fallback directory criteria for each of the relays """

  candidates = CandidateList()
  candidates.add_relays()

  guard_count = candidates.count_guards()
  if FALLBACK_PROPORTION_OF_GUARDS is None:
    target_count = guard_count
  else:
    target_count = int(guard_count * FALLBACK_PROPORTION_OF_GUARDS)
  # the maximum number of fallbacks is the least of:
  # - the target fallback count (FALLBACK_PROPORTION_OF_GUARDS * guard count)
  # - the maximum fallback count (MAX_FALLBACK_COUNT)
  if MAX_FALLBACK_COUNT is None:
    max_count = guard_count
  else:
    max_count = min(target_count, MAX_FALLBACK_COUNT)

  candidates.compute_fallbacks()

  initial_count = len(candidates.fallbacks)
  excluded_count = candidates.apply_filter_lists()
  print candidates.summarise_filters(initial_count, excluded_count)

  eligible_count = len(candidates.fallbacks)
  eligible_weight = candidates.fallback_weight_total()

  # print the raw fallback list
  #total_weight = candidates.fallback_weight_total()
  #for x in candidates.fallbacks:
  #  print x.fallbackdir_line(total_weight, total_weight)

  # When candidates are excluded, total_weight decreases, and
  # the proportional weight of other candidates increases.
  candidates.exclude_excess_fallbacks()
  total_weight = candidates.fallback_weight_total()

  # When candidates are reweighted, total_weight decreases, and
  # the proportional weight of other candidates increases.
  # Previously low-weight candidates might obtain sufficient proportional
  # weights to be included.
  # Save the weight at which we reweighted fallbacks for the summary.
  pre_clamp_total_weight = total_weight
  relays_clamped = candidates.clamp_high_weight_fallbacks(total_weight)

  # When candidates are excluded, total_weight decreases, and
  # the proportional weight of other candidates increases.
  # No new low weight candidates will be created during exclusions.
  # However, high weight candidates may increase over the maximum proportion.
  # This should not be an issue, except in pathological cases.
  candidates.exclude_low_weight_fallbacks(total_weight)
  total_weight = candidates.fallback_weight_total()

  # check we haven't exceeded TARGET_MAX_WEIGHT_FRACTION
  # since reweighting preserves the orginal sort order,
  # the maximum weights will be at the head of the list
  if len(candidates.fallbacks) > 0:
    max_weight_fb = candidates.fallback_max_weight()
    max_weight = max_weight_fb.fallback_weight_fraction(total_weight)
    if  max_weight > TARGET_MAX_WEIGHT_FRACTION:
      error_str  = 'Maximum fallback weight: %.3f%% exceeds target %.3f%%. '%(
                                              max_weight*100.0,
                                              TARGET_MAX_WEIGHT_FRACTION*100.0)
      error_str += 'Try decreasing REWEIGHTING_FUDGE_FACTOR.'
      if STRICT_FALLBACK_WEIGHTS:
        print '#error ' + error_str
      else:
        print '/* ' + error_str + ' */'

    print candidates.summarise_fallbacks(eligible_count, eligible_weight,
                                         relays_clamped,
                                         pre_clamp_total_weight - total_weight,
                                         guard_count, target_count, max_count)
  else:
    print '/* No Fallbacks met criteria */'

  for s in fetch_source_list():
    print describe_fetch_source(s)

  for x in candidates.fallbacks[:max_count]:
    dl_speed_ok = x.fallback_consensus_dl_check()
    print x.fallbackdir_line(total_weight, pre_clamp_total_weight, dl_speed_ok)
    #print json.dumps(candidates[x]._data, sort_keys=True, indent=4,
    #                  separators=(',', ': '), default=json_util.default)

if __name__ == "__main__":
  list_fallbacks()
