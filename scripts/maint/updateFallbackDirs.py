#!/usr/bin/python

# Usage:
#
# Regenerate the list:
# scripts/maint/updateFallbackDirs.py > src/or/fallback_dirs.inc
#
# Check the existing list:
# scripts/maint/updateFallbackDirs.py check_existing > fallback_dirs.inc.ok
# mv fallback_dirs.inc.ok src/or/fallback_dirs.inc
#
# This script should be run from a stable, reliable network connection,
# with no other network activity (and not over tor).
# If this is not possible, please disable:
# PERFORM_IPV4_DIRPORT_CHECKS and PERFORM_IPV6_DIRPORT_CHECKS
#
# Needs dateutil (and potentially other python packages)
# Needs stem available in your PYTHONPATH, or just ln -s ../stem/stem .
# Optionally uses ipaddress (python 3 builtin) or py2-ipaddress (package)
# for netblock analysis, in PYTHONPATH, or just
# ln -s ../py2-ipaddress-3.4.1/ipaddress.py .
#
# Then read the logs to make sure the fallbacks aren't dominated by a single
# netblock or port

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
import copy
import re

from stem.descriptor import DocumentHandler
from stem.descriptor.remote import get_consensus

import logging
logging.root.name = ''

HAVE_IPADDRESS = False
try:
  # python 3 builtin, or install package py2-ipaddress
  # there are several ipaddress implementations for python 2
  # with slightly different semantics with str typed text
  # fortunately, all our IP addresses are in unicode
  import ipaddress
  HAVE_IPADDRESS = True
except ImportError:
  # if this happens, we avoid doing netblock analysis
  logging.warning('Unable to import ipaddress, please install py2-ipaddress.' +
                  ' A fallback list will be created, but optional netblock' +
                  ' analysis will not be performed.')

## Top-Level Configuration

# Output all candidate fallbacks, or only output selected fallbacks?
OUTPUT_CANDIDATES = False

# Perform DirPort checks over IPv4?
# Change this to False if IPv4 doesn't work for you, or if you don't want to
# download a consensus for each fallback
# Don't check ~1000 candidates when OUTPUT_CANDIDATES is True
PERFORM_IPV4_DIRPORT_CHECKS = False if OUTPUT_CANDIDATES else True

# Perform DirPort checks over IPv6?
# If you know IPv6 works for you, set this to True
# This will exclude IPv6 relays without an IPv6 DirPort configured
# So it's best left at False until #18394 is implemented
# Don't check ~1000 candidates when OUTPUT_CANDIDATES is True
PERFORM_IPV6_DIRPORT_CHECKS = False if OUTPUT_CANDIDATES else False

# Must relays be running now?
MUST_BE_RUNNING_NOW = (PERFORM_IPV4_DIRPORT_CHECKS
                       or PERFORM_IPV6_DIRPORT_CHECKS)

# Clients have been using microdesc consensuses by default for a while now
DOWNLOAD_MICRODESC_CONSENSUS = True

# If a relay delivers an expired consensus, if it expired less than this many
# seconds ago, we still allow the relay. This should never be less than -90,
# as all directory mirrors should have downloaded a consensus 90 minutes
# before it expires. It should never be more than 24 hours, because clients
# reject consensuses that are older than REASONABLY_LIVE_TIME.
# For the consensus expiry check to be accurate, the machine running this
# script needs an accurate clock.
# We use 24 hours to compensate for #20909, where relays on 0.2.9.5-alpha and
# 0.3.0.0-alpha-dev and later deliver stale consensuses, but typically recover
# after ~12 hours.
# We should make this lower when #20909 is fixed, see #20942.
CONSENSUS_EXPIRY_TOLERANCE = 24*60*60

# Output fallback name, flags, bandwidth, and ContactInfo in a C comment?
OUTPUT_COMMENTS = True if OUTPUT_CANDIDATES else False

# Output matching ContactInfo in fallbacks list or the blacklist?
# Useful if you're trying to contact operators
CONTACT_COUNT = True if OUTPUT_CANDIDATES else False
CONTACT_BLACKLIST_COUNT = True if OUTPUT_CANDIDATES else False

# How the list should be sorted:
# fingerprint: is useful for stable diffs of fallback lists
# measured_bandwidth: is useful when pruning the list based on bandwidth
# contact: is useful for contacting operators once the list has been pruned
OUTPUT_SORT_FIELD = 'contact' if OUTPUT_CANDIDATES else 'fingerprint'

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
FALLBACK_FILE_NAME  = 'src/or/fallback_dirs.inc'

# The number of bytes we'll read from a filter file before giving up
MAX_LIST_FILE_SIZE = 1024 * 1024

## Eligibility Settings

# Require fallbacks to have the same address and port for a set amount of time
# We used to have this at 1 week, but that caused many fallback failures, which
# meant that we had to rebuild the list more often.
#
# There was a bug in Tor 0.2.8.1-alpha and earlier where a relay temporarily
# submits a 0 DirPort when restarted.
# This causes OnionOO to (correctly) reset its stability timer.
# Affected relays should upgrade to Tor 0.2.8.7 or later, which has a fix
# for this issue.
ADDRESS_AND_PORT_STABLE_DAYS = 30
# We ignore relays that have been down for more than this period
MAX_DOWNTIME_DAYS = 0 if MUST_BE_RUNNING_NOW else 7
# What time-weighted-fraction of these flags must FallbackDirs
# Equal or Exceed?
CUTOFF_RUNNING = .90
CUTOFF_V2DIR = .90
# Tolerate lower guard flag averages, as guard flags are removed for some time
# after a relay restarts
CUTOFF_GUARD = .80
# What time-weighted-fraction of these flags must FallbackDirs
# Equal or Fall Under?
# .00 means no bad exits
PERMITTED_BADEXIT = .00

# older entries' weights are adjusted with ALPHA^(age in days)
AGE_ALPHA = 0.99

# this factor is used to scale OnionOO entries to [0,1]
ONIONOO_SCALE_ONE = 999.

## Fallback Count Limits

# The target for these parameters is 20% of the guards in the network
# This is around 200 as of October 2015
_FB_POG = 0.2
FALLBACK_PROPORTION_OF_GUARDS = None if OUTPUT_CANDIDATES else _FB_POG

# Limit the number of fallbacks (eliminating lowest by advertised bandwidth)
MAX_FALLBACK_COUNT = None if OUTPUT_CANDIDATES else 200
# Emit a C #error if the number of fallbacks is less than expected
MIN_FALLBACK_COUNT = 0 if OUTPUT_CANDIDATES else MAX_FALLBACK_COUNT*0.5

# The maximum number of fallbacks on the same address, contact, or family
# With 200 fallbacks, this means each operator can see 1% of client bootstraps
# (The directory authorities used to see ~12% of client bootstraps each.)
MAX_FALLBACKS_PER_IP = 1
MAX_FALLBACKS_PER_IPV4 = MAX_FALLBACKS_PER_IP
MAX_FALLBACKS_PER_IPV6 = MAX_FALLBACKS_PER_IP
MAX_FALLBACKS_PER_CONTACT = 3
MAX_FALLBACKS_PER_FAMILY = 3

## Fallback Bandwidth Requirements

# Any fallback with the Exit flag has its bandwidth multipled by this fraction
# to make sure we aren't further overloading exits
# (Set to 1.0, because we asked that only lightly loaded exits opt-in,
# and the extra load really isn't that much for large relays.)
EXIT_BANDWIDTH_FRACTION = 1.0

# If a single fallback's bandwidth is too low, it's pointless adding it
# We expect fallbacks to handle an extra 10 kilobytes per second of traffic
# Make sure they can support a hundred times the expected extra load
# (Use 102.4 to make it come out nicely in MByte/s)
# We convert this to a consensus weight before applying the filter,
# because all the bandwidth amounts are specified by the relay
MIN_BANDWIDTH = 102.4 * 10.0 * 1024.0

# Clients will time out after 30 seconds trying to download a consensus
# So allow fallback directories half that to deliver a consensus
# The exact download times might change based on the network connection
# running this script, but only by a few seconds
# There is also about a second of python overhead
CONSENSUS_DOWNLOAD_SPEED_MAX = 15.0
# If the relay fails a consensus check, retry the download
# This avoids delisting a relay due to transient network conditions
CONSENSUS_DOWNLOAD_RETRY = True

## Fallback Weights for Client Selection

# All fallback weights are equal, and set to the value below
# Authorities are weighted 1.0 by default
# Clients use these weights to select fallbacks and authorities at random
# If there are 100 fallbacks and 9 authorities:
#  - each fallback is chosen with probability 10.0/(10.0*100 + 1.0*9) ~= 0.99%
#  - each authority is chosen with probability 1.0/(10.0*100 + 1.0*9) ~= 0.09%
# A client choosing a bootstrap directory server will choose a fallback for
# 10.0/(10.0*100 + 1.0*9) * 100 = 99.1% of attempts, and an authority for
# 1.0/(10.0*100 + 1.0*9) * 9 = 0.9% of attempts.
# (This disregards the bootstrap schedules, where clients start by choosing
# from fallbacks & authoritites, then later choose from only authorities.)
FALLBACK_OUTPUT_WEIGHT = 10.0

## Parsing Functions

def parse_ts(t):
  return datetime.datetime.strptime(t, "%Y-%m-%d %H:%M:%S")

def remove_bad_chars(raw_string, bad_char_list):
  # Remove each character in the bad_char_list
  cleansed_string = raw_string
  for c in bad_char_list:
    cleansed_string = cleansed_string.replace(c, '')
  return cleansed_string

def cleanse_unprintable(raw_string):
  # Remove all unprintable characters
  cleansed_string = ''
  for c in raw_string:
    if c in string.printable:
      cleansed_string += c
  return cleansed_string

def cleanse_whitespace(raw_string):
  # Replace all whitespace characters with a space
  cleansed_string = raw_string
  for c in string.whitespace:
    cleansed_string = cleansed_string.replace(c, ' ')
  return cleansed_string

def cleanse_c_multiline_comment(raw_string):
  cleansed_string = raw_string
  # Embedded newlines should be removed by tor/onionoo, but let's be paranoid
  cleansed_string = cleanse_whitespace(cleansed_string)
  # ContactInfo and Version can be arbitrary binary data
  cleansed_string = cleanse_unprintable(cleansed_string)
  # Prevent a malicious / unanticipated string from breaking out
  # of a C-style multiline comment
  # This removes '/*' and '*/' and '//'
  bad_char_list = '*/'
  # Prevent a malicious string from using C nulls
  bad_char_list += '\0'
  # Be safer by removing bad characters entirely
  cleansed_string = remove_bad_chars(cleansed_string, bad_char_list)
  # Some compilers may further process the content of comments
  # There isn't much we can do to cover every possible case
  # But comment-based directives are typically only advisory
  return cleansed_string

def cleanse_c_string(raw_string):
  cleansed_string = raw_string
  # Embedded newlines should be removed by tor/onionoo, but let's be paranoid
  cleansed_string = cleanse_whitespace(cleansed_string)
  # ContactInfo and Version can be arbitrary binary data
  cleansed_string = cleanse_unprintable(cleansed_string)
  # Prevent a malicious address/fingerprint string from breaking out
  # of a C-style string
  bad_char_list = '"'
  # Prevent a malicious string from using escapes
  bad_char_list += '\\'
  # Prevent a malicious string from using C nulls
  bad_char_list += '\0'
  # Be safer by removing bad characters entirely
  cleansed_string = remove_bad_chars(cleansed_string, bad_char_list)
  # Some compilers may further process the content of strings
  # There isn't much we can do to cover every possible case
  # But this typically only results in changes to the string data
  return cleansed_string

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
    logging.error('Writing file %s failed: %d: %s'%
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
    logging.info('Loading file %s failed: %d: %s'%
                 (file_name,
                  error.errno,
                  error.strerror)
                 )
  return None

def parse_fallback_file(file_name):
  file_data = read_from_file(file_name, MAX_LIST_FILE_SIZE)
  file_data = cleanse_unprintable(file_data)
  file_data = remove_bad_chars(file_data, '\n"\0')
  file_data = re.sub('/\*.*?\*/', '', file_data)
  file_data = file_data.replace(',', '\n')
  file_data = file_data.replace(' weight=10', '')
  return file_data

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
  params['first_seen_days'] = '%d-'%(ADDRESS_AND_PORT_STABLE_DAYS)
  params['last_seen_days'] = '-%d'%(MAX_DOWNTIME_DAYS)
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
    if (not 'advertised_bandwidth' in details
        or details['advertised_bandwidth'] is None):
      # relays without advertised bandwdith have it calculated from their
      # consensus weight
      details['advertised_bandwidth'] = 0
    if (not 'effective_family' in details
        or details['effective_family'] is None):
      details['effective_family'] = []
    if not 'platform' in details:
      details['platform'] = None
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
    if not self.has_ipv6():
      logging.debug("Failed to get an ipv6 address for %s."%(self._fpr,))
    self._compute_version()

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
        self.ipv6orport = int(port)
        return
    # Choose the first IPv6 address in the list
    for i in self._data['or_addresses']:
      (ipaddr, port) = i.rsplit(':', 1)
      if Candidate.is_valid_ipv6_address(ipaddr):
        self.ipv6addr = ipaddr
        self.ipv6orport = int(port)
        return

  def _compute_version(self):
    # parse the version out of the platform string
    # The platform looks like: "Tor 0.2.7.6 on Linux"
    self._data['version'] = None
    if self._data['platform'] is None:
      return
    # be tolerant of weird whitespacing, use a whitespace split
    tokens = self._data['platform'].split()
    for token in tokens:
      vnums = token.split('.')
      # if it's at least a.b.c.d, with potentially an -alpha-dev, -alpha, -rc
      if (len(vnums) >= 4 and vnums[0].isdigit() and vnums[1].isdigit() and
          vnums[2].isdigit()):
        self._data['version'] = token
        return

  # From #20509
  # bug #20499 affects versions from 0.2.9.1-alpha-dev to 0.2.9.4-alpha-dev
  # and version 0.3.0.0-alpha-dev
  # Exhaustive lists are hard to get wrong
  STALE_CONSENSUS_VERSIONS = ['0.2.9.1-alpha-dev',
                              '0.2.9.2-alpha',
                              '0.2.9.2-alpha-dev',
                              '0.2.9.3-alpha',
                              '0.2.9.3-alpha-dev',
                              '0.2.9.4-alpha',
                              '0.2.9.4-alpha-dev',
                              '0.3.0.0-alpha-dev'
                              ]

  def is_valid_version(self):
    # call _compute_version before calling this
    # is the version of the relay a version we want as a fallback?
    # checks both recommended versions and bug #20499 / #20509
    #
    # if the relay doesn't have a recommended version field, exclude the relay
    if not self._data.has_key('recommended_version'):
      log_excluded('%s not a candidate: no recommended_version field',
                   self._fpr)
      return False
    if not self._data['recommended_version']:
      log_excluded('%s not a candidate: version not recommended', self._fpr)
      return False
    # if the relay doesn't have version field, exclude the relay
    if not self._data.has_key('version'):
      log_excluded('%s not a candidate: no version field', self._fpr)
      return False
    if self._data['version'] in Candidate.STALE_CONSENSUS_VERSIONS:
      logging.warning('%s not a candidate: version delivers stale consensuses',
                      self._fpr)
      return False
    return True

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
        logging.warning('Inconsistent value count in %s document for %s'
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
        logging.warning('Inconsistent time information in %s document for %s'
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
    try:
      if (MUST_BE_RUNNING_NOW and not self.is_running()):
        log_excluded('%s not a candidate: not running now, unable to check ' +
                     'DirPort consensus download', self._fpr)
        return False
      if (self._data['last_changed_address_or_port'] >
          self.CUTOFF_ADDRESS_AND_PORT_STABLE):
        log_excluded('%s not a candidate: changed address/port recently (%s)',
                     self._fpr, self._data['last_changed_address_or_port'])
        return False
      if self._running < CUTOFF_RUNNING:
        log_excluded('%s not a candidate: running avg too low (%lf)',
                     self._fpr, self._running)
        return False
      if self._v2dir < CUTOFF_V2DIR:
        log_excluded('%s not a candidate: v2dir avg too low (%lf)',
                     self._fpr, self._v2dir)
        return False
      if self._badexit is not None and self._badexit > PERMITTED_BADEXIT:
        log_excluded('%s not a candidate: badexit avg too high (%lf)',
                     self._fpr, self._badexit)
        return False
      # this function logs a message depending on which check fails
      if not self.is_valid_version():
        return False
      if self._guard < CUTOFF_GUARD:
        log_excluded('%s not a candidate: guard avg too low (%lf)',
                     self._fpr, self._guard)
        return False
      if (not self._data.has_key('consensus_weight')
          or self._data['consensus_weight'] < 1):
        log_excluded('%s not a candidate: consensus weight invalid', self._fpr)
        return False
    except BaseException as e:
      logging.warning("Exception %s when checking if fallback is a candidate",
                      str(e))
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
    ipv6 = None
    if self.has_ipv6():
      ipv6 = '%s:%d'%(self.ipv6addr, self.ipv6orport)
    for entry in relaylist:
      if entry['id'] != self._fpr:
        # can't log here unless we match an IP and port, because every relay's
        # fingerprint is compared to every entry's fingerprint
        if entry['ipv4'] == self.dirip and int(entry['orport']) == self.orport:
          logging.warning('%s excluded: has OR %s:%d changed fingerprint to ' +
                          '%s?', entry['id'], self.dirip, self.orport,
                          self._fpr)
        if self.has_ipv6() and entry.has_key('ipv6') and entry['ipv6'] == ipv6:
          logging.warning('%s excluded: has OR %s changed fingerprint to ' +
                          '%s?', entry['id'], ipv6, self._fpr)
        continue
      if entry['ipv4'] != self.dirip:
        logging.warning('%s excluded: has it changed IPv4 from %s to %s?',
                        self._fpr, entry['ipv4'], self.dirip)
        continue
      if int(entry['dirport']) != self.dirport:
        logging.warning('%s excluded: has it changed DirPort from %s:%d to ' +
                        '%s:%d?', self._fpr, self.dirip, int(entry['dirport']),
                        self.dirip, self.dirport)
        continue
      if int(entry['orport']) != self.orport:
        logging.warning('%s excluded: has it changed ORPort from %s:%d to ' +
                        '%s:%d?', self._fpr, self.dirip, int(entry['orport']),
                        self.dirip, self.orport)
        continue
      if entry.has_key('ipv6') and self.has_ipv6():
        # if both entry and fallback have an ipv6 address, compare them
        if entry['ipv6'] != ipv6:
          logging.warning('%s excluded: has it changed IPv6 ORPort from %s ' +
                          'to %s?', self._fpr, entry['ipv6'], ipv6)
          continue
      # if the fallback has an IPv6 address but the whitelist entry
      # doesn't, or vice versa, the whitelist entry doesn't match
      elif entry.has_key('ipv6') and not self.has_ipv6():
        logging.warning('%s excluded: has it lost its former IPv6 address %s?',
                        self._fpr, entry['ipv6'])
        continue
      elif not entry.has_key('ipv6') and self.has_ipv6():
        logging.warning('%s excluded: has it gained an IPv6 address %s?',
                        self._fpr, ipv6)
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
        if key == 'id' and value == self._fpr:
          log_excluded('%s is in the blacklist: fingerprint matches',
                       self._fpr)
          return True
        if key == 'ipv4' and value == self.dirip:
          # if the dirport is present, check it too
          if entry.has_key('dirport'):
            if int(entry['dirport']) == self.dirport:
              log_excluded('%s is in the blacklist: IPv4 (%s) and ' +
                           'DirPort (%d) match', self._fpr, self.dirip,
                           self.dirport)
              return True
          # if the orport is present, check it too
          elif entry.has_key('orport'):
            if int(entry['orport']) == self.orport:
              log_excluded('%s is in the blacklist: IPv4 (%s) and ' +
                           'ORPort (%d) match', self._fpr, self.dirip,
                           self.orport)
              return True
          else:
            log_excluded('%s is in the blacklist: IPv4 (%s) matches, and ' +
                         'entry has no DirPort or ORPort', self._fpr,
                         self.dirip)
            return True
        ipv6 = None
        if self.has_ipv6():
          ipv6 = '%s:%d'%(self.ipv6addr, self.ipv6orport)
        if (key == 'ipv6' and self.has_ipv6()):
        # if both entry and fallback have an ipv6 address, compare them,
        # otherwise, disregard ipv6 addresses
          if value == ipv6:
            # if the dirport is present, check it too
            if entry.has_key('dirport'):
              if int(entry['dirport']) == self.dirport:
                log_excluded('%s is in the blacklist: IPv6 (%s) and ' +
                             'DirPort (%d) match', self._fpr, ipv6,
                             self.dirport)
                return True
            # we've already checked the ORPort, it's part of entry['ipv6']
            else:
              log_excluded('%s is in the blacklist: IPv6 (%s) matches, and' +
                           'entry has no DirPort', self._fpr, ipv6)
              return True
        elif (key == 'ipv6' or self.has_ipv6()):
          # only log if the fingerprint matches but the IPv6 doesn't
          if entry.has_key('id') and entry['id'] == self._fpr:
            log_excluded('%s skipping IPv6 blacklist comparison: relay ' +
                         'has%s IPv6%s, but entry has%s IPv6%s', self._fpr,
                         '' if self.has_ipv6() else ' no',
                         (' (' + ipv6 + ')') if self.has_ipv6() else  '',
                         '' if key == 'ipv6' else ' no',
                         (' (' + value + ')') if key == 'ipv6' else '')
            logging.warning('Has %s %s IPv6 address %s?', self._fpr,
                        'gained an' if self.has_ipv6() else 'lost its former',
                        ipv6 if self.has_ipv6() else value)
    return False

  def cw_to_bw_factor(self):
    # any relays with a missing or zero consensus weight are not candidates
    # any relays with a missing advertised bandwidth have it set to zero
    return self._data['advertised_bandwidth'] / self._data['consensus_weight']

  # since advertised_bandwidth is reported by the relay, it can be gamed
  # to avoid this, use the median consensus weight to bandwidth factor to
  # estimate this relay's measured bandwidth, and make that the upper limit
  def measured_bandwidth(self, median_cw_to_bw_factor):
    cw_to_bw= median_cw_to_bw_factor
    # Reduce exit bandwidth to make sure we're not overloading them
    if self.is_exit():
      cw_to_bw *= EXIT_BANDWIDTH_FRACTION
    measured_bandwidth = self._data['consensus_weight'] * cw_to_bw
    if self._data['advertised_bandwidth'] != 0:
      # limit advertised bandwidth (if available) to measured bandwidth
      return min(measured_bandwidth, self._data['advertised_bandwidth'])
    else:
      return measured_bandwidth

  def set_measured_bandwidth(self, median_cw_to_bw_factor):
    self._data['measured_bandwidth'] = self.measured_bandwidth(
                                                      median_cw_to_bw_factor)

  def is_exit(self):
    return 'Exit' in self._data['flags']

  def is_guard(self):
    return 'Guard' in self._data['flags']

  def is_running(self):
    return 'Running' in self._data['flags']

  # does this fallback have an IPv6 address and orport?
  def has_ipv6(self):
    return self.ipv6addr is not None and self.ipv6orport is not None

  # strip leading and trailing brackets from an IPv6 address
  # safe to use on non-bracketed IPv6 and on IPv4 addresses
  # also convert to unicode, and make None appear as ''
  @staticmethod
  def strip_ipv6_brackets(ip):
    if ip is None:
      return unicode('')
    if len(ip) < 2:
      return unicode(ip)
    if ip[0] == '[' and ip[-1] == ']':
      return unicode(ip[1:-1])
    return unicode(ip)

  # are ip_a and ip_b in the same netblock?
  # mask_bits is the size of the netblock
  # takes both IPv4 and IPv6 addresses
  # the versions of ip_a and ip_b must be the same
  # the mask must be valid for the IP version
  @staticmethod
  def netblocks_equal(ip_a, ip_b, mask_bits):
    if ip_a is None or ip_b is None:
      return False
    ip_a = Candidate.strip_ipv6_brackets(ip_a)
    ip_b = Candidate.strip_ipv6_brackets(ip_b)
    a = ipaddress.ip_address(ip_a)
    b = ipaddress.ip_address(ip_b)
    if a.version != b.version:
      raise Exception('Mismatching IP versions in %s and %s'%(ip_a, ip_b))
    if mask_bits > a.max_prefixlen:
      logging.error('Bad IP mask %d for %s and %s'%(mask_bits, ip_a, ip_b))
      mask_bits = a.max_prefixlen
    if mask_bits < 0:
      logging.error('Bad IP mask %d for %s and %s'%(mask_bits, ip_a, ip_b))
      mask_bits = 0
    a_net = ipaddress.ip_network('%s/%d'%(ip_a, mask_bits), strict=False)
    return b in a_net

  # is this fallback's IPv4 address (dirip) in the same netblock as other's
  # IPv4 address?
  # mask_bits is the size of the netblock
  def ipv4_netblocks_equal(self, other, mask_bits):
    return Candidate.netblocks_equal(self.dirip, other.dirip, mask_bits)

  # is this fallback's IPv6 address (ipv6addr) in the same netblock as
  # other's IPv6 address?
  # Returns False if either fallback has no IPv6 address
  # mask_bits is the size of the netblock
  def ipv6_netblocks_equal(self, other, mask_bits):
    if not self.has_ipv6() or not other.has_ipv6():
      return False
    return Candidate.netblocks_equal(self.ipv6addr, other.ipv6addr, mask_bits)

  # is this fallback's IPv4 DirPort the same as other's IPv4 DirPort?
  def dirport_equal(self, other):
    return self.dirport == other.dirport

  # is this fallback's IPv4 ORPort the same as other's IPv4 ORPort?
  def ipv4_orport_equal(self, other):
    return self.orport == other.orport

  # is this fallback's IPv6 ORPort the same as other's IPv6 ORPort?
  # Returns False if either fallback has no IPv6 address
  def ipv6_orport_equal(self, other):
    if not self.has_ipv6() or not other.has_ipv6():
      return False
    return self.ipv6orport == other.ipv6orport

  # does this fallback have the same DirPort, IPv4 ORPort, or
  # IPv6 ORPort as other?
  # Ignores IPv6 ORPort if either fallback has no IPv6 address
  def port_equal(self, other):
    return (self.dirport_equal(other) or self.ipv4_orport_equal(other)
            or self.ipv6_orport_equal(other))

  # return a list containing IPv4 ORPort, DirPort, and IPv6 ORPort (if present)
  def port_list(self):
    ports = [self.dirport, self.orport]
    if self.has_ipv6() and not self.ipv6orport in ports:
      ports.append(self.ipv6orport)
    return ports

  # does this fallback share a port with other, regardless of whether the
  # port types match?
  # For example, if self's IPv4 ORPort is 80 and other's DirPort is 80,
  # return True
  def port_shared(self, other):
    for p in self.port_list():
      if p in other.port_list():
        return True
    return False

  # log how long it takes to download a consensus from dirip:dirport
  # returns True if the download failed, False if it succeeded within max_time
  @staticmethod
  def fallback_consensus_download_speed(dirip, dirport, nickname, fingerprint,
                                        max_time):
    download_failed = False
    # some directory mirrors respond to requests in ways that hang python
    # sockets, which is why we log this line here
    logging.info('Initiating %sconsensus download from %s (%s:%d) %s.',
                 'microdesc ' if DOWNLOAD_MICRODESC_CONSENSUS else '',
                 nickname, dirip, dirport, fingerprint)
    # there appears to be about 1 second of overhead when comparing stem's
    # internal trace time and the elapsed time calculated here
    TIMEOUT_SLOP = 1.0
    start = datetime.datetime.utcnow()
    try:
      consensus = get_consensus(
                              endpoints = [(dirip, dirport)],
                              timeout = (max_time + TIMEOUT_SLOP),
                              validate = True,
                              retries = 0,
                              fall_back_to_authority = False,
                              document_handler = DocumentHandler.BARE_DOCUMENT,
                              microdescriptor = DOWNLOAD_MICRODESC_CONSENSUS
                                ).run()[0]
      end = datetime.datetime.utcnow()
      time_since_expiry = (end - consensus.valid_until).total_seconds()
    except Exception, stem_error:
      end = datetime.datetime.utcnow()
      log_excluded('Unable to retrieve a consensus from %s: %s', nickname,
                    stem_error)
      status = 'error: "%s"' % (stem_error)
      level = logging.WARNING
      download_failed = True
    elapsed = (end - start).total_seconds()
    if download_failed:
      # keep the error failure status, and avoid using the variables
      pass
    elif elapsed > max_time:
      status = 'too slow'
      level = logging.WARNING
      download_failed = True
    elif (time_since_expiry > 0):
      status = 'outdated consensus, expired %ds ago'%(int(time_since_expiry))
      if time_since_expiry <= CONSENSUS_EXPIRY_TOLERANCE:
        status += ', tolerating up to %ds'%(CONSENSUS_EXPIRY_TOLERANCE)
        level = logging.INFO
      else:
        status += ', invalid'
        level = logging.WARNING
        download_failed = True
    else:
      status = 'ok'
      level = logging.DEBUG
    logging.log(level, 'Consensus download: %0.1fs %s from %s (%s:%d) %s, ' +
                 'max download time %0.1fs.', elapsed, status, nickname,
                 dirip, dirport, fingerprint, max_time)
    return download_failed

  # does this fallback download the consensus fast enough?
  def check_fallback_download_consensus(self):
    # include the relay if we're not doing a check, or we can't check (IPv6)
    ipv4_failed = False
    ipv6_failed = False
    if PERFORM_IPV4_DIRPORT_CHECKS:
      ipv4_failed = Candidate.fallback_consensus_download_speed(self.dirip,
                                                self.dirport,
                                                self._data['nickname'],
                                                self._fpr,
                                                CONSENSUS_DOWNLOAD_SPEED_MAX)
    if self.has_ipv6() and PERFORM_IPV6_DIRPORT_CHECKS:
      # Clients assume the IPv6 DirPort is the same as the IPv4 DirPort
      ipv6_failed = Candidate.fallback_consensus_download_speed(self.ipv6addr,
                                                self.dirport,
                                                self._data['nickname'],
                                                self._fpr,
                                                CONSENSUS_DOWNLOAD_SPEED_MAX)
    return ((not ipv4_failed) and (not ipv6_failed))

  # if this fallback has not passed a download check, try it again,
  # and record the result, available in get_fallback_download_consensus
  def try_fallback_download_consensus(self):
    if not self.get_fallback_download_consensus():
      self._data['download_check'] = self.check_fallback_download_consensus()

  # did this fallback pass the download check?
  def get_fallback_download_consensus(self):
    # if we're not performing checks, return True
    if not PERFORM_IPV4_DIRPORT_CHECKS and not PERFORM_IPV6_DIRPORT_CHECKS:
      return True
    # if we are performing checks, but haven't done one, return False
    if not self._data.has_key('download_check'):
      return False
    return self._data['download_check']

  # output an optional header comment and info for this fallback
  # try_fallback_download_consensus before calling this
  def fallbackdir_line(self, fallbacks, prefilter_fallbacks):
    s = ''
    if OUTPUT_COMMENTS:
      s += self.fallbackdir_comment(fallbacks, prefilter_fallbacks)
    # if the download speed is ok, output a C string
    # if it's not, but we OUTPUT_COMMENTS, output a commented-out C string
    if self.get_fallback_download_consensus() or OUTPUT_COMMENTS:
      s += self.fallbackdir_info(self.get_fallback_download_consensus())
    return s

  # output a header comment for this fallback
  def fallbackdir_comment(self, fallbacks, prefilter_fallbacks):
    # /*
    # nickname
    # flags
    # adjusted bandwidth, consensus weight
    # [contact]
    # [identical contact counts]
    # */
    # Multiline C comment
    s = '/*'
    s += '\n'
    s += cleanse_c_multiline_comment(self._data['nickname'])
    s += '\n'
    s += 'Flags: '
    s += cleanse_c_multiline_comment(' '.join(sorted(self._data['flags'])))
    s += '\n'
    # this is an adjusted bandwidth, see calculate_measured_bandwidth()
    bandwidth = self._data['measured_bandwidth']
    weight = self._data['consensus_weight']
    s += 'Bandwidth: %.1f MByte/s, Consensus Weight: %d'%(
        bandwidth/(1024.0*1024.0),
        weight)
    s += '\n'
    if self._data['contact'] is not None:
      s += cleanse_c_multiline_comment(self._data['contact'])
      if CONTACT_COUNT or CONTACT_BLACKLIST_COUNT:
        fallback_count = len([f for f in fallbacks
                              if f._data['contact'] == self._data['contact']])
        if fallback_count > 1:
          s += '\n'
          s += '%d identical contacts listed' % (fallback_count)
      if CONTACT_BLACKLIST_COUNT:
        prefilter_count = len([f for f in prefilter_fallbacks
                               if f._data['contact'] == self._data['contact']])
        filter_count = prefilter_count - fallback_count
        if filter_count > 0:
          if fallback_count > 1:
            s += ' '
          else:
            s += '\n'
          s += '%d blacklisted' % (filter_count)
      s += '\n'
    s += '*/'
    s += '\n'
    return s

  # output the fallback info C string for this fallback
  # this is the text that would go after FallbackDir in a torrc
  # if this relay failed the download test and we OUTPUT_COMMENTS,
  # comment-out the returned string
  def fallbackdir_info(self, dl_speed_ok):
    # "address:dirport orport=port id=fingerprint"
    # "[ipv6=addr:orport]"
    # "weight=FALLBACK_OUTPUT_WEIGHT",
    #
    # Do we want a C string, or a commented-out string?
    c_string = dl_speed_ok
    comment_string = not dl_speed_ok and OUTPUT_COMMENTS
    # If we don't want either kind of string, bail
    if not c_string and not comment_string:
      return ''
    s = ''
    # Comment out the fallback directory entry if it's too slow
    # See the debug output for which address and port is failing
    if comment_string:
      s += '/* Consensus download failed or was too slow:\n'
    # Multi-Line C string with trailing comma (part of a string list)
    # This makes it easier to diff the file, and remove IPv6 lines using grep
    # Integers don't need escaping
    s += '"%s orport=%d id=%s"'%(
            cleanse_c_string(self._data['dir_address']),
            self.orport,
            cleanse_c_string(self._fpr))
    s += '\n'
    if self.has_ipv6():
      s += '" ipv6=%s:%d"'%(cleanse_c_string(self.ipv6addr), self.ipv6orport)
      s += '\n'
    s += '" weight=%d",'%(FALLBACK_OUTPUT_WEIGHT)
    if comment_string:
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
                'consensus_weight,advertised_bandwidth,or_addresses,' +
                'dir_address,recommended_version,flags,effective_family,' +
                'platform'))
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

  # Find fallbacks that fit the uptime, stability, and flags criteria,
  # and make an array of them in self.fallbacks
  def compute_fallbacks(self):
    self.fallbacks = map(lambda x: self[x],
                         filter(lambda x: self[x].is_candidate(),
                                self.keys()))

  # sort fallbacks by their consensus weight to advertised bandwidth factor,
  # lowest to highest
  # used to find the median cw_to_bw_factor()
  def sort_fallbacks_by_cw_to_bw_factor(self):
    self.fallbacks.sort(key=lambda f: f.cw_to_bw_factor())

  # sort fallbacks by their measured bandwidth, highest to lowest
  # calculate_measured_bandwidth before calling this
  # this is useful for reviewing candidates in priority order
  def sort_fallbacks_by_measured_bandwidth(self):
    self.fallbacks.sort(key=lambda f: f._data['measured_bandwidth'],
                        reverse=True)

  # sort fallbacks by the data field data_field, lowest to highest
  def sort_fallbacks_by(self, data_field):
    self.fallbacks.sort(key=lambda f: f._data[data_field])

  @staticmethod
  def load_relaylist(file_obj):
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
    file_data = file_obj['data']
    file_name = file_obj['name']
    relaylist = []
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
  def apply_filter_lists(self, whitelist_obj, blacklist_obj):
    excluded_count = 0
    logging.debug('Applying whitelist and blacklist.')
    # parse the whitelist and blacklist
    whitelist = self.load_relaylist(whitelist_obj)
    blacklist = self.load_relaylist(blacklist_obj)
    filtered_fallbacks = []
    for f in self.fallbacks:
      in_whitelist = f.is_in_whitelist(whitelist)
      in_blacklist = f.is_in_blacklist(blacklist)
      if in_whitelist and in_blacklist:
        if BLACKLIST_EXCLUDES_WHITELIST_ENTRIES:
          # exclude
          excluded_count += 1
          logging.warning('Excluding %s: in both blacklist and whitelist.',
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
        log_excluded('Excluding %s: in blacklist.', f._fpr)
      else:
        if INCLUDE_UNLISTED_ENTRIES:
          # include
          filtered_fallbacks.append(f)
        else:
          # exclude
          excluded_count += 1
          log_excluded('Excluding %s: in neither blacklist nor whitelist.',
                       f._fpr)
    self.fallbacks = filtered_fallbacks
    return excluded_count

  @staticmethod
  def summarise_filters(initial_count, excluded_count):
    return '/* Whitelist & blacklist excluded %d of %d candidates. */'%(
                                                excluded_count, initial_count)

  # calculate each fallback's measured bandwidth based on the median
  # consensus weight to advertised bandwdith ratio
  def calculate_measured_bandwidth(self):
    self.sort_fallbacks_by_cw_to_bw_factor()
    median_fallback = self.fallback_median(True)
    if median_fallback is not None:
      median_cw_to_bw_factor = median_fallback.cw_to_bw_factor()
    else:
      # this will never be used, because there are no fallbacks
      median_cw_to_bw_factor = None
    for f in self.fallbacks:
      f.set_measured_bandwidth(median_cw_to_bw_factor)

  # remove relays with low measured bandwidth from the fallback list
  # calculate_measured_bandwidth for each relay before calling this
  def remove_low_bandwidth_relays(self):
    if MIN_BANDWIDTH is None:
      return
    above_min_bw_fallbacks = []
    for f in self.fallbacks:
      if f._data['measured_bandwidth'] >= MIN_BANDWIDTH:
        above_min_bw_fallbacks.append(f)
      else:
        # the bandwidth we log here is limited by the relay's consensus weight
        # as well as its adverttised bandwidth. See set_measured_bandwidth
        # for details
        log_excluded('%s not a candidate: bandwidth %.1fMByte/s too low, ' +
                     'must be at least %.1fMByte/s', f._fpr,
                     f._data['measured_bandwidth']/(1024.0*1024.0),
                     MIN_BANDWIDTH/(1024.0*1024.0))
    self.fallbacks = above_min_bw_fallbacks

  # the minimum fallback in the list
  # call one of the sort_fallbacks_* functions before calling this
  def fallback_min(self):
    if len(self.fallbacks) > 0:
      return self.fallbacks[-1]
    else:
      return None

  # the median fallback in the list
  # call one of the sort_fallbacks_* functions before calling this
  def fallback_median(self, require_advertised_bandwidth):
    # use the low-median when there are an evan number of fallbacks,
    # for consistency with the bandwidth authorities
    if len(self.fallbacks) > 0:
      median_position = (len(self.fallbacks) - 1) / 2
      if not require_advertised_bandwidth:
        return self.fallbacks[median_position]
      # if we need advertised_bandwidth but this relay doesn't have it,
      # move to a fallback with greater consensus weight until we find one
      while not self.fallbacks[median_position]._data['advertised_bandwidth']:
        median_position += 1
        if median_position >= len(self.fallbacks):
          return None
      return self.fallbacks[median_position]
    else:
      return None

  # the maximum fallback in the list
  # call one of the sort_fallbacks_* functions before calling this
  def fallback_max(self):
    if len(self.fallbacks) > 0:
      return self.fallbacks[0]
    else:
      return None

  # return a new bag suitable for storing attributes
  @staticmethod
  def attribute_new():
    return dict()

  # get the count of attribute in attribute_bag
  # if attribute is None or the empty string, return 0
  @staticmethod
  def attribute_count(attribute, attribute_bag):
    if attribute is None or attribute == '':
      return 0
    if attribute not in attribute_bag:
      return 0
    return attribute_bag[attribute]

  # does attribute_bag contain more than max_count instances of attribute?
  # if so, return False
  # if not, return True
  # if attribute is None or the empty string, or max_count is invalid,
  # always return True
  @staticmethod
  def attribute_allow(attribute, attribute_bag, max_count=1):
    if attribute is None or attribute == '' or max_count <= 0:
      return True
    elif CandidateList.attribute_count(attribute, attribute_bag) >= max_count:
      return False
    else:
      return True

  # add attribute to attribute_bag, incrementing the count if it is already
  # present
  # if attribute is None or the empty string, or count is invalid,
  # do nothing
  @staticmethod
  def attribute_add(attribute, attribute_bag, count=1):
    if attribute is None or attribute == '' or count <= 0:
      pass
    attribute_bag.setdefault(attribute, 0)
    attribute_bag[attribute] += count

  # make sure there are only MAX_FALLBACKS_PER_IP fallbacks per IPv4 address,
  # and per IPv6 address
  # there is only one IPv4 address on each fallback: the IPv4 DirPort address
  # (we choose the IPv4 ORPort which is on the same IPv4 as the DirPort)
  # there is at most one IPv6 address on each fallback: the IPv6 ORPort address
  # we try to match the IPv4 ORPort, but will use any IPv6 address if needed
  # (clients only use the IPv6 ORPort)
  # if there is no IPv6 address, only the IPv4 address is checked
  # return the number of candidates we excluded
  def limit_fallbacks_same_ip(self):
    ip_limit_fallbacks = []
    ip_list = CandidateList.attribute_new()
    for f in self.fallbacks:
      if (CandidateList.attribute_allow(f.dirip, ip_list,
                                        MAX_FALLBACKS_PER_IPV4)
          and CandidateList.attribute_allow(f.ipv6addr, ip_list,
                                            MAX_FALLBACKS_PER_IPV6)):
        ip_limit_fallbacks.append(f)
        CandidateList.attribute_add(f.dirip, ip_list)
        if f.has_ipv6():
          CandidateList.attribute_add(f.ipv6addr, ip_list)
      elif not CandidateList.attribute_allow(f.dirip, ip_list,
                                             MAX_FALLBACKS_PER_IPV4):
        log_excluded('Eliminated %s: already have %d fallback(s) on IPv4 %s'
                     %(f._fpr, CandidateList.attribute_count(f.dirip, ip_list),
                       f.dirip))
      elif (f.has_ipv6() and
            not CandidateList.attribute_allow(f.ipv6addr, ip_list,
                                              MAX_FALLBACKS_PER_IPV6)):
        log_excluded('Eliminated %s: already have %d fallback(s) on IPv6 %s'
                     %(f._fpr, CandidateList.attribute_count(f.ipv6addr,
                                                             ip_list),
                       f.ipv6addr))
    original_count = len(self.fallbacks)
    self.fallbacks = ip_limit_fallbacks
    return original_count - len(self.fallbacks)

  # make sure there are only MAX_FALLBACKS_PER_CONTACT fallbacks for each
  # ContactInfo
  # if there is no ContactInfo, allow the fallback
  # this check can be gamed by providing no ContactInfo, or by setting the
  # ContactInfo to match another fallback
  # However, given the likelihood that relays with the same ContactInfo will
  # go down at similar times, its usefulness outweighs the risk
  def limit_fallbacks_same_contact(self):
    contact_limit_fallbacks = []
    contact_list = CandidateList.attribute_new()
    for f in self.fallbacks:
      if CandidateList.attribute_allow(f._data['contact'], contact_list,
                                       MAX_FALLBACKS_PER_CONTACT):
        contact_limit_fallbacks.append(f)
        CandidateList.attribute_add(f._data['contact'], contact_list)
      else:
        log_excluded(
          'Eliminated %s: already have %d fallback(s) on ContactInfo %s'
          %(f._fpr, CandidateList.attribute_count(f._data['contact'],
                                                  contact_list),
            f._data['contact']))
    original_count = len(self.fallbacks)
    self.fallbacks = contact_limit_fallbacks
    return original_count - len(self.fallbacks)

  # make sure there are only MAX_FALLBACKS_PER_FAMILY fallbacks per effective
  # family
  # if there is no family, allow the fallback
  # we use effective family, which ensures mutual family declarations
  # but the check can be gamed by not declaring a family at all
  # if any indirect families exist, the result depends on the order in which
  # fallbacks are sorted in the list
  def limit_fallbacks_same_family(self):
    family_limit_fallbacks = []
    fingerprint_list = CandidateList.attribute_new()
    for f in self.fallbacks:
      if CandidateList.attribute_allow(f._fpr, fingerprint_list,
                                       MAX_FALLBACKS_PER_FAMILY):
        family_limit_fallbacks.append(f)
        CandidateList.attribute_add(f._fpr, fingerprint_list)
        for family_fingerprint in f._data['effective_family']:
          CandidateList.attribute_add(family_fingerprint, fingerprint_list)
      else:
        # we already have a fallback with this fallback in its effective
        # family
        log_excluded(
          'Eliminated %s: already have %d fallback(s) in effective family'
          %(f._fpr, CandidateList.attribute_count(f._fpr, fingerprint_list)))
    original_count = len(self.fallbacks)
    self.fallbacks = family_limit_fallbacks
    return original_count - len(self.fallbacks)

  # try a download check on each fallback candidate in order
  # stop after max_count successful downloads
  # but don't remove any candidates from the array
  def try_download_consensus_checks(self, max_count):
    dl_ok_count = 0
    for f in self.fallbacks:
      f.try_fallback_download_consensus()
      if f.get_fallback_download_consensus():
        # this fallback downloaded a consensus ok
        dl_ok_count += 1
        if dl_ok_count >= max_count:
          # we have enough fallbacks
          return

  # put max_count successful candidates in the fallbacks array:
  # - perform download checks on each fallback candidate
  # - retry failed candidates if CONSENSUS_DOWNLOAD_RETRY is set
  # - eliminate failed candidates
  # - if there are more than max_count candidates, eliminate lowest bandwidth
  # - if there are fewer than max_count candidates, leave only successful
  # Return the number of fallbacks that failed the consensus check
  def perform_download_consensus_checks(self, max_count):
    self.sort_fallbacks_by_measured_bandwidth()
    self.try_download_consensus_checks(max_count)
    if CONSENSUS_DOWNLOAD_RETRY:
      # try unsuccessful candidates again
      # we could end up with more than max_count successful candidates here
      self.try_download_consensus_checks(max_count)
    # now we have at least max_count successful candidates,
    # or we've tried them all
    original_count = len(self.fallbacks)
    self.fallbacks = filter(lambda x: x.get_fallback_download_consensus(),
                            self.fallbacks)
    # some of these failed the check, others skipped the check,
    # if we already had enough successful downloads
    failed_count = original_count - len(self.fallbacks)
    self.fallbacks = self.fallbacks[:max_count]
    return failed_count

  # return a string that describes a/b as a percentage
  @staticmethod
  def describe_percentage(a, b):
    if b != 0:
      return '%d/%d = %.0f%%'%(a, b, (a*100.0)/b)
    else:
      # technically, 0/0 is undefined, but 0.0% is a sensible result
      return '%d/%d = %.0f%%'%(a, b, 0.0)

  # return a dictionary of lists of fallbacks by IPv4 netblock
  # the dictionary is keyed by the fingerprint of an arbitrary fallback
  # in each netblock
  # mask_bits is the size of the netblock
  def fallbacks_by_ipv4_netblock(self, mask_bits):
    netblocks = {}
    for f in self.fallbacks:
      found_netblock = False
      for b in netblocks.keys():
        # we found an existing netblock containing this fallback
        if f.ipv4_netblocks_equal(self[b], mask_bits):
          # add it to the list
          netblocks[b].append(f)
          found_netblock = True
          break
      # make a new netblock based on this fallback's fingerprint
      if not found_netblock:
        netblocks[f._fpr] = [f]
    return netblocks

  # return a dictionary of lists of fallbacks by IPv6 netblock
  # where mask_bits is the size of the netblock
  def fallbacks_by_ipv6_netblock(self, mask_bits):
    netblocks = {}
    for f in self.fallbacks:
      # skip fallbacks without IPv6 addresses
      if not f.has_ipv6():
        continue
      found_netblock = False
      for b in netblocks.keys():
        # we found an existing netblock containing this fallback
        if f.ipv6_netblocks_equal(self[b], mask_bits):
          # add it to the list
          netblocks[b].append(f)
          found_netblock = True
          break
      # make a new netblock based on this fallback's fingerprint
      if not found_netblock:
        netblocks[f._fpr] = [f]
    return netblocks

  # log a message about the proportion of fallbacks in each IPv4 netblock,
  # where mask_bits is the size of the netblock
  def describe_fallback_ipv4_netblock_mask(self, mask_bits):
    fallback_count = len(self.fallbacks)
    shared_netblock_fallback_count = 0
    most_frequent_netblock = None
    netblocks = self.fallbacks_by_ipv4_netblock(mask_bits)
    for b in netblocks.keys():
      if len(netblocks[b]) > 1:
        # how many fallbacks are in a netblock with other fallbacks?
        shared_netblock_fallback_count += len(netblocks[b])
        # what's the netblock with the most fallbacks?
        if (most_frequent_netblock is None
            or len(netblocks[b]) > len(netblocks[most_frequent_netblock])):
          most_frequent_netblock = b
        logging.debug('Fallback IPv4 addresses in the same /%d:'%(mask_bits))
        for f in netblocks[b]:
          logging.debug('%s - %s', f.dirip, f._fpr)
    if most_frequent_netblock is not None:
      logging.warning('There are %s fallbacks in the IPv4 /%d containing %s'%(
                                    CandidateList.describe_percentage(
                                      len(netblocks[most_frequent_netblock]),
                                      fallback_count),
                                    mask_bits,
                                    self[most_frequent_netblock].dirip))
    if shared_netblock_fallback_count > 0:
      logging.warning(('%s of fallbacks are in an IPv4 /%d with other ' +
                       'fallbacks')%(CandidateList.describe_percentage(
                                                shared_netblock_fallback_count,
                                                fallback_count),
                                     mask_bits))

  # log a message about the proportion of fallbacks in each IPv6 netblock,
  # where mask_bits is the size of the netblock
  def describe_fallback_ipv6_netblock_mask(self, mask_bits):
    fallback_count = len(self.fallbacks_with_ipv6())
    shared_netblock_fallback_count = 0
    most_frequent_netblock = None
    netblocks = self.fallbacks_by_ipv6_netblock(mask_bits)
    for b in netblocks.keys():
      if len(netblocks[b]) > 1:
        # how many fallbacks are in a netblock with other fallbacks?
        shared_netblock_fallback_count += len(netblocks[b])
        # what's the netblock with the most fallbacks?
        if (most_frequent_netblock is None
            or len(netblocks[b]) > len(netblocks[most_frequent_netblock])):
          most_frequent_netblock = b
        logging.debug('Fallback IPv6 addresses in the same /%d:'%(mask_bits))
        for f in netblocks[b]:
          logging.debug('%s - %s', f.ipv6addr, f._fpr)
    if most_frequent_netblock is not None:
      logging.warning('There are %s fallbacks in the IPv6 /%d containing %s'%(
                                    CandidateList.describe_percentage(
                                      len(netblocks[most_frequent_netblock]),
                                      fallback_count),
                                    mask_bits,
                                    self[most_frequent_netblock].ipv6addr))
    if shared_netblock_fallback_count > 0:
      logging.warning(('%s of fallbacks are in an IPv6 /%d with other ' +
                       'fallbacks')%(CandidateList.describe_percentage(
                                                shared_netblock_fallback_count,
                                                fallback_count),
                                     mask_bits))

  # log a message about the proportion of fallbacks in each IPv4 /8, /16,
  # and /24
  def describe_fallback_ipv4_netblocks(self):
   # this doesn't actually tell us anything useful
   #self.describe_fallback_ipv4_netblock_mask(8)
   self.describe_fallback_ipv4_netblock_mask(16)
   self.describe_fallback_ipv4_netblock_mask(24)

  # log a message about the proportion of fallbacks in each IPv6 /12 (RIR),
  # /23 (smaller RIR blocks), /32 (LIR), /48 (Customer), and /64 (Host)
  # https://www.iana.org/assignments/ipv6-unicast-address-assignments/
  def describe_fallback_ipv6_netblocks(self):
    # these don't actually tell us anything useful
    #self.describe_fallback_ipv6_netblock_mask(12)
    #self.describe_fallback_ipv6_netblock_mask(23)
    self.describe_fallback_ipv6_netblock_mask(32)
    self.describe_fallback_ipv6_netblock_mask(48)
    self.describe_fallback_ipv6_netblock_mask(64)

  # log a message about the proportion of fallbacks in each IPv4 and IPv6
  # netblock
  def describe_fallback_netblocks(self):
    self.describe_fallback_ipv4_netblocks()
    self.describe_fallback_ipv6_netblocks()

  # return a list of fallbacks which are on the IPv4 ORPort port
  def fallbacks_on_ipv4_orport(self, port):
    return filter(lambda x: x.orport == port, self.fallbacks)

  # return a list of fallbacks which are on the IPv6 ORPort port
  def fallbacks_on_ipv6_orport(self, port):
    return filter(lambda x: x.ipv6orport == port, self.fallbacks_with_ipv6())

  # return a list of fallbacks which are on the DirPort port
  def fallbacks_on_dirport(self, port):
    return filter(lambda x: x.dirport == port, self.fallbacks)

  # log a message about the proportion of fallbacks on IPv4 ORPort port
  # and return that count
  def describe_fallback_ipv4_orport(self, port):
    port_count = len(self.fallbacks_on_ipv4_orport(port))
    fallback_count = len(self.fallbacks)
    logging.warning('%s of fallbacks are on IPv4 ORPort %d'%(
                    CandidateList.describe_percentage(port_count,
                                                      fallback_count),
                    port))
    return port_count

  # log a message about the proportion of IPv6 fallbacks on IPv6 ORPort port
  # and return that count
  def describe_fallback_ipv6_orport(self, port):
    port_count = len(self.fallbacks_on_ipv6_orport(port))
    fallback_count = len(self.fallbacks_with_ipv6())
    logging.warning('%s of IPv6 fallbacks are on IPv6 ORPort %d'%(
                    CandidateList.describe_percentage(port_count,
                                                      fallback_count),
                    port))
    return port_count

  # log a message about the proportion of fallbacks on DirPort port
  # and return that count
  def describe_fallback_dirport(self, port):
    port_count = len(self.fallbacks_on_dirport(port))
    fallback_count = len(self.fallbacks)
    logging.warning('%s of fallbacks are on DirPort %d'%(
                    CandidateList.describe_percentage(port_count,
                                                      fallback_count),
                    port))
    return port_count

  # log a message about the proportion of fallbacks on each dirport,
  # each IPv4 orport, and each IPv6 orport
  def describe_fallback_ports(self):
    fallback_count = len(self.fallbacks)
    ipv4_or_count = fallback_count
    ipv4_or_count -= self.describe_fallback_ipv4_orport(443)
    ipv4_or_count -= self.describe_fallback_ipv4_orport(9001)
    logging.warning('%s of fallbacks are on other IPv4 ORPorts'%(
                    CandidateList.describe_percentage(ipv4_or_count,
                                                      fallback_count)))
    ipv6_fallback_count = len(self.fallbacks_with_ipv6())
    ipv6_or_count = ipv6_fallback_count
    ipv6_or_count -= self.describe_fallback_ipv6_orport(443)
    ipv6_or_count -= self.describe_fallback_ipv6_orport(9001)
    logging.warning('%s of IPv6 fallbacks are on other IPv6 ORPorts'%(
                    CandidateList.describe_percentage(ipv6_or_count,
                                                      ipv6_fallback_count)))
    dir_count = fallback_count
    dir_count -= self.describe_fallback_dirport(80)
    dir_count -= self.describe_fallback_dirport(9030)
    logging.warning('%s of fallbacks are on other DirPorts'%(
                    CandidateList.describe_percentage(dir_count,
                                                      fallback_count)))

  # return a list of fallbacks which have the Exit flag
  def fallbacks_with_exit(self):
    return filter(lambda x: x.is_exit(), self.fallbacks)

  # log a message about the proportion of fallbacks with an Exit flag
  def describe_fallback_exit_flag(self):
    exit_falback_count = len(self.fallbacks_with_exit())
    fallback_count = len(self.fallbacks)
    logging.warning('%s of fallbacks have the Exit flag'%(
                    CandidateList.describe_percentage(exit_falback_count,
                                                      fallback_count)))

  # return a list of fallbacks which have an IPv6 address
  def fallbacks_with_ipv6(self):
    return filter(lambda x: x.has_ipv6(), self.fallbacks)

  # log a message about the proportion of fallbacks on IPv6
  def describe_fallback_ip_family(self):
    ipv6_falback_count = len(self.fallbacks_with_ipv6())
    fallback_count = len(self.fallbacks)
    logging.warning('%s of fallbacks are on IPv6'%(
                    CandidateList.describe_percentage(ipv6_falback_count,
                                                      fallback_count)))

  def summarise_fallbacks(self, eligible_count, operator_count, failed_count,
                          guard_count, target_count):
    s = ''
    s += '/* To comment-out entries in this file, use C comments, and add *'
    s += ' to the start of each line. (stem finds fallback entries using "'
    s += ' at the start of a line.) */'
    s += '\n'
    # Report:
    #  whether we checked consensus download times
    #  the number of fallback directories (and limits/exclusions, if relevant)
    #  min & max fallback bandwidths
    #  #error if below minimum count
    if PERFORM_IPV4_DIRPORT_CHECKS or PERFORM_IPV6_DIRPORT_CHECKS:
      s += '/* Checked %s%s%s DirPorts served a consensus within %.1fs. */'%(
            'IPv4' if PERFORM_IPV4_DIRPORT_CHECKS else '',
            ' and ' if (PERFORM_IPV4_DIRPORT_CHECKS
                        and PERFORM_IPV6_DIRPORT_CHECKS) else '',
            'IPv6' if PERFORM_IPV6_DIRPORT_CHECKS else '',
            CONSENSUS_DOWNLOAD_SPEED_MAX)
    else:
      s += '/* Did not check IPv4 or IPv6 DirPort consensus downloads. */'
    s += '\n'
    # Multiline C comment with #error if things go bad
    s += '/*'
    s += '\n'
    # Integers don't need escaping in C comments
    fallback_count = len(self.fallbacks)
    if FALLBACK_PROPORTION_OF_GUARDS is None:
      fallback_proportion = ''
    else:
      fallback_proportion = ', Target %d (%d * %.2f)'%(target_count,
                                                guard_count,
                                                FALLBACK_PROPORTION_OF_GUARDS)
    s += 'Final Count: %d (Eligible %d%s'%(fallback_count, eligible_count,
                                           fallback_proportion)
    if MAX_FALLBACK_COUNT is not None:
      s += ', Max %d'%(MAX_FALLBACK_COUNT)
    s += ')\n'
    if eligible_count != fallback_count:
      removed_count = eligible_count - fallback_count
      excess_to_target_or_max = (eligible_count - operator_count - failed_count
                                 - fallback_count)
      # some 'Failed' failed the check, others 'Skipped' the check,
      # if we already had enough successful downloads
      s += ('Excluded: %d (Same Operator %d, Failed/Skipped Download %d, ' +
            'Excess %d)')%(removed_count, operator_count, failed_count,
                           excess_to_target_or_max)
      s += '\n'
    min_fb = self.fallback_min()
    min_bw = min_fb._data['measured_bandwidth']
    max_fb = self.fallback_max()
    max_bw = max_fb._data['measured_bandwidth']
    s += 'Bandwidth Range: %.1f - %.1f MByte/s'%(min_bw/(1024.0*1024.0),
                                                 max_bw/(1024.0*1024.0))
    s += '\n'
    s += '*/'
    if fallback_count < MIN_FALLBACK_COUNT:
      # We must have a minimum number of fallbacks so they are always
      # reachable, and are in diverse locations
      s += '\n'
      s += '#error Fallback Count %d is too low. '%(fallback_count)
      s += 'Must be at least %d for diversity. '%(MIN_FALLBACK_COUNT)
      s += 'Try adding entries to the whitelist, '
      s += 'or setting INCLUDE_UNLISTED_ENTRIES = True.'
    return s

def process_existing():
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('stem').setLevel(logging.INFO)
  whitelist = {'data': parse_fallback_file(FALLBACK_FILE_NAME),
               'name': FALLBACK_FILE_NAME}
  blacklist = {'data': read_from_file(BLACKLIST_FILE_NAME, MAX_LIST_FILE_SIZE),
               'name': BLACKLIST_FILE_NAME}
  list_fallbacks(whitelist, blacklist)

def process_default():
  logging.basicConfig(level=logging.WARNING)
  logging.getLogger('stem').setLevel(logging.WARNING)
  whitelist = {'data': read_from_file(WHITELIST_FILE_NAME, MAX_LIST_FILE_SIZE),
               'name': WHITELIST_FILE_NAME}
  blacklist = {'data': read_from_file(BLACKLIST_FILE_NAME, MAX_LIST_FILE_SIZE),
               'name': BLACKLIST_FILE_NAME}
  list_fallbacks(whitelist, blacklist)

## Main Function
def main():
  if get_command() == 'check_existing':
    process_existing()
  else:
    process_default()

def get_command():
  if len(sys.argv) == 2:
    return sys.argv[1]
  else:
    return None

def log_excluded(msg, *args):
  if get_command() == 'check_existing':
    logging.warning(msg, *args)
  else:
    logging.info(msg, *args)

def list_fallbacks(whitelist, blacklist):
  """ Fetches required onionoo documents and evaluates the
      fallback directory criteria for each of the relays """

  logging.warning('Downloading and parsing Onionoo data. ' +
                  'This may take some time.')
  # find relays that could be fallbacks
  candidates = CandidateList()
  candidates.add_relays()

  # work out how many fallbacks we want
  guard_count = candidates.count_guards()
  if FALLBACK_PROPORTION_OF_GUARDS is None:
    target_count = guard_count
  else:
    target_count = int(guard_count * FALLBACK_PROPORTION_OF_GUARDS)
  # the maximum number of fallbacks is the least of:
  # - the target fallback count (FALLBACK_PROPORTION_OF_GUARDS * guard count)
  # - the maximum fallback count (MAX_FALLBACK_COUNT)
  if MAX_FALLBACK_COUNT is None:
    max_count = target_count
  else:
    max_count = min(target_count, MAX_FALLBACK_COUNT)

  candidates.compute_fallbacks()
  prefilter_fallbacks = copy.copy(candidates.fallbacks)

  # filter with the whitelist and blacklist
  # if a relay has changed IPv4 address or ports recently, it will be excluded
  # as ineligible before we call apply_filter_lists, and so there will be no
  # warning that the details have changed from those in the whitelist.
  # instead, there will be an info-level log during the eligibility check.
  initial_count = len(candidates.fallbacks)
  excluded_count = candidates.apply_filter_lists(whitelist, blacklist)
  print candidates.summarise_filters(initial_count, excluded_count)
  eligible_count = len(candidates.fallbacks)

  # calculate the measured bandwidth of each relay,
  # then remove low-bandwidth relays
  candidates.calculate_measured_bandwidth()
  candidates.remove_low_bandwidth_relays()

  # print the raw fallback list
  #for x in candidates.fallbacks:
  #  print x.fallbackdir_line(True)
  #  print json.dumps(candidates[x]._data, sort_keys=True, indent=4,
  #                   separators=(',', ': '), default=json_util.default)

  # impose mandatory conditions here, like one per contact, family, IP
  # in measured bandwidth order
  candidates.sort_fallbacks_by_measured_bandwidth()
  operator_count = 0
  # only impose these limits on the final list - operators can nominate
  # multiple candidate fallbacks, and then we choose the best set
  if not OUTPUT_CANDIDATES:
    operator_count += candidates.limit_fallbacks_same_ip()
    operator_count += candidates.limit_fallbacks_same_contact()
    operator_count += candidates.limit_fallbacks_same_family()

  # check if each candidate can serve a consensus
  # there's a small risk we've eliminated relays from the same operator that
  # can serve a consensus, in favour of one that can't
  # but given it takes up to 15 seconds to check each consensus download,
  # the risk is worth it
  if PERFORM_IPV4_DIRPORT_CHECKS or PERFORM_IPV6_DIRPORT_CHECKS:
    logging.warning('Checking consensus download speeds. ' +
                    'This may take some time.')
  failed_count = candidates.perform_download_consensus_checks(max_count)

  # analyse and log interesting diversity metrics
  # like netblock, ports, exit, IPv4-only
  # (we can't easily analyse AS, and it's hard to accurately analyse country)
  candidates.describe_fallback_ip_family()
  # if we can't import the ipaddress module, we can't do netblock analysis
  if HAVE_IPADDRESS:
    candidates.describe_fallback_netblocks()
  candidates.describe_fallback_ports()
  candidates.describe_fallback_exit_flag()

  # output C comments summarising the fallback selection process
  if len(candidates.fallbacks) > 0:
    print candidates.summarise_fallbacks(eligible_count, operator_count,
                                         failed_count, guard_count,
                                         target_count)
  else:
    print '/* No Fallbacks met criteria */'

  # output C comments specifying the OnionOO data used to create the list
  for s in fetch_source_list():
    print describe_fetch_source(s)

  # sort the list differently depending on why we've created it:
  # if we're outputting the final fallback list, sort by fingerprint
  # this makes diffs much more stable
  # otherwise, if we're trying to find a bandwidth cutoff, or we want to
  # contact operators in priority order, sort by bandwidth (not yet
  # implemented)
  # otherwise, if we're contacting operators, sort by contact
  candidates.sort_fallbacks_by(OUTPUT_SORT_FIELD)

  for x in candidates.fallbacks:
    print x.fallbackdir_line(candidates.fallbacks, prefilter_fallbacks)

if __name__ == "__main__":
  main()
