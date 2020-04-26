/* Copyright (c) 2019 Christian Hofer.
 * Copyright (c) 2019-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dns_string.c
 * \brief Encode DNS messages to string and decode DNS messages from string.
 **/

#define DNS_WIREFORMAT_PRIVATE
#include "lib/encoding/dns_string.h"

#include "lib/buf/buffers.h"
#include "lib/container/dns_message.h"
#include "lib/container/dns_message_st.h"
#include "lib/container/smartlist.h"
#include "lib/defs/digest_sizes.h"
#include "lib/defs/dns_types.h"
#include "lib/encoding/binascii.h"
#include "lib/encoding/dns_wireformat.h"
#include "lib/log/log.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/string/printf.h"
#include "lib/string/util_string.h"

#include <string.h>

// LCOV_EXCL_START
/** Return a pointer to a NUL-terminated opcode. */
static const char *
dns_opcode_str(uint8_t opcode)
{
  static char buf[14];
  memset(&buf, 0, sizeof(buf));

  switch (opcode) {
    case DNS_OPCODE_QUERY:
      return "QUERY";
    case DNS_OPCODE_IQUERY:
      return "IQUERY";
    case DNS_OPCODE_STATUS:
      return "STATUS";
    case DNS_OPCODE_UNKNOWN:
      return "UNKNOWN";
    case DNS_OPCODE_NOTIFY:
      return "NOTIFY";
    case DNS_OPCODE_UPDATE:
      return "UPDATE";
    default:
      tor_snprintf(buf, sizeof(buf), "UNKNOWN (%d)", opcode);
      return buf;
  }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
/** Return the DNS class for a given value. */
static uint16_t
dns_class_value_of(const char *value)
{
  if (!value) {
    return DNS_CLASS_NONE;
  }

  if (strcasecmp(value, "IN") == 0) {
    return DNS_CLASS_IN;
  }
  if (strcasecmp(value, "CHAOS") == 0) {
    return DNS_CLASS_CHAOS;
  }
  if (strcasecmp(value, "HESIOD") == 0) {
    return DNS_CLASS_HESIOD;
  }
  if (strcasecmp(value, "NONE") == 0) {
    return DNS_CLASS_NONE;
  }
  if (strcasecmp(value, "ANY") == 0) {
    return DNS_CLASS_ANY;
  }

  return DNS_CLASS_NONE;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
/** Return a pointer to a NUL-terminated DNS class. */
static const char *
dns_class_str(uint8_t class)
{
  static char buf[14];
  memset(&buf, 0, sizeof(buf));

  switch (class) {
    case DNS_CLASS_IN:
      return "IN";
    case DNS_CLASS_CHAOS:
      return "CHAOS";
    case DNS_CLASS_HESIOD:
      return "HESIOD";
    case DNS_CLASS_NONE:
      return "NONE";
    case DNS_CLASS_ANY:
      return "ANY";
    default:
      tor_snprintf(buf, sizeof(buf), "UNKNOWN (%d)", class);
      return buf;
  }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
/** Return a pointer to a NUL-terminated response code. */
static const char *
dns_response_code_str(uint8_t rcode)
{
  static char buf[14];
  memset(&buf, 0, sizeof(buf));

  switch (rcode) {
    case DNS_RCODE_NOERROR:
      return "NOERROR";
    case DNS_RCODE_FORMERR:
      return "FORMERR";
    case DNS_RCODE_SERVFAIL:
      return "SERVFAIL";
    case DNS_RCODE_NXDOMAIN:
      return "NXDOMAIN";
    case DNS_RCODE_NOTIMPL:
      return "NOTIMPL";
    case DNS_RCODE_REFUSED:
      return "REFUSED";
    case DNS_RCODE_YXDOMAIN:
      return "YXDOMAIN";
    case DNS_RCODE_YXRRSET:
      return "YXRRSET";
    case DNS_RCODE_NXRRSET:
      return "NXRRSET";
    case DNS_RCODE_NOTAUTH:
      return "NOTAUTH";
    case DNS_RCODE_NOTZONE:
      return "NOTZONE";
    case DNS_RCODE_BADSIG:
      return "BADSIG";
    case DNS_RCODE_BADKEY:
      return "BADKEY";
    case DNS_RCODE_BADTIME:
      return "BADTIME";
    case DNS_RCODE_BADMODE:
      return "BADMODE";
    case DNS_RCODE_BADNAME:
      return "BADNAME";
    case DNS_RCODE_BADALG:
      return "BADALG";
    case DNS_RCODE_BADTRUC:
      return "BADTRUC";
    default:
      tor_snprintf(buf, sizeof(buf), "UNKNOWN (%d)", rcode);
      return buf;
  }
}
// LCOV_EXCL_STOP

/** Return a new dns_name_t for the given value. */
dns_name_t *
dns_name_of(const char *value)
{
  dns_name_t *dn = dns_name_new();
  if (value) {
    dn->length = strlen(value);
    dn->value = tor_strdup(value);
  }
  return dn;
}

/** Return a pointer to a NUL-terminated DNS name. */
const char *
dns_name_str(const dns_name_t *name)
{
  if (!name || !name->value) {
    return "";
  }
  return name->value;
}

/** Return a new dns_type_t for the given value. */
dns_type_t *
dns_type_of(uint16_t value)
{
  dns_type_t *dt = dns_type_new();
  dt->value = value;
  dt->name = tor_strdup(dns_type_str(value));
  return dt;
}

// LCOV_EXCL_START
/** Return a pointer to a NUL-terminated DNS type. */
const char *
dns_type_str(uint16_t type)
{
  static char buf[16];
  memset(&buf, 0, sizeof(buf));

  switch (type) {
    case DNS_TYPE_NONE:
      return "NONE";
    case DNS_TYPE_A:
      return "A";
    case DNS_TYPE_NS:
      return "NS";
    case DNS_TYPE_MD:
      return "MD";
    case DNS_TYPE_MF:
      return "MF";
    case DNS_TYPE_CNAME:
      return "CNAME";
    case DNS_TYPE_SOA:
      return "SOA";
    case DNS_TYPE_MB:
      return "MB";
    case DNS_TYPE_MG:
      return "MG";
    case DNS_TYPE_MR:
      return "MR";
    case DNS_TYPE_NULL:
      return "NULL";
    case DNS_TYPE_WKS:
      return "WKS";
    case DNS_TYPE_PTR:
      return "PTR";
    case DNS_TYPE_HINFO:
      return "HINFO";
    case DNS_TYPE_MINFO:
      return "MINFO";
    case DNS_TYPE_MX:
      return "MX";
    case DNS_TYPE_TXT:
      return "TXT";
    case DNS_TYPE_RP:
      return "RP";
    case DNS_TYPE_AFSDB:
      return "AFSDB";
    case DNS_TYPE_X25:
      return "X25";
    case DNS_TYPE_ISDN:
      return "ISDN";
    case DNS_TYPE_RT:
      return "RT";
    case DNS_TYPE_NSAP:
      return "NSAP";
    case DNS_TYPE_NSAP_PTR:
      return "PTR";
    case DNS_TYPE_SIG:
      return "SIG";
    case DNS_TYPE_KEY:
      return "KEY";
    case DNS_TYPE_PX:
      return "PX";
    case DNS_TYPE_GPOS:
      return "GPOS";
    case DNS_TYPE_AAAA:
      return "AAAA";
    case DNS_TYPE_LOC:
      return "LOC";
    case DNS_TYPE_NXT:
      return "NXT";
    case DNS_TYPE_EID:
      return "EID";
    case DNS_TYPE_NIMLOC:
      return "NIMLOC";
    case DNS_TYPE_SRV:
      return "SRV";
    case DNS_TYPE_ATMA:
      return "ATMA";
    case DNS_TYPE_NAPTR:
      return "NAPTR";
    case DNS_TYPE_KX:
      return "KX";
    case DNS_TYPE_CERT:
      return "CERT";
    case DNS_TYPE_A6:
      return "A6";
    case DNS_TYPE_DNAME:
      return "DNAME";
    case DNS_TYPE_SINK:
      return "SINK";
    case DNS_TYPE_OPT:
      return "OPT";
    case DNS_TYPE_APL:
      return "APL";
    case DNS_TYPE_DS:
      return "DS";
    case DNS_TYPE_SSHFP:
      return "SSHFP";
    case DNS_TYPE_IPSECKEY:
      return "IPSECKEY";
    case DNS_TYPE_RRSIG:
      return "RRSIG";
    case DNS_TYPE_NSEC:
      return "NSEC";
    case DNS_TYPE_DNSKEY:
      return "DNSKEY";
    case DNS_TYPE_DHCID:
      return "DHCID";
    case DNS_TYPE_NSEC3:
      return "NSEC3";
    case DNS_TYPE_NSEC3PARAM:
      return "NSEC3PARAM";
    case DNS_TYPE_TLSA:
      return "TLSA";
    case DNS_TYPE_HIP:
      return "HIP";
    case DNS_TYPE_CDS:
      return "CDS";
    case DNS_TYPE_CDNSKEY:
      return "CDNSKEY";
    case DNS_TYPE_OPENPGPKEY:
      return "OPENPGPKEY";
    case DNS_TYPE_SMIMEA:
      return "SMIMEA";
    case DNS_TYPE_TKEY:
      return "TKEY";
    case DNS_TYPE_TSIG:
      return "TSIG";
    case DNS_TYPE_IXFR:
      return "IXFR";
    case DNS_TYPE_AXFR:
      return "AXFR";
    case DNS_TYPE_MAILB:
      return "MAILB";
    case DNS_TYPE_MAILA:
      return "MAILA";
    case DNS_TYPE_ALL:
      return "ALL";
    case DNS_TYPE_URI:
      return "URI";
    case DNS_TYPE_CAA:
      return "CAA";
    case DNS_TYPE_TA:
      return "TA";
    case DNS_TYPE_DLV:
      return "DLV";
    default:
      tor_snprintf(buf, sizeof(buf), "TYPE%d", type);
      return buf;
  }
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
/** Return the DNS type for the given value. */
dns_type_t *
dns_type_value_of(const char *value)
{
  if (!value) {
    return NULL;
  }

  if (strcasecmp(value, "NONE") == 0) {
    return dns_type_of(DNS_TYPE_NONE);
  }
  if (strcasecmp(value, "A") == 0) {
    return dns_type_of(DNS_TYPE_A);
  }
  if (strcasecmp(value, "NS") == 0) {
    return dns_type_of(DNS_TYPE_NS);
  }
  if (strcasecmp(value, "MD") == 0) {
    return dns_type_of(DNS_TYPE_MD);
  }
  if (strcasecmp(value, "MF") == 0) {
    return dns_type_of(DNS_TYPE_MF);
  }
  if (strcasecmp(value, "CNAME") == 0) {
    return dns_type_of(DNS_TYPE_CNAME);
  }
  if (strcasecmp(value, "SOA") == 0) {
    return dns_type_of(DNS_TYPE_SOA);
  }
  if (strcasecmp(value, "MB") == 0) {
    return dns_type_of(DNS_TYPE_MB);
  }
  if (strcasecmp(value, "MG") == 0) {
    return dns_type_of(DNS_TYPE_MG);
  }
  if (strcasecmp(value, "MR") == 0) {
    return dns_type_of(DNS_TYPE_MR);
  }
  if (strcasecmp(value, "NULL") == 0) {
    return dns_type_of(DNS_TYPE_NULL);
  }
  if (strcasecmp(value, "WKS") == 0) {
    return dns_type_of(DNS_TYPE_WKS);
  }
  if (strcasecmp(value, "PTR") == 0) {
    return dns_type_of(DNS_TYPE_PTR);
  }
  if (strcasecmp(value, "HINFO") == 0) {
    return dns_type_of(DNS_TYPE_HINFO);
  }
  if (strcasecmp(value, "MINFO") == 0) {
    return dns_type_of(DNS_TYPE_MINFO);
  }
  if (strcasecmp(value, "MX") == 0) {
    return dns_type_of(DNS_TYPE_MX);
  }
  if (strcasecmp(value, "TXT") == 0) {
    return dns_type_of(DNS_TYPE_TXT);
  }
  if (strcasecmp(value, "RP") == 0) {
    return dns_type_of(DNS_TYPE_RP);
  }
  if (strcasecmp(value, "AFSDB") == 0) {
    return dns_type_of(DNS_TYPE_AFSDB);
  }
  if (strcasecmp(value, "X25") == 0) {
    return dns_type_of(DNS_TYPE_X25);
  }
  if (strcasecmp(value, "ISDN") == 0) {
    return dns_type_of(DNS_TYPE_ISDN);
  }
  if (strcasecmp(value, "RT") == 0) {
    return dns_type_of(DNS_TYPE_RT);
  }
  if (strcasecmp(value, "NSAP") == 0) {
    return dns_type_of(DNS_TYPE_NSAP);
  }
  if (strcasecmp(value, "NSAP_PTR") == 0) {
    return dns_type_of(DNS_TYPE_NSAP_PTR);
  }
  if (strcasecmp(value, "SIG") == 0) {
    return dns_type_of(DNS_TYPE_SIG);
  }
  if (strcasecmp(value, "KEY") == 0) {
    return dns_type_of(DNS_TYPE_KEY);
  }
  if (strcasecmp(value, "PX") == 0) {
    return dns_type_of(DNS_TYPE_PX);
  }
  if (strcasecmp(value, "GPOS") == 0) {
    return dns_type_of(DNS_TYPE_GPOS);
  }
  if (strcasecmp(value, "AAAA") == 0) {
    return dns_type_of(DNS_TYPE_AAAA);
  }
  if (strcasecmp(value, "LOC") == 0) {
    return dns_type_of(DNS_TYPE_LOC);
  }
  if (strcasecmp(value, "NXT") == 0) {
    return dns_type_of(DNS_TYPE_NXT);
  }
  if (strcasecmp(value, "EID") == 0) {
    return dns_type_of(DNS_TYPE_EID);
  }
  if (strcasecmp(value, "NIMLOC") == 0) {
    return dns_type_of(DNS_TYPE_NIMLOC);
  }
  if (strcasecmp(value, "SRV") == 0) {
    return dns_type_of(DNS_TYPE_SRV);
  }
  if (strcasecmp(value, "ATMA") == 0) {
    return dns_type_of(DNS_TYPE_ATMA);
  }
  if (strcasecmp(value, "NAPTR") == 0) {
    return dns_type_of(DNS_TYPE_NAPTR);
  }
  if (strcasecmp(value, "KX") == 0) {
    return dns_type_of(DNS_TYPE_KX);
  }
  if (strcasecmp(value, "CERT") == 0) {
    return dns_type_of(DNS_TYPE_CERT);
  }
  if (strcasecmp(value, "A6") == 0) {
    return dns_type_of(DNS_TYPE_A6);
  }
  if (strcasecmp(value, "DNAME") == 0) {
    return dns_type_of(DNS_TYPE_DNAME);
  }
  if (strcasecmp(value, "SINK") == 0) {
    return dns_type_of(DNS_TYPE_SINK);
  }
  if (strcasecmp(value, "OPT") == 0) {
    return dns_type_of(DNS_TYPE_OPT);
  }
  if (strcasecmp(value, "APL") == 0) {
    return dns_type_of(DNS_TYPE_APL);
  }
  if (strcasecmp(value, "DS") == 0) {
    return dns_type_of(DNS_TYPE_DS);
  }
  if (strcasecmp(value, "SSHFP") == 0) {
    return dns_type_of(DNS_TYPE_SSHFP);
  }
  if (strcasecmp(value, "IPSECKEY") == 0) {
    return dns_type_of(DNS_TYPE_IPSECKEY);
  }
  if (strcasecmp(value, "RRSIG") == 0) {
    return dns_type_of(DNS_TYPE_RRSIG);
  }
  if (strcasecmp(value, "NSEC") == 0) {
    return dns_type_of(DNS_TYPE_NSEC);
  }
  if (strcasecmp(value, "DNSKEY") == 0) {
    return dns_type_of(DNS_TYPE_DNSKEY);
  }
  if (strcasecmp(value, "DHCID") == 0) {
    return dns_type_of(DNS_TYPE_DHCID);
  }
  if (strcasecmp(value, "NSEC3") == 0) {
    return dns_type_of(DNS_TYPE_NSEC3);
  }
  if (strcasecmp(value, "NSEC3PARAM") == 0) {
    return dns_type_of(DNS_TYPE_NSEC3PARAM);
  }
  if (strcasecmp(value, "TLSA") == 0) {
    return dns_type_of(DNS_TYPE_TLSA);
  }
  if (strcasecmp(value, "HIP") == 0) {
    return dns_type_of(DNS_TYPE_HIP);
  }
  if (strcasecmp(value, "CDS") == 0) {
    return dns_type_of(DNS_TYPE_CDS);
  }
  if (strcasecmp(value, "CDNSKEY") == 0) {
    return dns_type_of(DNS_TYPE_CDNSKEY);
  }
  if (strcasecmp(value, "OPENPGPKEY") == 0) {
    return dns_type_of(DNS_TYPE_OPENPGPKEY);
  }
  if (strcasecmp(value, "SMIMEA") == 0) {
    return dns_type_of(DNS_TYPE_SMIMEA);
  }
  if (strcasecmp(value, "TKEY") == 0) {
    return dns_type_of(DNS_TYPE_TKEY);
  }
  if (strcasecmp(value, "TSIG") == 0) {
    return dns_type_of(DNS_TYPE_TSIG);
  }
  if (strcasecmp(value, "IXFR") == 0) {
    return dns_type_of(DNS_TYPE_IXFR);
  }
  if (strcasecmp(value, "AXFR") == 0) {
    return dns_type_of(DNS_TYPE_AXFR);
  }
  if (strcasecmp(value, "MAILB") == 0) {
    return dns_type_of(DNS_TYPE_MAILB);
  }
  if (strcasecmp(value, "MAILA") == 0) {
    return dns_type_of(DNS_TYPE_MAILA);
  }
  if (strcasecmp(value, "ALL") == 0) {
    return dns_type_of(DNS_TYPE_ALL);
  }
  if (strcasecmp(value, "URI") == 0) {
    return dns_type_of(DNS_TYPE_URI);
  }
  if (strcasecmp(value, "CAA") == 0) {
    return dns_type_of(DNS_TYPE_CAA);
  }
  if (strcasecmp(value, "TA") == 0) {
    return dns_type_of(DNS_TYPE_TA);
  }
  if (strcasecmp(value, "DLV") == 0) {
    return dns_type_of(DNS_TYPE_DLV);
  }

  return NULL;
}
// LCOV_EXCL_STOP

/** Return a pointer to a NUL-terminated list of DNS types. */
const char *
dns_types_str(const smartlist_t *types)
{
  static char buf[96];
  memset(&buf, 0, sizeof(buf));

  if (!types) {
    return buf;
  }

  memset(buf, 0, sizeof(buf));
  SMARTLIST_FOREACH_BEGIN(types, dns_type_t *, type) {
    if (strlen(buf) < sizeof(buf)) {
      tor_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " %s",
                   type->name);
    }
  } SMARTLIST_FOREACH_END(type);

  return buf;
}

//
// Header

/** Return a pointer to a NUL-terminated header. */
const char *
dns_header_str(const dns_header_t *dh)
{
  static char buf[200];
  memset(&buf, 0, sizeof(buf));

  tor_snprintf(buf, sizeof(buf),
               "->>HEADER<<- opcode: %s, status: %s, id: %d\n"
               "flags:%s%s%s%s%s%s%s%s; "
               "QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d",
               dns_opcode_str(dh->opcode),
               dns_response_code_str(dh->rcode),
               dh->id, dh->qr ? " qr" : "", dh->aa ? " aa" : "",
               dh->tc ? " tc" : "", dh->rd ? " rd" : "", dh->ra ? " ra" : "",
               dh->z ? " z" : "", dh->ad ? " ad" : "", dh->cd ? " cd" : "",
               dh->qdcount, dh->ancount, dh->nscount, dh->arcount);

  return buf;
}

//
// Question

/** Return a pointer to a NUL-terminated question. */
const char *
dns_question_str(const dns_question_t *dq)
{
  static char buf[200];
  memset(&buf, 0, sizeof(buf));

  if (!dq || !dq->qtype) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%-10s \t%s\t%s", dns_name_str(dq->qname),
               dns_class_str(dq->qclass), dq->qtype->name);

  return buf;
}

//
// Resource Record - A

/** Return a new A record for the given parts. */
char *
dns_a_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  if (smartlist_len(parts) < 5) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 5)",
              smartlist_len(parts));
    return NULL;
  }

  return tor_strdup(smartlist_get(parts, 4));
}

/** Return a pointer to a NUL-terminated A record. */
const char *
dns_a_str(const char *da)
{
  if (!da) {
    return "";
  }
  return da;
}

//
// Resource Record - NS

/** Return a new NS record for the given parts. */
dns_name_t *
dns_ns_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  if (smartlist_len(parts) < 5) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 5)",
              smartlist_len(parts));
    return dns_name_new();
  }

  return dns_name_of(smartlist_get(parts, 4));
}

/** Return a pointer to a NUL-terminated NS record. */
const char *
dns_ns_str(const dns_name_t *dns)
{
  return dns_name_str(dns);
}

//
// Resource Record - CNAME

/** Return a new CNAME record for the given parts. */
dns_name_t *
dns_cname_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  if (smartlist_len(parts) < 5) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 5)",
              smartlist_len(parts));
    return dns_name_new();
  }

  return dns_name_of(smartlist_get(parts, 4));
}

/** Return a pointer to a NUL-terminated CNAME record. */
const char *
dns_cname_str(const dns_name_t *dcname)
{
  return dns_name_str(dcname);
}

//
// Resource Record - SOA

/** Return a new SOA record for the given parts. */
dns_soa_t *
dns_soa_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_soa_t *dsoa = dns_soa_new();

  if (smartlist_len(parts) < 11) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 11)",
              smartlist_len(parts));
    return dsoa;
  }

  dsoa->mname = dns_name_of(smartlist_get(parts, 4));
  dsoa->rname = dns_name_of(smartlist_get(parts, 5));
  dsoa->serial = (uint32_t) strtoul(smartlist_get(parts, 6), NULL, 10);
  dsoa->refresh = (uint32_t) strtoul(smartlist_get(parts, 7), NULL, 10);
  dsoa->retry = (uint32_t) strtoul(smartlist_get(parts, 8), NULL, 10);
  dsoa->expire = (uint32_t) strtoul(smartlist_get(parts, 9), NULL, 10);
  dsoa->minimum = (uint32_t) strtoul(smartlist_get(parts, 10), NULL, 10);

  return dsoa;
}

/** Return a pointer to a NUL-terminated SOA record. */
const char *
dns_soa_str(const dns_soa_t *dsoa)
{
  static char buf[400];
  memset(&buf, 0, sizeof(buf));

  if (!dsoa) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%s %s %d %d %d %d %d",
               dns_name_str(dsoa->mname), dns_name_str(dsoa->rname),
               dsoa->serial, dsoa->refresh, dsoa->retry, dsoa->expire,
               dsoa->minimum);

  return buf;
}

//
// Resource Record - PTR

/** Return a new PTR record for the given parts. */
dns_name_t *
dns_ptr_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  if (smartlist_len(parts) < 5) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 5)",
              smartlist_len(parts));
    return dns_name_new();
  }

  return dns_name_of(smartlist_get(parts, 4));
}

/** Return a pointer to a NUL-terminated PTR record. */
const char *
dns_ptr_str(const dns_name_t *dptr)
{
  return dns_name_str(dptr);
}

//
// Resource Record - MX

/** Return a new MX record for the given parts. */
dns_mx_t *
dns_mx_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_mx_t *dmx = dns_mx_new();

  if (smartlist_len(parts) < 6) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 6)",
              smartlist_len(parts));
    return dmx;
  }

  dmx->preference = strtol(smartlist_get(parts, 4), NULL, 10);
  dmx->exchange = dns_name_of(smartlist_get(parts, 5));

  return dmx;
}

/** Return a pointer to a NUL-terminated MX record. */
const char *
dns_mx_str(const dns_mx_t *dmx)
{
  static char buf[400];
  memset(&buf, 0, sizeof(buf));

  if (!dmx) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%d %s", dmx->preference,
               dns_name_str(dmx->exchange));

  return buf;
}

//
// Resource Record - KEY

/** Return a new KEY record for the given parts. */
dns_key_t *
dns_key_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_key_t *dkey = dns_key_new();

  if (smartlist_len(parts) < 8) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 8)",
              smartlist_len(parts));
    return dkey;
  }

  dkey->flags = strtol(smartlist_get(parts, 4), NULL, 10);
  dkey->protocol = strtol(smartlist_get(parts, 5), NULL, 10);
  dkey->algorithm = strtol(smartlist_get(parts, 6), NULL, 10);

  char *public_key = smartlist_get(parts, 7);
  size_t public_key_len = strlen(public_key);
  dkey->public_key = tor_malloc_zero(base64_decode_maxsize(public_key_len));
  dkey->public_key_len = base64_decode_maxsize(public_key_len);

  if (public_key[public_key_len - 1] == '=') {
    dkey->public_key_len--;
  }
  if (public_key[public_key_len - 2] == '=') {
    dkey->public_key_len--;
  }

  if (base64_decode((char *)dkey->public_key, dkey->public_key_len,
                    public_key, public_key_len) < 0) {
    log_debug(LD_GENERAL, "unable to convert base64 string to bytes");
    tor_free(dkey->public_key);
    dkey->public_key_len = 0;
  }

  return dkey;
}

/** Return a pointer to a NUL-terminated KEY record. */
const char *
dns_key_str(const dns_key_t *dkey)
{
  static char buf[400];
  static char public_key[360];

  memset(&buf, 0, sizeof(buf));
  memset(&public_key, 0, sizeof(public_key));

  if (!dkey) {
    return buf;
  }

  base64_encode(public_key, sizeof(public_key),
                (const char *) dkey->public_key, dkey->public_key_len, 0);

  tor_snprintf(buf, sizeof(buf), "%d %d %d %s", dkey->flags, dkey->protocol,
               dkey->algorithm, public_key);

  return buf;
}

//
// Resource Record - AAAA

/** Return a new AAAA record for the given parts. */
char *
dns_aaaa_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  if (smartlist_len(parts) < 5) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 5)",
              smartlist_len(parts));
    return NULL;
  }

  return tor_strdup(smartlist_get(parts, 4));
}

/** Return a pointer to a NUL-terminated AAAA record. */
const char *
dns_aaaa_str(const char *daaaa)
{
  if (!daaaa) {
    return "";
  }
  return daaaa;
}

//
// Resource Record - DS

/** Return a new DS record for the given parts. */
dns_ds_t *
dns_ds_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_ds_t *dds = dns_ds_new();

  if (smartlist_len(parts) < 8) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 8)",
              smartlist_len(parts));
    return dds;
  }

  dds->key_tag = strtol(smartlist_get(parts, 4), NULL, 10);
  dds->algorithm = strtol(smartlist_get(parts, 5), NULL, 10);
  dds->digest_type = strtol(smartlist_get(parts, 6), NULL, 10);

  size_t destlen = 0;
  if (hex_to_bin(&dds->digest, &destlen, smartlist_get(parts, 7)) < 0) {
    log_debug(LD_GENERAL, "unable to convert hex string to bytes");
    tor_free(dds->digest);
  }
  dds->digest_len = (uint16_t) destlen;

  return dds;
}

/** Return a pointer to a NUL-terminated DS record. */
const char *
dns_ds_str(const dns_ds_t *dds)
{
  static char buf[400];
  memset(&buf, 0, sizeof(buf));

  if (!dds) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%d %d %d %s", dds->key_tag, dds->algorithm,
               dds->digest_type,
               hex_str((const char *) dds->digest, dds->digest_len));

  return buf;
}

//
// Resource Record - RRSIG

/** Return a new RRSIG record for the given parts. */
dns_rrsig_t *
dns_rrsig_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_rrsig_t *drrsig = dns_rrsig_new();

  if (smartlist_len(parts) < 13) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 13)",
              smartlist_len(parts));
    return drrsig;
  }

  drrsig->type_covered = dns_type_value_of(smartlist_get(parts, 4));
  drrsig->algorithm = strtol(smartlist_get(parts, 5), NULL, 10);
  drrsig->labels = strtol(smartlist_get(parts, 6), NULL, 10);
  drrsig->original_ttl = (uint32_t) strtoul(smartlist_get(parts, 7), NULL, 10);
  drrsig->signature_inception = (uint32_t) strtoul(smartlist_get(parts, 8),
                                                   NULL, 10);
  drrsig->signature_expiration = (uint32_t) strtoul(smartlist_get(parts, 9),
                                                    NULL, 10);
  drrsig->key_tag = strtol(smartlist_get(parts, 10), NULL, 10);
  drrsig->signer_name = dns_name_of(smartlist_get(parts, 11));

  char *signature = smartlist_get(parts, 12);
  size_t signature_len = strlen(signature);
  drrsig->signature = tor_malloc_zero(base64_decode_maxsize(signature_len));
  drrsig->signature_len = base64_decode_maxsize(signature_len);

  if (signature[signature_len - 1] == '=') {
    drrsig->signature_len--;
  }
  if (signature[signature_len - 2] == '=') {
    drrsig->signature_len--;
  }

  if (base64_decode((char *)drrsig->signature, drrsig->signature_len,
                    signature, signature_len) < 0) {
    log_debug(LD_GENERAL, "unable to convert base64 string to bytes");
    tor_free(drrsig->signature);
    drrsig->signature_len = 0;
  }

  return drrsig;
}

/** Return a pointer to a NUL-terminated RRSIG record. */
const char *
dns_rrsig_str(const dns_rrsig_t *drrsig)
{
  static char buf[480];
  static char signature[400];

  memset(&buf, 0, sizeof(buf));
  memset(&signature, 0, sizeof(signature));

  if (!drrsig || !drrsig->type_covered) {
    return buf;
  }

  base64_encode(signature, sizeof(signature), (const char *) drrsig->signature,
                drrsig->signature_len, 0);

  tor_snprintf(buf, sizeof(buf), "%s %d %d %u %u %u %d %s %s",
               drrsig->type_covered->name, drrsig->algorithm, drrsig->labels,
               drrsig->original_ttl, drrsig->signature_inception,
               drrsig->signature_expiration, drrsig->key_tag,
               dns_name_str(drrsig->signer_name), signature);

  return buf;
}

//
// Resource Record - NSEC

/** Return a new NSEC record for the given parts. */
dns_nsec_t *
dns_nsec_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_nsec_t *dnsec = dns_nsec_new();

  if (smartlist_len(parts) < 5) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 5)",
              smartlist_len(parts));
    return dnsec;
  }

  dnsec->next_domain_name = dns_name_of(smartlist_get(parts, 4));
  for (int i = 5, length = smartlist_len(parts); i < length; i++) {
    dns_type_t *type = dns_type_value_of(smartlist_get(parts, i));
    if (type) {
      smartlist_add(dnsec->types, type);
    }
  }

  return dnsec;
}

/** Return a pointer to a NUL-terminated NSEC record. */
const char *
dns_nsec_str(const dns_nsec_t *dnsec)
{
  static char buf[128];
  memset(&buf, 0, sizeof(buf));

  if (!dnsec) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%s%s", dns_name_str(dnsec->next_domain_name),
               dns_types_str(dnsec->types));

  return buf;
}

//
// Resource Record - DNSKEY

/** Return a new DNSKEY record for the given parts. */
dns_dnskey_t *
dns_dnskey_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_dnskey_t *ddnskey = dns_dnskey_new();

  if (smartlist_len(parts) < 8) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 8)",
              smartlist_len(parts));
    return ddnskey;
  }

  ddnskey->flags = strtol(smartlist_get(parts, 4), NULL, 10);
  ddnskey->protocol = strtol(smartlist_get(parts, 5), NULL, 10);
  ddnskey->algorithm = strtol(smartlist_get(parts, 6), NULL, 10);

  char *public_key = smartlist_get(parts, 7);
  size_t public_key_len = strlen(public_key);
  ddnskey->public_key = tor_malloc_zero(base64_decode_maxsize(public_key_len));
  ddnskey->public_key_len = base64_decode_maxsize(public_key_len);

  if (public_key[public_key_len - 1] == '=') {
    ddnskey->public_key_len--;
  }
  if (public_key[public_key_len - 2] == '=') {
    ddnskey->public_key_len--;
  }

  if (base64_decode((char *)ddnskey->public_key, ddnskey->public_key_len,
                    public_key, public_key_len) < 0) {
    log_debug(LD_GENERAL, "unable to convert base64 string to bytes");
    tor_free(ddnskey->public_key);
    ddnskey->public_key_len = 0;
  }

  return ddnskey;
}

/** Return a pointer to a NUL-terminated DNSKEY record. */
const char *
dns_dnskey_str(const dns_dnskey_t *ddnskey)
{
  static char buf[400];
  static char public_key[360];

  memset(&buf, 0, sizeof(buf));
  memset(&public_key, 0, sizeof(public_key));

  if (!ddnskey) {
    return buf;
  }

  base64_encode(public_key, sizeof(public_key),
                (const char *) ddnskey->public_key, ddnskey->public_key_len,
                0);

  tor_snprintf(buf, sizeof(buf), "%d %d %d %s", ddnskey->flags,
               ddnskey->protocol, ddnskey->algorithm, public_key);

  return buf;
}

//
// Resource Record - NSEC3

/** Return a new NSEC3 record for the given parts. */
dns_nsec3_t *
dns_nsec3_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_nsec3_t *dnsec3 = dns_nsec3_new();

  if (smartlist_len(parts) < 9) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 9)",
              smartlist_len(parts));
    return dnsec3;
  }

  dnsec3->hash_algorithm = strtol(smartlist_get(parts, 4), NULL, 10);
  dnsec3->flags = strtol(smartlist_get(parts, 5), NULL, 10);
  dnsec3->iterations = strtol(smartlist_get(parts, 6), NULL, 10);

  size_t destlen = 0;
  if (hex_to_bin(&dnsec3->salt, &destlen, smartlist_get(parts, 7)) < 0) {
    log_debug(LD_GENERAL, "unable to convert hex string to bytes");
    tor_free(dnsec3->salt);
  }
  dnsec3->salt_length = (uint8_t) destlen;

  char *next_hashed_owner_name = smartlist_get(parts, 8);
  char decoded_next[DIGEST_LEN];
  if (base32hex_decode(decoded_next, sizeof(decoded_next),
                       next_hashed_owner_name,
                       strlen(next_hashed_owner_name)) == 0) {
    log_debug(LD_GENERAL, "unable to convert base32hex string to bytes");
    dnsec3->hash_length = sizeof(decoded_next);
    dnsec3->next_hashed_owner_name = tor_memdup(decoded_next,
                                                dnsec3->hash_length);
  } else {
    log_debug(LD_GENERAL, "unable to convert base32hex string to bytes");
  }

  for (int i = 9, length = smartlist_len(parts); i < length; i++) {
    dns_type_t *type = dns_type_value_of(smartlist_get(parts, i));
    if (type) {
      smartlist_add(dnsec3->types, type);
    }
  }

  return dnsec3;
}

/** Return a pointer to a NUL-terminated NSEC3 record. */
const char *
dns_nsec3_str(const dns_nsec3_t *dnsec3)
{
  static char buf[128];
  static char hash[64];

  memset(&buf, 0, sizeof(buf));
  memset(&hash, 0, sizeof(hash));

  if (!dnsec3) {
    return buf;
  }

  base32hex_encode(hash, sizeof(hash),
                   (const char *) dnsec3->next_hashed_owner_name,
                   dnsec3->hash_length);

  tor_snprintf(buf, sizeof(buf), "%d %d %d %s %s%s",
               dnsec3->hash_algorithm, dnsec3->flags, dnsec3->iterations,
               hex_str((const char *) dnsec3->salt, dnsec3->salt_length),
                       hash, dns_types_str(dnsec3->types));

  return buf;
}

//
// Resource Record - NSEC3PARAM

/** Return a new NSEC3PARAM record for the given parts. */
dns_nsec3param_t *
dns_nsec3param_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_nsec3param_t *dnsec3param = dns_nsec3param_new();

  if (smartlist_len(parts) < 8) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 8)",
              smartlist_len(parts));
    return dnsec3param;
  }

  dnsec3param->hash_algorithm = strtol(smartlist_get(parts, 4), NULL, 10);
  dnsec3param->flags = strtol(smartlist_get(parts, 5), NULL, 10);
  dnsec3param->iterations = strtol(smartlist_get(parts, 6), NULL, 10);

  size_t destlen = 0;
  if (hex_to_bin(&dnsec3param->salt, &destlen, smartlist_get(parts, 7)) < 0) {
    log_debug(LD_GENERAL, "unable to convert hex string to bytes");
    tor_free(dnsec3param->salt);
  }
  dnsec3param->salt_length = (uint8_t) destlen;

  return dnsec3param;
}

/** Return a pointer to a NUL-terminated NSEC3PARAM record. */
const char *
dns_nsec3param_str(const dns_nsec3param_t *dnsec3param)
{
  static char buf[128];
  memset(&buf, 0, sizeof(buf));

  if (!dnsec3param) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%d %d %d %s", dnsec3param->hash_algorithm,
               dnsec3param->flags, dnsec3param->iterations,
               hex_str((const char *) dnsec3param->salt,
                       dnsec3param->salt_length));

  return buf;
}

//
// Resource Record - URI

/** Return a new URI record for the given parts. */
dns_uri_t *
dns_uri_value_of(const smartlist_t *parts)
{
  // LCOV_EXCL_START
  tor_assert(parts);
  // LCOV_EXCL_STOP

  dns_uri_t *duri = dns_uri_new();

  if (smartlist_len(parts) < 7) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 7)",
              smartlist_len(parts));
    return duri;
  }

  duri->priority = strtol(smartlist_get(parts, 4), NULL, 10);
  duri->weight = strtol(smartlist_get(parts, 5), NULL, 10);
  duri->target = tor_strdup(smartlist_get(parts, 6));

  return duri;
}

/** Return a pointer to a NUL-terminated URI record. */
const char *
dns_uri_str(const dns_uri_t *duri)
{
  static char buf[400];
  memset(&buf, 0, sizeof(buf));

  if (!duri) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%d %d %s", duri->priority, duri->weight,
               duri->target);

  return buf;
}

//
// Resource Record

/** Return a new dns_rr_t for the given <b>value</b>. */
dns_rr_t *
dns_rr_value_of(const char *value)
{
  // LCOV_EXCL_START
  tor_assert(value);
  // LCOV_EXCL_STOP

  dns_rr_t *drr = dns_rr_new();

  char *temp = tor_strdup(value);
  tor_strwhitespace(temp);

  smartlist_t *parts = smartlist_new();
  smartlist_split_string(parts, temp, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  tor_free(temp);

  if (smartlist_len(parts) < 4) {
    log_debug(LD_GENERAL, "invalid number of parts (%d < 4)",
              smartlist_len(parts));
    goto cleanup;
  }

  drr->name = dns_name_of(smartlist_get(parts, 0));
  drr->ttl = (uint32_t) strtoul(smartlist_get(parts, 1), NULL, 10);
  drr->rrclass = dns_class_value_of(smartlist_get(parts, 2));
  drr->rrtype = dns_type_value_of(smartlist_get(parts, 3));

  if (drr->rrtype == NULL) {
    log_debug(LD_GENERAL, "got invalid rrtype: %s",
              (char *) smartlist_get(parts, 3));
    goto cleanup;
  }

  switch (drr->rrtype->value) {
    case DNS_TYPE_A:
      drr->a = dns_a_value_of(parts);
      break;
    case DNS_TYPE_NS:
      drr->ns = dns_ns_value_of(parts);
      break;
    case DNS_TYPE_CNAME:
      drr->cname = dns_cname_value_of(parts);
      break;
    case DNS_TYPE_SOA:
      drr->soa = dns_soa_value_of(parts);
      break;
    case DNS_TYPE_PTR:
      drr->ptr = dns_ptr_value_of(parts);
      break;
    case DNS_TYPE_MX:
      drr->mx = dns_mx_value_of(parts);
      break;
    case DNS_TYPE_KEY:
      drr->key = dns_key_value_of(parts);
      break;
    case DNS_TYPE_AAAA:
      drr->aaaa = dns_aaaa_value_of(parts);
      break;
    case DNS_TYPE_DS:
      drr->ds = dns_ds_value_of(parts);
      break;
    case DNS_TYPE_RRSIG:
      drr->rrsig = dns_rrsig_value_of(parts);
      break;
    case DNS_TYPE_NSEC:
      drr->nsec = dns_nsec_value_of(parts);
      break;
    case DNS_TYPE_DNSKEY:
      drr->dnskey = dns_dnskey_value_of(parts);
      break;
    case DNS_TYPE_NSEC3:
      drr->nsec3 = dns_nsec3_value_of(parts);
      break;
    case DNS_TYPE_NSEC3PARAM:
      drr->nsec3param = dns_nsec3param_value_of(parts);
      break;
    case DNS_TYPE_URI:
      drr->uri = dns_uri_value_of(parts);
      break;
    default:
      log_debug(LD_GENERAL, "dns value of: %s not implemented",
                drr->rrtype->name);
  }
  dns_encode_rr_rdata(drr);

 cleanup:
  SMARTLIST_FOREACH(parts, char *, part, tor_free(part));
  smartlist_free(parts);
  return drr;
}

/** Return a pointer to a NUL-terminated RR. */
const char *
dns_rr_str(const dns_rr_t *drr)
{
  static char buf[1024];
  memset(&buf, 0, sizeof(buf));

  if (!drr || !drr->rrtype) {
    return buf;
  }

  tor_snprintf(buf, sizeof(buf), "%-10s \t%d\t%s\t%s\t%s",
               dns_name_str(drr->name), drr->ttl, dns_class_str(drr->rrclass),
               drr->rrtype->name, dns_rdata_str(drr));

  return buf;
}

/** Return a pointer to a NUL-terminated RR rdata. */
const char *
dns_rdata_str(const dns_rr_t *drr)
{
  if (!drr || !drr->rrtype || drr->rdlength == 0) {
    return "";
  }

  switch (drr->rrtype->value) {
    case DNS_TYPE_A:
      return dns_a_str(drr->a);
    case DNS_TYPE_NS:
      return dns_ns_str(drr->ns);
    case DNS_TYPE_CNAME:
      return dns_cname_str(drr->cname);
    case DNS_TYPE_SOA:
      return dns_soa_str(drr->soa);
    case DNS_TYPE_PTR:
      return dns_ptr_str(drr->ptr);
    case DNS_TYPE_MX:
      return dns_mx_str(drr->mx);
    case DNS_TYPE_KEY:
      return dns_key_str(drr->key);
    case DNS_TYPE_AAAA:
      return dns_aaaa_str(drr->aaaa);
    case DNS_TYPE_DS:
      return dns_ds_str(drr->ds);
    case DNS_TYPE_RRSIG:
      return dns_rrsig_str(drr->rrsig);
    case DNS_TYPE_NSEC:
      return dns_nsec_str(drr->nsec);
    case DNS_TYPE_DNSKEY:
      return dns_dnskey_str(drr->dnskey);
    case DNS_TYPE_NSEC3:
      return dns_nsec3_str(drr->nsec3);
    case DNS_TYPE_NSEC3PARAM:
      return dns_nsec3param_str(drr->nsec3param);
    case DNS_TYPE_URI:
      return dns_uri_str(drr->uri);
    default:
      return hex_str((const char *) drr->rdata, drr->rdlength);
  }
}

//
// Message

/** Return a pointer to a NUL-terminated message. */
const char *
dns_message_str(const dns_message_t *dm)
{
  static char buf[1800];
  memset(&buf, 0, sizeof(buf));

  if (!dm) {
    return buf;
  }

  buf_t *stash = buf_new();
  buf_add_string(stash, dns_header_str(dm->header));

  if (dm->header->qdcount > 0) {
    buf_add_string(stash, "\n\nQUESTION SECTION:");
  }
  SMARTLIST_FOREACH(dm->question_list, dns_question_t *, dq,
    buf_add_printf(stash, "\n%s", dns_question_str(dq)));

  if (dm->header->ancount > 0) {
    buf_add_string(stash, "\n\nANSWER SECTION:");
  }
  SMARTLIST_FOREACH(dm->answer_list, dns_rr_t *, dan,
    buf_add_printf(stash, "\n%s", dns_rr_str(dan)));

  if (dm->header->nscount > 0) {
    buf_add_string(stash, "\n\nAUTHORITY SECTION:");
  }
  SMARTLIST_FOREACH(dm->name_server_list, dns_rr_t *, dns,
    buf_add_printf(stash, "\n%s", dns_rr_str(dns)));

  if (dm->header->arcount > 0) {
    buf_add_string(stash, "\n\nADDITIONAL SECTION:");
  }
  SMARTLIST_FOREACH(dm->additional_record_list, dns_rr_t *, dar,
    buf_add_printf(stash, "\n%s", dns_rr_str(dar)));

  size_t size;
  char *data = buf_extract(stash, &size);

  tor_snprintf(buf, sizeof(buf), "%s", data);

  buf_free(stash);
  tor_free(data);

  return buf;
}
