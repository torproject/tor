/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char policies_c_id[] = \
  "$Id$";

/**
 * \file policies.c
 * \brief Code to parse and use address policies and exit policies.
 **/

#include "or.h"

static int expand_exit_policy_aliases(smartlist_t *entries, int assume_action);

static addr_policy_t *socks_policy = NULL;
static addr_policy_t *dir_policy = NULL;
static addr_policy_t *authdir_reject_policy = NULL;
static addr_policy_t *authdir_invalid_policy = NULL;
static addr_policy_t *authdir_badexit_policy = NULL;

/** Parsed addr_policy_t describing which addresses we believe we can start
 * circuits at. */
static addr_policy_t *reachable_or_addr_policy = NULL;
/** Parsed addr_policy_t describing which addresses we believe we can connect
 * to directories at. */
static addr_policy_t *reachable_dir_addr_policy = NULL;

/**
 * Given a linked list of config lines containing "allow" and "deny"
 * tokens, parse them and append the result to <b>dest</b>. Return -1
 * if any tokens are malformed, else return 0.
 */
static int
parse_addr_policy(config_line_t *cfg, addr_policy_t **dest,
                  int assume_action)
{
  addr_policy_t **nextp;
  smartlist_t *entries;
  int r = 0;

  if (!cfg)
    return 0;

  nextp = dest;

  while (*nextp)
    nextp = &((*nextp)->next);

  entries = smartlist_create();
  for (; cfg; cfg = cfg->next) {
    smartlist_split_string(entries, cfg->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    if (expand_exit_policy_aliases(entries,assume_action)<0) {
      r = -1;
      continue;
    }
    SMARTLIST_FOREACH(entries, const char *, ent,
    {
      log_debug(LD_CONFIG,"Adding new entry '%s'",ent);
      *nextp = router_parse_addr_policy_from_string(ent, assume_action);
      if (*nextp) {
        if (addr_mask_get_bits((*nextp)->msk)<0) {
          log_warn(LD_CONFIG, "Address policy element '%s' can't be expressed "
                   "as a bit prefix.", ent);
        }
        /* Advance nextp to the end of the policy. */
        while (*nextp)
          nextp = &((*nextp)->next);
      } else {
        log_warn(LD_CONFIG,"Malformed policy '%s'.", ent);
        r = -1;
      }
    });
    SMARTLIST_FOREACH(entries, char *, ent, tor_free(ent));
    smartlist_clear(entries);
  }
  smartlist_free(entries);
  return r;
}

/** Helper: parse the Reachable(Dir|OR)?Addresses fields into
 * reachable_(or|dir)_addr_policy. */
static void
parse_reachable_addresses(void)
{
  or_options_t *options = get_options();

  if (options->ReachableDirAddresses &&
      options->ReachableORAddresses &&
      options->ReachableAddresses) {
    log_warn(LD_CONFIG,
             "Both ReachableDirAddresses and ReachableORAddresses are set. "
             "ReachableAddresses setting will be ignored.");
  }
  addr_policy_free(reachable_or_addr_policy);
  reachable_or_addr_policy = NULL;
  if (!options->ReachableORAddresses && options->ReachableAddresses)
    log_info(LD_CONFIG,
             "Using ReachableAddresses as ReachableORAddresses.");
  if (parse_addr_policy(options->ReachableORAddresses ?
                          options->ReachableORAddresses :
                          options->ReachableAddresses,
                        &reachable_or_addr_policy, ADDR_POLICY_ACCEPT)) {
    log_warn(LD_CONFIG,
             "Error parsing Reachable%sAddresses entry; ignoring.",
             options->ReachableORAddresses ? "OR" : "");
  }

  addr_policy_free(reachable_dir_addr_policy);
  reachable_dir_addr_policy = NULL;
  if (!options->ReachableDirAddresses && options->ReachableAddresses)
    log_info(LD_CONFIG,
             "Using ReachableAddresses as ReachableDirAddresses");
  if (parse_addr_policy(options->ReachableDirAddresses ?
                          options->ReachableDirAddresses :
                          options->ReachableAddresses,
                        &reachable_dir_addr_policy, ADDR_POLICY_ACCEPT)) {
    if (options->ReachableDirAddresses)
      log_warn(LD_CONFIG,
               "Error parsing ReachableDirAddresses entry; ignoring.");
  }
}

/** Return true iff the firewall options might block any address:port
 * combination.
 */
int
firewall_is_fascist_or(void)
{
  return reachable_or_addr_policy != NULL;
}

/** Return true iff <b>policy</b> (possibly NULL) will allow a
 * connection to <b>addr</b>:<b>port</b>.
 */
static int
addr_policy_permits_address(uint32_t addr, uint16_t port,
                            addr_policy_t *policy)
{
  addr_policy_result_t p;
  p = compare_addr_to_addr_policy(addr, port, policy);
  switch (p) {
    case ADDR_POLICY_PROBABLY_ACCEPTED:
    case ADDR_POLICY_ACCEPTED:
      return 1;
    case ADDR_POLICY_PROBABLY_REJECTED:
    case ADDR_POLICY_REJECTED:
      return 0;
    default:
      log_warn(LD_BUG, "Unexpected result: %d", (int)p);
      return 0;
  }
}

int
fascist_firewall_allows_address_or(uint32_t addr, uint16_t port)
{
  return addr_policy_permits_address(addr, port,
                                     reachable_or_addr_policy);
}

int
fascist_firewall_allows_address_dir(uint32_t addr, uint16_t port)
{
  return addr_policy_permits_address(addr, port,
                                     reachable_dir_addr_policy);
}

/** Return 1 if <b>addr</b> is permitted to connect to our dir port,
 * based on <b>dir_policy</b>. Else return 0.
 */
int
dir_policy_permits_address(uint32_t addr)
{
  return addr_policy_permits_address(addr, 1, dir_policy);
}

/** Return 1 if <b>addr</b> is permitted to connect to our socks port,
 * based on <b>socks_policy</b>. Else return 0.
 */
int
socks_policy_permits_address(uint32_t addr)
{
  return addr_policy_permits_address(addr, 1, socks_policy);
}

/** Return 1 if <b>addr</b>:<b>port</b> is permitted to publish to our
 * directory, based on <b>authdir_reject_policy</b>. Else return 0.
 */
int
authdir_policy_permits_address(uint32_t addr, uint16_t port)
{
  return addr_policy_permits_address(addr, port, authdir_reject_policy);
}

/** Return 1 if <b>addr</b>:<b>port</b> is considered valid in our
 * directory, based on <b>authdir_invalid_policy</b>. Else return 0.
 */
int
authdir_policy_valid_address(uint32_t addr, uint16_t port)
{
  return addr_policy_permits_address(addr, port, authdir_invalid_policy);
}

/** Return 1 if <b>addr</b>:<b>port</b> should be marked as a bad exit,
 * based on <b>authdir_badexit_policy</b>. Else return 0.
 */
int
authdir_policy_badexit_address(uint32_t addr, uint16_t port)
{
  return ! addr_policy_permits_address(addr, port, authdir_badexit_policy);
}

#define REJECT(arg) \
  do { *msg = tor_strdup(arg); goto err; } while (0)
int
validate_addr_policies(or_options_t *options, char **msg)
{
  addr_policy_t *addr_policy=NULL;
  *msg = NULL;

  if (policies_parse_exit_policy(options->ExitPolicy, &addr_policy,
                                 options->ExitPolicyRejectPrivate))
    REJECT("Error in ExitPolicy entry.");

  /* The rest of these calls *append* to addr_policy. So don't actually
   * use the results for anything other than checking if they parse! */
  if (parse_addr_policy(options->DirPolicy, &addr_policy, -1))
    REJECT("Error in DirPolicy entry.");
  if (parse_addr_policy(options->SocksPolicy, &addr_policy, -1))
    REJECT("Error in SocksPolicy entry.");
  if (parse_addr_policy(options->ReachableAddresses, &addr_policy,
                        ADDR_POLICY_ACCEPT))
    REJECT("Error in ReachableAddresses entry.");
  if (parse_addr_policy(options->ReachableORAddresses, &addr_policy,
                        ADDR_POLICY_ACCEPT))
    REJECT("Error in ReachableORAddresses entry.");
  if (parse_addr_policy(options->ReachableDirAddresses, &addr_policy,
                        ADDR_POLICY_ACCEPT))
    REJECT("Error in ReachableDirAddresses entry.");
  if (parse_addr_policy(options->AuthDirReject, &addr_policy,
                        ADDR_POLICY_REJECT))
    REJECT("Error in AuthDirReject entry.");
  if (parse_addr_policy(options->AuthDirInvalid, &addr_policy,
                        ADDR_POLICY_REJECT))
    REJECT("Error in AuthDirInvalid entry.");

err:
  addr_policy_free(addr_policy);
  return *msg ? -1 : 0;
#undef REJECT
}

/* Parse <b>string</b> in the same way that the exit policy
 * is parsed, and put the processed version in *<b>policy</b>.
 * Ignore port specifiers.
 */
static void
load_policy_from_option(config_line_t *config, addr_policy_t **policy,
                        int assume_action)
{
  addr_policy_t *n;
  addr_policy_free(*policy);
  *policy = NULL;
  parse_addr_policy(config, policy, assume_action);
  /* ports aren't used. */
  for (n=*policy; n; n = n->next) {
    n->prt_min = 1;
    n->prt_max = 65535;
  }
}

void
policies_parse_from_options(or_options_t *options)
{
  load_policy_from_option(options->SocksPolicy, &socks_policy, -1);
  load_policy_from_option(options->DirPolicy, &dir_policy, -1);
  load_policy_from_option(options->AuthDirReject,
                          &authdir_reject_policy, ADDR_POLICY_REJECT);
  load_policy_from_option(options->AuthDirInvalid,
                          &authdir_invalid_policy, ADDR_POLICY_REJECT);
  load_policy_from_option(options->AuthDirBadExit,
                          &authdir_badexit_policy, ADDR_POLICY_REJECT);
  parse_reachable_addresses();
}

/** Compare two provided address policy items, and return -1, 0, or 1
 * if the first is less than, equal to, or greater than the second. */
static int
cmp_single_addr_policy(addr_policy_t *a, addr_policy_t *b)
{
  int r;
  if ((r=((int)a->policy_type - (int)b->policy_type)))
    return r;
  if ((r=((int)a->addr - (int)b->addr)))
    return r;
  if ((r=((int)a->msk - (int)b->msk)))
    return r;
  if ((r=((int)a->prt_min - (int)b->prt_min)))
    return r;
  if ((r=((int)a->prt_max - (int)b->prt_max)))
    return r;
  return 0;
}

/** Like cmp_single_addr_policy() above, but looks at the
 * whole set of policies in each case. */
int
cmp_addr_policies(addr_policy_t *a, addr_policy_t *b)
{
  int r;
  while (a && b) {
    if ((r=cmp_single_addr_policy(a,b)))
      return r;
    a = a->next;
    b = b->next;
  }
  if (!a && !b)
    return 0;
  if (a)
    return -1;
  else
    return 1;
}

/** Decide whether a given addr:port is definitely accepted,
 * definitely rejected, probably accepted, or probably rejected by a
 * given policy.  If <b>addr</b> is 0, we don't know the IP of the
 * target address. If <b>port</b> is 0, we don't know the port of the
 * target address.
 *
 * For now, the algorithm is pretty simple: we look for definite and
 * uncertain matches.  The first definite match is what we guess; if
 * it was preceded by no uncertain matches of the opposite policy,
 * then the guess is definite; otherwise it is probable.  (If we
 * have a known addr and port, all matches are definite; if we have an
 * unknown addr/port, any address/port ranges other than "all" are
 * uncertain.)
 *
 * We could do better by assuming that some ranges never match typical
 * addresses (127.0.0.1, and so on).  But we'll try this for now.
 */
addr_policy_result_t
compare_addr_to_addr_policy(uint32_t addr, uint16_t port,
                            addr_policy_t *policy)
{
  int maybe_reject = 0;
  int maybe_accept = 0;
  int match = 0;
  int maybe = 0;
  addr_policy_t *tmpe;

  for (tmpe=policy; tmpe; tmpe=tmpe->next) {
    maybe = 0;
    if (!addr) {
      /* Address is unknown. */
      if ((port >= tmpe->prt_min && port <= tmpe->prt_max) ||
           (!port && tmpe->prt_min<=1 && tmpe->prt_max>=65535)) {
        /* The port definitely matches. */
        if (tmpe->msk == 0) {
          match = 1;
        } else {
          maybe = 1;
        }
      } else if (!port) {
        /* The port maybe matches. */
        maybe = 1;
      }
    } else {
      /* Address is known */
      if ((addr & tmpe->msk) == (tmpe->addr & tmpe->msk)) {
        if (port >= tmpe->prt_min && port <= tmpe->prt_max) {
          /* Exact match for the policy */
          match = 1;
        } else if (!port) {
          maybe = 1;
        }
      }
    }
    if (maybe) {
      if (tmpe->policy_type == ADDR_POLICY_REJECT)
        maybe_reject = 1;
      else
        maybe_accept = 1;
    }
    if (match) {
      if (tmpe->policy_type == ADDR_POLICY_ACCEPT) {
        /* If we already hit a clause that might trigger a 'reject', than we
         * can't be sure of this certain 'accept'.*/
        return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED :
                              ADDR_POLICY_ACCEPTED;
      } else {
        return maybe_accept ? ADDR_POLICY_PROBABLY_REJECTED :
                              ADDR_POLICY_REJECTED;
      }
    }
  }
  /* accept all by default. */
  return maybe_reject ? ADDR_POLICY_PROBABLY_ACCEPTED : ADDR_POLICY_ACCEPTED;
}

/** Return true iff the address policy <b>a</b> covers every case that
 * would be covered by <b>b</b>, so that a,b is redundant. */
static int
addr_policy_covers(addr_policy_t *a, addr_policy_t *b)
{
  /* We can ignore accept/reject, since "accept *:80, reject *:80" reduces
   * to "accept *:80". */
  if (a->msk & ~b->msk) {
    /* There's a wildcard bit in b->msk that's not a wildcard in a. */
    return 0;
  }
  if ((a->addr & a->msk) != (b->addr & a->msk)) {
    /* There's a fixed bit in a that's set differently in b. */
    return 0;
  }
  return (a->prt_min <= b->prt_min && a->prt_max >= b->prt_max);
}

/** Return true iff the address policies <b>a</b> and <b>b</b> intersect,
 * that is, there exists an address/port that is covered by <b>a</b> that
 * is also covered by <b>b</b>.
 */
static int
addr_policy_intersects(addr_policy_t *a, addr_policy_t *b)
{
  /* All the bits we care about are those that are set in both
   * netmasks.  If they are equal in a and b's networkaddresses
   * then the networks intersect.  If there is a difference,
   * then they do not. */
  if (((a->addr ^ b->addr) & a->msk & b->msk) != 0)
    return 0;
  if (a->prt_max < b->prt_min || b->prt_max < a->prt_min)
    return 0;
  return 1;
}

/** Add the exit policy described by <b>more</b> to <b>policy</b>.
 */
static void
append_exit_policy_string(addr_policy_t **policy, const char *more)
{
  config_line_t tmp;

  tmp.key = NULL;
  tmp.value = (char*) more;
  tmp.next = NULL;
  parse_addr_policy(&tmp, policy, -1);
}

static int
expand_exit_policy_aliases(smartlist_t *entries, int assume_action)
{
  static const char *prefixes[] = {
    "0.0.0.0/8", "169.254.0.0/16",
    "127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",NULL };
  int i;
  char *pre=NULL, *post=NULL;
  int expanded_any = 0;
  pre = smartlist_join_strings(entries,",",0,NULL);
  for (i = 0; i < smartlist_len(entries); ++i) {
    char *v = smartlist_get(entries, i);
    const char *cp, *ports;
    const char *action;
    int prefix_idx;
    if (!strcasecmpstart(v, "accept")) {
      action = "accept ";
      cp = v+strlen("accept");
    } else if (!strcasecmpstart(v, "reject")) {
      action = "reject ";
      cp = v+strlen("reject");
    } else if (assume_action >= 0) {
      action = "";
      cp = v;
    } else {
      log_warn(LD_CONFIG,"Policy '%s' didn't start with accept or reject.", v);
      tor_free(pre);
      return -1;
    }
    cp = eat_whitespace(cp);
    if (strcmpstart(cp, "private"))
      continue; /* No need to expand. */
    cp += strlen("private");
    cp = eat_whitespace(cp);
    if (*cp && *cp != ':')
      continue; /* It wasn't "private" after all. */
    ports = cp;
    /* Okay. We're going to replace entries[i] with a bunch of new entries,
     * in order. */
    smartlist_del_keeporder(entries, i);
    for (prefix_idx = 0; prefixes[prefix_idx]; ++prefix_idx) {
      size_t replacement_len = 16+strlen(prefixes[prefix_idx])+strlen(ports);
      char *replacement = tor_malloc(replacement_len);
      tor_snprintf(replacement, replacement_len, "%s%s%s",
                   action, prefixes[prefix_idx], ports);
      smartlist_insert(entries, i++, replacement);
    }
    tor_free(v);
    expanded_any = 1;
    --i;
  }
  post = smartlist_join_strings(entries,",",0,NULL);
  if (expanded_any)
    log_info(LD_CONFIG, "Expanded '%s' to '%s'", pre, post);
  tor_free(pre);
  tor_free(post);
  return expanded_any;
}

/** Detect and excise "dead code" from the policy *<b>dest</b>. */
static void
exit_policy_remove_redundancies(addr_policy_t **dest)
{
  addr_policy_t *ap, *tmp, *victim, *previous;

  /* Step one: find a *:* entry and cut off everything after it. */
  for (ap=*dest; ap; ap=ap->next) {
    if (ap->msk == 0 && ap->prt_min <= 1 && ap->prt_max >= 65535) {
      /* This is a catch-all line -- later lines are unreachable. */
      if (ap->next) {
        addr_policy_free(ap->next);
        ap->next = NULL;
      }
    }
  }

  /* Step two: for every entry, see if there's a redundant entry
   * later on, and remove it. */
  for (ap=*dest; ap; ap=ap->next) {
    tmp=ap;
    while (tmp) {
      if (tmp->next && addr_policy_covers(ap, tmp->next)) {
        log(LOG_DEBUG, LD_CONFIG, "Removing exit policy %s.  It is made "
            "redundant by %s.", tmp->next->string, ap->string);
        victim = tmp->next;
        tmp->next = victim->next;
        victim->next = NULL;
        addr_policy_free(victim);
      } else {
        tmp=tmp->next;
      }
    }
  }

  /* Step three: for every entry A, see if there's an entry B making this one
   * redundant later on.  This is the case if A and B are of the same type
   * (accept/reject), A is a subset of B, and there is no other entry of
   * different type in between those two that intersects with A.
   *
   * Anybody want to doublecheck the logic here? XXX
   */
  ap = *dest;
  previous = NULL;
  while (ap) {
    for (tmp=ap->next; tmp; tmp=tmp->next) {
      if (ap->policy_type != tmp->policy_type &&
          addr_policy_intersects(ap, tmp)) {
        tmp = NULL; /* so that we advance previous and ap */
        break;
      }
      if (ap->policy_type == tmp->policy_type &&
          addr_policy_covers(tmp, ap)) {
        log(LOG_DEBUG, LD_CONFIG, "Removing exit policy %s.  It is already "
            "covered by %s.", ap->string, tmp->string);
        victim = ap;
        ap = ap->next;

        if (previous) {
          assert(previous->next == victim);
          previous->next = victim->next;
        } else {
          assert(*dest == victim);
          *dest = victim->next;
        }

        victim->next = NULL;
        addr_policy_free(victim);
        break;
      }
    }
    if (!tmp) {
      previous = ap;
      ap = ap->next;
    }
  }
}

#define DEFAULT_EXIT_POLICY                                         \
  "reject *:25,reject *:119,reject *:135-139,reject *:445,"         \
  "reject *:465,reject *:563,reject *:587,"                         \
  "reject *:1214,reject *:4661-4666,"                               \
  "reject *:6346-6429,reject *:6699,reject *:6881-6999,accept *:*"

/** Parse the exit policy <b>cfg</b> into the linked list *<b>dest</b>. If
 * cfg doesn't end in an absolute accept or reject, add the default exit
 * policy afterwards. If <b>rejectprivate</b> is true, prepend
 * "reject private:*" to the policy. Return -1 if we can't parse cfg,
 * else return 0.
 *
 */
int
policies_parse_exit_policy(config_line_t *cfg, addr_policy_t **dest,
                           int rejectprivate)
{
  if (rejectprivate)
    append_exit_policy_string(dest, "reject private:*");
  if (parse_addr_policy(cfg, dest, -1))
    return -1;
  append_exit_policy_string(dest, DEFAULT_EXIT_POLICY);

  exit_policy_remove_redundancies(dest);
  return 0;
}

/** Return true iff <b>ri</b> is "useful as an exit node", meaning
 * it allows exit to at least one /8 address space for at least
 * two of ports 80, 443, and 6667. */
int
exit_policy_is_general_exit(addr_policy_t *policy)
{
  static const int ports[] = { 80, 443, 6667 };
  int n_allowed = 0;
  int i;
  for (i = 0; i < 3; ++i) {
    struct addr_policy_t *p = policy;
    for ( ; p; p = p->next) {
      if (p->prt_min > ports[i] || p->prt_max < ports[i])
        continue; /* Doesn't cover our port. */
      if ((p->msk & 0x00fffffful) != 0)
        continue; /* Narrower than a /8. */
      if ((p->addr & 0xff000000ul) == 0x7f000000ul)
        continue; /* 127.x */
      /* We have a match that is at least a /8. */
      if (p->policy_type == ADDR_POLICY_ACCEPT) {
        ++n_allowed;
        break; /* stop considering this port */
      }
    }
  }
  return n_allowed >= 2;
}

/** Return false if <b>policy</b> might permit access to some addr:port;
 * otherwise if we are certain it rejects everything, return true. */
int
policy_is_reject_star(addr_policy_t *p)
{
  for ( ; p; p = p->next) {
    if (p->policy_type == ADDR_POLICY_ACCEPT)
      return 0;
    else if (p->policy_type == ADDR_POLICY_REJECT &&
             p->prt_min <= 1 && p->prt_max == 65535 &&
             p->msk == 0)
      return 1;
  }
  return 1;
}

/** Write a single address policy to the buf_len byte buffer at buf.  Return
 * the number of characters written, or -1 on failure. */
int
policy_write_item(char *buf, size_t buflen, addr_policy_t *policy)
{
  struct in_addr in;
  size_t written = 0;
  char addrbuf[INET_NTOA_BUF_LEN];
  int result;

  in.s_addr = htonl(policy->addr);
  tor_inet_ntoa(&in, addrbuf, sizeof(addrbuf));
  /* write accept/reject 1.2.3.4 */
  result = tor_snprintf(buf, buflen, "%s %s",
            policy->policy_type == ADDR_POLICY_ACCEPT ? "accept" : "reject",
            policy->msk == 0 ? "*" : addrbuf);
  if (result < 0)
    return -1;
  written += strlen(buf);
  /* If the mask is 0xffffffff, we don't need to give it.  If the mask is 0,
   * we already wrote "*". */
  if (policy->msk != 0xFFFFFFFFu && policy->msk != 0) {
    int n_bits = addr_mask_get_bits(policy->msk);
    if (n_bits >= 0) {
      if (tor_snprintf(buf+written, buflen-written, "/%d", n_bits)<0)
        return -1;
    } else {
      /* Write "/255.255.0.0" */
      in.s_addr = htonl(policy->msk);
      tor_inet_ntoa(&in, addrbuf, sizeof(addrbuf));
      if (tor_snprintf(buf+written, buflen-written, "/%s", addrbuf)<0)
        return -1;
    }
    written += strlen(buf+written);
  }
  if (policy->prt_min <= 1 && policy->prt_max == 65535) {
    /* There is no port set; write ":*" */
    if (written+4 > buflen)
      return -1;
    strlcat(buf+written, ":*", buflen-written);
    written += 3;
  } else if (policy->prt_min == policy->prt_max) {
    /* There is only one port; write ":80". */
    result = tor_snprintf(buf+written, buflen-written, ":%d", policy->prt_min);
    if (result<0)
      return -1;
    written += result;
  } else {
    /* There is a range of ports; write ":79-80". */
    result = tor_snprintf(buf+written, buflen-written, ":%d-%d",
                          policy->prt_min, policy->prt_max);
    if (result<0)
      return -1;
    written += result;
  }
  if (written < buflen)
    buf[written] = '\0';
  else
    return -1;

  return (int)written;
}

int
getinfo_helper_policies(control_connection_t *conn,
                        const char *question, char **answer)
{
  (void) conn;
  if (!strcmp(question, "exit-policy/default")) {
    *answer = tor_strdup(DEFAULT_EXIT_POLICY);
  }
  return 0;
}

/** Release all storage held by <b>p</b> */
void
addr_policy_free(addr_policy_t *p)
{
  addr_policy_t *e;

  while (p) {
    e = p;
    p = p->next;
    tor_free(e->string);
    tor_free(e);
  }
}

void
policies_free_all(void)
{
  addr_policy_free(reachable_or_addr_policy);
  reachable_or_addr_policy = NULL;
  addr_policy_free(reachable_dir_addr_policy);
  reachable_dir_addr_policy = NULL;
  addr_policy_free(socks_policy);
  socks_policy = NULL;
  addr_policy_free(dir_policy);
  dir_policy = NULL;
  addr_policy_free(authdir_reject_policy);
  authdir_reject_policy = NULL;
  addr_policy_free(authdir_invalid_policy);
  authdir_invalid_policy = NULL;
}

