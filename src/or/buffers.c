/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/* buffers.c */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

/* Create a new buf of size MAX_BUF_SIZE. Write a pointer to it
 * into *buf, write MAX_BUF_SIZE into *buflen, and initialize
 * *buf_datalen to 0. Return 0.
 */
int buf_new(char **buf, int *buflen, int *buf_datalen) {

  assert(buf && buflen && buf_datalen);

  *buf = (char *)tor_malloc(MAX_BUF_SIZE);
//  memset(*buf,0,MAX_BUF_SIZE);
  *buflen = MAX_BUF_SIZE;
  *buf_datalen = 0;

  return 0;
}

void buf_free(char *buf) {
  free(buf);
}

/* read from socket s, writing onto buf+buf_datalen.
 * read at most 'at_most' bytes, and in any case don't read more than will fit based on buflen.
 * If read() returns 0, set *reached_eof to 1 and return 0. If you want to tear
 * down the connection return -1, else return the number of bytes read.
 */
int read_to_buf(int s, int at_most, char **buf, int *buflen, int *buf_datalen, int *reached_eof) {

  int read_result;
#ifdef MS_WINDOWS
  int e;
#endif

  assert(buf && *buf && buflen && buf_datalen && reached_eof && (s>=0));

  /* this is the point where you would grow the buffer, if you want to */

  if(at_most > *buflen - *buf_datalen)
    at_most = *buflen - *buf_datalen; /* take the min of the two */

  if(at_most == 0)
    return 0; /* we shouldn't read anything */

  if(!options.LinkPadding && at_most > 10*sizeof(cell_t)) {
    /* if no linkpadding: do a rudimentary round-robin so one
     * connection can't hog a thickpipe
     */
    at_most = 10*(CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE);
    /* XXX this still isn't perfect. now we read 10 relay data payloads per read --
     * but if we're reading from a connection that speaks cells, we always
     * read a partial cell from the network and can't process it yet. Good
     * enough for now though. (And maybe best, to stress our code more.)
     */
  }

//  log_fn(LOG_DEBUG,"reading at most %d bytes.",at_most);
  read_result = read(s, *buf+*buf_datalen, at_most);
  if (read_result < 0) {
    if(!ERRNO_EAGAIN(errno)) { /* it's a real error */
      return -1;
    }
#ifdef MS_WINDOWS
    e = correct_socket_errno(s);
    if(!ERRNO_EAGAIN(errno)) { /* no, it *is* a real error! */
      return -1;
    }
#endif
    return 0;
  } else if (read_result == 0) {
    log_fn(LOG_DEBUG,"Encountered eof");
    *reached_eof = 1;
    return 0;
  } else { /* we read some bytes */
    *buf_datalen += read_result;
//    log_fn(LOG_DEBUG,"Read %d bytes. %d on inbuf.",read_result, *buf_datalen);
    return read_result;
  }
}

int read_to_buf_tls(tor_tls *tls, int at_most, char **buf, int *buflen, int *buf_datalen) {
  int r;
  assert(tls && *buf && buflen && buf_datalen);
  
  if (at_most > *buflen - *buf_datalen)
    at_most = *buflen - *buf_datalen;

  if (at_most == 0)
    return 0;
  
  r = tor_tls_read(tls, *buf+*buf_datalen, at_most);
  if (r<0) 
    return r;
  *buf_datalen += r;
  return r;
} 

int flush_buf(int s, char **buf, int *buflen, int *buf_flushlen, int *buf_datalen) {

  /* push from buf onto s
   * then memmove to front of buf
   * return -1 or how many bytes remain to be flushed */

  int write_result;
#ifdef MS_WINDOWS
  int e;
#endif

  assert(buf && *buf && buflen && buf_flushlen && buf_datalen && (s>=0) && (*buf_flushlen <= *buf_datalen));

  if(*buf_flushlen == 0) /* nothing to flush */
    return 0;

  /* this is the point where you would grow the buffer, if you want to */

  write_result = write(s, *buf, *buf_flushlen);
  if (write_result < 0) {
    if(!ERRNO_EAGAIN(errno)) { /* it's a real error */
      return -1;
    }
#ifdef MS_WINDOWS
    e = correct_socket_errno(s);
    if(!ERRNO_EAGAIN(errno)) { /* no, it *is* a real error! */
      return -1;
    }
#endif
    log_fn(LOG_DEBUG,"write() would block, returning.");
    return 0;
  } else {
    *buf_datalen -= write_result;
    *buf_flushlen -= write_result;
    memmove(*buf, *buf+write_result, *buf_datalen);
//    log_fn(LOG_DEBUG,"flushed %d bytes, %d ready to flush, %d remain.",
//       write_result,*buf_flushlen,*buf_datalen);
    return *buf_flushlen;
  }
}

int flush_buf_tls(tor_tls *tls, char **buf, int *buflen, int *buf_flushlen, int *buf_datalen)
{
  int r;
  assert(tls && *buf && buflen && buf_datalen);
  if (*buf_flushlen == 0)
    return 0;
  r = tor_tls_write(tls, *buf, *buf_flushlen);
  if (r < 0) {
    return r;
  }
  *buf_datalen -= r;
  *buf_flushlen -= r;
  memmove(*buf, *buf+r, *buf_datalen);
  return r;
}

int write_to_buf(char *string, int string_len,
                 char **buf, int *buflen, int *buf_datalen) {

  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */

  assert(string && buf && *buf && buflen && buf_datalen);

  /* this is the point where you would grow the buffer, if you want to */

  if (string_len + *buf_datalen > *buflen) { /* we're out of luck */
    log_fn(LOG_DEBUG, "buflen too small. Time to implement growing dynamic bufs.");
    return -1;
  }

  memcpy(*buf+*buf_datalen, string, string_len);
  *buf_datalen += string_len;
//  log_fn(LOG_DEBUG,"added %d bytes to buf (now %d total).",string_len, *buf_datalen);
  return *buf_datalen;
}

int fetch_from_buf(char *string, int string_len,
                   char **buf, int *buflen, int *buf_datalen) {

  /* There must be string_len bytes in buf; write them onto string,
   * then memmove buf back (that is, remove them from buf).
   *
   * Return the number of bytes still on the buffer. */

  assert(string && buf && *buf && buflen && buf_datalen);
  assert(string_len <= *buf_datalen); /* make sure we don't ask for too much */

  memcpy(string,*buf,string_len);
  *buf_datalen -= string_len;
  memmove(*buf, *buf+string_len, *buf_datalen);
  return *buf_datalen;
}

int find_on_inbuf(char *string, int string_len,
                  char *buf, int buf_datalen) {
  /* find first instance of needle 'string' on haystack 'buf'. return how
   * many bytes from the beginning of buf to the end of string.
   * If it's not there, return -1.
   */

  char *location;
  char *last_possible = buf + buf_datalen - string_len;

  assert(string && string_len > 0 && buf);

  if(buf_datalen < string_len)
    return -1;

  for(location = buf; location <= last_possible; location++)
    if((*location == *string) && !memcmp(location+1, string+1, string_len-1))
      return location-buf+string_len;

  return -1;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
