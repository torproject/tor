/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/* buffers.c */

#include "or.h"

int buf_new(char **buf, size_t *buflen, size_t *buf_datalen) {

  assert(buf && buflen && buf_datalen);

  *buf = (char *)malloc(MAX_BUF_SIZE);
  if(!*buf)
    return -1;
  memset(*buf,0,MAX_BUF_SIZE);
  *buflen = MAX_BUF_SIZE;
  *buf_datalen = 0;

  return 0;
}

void buf_free(char *buf) {
  free(buf);
}

int read_to_buf(int s, int at_most, char **buf, size_t *buflen, size_t *buf_datalen, int *reached_eof) {

  /* read from socket s, writing onto buf+buf_datalen. If at_most is >= 0 then
   * read at most 'at_most' bytes, and in any case don't read more than will fit based on buflen.
   * If read() returns 0, set *reached_eof to 1 and return 0. If you want to tear
   * down the connection return -1, else return the number of bytes read.
   */

  int read_result;

  assert(buf && *buf && buflen && buf_datalen && reached_eof && (s>=0));

  /* this is the point where you would grow the buffer, if you want to */

  if(at_most < 0 || *buflen - *buf_datalen < at_most)
    at_most = *buflen - *buf_datalen; /* take the min of the two */
    /* (note that this only modifies at_most inside this function) */

  if(at_most == 0)
    return 0; /* we shouldn't read anything */

//  log(LOG_DEBUG,"read_to_buf(): reading at most %d bytes.",at_most);
  read_result = read(s, *buf+*buf_datalen, at_most);
  if (read_result < 0) {
    if(errno!=EAGAIN) { /* it's a real error */
      return -1;
    }
    return 0;
  } else if (read_result == 0) {
    log(LOG_DEBUG,"read_to_buf(): Encountered eof");
    *reached_eof = 1;
    return 0;
  } else { /* we read some bytes */
    *buf_datalen += read_result;
//    log(LOG_DEBUG,"read_to_buf(): Read %d bytes. %d on inbuf.",read_result, *buf_datalen);
    return read_result;
  }

}

int flush_buf(int s, char **buf, size_t *buflen, size_t *buf_flushlen, size_t *buf_datalen) {

  /* push from buf onto s
   * then memmove to front of buf
   * return -1 or how many bytes remain to be flushed */

  int write_result;

  assert(buf && *buf && buflen && buf_flushlen && buf_datalen && (s>=0) && (*buf_flushlen <= *buf_datalen));

  if(*buf_flushlen == 0) /* nothing to flush */
    return 0;

  /* this is the point where you would grow the buffer, if you want to */

  write_result = write(s, *buf, *buf_flushlen);
  if (write_result < 0) {
    if(errno!=EAGAIN) { /* it's a real error */
      return -1;
    }
    log(LOG_DEBUG,"flush_buf(): write() would block, returning.");
    return 0;
  } else {
    *buf_datalen -= write_result;
    *buf_flushlen -= write_result;
    memmove(*buf, *buf+write_result, *buf_datalen);
//    log(LOG_DEBUG,"flush_buf(): flushed %d bytes, %d ready to flush, %d remain.",
//       write_result,*buf_flushlen,*buf_datalen);
    return *buf_flushlen;
  }
}

int write_to_buf(char *string, size_t string_len,
                 char **buf, size_t *buflen, size_t *buf_datalen) {

  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */

  assert(string && buf && *buf && buflen && buf_datalen);

  /* this is the point where you would grow the buffer, if you want to */

  if (string_len + *buf_datalen > *buflen) { /* we're out of luck */
    log(LOG_DEBUG, "write_to_buf(): buflen too small. Time to implement growing dynamic bufs.");
    return -1;
  }

  memcpy(*buf+*buf_datalen, string, string_len);
  *buf_datalen += string_len;
//  log(LOG_DEBUG,"write_to_buf(): added %d bytes to buf (now %d total).",string_len, *buf_datalen);
  return *buf_datalen;

}

int fetch_from_buf(char *string, size_t string_len,
                 char **buf, size_t *buflen, size_t *buf_datalen) {

  /* if there is string_len bytes in buf, write them onto string,
   * then memmove buf back (that is, remove them from buf) */

  assert(string && buf && *buf && buflen && buf_datalen);

  /* this is the point where you would grow the buffer, if you want to */

  if(string_len > *buf_datalen) /* we want too much. sorry. */
    return -1;
 
  memcpy(string,*buf,string_len);
  *buf_datalen -= string_len;
  memmove(*buf, *buf+string_len, *buf_datalen);
  return *buf_datalen;
}

