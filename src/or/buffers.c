/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/* buffers.c */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

struct buf_t {
  char *buf;
  size_t len;
  size_t datalen;
};

#define BUF_OK(b) ((b) && (b)->buf && (b)->datalen <= (b)->len)

/* Find the first instance of str on buf.  If none exists, return -1.
 * Otherwise, return index of the first character in buf _after_ the
 * first instance of str.
 */
static int find_str_in_str(const char *str, int str_len, 
                           const char *buf, int buf_len)
{
  const char *location;
  const char *last_possible = buf + buf_len - str_len;

  assert(str && str_len > 0 && buf);

  if(buf_len < str_len)
    return -1;

  for(location = buf; location <= last_possible; location++)
    if((*location == *str) && !memcmp(location+1, str+1, str_len-1))
      return location-buf+str_len;

  return -1;
}

int find_on_inbuf(char *string, int string_len, buf_t *buf) {
  return find_str_in_str(string, string_len, buf->buf, buf->datalen);
}

/* Create and return a new buf of size 'size'
 */
buf_t *buf_new_with_capacity(size_t size) {
  buf_t *buf;
  buf = (buf_t*)tor_malloc(sizeof(buf_t));
  buf->buf = (char *)tor_malloc(size);
  buf->len = size;
  buf->datalen = 0;
//  memset(buf->buf,0,size);

  assert(BUF_OK(buf));
  return buf;
}

buf_t *buf_new()
{
  return buf_new_with_capacity(MAX_BUF_SIZE);
}


size_t buf_datalen(const buf_t *buf)
{
  return buf->datalen;
}

size_t buf_capacity(const buf_t *buf)
{
  return buf->len;
}

const char *_buf_peek_raw_buffer(const buf_t *buf)
{
  return buf->buf;
}

void buf_free(buf_t *buf) {
  assert(buf && buf->buf);
  free(buf->buf);
  free(buf);
}



/* read from socket s, writing onto end of buf.
 * read at most 'at_most' bytes, and in any case don't read more than will fit based on buflen.
 * If read() returns 0, set *reached_eof to 1 and return 0. If you want to tear
 * down the connection return -1, else return the number of bytes read.
 */
int read_to_buf(int s, int at_most, buf_t *buf, int *reached_eof) {

  int read_result;
#ifdef MS_WINDOWS
  int e;
#endif

  assert(BUF_OK(buf) && reached_eof && (s>=0));

  /* this is the point where you would grow the buffer, if you want to */

  if(at_most > buf->len - buf->datalen)
    at_most = buf->len - buf->datalen; /* take the min of the two */

  if(at_most == 0)
    return 0; /* we shouldn't read anything */

//  log_fn(LOG_DEBUG,"reading at most %d bytes.",at_most);
  read_result = read(s, buf->buf+buf->datalen, at_most);
  if (read_result < 0) {
    if(!ERRNO_EAGAIN(errno)) { /* it's a real error */
      return -1;
    }
#ifdef MS_WINDOWS
    e = correct_socket_errno(s);
    if(!ERRNO_EAGAIN(e)) { /* no, it *is* a real error! */
      return -1;
    }
#endif
    return 0;
  } else if (read_result == 0) {
    log_fn(LOG_DEBUG,"Encountered eof");
    *reached_eof = 1;
    return 0;
  } else { /* we read some bytes */
    buf->datalen += read_result;
    log_fn(LOG_DEBUG,"Read %d bytes. %d on inbuf.",read_result,
           (int)buf->datalen);
    return read_result;
  }
}

int read_to_buf_tls(tor_tls *tls, int at_most, buf_t *buf) {
  int r;
  assert(tls && BUF_OK(buf));
  
  if (at_most > buf->len - buf->datalen)
    at_most = buf->len - buf->datalen;

  if (at_most == 0)
    return 0;
  
  r = tor_tls_read(tls, buf->buf+buf->datalen, at_most);
  if (r<0) 
    return r;
  buf->datalen += r;
  log_fn(LOG_DEBUG,"Read %d bytes. %d on inbuf.",r, (int)buf->datalen);
  return r;
} 

int flush_buf(int s, buf_t *buf, int *buf_flushlen) 
{

  /* push from buf onto s
   * then memmove to front of buf
   * return -1 or how many bytes remain to be flushed */

  int write_result;
#ifdef MS_WINDOWS
  int e;
#endif

  assert(BUF_OK(buf) && buf_flushlen && (s>=0) && (*buf_flushlen <= buf->datalen));

  if(*buf_flushlen == 0) /* nothing to flush */
    return 0;

  write_result = write(s, buf->buf, *buf_flushlen);
  if (write_result < 0) {
    if(!ERRNO_EAGAIN(errno)) { /* it's a real error */
      return -1;
    }
#ifdef MS_WINDOWS
    e = correct_socket_errno(s);
    if(!ERRNO_EAGAIN(e)) { /* no, it *is* a real error! */
      return -1;
    }
#endif
    log_fn(LOG_DEBUG,"write() would block, returning.");
    return 0;
  } else {
    buf->datalen -= write_result;
    *buf_flushlen -= write_result;
    memmove(buf->buf, buf->buf+write_result, buf->datalen);
    log_fn(LOG_DEBUG,"%d: flushed %d bytes, %d ready to flush, %d remain.",
           s,write_result,*buf_flushlen,(int)buf->datalen);
    return *buf_flushlen;
    /* XXX USE_TLS should change to return write_result like any sane function would */
  }
}

int flush_buf_tls(tor_tls *tls, buf_t *buf, int *buf_flushlen) 
{
  int r;
  assert(tls && BUF_OK(buf) && buf_flushlen);

  /* we want to let tls write even if flushlen is zero, because it might
   * have a partial record pending */
  r = tor_tls_write(tls, buf->buf, *buf_flushlen);
  if (r < 0) {
    return r;
  }
  buf->datalen -= r;
  *buf_flushlen -= r;
  memmove(buf->buf, buf->buf+r, buf->datalen);
  log_fn(LOG_DEBUG,"flushed %d bytes, %d ready to flush, %d remain.",
    r,*buf_flushlen,(int)buf->datalen);
  return r;
}

int write_to_buf(const char *string, int string_len, buf_t *buf) {

  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */

  assert(string && BUF_OK(buf));

  /* this is the point where you would grow the buffer, if you want to */

  if (string_len + buf->datalen > buf->len) { /* we're out of luck */
    log_fn(LOG_WARNING, "buflen too small. Time to implement growing dynamic bufs.");
    return -1;
  }

  memcpy(buf->buf+buf->datalen, string, string_len);
  buf->datalen += string_len;
  log_fn(LOG_DEBUG,"added %d bytes to buf (now %d total).",string_len, (int)buf->datalen);
  return buf->datalen;
}

int fetch_from_buf(char *string, int string_len, buf_t *buf) {

  /* There must be string_len bytes in buf; write them onto string,
   * then memmove buf back (that is, remove them from buf).
   *
   * Return the number of bytes still on the buffer. */

  assert(string && BUF_OK(buf));
  assert(string_len <= buf->datalen); /* make sure we don't ask for too much */

  memcpy(string,buf->buf,string_len);
  buf->datalen -= string_len;
  memmove(buf->buf, buf->buf+string_len, buf->datalen);
  return buf->datalen;
}

/* There is a (possibly incomplete) http statement on *buf, of the
 * form "%s\r\n\r\n%s", headers, body.
 * If a) the headers include a Content-Length field and all bytes in
 * the body are present, or b) there's no Content-Length field and
 * all headers are present, then:
 *   copy headers and body into the supplied args (and null terminate
 *   them), remove them from buf, and return 1.
 *   (If headers or body is NULL, discard that part of the buf.)
 *   If a headers or body doesn't fit in the arg, return -1.
 * 
 * Else, change nothing and return 0.
 */
int fetch_from_buf_http(buf_t *buf,
                        char *headers_out, int max_headerlen,
                        char *body_out, int max_bodylen) {
  char *headers, *body;
  int i;
  int headerlen, bodylen, contentlen;

  assert(BUF_OK(buf));

  headers = buf->buf;
  i = find_on_inbuf("\r\n\r\n", 4, buf);
  if(i < 0) {
    log_fn(LOG_DEBUG,"headers not all here yet.");
    return 0;
  }
  body = buf->buf+i;
  headerlen = body-headers; /* includes the CRLFCRLF */
  bodylen = buf->datalen - headerlen;
  log_fn(LOG_DEBUG,"headerlen %d, bodylen %d.",headerlen,bodylen);

  if(headers_out && max_headerlen <= headerlen) {
    log_fn(LOG_WARNING,"headerlen %d larger than %d. Failing.", headerlen, max_headerlen-1);
    return -1;
  }
  if(body_out && max_bodylen <= bodylen) {
    log_fn(LOG_WARNING,"bodylen %d larger than %d. Failing.", bodylen, max_bodylen-1);
    return -1;
  }

#define CONTENT_LENGTH "\r\nContent-Length: "
  i = find_str_in_str(CONTENT_LENGTH, strlen(CONTENT_LENGTH), 
                      headers, headerlen);
  if(i > 0) {
    contentlen = atoi(headers+i);
    /* XXX What if content-length is malformed? */
    log_fn(LOG_DEBUG,"Got a contentlen of %d.",contentlen);
    if(bodylen < contentlen) {
      log_fn(LOG_DEBUG,"body not all here yet.");
      return 0; /* not all there yet */
    }
    bodylen = contentlen;
    log_fn(LOG_DEBUG,"bodylen reduced to %d.",bodylen);
  }
  /* all happy. copy into the appropriate places, and return 1 */
  if(headers_out) {
    memcpy(headers_out,buf->buf,headerlen);
    headers_out[headerlen] = 0; /* null terminate it */
  }
  if(body_out) {
    memcpy(body_out,buf->buf+headerlen,bodylen);
    body_out[bodylen] = 0; /* null terminate it */
  }
  buf->datalen -= (headerlen+bodylen);
  memmove(buf->buf, buf->buf+headerlen+bodylen, buf->datalen);

  return 1;
}

/* There is a (possibly incomplete) socks handshake on buf, of one
 * of the forms
 *   socks4: "socksheader username\0"
 *   socks4a: "socksheader username\0 destaddr\0"
 *   socks5 phase one: "version #methods methods"
 *   socks5 phase two: "version command 0 addresstype..."
 * If it's a complete and valid handshake, and destaddr fits in addr_out,
 *   then pull the handshake off the buf, assign to addr_out and port_out,
 *   and return 1.
 * If it's invalid or too big, return -1.
 * Else it's not all there yet, leave buf alone and return 0.
 * If you want to specify the socks reply, write it into *reply
 *   and set *replylen, else leave *replylen alone.
 * If returning 0 or -1, *addr_out and *port_out are undefined.
 */
int fetch_from_buf_socks(buf_t *buf, char *socks_version,
                         char *reply, int *replylen,
                         char *addr_out, int max_addrlen,
                         uint16_t *port_out) {
  unsigned char len;
  char *tmpbuf=NULL;
  uint32_t destip;
  enum {socks4, socks4a} socks4_prot = socks4a;
  char *next, *startaddr;
  struct in_addr in;

  if(buf->datalen < 2) /* version and another byte */
    return 0;
  switch(*(buf->buf)) { /* which version of socks? */

    case 5: /* socks5 */

      if(*socks_version != 5) { /* we need to negotiate a method */
        unsigned char nummethods = (unsigned char)*(buf->buf+1);
        assert(!*socks_version);
        log_fn(LOG_DEBUG,"socks5: learning offered methods");
        if(buf->datalen < 2+nummethods)
          return 0;
        if(!nummethods || !memchr(buf->buf+2, 0, nummethods)) {
          log_fn(LOG_WARNING,"socks5: offered methods don't include 'no auth'. Rejecting.");
          *replylen = 2; /* 2 bytes of response */
          *reply = 5; /* socks5 reply */
          *(reply+1) = 0xFF; /* reject all methods */
          return -1;
        }          
        buf->datalen -= (2+nummethods); /* remove packet from buf */
        memmove(buf->buf, buf->buf + 2 + nummethods, buf->datalen);

        *replylen = 2; /* 2 bytes of response */
        *reply = 5; /* socks5 reply */
        *(reply+1) = 0; /* choose the 'no auth' method */
        *socks_version = 5; /* remember that we've already negotiated auth */
        log_fn(LOG_DEBUG,"socks5: accepted method 0");
        return 0;
      }
      /* we know the method; read in the request */
      log_fn(LOG_DEBUG,"socks5: checking request");
      if(buf->datalen < 8) /* basic info plus >=2 for addr plus 2 for port */
        return 0; /* not yet */
      if(*(buf->buf+1) != 1) { /* not a connect? we don't support it. */
        log_fn(LOG_WARNING,"socks5: command %d not '1'.",*(buf->buf+1));
        return -1;
      }
      switch(*(buf->buf+3)) { /* address type */
        case 1: /* IPv4 address */
          log_fn(LOG_DEBUG,"socks5: ipv4 address type");
          if(buf->datalen < 10) /* ip/port there? */
            return 0; /* not yet */
          destip = ntohl(*(uint32_t*)(buf->buf+4));
          in.s_addr = htonl(destip);
          tmpbuf = inet_ntoa(in);
          if(strlen(tmpbuf)+1 > max_addrlen) {
            log_fn(LOG_WARNING,"socks5 IP takes %d bytes, which doesn't fit in %d",
                   strlen(tmpbuf)+1,max_addrlen);
            return -1;
          }
          strcpy(addr_out,tmpbuf);
          *port_out = ntohs(*(uint16_t*)(buf->buf+8));
          buf->datalen -= 10;
          memmove(buf->buf, buf->buf+10, buf->datalen);
          return 1;
        case 3: /* fqdn */
          log_fn(LOG_DEBUG,"socks5: fqdn address type");
          len = (unsigned char)*(buf->buf+4);
          if(buf->datalen < 7+len) /* addr/port there? */
            return 0; /* not yet */
          if(len+1 > max_addrlen) {
            log_fn(LOG_WARNING,"socks5 hostname is %d bytes, which doesn't fit in %d",
                   len+1,max_addrlen);
            return -1;
          }
          memcpy(addr_out,buf->buf+5,len);
          addr_out[len] = 0;
          *port_out = ntohs(*(uint16_t*)(buf->buf+5+len));
          buf->datalen -= (5+len+2);
          memmove(buf->buf, buf->buf+(5+len+2), buf->datalen);
          return 1;
        default: /* unsupported */
          log_fn(LOG_WARNING,"socks5: unsupported address type %d",*(buf->buf+3));
          return -1;
      }
      assert(0);
    case 4: /* socks4 */

       *socks_version = 4;
      if(buf->datalen < SOCKS4_NETWORK_LEN) /* basic info available? */
        return 0; /* not yet */

      if(*(buf->buf+1) != 1) { /* not a connect? we don't support it. */
        log_fn(LOG_WARNING,"socks4: command %d not '1'.",*(buf->buf+1));
        return -1;
      }

      *port_out = ntohs(*(uint16_t*)(buf->buf+2));
      destip = ntohl(*(uint32_t*)(buf->buf+4));
      if(!*port_out || !destip) {
        log_fn(LOG_WARNING,"socks4: Port or DestIP is zero.");
        return -1;
      }
      if(destip >> 8) {
        log_fn(LOG_DEBUG,"socks4: destip not in form 0.0.0.x.");
        in.s_addr = htonl(destip);
        tmpbuf = inet_ntoa(in);
        if(strlen(tmpbuf)+1 > max_addrlen) {
          log_fn(LOG_WARNING,"socks4 addr (%d bytes) too long.", strlen(tmpbuf));
          return -1;
        }
        log_fn(LOG_DEBUG,"socks4: successfully read destip (%s)", tmpbuf);
        socks4_prot = socks4;
      }

      next = memchr(buf->buf+SOCKS4_NETWORK_LEN, 0, buf->datalen);
      if(!next) {
        log_fn(LOG_DEBUG,"Username not here yet.");
        return 0;
      }

      startaddr = next+1;
      if(socks4_prot == socks4a) {
        next = memchr(startaddr, 0, buf->buf+buf->datalen-startaddr);
        if(!next) {
          log_fn(LOG_DEBUG,"Destaddr not here yet.");
          return 0;
        }
        if(max_addrlen <= next-startaddr) {
          log_fn(LOG_WARNING,"Destaddr too long.");
          return -1;
        }
      }
      log_fn(LOG_DEBUG,"Everything is here. Success.");
      strcpy(addr_out, socks4_prot == socks4 ? tmpbuf : startaddr);
      buf->datalen -= (next-buf->buf+1); /* next points to the final \0 on inbuf */
      memmove(buf->buf, next+1, buf->datalen);
      return 1;

    default: /* version is not socks4 or socks5 */
      log_fn(LOG_WARNING,"Socks version %d not recognized.",*(buf->buf));
      return -1;
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
