/* Copyright 2001 Matej Pfajfar, 2001-2004 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file buffers.c
 * \brief Abstractions for buffered IO.
 **/

#include "or.h"

#define BUFFER_MAGIC 0xB0FFF312u
struct buf_t {
  uint32_t magic; /**< Magic cookie for debugging: Must be set to BUFFER_MAGIC */
  char *mem;      /**< Storage for data in the buffer */
  size_t len;     /**< Maximum amount of data that <b>mem</b> can hold. */
  size_t datalen; /**< Number of bytes currently in <b>mem</b>. */
};

/** Size, in bytes, for newly allocated buffers.  Should be a power of 2. */
#define INITIAL_BUF_SIZE (4*1024)
/** Maximum size, in bytes, for resized buffers. */
#define MAX_BUF_SIZE (1024*1024*10)
/** Size, in bytes, for minimum 'shrink' size for buffers.  Buffers may start
 * out smaller than this, but they will never autoshrink to less
 * than this size. */
#define MIN_BUF_SHRINK_SIZE (16*1024)

/** Change a buffer's capacity. <b>new_capacity</b> must be \<= buf->datalen. */
static INLINE void buf_resize(buf_t *buf, size_t new_capacity)
{
  tor_assert(buf->datalen <= new_capacity);
  tor_assert(new_capacity);
  buf->mem = tor_realloc(buf->mem, new_capacity);
  buf->len = new_capacity;
}

/** If the buffer is not large enough to hold <b>capacity</b> bytes, resize
 * it so that it can.  (The new size will be a power of 2 times the old
 * size.)
 */
static INLINE int buf_ensure_capacity(buf_t *buf, size_t capacity)
{
  size_t new_len;
  if (buf->len >= capacity)  /* Don't grow if we're already big enough. */
    return 0;
  if (capacity > MAX_BUF_SIZE) /* Don't grow past the maximum. */
    return -1;
  /* Find the smallest new_len equal to (2**X)*len for some X; such that
   * new_len is at least capacity.
   */
  new_len = buf->len*2;
  while (new_len < capacity)
    new_len *= 2;
  /* Resize the buffer. */
  log_fn(LOG_DEBUG,"Growing buffer from %d to %d bytes.",
         (int)buf->len, (int)new_len);
  buf_resize(buf,new_len);
  return 0;
}

/** If the buffer is at least 2*MIN_BUF_SHRINK_SIZE bytes in capacity,
 * and if the buffer is less than 1/4 full, shrink the buffer until
 * one of the above no longer holds.  (We shrink the buffer by
 * dividing by powers of 2.)
 */
static INLINE void buf_shrink_if_underfull(buf_t *buf) {
  size_t new_len;
  /* If the buffer is at least .25 full, or if shrinking the buffer would
   * put it onder MIN_BUF_SHRINK_SIZE, don't do it. */
  if (buf->datalen >= buf->len/4 || buf->len < 2*MIN_BUF_SHRINK_SIZE)
    return;
  /* Shrink new_len by powers of 2 until: datalen is at least 1/4 of
   * new_len, OR shrinking new_len more would put it under
   * MIN_BUF_SHRINK_SIZE.
   */
  new_len = buf->len / 2;
  while (buf->datalen < new_len/4 && new_len/2 > MIN_BUF_SHRINK_SIZE)
    new_len /= 2;
  log_fn(LOG_DEBUG,"Shrinking buffer from %d to %d bytes.",
         (int)buf->len, (int)new_len);
  buf_resize(buf, new_len);
}

/** Remove the first <b>n</b> bytes from buf.
 */
static INLINE void buf_remove_from_front(buf_t *buf, size_t n) {
  tor_assert(buf->datalen >= n);
  buf->datalen -= n;
  memmove(buf->mem, buf->mem+n, buf->datalen);
  buf_shrink_if_underfull(buf);
}

/** Make sure that the memory in buf ends with a zero byte. */
static INLINE int buf_nul_terminate(buf_t *buf)
{
  if (buf_ensure_capacity(buf,buf->datalen+1)<0)
    return -1;
  buf->mem[buf->datalen] = '\0';
  return 0;
}

/** Create and return a new buf with capacity <b>size</b>.
 */
buf_t *buf_new_with_capacity(size_t size) {
  buf_t *buf;
  buf = tor_malloc(sizeof(buf_t));
  buf->magic = BUFFER_MAGIC;
  buf->mem = tor_malloc(size);
  buf->len = size;
  buf->datalen = 0;
//  memset(buf->mem,0,size);

  assert_buf_ok(buf);
  return buf;
}

/** Allocate and return a new buffer with default capacity. */
buf_t *buf_new()
{
  return buf_new_with_capacity(INITIAL_BUF_SIZE);
}

/** Remove all data from <b>buf</b> */
void buf_clear(buf_t *buf)
{
  buf->datalen = 0;
}

/** Return the number of bytes stored in <b>buf</b> */
size_t buf_datalen(const buf_t *buf)
{
  return buf->datalen;
}

/** Return the maximum bytes that can be stored in <b>buf</b> before buf
 * needs to resize. */
size_t buf_capacity(const buf_t *buf)
{
  return buf->len;
}

/** For testing only: Return a pointer to the raw memory stored in <b>buf</b>.
 */
const char *_buf_peek_raw_buffer(const buf_t *buf)
{
  return buf->mem;
}

/** Release storage held by <b>buf</b>.
 */
void buf_free(buf_t *buf) {
  assert_buf_ok(buf);
  buf->magic = 0xDEADBEEF;
  tor_free(buf->mem);
  tor_free(buf);
}

/** Read from socket <b>s</b>, writing onto end of <b>buf</b>.  Read at most
 * <b>at_most</b> bytes, resizing the buffer as necessary.  If read()
 * returns 0, set <b>*reached_eof</b> to 1 and return 0. Return -1 on error;
 * else return the number of bytes read.  Return 0 if read() would
 * block.
 */
int read_to_buf(int s, size_t at_most, buf_t *buf, int *reached_eof) {

  int read_result;

  assert_buf_ok(buf);
  tor_assert(reached_eof && (s>=0));

  if (buf_ensure_capacity(buf,buf->datalen+at_most))
    return -1;

  if(at_most + buf->datalen > buf->len)
    at_most = buf->len - buf->datalen; /* take the min of the two */

  if(at_most == 0)
    return 0; /* we shouldn't read anything */

//  log_fn(LOG_DEBUG,"reading at most %d bytes.",at_most);
  read_result = recv(s, buf->mem+buf->datalen, at_most, 0);
  if (read_result < 0) {
    if(!ERRNO_IS_EAGAIN(tor_socket_errno(s))) { /* it's a real error */
      return -1;
    }
    return 0; /* would block. */
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

/** As read_to_buf, but reads from a TLS connection.
 */
int read_to_buf_tls(tor_tls *tls, size_t at_most, buf_t *buf) {
  int r;
  tor_assert(tls);
  assert_buf_ok(buf);

  log_fn(LOG_DEBUG,"start: %d on buf, %d pending, at_most %d.",
         (int)buf_datalen(buf), (int)tor_tls_get_pending_bytes(tls),
         (int)at_most);

  if (buf_ensure_capacity(buf, at_most+buf->datalen))
    return TOR_TLS_ERROR;

  if (at_most + buf->datalen > buf->len)
    at_most = buf->len - buf->datalen;

  if (at_most == 0)
    return 0;

  log_fn(LOG_DEBUG,"before: %d on buf, %d pending, at_most %d.",
         (int)buf_datalen(buf), (int)tor_tls_get_pending_bytes(tls),
         (int)at_most);

  assert_no_tls_errors();
  r = tor_tls_read(tls, buf->mem+buf->datalen, at_most);
  if (r<0)
    return r;
  buf->datalen += r;
  log_fn(LOG_DEBUG,"Read %d bytes. %d on inbuf; %d pending",r,
         (int)buf->datalen,(int)tor_tls_get_pending_bytes(tls));
  return r;
}

/** Write data from <b>buf</b> to the socket <b>s</b>.  Write at most
 * <b>*buf_flushlen</b> bytes, decrement <b>*buf_flushlen</b> by
 * the number of bytes actually written, and remove the written bytes
 * from the buffer.  Return the number of bytes written on success,
 * -1 on failure.  Return 0 if write() would block.
 */
int flush_buf(int s, buf_t *buf, int *buf_flushlen)
{
  int write_result;

  assert_buf_ok(buf);
  tor_assert(buf_flushlen && (s>=0) && ((unsigned)*buf_flushlen <= buf->datalen));

  if(*buf_flushlen == 0) /* nothing to flush */
    return 0;

  write_result = send(s, buf->mem, *buf_flushlen, 0);
  if (write_result < 0) {
    if(!ERRNO_IS_EAGAIN(tor_socket_errno(s))) { /* it's a real error */
      return -1;
    }
    log_fn(LOG_DEBUG,"write() would block, returning.");
    return 0;
  } else {
    *buf_flushlen -= write_result;
    buf_remove_from_front(buf, write_result);
    log_fn(LOG_DEBUG,"%d: flushed %d bytes, %d ready to flush, %d remain.",
           s,write_result,*buf_flushlen,(int)buf->datalen);

    return write_result;
  }
}

/** As flush_buf, but writes data to a TLS connection.
 */
int flush_buf_tls(tor_tls *tls, buf_t *buf, int *buf_flushlen)
{
  int r;
  assert_buf_ok(buf);
  tor_assert(tls && buf_flushlen);

  /* we want to let tls write even if flushlen is zero, because it might
   * have a partial record pending */
  r = tor_tls_write(tls, buf->mem, *buf_flushlen);
  if (r < 0) {
    return r;
  }
  *buf_flushlen -= r;
  buf_remove_from_front(buf, r);
  log_fn(LOG_DEBUG,"flushed %d bytes, %d ready to flush, %d remain.",
    r,*buf_flushlen,(int)buf->datalen);
  return r;
}

/** Append <b>string_len</b> bytes from <b>string</b> to the end of
 * <b>buf</b>.
 *
 * Return the new length of the buffer on success, -1 on failure.
 */
int write_to_buf(const char *string, int string_len, buf_t *buf) {

  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */

  tor_assert(string);
  assert_buf_ok(buf);

  if (buf_ensure_capacity(buf, buf->datalen+string_len)) {
    log_fn(LOG_WARN, "buflen too small, can't hold %d bytes.", (int)buf->datalen+string_len);
    return -1;
  }

  memcpy(buf->mem+buf->datalen, string, string_len);
  buf->datalen += string_len;
  log_fn(LOG_DEBUG,"added %d bytes to buf (now %d total).",string_len, (int)buf->datalen);
  return buf->datalen;
}

/** Remove <b>string_len</b> bytes from the front of <b>buf</b>, and store them
 * into <b>string</b>.  Return the new buffer size.  <b>string_len</b> must be \<=
 * the number of bytes on the buffer.
 */
int fetch_from_buf(char *string, size_t string_len, buf_t *buf) {

  /* There must be string_len bytes in buf; write them onto string,
   * then memmove buf back (that is, remove them from buf).
   *
   * Return the number of bytes still on the buffer. */

  tor_assert(string);
  tor_assert(string_len <= buf->datalen); /* make sure we don't ask for too much */
  assert_buf_ok(buf);

  memcpy(string,buf->mem,string_len);
  buf_remove_from_front(buf, string_len);
  return buf->datalen;
}

/** There is a (possibly incomplete) http statement on <b>buf</b>, of the
 * form "\%s\\r\\n\\r\\n\%s", headers, body. (body may contain nuls.)
 * If a) the headers include a Content-Length field and all bytes in
 * the body are present, or b) there's no Content-Length field and
 * all headers are present, then:
 *
 *  - strdup headers into <b>*headers_out</b>, and nul-terminate it.
 *  - memdup body into <b>*body_out</b>, and nul-terminate it.
 *  - Then remove them from <b>buf</b>, and return 1.
 *
 *  - If headers or body is NULL, discard that part of the buf.
 *  - If a headers or body doesn't fit in the arg, return -1.
 *
 * Else, change nothing and return 0.
 */
int fetch_from_buf_http(buf_t *buf,
                        char **headers_out, int max_headerlen,
                        char **body_out, int *body_used, int max_bodylen) {
  char *headers, *body, *p;
  int headerlen, bodylen, contentlen;

  assert_buf_ok(buf);

  headers = buf->mem;
  if (buf_nul_terminate(buf)<0) {
    log_fn(LOG_WARN,"Couldn't nul-terminate buffer");
    return -1;
  }
  body = strstr(headers,"\r\n\r\n");
  if (!body) {
    log_fn(LOG_DEBUG,"headers not all here yet.");
    return 0;
  }
  body += 4; /* Skip the the CRLFCRLF */
  headerlen = body-headers; /* includes the CRLFCRLF */
  bodylen = buf->datalen - headerlen;
  log_fn(LOG_DEBUG,"headerlen %d, bodylen %d.", headerlen, bodylen);

  if(headers_out && max_headerlen <= headerlen) {
    log_fn(LOG_WARN,"headerlen %d larger than %d. Failing.", headerlen, max_headerlen-1);
    return -1;
  }
  if(body_out && max_bodylen <= bodylen) {
    log_fn(LOG_WARN,"bodylen %d larger than %d. Failing.", bodylen, max_bodylen-1);
    return -1;
  }

#define CONTENT_LENGTH "\r\nContent-Length: "
  p = strstr(headers, CONTENT_LENGTH);
  if (p) {
    contentlen = atoi(p+strlen(CONTENT_LENGTH));
    /* if content-length is malformed, then our body length is 0. fine. */
    log_fn(LOG_DEBUG,"Got a contentlen of %d.",contentlen);
    if(bodylen < contentlen) {
      log_fn(LOG_DEBUG,"body not all here yet.");
      return 0; /* not all there yet */
    }
    if(bodylen > contentlen) {
      bodylen = contentlen;
      log_fn(LOG_DEBUG,"bodylen reduced to %d.",bodylen);
    }
  }
  /* all happy. copy into the appropriate places, and return 1 */
  if(headers_out) {
    *headers_out = tor_malloc(headerlen+1);
    memcpy(*headers_out,buf->mem,headerlen);
    (*headers_out)[headerlen] = 0; /* null terminate it */
  }
  if(body_out) {
    tor_assert(body_used);
    *body_used = bodylen;
    *body_out = tor_malloc(bodylen+1);
    memcpy(*body_out,buf->mem+headerlen,bodylen);
    (*body_out)[bodylen] = 0; /* null terminate it */
  }
  buf_remove_from_front(buf, headerlen+bodylen);
  return 1;
}

/** There is a (possibly incomplete) socks handshake on <b>buf</b>, of one
 * of the forms
 *  - socks4: "socksheader username\\0"
 *  - socks4a: "socksheader username\\0 destaddr\\0"
 *  - socks5 phase one: "version #methods methods"
 *  - socks5 phase two: "version command 0 addresstype..."
 * If it's a complete and valid handshake, and destaddr fits in
 *   MAX_SOCKS_ADDR_LEN bytes, then pull the handshake off the buf,
 *   assign to <b>req</b>, and return 1.
 *
 * If it's invalid or too big, return -1.
 *
 * Else it's not all there yet, leave buf alone and return 0.
 *
 * If you want to specify the socks reply, write it into <b>req->reply</b>
 *   and set <b>req->replylen</b>, else leave <b>req->replylen</b> alone.
 *
 * If returning 0 or -1, <b>req->address</b> and <b>req->port</b> are undefined.
 */
int fetch_from_buf_socks(buf_t *buf, socks_request_t *req) {
  unsigned char len;
  char *tmpbuf=NULL;
  uint32_t destip;
  enum {socks4, socks4a} socks4_prot = socks4a;
  char *next, *startaddr;
  struct in_addr in;

  if(buf->datalen < 2) /* version and another byte */
    return 0;
  switch(*(buf->mem)) { /* which version of socks? */

    case 5: /* socks5 */

      if(req->socks_version != 5) { /* we need to negotiate a method */
        unsigned char nummethods = (unsigned char)*(buf->mem+1);
        tor_assert(!req->socks_version);
        if(buf->datalen < 2u+nummethods)
          return 0;
        if(!nummethods || !memchr(buf->mem+2, 0, nummethods)) {
          log_fn(LOG_WARN,"socks5: offered methods don't include 'no auth'. Rejecting.");
          req->replylen = 2; /* 2 bytes of response */
          req->reply[0] = 5; /* socks5 reply */
          req->reply[1] = '\xFF'; /* reject all methods */
          return -1;
        }
        buf_remove_from_front(buf,2+nummethods);/* remove packet from buf */

        req->replylen = 2; /* 2 bytes of response */
        req->reply[0] = 5; /* socks5 reply */
        req->reply[1] = 0; /* choose the 'no auth' method */
        req->socks_version = 5; /* remember that we've already negotiated auth */
        log_fn(LOG_DEBUG,"socks5: accepted method 0");
        return 0;
      }
      /* we know the method; read in the request */
      log_fn(LOG_DEBUG,"socks5: checking request");
      if(buf->datalen < 8) /* basic info plus >=2 for addr plus 2 for port */
        return 0; /* not yet */
      req->command = (unsigned char) *(buf->mem+1);
      if(req->command != SOCKS_COMMAND_CONNECT &&
         req->command != SOCKS_COMMAND_RESOLVE) {
        /* not a connect or resolve? we don't support it. */
        log_fn(LOG_WARN,"socks5: command %d not recognized. Rejecting.",
               req->command);
        return -1;
      }
      switch(*(buf->mem+3)) { /* address type */
        case 1: /* IPv4 address */
          log_fn(LOG_DEBUG,"socks5: ipv4 address type");
          if(buf->datalen < 10) /* ip/port there? */
            return 0; /* not yet */
          destip = ntohl(*(uint32_t*)(buf->mem+4));
          in.s_addr = htonl(destip);
          tmpbuf = inet_ntoa(in);
          if(strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN) {
            log_fn(LOG_WARN,"socks5 IP takes %d bytes, which doesn't fit in %d. Rejecting.",
                   (int)strlen(tmpbuf)+1,(int)MAX_SOCKS_ADDR_LEN);
            return -1;
          }
          strcpy(req->address,tmpbuf);
          req->port = ntohs(*(uint16_t*)(buf->mem+8));
          buf_remove_from_front(buf, 10);
          return 1;
        case 3: /* fqdn */
          log_fn(LOG_DEBUG,"socks5: fqdn address type");
          len = (unsigned char)*(buf->mem+4);
          if(buf->datalen < 7u+len) /* addr/port there? */
            return 0; /* not yet */
          if(len+1 > MAX_SOCKS_ADDR_LEN) {
            log_fn(LOG_WARN,"socks5 hostname is %d bytes, which doesn't fit in %d. Rejecting.",
                   len+1,MAX_SOCKS_ADDR_LEN);
            return -1;
          }
          memcpy(req->address,buf->mem+5,len);
          req->address[len] = 0;
          req->port = ntohs(get_uint16(buf->mem+5+len));
          buf_remove_from_front(buf, 5+len+2);
          return 1;
        default: /* unsupported */
          log_fn(LOG_WARN,"socks5: unsupported address type %d. Rejecting.",*(buf->mem+3));
          return -1;
      }
      tor_assert(0);
    case 4: /* socks4 */
      /* http://archive.socks.permeo.com/protocol/socks4.protocol */
      /* http://archive.socks.permeo.com/protocol/socks4a.protocol */

      req->socks_version = 4;
      if(buf->datalen < SOCKS4_NETWORK_LEN) /* basic info available? */
        return 0; /* not yet */

      req->command = (unsigned char) *(buf->mem+1);
      if(req->command != SOCKS_COMMAND_CONNECT &&
         req->command != SOCKS_COMMAND_RESOLVE) {
        /* not a connect or resolve? we don't support it. */
        log_fn(LOG_WARN,"socks4: command %d not recognized. Rejecting.",
               req->command);
        return -1;
      }

      req->port = ntohs(*(uint16_t*)(buf->mem+2));
      destip = ntohl(*(uint32_t*)(buf->mem+4));
      if((!req->port && req->command!=SOCKS_COMMAND_RESOLVE) || !destip) {
        log_fn(LOG_WARN,"socks4: Port or DestIP is zero. Rejecting.");
        return -1;
      }
      if(destip >> 8) {
        log_fn(LOG_DEBUG,"socks4: destip not in form 0.0.0.x.");
        in.s_addr = htonl(destip);
        tmpbuf = inet_ntoa(in);
        if(strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN) {
          log_fn(LOG_WARN,"socks4 addr (%d bytes) too long. Rejecting.",
                 (int)strlen(tmpbuf));
          return -1;
        }
        log_fn(LOG_DEBUG,"socks4: successfully read destip (%s)", tmpbuf);
        socks4_prot = socks4;
      }

      next = memchr(buf->mem+SOCKS4_NETWORK_LEN, 0,
                    buf->datalen-SOCKS4_NETWORK_LEN);
      if(!next) {
        log_fn(LOG_DEBUG,"socks4: Username not here yet.");
        return 0;
      }

      startaddr = next+1;
      if(socks4_prot == socks4a) {
        next = memchr(startaddr, 0, buf->mem+buf->datalen-startaddr);
        if(!next) {
          log_fn(LOG_DEBUG,"socks4: Destaddr not here yet.");
          return 0;
        }
        if(MAX_SOCKS_ADDR_LEN <= next-startaddr) {
          log_fn(LOG_WARN,"socks4: Destaddr too long. Rejecting.");
          return -1;
        }
      }
      log_fn(LOG_DEBUG,"socks4: Everything is here. Success.");
      strcpy(req->address, socks4_prot == socks4 ? tmpbuf : startaddr);
      /* XXX on very old netscapes (socks4) the next line triggers an
       * assert, because next-buf->mem+1 is greater than buf->datalen.
       */
      buf_remove_from_front(buf, next-buf->mem+1); /* next points to the final \0 on inbuf */
      return 1;

    case 'G': /* get */
    case 'H': /* head */
    case 'P': /* put/post */
    case 'C': /* connect */
      strcpy(req->reply,
"HTTP/1.0 501 Tor is not an HTTP Proxy\r\n"
"Content-Type: text/html; charset=iso-8859-1\r\n\r\n"
"<html>\n"
"<head>\n"
"<title>Tor is not an HTTP Proxy</title>\n"
"</head>\n"
"<body>\n"
"<h1>Tor is not an HTTP Proxy</h1>\n"
"<p>\n"
"It appears you have configured your web browser to use Tor as an HTTP Proxy.\n"
"This is not correct: Tor provides a SOCKS proxy. Please configure your\n"
"client accordingly.\n"
"</p>\n"
"<p>\n"
"See <a href=\"http://freehaven.net/tor/cvs/INSTALL\">http://freehaven.net/tor/cvs/INSTALL</a> for more information.\n"
"<!-- Plus this comment, to make the body response more than 512 bytes, so IE will be willing to display it. Comment comment comment comment comment comment comment comment comment comment comment comment.-->\n"
"</p>\n"
"</body>\n"
"</html>\n"
);
      req->replylen = strlen(req->reply)+1;
      /* fall through */
    default: /* version is not socks4 or socks5 */
      log_fn(LOG_WARN,"Socks version %d not recognized. (Tor is not an http proxy.)",
             *(buf->mem));
      return -1;
  }
}

/** Log an error and exit if <b>buf</b> is corrupted.
 */
void assert_buf_ok(buf_t *buf)
{
  tor_assert(buf);
  tor_assert(buf->magic == BUFFER_MAGIC);
  tor_assert(buf->mem);
  tor_assert(buf->datalen <= buf->len);
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
