/*
 * routent.c
 * Onion Router and related definitions.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.6  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.5  2002/03/12 23:38:54  mp292
 * Being pedantic about some pointer conversions.
 *
 * Revision 1.4  2002/03/03 00:24:26  mp292
 * Corrected paths to some #include files.
 *
 * Revision 1.3  2002/03/03 00:06:45  mp292
 * Modifications to support re-transmission.
 *
 * Revision 1.2  2002/01/26 19:26:55  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.1  2002/01/10 08:28:33  badbytes
 * routent and routentEX related routines
 *
 */

#include "policies.h"

#include "routent.h"

routentEX_t *id_router(routentEX_t **routerarray, size_t rarray_len, uint32_t addr, uint16_t port)
{
  routentEX_t *router;
  int i;
  
  if (!routerarray)
    return NULL;
  
  for(i=0;i<rarray_len;i++)
  {
    router = routerarray[i];
    if ((router->addr == addr) && (router->port == port))
      return router;
  }
  
  return NULL;
}

routentEX_t *id_routerbys(routentEX_t **routerarray, size_t rarray_len, int s)
{
  routentEX_t *router;
  int i;
  
  if (!routerarray)
    return NULL;
  
  for(i=0;i<rarray_len;i++)
  {
    router = routerarray[i];
    if (router->s == s)
      return router;
  }
  
  return NULL;
}

conn_buf_t *new_conn_buf(uint16_t aci, int policy, conn_buf_t **conn_bufs, conn_buf_t **last_conn_buf)
{
  conn_buf_t *conn_buf;
  
  if ((!aci) || (!conn_bufs) || (!last_conn_buf)) /* invalid parameters */
    return NULL;
  
  conn_buf = (conn_buf_t *)malloc(sizeof(conn_buf_t));
  if (!conn_buf)
    return NULL;
  
  memset((void *)conn_buf,0,sizeof(conn_buf_t));
  conn_buf->win_size = DEFAULT_WINDOW_SIZE;
  conn_buf->win_avail = DEFAULT_WINDOW_SIZE;
  conn_buf->aci = aci;
  conn_buf->policy = policy;
  
  if (!*conn_bufs)
  {
    *conn_bufs = conn_buf;
  }
  else
  {
    (*last_conn_buf)->next=(void *)conn_buf;
    conn_buf->prev = (void *)*last_conn_buf;
  }
  
  *last_conn_buf = conn_buf;
  
  return conn_buf;
}

int remove_conn_buf(conn_buf_t *conn_buf, conn_buf_t **conn_bufs, conn_buf_t **last_conn_buf)
{
  if ( (!conn_buf) || (!*conn_bufs) || (!*last_conn_buf) ) /* invalid parameters */
    return -1;
  
  if (conn_buf->next)
    ((conn_buf_t *)(conn_buf->next))->prev = conn_buf->prev;
  if (conn_buf->prev)
    ((conn_buf_t *)(conn_buf->prev))->next = conn_buf->next;
  
  if (conn_buf == *last_conn_buf)
    *last_conn_buf = (conn_buf_t *)conn_buf->prev;
  
  if (conn_buf == *conn_bufs)
    *conn_bufs = (conn_buf_t *)conn_buf->next;

  if (conn_buf->buf)
    free((void *)conn_buf->buf);
  
  free((void *)conn_buf);
  
  return 0;
}

conn_buf_t *id_conn_buf(conn_buf_t *conn_bufs, uint16_t aci)
{
  conn_buf_t *conn_buf;
  
  if ( (!aci) || (!conn_bufs) )
    return NULL;
  
  conn_buf = conn_bufs;
  while (conn_buf)
  {
    if (conn_buf->aci == aci)
      return conn_buf;
    
    conn_buf = conn_buf->next;
  }
  
  return NULL;
}
