
#include "or.h"

/********* START VARIABLES **********/

circuit_t *global_circuitlist=NULL;

/********* END VARIABLES ************/

void circuit_add(circuit_t *circ) {

  if(!global_circuitlist) { /* first one */
    global_circuitlist = circ;
    circ->next = NULL;
  } else {
    circ->next = global_circuitlist;
    global_circuitlist = circ;
  }

}

void circuit_remove(circuit_t *circ) {
  circuit_t *tmpcirc;

  if(!circ || !global_circuitlist)
    return;

  if(global_circuitlist == circ) {
    global_circuitlist = global_circuitlist->next;
    return;
  }

  for(tmpcirc = global_circuitlist;tmpcirc->next;tmpcirc = tmpcirc->next) {
    if(tmpcirc->next == circ) {
      tmpcirc->next = circ->next;
      return;
    }
  }

}

circuit_t *circuit_new(aci_t p_aci, connection_t *p_conn) {

  circuit_t *circ; 

  circ = (circuit_t *)malloc(sizeof(circuit_t));
  if(!circ)
    return NULL;
  memset(circ,0,sizeof(circuit_t)); /* zero it out */

  circ->p_aci = p_aci;
  circ->p_conn = p_conn;

  circ->state = CIRCUIT_STATE_OPEN_WAIT;
  circ->onion = NULL;
  circ->onionlen=0;
  circ->recvlen=0;

  /* ACIs */
  circ->p_aci = p_aci;
  circ->n_aci = 0; /* we need to have identified the next hop to choose a correct ACI */

  circuit_add(circ);

  return circ;
}

void circuit_free(circuit_t *circ) {

  EVP_CIPHER_CTX_cleanup(&circ->n_ctx);
  EVP_CIPHER_CTX_cleanup(&circ->p_ctx);

  if(circ->onion)
    free(circ->onion);

  free(circ);

}

aci_t get_unique_aci_by_addr_port(uint32_t addr, uint16_t port, int aci_type) {
  aci_t test_aci;
  connection_t *conn;

  log(LOG_DEBUG,"get_unique_aci_by_addr_port() trying to get a unique aci");

  RAND_pseudo_bytes((unsigned char *)&test_aci, 2);

  if(aci_type == ACI_TYPE_LOWER)
    test_aci &= htons(0x00FF);
  if(aci_type == ACI_TYPE_HIGHER)
    test_aci &= htons(0xFF00);

  if(test_aci == 0)
    return get_unique_aci_by_addr_port(addr, port, aci_type); /* try again */ 

  conn = connection_get_by_addr_port(addr,port);  
  if(!conn) /* there can't be a conflict -- no connection of that sort yet */
    return test_aci;

  if(circuit_get_by_aci_conn(test_aci, conn))
    return get_unique_aci_by_addr_port(addr, port, aci_type); /* try again */

  return test_aci;
  
}

int circuit_init(circuit_t *circ, int aci_type) {
  onion_layer_t *ol;
  int retval = 0;
  unsigned char digest1[20];
  unsigned char digest2[20];

  if (!circ)
    return -1;

  ol = (onion_layer_t *)circ->onion;
  if (!ol)
    return -1;

  log(LOG_DEBUG,"circuit_init(): starting");
  circ->n_addr = ol->addr;
  circ->n_port = ol->port;
  log(LOG_DEBUG,"circuit_init(): Set port to %u.",ntohs(ol->port));
  circ->p_f = ol->backf;
  log(LOG_DEBUG,"circuit_init(): Set BACKF to %u.",ol->backf);
  circ->n_f = ol->forwf;
  log(LOG_DEBUG,"circuit_init(): Set FORWF to %u.",ol->forwf);
  circ->state = CIRCUIT_STATE_OPEN;

  log(LOG_DEBUG,"circuit_init(): aci_type = %u.",aci_type);

  circ->n_aci = get_unique_aci_by_addr_port(circ->n_addr, circ->n_port, aci_type);

  log(LOG_DEBUG,"circuit_init(): Chosen ACI %u.",circ->n_aci);

  /* keys */
  SHA1(ol->keyseed,16,digest1);
  SHA1(digest1,20,digest2);
  SHA1(digest2,20,digest1);
  memcpy(circ->p_key,digest2,16);
  memcpy(circ->n_key,digest1,16);
  log(LOG_DEBUG,"circuit_init(): Computed keys.");

  /* set IVs to zero */
  memset(circ->n_iv,0,16);
  memset(circ->p_iv,0,16);

  /* initialize cipher context */
  EVP_CIPHER_CTX_init(&circ->n_ctx);
  EVP_CIPHER_CTX_init(&circ->p_ctx);

  /* initialize crypto engines */
  switch(circ->p_f)
  {
   case ONION_CIPHER_DES :
    retval = EVP_EncryptInit(&circ->p_ctx, EVP_des_ofb(), circ->p_key, circ->p_iv);
    break;
   case ONION_CIPHER_RC4 :
    retval = EVP_EncryptInit(&circ->p_ctx, EVP_rc4(), circ->p_key,circ->p_iv);
    break;
   case ONION_CIPHER_IDENTITY :
    retval = EVP_EncryptInit(&circ->p_ctx, EVP_enc_null(), circ->p_key, circ->p_iv);
    break;
   default :
    log(LOG_ERR,"Onion contains unrecognized cipher(%u) for ACI : %u.",circ->p_f,circ->n_aci);
    return -1;
    break;
  }

  if (!retval) /* EVP_EncryptInit() error */
  {
    log(LOG_ERR,"Cipher initialization failed (ACI %u).",circ->n_aci);
    EVP_CIPHER_CTX_cleanup(&circ->n_ctx);
    EVP_CIPHER_CTX_cleanup(&circ->p_ctx);
    return -1;
  }
  switch(circ->n_f)
  {
   case ONION_CIPHER_DES :
    retval = EVP_DecryptInit(&circ->n_ctx, EVP_des_ofb(), circ->n_key, circ->n_iv);
    break;
   case ONION_CIPHER_RC4 :
    retval = EVP_DecryptInit(&circ->n_ctx, EVP_rc4(), circ->n_key,circ->n_iv);
    break;
   case ONION_CIPHER_IDENTITY :
    retval = EVP_DecryptInit(&circ->n_ctx, EVP_enc_null(), circ->n_key, circ->n_iv);
    break;
   default :
    log(LOG_ERR,"Onion contains unrecognized cipher for ACI : %u.",circ->n_aci);
    return -1;
    break;
  }
  if (!retval) /* EVP_EncryptInit() error */
  {
    log(LOG_ERR,"Cipher initialization failed (ACI %u).",circ->n_aci);
    EVP_CIPHER_CTX_cleanup(&circ->n_ctx);
    EVP_CIPHER_CTX_cleanup(&circ->p_ctx);
    return -1;
  }
  log(LOG_DEBUG,"circuit_init(): Cipher initialization complete.");

  circ->expire = ol->expire;

  return 0;
}

circuit_t *circuit_get_by_aci_conn(aci_t aci, connection_t *conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_conn == conn && circ->p_aci == aci)
       return circ;
    if(circ->n_conn == conn && circ->n_aci == aci)
       return circ;
  }
  return NULL;
}

circuit_t *circuit_get_by_conn(connection_t *conn) {
  circuit_t *circ;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(circ->p_conn == conn)
       return circ;
    if(circ->n_conn == conn)
       return circ;
  }
  return NULL;
}

int circuit_deliver_data_cell(cell_t *cell, circuit_t *circ, connection_t *conn, int crypt_type) {

  /* first decrypt cell->length */
  if(circuit_crypt(circ, &(cell->length), 1, crypt_type) < 0) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): length decryption failed. Dropping connection.");
    return -1;
  }

  /* then decrypt the payload */
  if(circuit_crypt(circ, (char *)&(cell->payload), CELL_PAYLOAD_SIZE, crypt_type) < 0) {
    log(LOG_DEBUG,"circuit_deliver_data_cell(): payload decryption failed. Dropping connection.");
    return -1;
  }

  if(conn->type == CONN_TYPE_APP) { /* send payload directly */
    log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to application.");
    if(connection_app_process_data_cell(cell, conn) < 0) {
      return -1;
    }
  } else { /* send it as a cell */
    log(LOG_DEBUG,"circuit_deliver_data_cell(): Sending to connection.");
    if(connection_write_cell_to_buf(cell, conn) < 0) {
      return -1;
    }
  }
  return 0; /* success */
}

int circuit_crypt(circuit_t *circ, char *in, size_t inlen, char crypt_type) {
  char *out;
  int outlen;

  if(!circ || !in)
    return -1;

  out = malloc(inlen);
  if(!out)
    return -1;

  if(crypt_type == 'e') {
    log(LOG_DEBUG,"circuit_crypt(): Encrypting %d bytes.",inlen);
    if(!EVP_EncryptUpdate(&circ->p_ctx,out,&outlen,in,inlen)) {
      log(LOG_ERR,"circuit_encrypt(): Encryption failed for ACI : %u (%s).",circ->p_aci, ERR_reason_error_string(ERR_get_error()));
      return -1;
    }
  } else if(crypt_type == 'd') {
    log(LOG_DEBUG,"circuit_crypt(): Decrypting %d bytes.",inlen);
    if(!EVP_DecryptUpdate(&circ->n_ctx,out,&outlen,in,inlen)) {
      log(LOG_ERR,"circuit_crypt(): Decryption failed for ACI : %u (%s).",circ->n_aci, ERR_reason_error_string(ERR_get_error()));
      return -1;
    }
  }

  if(outlen != inlen) {
    log(LOG_DEBUG,"circuit_crypt(): %d bytes crypted to %d bytes. Weird.",inlen,outlen);
    return -1;
  }
  
  memcpy(in,out,inlen);
  free(out);

  return 0;
}

void circuit_close(circuit_t *circ) {
  circuit_remove(circ);
  connection_send_destroy(circ->n_aci, circ->n_conn); 
  connection_send_destroy(circ->p_aci, circ->p_conn); 
  circuit_free(circ);
}

void circuit_about_to_close_connection(connection_t *conn) {
  /* send destroys for all circuits using conn */
  /* currently, we assume it's too late to flush conn's buf here.
   * down the road, maybe we'll consider that eof doesn't mean can't-write
   */

  circuit_t *circ;

  while((circ = circuit_get_by_conn(conn))) {
    circuit_remove(circ);
    if(circ->n_conn == conn) /* it's closing in front of us */
      connection_send_destroy(circ->p_aci, circ->p_conn);
    if(circ->p_conn == conn) /* it's closing behind us */
      connection_send_destroy(circ->n_aci, circ->n_conn);
    circuit_free(circ);
  }  
}

