
#include "or.h"

/********* START VARIABLES **********/

tracked_onion_t *tracked_onions = NULL; /* linked list of tracked onions */
tracked_onion_t *last_tracked_onion = NULL;

/********* END VARIABLES ************/


int decide_aci_type(uint32_t local_addr, uint16_t local_port,
                    uint32_t remote_addr, uint16_t remote_port) {

  if(local_addr > remote_addr)
    return ACI_TYPE_HIGHER;
  if(local_addr < remote_addr)
    return ACI_TYPE_LOWER;
  if(local_port > remote_port)
    return ACI_TYPE_HIGHER;
   /* else */
   return ACI_TYPE_LOWER; 
}

int process_onion(circuit_t *circ, connection_t *conn) {
  aci_t aci_type;

  if(!decrypt_onion((onion_layer_t *)circ->onion,circ->onionlen,conn->prkey)) {
    log(LOG_DEBUG,"command_process_create_cell(): decrypt_onion() failed, closing circuit.");
    return -1;
  }
  log(LOG_DEBUG,"command_process_create_cell(): Onion decrypted.");

  /* check freshness */
  if (((onion_layer_t *)circ->onion)->expire < time(NULL)) /* expired onion */
  { 
    log(LOG_NOTICE,"I have just received an expired onion. This could be a replay attack.");
    return -1;
  }

  aci_type = decide_aci_type(conn->local.sin_addr.s_addr, conn->local.sin_port,
             ((onion_layer_t *)circ->onion)->addr,((onion_layer_t *)circ->onion)->port);
      
  if(circuit_init(circ, aci_type) < 0) { 
    log(LOG_ERR,"process_onion(): init_circuit() failed.");
    return -1;
  }

  /* check for replay */
  if(id_tracked_onion(circ->onion, circ->onionlen, tracked_onions)) {
    log(LOG_NOTICE,"process_onion(): I have just received a replayed onion. This could be a replay attack.");
    return -1;
  }

  /* track the new onion */
  if(!new_tracked_onion(circ->onion,circ->onionlen, &tracked_onions, &last_tracked_onion)) {
    log(LOG_DEBUG,"process_onion(): Onion tracking failed. Will ignore.");
  }

  return 0;
}

