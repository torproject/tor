
#include "or.h"

int check_sane_cell(cell_t *cell) {

  if(!cell)
    return -1;

  if(cell->aci == 0) {
    log(LOG_DEBUG,"check_sane_cell(): Cell has aci=0. Dropping.");
    return -1;
  }

#if 0 /* actually, the length is sometimes encrypted. so it's ok. */
  if(cell->length > 120) {
    log(LOG_DEBUG,"check_sane_cell(): Cell claims to have payload length %d. Dropping.",cell->length);
    return -1;
  }
#endif

  return 0; /* looks good */
}

