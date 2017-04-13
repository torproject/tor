/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation hidden service functionality
 **/

#include "or.h"
#include "relay.h"
#include "rendservice.h"
#include "circuitlist.h"
#include "circpathbias.h"

#include "hs_intropoint.h"
#include "hs_service.h"
#include "hs_common.h"

#include "hs/cell_establish_intro.h"
#include "hs/cell_common.h"

/* XXX We don't currently use these functions, apart from generating unittest
   data. When we start implementing the service-side support for prop224 we
   should revisit these functions and use them. */

/** Given an ESTABLISH_INTRO <b>cell</b>, encode it and place its payload in
 *  <b>buf_out</b> which has size <b>buf_out_len</b>. Return the number of
 *  bytes written, or a negative integer if there was an error. */
ssize_t
get_establish_intro_payload(uint8_t *buf_out, size_t buf_out_len,
                            const trn_cell_establish_intro_t *cell)
{
  ssize_t bytes_used = 0;

  if (buf_out_len < RELAY_PAYLOAD_SIZE) {
    return -1;
  }

  bytes_used = trn_cell_establish_intro_encode(buf_out, buf_out_len,
                                              cell);
  return bytes_used;
}

/* Set the cell extensions of <b>cell</b>. */
static void
set_trn_cell_extensions(trn_cell_establish_intro_t *cell)
{
  trn_cell_extension_t *trn_cell_extensions = trn_cell_extension_new();

  /* For now, we don't use extensions at all. */
  trn_cell_extensions->num = 0; /* It's already zeroed, but be explicit. */
  trn_cell_establish_intro_set_extensions(cell, trn_cell_extensions);
}

/** Given the circuit handshake info in <b>circuit_key_material</b>, create and
 *  return an ESTABLISH_INTRO cell. Return NULL if something went wrong.  The
 *  returned cell is allocated on the heap and it's the responsibility of the
 *  caller to free it. */
trn_cell_establish_intro_t *
generate_establish_intro_cell(const uint8_t *circuit_key_material,
                              size_t circuit_key_material_len)
{
  trn_cell_establish_intro_t *cell = NULL;
  ssize_t encoded_len;

  log_warn(LD_GENERAL,
           "Generating ESTABLISH_INTRO cell (key_material_len: %u)",
           (unsigned) circuit_key_material_len);

  /* Generate short-term keypair for use in ESTABLISH_INTRO */
  ed25519_keypair_t key_struct;
  if (ed25519_keypair_generate(&key_struct, 0) < 0) {
    goto err;
  }

  cell = trn_cell_establish_intro_new();

  /* Set AUTH_KEY_TYPE: 2 means ed25519 */
  trn_cell_establish_intro_set_auth_key_type(cell,
                                             HS_INTRO_AUTH_KEY_TYPE_ED25519);

  /* Set AUTH_KEY_LEN field */
  /* Must also set byte-length of AUTH_KEY to match */
  int auth_key_len = ED25519_PUBKEY_LEN;
  trn_cell_establish_intro_set_auth_key_len(cell, auth_key_len);
  trn_cell_establish_intro_setlen_auth_key(cell, auth_key_len);

  /* Set AUTH_KEY field */
  uint8_t *auth_key_ptr = trn_cell_establish_intro_getarray_auth_key(cell);
  memcpy(auth_key_ptr, key_struct.pubkey.pubkey, auth_key_len);

  /* No cell extensions needed */
  set_trn_cell_extensions(cell);

  /* Set signature size.
     We need to do this up here, because _encode() needs it and we need to call
     _encode() to calculate the MAC and signature.
  */
  int sig_len = ED25519_SIG_LEN;
  trn_cell_establish_intro_set_sig_len(cell, sig_len);
  trn_cell_establish_intro_setlen_sig(cell, sig_len);

  /* XXX How to make this process easier and nicer? */

  /* Calculate the cell MAC (aka HANDSHAKE_AUTH). */
  {
    /* To calculate HANDSHAKE_AUTH, we dump the cell in bytes, and then derive
       the MAC from it. */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    uint8_t mac[TRUNNEL_SHA3_256_LEN];

    encoded_len = trn_cell_establish_intro_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell.");
      goto err;
    }

    /* sanity check */
    tor_assert(encoded_len > ED25519_SIG_LEN + 2 + TRUNNEL_SHA3_256_LEN);

    /* Calculate MAC of all fields before HANDSHAKE_AUTH */
    crypto_mac_sha3_256(mac, sizeof(mac),
                        circuit_key_material, circuit_key_material_len,
                        cell_bytes_tmp,
                        encoded_len -
                          (ED25519_SIG_LEN + 2 + TRUNNEL_SHA3_256_LEN));
    /* Write the MAC to the cell */
    uint8_t *handshake_ptr =
      trn_cell_establish_intro_getarray_handshake_mac(cell);
    memcpy(handshake_ptr, mac, sizeof(mac));
  }

  /* Calculate the cell signature */
  {
    /* To calculate the sig we follow the same procedure as above. We first
       dump the cell up to the sig, and then calculate the sig */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    ed25519_signature_t sig;

    encoded_len = trn_cell_establish_intro_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell (2).");
      goto err;
    }

    tor_assert(encoded_len > ED25519_SIG_LEN);

    if (ed25519_sign_prefixed(&sig,
                              cell_bytes_tmp,
                              encoded_len -
                                (ED25519_SIG_LEN + sizeof(cell->sig_len)),
                              ESTABLISH_INTRO_SIG_PREFIX,
                              &key_struct)) {
      log_warn(LD_BUG, "Unable to gen signature for ESTABLISH_INTRO cell.");
      goto err;
    }

    /* And write the signature to the cell */
    uint8_t *sig_ptr = trn_cell_establish_intro_getarray_sig(cell);
    memcpy(sig_ptr, sig.sig, sig_len);
  }

  /* We are done! Return the cell! */
  return cell;

 err:
  trn_cell_establish_intro_free(cell);
  return NULL;
}

