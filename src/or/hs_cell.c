/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_cell.c
 * \brief Hidden service API for cell creation and handling.
 **/

#include "or.h"
#include "rendservice.h"

#include "hs_cell.h"

/* Trunnel. */
#include "hs/cell_common.h"
#include "hs/cell_establish_intro.h"

/* Build a legacy ESTABLISH_INTRO cell with the given circuit nonce and RSA
 * encryption key. The encoded cell is put in cell_out that MUST at least be
 * of the size of RELAY_PAYLOAD_SIZE. Return the encoded cell length on
 * success else a negative value and cell_out is untouched. */
static ssize_t
build_legacy_establish_intro(const char *circ_nonce, crypto_pk_t *enc_key,
                             uint8_t *cell_out)
{
  ssize_t cell_len;
  char buf[RELAY_PAYLOAD_SIZE] = {0};

  tor_assert(circ_nonce);
  tor_assert(enc_key);
  tor_assert(cell_out);

  cell_len = rend_service_encode_establish_intro_cell(buf, sizeof(buf),
                                                      enc_key, circ_nonce);
  tor_assert(cell_len <= RELAY_PAYLOAD_SIZE);
  if (cell_len >= 0) {
    memcpy(cell_out, buf, cell_len);
  }
  return cell_len;
}

/* ========== */
/* Public API */
/* ========== */

/* Build an ESTABLISH_INTRO cell with the given circuit nonce and intro point
 * object. The encoded cell is put in cell_out that MUST at least be of the
 * size of RELAY_PAYLOAD_SIZE. Return the encoded cell length on success else
 * a negative value and cell_out is untouched. This function also supports
 * legacy cell creation. */
ssize_t
hs_cell_build_establish_intro(const char *circ_nonce,
                              const hs_service_intro_point_t *ip,
                              uint8_t *cell_out)
{
  ssize_t cell_len = -1;
  uint16_t sig_len = ED25519_SIG_LEN;
  trn_cell_extension_t *ext;
  trn_cell_establish_intro_t *cell = NULL;

  tor_assert(circ_nonce);
  tor_assert(ip);

  /* Quickly handle the legacy IP. */
  if (ip->base.is_only_legacy) {
    tor_assert(ip->legacy_key);
    cell_len = build_legacy_establish_intro(circ_nonce, ip->legacy_key,
                                            cell_out);
    tor_assert(cell_len <= RELAY_PAYLOAD_SIZE);
    /* Success or not we are done here. */
    goto done;
  }

  /* Set extension data. None used here. */
  ext = trn_cell_extension_new();
  trn_cell_extension_set_num(ext, 0);
  cell = trn_cell_establish_intro_new();
  trn_cell_establish_intro_set_extensions(cell, ext);
  /* Set signature size. Array is then allocated in the cell. We need to do
   * this early so we can use trunnel API to get the signature length. */
  trn_cell_establish_intro_set_sig_len(cell, sig_len);
  trn_cell_establish_intro_setlen_sig(cell, sig_len);

  /* Set AUTH_KEY_TYPE: 2 means ed25519 */
  trn_cell_establish_intro_set_auth_key_type(cell,
                                             HS_INTRO_AUTH_KEY_TYPE_ED25519);

  /* Set AUTH_KEY and AUTH_KEY_LEN field. Must also set byte-length of
   * AUTH_KEY to match */
  {
    uint16_t auth_key_len = ED25519_PUBKEY_LEN;
    trn_cell_establish_intro_set_auth_key_len(cell, auth_key_len);
    trn_cell_establish_intro_setlen_auth_key(cell, auth_key_len);
    /* We do this call _after_ setting the length because it's reallocated at
     * that point only. */
    uint8_t *auth_key_ptr = trn_cell_establish_intro_getarray_auth_key(cell);
    memcpy(auth_key_ptr, ip->auth_key_kp.pubkey.pubkey, auth_key_len);
  }

  /* Calculate HANDSHAKE_AUTH field (MAC). */
  {
    ssize_t tmp_cell_enc_len = 0;
    ssize_t tmp_cell_mac_offset =
      sig_len + sizeof(cell->sig_len) +
      trn_cell_establish_intro_getlen_handshake_mac(cell);
    uint8_t tmp_cell_enc[RELAY_PAYLOAD_SIZE] = {0};
    uint8_t mac[TRUNNEL_SHA3_256_LEN], *handshake_ptr;

    /* We first encode the current fields we have in the cell so we can
     * compute the MAC using the raw bytes. */
    tmp_cell_enc_len = trn_cell_establish_intro_encode(tmp_cell_enc,
                                                       sizeof(tmp_cell_enc),
                                                       cell);
    if (BUG(tmp_cell_enc_len < 0)) {
      goto done;
    }
    /* Sanity check. */
    tor_assert(tmp_cell_enc_len > tmp_cell_mac_offset);

    /* Circuit nonce is always DIGEST_LEN according to tor-spec.txt. */
    crypto_mac_sha3_256(mac, sizeof(mac),
                        (uint8_t *) circ_nonce, DIGEST_LEN,
                        tmp_cell_enc, tmp_cell_enc_len - tmp_cell_mac_offset);
    handshake_ptr = trn_cell_establish_intro_getarray_handshake_mac(cell);
    memcpy(handshake_ptr, mac, sizeof(mac));
  }

  /* Calculate the cell signature SIG. */
  {
    ssize_t tmp_cell_enc_len = 0;
    ssize_t tmp_cell_sig_offset = (sig_len + sizeof(cell->sig_len));
    uint8_t tmp_cell_enc[RELAY_PAYLOAD_SIZE] = {0}, *sig_ptr;
    ed25519_signature_t sig;

    /* We first encode the current fields we have in the cell so we can
     * compute the signature from the raw bytes of the cell. */
    tmp_cell_enc_len = trn_cell_establish_intro_encode(tmp_cell_enc,
                                                       sizeof(tmp_cell_enc),
                                                       cell);
    if (BUG(tmp_cell_enc_len < 0)) {
      goto done;
    }

    if (ed25519_sign_prefixed(&sig, tmp_cell_enc,
                              tmp_cell_enc_len - tmp_cell_sig_offset,
                              ESTABLISH_INTRO_SIG_PREFIX, &ip->auth_key_kp)) {
      log_warn(LD_BUG, "Unable to make signature for ESTABLISH_INTRO cell.");
      goto done;
    }
    /* Copy the signature into the cell. */
    sig_ptr = trn_cell_establish_intro_getarray_sig(cell);
    memcpy(sig_ptr, sig.sig, sig_len);
  }

  /* Encode the cell. Can't be bigger than a standard cell. */
  cell_len = trn_cell_establish_intro_encode(cell_out, RELAY_PAYLOAD_SIZE,
                                             cell);

 done:
  trn_cell_establish_intro_free(cell);
  return cell_len;
}

