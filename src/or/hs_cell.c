/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_cell.c
 * \brief Hidden service API for cell creation and handling.
 **/

#include "or.h"
#include "config.h"
#include "rendservice.h"
#include "replaycache.h"

#include "hs_cell.h"
#include "hs_ntor.h"

/* Trunnel. */
#include "ed25519_cert.h"
#include "hs/cell_common.h"
#include "hs/cell_establish_intro.h"
#include "hs/cell_introduce1.h"
#include "hs/cell_rendezvous.h"

/* Compute the MAC of an INTRODUCE cell in mac_out. The encoded_cell param is
 * the cell content up to the ENCRYPTED section of length encoded_cell_len.
 * The encrypted param is the start of the ENCRYPTED section of length
 * encrypted_len. The mac_key is the key needed for the computation of the MAC
 * derived from the ntor handshake of length mac_key_len.
 *
 * The length mac_out_len must be at least DIGEST256_LEN. */
static void
compute_introduce_mac(const uint8_t *encoded_cell, size_t encoded_cell_len,
                      const uint8_t *encrypted, size_t encrypted_len,
                      const uint8_t *mac_key, size_t mac_key_len,
                      uint8_t *mac_out, size_t mac_out_len)
{
  size_t offset = 0;
  size_t mac_msg_len;
  uint8_t mac_msg[RELAY_PAYLOAD_SIZE] = {0};

  tor_assert(encoded_cell);
  tor_assert(encrypted);
  tor_assert(mac_key);
  tor_assert(mac_out);
  tor_assert(mac_out_len >= DIGEST256_LEN);

  /* Compute the size of the message which is basically the entire cell until
   * the MAC field of course. */
  mac_msg_len = encoded_cell_len + (encrypted_len - DIGEST256_LEN);
  tor_assert(mac_msg_len <= sizeof(mac_msg));

  /* First, put the encoded cell in the msg. */
  memcpy(mac_msg, encoded_cell, encoded_cell_len);
  offset += encoded_cell_len;
  /* Second, put the CLIENT_PK + ENCRYPTED_DATA but ommit the MAC field (which
   * is junk at this point). */
  memcpy(mac_msg + offset, encrypted, (encrypted_len - DIGEST256_LEN));
  offset += (encrypted_len - DIGEST256_LEN);
  tor_assert(offset == mac_msg_len);

  crypto_mac_sha3_256(mac_out, mac_out_len,
                      mac_key, mac_key_len,
                      mac_msg, mac_msg_len);
  memwipe(mac_msg, 0, sizeof(mac_msg));
}

/* From a set of keys, subcredential and the ENCRYPTED section of an
 * INTRODUCE2 cell, return a newly allocated intro cell keys structure.
 * Finally, the client public key is copied in client_pk. On error, return
 * NULL. */
static hs_ntor_intro_cell_keys_t *
get_introduce2_key_material(const ed25519_public_key_t *auth_key,
                            const curve25519_keypair_t *enc_key,
                            const uint8_t *subcredential,
                            const uint8_t *encrypted_section,
                            curve25519_public_key_t *client_pk)
{
  hs_ntor_intro_cell_keys_t *keys;

  tor_assert(auth_key);
  tor_assert(enc_key);
  tor_assert(subcredential);
  tor_assert(encrypted_section);
  tor_assert(client_pk);

  keys = tor_malloc_zero(sizeof(*keys));

  /* First bytes of the ENCRYPTED section are the client public key. */
  memcpy(client_pk->public_key, encrypted_section, CURVE25519_PUBKEY_LEN);

  if (hs_ntor_service_get_introduce1_keys(auth_key, enc_key, client_pk,
                                          subcredential, keys) < 0) {
    /* Don't rely on the caller to wipe this on error. */
    memwipe(client_pk, 0, sizeof(curve25519_public_key_t));
    tor_free(keys);
    keys = NULL;
  }
  return keys;
}

/* Using the given encryption key, decrypt the encrypted_section of length
 * encrypted_section_len of an INTRODUCE2 cell and return a newly allocated
 * buffer containing the decrypted data. On decryption failure, NULL is
 * returned. */
static uint8_t *
decrypt_introduce2(const uint8_t *enc_key, const uint8_t *encrypted_section,
                   size_t encrypted_section_len)
{
  uint8_t *decrypted = NULL;
  crypto_cipher_t *cipher = NULL;

  tor_assert(enc_key);
  tor_assert(encrypted_section);

  /* Decrypt ENCRYPTED section. */
  cipher = crypto_cipher_new_with_bits((char *) enc_key,
                                       CURVE25519_PUBKEY_LEN * 8);
  tor_assert(cipher);

  /* This is symmetric encryption so can't be bigger than the encrypted
   * section length. */
  decrypted = tor_malloc_zero(encrypted_section_len);
  if (crypto_cipher_decrypt(cipher, (char *) decrypted,
                            (const char *) encrypted_section,
                            encrypted_section_len) < 0) {
    tor_free(decrypted);
    decrypted = NULL;
    goto done;
  }

 done:
  crypto_cipher_free(cipher);
  return decrypted;
}

/* Given a pointer to the decrypted data of the ENCRYPTED section of an
 * INTRODUCE2 cell of length decrypted_len, parse and validate the cell
 * content. Return a newly allocated cell structure or NULL on error. The
 * circuit and service object are only used for logging purposes. */
static trn_cell_introduce_encrypted_t *
parse_introduce2_encrypted(const uint8_t *decrypted_data,
                           size_t decrypted_len, const origin_circuit_t *circ,
                           const hs_service_t *service)
{
  trn_cell_introduce_encrypted_t *enc_cell = NULL;

  tor_assert(decrypted_data);
  tor_assert(circ);
  tor_assert(service);

  if (trn_cell_introduce_encrypted_parse(&enc_cell, decrypted_data,
                                         decrypted_len) < 0) {
    log_info(LD_REND, "Unable to parse the decrypted ENCRYPTED section of "
                      "the INTRODUCE2 cell on circuit %u for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto err;
  }

  if (trn_cell_introduce_encrypted_get_onion_key_type(enc_cell) !=
      HS_CELL_ONION_KEY_TYPE_NTOR) {
    log_info(LD_REND, "INTRODUCE2 onion key type is invalid. Got %u but "
                      "expected %u on circuit %u for service %s",
             trn_cell_introduce_encrypted_get_onion_key_type(enc_cell),
             HS_CELL_ONION_KEY_TYPE_NTOR, TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto err;
  }

  if (trn_cell_introduce_encrypted_getlen_onion_key(enc_cell) !=
      CURVE25519_PUBKEY_LEN) {
    log_info(LD_REND, "INTRODUCE2 onion key length is invalid. Got %ld but "
                      "expected %d on circuit %u for service %s",
             trn_cell_introduce_encrypted_getlen_onion_key(enc_cell),
             CURVE25519_PUBKEY_LEN, TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto err;
  }
  /* XXX: Validate NSPEC field as well. */

  return enc_cell;
 err:
  trn_cell_introduce_encrypted_free(enc_cell);
  return NULL;
}

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

/* Free the given cell pointer. If is_legacy_cell is set, cell_ptr is cast to
 * a rend_intro_cell_t else to a trn_cell_introduce1_t. */
static void
introduce2_free_cell(void *cell_ptr, unsigned int is_legacy_cell)
{
  if (cell_ptr == NULL) {
    return;
  }
  if (is_legacy_cell) {
    rend_intro_cell_t *legacy_cell = cell_ptr;
    rend_service_free_intro(legacy_cell);
  } else {
    trn_cell_introduce1_free((trn_cell_introduce1_t *) cell_ptr);
  }
}

/* Return the length of the encrypted section of the cell_ptr. If
 * is_legacy_cell is set, cell_ptr is cast to a rend_intro_cell_t else to a
 * trn_cell_introduce1_t. */
static size_t
get_introduce2_encrypted_section_len(const void *cell_ptr,
                                     unsigned int is_legacy_cell)
{
  tor_assert(cell_ptr);
  if (is_legacy_cell) {
    return ((const rend_intro_cell_t *) cell_ptr)->ciphertext_len;
  }
  return trn_cell_introduce1_getlen_encrypted(
                             (const trn_cell_introduce1_t *) cell_ptr);
}

/* Return the encrypted section pointer from the the cell_ptr. If
 * is_legacy_cell is set, cell_ptr is cast to a rend_intro_cell_t else to a
 * trn_cell_introduce1_t. */
static const uint8_t *
get_introduce2_encrypted_section(const void *cell_ptr,
                                 unsigned int is_legacy_cell)
{
  tor_assert(cell_ptr);
  if (is_legacy_cell) {
    return ((const rend_intro_cell_t *) cell_ptr)->ciphertext;
  }
  return trn_cell_introduce1_getconstarray_encrypted(
                             (const trn_cell_introduce1_t *) cell_ptr);
}

/* Parse an INTRODUCE2 cell from payload of size payload_len for the given
 * service and circuit which are used only for logging purposes. The resulting
 * parsed cell is put in cell_ptr_out. If is_legacy_cell is set, the type of
 * the returned cell is rend_intro_cell_t else trn_cell_introduce1_t.
 *
 * Return 0 on success else a negative value and cell_ptr_out is untouched. */
static int
parse_introduce2_cell(const hs_service_t *service,
                      const origin_circuit_t *circ, const uint8_t *payload,
                      size_t payload_len, unsigned int is_legacy_cell,
                      void **cell_ptr_out)
{
  tor_assert(service);
  tor_assert(circ);
  tor_assert(payload);
  tor_assert(cell_ptr_out);

  /* We parse the cell differently for legacy. */
  if (is_legacy_cell) {
    char *err_msg;
    rend_intro_cell_t *legacy_cell = NULL;

    legacy_cell = rend_service_begin_parse_intro(payload, payload_len, 2,
                                                 &err_msg);
    if (legacy_cell == NULL) {
      log_info(LD_REND, "Unable to parse legacy INTRODUCE2 cell on "
                        "circuit %u for service %s: %s",
               TO_CIRCUIT(circ)->n_circ_id, err_msg,
               safe_str_client(service->onion_address));
      tor_free(err_msg);
      goto err;
    }
    *cell_ptr_out = legacy_cell;
  } else {
    trn_cell_introduce1_t *cell = NULL;
    /* Parse the cell so we can start cell validation. */
    if (trn_cell_introduce1_parse(&cell, payload, payload_len) < 0) {
      log_info(LD_PROTOCOL, "Unable to parse INTRODUCE2 cell on circuit %u "
                            "for service %s",
               TO_CIRCUIT(circ)->n_circ_id,
               safe_str_client(service->onion_address));
      goto err;
    }
    *cell_ptr_out = cell;
  }

  /* On success, we must have set the cell pointer. */
  tor_assert(*cell_ptr_out);
  return 0;
 err:
  return -1;
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

/* Parse the INTRO_ESTABLISHED cell in the payload of size payload_len. If we
 * are successful at parsing it, return the length of the parsed cell else a
 * negative value on error. */
ssize_t
hs_cell_parse_intro_established(const uint8_t *payload, size_t payload_len)
{
  ssize_t ret;
  trn_cell_intro_established_t *cell = NULL;

  tor_assert(payload);

  /* Try to parse the payload into a cell making sure we do actually have a
   * valid cell. */
  ret = trn_cell_intro_established_parse(&cell, payload, payload_len);
  if (ret >= 0) {
    /* On success, we do not keep the cell, we just notify the caller that it
     * was successfully parsed. */
    trn_cell_intro_established_free(cell);
  }
  return ret;
}

/* Parsse the INTRODUCE2 cell using data which contains everything we need to
 * do so and contains the destination buffers of information we extract and
 * compute from the cell. Return 0 on success else a negative value. The
 * service and circ are only used for logging purposes. */
ssize_t
hs_cell_parse_introduce2(hs_cell_introduce2_data_t *data,
                         const origin_circuit_t *circ,
                         const hs_service_t *service)
{
  int ret = -1;
  time_t elapsed;
  uint8_t *decrypted = NULL;
  size_t encrypted_section_len;
  const uint8_t *encrypted_section;
  trn_cell_introduce_encrypted_t *enc_cell = NULL;
  hs_ntor_intro_cell_keys_t *intro_keys = NULL;
  void *cell_ptr = NULL;

  tor_assert(data);
  tor_assert(circ);
  tor_assert(service);

  /* Parse the cell into a decoded data structure pointed by cell_ptr. */
  if (parse_introduce2_cell(service, circ, data->payload, data->payload_len,
                            data->is_legacy, &cell_ptr) < 0) {
    goto done;
  }

  log_info(LD_REND, "Received a decodable INTRODUCE2 cell on circuit %u "
                    "for service %s. Decoding encrypted section...",
           TO_CIRCUIT(circ)->n_circ_id,
           safe_str_client(service->onion_address));

  encrypted_section =
    get_introduce2_encrypted_section(cell_ptr, data->is_legacy);
  encrypted_section_len =
    get_introduce2_encrypted_section_len(cell_ptr, data->is_legacy);

  /* Encrypted section must at least contain the CLIENT_PK and MAC which is
   * defined in section 3.3.2 of the specification. */
  if (encrypted_section_len < (CURVE25519_PUBKEY_LEN + DIGEST256_LEN)) {
    log_info(LD_REND, "Invalid INTRODUCE2 encrypted section length "
                      "for service %s. Dropping cell.",
             safe_str_client(service->onion_address));
    goto done;
  }

  /* Check our replay cache for this introduction point. */
  if (replaycache_add_test_and_elapsed(data->replay_cache, encrypted_section,
                                       encrypted_section_len, &elapsed)) {
    log_warn(LD_REND, "Possible replay detected! An INTRODUCE2 cell with the"
                      "same ENCRYPTED section was seen %ld seconds ago. "
                      "Dropping cell.", elapsed);
    goto done;
  }

  /* Build the key material out of the key material found in the cell. */
  intro_keys = get_introduce2_key_material(data->auth_pk, data->enc_kp,
                                           data->subcredential,
                                           encrypted_section,
                                           &data->client_pk);
  if (intro_keys == NULL) {
    log_info(LD_REND, "Invalid INTRODUCE2 encrypted data. Unable to "
                      "compute key material on circuit %u for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto done;
  }

  /* Validate MAC from the cell and our computed key material. The MAC field
   * in the cell is at the end of the encrypted section. */
  {
    uint8_t mac[DIGEST256_LEN];
    /* The MAC field is at the very end of the ENCRYPTED section. */
    size_t mac_offset = encrypted_section_len - sizeof(mac);
    /* Compute the MAC. Use the entire encoded payload with a length up to the
     * ENCRYPTED section. */
    compute_introduce_mac(data->payload,
                          data->payload_len - encrypted_section_len,
                          encrypted_section, encrypted_section_len,
                          intro_keys->mac_key, sizeof(intro_keys->mac_key),
                          mac, sizeof(mac));
    if (tor_memcmp(mac, encrypted_section + mac_offset, sizeof(mac))) {
      log_info(LD_REND, "Invalid MAC validation for INTRODUCE2 cell on "
                        "circuit %u for service %s",
               TO_CIRCUIT(circ)->n_circ_id,
               safe_str_client(service->onion_address));
      goto done;
    }
  }

  {
    /* The ENCRYPTED_DATA section starts just after the CLIENT_PK. */
    const uint8_t *encrypted_data =
      encrypted_section + sizeof(data->client_pk);
    /* It's symmetric encryption so it's correct to use the ENCRYPTED length
     * for decryption. Computes the length of ENCRYPTED_DATA meaning removing
     * the CLIENT_PK and MAC length. */
    size_t encrypted_data_len =
      encrypted_section_len - (sizeof(data->client_pk) + DIGEST256_LEN);

    /* This decrypts the ENCRYPTED_DATA section of the cell. */
    decrypted = decrypt_introduce2(intro_keys->enc_key,
                                   encrypted_data, encrypted_data_len);
    if (decrypted == NULL) {
      log_info(LD_REND, "Unable to decrypt the ENCRYPTED section of an "
                        "INTRODUCE2 cell on circuit %u for service %s",
               TO_CIRCUIT(circ)->n_circ_id,
               safe_str_client(service->onion_address));
      goto done;
    }

    /* Parse this blob into an encrypted cell structure so we can then extract
     * the data we need out of it. */
    enc_cell = parse_introduce2_encrypted(decrypted, encrypted_data_len,
                                          circ, service);
    memwipe(decrypted, 0, encrypted_data_len);
    if (enc_cell == NULL) {
      goto done;
    }
  }

  /* XXX: Implement client authorization checks. */

  /* Extract onion key and rendezvous cookie from the cell used for the
   * rendezvous point circuit e2e encryption. */
  memcpy(data->onion_pk.public_key,
         trn_cell_introduce_encrypted_getconstarray_onion_key(enc_cell),
         CURVE25519_PUBKEY_LEN);
  memcpy(data->rendezvous_cookie,
         trn_cell_introduce_encrypted_getconstarray_rend_cookie(enc_cell),
         sizeof(data->rendezvous_cookie));

  /* Extract rendezvous link specifiers. */
  for (size_t idx = 0;
       idx < trn_cell_introduce_encrypted_get_nspec(enc_cell); idx++) {
    link_specifier_t *lspec =
      trn_cell_introduce_encrypted_get_nspecs(enc_cell, idx);
    smartlist_add(data->link_specifiers, hs_link_specifier_dup(lspec));
  }

  /* Success. */
  ret = 0;
  log_info(LD_REND, "Valid INTRODUCE2 cell. Launching rendezvous circuit.");

 done:
  if (intro_keys) {
    memwipe(intro_keys, 0, sizeof(hs_ntor_intro_cell_keys_t));
    tor_free(intro_keys);
  }
  tor_free(decrypted);
  trn_cell_introduce_encrypted_free(enc_cell);
  introduce2_free_cell(cell_ptr, data->is_legacy);
  return ret;
}

/* Build a RENDEZVOUS1 cell with the given rendezvous cookie and handshake
 * info. The encoded cell is put in cell_out and the length of the data is
 * returned. This can't fail. */
ssize_t
hs_cell_build_rendezvous1(const uint8_t *rendezvous_cookie,
                          size_t rendezvous_cookie_len,
                          const uint8_t *rendezvous_handshake_info,
                          size_t rendezvous_handshake_info_len,
                          uint8_t *cell_out)
{
  ssize_t cell_len;
  trn_cell_rendezvous1_t *cell;

  tor_assert(rendezvous_cookie);
  tor_assert(rendezvous_handshake_info);
  tor_assert(cell_out);

  cell = trn_cell_rendezvous1_new();
  /* Set the RENDEZVOUS_COOKIE. */
  memcpy(trn_cell_rendezvous1_getarray_rendezvous_cookie(cell),
         rendezvous_cookie, rendezvous_cookie_len);
  /* Set the HANDSHAKE_INFO. */
  trn_cell_rendezvous1_setlen_handshake_info(cell,
                                            rendezvous_handshake_info_len);
  memcpy(trn_cell_rendezvous1_getarray_handshake_info(cell),
         rendezvous_handshake_info, rendezvous_handshake_info_len);
  /* Encoding. */
  cell_len = trn_cell_rendezvous1_encode(cell_out, RELAY_PAYLOAD_SIZE, cell);
  tor_assert(cell_len > 0);

  trn_cell_rendezvous1_free(cell);
  return cell_len;
}

