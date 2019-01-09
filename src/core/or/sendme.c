/* Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file sendme.c
 * \brief Code that is related to SENDME cells both in terms of
 *        creating/parsing cells and handling the content.
 */

#include "core/or/or.h"

#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/relay.h"
#include "core/or/sendme.h"
#include "feature/nodelist/networkstatus.h"
#include "trunnel/sendme.h"

/* The cell version constants for when emitting a cell. */
#define SENDME_EMIT_MIN_VERSION_DEFAULT 0
#define SENDME_EMIT_MIN_VERSION_MIN 0
#define SENDME_EMIT_MIN_VERSION_MAX UINT8_MAX

/* The cell version constants for when accepting a cell. */
#define SENDME_ACCEPT_MIN_VERSION_DEFAULT 0
#define SENDME_ACCEPT_MIN_VERSION_MIN 0
#define SENDME_ACCEPT_MIN_VERSION_MAX UINT8_MAX

/* Return the minimum version given by the consensus (if any) that should be
 * used when emitting a SENDME cell. */
static int
get_emit_min_version(void)
{
  return networkstatus_get_param(NULL, "sendme_emit_min_version",
                                 SENDME_EMIT_MIN_VERSION_DEFAULT,
                                 SENDME_EMIT_MIN_VERSION_MIN,
                                 SENDME_EMIT_MIN_VERSION_MAX);
}

#if 0
/* Return the minimum version given by the consensus (if any) that should be
 * accepted when receiving a SENDME cell. */
static int
get_accept_min_version(void)
{
  return networkstatus_get_param(NULL, "sendme_accept_min_version",
                                 SENDME_ACCEPT_MIN_VERSION_DEFAULT,
                                 SENDME_ACCEPT_MIN_VERSION_MIN,
                                 SENDME_ACCEPT_MIN_VERSION_MAX);
}
#endif

/* Build and encode a version 1 SENDME cell into payload, which must be at
 * least of RELAY_PAYLOAD_SIZE bytes, using the digest for the cell data.
 *
 * Return the size in bytes of the encoded cell in payload. A negative value
 * is returned on encoding failure. */
static ssize_t
build_cell_payload_v1(crypto_digest_t *cell_digest, uint8_t *payload)
{
  ssize_t len = -1;
  sendme_cell_t *cell = NULL;
  sendme_data_v1_t *data = NULL;

  tor_assert(cell_digest);
  tor_assert(payload);

  cell = sendme_cell_new();
  data = sendme_data_v1_new();

  /* Building a payload for version 1. */
  sendme_cell_set_version(cell, 0x01);

  /* Copy the digest into the data payload. */
  crypto_digest_get_digest(cell_digest,
                           (char *) sendme_data_v1_getarray_digest(data),
                           sendme_data_v1_getlen_digest(data));

  /* Set the length of the data in the cell payload. It is the encoded length
   * of the v1 data object. */
  sendme_cell_setlen_data(cell, sendme_data_v1_encoded_len(data));
  /* Encode into the cell's data field using its current length just set. */
  if (sendme_data_v1_encode(sendme_cell_getarray_data(cell),
                            sendme_cell_getlen_data(cell), data) < 0) {
    goto end;
  }
  /* Set the DATA_LEN field to what we've just encoded. */
  sendme_cell_set_data_len(cell, sendme_cell_getlen_data(cell));

  /* Finally, encode the cell into the payload. */
  len = sendme_cell_encode(payload, RELAY_PAYLOAD_SIZE, cell);

 end:
  sendme_cell_free(cell);
  sendme_data_v1_free(data);
  return len;
}

/* Send a circuit-level SENDME on the given circuit using the layer_hint if
 * not NULL. The digest is only used for version 1.
 *
 * Return 0 on success else a negative value and the circuit will be closed
 * because we failed to send the cell on it. */
static int
send_circuit_level_sendme(circuit_t *circ, crypt_path_t *layer_hint,
                          crypto_digest_t *cell_digest)
{
  uint8_t emit_version;
  uint8_t payload[RELAY_PAYLOAD_SIZE];
  ssize_t payload_len;

  tor_assert(circ);
  tor_assert(cell_digest);

  emit_version = get_emit_min_version();
  switch (emit_version) {
  case 0x01:
    payload_len = build_cell_payload_v1(cell_digest, payload);
    if (BUG(payload_len < 0)) {
      /* Unable to encode the cell, abort. We can recover from this by closing
       * the circuit but in theory it should never happen. */
      return -1;
    }
    log_debug(LD_PROTOCOL, "Emitting SENDME version 1 cell.");
    break;
  case 0x00:
    /* Fallthrough because default is to use v0. */
  default:
    /* Unknown version, fallback to version 0 meaning no payload. */
    payload_len = 0;
    break;
  }

  if (relay_send_command_from_edge(0, circ, RELAY_COMMAND_SENDME,
                                   (char *) payload, payload_len,
                                   layer_hint) < 0) {
    log_warn(LD_CIRC,
             "SENDME relay_send_command_from_edge failed. Circuit's closed.");
    return -1; /* the circuit's closed, don't continue */
  }
  return 0;
}

/** Called when we've just received a relay data cell, when we've just
 * finished flushing all bytes to stream <b>conn</b>, or when we've flushed
 * *some* bytes to the stream <b>conn</b>.
 *
 * If conn->outbuf is not too full, and our deliver window is low, send back a
 * suitable number of stream-level sendme cells.
 */
void
sendme_connection_edge_consider_sending(edge_connection_t *conn)
{
  tor_assert(conn);

  int log_domain = TO_CONN(conn)->type == CONN_TYPE_AP ? LD_APP : LD_EXIT;

  /* Don't send it if we still have data to deliver. */
  if (connection_outbuf_too_full(TO_CONN(conn))) {
    goto end;
  }

  if (circuit_get_by_edge_conn(conn) == NULL) {
    /* This can legitimately happen if the destroy has already arrived and
     * torn down the circuit. */
    log_info(log_domain, "No circuit associated with edge connection. "
                         "Skipping sending SENDME.");
    goto end;
  }

  while (conn->deliver_window <=
         (STREAMWINDOW_START - STREAMWINDOW_INCREMENT)) {
    log_debug(log_domain, "Outbuf %lu, queuing stream SENDME.",
              TO_CONN(conn)->outbuf_flushlen);
    conn->deliver_window += STREAMWINDOW_INCREMENT;
    if (connection_edge_send_command(conn, RELAY_COMMAND_SENDME,
                                     NULL, 0) < 0) {
      log_warn(LD_APP, "connection_edge_send_command failed while sending "
                       "a SENDME. Circuit probably closed, skipping.");
      goto end; /* The circuit's closed, don't continue */
    }
  }

 end:
  return;
}

/** Check if the deliver_window for circuit <b>circ</b> (at hop
 * <b>layer_hint</b> if it's defined) is low enough that we should
 * send a circuit-level sendme back down the circuit. If so, send
 * enough sendmes that the window would be overfull if we sent any
 * more.
 */
void
sendme_circuit_consider_sending(circuit_t *circ, crypt_path_t *layer_hint,
                                crypto_digest_t *digest)
{
  tor_assert(digest);

  while ((layer_hint ? layer_hint->deliver_window : circ->deliver_window) <=
          CIRCWINDOW_START - CIRCWINDOW_INCREMENT) {
    log_debug(LD_CIRC,"Queuing circuit sendme.");
    if (layer_hint)
      layer_hint->deliver_window += CIRCWINDOW_INCREMENT;
    else
      circ->deliver_window += CIRCWINDOW_INCREMENT;
    if (send_circuit_level_sendme(circ, layer_hint, digest) < 0) {
      return; /* The circuit's closed, don't continue */
    }
  }
}

/* Process a circuit-level SENDME cell that we just received. The layer_hint,
 * if not NULL, is the Exit hop of the connection which means that we are a
 * client. In that case, circ must be an origin circuit. The cell_body_len is
 * the length of the SENDME cell payload (excluding the header).
 *
 * Return 0 on success that is the SENDME is valid and the package window has
 * been updated properly.
 *
 * On error, a negative value is returned which indicate that the circuit must
 * be closed using the value as the reason for it. */
int
sendme_process_circuit_level(crypt_path_t *layer_hint,
                             circuit_t *circ, uint16_t cell_body_len)
{
  tor_assert(circ);

  /* If we are the origin of the circuit, we are the Client so we use the
   * layer hint (the Exit hop) for the package window tracking. */
  if (CIRCUIT_IS_ORIGIN(circ)) {
    if ((layer_hint->package_window + CIRCWINDOW_INCREMENT) >
        CIRCWINDOW_START_MAX) {
      static struct ratelim_t exit_warn_ratelim = RATELIM_INIT(600);
      log_fn_ratelim(&exit_warn_ratelim, LOG_WARN, LD_PROTOCOL,
                     "Unexpected sendme cell from exit relay. "
                     "Closing circ.");
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    layer_hint->package_window += CIRCWINDOW_INCREMENT;
    log_debug(LD_APP, "circ-level sendme at origin, packagewindow %d.",
              layer_hint->package_window);

    /* We count circuit-level sendme's as valid delivered data because they
     * are rate limited. */
    circuit_read_valid_data(TO_ORIGIN_CIRCUIT(circ), cell_body_len);
  } else {
    /* We aren't the origin of this circuit so we are the Exit and thus we
     * track the package window with the circuit object. */
    if ((circ->package_window + CIRCWINDOW_INCREMENT) >
        CIRCWINDOW_START_MAX) {
      static struct ratelim_t client_warn_ratelim = RATELIM_INIT(600);
      log_fn_ratelim(&client_warn_ratelim, LOG_PROTOCOL_WARN, LD_PROTOCOL,
                     "Unexpected sendme cell from client. "
                     "Closing circ (window %d).", circ->package_window);
      return -END_CIRC_REASON_TORPROTOCOL;
    }
    circ->package_window += CIRCWINDOW_INCREMENT;
    log_debug(LD_EXIT, "circ-level sendme at non-origin, packagewindow %d.",
              circ->package_window);
  }

  return 0;
}

/* Process a stream-level SENDME cell that we just received. The conn is the
 * edge connection (stream) that the circuit circ is associated with. The
 * cell_body_len is the length of the payload (excluding the header).
 *
 * Return 0 on success that is the SENDME is valid and the package window has
 * been updated properly.
 *
 * On error, a negative value is returned which indicate that the circuit must
 * be closed using the value as the reason for it. */
int
sendme_process_stream_level(edge_connection_t *conn, circuit_t *circ,
                            uint16_t cell_body_len)
{
  tor_assert(conn);
  tor_assert(circ);

  /* Don't allow the other endpoint to request more than our maximum (i.e.
   * initial) stream SENDME window worth of data. Well-behaved stock clients
   * will not request more than this max (as per the check in the while loop
   * of sendme_connection_edge_consider_sending()). */
  if ((conn->package_window + STREAMWINDOW_INCREMENT) >
      STREAMWINDOW_START_MAX) {
    static struct ratelim_t stream_warn_ratelim = RATELIM_INIT(600);
    log_fn_ratelim(&stream_warn_ratelim, LOG_PROTOCOL_WARN, LD_PROTOCOL,
                   "Unexpected stream sendme cell. Closing circ (window %d).",
                   conn->package_window);
    return -END_CIRC_REASON_TORPROTOCOL;
  }
  /* At this point, the stream sendme is valid */
  conn->package_window += STREAMWINDOW_INCREMENT;

  /* We count circuit-level sendme's as valid delivered data because they are
   * rate limited. */
  if (CIRCUIT_IS_ORIGIN(circ)) {
    circuit_read_valid_data(TO_ORIGIN_CIRCUIT(circ), cell_body_len);
  }

  log_debug(CIRCUIT_IS_ORIGIN(circ) ? LD_APP : LD_EXIT,
            "stream-level sendme, package_window now %d.",
            conn->package_window);
  return 0;
}

/* Called when a relay DATA cell is received on the given circuit. If
 * layer_hint is NULL, this means we are the Exit end point else we are the
 * Client. Update the deliver window and return its new value. */
int
sendme_circuit_data_received(circuit_t *circ, crypt_path_t *layer_hint)
{
  int deliver_window, domain;

  if (CIRCUIT_IS_ORIGIN(circ)) {
    tor_assert(layer_hint);
    --layer_hint->deliver_window;
    deliver_window = layer_hint->deliver_window;
    domain = LD_APP;
  } else {
    tor_assert(!layer_hint);
    --circ->deliver_window;
    deliver_window = circ->deliver_window;
    domain = LD_EXIT;
  }

  log_debug(domain, "Circuit deliver_window now %d.", deliver_window);
  return deliver_window;
}

/* Called when a relay DATA cell is received for the given edge connection
 * conn. Update the deliver window and return its new value. */
int
sendme_stream_data_received(edge_connection_t *conn)
{
  tor_assert(conn);
  return --conn->deliver_window;
}

/* Called when a relay DATA cell is packaged on the given circuit. If
 * layer_hint is NULL, this means we are the Exit end point else we are the
 * Client. Update the package window and return its new value. */
int
sendme_circuit_data_packaged(circuit_t *circ, crypt_path_t *layer_hint)
{
  int package_window, domain;

  tor_assert(circ);

  if (CIRCUIT_IS_ORIGIN(circ)) {
    /* Client side. */
    tor_assert(layer_hint);
    --layer_hint->package_window;
    package_window = layer_hint->package_window;
    domain = LD_APP;
  } else {
    /* Exit side. */
    tor_assert(!layer_hint);
    --circ->package_window;
    package_window = circ->package_window;
    domain = LD_EXIT;
  }

  log_debug(domain, "Circuit package_window now %d.", package_window);
  return package_window;
}

/* Called when a relay DATA cell is packaged for the given edge connection
 * conn. Update the package window and return its new value. */
int
sendme_stream_data_packaged(edge_connection_t *conn)
{
  tor_assert(conn);
  return --conn->package_window;
}
