/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/* TOR_CHANNEL_INTERNAL_ define needed for an O(1) implementation of
 * channelpadding_channel_to_channelinfo() */
#define TOR_CHANNEL_INTERNAL_

#include "or.h"
#include "channel.h"
#include "channelpadding.h"
#include "channeltls.h"
#include "config.h"
#include "networkstatus.h"
#include "connection.h"
#include "connection_or.h"
#include "main.h"
#include "rephist.h"
#include "router.h"
#include "compat_time.h"
#include <event.h>

STATIC int channelpadding_get_netflow_inactive_timeout_ms(const channel_t *);
STATIC int channelpadding_send_disable_command(channel_t *);
STATIC int64_t channelpadding_compute_time_until_pad_for_netflow(channel_t *);

/** The total number of pending channelpadding timers */
static uint64_t total_timers_pending;

/**
 * Get a random netflow inactive timeout keepalive period in milliseconds,
 * the range for which is determined by consensus parameters, negotiation,
 * configuration, or default values. The consensus parameters enforce the
 * minimum possible value, to avoid excessively frequent padding.
 *
 * The ranges for this value were chosen to be low enough to ensure that
 * routers do not emit a new netflow record for a connection due to it
 * being idle.
 *
 * Specific timeout values for major routers are listed in Proposal 251.
 * No major router appeared capable of setting an inactive timeout below 10
 * seconds, so we set the defaults below that value, since we can always
 * scale back if it ends up being too much padding.
 *
 * Returns the next timeout period (in milliseconds) after which we should
 * send a padding packet, or 0 if padding is disabled.
 */
#define DFLT_NETFLOW_INACTIVE_KEEPALIVE_LOW 1500
#define DFLT_NETFLOW_INACTIVE_KEEPALIVE_HIGH 9500
#define DFLT_NETFLOW_INACTIVE_KEEPALIVE_MIN 0
#define DFLT_NETFLOW_INACTIVE_KEEPALIVE_MAX 60000
STATIC int
channelpadding_get_netflow_inactive_timeout_ms(const channel_t *chan)
{
  int low_timeout = networkstatus_get_param(NULL, "nf_ito_low",
      DFLT_NETFLOW_INACTIVE_KEEPALIVE_LOW,
      DFLT_NETFLOW_INACTIVE_KEEPALIVE_MIN,
      DFLT_NETFLOW_INACTIVE_KEEPALIVE_MAX);
  int high_timeout = networkstatus_get_param(NULL, "nf_ito_high",
      DFLT_NETFLOW_INACTIVE_KEEPALIVE_HIGH,
      low_timeout,
      DFLT_NETFLOW_INACTIVE_KEEPALIVE_MAX);
  int X1, X2;

  if (low_timeout == 0 && low_timeout == high_timeout)
    return 0; // No padding

  /* If we have negotiated different timeout values, use those, but
   * don't allow them to be lower than the consensus ones */
  if (chan->padding_timeout_low_ms && chan->padding_timeout_high_ms) {
    low_timeout = MAX(low_timeout, chan->padding_timeout_low_ms);
    high_timeout = MAX(high_timeout, chan->padding_timeout_high_ms);
  }

  if (low_timeout == high_timeout)
    return low_timeout; // No randomization

  /*
   * This MAX() hack is here because we apply the timeout on both the client
   * and the server. This creates the situation where the total time before
   * sending a packet in either direction is actually
   * min(client_timeout,server_timeout).
   *
   * If X is a random variable uniform from 0..R-1 (where R=high-low),
   * then Y=max(X,X) has Prob(Y == i) = (2.0*i + 1)/(R*R).
   *
   * If we create a third random variable Z=min(Y,Y), then it turns out that
   * Exp[Z] ~= Exp[X]. Here's a table:
   *
   *    R     Exp[X]    Exp[Z]    Exp[min(X,X)]   Exp[max(X,X)]
   *  2000     999.5    1066        666.2           1332.8
   *  3000    1499.5    1599.5      999.5           1999.5
   *  5000    2499.5    2666       1666.2           3332.8
   *  6000    2999.5    3199.5     1999.5           3999.5
   *  7000    3499.5    3732.8     2332.8           4666.2
   *  8000    3999.5    4266.2     2666.2           5332.8
   *  10000   4999.5    5328       3332.8           6666.2
   *  15000   7499.5    7995       4999.5           9999.5
   *  20000   9900.5    10661      6666.2           13332.8
   *
   * In other words, this hack makes it so that when both the client and
   * the guard are sending this padding, then the averages work out closer
   * to the midpoint of the range, making the overhead easier to tune.
   * If only one endpoint is padding (for example: if the relay does not
   * support padding, but the client has set ConnectionPadding 1; or
   * if the relay does support padding, but the client has set
   * ReducedConnectionPadding 1), then the defense will still prevent
   * record splitting, but with less overhead than the midpoint
   * (as seen by the Exp[max(X,X)] column).
   *
   * To calculate average padding packet frequency (and thus overhead),
   * index into the table by picking a row based on R = high-low. Then,
   * use the appropriate column (Exp[Z] for two-sided padding, and
   * Exp[max(X,X)] for one-sided padding). Finally, take this value
   * and add it to the low timeout value. This value is the average
   * frequency which padding packets will be sent.
   */

  X1 = crypto_rand_int(high_timeout - low_timeout);
  X2 = crypto_rand_int(high_timeout - low_timeout);
  return low_timeout + MAX(X1, X2);
}

/**
 * Update this channel's padding settings based on the PADDING_NEGOTIATE
 * contents.
 *
 * Returns -1 on error; 1 on success.
 */
int
channelpadding_update_padding_for_channel(channel_t *chan,
                const channelpadding_negotiate_t *pad_vars)
{
  if (pad_vars->version != 0) {
    static ratelim_t version_limit = RATELIM_INIT(600);

    log_fn_ratelim(&version_limit,LOG_PROTOCOL_WARN,LD_PROTOCOL,
           "Got a PADDING_NEGOTIATE cell with an unknown version. Ignoring.");
    return -1;
  }

  // We should not allow malicious relays to disable or reduce padding for
  // us as clients. In fact, we should only accept this cell at all if we're
  // operating as a relay. Brides should not accept it from relays, either
  // (only from their clients).
  if ((get_options()->BridgeRelay &&
        connection_or_digest_is_known_relay(chan->identity_digest)) ||
      !get_options()->ORPort_set) {
    static ratelim_t relay_limit = RATELIM_INIT(600);

    log_fn_ratelim(&relay_limit,LOG_PROTOCOL_WARN,LD_PROTOCOL,
           "Got a PADDING_NEGOTIATE from relay at %s (%s). "
           "This should not happen.",
           chan->get_remote_descr(chan, 0),
           hex_str(chan->identity_digest, DIGEST_LEN));
    return -1;
  }

  chan->padding_enabled = (pad_vars->command == CHANNELPADDING_COMMAND_START);

  /* Min must not be lower than the current consensus parameter
     nf_ito_low. */
  chan->padding_timeout_low_ms = MAX(networkstatus_get_param(NULL,
              "nf_ito_low",
              DFLT_NETFLOW_INACTIVE_KEEPALIVE_LOW,
              DFLT_NETFLOW_INACTIVE_KEEPALIVE_MIN,
              DFLT_NETFLOW_INACTIVE_KEEPALIVE_MAX),
          pad_vars->ito_low_ms);

  /* Max must not be lower than ito_low_ms */
  chan->padding_timeout_high_ms = MAX(chan->padding_timeout_low_ms,
                                   pad_vars->ito_high_ms);

  log_fn(LOG_INFO,LD_OR,
         "Negotiated padding=%d, lo=%d, hi=%d on "U64_FORMAT,
         chan->padding_enabled, chan->padding_timeout_low_ms,
         chan->padding_timeout_high_ms,
         U64_PRINTF_ARG(chan->global_identifier));

  return 1;
}

/**
 * Sends a CELL_PADDING_NEGOTIATE on the channel to tell the other side not
 * to send padding.
 *
 * Returns -1 on error, 0 on success.
 */
STATIC int
channelpadding_send_disable_command(channel_t *chan)
{
  channelpadding_negotiate_t disable;
  cell_t cell;

  tor_assert(BASE_CHAN_TO_TLS(chan)->conn->link_proto >=
             MIN_LINK_PROTO_FOR_CHANNEL_PADDING);

  memset(&cell, 0, sizeof(cell_t));
  memset(&disable, 0, sizeof(channelpadding_negotiate_t));
  cell.command = CELL_PADDING_NEGOTIATE;

  channelpadding_negotiate_set_command(&disable, CHANNELPADDING_COMMAND_STOP);

  if (channelpadding_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE,
        &disable) < 0)
    return -1;

  if (chan->write_cell(chan, &cell) == 1)
    return 0;
  else
    return -1;
}

/**
 * Sends a CELL_PADDING_NEGOTIATE on the channel to tell the other side to
 * resume sending padding at some rate.
 *
 * Returns -1 on error, 0 on success.
 */
int
channelpadding_send_enable_command(channel_t *chan, uint16_t low_timeout,
                                   uint16_t high_timeout)
{
  channelpadding_negotiate_t enable;
  cell_t cell;

  tor_assert(BASE_CHAN_TO_TLS(chan)->conn->link_proto >=
             MIN_LINK_PROTO_FOR_CHANNEL_PADDING);

  memset(&cell, 0, sizeof(cell_t));
  memset(&enable, 0, sizeof(channelpadding_negotiate_t));
  cell.command = CELL_PADDING_NEGOTIATE;

  channelpadding_negotiate_set_command(&enable, CHANNELPADDING_COMMAND_START);
  channelpadding_negotiate_set_ito_low_ms(&enable, low_timeout);
  channelpadding_negotiate_set_ito_high_ms(&enable, high_timeout);

  if (channelpadding_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE,
        &enable) < 0)
    return -1;

  if (chan->write_cell(chan, &cell) == 1)
    return 0;
  else
    return -1;
}

/**
 * Sends a CELL_PADDING cell on a channel if it has been idle since
 * our callback was scheduled.
 *
 * This function also clears the pending padding timer and the callback
 * flags.
 */
static void
channelpadding_send_padding_cell_for_callback(channel_t *chan)
{
  cell_t cell;

  /* Check that the channel is still valid and open */
  if (!chan || chan->state != CHANNEL_STATE_OPEN) {
    if (chan) chan->pending_padding_callback = 0;
    log_fn(LOG_INFO,LD_OR,
           "Scheduled a netflow padding cell, but connection already closed.");
    return;
  }

  /* We should have a pending callback flag set. */
  if (BUG(chan->pending_padding_callback == 0))
    return;

  chan->pending_padding_callback = 0;

  if (!chan->next_padding_time_ms ||
      chan->has_queued_writes(chan)) {
    /* We must have been active before the timer fired */
    chan->next_padding_time_ms = 0;
    return;
  }

  {
    uint64_t now = monotime_coarse_absolute_msec();

    log_fn(LOG_INFO,LD_OR,
        "Sending netflow keepalive on "U64_FORMAT" to %s (%s) after "
        I64_FORMAT" ms. Delta "I64_FORMAT"ms",
        U64_PRINTF_ARG(chan->global_identifier),
        safe_str_client(chan->get_remote_descr(chan, 0)),
        safe_str_client(hex_str(chan->identity_digest, DIGEST_LEN)),
        U64_PRINTF_ARG(now - chan->timestamp_xfer_ms),
        U64_PRINTF_ARG(now - chan->next_padding_time_ms));
  }

  /* Clear the timer */
  chan->next_padding_time_ms = 0;

  /* Send the padding cell. This will cause the channel to get a
   * fresh timestamp_active */
  memset(&cell, 0, sizeof(cell));
  cell.command = CELL_PADDING;
  chan->write_cell(chan, &cell);
}

/**
 * tor_timer callback function for us to send padding on an idle channel.
 *
 * This function just obtains the channel from the callback handle, ensures
 * it is still valid, and then hands it off to
 * channelpadding_send_padding_cell_for_callback(), which checks if
 * the channel is still idle before sending padding.
 */
static void
channelpadding_send_padding_callback(tor_timer_t *timer, void *args,
                                     const struct monotime_t *time)
{
  channel_t *chan = channel_handle_get((struct channel_handle_t*)args);
  (void)timer; (void)time;

  if (chan && CHANNEL_CAN_HANDLE_CELLS(chan)) {
    /* Hrmm.. It might be nice to have an equivalent to assert_connection_ok
     * for channels. Then we could get rid of the channeltls dependency */
    tor_assert(BASE_CHAN_TO_TLS(chan)->conn->base_.magic ==
               OR_CONNECTION_MAGIC);
    assert_connection_ok(&BASE_CHAN_TO_TLS(chan)->conn->base_, approx_time());

    channelpadding_send_padding_cell_for_callback(chan);
  } else {
     log_fn(LOG_INFO,LD_OR,
            "Channel closed while waiting for timer.");
  }

  total_timers_pending--;
}

/**
 * Schedules a callback to send padding on a channel in_ms milliseconds from
 * now.
 *
 * Returns CHANNELPADDING_WONTPAD on error, CHANNELPADDING_PADDING_SENT if we
 * sent the packet immediately without a timer, and
 * CHANNELPADDING_PADDING_SCHEDULED if we decided to schedule a timer.
 */
static channelpadding_decision_t
channelpadding_schedule_padding(channel_t *chan, int in_ms)
{
  struct timeval timeout;
  tor_assert(!chan->pending_padding_callback);

  if (in_ms <= 0) {
    chan->pending_padding_callback = 1;
    channelpadding_send_padding_cell_for_callback(chan);
    return CHANNELPADDING_PADDING_SENT;
  }

  timeout.tv_sec = in_ms/1000;
  timeout.tv_usec = (in_ms%1000)*1000;

  if (!chan->timer_handle) {
    chan->timer_handle = channel_handle_new(chan);
  }

  if (chan->padding_timer) {
    timer_set_cb(chan->padding_timer,
                 channelpadding_send_padding_callback,
                 chan->timer_handle);
  } else {
    chan->padding_timer = timer_new(channelpadding_send_padding_callback,
                                    chan->timer_handle);
  }
  timer_schedule(chan->padding_timer, &timeout);

  rep_hist_padding_count_timers(++total_timers_pending);

  chan->pending_padding_callback = 1;
  return CHANNELPADDING_PADDING_SCHEDULED;
}

/**
 * Calculates the number of milliseconds from now to schedule a padding cell.
 *
 * Returns the number of milliseconds from now (relative) to schedule the
 * padding callback. If the padding timer is more than 1.1 seconds in the
 * future, we return -1, to avoid scheduling excessive callbacks. If padding
 * is disabled in the consensus, we return -2.
 *
 * Side-effects: Updates chan->next_padding_time_ms, storing an (absolute, not
 * relative) millisecond representation of when we should send padding, unless
 * other activity happens first. This side-effect allows us to avoid
 * scheduling a libevent callback until we're within 1.1 seconds of the padding
 * time.
 */
#define CHANNELPADDING_TIME_LATER -1
#define CHANNELPADDING_TIME_DISABLED -2
STATIC int64_t
channelpadding_compute_time_until_pad_for_netflow(channel_t *chan)
{
  uint64_t long_now = monotime_coarse_absolute_msec();

  if (!chan->next_padding_time_ms) {
    int64_t padding_timeout =
        channelpadding_get_netflow_inactive_timeout_ms(chan);

    if (!padding_timeout)
      return CHANNELPADDING_TIME_DISABLED;

    chan->next_padding_time_ms = padding_timeout
        + chan->timestamp_xfer_ms;
  }

  /* If the next padding time is beyond the maximum possible consensus value,
   * then this indicates a clock jump, so just send padding now. This is
   * better than using monotonic time because we want to avoid the situation
   * where we wait around forever for monotonic time to move forward after
   * a clock jump far into the past.
   */
  if (chan->next_padding_time_ms > long_now +
      DFLT_NETFLOW_INACTIVE_KEEPALIVE_MAX) {
    tor_fragile_assert();
    log_warn(LD_BUG,
        "Channel padding timeout scheduled "I64_FORMAT"ms in the future. "
        "Did the monotonic clock just jump?",
        I64_PRINTF_ARG(chan->next_padding_time_ms - long_now));
    return 0; /* Clock jumped: Send padding now */
  }

  /* If the timeout will expire before the next time we're called (1000ms
     from now, plus some slack), then calcualte the number of milliseconds
     from now which we should send padding, so we can schedule a callback
     then.
   */
  if (long_now + 1100 >= chan->next_padding_time_ms) {
    int64_t ms_until_pad_for_netflow = chan->next_padding_time_ms -
                                       long_now;
    if (ms_until_pad_for_netflow < 0) {
      log_warn(LD_BUG,
              "Channel padding timeout scheduled "I64_FORMAT"ms in the past. "
              "Did the monotonic clock just jump?",
              I64_PRINTF_ARG(-ms_until_pad_for_netflow));
      return 0; /* Clock jumped: Send padding now */
    }

    return ms_until_pad_for_netflow;
  }
  return CHANNELPADDING_TIME_LATER;
}

/**
 * Calling this function on a channel causes it to tell the other side
 * not to send padding, and disables sending padding from this side as well.
 */
void
channelpadding_disable_padding_on_channel(channel_t *chan)
{
  chan->padding_enabled = 0;

  // Send cell to disable padding on the other end
  channelpadding_send_disable_command(chan);
}

/**
 * Calling this function on a channel causes it to tell the other side
 * not to send padding, and reduces the rate that padding is sent from
 * this side.
 */
void
channelpadding_reduce_padding_on_channel(channel_t *chan)
{
  /* Padding can be forced and reduced by clients, regardless of if
   * the channel supports it. So we check for support here before
   * sending any commands. */
  if (chan->padding_enabled) {
    channelpadding_send_disable_command(chan);
  }

#define DFLT_NETFLOW_REDUCED_KEEPALIVE_LOW 9000
#define DFLT_NETFLOW_REDUCED_KEEPALIVE_HIGH 14000
#define DFLT_NETFLOW_REDUCED_KEEPALIVE_MIN 0
#define DFLT_NETFLOW_REDUCED_KEEPALIVE_MAX 60000
  chan->padding_timeout_low_ms =
    networkstatus_get_param(NULL, "nf_ito_low_reduced",
        DFLT_NETFLOW_REDUCED_KEEPALIVE_LOW,
        DFLT_NETFLOW_REDUCED_KEEPALIVE_MIN,
        DFLT_NETFLOW_REDUCED_KEEPALIVE_MAX);

  chan->padding_timeout_high_ms =
    networkstatus_get_param(NULL, "nf_ito_high_reduced",
        DFLT_NETFLOW_REDUCED_KEEPALIVE_HIGH,
        chan->padding_timeout_low_ms,
        DFLT_NETFLOW_REDUCED_KEEPALIVE_MAX);

  log_fn(LOG_INFO,LD_OR,
         "Reduced padding on channel "U64_FORMAT": lo=%d, hi=%d",
         U64_PRINTF_ARG(chan->global_identifier),
         chan->padding_timeout_low_ms, chan->padding_timeout_high_ms);
}

/**
 * This function is called once per second by run_connection_housekeeping(),
 * but only if the channel is still open, valid, and non-wedged.
 *
 * It decides if and when we should send a padding cell, and if needed,
 * schedules a callback to send that cell at the appropriate time.
 *
 * Returns an enum that represents the current padding decision state.
 * Return value is currently used only by unit tests.
 */
channelpadding_decision_t
channelpadding_decide_to_pad_channel(channel_t *chan)
{
  const or_options_t *options = get_options();

  /* Only pad open channels */
  if (chan->state != CHANNEL_STATE_OPEN)
    return CHANNELPADDING_WONTPAD;

  if (chan->channel_usage == CHANNEL_USED_FOR_FULL_CIRCS) {
    if (!networkstatus_get_param(NULL, "nf_pad_before_usage", 1, 0, 1))
      return CHANNELPADDING_WONTPAD;
  } else if (chan->channel_usage != CHANNEL_USED_FOR_USER_TRAFFIC) {
    return CHANNELPADDING_WONTPAD;
  }

  if (chan->pending_padding_callback)
    return CHANNELPADDING_PADDING_ALREADY_SCHEDULED;

  /* Don't pad the channel if we didn't negotiate it, but still
   * allow clients to force padding if options->ChannelPadding is
   * explicitly set to 1.
   */
  if (!chan->padding_enabled && options->ConnectionPadding != 1) {
    return CHANNELPADDING_WONTPAD;
  }

  if (!chan->has_queued_writes(chan)) {
    int is_client_channel = 0;

    if (!public_server_mode(options) || chan->is_client ||
            !connection_or_digest_is_known_relay(chan->identity_digest)) {
       is_client_channel = 1;
    }

    /* If nf_pad_relays=1 is set in the consensus, we pad
     * on *all* idle connections, relay-relay or relay-client.
     * Otherwise pad only for client+bridge cons */
    if (is_client_channel ||
        networkstatus_get_param(NULL, "nf_pad_relays", 0, 0, 1)) {
      int64_t pad_time_ms =
          channelpadding_compute_time_until_pad_for_netflow(chan);

      if (pad_time_ms == CHANNELPADDING_TIME_DISABLED) {
        return CHANNELPADDING_WONTPAD;
      } else if (pad_time_ms == CHANNELPADDING_TIME_LATER) {
        chan->currently_padding = 1;
        return CHANNELPADDING_PADLATER;
      } else {
       /* We have to schedule a callback because we're called exactly once per
        * second, but we don't want padding packets to go out exactly on an
        * integer multiple of seconds. This callback will only be scheduled
        * if we're within 1.1 seconds of the padding time.
        */
        chan->currently_padding = 1;
        return channelpadding_schedule_padding(chan, pad_time_ms);
      }
    } else {
      chan->currently_padding = 0;
      return CHANNELPADDING_WONTPAD;
    }
  } else {
    return CHANNELPADDING_PADLATER;
  }
}

