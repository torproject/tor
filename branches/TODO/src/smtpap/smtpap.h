/**
 * smtpap.h
 * SMTP Application Proxy for Onion Routing
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.12  2002/01/29 01:00:10  mp292
 * All network operations are now timeoutable.
 *
 * Revision 1.11  2002/01/26 21:50:17  mp292
 * Reviewed according to Secure-Programs-HOWTO. Still need to deal with network
 * timeouts.
 *
 * Revision 1.10  2001/12/18 14:56:29  badbytes
 * *** empty log message ***
 *
 * Revision 1.9  2001/12/18 14:43:19  badbytes
 * Added DEFAULT_SMTP_PORT.
 *
 * Revision 1.8  2001/12/12 16:02:29  badbytes
 * Testing completed.
 *
 * Revision 1.7  2001/12/11 10:43:21  badbytes
 * MAIL and RCPT handling completed. Still coding connection to Onion Proxy.
 *
 * Revision 1.6  2001/12/10 16:10:35  badbytes
 * Wrote a tokenize() function to help with parsing input from SMTP clients.
 *
 * Revision 1.5  2001/12/07 15:02:43  badbytes
 * Server setup code completed.
 *
 */

#ifndef __SMTPAP_H

#define __SMTPAP_H

#define SMTPAP_CRLF "\015\012"
#define SMTPAP_CRLF_LEN 2

#define SMTPAP_CR '\015'
#define SMTPAP_LF '\012'

/* terminator for DATA input */
#define SMTPAP_ENDDATA "\015\012.\015\012" 
#define SMTPAP_ENDDATA_LEN 5

/* characters that separate tokens in SMTPAP commands */
#define SMTPAP_SEPCHARS " \t\015\012" /* for general commands */
#define SMTPAP_PATH_SEPCHARS " \t\015\012<>" /* for forward and reverse path */

/* default listening port */
#define SMTPAP_LISTEN_PORT 25

/* default SMTP port */
#define SMTPAP_DEFAULT_SMTP_PORT 25

/* default connection timeout */
#define SMTPAP_DEFAULT_CONN_TIMEOUT 120; /* 120s */

/* SMTP commands and their lengths */
#define SMTPAP_QUIT "quit"
#define SMTPAP_QUIT_LEN 4

#define SMTPAP_HELO "helo"
#define SMTPAP_HELO_LEN 4
#define SMTPAP_EHLO "ehlo"
#define SMTPAP_EHLO_LEN 4

#define SMTPAP_MAIL "mail"
#define SMTPAP_MAIL_LEN 4

#define SMTPAP_RSET "rset"
#define SMTPAP_RSET_LEN 4

#define SMTPAP_RCPT "rcpt"
#define SMTPAP_RCPT_LEN 4

#define SMTPAP_DATA "data"
#define SMTPAP_DATA_LEN 4

#endif

