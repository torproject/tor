/*
 * http.h 
 * HTTP parsers.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.2  2002/04/02 14:27:33  badbytes
 * Final finishes.
 *
 * Revision 1.1  2002/03/12 23:46:14  mp292
 * HTTP-related routines.
 *
 */

#define HTTPAP_MAXLEN 1024 /* maximum length of a line */

#define HTTPAP_CR '\015'
#define HTTPAP_LF '\012'
#define HTTPAP_CRLF "\015\012"

#define HTTPAP_VERSION "HTTP/1.0"

#define HTTPAP_STATUS_LINE_FORBIDDEN HTTPAP_VERSION " 403 Only local connections are allowed." HTTPAP_CRLF
#define HTTPAP_STATUS_LINE_VERSION_NOT_SUPPORTED HTTPAP_VERSION " 505 Only HTTP/1.0 is supported." HTTPAP_CRLF
#define HTTPAP_STATUS_LINE_UNAVAILABLE HTTPAP_VERSION " 503 Connection to the server failed." HTTPAP_CRLF
#define HTTPAP_STATUS_LINE_BAD_REQUEST HTTPAP_VERSION " 400 Invalid syntax." HTTPAP_CRLF
#define HTTPAP_STATUS_LINE_UNEXPECTED HTTPAP_VERSION " 500 Internal server error." HTTPAP_CRLF

#define HTTPAP_HEADER_PROXY_CONNECTION "Proxy-Connection"
#define HTTPAP_HEADER_USER_AGENT "User-Agent"
#define HTTPAP_HEADER_REFERER "Referer"

int http_get_line(int s, unsigned char **line, size_t *len, struct timeval *conn_tout);

int http_get_version(unsigned char *rl, unsigned char **http_ver);

int http_get_dest(unsigned char *rl, unsigned char **addr, unsigned char **port);

int http_get_header_name(unsigned char *rl, unsigned char **hname);
