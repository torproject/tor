/*
 * log.h
 * Logging facilities.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.4  2003/05/09 03:37:18  nickm
 * Fix build on linux; macos is still messed up
 *
 * Revision 1.3  2003/05/09 02:41:27  nickm
 * One is the language; the other is the compiler
 *
 * Revision 1.2  2003/05/09 02:25:37  nickm
 * work on versioning; new log_fn function
 *
 * Revision 1.1.1.1  2002/06/26 22:45:50  arma
 * initial commit: current code
 *
 * Revision 1.5  2002/01/26 18:52:00  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.4  2001/12/18 10:37:47  badbytes
 * Header files now only apply if they were not previously included from somewhere else.
 *
 * Revision 1.3  2001/12/07 09:38:03  badbytes
 * Tested.
 *
 * Revision 1.2  2001/12/06 15:43:50  badbytes
 * config.c compiles. Proceeding to test it.
 *
 * Revision 1.1  2001/11/21 23:03:41  mp292
 * log function coded and tested.
 * Top-level makefile.
 *
 */

#ifndef __LOG_H

#include <syslog.h>

/* Outputs a message to stdout and also logs the same message using syslog. */
void log(int severity, const char *format, ...);

#ifdef __GNUC__
#define log_fn(severity, format, args...) \
  log((severity), __PRETTY_FUNCTION__ "(): " # format , ##args)
#else
#define log_fn log
#endif

# define __LOG_H
#endif
