/*
 * config.h
 * Functions for the manipulation of configuration files.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.7  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.6  2002/01/26 18:42:15  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.5  2002/01/21 21:07:56  mp292
 * Parameter checking was missing in some functions.
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
 * Revision 1.1  2001/11/22 01:20:27  mp292
 * Functions for dealing with configuration files.
 *
 *
 */

#ifndef __CONFIG_H

# include <stdio.h>

/* enumeration of types which option values can take */
#define CONFIG_TYPE_STRING  0
#define CONFIG_TYPE_CHAR    1
#define CONFIG_TYPE_INT     2
#define CONFIG_TYPE_LONG    3
#define CONFIG_TYPE_DOUBLE  4

/* max. length of an option keyword */
#define CONFIG_KEYWORD_MAXLEN 255

/* max. length (in characters) of an option value */
#define CONFIG_VALUE_MAXLEN 255

/* legal characters in a filename */
#define CONFIG_LEGAL_FILENAME_CHARACTERS "abcdefghijklmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/"

typedef struct
{
  unsigned char *keyword; /* option keyword */
  
  unsigned int r_type; /* return type as defined above */
 
  union /* return value */
  {
    char *str;
    char c;
    int i;
    long l;
    double d;
  } r;
  
  int err;      /*  1  OK
		 *  0  keyword not found
		 * -1  error while parsing */
} config_opt_t;

/* open configuration file for reading */
FILE *open_config(const unsigned char *filename);

/* close configuration file */
int close_config(FILE *f);

/* parse the config file and obtain required option values */
int parse_config(FILE *f, config_opt_t *option);

#define __CONFIG_H
#endif
