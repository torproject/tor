/*
 * config.c
 * Functions for the manipulation of configuration files.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.2  2002/06/28 18:14:55  montrose
 * Added poptReadOptions() and poptReadDefaultOptions()
 *
 * Revision 1.1.1.1  2002/06/26 22:45:50  arma
 * initial commit: current code
 *
 * Revision 1.7  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.6  2002/01/27 19:23:03  mp292
 * Fixed a bug in parameter checking.
 *
 * Revision 1.5  2002/01/26 18:42:15  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.4  2002/01/21 21:07:56  mp292
 * Parameter checking was missing in some functions.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <popt.h>
#include <limits.h>

#include "config.h"
#include "log.h"

/* open configuration file for reading */
FILE *open_config(const unsigned char *filename)
{
  FILE *f;

  if (filename) /* non-NULL filename */
  {
    if (strspn(filename,CONFIG_LEGAL_FILENAME_CHARACTERS) == strlen(filename)) /* filename consists of legal characters only */
    {
      f = fopen(filename, "r");
      
      return f;
    } /* filename consists of legal characters only */
    else /* illegal values in filename */
    {
      return NULL;
    } /* illegal values in filename */
  } /* non-NULL filename */
  else /* NULL filename */
    return NULL;
}

/* close configuration file */
int close_config(FILE *f)
{
  int retval = 0;

  if (f) /* valid file descriptor */
  {
    retval = fclose(f);
  
    return retval;
  } /* valid file descriptor */
  else
    return -1;
}

/* parse the config file and obtain the required option values */
int parse_config(FILE *f, config_opt_t *option)
{
  unsigned char keyword[CONFIG_KEYWORD_MAXLEN+1]; /* for storing the option keyword */
  
  unsigned char *buffer = NULL; /* option value */
  size_t buflen = 0;
  
  char *errtest = NULL; /* used for testing correctness of strtol() etc. */
  
  unsigned int i_keyword = 0; /* current position within keyword */
  unsigned int i_buf = 0; /* current position within buffer */
  
  char c=0; /* input char */
  
  unsigned int state=0; /* internal state
		* 0 - trying to find a keyword
		* 1 - reading a keyword
		* 2 - keyword read and recognized, looking for the option value
		* 3 - reading the option value
		* 4 - option value read
		* 5 - inside a comment
		*/
  
  int retval=0; /* return value */
  
  int lineno=1; /* current line number */
  int curopt=-1; /* current option, as an indexed in config_opt_t */
  int i;
  
  if ( (f==NULL) || (option==NULL) ) /* invalid parameters */
    return -1;
  
  fseek(f,0,SEEK_SET); /* make sure we start at the beginning of file */
  
  for (;;) /* infinite loop */
  {
    c = getc(f);
    
    if  ((c == '\n') || (c == EOF))
    {
      if (state == 1) /* reading a keyboard */
      {
	log(LOG_ERR,"Error parsing the configuration file on line %d.", lineno);
	i_keyword = 0;
	state = 0;
	retval = -1;
	break;
      } /* reading a keyboard */
      else if (state == 2) /* keyword read and recognized */
      {
	log(LOG_ERR,"Error parsing option %s on line %d.",option[curopt].keyword, lineno);
	i_keyword = 0;
	state = 0;
	option[curopt].err=-1;
	retval = -1;
	break;
      } /* keyboard read and recognized */
      else if (state == 3) /* reading the option value */
      {
	buffer[i_buf++] = 0; /* add NULL character to terminate the string */
	state = 4;
	/* conversion and copying the value into config_opt_t is done later on */
      } /* reading the option value */
      else if (state == 5) /* reached end of comment */
	state = 0;
      
      if (c == EOF)
      {
	log(LOG_DEBUG,"parse_config() : Reached eof on line %d.",lineno);
	break;
      } 
      else
      {
	log(LOG_DEBUG,"parse_config() : Reached eol on line %d.", lineno);
	lineno++;
      }
    }
    else if ( (state==0) && (c == '#') ) /* lines beginning with # are ignored */
    {
      log(LOG_DEBUG,"parse_config() : Line %d begins with #.",lineno);
      state = 5;
    }
    else if ( (state==0) && (isspace(c)) ) /* leading whitespace is ignored */
      ;
    else if ( (state==1) && (isspace(c)) ) /* have apparently read in all of the keyword */
    {
      keyword[i_keyword++] = 0;
      curopt = -1;
      for (i=0;option[i].keyword != NULL;i++) /* try and identify the keyword */
      {
	if (!strncmp(keyword,option[i].keyword,CONFIG_KEYWORD_MAXLEN))
	{
	  curopt = i;
	  break;
	}
      } /* try and identify the keyword */
      
      if (curopt == -1) /* can't recognise the keyword */
      {
	log(LOG_ERR,"Error parsing the configuration file. Cannot recognize keyword %s on line %d.",keyword,lineno);
	retval=-1;
	break;
      }
      else
	state = 2;
    }
    else if ( (state==2) && (isspace(c)) ) /* whitespace separating keyword and value is ignored */
      ;
    else if ( (state==3) && (isspace(c)) ) /* have apparently finished reading the option value */
    {      
      buffer[i_buf++]=0;
      state = 4;
    }
    else /* all other characters */
    { 
      if (state == 0) /* first character of the keyword */
      {
	log(LOG_DEBUG, "parse_config() : %c is the start of a keyword on line %d.",c,lineno);
	state = 1;
	i_keyword = 0;
	keyword[i_keyword++] = c;
      }
      else if (state == 1) /* keep on reading the keyword */
      {
	log(LOG_DEBUG,"parse_config() : %c is a character in the keyword on line %d.",c,lineno);
	if (i_keyword < CONFIG_KEYWORD_MAXLEN) /* check for buffer overflow */
	  keyword[i_keyword++] = c;
	else
	{
	  log(LOG_ERR,"Error parsing the configuration file. Keyword on line %d exceeds %d characters.",lineno,CONFIG_KEYWORD_MAXLEN);
	  retval=-1;
	  break;
	}
      }
      else if (state == 2) /* first character of the value */
      {
	log(LOG_DEBUG,"parse_config() : %c is the first character of the option value on line %d.",c,lineno);
	state = 3;
	i_buf=0;
	buflen = CONFIG_VALUE_MAXLEN+1; /* allocate memory for the value buffer */
	buffer = (char *)malloc(buflen);
	if (!buffer)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  retval=-1;
	  break;
	} else
	  buffer[i_buf++]=c;
      }
      else if (state == 3) /* keep on reading the value */
      {
	log(LOG_DEBUG,"parse_config() : %c is a character in the value of the keyword on line %d.",c,lineno);
	if (i_buf >= buflen)
	{
	  log(LOG_ERR,"Length of keyword value on line %u exceeds the length limit (%u).",lineno, CONFIG_VALUE_MAXLEN);
	  retval=-1;
	  break;
	}

	buffer[i_buf++]=c;
      }
      else if (state == 5)
	; /* character is part of a comment, skip */
      else /* unexpected error */
      {
	log(LOG_ERR,"Unexpected error while parsing the configuration file.");
	log(LOG_DEBUG,"parse_config() : Encountered a non-delimiter character while not in states 0,1,2 or 3!");
	break;
      }
    }
    
    if (state==4) /* convert the value of the option to the appropriate type and write into OPT */
    {
      switch(option[curopt].r_type) /* consider each type separately */
      {
       case CONFIG_TYPE_STRING:
	/* resize the buffer to fit the data exactly */
	buffer = (char *)realloc(buffer,i_buf);
	if (!buffer)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  return -1;
	}
	option[curopt].r.str = buffer;
	option[curopt].err = 1;
	break;
	
       case CONFIG_TYPE_CHAR:
	option[curopt].r.c = *buffer;
	option[curopt].err = 1;
	break;
	
       case CONFIG_TYPE_INT:
	errtest = NULL;
	option[curopt].r.i = (int)strtol(buffer,&errtest,0);
	if ((unsigned char *)errtest == buffer)
	{
	  log(LOG_ERR, "Error parsing configuration file. Option %s on line %d does not seem to be of the required type.\n",option[curopt].keyword,--lineno);
	  option[curopt].err = -1;
	  if (buffer)
	    free(buffer);
	  return -1;
	}
	else
	  option[curopt].err = 1;
	break;
	
       case CONFIG_TYPE_LONG:
	errtest = NULL;
	option[curopt].r.l = strtol(buffer,&errtest,0);
	if ((unsigned char *)errtest == buffer)
	{
	  log(LOG_ERR, "Error parsing configuration file. Option %s on line %d does not seem to be of the required type.\n",option[curopt].keyword,--lineno);
	  option[curopt].err = -1;
	  if (buffer)
	    free(buffer);
	  return -1;
	}
	else
	  option[curopt].err = 1;
	break;
	
       case CONFIG_TYPE_DOUBLE:
	errtest = NULL;
	option[curopt].r.d = strtod(buffer,&errtest);
	if ((unsigned char *)errtest == buffer)
	{
	  log(LOG_ERR, "Error parsing configuration file. Option %s on line %d does not seem to be of the required type.\n",option[curopt].keyword,--lineno);
	  option[curopt].err = -1;
	  if (buffer)
	    free(buffer);
	  return -1;
	}
	else
	  option[curopt].err = 1;
	break;
	
       default: /* unexpected type */
	log(LOG_ERR, "Error parsing configuration file. Unrecognized option type!");
	if (buffer)
	  free(buffer);
	return -1;
      }
      
      /* clean up */
      if (option[curopt].r_type != CONFIG_TYPE_STRING)
      {
	if (buffer)
	  free(buffer);
	buflen=0;
      }
      
      state = 0;
      curopt = -1;
      i_buf=0;
      i_keyword=0;
    }
    
    
  } /* infinite loop */
  
  return retval;
}

int poptReadOptions(poptContext optCon, const unsigned char *fname)
/**
poptReadOptions reads popt-style options from the specified filename.
RETURN VALUE: INT_MIN = problem opening config file, else standard poptGetNextOpt() return value
**/
{
   FILE *fp;
   int argc, c;
   char **argv;
   char line[256];
   line[0] = line[1] = '-';  /* prepend expected long name option flag */
   fp = open_config(fname);
   if ( fp == NULL ) return INT_MIN;
   c = 0;
   /**
   this loop skips over all leading whitespace and blank lines then returns all text
   from that point to the next newline.
   **/
   while ( c >= -1 && fscanf(fp,"%*[ \n]%[^\n]",&line[2]) == 1 )
   {
      switch ( line[2] )
      {
      case '#':   /* comments begin with this */
      case '[':   /* section header. ignore for now. maybe do something special in future version... */
         continue;/* ignore */
      default:    /* we got a bite, lets reel it in now */
         poptParseArgvString(line,&argc,(const char ***)&argv); /* Argv-ify what we found */
         poptStuffArgs(optCon,(const char **)argv);   /* stuff new arguments so they can be interpreted */
         free(argv);                                  /* free storage allocated by poptParseArgvString */
         c = poptGetNextOpt(optCon);                  /* interpret option read from config file */
      }
   }
   close_config(fp);
   return c;
}

int poptReadDefaultOptions(const char *cmd, poptContext optCon)
/**
reads popt-style options from /etc/<cmd>rc and ~/.<cmd>rc
RETURN VALUE: same as poptReadOptions()
**/
{
   char fname[256];
   int c;
   sprintf(fname,"/etc/%src",cmd);
   c = poptReadOptions(optCon,fname);
   if ( c == INT_MIN || c >= -1 )
   {
      sprintf(fname,"~/.%src",cmd);
      c = poptReadOptions(optCon,fname);
   }
   return c;
}

