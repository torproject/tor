/**
 * routers.c 
 * Routines for loading the list of routers and their public RSA keys.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.16  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 * Revision 1.15  2002/03/25 10:48:48  badbytes
 * Added explicit dependency on <netinet/in.h>.
 *
 * Revision 1.14  2002/01/27 19:24:33  mp292
 * Fixed a bug in parameter checking.
 *
 * Revision 1.13  2002/01/26 22:19:15  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.12  2002/01/18 20:42:25  mp292
 * Slight modification to the way keys are read from the route file.
 *
 * Revision 1.11  2002/01/14 13:05:39  badbytes
 * System testing in progress.
 *
 * Revision 1.10  2002/01/11 15:47:25  badbytes
 * *** empty log message ***
 *
 * Revision 1.9  2001/12/18 15:51:58  badbytes
 * Connection with onion router established. Will continue testing tomorrow.
 *
 * Revision 1.8  2001/12/17 13:36:15  badbytes
 * Writing handle_connection()
 *
 * Revision 1.7  2001/12/17 08:42:45  badbytes
 * getrouters() now returns an array of routers and also writes the length of the array to an int*.
 *
 * Revision 1.6  2001/12/14 14:08:50  badbytes
 * getrouters() now returns an array of pointers rather than a linked list
 *
 * Revision 1.5  2001/12/14 14:05:56  badbytes
 * Added routent_t** make_rarray(routent_t* list);
 *
 * Revision 1.4  2001/12/14 13:25:17  badbytes
 * Moved back from common/
 *
 * Revision 1.2  2001/12/14 11:24:57  badbytes
 * Tested.
 *
 * Revision 1.1  2001/12/13 15:15:11  badbytes
 * Started coding the onion proxy.
 *
 */

#include <openssl/pem.h>
#include <openssl/err.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>

#include "routers.h"
#include "../common/log.h"
#include "../common/utils.h"
#include "../common/config.h"

/* delete a list of routers from memory */
void delete_routerlist(routent_t *list)
{
  routent_t *tmp = NULL;
  
  if (!list)
    return;
  
  do
  {
    tmp=list->next;
    free(list->address);
    RSA_free(list->pkey);
    free(list);
    list = tmp;
  }
  while (list != NULL);
  
  return;
}

/* create an NULL-terminated array of pointers pointing to elements of a router list */
/* this is done in two passes through the list - inefficient but irrelevant as this is
 * only done once when op/or start up */
routent_t **make_rarray(routent_t* list, size_t *len)
{
  routent_t *tmp=NULL;
  int listlen = 0;
  routent_t **array=NULL;
  routent_t **p=NULL;
  
  if ((!list) || (!len))
    return NULL;
  
  /* get the length of the list */
  tmp = list;
  do
  {
    listlen++;
    tmp = tmp->next;
  }
  while (tmp != NULL);
  
  array = malloc((listlen+1)*sizeof(routent_t *));
  if (!array)
  {
    log(LOG_ERR,"Error allocating memory.");
    return NULL;
  }
  
  tmp=list;
  p = array;
  do
  {
    *p = tmp;
    p++;
    tmp = tmp->next;
  }
  while(tmp != NULL);
  *p=NULL;
  
  *len = listlen;
  return array;
}

/* load the router list */
routent_t **getrouters(char *routerfile, size_t *lenp)
{
  int retval = 0;
  char *retp = NULL;
  routent_t *router=NULL, *routerlist=NULL, *lastrouter=NULL;
  FILE *rf; /* router file */
  fpos_t fpos;
  char line[512];
  char *token;
  char *errtest; /* detecting errors in strtoul() calls */
  struct hostent *rent;
  
  if ((!routerfile) || (!lenp)) /* invalid parameters */
    return NULL;

  if (strspn(routerfile,CONFIG_LEGAL_FILENAME_CHARACTERS) != strlen(routerfile)) /* invalid filename */
  {
    log(LOG_ERR,"Could not open %s because it contains illegal characters.",routerfile);
    return NULL;
  }
  
  /* open the router list */
  rf = fopen(routerfile,"r");
  if (!rf)
  {
    log(LOG_ERR,"Could not open %s.",routerfile);
    return NULL;
  }
  
  retp= fgets(line,512,rf);
  while (retp)
  {
    log(LOG_DEBUG,"getrouters() : Line :%s",line);
    token = (char *)strtok(line,OP_ROUTERLIST_SEPCHARS);
    if (token)
    {
      log(LOG_DEBUG,"getrouters() : Token : %s",token);
      if (token[0] != '#') /* ignore comment lines */
      {
	router = malloc(sizeof(routent_t));
	if (!router)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  fclose(rf);
	  delete_routerlist(routerlist);
	  return NULL;
	}
	
	/* read the address */
	router->address = malloc(strlen(token)+1);
	if (!router->address)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  fclose(rf);
	  free(router);
	  delete_routerlist(routerlist);
	  return NULL;
	}
	strcpy(router->address,token);
	
	rent = (struct hostent *)gethostbyname(router->address);
	if (!rent)
	{
	  log(LOG_ERR,"Could not get address for router %s.",router->address);
	  fclose(rf);
	  free(router->address);
	  free(router);
	  delete_routerlist(routerlist);
	  return NULL;
	}

	memcpy(&router->addr, rent->h_addr,rent->h_length);
	
	/* read the network port */
	token = (char *)strtok(NULL,OP_ROUTERLIST_SEPCHARS);
	if (token) /* network port */
	{
	  log(LOG_DEBUG,"getrouters() : Token :%s",token);
	  router->port = (uint16_t)strtoul(token,&errtest,0);
	  if ((*token != '\0') && (*errtest == '\0')) /* network port conversion was successful */
	  {
	    router->port = htons(router->port);
	    /* read the entry port */
	    token = (char *)strtok(NULL,OP_ROUTERLIST_SEPCHARS);
	    if (token) /* entry port */
	    {
	      log(LOG_DEBUG,"getrouters() : Token :%s",token);
	      router->entry_port = (uint16_t)strtoul(token,&errtest,0);
	      if ((*token != '\0') && (*errtest == '\0')) /* entry port number conversion was successful */
	      {
		router->entry_port = htons(router->entry_port);
		/* check that there is a public key entry for that router */
		retval = fgetpos(rf, &fpos); /* save the current file position
					      * we wil return to it later if we find a public key */
		if (retval == -1)
		{
		  log(LOG_ERR,"Could not save position in %s.",routerfile);
		  free(router->address);
		  free(router);
		  fclose(rf);
		  delete_routerlist(routerlist);
		  return NULL;
		}
		do /* read through to the next non-empty line */
		{
		  retp=fgets(line,512,rf);
		  if (!retp)
		  {
		    log(LOG_ERR,"Could not find a public key entry for router %s:%u.",router->address,router->port);
		    free(router->address);
		    free(router);
		    fclose(rf);
		    delete_routerlist(routerlist);
		    return NULL;
		  }
		  log(LOG_DEBUG,"getrouters() : Line:%s",line);
		  if ((*line != '#') && (strspn(line,OP_ROUTERLIST_SEPCHARS) != strlen(line) ))
		  {
		    break;
		  }
		} while (1);
	    
		if (!strcmp(line,OP_PUBLICKEY_BEGIN_TAG)) /* we've got the public key */
		{
		  retval = fsetpos(rf,&fpos); /* get us back to where we were otherwise crypto lib won't find the key */
		  if (retval == -1)
		  {
		    log(LOG_ERR,"Could not set position in %s.",routerfile);
		    free(router->address);
		    free(router);
		    fclose(rf);
		    delete_routerlist(routerlist);
		    return NULL;
		  }
		}
		else /* we found something else; this isn't right */
		{
		  log(LOG_ERR,"Could not find a public key entry for router %s:%u.",router->address,router->port);
		  free(router->address);
		  free(router);
		  fclose(rf);
		  delete_routerlist(routerlist);
		  return NULL;
		}
		
		log(LOG_DEBUG,"getrouters() : Reading the key ...");
		/* read the public key into router->pkey */
		router->pkey=NULL;
		router->pkey = PEM_read_RSAPublicKey(rf,NULL,NULL,NULL);
		if (!router->pkey) /* something went wrong */
		{
		  log(LOG_ERR,"Could not read public key for router %s:%u.",router->address,router->port);
		  free(router->address);
		  free(router);
		  fclose(rf);
		  delete_routerlist(routerlist);
		  return NULL;
		}
		else /* read the key */
		{
		  log(LOG_DEBUG,"getrouters() : Public key size = %u.", RSA_size(router->pkey));
		  if (RSA_size(router->pkey) != 128) /* keys MUST be 1024 bits in size */
		  {
		    log(LOG_ERR,"Key for router %s:%u is not 1024 bits. All keys must be exactly 1024 bits long.",router->address,router->port);
		    free(router->address);
		    RSA_free(router->pkey);
		    free(router);
		    fclose(rf);
		    delete_routerlist(routerlist);
		    return NULL;
		  }
		  router->next = NULL;
		  /* save the entry into the routerlist linked list */
		  if (!routerlist) /* this is the first entry */
		    routerlist = router;
		  else
		    lastrouter->next = (void *)router;
		  lastrouter = router;
		}
	      }
	      else
	      {
		log(LOG_ERR,"Entry for router %s doesn't seem to contain a valid entry funnel port.",router->address);
		free(router->address);
		free(router);
		fclose(rf);
		delete_routerlist(routerlist);
		return NULL;
	      }
	    }
	    else
	    {
	      log(LOG_ERR,"Entry for router %s doesn't seem to contain an entry funnel port.",router->address);
	      free(router->address);
	      free(router);
	      fclose(rf);
	      delete_routerlist(routerlist);
	      return NULL;
	    }
	  }
	  else
	  {
	    log(LOG_ERR,"Entry for router %s doesn't seem to contain a valid network funnel port.",router->address);
	    free(router->address);
	    free(router);
	    fclose(rf);
	    delete_routerlist(routerlist);
	    return NULL;
	  }
	}
	else
	{
	  log(LOG_ERR,"Entry for router %s doesn't seem to contain a network funnel port.",router->address);
	  free(router->address);
	  free(router);
	  fclose(rf);
	  delete_routerlist(routerlist);
	  return NULL;
	}
      }
    }
    retp=fgets(line,512,rf);
  }
  
  fclose(rf);
  return make_rarray(routerlist, lenp);
}
