/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * routers.c 
 * Routines for loading the list of routers and their public RSA keys.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

#define OR_ROUTERLIST_SEPCHARS " \t\n"
#define OR_PUBLICKEY_BEGIN_TAG "-----BEGIN RSA PUBLIC KEY-----\n"

#include "or.h"

/* private function, to determine whether the current entry in the router list is actually us */
static int routers_is_us(uint32_t or_address, uint16_t or_listenport, uint16_t my_or_listenport)
{
  /* local host information */
  char localhostname[512];
  struct hostent *localhost;
  
  char *addr = NULL;
  int i = 0;
  
  /* obtain local host information */
  if (gethostname(localhostname,512) < 0) {
    log(LOG_ERR,"Error obtaining local hostname.");
    return -1;
  }
  localhost = gethostbyname(localhostname);
  if (!localhost) {
    log(LOG_ERR,"Error obtaining local host info.");
    return -1;
  }
  
  /* check host addresses for a match with or_address above */
  addr = localhost->h_addr_list[i++]; /* set to the first local address */
  while(addr)
  {
    if (!memcmp((void *)&or_address, (void *)addr, sizeof(uint32_t))) { /* addresses match */
      if (or_listenport == htons(my_or_listenport)) /* ports also match */
	      return 1;
    }
    
    addr = localhost->h_addr_list[i++];
  }
  
  return 0;
}

/* delete a list of routers from memory */
void delete_routerlist(routerinfo_t *list)
{
  routerinfo_t *tmp = NULL;
  
  if (!list)
    return;
  
  do
  {
    tmp=list->next;
    free((void *)list->address);
    RSA_free(list->pkey);
    free((void *)list);
    list = tmp;
  }
  while (list != NULL);
  
  return;
}

/* create an NULL-terminated array of pointers pointing to elements of a router list */
/* this is done in two passes through the list - inefficient but irrelevant as this is
 * only done once when op/or start up */
routerinfo_t **make_rarray(routerinfo_t* list, size_t *len)
{
  routerinfo_t *tmp=NULL;
  int listlen = 0;
  routerinfo_t **array=NULL;
  routerinfo_t **p=NULL;
  
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
  
  array = malloc((listlen+1)*sizeof(routerinfo_t *));
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
routerinfo_t **getrouters(char *routerfile, size_t *lenp, uint16_t or_listenport)
{
  int retval = 0;
  char *retp = NULL;
  routerinfo_t *router=NULL, *routerlist=NULL, *lastrouter=NULL;
  FILE *rf; /* router file */
  fpos_t fpos;
  char line[512];
  char *token;
  char *errtest; /* detecting errors in strtoul() calls */
  struct hostent *rent;

  if ((!routerfile) || (!lenp))
    return NULL;
  
  if (strcspn(routerfile,CONFIG_LEGAL_FILENAME_CHARACTERS) != 0)
  {
    log(LOG_ERR,"Filename %s contains illegal characters.",routerfile);
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
    log(LOG_DEBUG,"getrouters():Line :%s",line);
    token = (char *)strtok(line,OR_ROUTERLIST_SEPCHARS);
    if (token)
    {
      log(LOG_DEBUG,"getrouters():Token : %s",token);
      if (token[0] != '#') /* ignore comment lines */
      {
	router = malloc(sizeof(routerinfo_t));
	if (!router)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  fclose(rf);
	  delete_routerlist(routerlist);
	  return NULL;
	}
	
#if 0
	router->conn_bufs = NULL; /* no output buffers */
	router->last_conn_buf = NULL;
	router->next_to_service = 0;
	
	router->s = -1; /* to signify this router is as yet unconnected */
	router->celllen = 0; /* cell buffer is empty */
#endif
	
	/* read the address */
	router->address = malloc(strlen(token)+1);
	if (!router->address)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  fclose(rf);
	  free((void *)router);
	  delete_routerlist(routerlist);
	  return NULL;
	}
	strcpy(router->address,token);
	
	rent = (struct hostent *)gethostbyname(router->address);
	if (!rent)
	{
	  log(LOG_ERR,"Could not get address for router %s.",router->address);
	  fclose(rf);
	  free((void *)router->address);
	  free((void *)router);
	  delete_routerlist(routerlist);
	  return NULL;
	}

	memcpy(&router->addr, rent->h_addr,rent->h_length);
	
	/* read the port */
	token = (char *)strtok(NULL,OR_ROUTERLIST_SEPCHARS);
	if (token)
	{
	  log(LOG_DEBUG,"getrouters():Token :%s",token);
	  router->or_port = (uint16_t)strtoul(token,&errtest,0);
	  if ((*token != '\0') && (*errtest == '\0')) /* conversion was successful */
	  {
/* FIXME patch from RD. We should make it actually read these. */
	    router->op_port = htons(router->or_port + 10);
	    router->ap_port = htons(router->or_port + 20);
	    /* convert port to network format */
	    router->or_port = htons(router->or_port);
	    
	    /* read min bandwidth */
	    token = (char *)strtok(NULL,OR_ROUTERLIST_SEPCHARS);
	    if (token) /* min bandwidth */
	    {
	      router->min = (uint32_t)strtoul(token,&errtest,0);
	      if ((*token != '\0') && (*errtest == '\0')) /* conversion was successful */
	      {
		if (router->min) /* must not be zero */
		{
		  /* read max bandwidth */
		  token = (char *)strtok(NULL,OR_ROUTERLIST_SEPCHARS);
		  if (token) /* max bandwidth */
		  {
		    router->max = (uint32_t)strtoul(token,&errtest,0);
		    if ((*token != '\0') && (*errtest == '\0')) /* conversion was successful */
		    {
		      if (router->max) /* must not be zero */
		      {
			/* check that there is a public key entry for that router */
			retval = fgetpos(rf, &fpos); /* save the current file position
						      * we wil return to it later if we find a public key */
			if (retval == -1)
			{
			  log(LOG_ERR,"Could not save position in %s.",routerfile);
			  free((void *)router->address);
			  free((void *)router);
			  fclose(rf);
			  delete_routerlist(routerlist);
			  return NULL;
			}
			do /* read through to the next non-empty line */
			{
			  retp=fgets(line,512,rf);
			  if (!retp)
			  {
			    log(LOG_ERR,"Could not find a public key entry for router %s:%u.",
				router->address,router->or_port);
			    free((void *)router->address);
			    free((void *)router);
			    fclose(rf);
			    delete_routerlist(routerlist);
			    return NULL;
			  }
			  log(LOG_DEBUG,"getrouters():Line:%s",line);
			  if ((*line != '#') && ( strspn(line,OR_ROUTERLIST_SEPCHARS) != strlen(line) ))
			  {
			    break;
			  }
			} while (1);
			
			if (!strcmp(line,OR_PUBLICKEY_BEGIN_TAG)) /* we've got the public key */
			{
			  retval = fsetpos(rf,&fpos); /* get us back to where we were otherwise crypto lib won't find the key */
			  if (retval == -1)
			  {
			    log(LOG_ERR,"Could not set position in %s.",routerfile);
			    free((void *)router->address);
			    free((void *)router);
			    fclose(rf);
			    delete_routerlist(routerlist);
			    return NULL;
			  }
			}
			else /* we found something else; this isn't right */
			{
			  log(LOG_ERR,"Could not find a public key entry for router %s:%u.",
			      router->address,router->or_port);
			  free((void *)router->address);
			  free((void *)router);
			  fclose(rf);
			  delete_routerlist(routerlist);
			  return NULL;
			}
			
			log(LOG_DEBUG,"getrouters():Reading the key ...");
			/* read the public key into router->pkey */
			router->pkey=NULL;
			router->pkey = PEM_read_RSAPublicKey(rf,&router->pkey,NULL,NULL);
			if (!router->pkey) /* something went wrong */
			{
			  log(LOG_ERR,"Could not read public key for router %s:%u.", 
			      router->address,router->or_port);
			  free((void *)router->address);
			  free((void *)router);
			  fclose(rf);
			  delete_routerlist(routerlist);
			  return NULL;
			}
			else /* read the key */
			{
			  log(LOG_DEBUG,"getrouters():Public key size = %u.", RSA_size(router->pkey));
			  if (RSA_size(router->pkey) != 128) /* keys MUST be 1024 bits in size */
			  {
			    log(LOG_ERR,"Key for router %s:%u is not 1024 bits. All keys must be exactly 1024 bits long.",router->address,router->or_port);
			    free((void *)router->address);
			    RSA_free(router->pkey);
			    free((void *)router);
			    fclose(rf);
			    delete_routerlist(routerlist);
			    return NULL;
			  }
			  
			  /* check that this router doesn't actually represent us */
			  retval = routers_is_us(router->addr, router->or_port, or_listenport);
			  if (!retval) { /* this isn't us, continue */
			    router->next = NULL;
			    /* save the entry into the routerlist linked list */
			    if (!routerlist) /* this is the first entry */
				    routerlist = router;
			    else
				    lastrouter->next = (void *)router;
			    lastrouter = router;
			  }
			  else if (retval == 1) /* this is us, ignore */
			  {
			    log(LOG_DEBUG,"getrouters(): This entry is actually me. Ignoring.");
			    free((void *)router->address);
			    RSA_free(router->pkey);
			    free((void *)router);
			  }
			  else /* routers_is_us() returned an error */
			  {
			    free((void *)router->address);
			    RSA_free(router->pkey);
			    free((void *)router);
			    fclose(rf);
			    delete_routerlist(routerlist);
			    return NULL;
			  }
			}
		      }
		      else /* maximum link utilisation is zero */
		      {
			log(LOG_ERR,"Entry for router %s doesn't contain a valid maximum bandwidth entry (must be > 0).",router->address);
			free((void *)router->address);
			free((void *)router);
			fclose(rf);
			delete_routerlist(routerlist);
			return NULL;
		      }
		    }
		    else
		    {
		      log(LOG_ERR,"Entry for router %s doesn't seem to contain a valid maximum bandwidth entry.",router->address);
		      free((void *)router->address);
		      free((void *)router);
		      fclose(rf);
		      delete_routerlist(routerlist);
		      return NULL;
		    }
		  }
		  else
		  {
		    log(LOG_ERR,"Entry for router %s doesn't seem to contain a maximum bandwidth entry.",router->address);
		    free((void *)router->address);
		    free((void *)router);
		    fclose(rf);
		    delete_routerlist(routerlist);
		    return NULL;
		  }
		}
		else
		{
		  log(LOG_ERR,"Entry for router %s doesn't contain a valid minimum bandwidth entry (must be > 0).",router->address);
		  free((void *)router->address);
		  free((void *)router);
		  fclose(rf);
		  delete_routerlist(routerlist);
		  return NULL;
		}
	      }
	      else
	      {
		log(LOG_ERR,"Entry for router %s doesn't seem to contain a valid minimum bandwidth entry.",router->address);
		free((void *)router->address);
		free((void *)router);
		fclose(rf);
		delete_routerlist(routerlist);
		return NULL;
	      }
	    }
	    else
	    {
	      log(LOG_ERR,"Entry for router %s doesn't seem to contain a minimum bandwidth entry.",router->address);
	      free((void *)router->address);
	      free((void *)router);
	      fclose(rf);
	      delete_routerlist(routerlist);
	      return NULL;
	    }
	  }
	  else
	  {
	    log(LOG_ERR,"Entry for router %s doesn't seem to contain a valid port number.",router->address);
	    free((void *)router->address);
	    free((void *)router);
	    fclose(rf);
	    delete_routerlist(routerlist);
	    return NULL;
	  }
	}
	else
	{
	  log(LOG_ERR,"Entry for router %s doesn't seem to contain a port number.",router->address);
	  free((void *)router->address);
	  free((void *)router);
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
