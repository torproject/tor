/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include "../or/or.h"

#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif

/*
 *    Memory wrappers
 */

void *tor_malloc(size_t size) {
  void *result;

  result = malloc(size);

  if(!result) {
    log_fn(LOG_ERR, "Out of memory. Dying.");
    exit(1);
  }
  memset(result,'X',size); /* XXX deadbeef to encourage bugs */
  return result;
}

void *tor_realloc(void *ptr, size_t size) {
  void *result;
  
  result = realloc(ptr, size);
  if (!result) {
    log_fn(LOG_ERR, "Out of memory. Dying.");
    exit(1);
  }
  return result;
}

char *tor_strdup(const char *s) {
  char *dup;
  assert(s);

  dup = strdup(s);
  if(!dup) {
    log_fn(LOG_ERR,"Out of memory. Dying.");
    exit(1);
  }
  return dup;
}

/*
 *    Time
 */

void tor_gettimeofday(struct timeval *timeval) {
#ifdef HAVE_GETTIMEOFDAY
  if (gettimeofday(timeval, NULL)) {
    log_fn(LOG_ERR, "gettimeofday failed.");
    /* If gettimeofday dies, we have either given a bad timezone (we didn't),
       or segfaulted.*/
    exit(1);
  }
#elif defined(HAVE_FTIME)
  ftime(timeval);
#else
#error "No way to get time."
#endif
  return;
}

long
tv_udiff(struct timeval *start, struct timeval *end)
{
  long udiff;
  long secdiff = end->tv_sec - start->tv_sec;

  if (secdiff+1 > LONG_MAX/1000000) {
    log_fn(LOG_WARN, "comparing times too far apart.");
    return LONG_MAX;
  }

  udiff = secdiff*1000000L + (end->tv_usec - start->tv_usec);
  if(udiff < 0) {
    log_fn(LOG_INFO, "start (%ld.%ld) is after end (%ld.%ld). Returning 0.",
           (long)start->tv_sec, (long)start->tv_usec, (long)end->tv_sec, (long)end->tv_usec);
    return 0;
  }
  return udiff;
}

int tv_cmp(struct timeval *a, struct timeval *b) {
  if (a->tv_sec > b->tv_sec)
    return 1;
  if (a->tv_sec < b->tv_sec)
    return -1;
  if (a->tv_usec > b->tv_usec)
    return 1;
  if (a->tv_usec < b->tv_usec)
    return -1;
  return 0;
}

void tv_add(struct timeval *a, struct timeval *b) {
  a->tv_usec += b->tv_usec;
  a->tv_sec += b->tv_sec + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}

void tv_addms(struct timeval *a, long ms) {
  a->tv_usec += (ms * 1000) % 1000000;
  a->tv_sec += ((ms * 1000) / 1000000) + (a->tv_usec / 1000000);
  a->tv_usec %= 1000000;
}

/*
 *   Low-level I/O.
 */

/* a wrapper for write(2) that makes sure to write all count bytes.
 * Only use if fd is a blocking fd. */
int write_all(int fd, const void *buf, size_t count) {
  int written = 0;
  int result;

  while(written != count) {
    result = write(fd, buf+written, count-written);
    if(result<0)
      return -1;
    written += result;
  }
  return count;
}

/* a wrapper for read(2) that makes sure to read all count bytes.
 * Only use if fd is a blocking fd. */
int read_all(int fd, void *buf, size_t count) {
  int numread = 0;
  int result;

  while(numread != count) {
    result = read(fd, buf+numread, count-numread);
    if(result<=0)
      return -1;
    numread += result;
  }
  return count;
}

void set_socket_nonblocking(int socket)
{
#ifdef MS_WINDOWS
	/* Yes means no and no means yes.  Do you not want to be nonblocking? */
	int nonblocking = 0;
	ioctlsocket(socket, FIONBIO, (unsigned long*) &nonblocking);
#else
	fcntl(socket, F_SETFL, O_NONBLOCK);
#endif
}

/*
 *   Process control
 */

/* Minimalist interface to run a void function in the background.  On
 * unix calls fork, on win32 calls beginthread.  Returns -1 on failure.
 * func should not return, but rather should call spawn_exit.
 */
int spawn_func(int (*func)(void *), void *data)
{
#ifdef MS_WINDOWS
  int rv;
  rv = _beginthread(func, 0, data);
  if (rv == (unsigned long) -1)
    return -1;
  return 0;
#else
  pid_t pid;
  pid = fork();
  if (pid<0)
    return -1;
  if (pid==0) {
    /* Child */
    func(data);
    assert(0); /* Should never reach here. */
    return 0; /* suppress "control-reaches-end-of-non-void" warning. */
  } else {
    /* Parent */
    return 0;
  }
#endif
}

void spawn_exit()
{
#ifdef MS_WINDOWS
  _endthread();
#else
  exit(0);
#endif
}


/*
 *   Windows compatibility.
 */
int
tor_socketpair(int family, int type, int protocol, int fd[2])
{
#ifdef HAVE_SOCKETPAIR_XXXX
    /* For testing purposes, we never fall back to real socketpairs. */
    return socketpair(family, type, protocol, fd);
#else
    int listener = -1;
    int connector = -1;
    int acceptor = -1;
    struct sockaddr_in listen_addr;
    struct sockaddr_in connect_addr;
    int size;
    
    if (protocol
#ifdef AF_UNIX
        || family != AF_UNIX
#endif
        ) {
#ifdef MS_WINDOWS
        errno = WSAEAFNOSUPPORT;
#else
        errno = EAFNOSUPPORT;
#endif
        return -1;
    }
    if (!fd) {
        errno = EINVAL;
        return -1;
    }

    listener = socket(AF_INET, type, 0);
    if (listener == -1)
      return -1;
    memset (&listen_addr, 0, sizeof (listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    listen_addr.sin_port = 0;   /* kernel choses port.  */
    if (bind(listener, (struct sockaddr *) &listen_addr, sizeof (listen_addr))
        == -1)
        goto tidy_up_and_fail;
    if (listen(listener, 1) == -1)
        goto tidy_up_and_fail;

    connector = socket(AF_INET, type, 0);
    if (connector == -1)
        goto tidy_up_and_fail;
    /* We want to find out the port number to connect to.  */
    size = sizeof (connect_addr);
    if (getsockname(listener, (struct sockaddr *) &connect_addr, &size) == -1)
        goto tidy_up_and_fail;
    if (size != sizeof (connect_addr))
        goto abort_tidy_up_and_fail;
    if (connect(connector, (struct sockaddr *) &connect_addr,
                sizeof (connect_addr)) == -1)
        goto tidy_up_and_fail;

    size = sizeof (listen_addr);
    acceptor = accept(listener, (struct sockaddr *) &listen_addr, &size);
    if (acceptor == -1)
        goto tidy_up_and_fail;
    if (size != sizeof(listen_addr))
        goto abort_tidy_up_and_fail;
    close(listener);
    /* Now check we are talking to ourself by matching port and host on the
       two sockets.  */
    if (getsockname(connector, (struct sockaddr *) &connect_addr, &size) == -1)
        goto tidy_up_and_fail;
    if (size != sizeof (connect_addr)
        || listen_addr.sin_family != connect_addr.sin_family
        || listen_addr.sin_addr.s_addr != connect_addr.sin_addr.s_addr
        || listen_addr.sin_port != connect_addr.sin_port) {
        goto abort_tidy_up_and_fail;
    }
    fd[0] = connector;
    fd[1] = acceptor;
    return 0;

  abort_tidy_up_and_fail:
#ifdef MS_WINDOWS
  errno = WSAECONNABORTED;
#else
  errno = ECONNABORTED; /* I hope this is portable and appropriate.  */
#endif
  tidy_up_and_fail:
    {
        int save_errno = errno;
        if (listener != -1)
            close(listener);
        if (connector != -1)
	    close(connector);
        if (acceptor != -1)
            close(acceptor);
        errno = save_errno;
        return -1;
    }
#endif
}

#ifdef MS_WINDOWS
int correct_socket_errno(int s)
{
  int optval, optvallen=sizeof(optval);
  assert(errno == WSAEWOULDBLOCK);
  if (getsockopt(s, SOL_SOCKET, SO_ERROR, (void*)&optval, &optvallen))
    return errno;
  if (optval)
    return optval;
  return WSAEWOULDBLOCK;
}
#endif

/*
 *    Filesystem operations.
 */

/* Return FN_ERROR if filename can't be read, FN_NOENT if it doesn't
 * exist, FN_FILE if it is a regular file, or FN_DIR if it's a
 * directory. */
file_status_t file_status(const char *fname)
{
  struct stat st;
  if (stat(fname, &st)) {
    if (errno == ENOENT) {
      return FN_NOENT;
    }
    return FN_ERROR;
  }
  if (st.st_mode & S_IFDIR) 
    return FN_DIR;
  else if (st.st_mode & S_IFREG)
    return FN_FILE;
  else
    return FN_ERROR;
}

/* Check whether dirname exists and is private.  If yes returns
   0.  Else returns -1. */
int check_private_dir(const char *dirname, int create)
{
  struct stat st;
  if (stat(dirname, &st)) {
    if (errno != ENOENT) {
      log(LOG_WARN, "Directory %s cannot be read: %s", dirname, 
          strerror(errno));
      return -1;
    } 
    if (!create) {
      log(LOG_WARN, "Directory %s does not exist.", dirname);
      return -1;
    }
    log(LOG_INFO, "Creating directory %s", dirname); 
    if (mkdir(dirname, 0700)) {
      log(LOG_WARN, "Error creating directory %s: %s", dirname, 
          strerror(errno));
      return -1;
    } else {
      return 0;
    }
  }
  if (!(st.st_mode & S_IFDIR)) {
    log(LOG_WARN, "%s is not a directory", dirname);
    return -1;
  }
  if (st.st_uid != getuid()) {
    log(LOG_WARN, "%s is not owned by this UID (%d)", dirname, getuid());
    return -1;
  }
  if (st.st_mode & 0077) {
    log(LOG_WARN, "Fixing permissions on directory %s", dirname);
    if (chmod(dirname, 0700)) {
      log(LOG_WARN, "Could not chmod directory %s: %s", dirname, 
          strerror(errno));
      return -1;
    } else {
      return 0;
    }
  }
  return 0;
}

int
write_str_to_file(const char *fname, const char *str)
{
  char tempname[1024];
  int fd;
  FILE *file;
  if (strlen(fname) > 1000) {
    log(LOG_WARN, "Filename %s is too long.", fname);
    return -1;
  }
  strcpy(tempname,fname);
  strcat(tempname,".tmp");
  if ((fd = open(tempname, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
    log(LOG_WARN, "Couldn't open %s for writing: %s", tempname, 
        strerror(errno));
    return -1;
  }
  if (!(file = fdopen(fd, "w"))) {
    log(LOG_WARN, "Couldn't fdopen %s for writing: %s", tempname, 
        strerror(errno));
    close(fd); return -1;
  }
  if (fputs(str,file) == EOF) {
    log(LOG_WARN, "Error writing to %s: %s", tempname, strerror(errno));
    fclose(file); return -1;
  }
  fclose(file);
  if (rename(tempname, fname)) {
    log(LOG_WARN, "Error replacing %s: %s", fname, strerror(errno));
    return -1;
  }
  return 0;
}

char *read_file_to_str(const char *filename) {
  int fd; /* router file */
  struct stat statbuf;
  char *string;

  assert(filename);

  if(strcspn(filename,CONFIG_LEGAL_FILENAME_CHARACTERS) != 0) {
    log_fn(LOG_WARN,"Filename %s contains illegal characters.",filename);
    return NULL;
  }
  
  if(stat(filename, &statbuf) < 0) {
    log_fn(LOG_INFO,"Could not stat %s.",filename);
    return NULL;
  }

  fd = open(filename,O_RDONLY,0);
  if (fd<0) {
    log_fn(LOG_WARN,"Could not open %s.",filename);
    return NULL;
  }

  string = tor_malloc(statbuf.st_size+1);

  if(read_all(fd,string,statbuf.st_size) != statbuf.st_size) {
    log_fn(LOG_WARN,"Couldn't read all %ld bytes of file '%s'.",
           (long)statbuf.st_size,filename);
    free(string);
    close(fd);
    return NULL;
  }
  close(fd);
  
  string[statbuf.st_size] = 0; /* null terminate it */
  return string;
}

/* read lines from f (no more than maxlen-1 bytes each) until we
 * get one with a well-formed "key value".
 * point *key to the first word in line, point *value to the second.
 * Put a \0 at the end of key, remove everything at the end of value
 * that is whitespace or comment.
 * Return 1 if success, 0 if no more lines, -1 if error.
 */
int parse_line_from_file(char *line, int maxlen, FILE *f, char **key_out, char **value_out) {
  char *s, *key, *end, *value;

try_next_line:
  if(!fgets(line, maxlen, f)) {
    if(feof(f))
      return 0;
    return -1; /* real error */
  }

  if((s = strchr(line,'#'))) /* strip comments */
    *s = 0; /* stop the line there */

  /* remove end whitespace */
  s = strchr(line, 0); /* now we're at the null */
  do {
    *s = 0;
    s--;
  } while (isspace(*s));

  key = line;
  while(isspace(*key))
    key++;
  if(*key == 0)
    goto try_next_line; /* this line has nothing on it */
  end = key;
  while(*end && !isspace(*end))
    end++;
  value = end;
  while(*value && isspace(*value))
    value++;

  if(!*end || !*value) { /* only a key on this line. no value. */
    log_fn(LOG_WARN,"Line has keyword '%s' but no value. Skipping.",s);
    goto try_next_line;
  }
  *end = 0; /* null it out */

  log_fn(LOG_DEBUG,"got keyword '%s', value '%s'", key, value);
  *key_out = key, *value_out = value;
  return 1;
}

static char uname_result[256];
static int uname_result_is_set = 0;

const char *
get_uname(void)
{
#ifdef HAVE_UNAME
  struct utsname u;
#endif
  if (!uname_result_is_set) {
#ifdef HAVE_UNAME
    if (!uname((&u))) {
      snprintf(uname_result, 255, "%s %s %s %s %s",
               u.sysname, u.nodename, u.release, u.version, u.machine);
      uname_result[255] = '\0';
    } else 
#endif
      {
        strcpy(uname_result, "Unknown platform");
      }
    uname_result_is_set = 1;
  }
  return uname_result;
}
      
