int sendmessage(int s, char *buf, size_t buflen, const char *format, ...);
int receive(int s, char **inbuf,size_t *inbuflen, int flags);
