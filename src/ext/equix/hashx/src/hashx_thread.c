/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#include "hashx_thread.h"

hashx_thread hashx_thread_create(hashx_thread_func* func, void* args) {
#ifdef HASHX_WIN
	return CreateThread(NULL, 0, func, args, 0, NULL);
#else
	hashx_thread thread;
	if (pthread_create(&thread, NULL, func, args) != 0)
	{
		thread = 0;
	}
	return thread;
#endif
}

void hashx_thread_join(hashx_thread thread) {
#ifdef HASHX_WIN
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
#else
	void* retval;
	pthread_join(thread, &retval);
#endif
}
