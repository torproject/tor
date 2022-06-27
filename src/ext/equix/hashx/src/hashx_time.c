/* Copyright (c) 2020 tevador <tevador@gmail.com> */
/* See LICENSE for licensing information */

#include "hashx_time.h"
#include <hashx.h>

#if defined(HASHX_WIN)
#include <windows.h>
#else
#include <sys/time.h>
#endif

double hashx_time() {
#ifdef HASHX_WIN
	static double freq = 0;
	if (freq == 0) {
		LARGE_INTEGER freq_long;
		if (!QueryPerformanceFrequency(&freq_long)) {
			return 0;
		}
		freq = freq_long.QuadPart;
	}
	LARGE_INTEGER time;
	if (!QueryPerformanceCounter(&time)) {
		return 0;
	}
	return time.QuadPart / freq;
#else
	struct timeval time;
	if (gettimeofday(&time, NULL) != 0) {
		return 0;
	}
	return (double)time.tv_sec + (double)time.tv_usec * 1.0e-6;
#endif
}
