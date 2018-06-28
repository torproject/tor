/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_WINLIB_H
#define TOR_WINLIB_H

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>

HANDLE load_windows_system_library(const TCHAR *library_name);
#endif

#endif
