/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */



#ifndef GMSSL_ERROR_H
#define GMSSL_ERROR_H


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEBUG 1

#define error_print() \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s():\n",__FILE__, __LINE__, __func__); } while (0)

#define error_print_msg(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, __VA_ARGS__); } while (0)

#define error_puts(str) \
            do { if (DEBUG) fprintf(stderr, "%s: %d: %s: %s", __FILE__, __LINE__, __func__, str); } while (0)

#ifdef __cplusplus
}
#endif
#endif
