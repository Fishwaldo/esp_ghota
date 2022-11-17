/**
 * \file            lwjson_opt.h
 * \brief           LwJSON options
 */

/*
 * Copyright (c) 2022 Tilen MAJERLE
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * This file is part of LwJSON - Lightweight JSON format parser.
 *
 * Author:          Tilen MAJERLE <tilen@majerle.eu>
 * Version:         v1.5.0
 */
#ifndef LWJSON_HDR_OPT_H
#define LWJSON_HDR_OPT_H

//#define LWJSON_DEV 1
/* Uncomment to ignore user options (or set macro in compiler flags) */
#define LWJSON_IGNORE_USER_OPTS

/* Include application options */
#ifndef LWJSON_IGNORE_USER_OPTS
#include "lwjson_opts.h"
#endif /* LWJSON_IGNORE_USER_OPTS */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \defgroup        LWJSON_OPT Configuration
 * \brief           LwJSON options
 * \{
 */

/**
 * \brief           Real data type used to parse numbers with floating point number
 * \note            Data type must be signed, normally `float` or `double`
 *
 * This is used for numbers in \ref LWJSON_TYPE_NUM_REAL token data type.
 */
#ifndef LWJSON_CFG_REAL_TYPE
#define LWJSON_CFG_REAL_TYPE float
#endif

/**
 * \brief           Integer type used to parse numbers
 * \note            Data type must be signed integer
 *
 * This is used for numbers in \ref LWJSON_TYPE_NUM_INT token data type.
 */
#ifndef LWJSON_CFG_INT_TYPE
#define LWJSON_CFG_INT_TYPE long long
#endif

/**
 * \brief           Enables `1` or disables `0` support for inline comments
 *
 * Default set to `0` to be JSON compliant
 */
#ifndef LWJSON_CFG_COMMENTS
#define LWJSON_CFG_COMMENTS 0
#endif

/**
 * \defgroup        LWJSON_OPT_STREAM JSON stream
 * \brief           JSON streaming confiuration
 * \{
 */

/**
 * \brief           Max length of token key (object key name) to be available for stack storage
 * 
 */
#ifndef LWJSON_CFG_STREAM_KEY_MAX_LEN
#define LWJSON_CFG_STREAM_KEY_MAX_LEN 32
#endif

/**
 * \brief           Max stack size (depth) in units of \ref lwjson_stream_stack_t structure
 * 
 */
#ifndef LWJSON_CFG_STREAM_STACK_SIZE
#define LWJSON_CFG_STREAM_STACK_SIZE 16
#endif

/**
 * \brief           Max size of string for single parsing in units of bytes
 * 
 */
#ifndef LWJSON_CFG_STREAM_STRING_MAX_LEN
#define LWJSON_CFG_STREAM_STRING_MAX_LEN 256
#endif

/**
 * \brief           Max number of bytes used to parse primitive.
 * 
 * Primitives are all numbers and logical values (null, true, false)
 */
#ifndef LWJSON_CFG_STREAM_PRIMITIVE_MAX_LEN
#define LWJSON_CFG_STREAM_PRIMITIVE_MAX_LEN 32
#endif

/**
 * \}
 */

/**
 * \}
 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LWJSON_HDR_OPT_H */
