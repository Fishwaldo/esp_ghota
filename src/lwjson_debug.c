/**
 * \file            lwjson_debug.c
 * \brief           Debug and print function for tokens
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
#include <stdio.h>
#include <string.h>
#include "lwjson.h"

/**
 * \brief           Token print instance
 */
typedef struct {
    size_t indent; /*!< Indent level for token print */
} lwjson_token_print_t;

/**
 * \brief           Print token value
 * \param[in]       p: Token print instance
 * \param[in]       token: Token to print
 */
static void
prv_print_token(lwjson_token_print_t* p, const lwjson_token_t* token) {
#define print_indent() printf("%.*s", (int)((p->indent)), "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t");

    if (token == NULL) {
        return;
    }

    /* Check if token has a name */
    print_indent();
    if (token->token_name != NULL) {
        printf("\"%.*s\":", (int)token->token_name_len, token->token_name);
    }

    /* Print different types */
    switch (token->type) {
        case LWJSON_TYPE_OBJECT:
        case LWJSON_TYPE_ARRAY: {
            printf("%c", token->type == LWJSON_TYPE_OBJECT ? '{' : '[');
            if (token->u.first_child != NULL) {
                printf("\n");
                ++p->indent;
                for (const lwjson_token_t* t = lwjson_get_first_child(token); t != NULL; t = t->next) {
                    prv_print_token(p, t);
                }
                --p->indent;
                print_indent();
            }
            printf("%c", token->type == LWJSON_TYPE_OBJECT ? '}' : ']');
            break;
        }
        case LWJSON_TYPE_STRING: {
            printf("\"%.*s\"", (int)lwjson_get_val_string_length(token), lwjson_get_val_string(token, NULL));
            break;
        }
        case LWJSON_TYPE_NUM_INT: {
            printf("%lld", (long long)lwjson_get_val_int(token));
            break;
        }
        case LWJSON_TYPE_NUM_REAL: {
            printf("%f", (double)lwjson_get_val_real(token));
            break;
        }
        case LWJSON_TYPE_TRUE: {
            printf("true");
            break;
        }
        case LWJSON_TYPE_FALSE: {
            printf("false");
            break;
        }
        case LWJSON_TYPE_NULL: {
            printf("NULL");
            break;
        }
        default:
            break;
    }
    if (token->next != NULL) {
        printf(",");
    }
    printf("\n");
}

/**
 * \brief           Prints and outputs token data to the stream output
 * \note            This function is not re-entrant
 * \param[in]       token: Token to print
 */
void
lwjson_print_token(const lwjson_token_t* token) {
    lwjson_token_print_t p = {0};
    prv_print_token(&p, token);
}

/**
 * \brief           Prints and outputs full parsed LwJSON instance
 * \note            This function is not re-entrant
 * \param[in]       lw: LwJSON instance to print
 */
void
lwjson_print_json(const lwjson_t* lw) {
    lwjson_token_print_t p = {0};
    prv_print_token(&p, lwjson_get_first_token(lw));
}
