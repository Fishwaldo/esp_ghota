/**
 * \file            lwjson_stream.c
 * \brief           Lightweight JSON format parser
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
#include <string.h>
#include "lwjson.h"

#if defined(LWJSON_DEV)
#include <stdio.h>
#define DEBUG_STRING_PREFIX_SPACES                                                                                     \
    "                                                                                                "
#define LWJSON_DEBUG(jsp, ...)                                                                                         \
    do {                                                                                                               \
        if ((jsp) != NULL) {                                                                                           \
            printf("%.*s", (int)(4 * (jsp)->stack_pos), DEBUG_STRING_PREFIX_SPACES);                                   \
        }                                                                                                              \
        printf(__VA_ARGS__);                                                                                           \
    } while (0)

/* Strings for debug */
static const char* type_strings[] = {
    [LWJSON_STREAM_TYPE_NONE] = "none",
    [LWJSON_STREAM_TYPE_OBJECT] = "object",
    [LWJSON_STREAM_TYPE_OBJECT_END] = "object_end",
    [LWJSON_STREAM_TYPE_ARRAY] = "array",
    [LWJSON_STREAM_TYPE_ARRAY_END] = "array_end",
    [LWJSON_STREAM_TYPE_KEY] = "key",
    [LWJSON_STREAM_TYPE_STRING] = "string",
    [LWJSON_STREAM_TYPE_TRUE] = "true",
    [LWJSON_STREAM_TYPE_FALSE] = "false",
    [LWJSON_STREAM_TYPE_NULL] = "null",
    [LWJSON_STREAM_TYPE_NUMBER] = "number",
};
#else
#define LWJSON_DEBUG(jsp, ...)
#endif /* defined(LWJSON_DEV) */

/**
 * \brief           Sends an event to user for further processing
 * 
 */
#define SEND_EVT(jsp, type)                                                                                            \
    if ((jsp) != NULL && (jsp)->evt_fn != NULL) {                                                                      \
        (jsp)->evt_fn((jsp), (type));                                                                                  \
    }

/**
 * \brief           Check if character is a space character (with extended chars)
 * \param[in]       c: Character to check
 * \return          `1` if considered extended space, `0` otherwise
 */
#define prv_is_space_char_ext(c) ((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n' || (c) == '\f')

/**
 * \brief           Push "parent" state to the artificial stack
 * \param           jsp: JSON stream parser instance
 * \param           type: Stream type to be pushed on stack
 * \return          `1` on success, `0` otherwise
 */
static uint8_t
prv_stack_push(lwjson_stream_parser_t* jsp, lwjson_stream_type_t type) {
    if (jsp->stack_pos < LWJSON_ARRAYSIZE(jsp->stack)) {
        jsp->stack[jsp->stack_pos].type = type;
        jsp->stack[jsp->stack_pos].meta.index = 0;
        LWJSON_DEBUG(jsp, "Pushed to stack: %s\r\n", type_strings[type]);
        jsp->stack_pos++;
        return 1;
    }
    return 0;
}

/**
 * \brief           Pop value from stack (remove it) and return its value
 * \param           jsp: JSON stream parser instance
 * \return          Member of \ref lwjson_stream_type_t enumeration 
 */
static lwjson_stream_type_t
prv_stack_pop(lwjson_stream_parser_t* jsp) {
    if (jsp->stack_pos > 0) {
        lwjson_stream_type_t t = jsp->stack[--jsp->stack_pos].type;
        jsp->stack[jsp->stack_pos].type = LWJSON_STREAM_TYPE_NONE;
        LWJSON_DEBUG(jsp, "Popped from stack: %s\r\n", type_strings[t]);

        /* Take care of array to indicate number of entries */
        if (jsp->stack_pos > 0 && jsp->stack[jsp->stack_pos - 1].type == LWJSON_STREAM_TYPE_ARRAY) {
            jsp->stack[jsp->stack_pos - 1].meta.index++;
        }
        return t;
    }
    return LWJSON_STREAM_TYPE_NONE;
}

/**
 * \brief           Get top type value currently on the stack
 * \param           jsp: JSON stream parser instance
 * \return          Member of \ref lwjson_stream_type_t enumeration 
 */
static lwjson_stream_type_t
prv_stack_get_top(lwjson_stream_parser_t* jsp) {
    if (jsp->stack_pos > 0) {
        return jsp->stack[jsp->stack_pos - 1].type;
    }
    return LWJSON_STREAM_TYPE_NONE;
}

/**
 * \brief           Initialize LwJSON stream object before parsing takes place
 * \param[in,out]   jsp: Stream JSON structure 
 * \return          \ref lwjsonOK on success, member of \ref lwjsonr_t otherwise
 */
lwjsonr_t
lwjson_stream_init(lwjson_stream_parser_t* jsp, lwjson_stream_parser_callback_fn evt_fn) {
    memset(jsp, 0x00, sizeof(*jsp));
    jsp->parse_state = LWJSON_STREAM_STATE_WAITINGFIRSTCHAR;
    jsp->evt_fn = evt_fn;
    return lwjsonOK;
}

/**
 * \brief           Reset LwJSON stream structure
 * 
 * \param           jsp: LwJSON stream parser
 * \return          \ref lwjsonOK on success, member of \ref lwjsonr_t otherwise
 */
lwjsonr_t
lwjson_stream_reset(lwjson_stream_parser_t* jsp) {
    jsp->parse_state = LWJSON_STREAM_STATE_WAITINGFIRSTCHAR;
    jsp->stack_pos = 0;
    return lwjsonOK;
}

/**
 * \brief           Parse JSON string in streaming mode
 * \param[in,out]   jsp: Stream JSON structure 
 * \param[in]       c: Character to parse
 * \return          \ref lwjsonOK if parsing is in progress and no hard error detected
 *                  \ref lwjsonSTREAMDONE when valid JSON was detected and stack level reached back `0` level
 */
lwjsonr_t
lwjson_stream_parse(lwjson_stream_parser_t* jsp, char c) {
    /* Get first character first */
    if (jsp->parse_state == LWJSON_STREAM_STATE_WAITINGFIRSTCHAR && c != '{' && c != '[') {
        return lwjsonSTREAMDONE;
    }

start_over:
    /*
     * Determine what to do from parsing state
     */
    switch (jsp->parse_state) {

        /*
         * Waiting for very first valid characters,
         * that is used to indicate start of JSON stream
         */
        case LWJSON_STREAM_STATE_WAITINGFIRSTCHAR:
        case LWJSON_STREAM_STATE_PARSING: {
            /* Determine start of object or an array */
            if (c == '{' || c == '[') {
                /* Reset stack pointer if this character came from waiting for first character */
                if (jsp->parse_state == LWJSON_STREAM_STATE_WAITINGFIRSTCHAR) {
                    jsp->stack_pos = 0;
                }
                if (!prv_stack_push(jsp, c == '{' ? LWJSON_STREAM_TYPE_OBJECT : LWJSON_STREAM_TYPE_ARRAY)) {
                    LWJSON_DEBUG(jsp, "Cannot push object/array to stack\r\n");
                    return lwjsonERRMEM;
                }
                jsp->parse_state = LWJSON_STREAM_STATE_PARSING;
                SEND_EVT(jsp, c == '{' ? LWJSON_STREAM_TYPE_OBJECT : LWJSON_STREAM_TYPE_ARRAY);

                /* Determine end of object or an array */
            } else if (c == '}' || c == ']') {
                lwjson_stream_type_t t = prv_stack_get_top(jsp);

                /* 
                 * If it is a key last entry on closing area,
                 * it is an error - an example: {"key":}
                 */
                if (t == LWJSON_STREAM_TYPE_KEY) {
                    LWJSON_DEBUG(jsp, "ERROR - key should not be followed by ] without value for a key\r\n");
                    return lwjsonERRJSON;
                }

                /*
                 * Check if closing character matches stack value
                 * Avoid cases like: {"key":"value"] or ["v1", "v2", "v3"}
                 */
                if ((c == '}' && t != LWJSON_STREAM_TYPE_OBJECT) || (c == ']' && t != LWJSON_STREAM_TYPE_ARRAY)) {
                    LWJSON_DEBUG(jsp, "ERROR - closing character '%c' does not match stack element \"%s\"\r\n", c,
                                 type_strings[t]);
                    return lwjsonERRJSON;
                }

                /* Now remove the array or object from stack */
                if (prv_stack_pop(jsp) == LWJSON_STREAM_TYPE_NONE) {
                    return lwjsonERRJSON;
                }

                /*
                 * Check if above is a key type
                 * and remove it too as we finished with processing of potential case.
                 * 
                 * {"key":{"abc":1}} - remove "key" part
                 */
                if (prv_stack_get_top(jsp) == LWJSON_STREAM_TYPE_KEY) {
                    prv_stack_pop(jsp);
                }
                SEND_EVT(jsp, c == '}' ? LWJSON_STREAM_TYPE_OBJECT_END : LWJSON_STREAM_TYPE_ARRAY_END);

                /* If that is the end of JSON */
                if (jsp->stack_pos == 0) {
                    return lwjsonSTREAMDONE;
                }

                /* Determine start of string - can be key or regular string (in array or after key) */
            } else if (c == '"') {
#if defined(LWJSON_DEV)
                lwjson_stream_type_t t = prv_stack_get_top(jsp);
                if (t == LWJSON_STREAM_TYPE_OBJECT) {
                    LWJSON_DEBUG(jsp, "Start of string parsing - expected key name in an object\r\n");
                } else if (t == LWJSON_STREAM_TYPE_KEY) {
                    LWJSON_DEBUG(jsp,
                                 "Start of string parsing - string value associated to previous key in an object\r\n");
                } else if (t == LWJSON_STREAM_TYPE_ARRAY) {
                    LWJSON_DEBUG(jsp, "Start of string parsing - string entry in an array\r\n");
                }
#endif /* defined(LWJSON_DEV) */
                jsp->parse_state = LWJSON_STREAM_STATE_PARSING_STRING;
                memset(&jsp->data.str, 0x00, sizeof(jsp->data.str));

                /* Check for end of key character */
            } else if (c == ':') {
                lwjson_stream_type_t t = prv_stack_get_top(jsp);

                /*
                 * Color can only be followed by key on the stack
                 * 
                 * It is clear JSON error if this is not the case
                 */
                if (t != LWJSON_STREAM_TYPE_KEY) {
                    LWJSON_DEBUG(jsp, "Error - wrong ':' character\r\n");
                    return lwjsonERRJSON;
                }
                /* Check if this is start of number or "true", "false" or "null" */
            } else if (c == '-' || (c >= '0' && c <= '9') || c == 't' || c == 'f' || c == 'n') {
                LWJSON_DEBUG(jsp, "Start of primitive parsing parsing - %s, First char: %c\r\n",
                             (c == '-' || (c >= '0' && c <= '9')) ? "number" : "true,false,null", c);
                jsp->parse_state = LWJSON_STREAM_STATE_PARSING_PRIMITIVE;
                memset(&jsp->data.prim, 0x00, sizeof(jsp->data.prim));
                jsp->data.prim.buff[jsp->data.prim.buff_pos++] = c;
            }
            break;
        }

        /*
         * Parse any type of string in a sequence
         *
         * It is used for key or string in an object or an array
         */
        case LWJSON_STREAM_STATE_PARSING_STRING: {
            lwjson_stream_type_t t = prv_stack_get_top(jsp);

            /* 
             * Quote character may trigger end of string, 
             * or if backslasled before - it is part of string
             * 
             * TODO: Handle backslash
             */
            if (c == '"' && jsp->prev_c != '\\') {
#if defined(LWJSON_DEV)
                if (t == LWJSON_STREAM_TYPE_OBJECT) {
                    LWJSON_DEBUG(jsp, "End of string parsing - object key name: \"%s\"\r\n", jsp->data.str.buff);
                } else if (t == LWJSON_STREAM_TYPE_KEY) {
                    LWJSON_DEBUG(
                        jsp, "End of string parsing - string value associated to previous key in an object: \"%s\"\r\n",
                        jsp->data.str.buff);
                } else if (t == LWJSON_STREAM_TYPE_ARRAY) {
                    LWJSON_DEBUG(jsp, "End of string parsing - an array string entry: \"%s\"\r\n", jsp->data.str.buff);
                }
#endif /* defined(LWJSON_DEV) */

                /* Set is_last to 1 as this is the last part of this string token */
                jsp->data.str.is_last = 1;

                /*
                 * When top of stack is object - string is treated as a key
                 * When top of stack is a key - string is a value for a key - notify user and pop the value for key
                 * When top of stack is an array - string is one type - notify user and don't do anything
                 */
                if (t == LWJSON_STREAM_TYPE_OBJECT) {
                    SEND_EVT(jsp, LWJSON_STREAM_TYPE_KEY);
                    if (prv_stack_push(jsp, LWJSON_STREAM_TYPE_KEY)) {
                        size_t len = jsp->data.str.buff_pos;
                        if (len > (sizeof(jsp->stack[0].meta.name) - 1)) {
                            len = sizeof(jsp->stack[0].meta.name) - 1;
                        }
                        memcpy(jsp->stack[jsp->stack_pos - 1].meta.name, jsp->data.str.buff, len);
                        jsp->stack[jsp->stack_pos - 1].meta.name[len] = '\0';
                    } else {
                        LWJSON_DEBUG(jsp, "Cannot push key to stack\r\n");
                        return lwjsonERRMEM;
                    }
                } else if (t == LWJSON_STREAM_TYPE_KEY) {
                    SEND_EVT(jsp, LWJSON_STREAM_TYPE_STRING);
                    prv_stack_pop(jsp);
                    /* Next character to wait for is either space or comma or end of object */
                } else if (t == LWJSON_STREAM_TYPE_ARRAY) {
                    SEND_EVT(jsp, LWJSON_STREAM_TYPE_STRING);
                    jsp->stack[jsp->stack_pos - 1].meta.index++;
                }
                jsp->parse_state = LWJSON_STREAM_STATE_PARSING;
            } else {
                /* TODO: Check other backslash elements */
                jsp->data.str.buff[jsp->data.str.buff_pos++] = c;
                jsp->data.str.buff_total_pos++;

                /* Handle buffer "overflow" */
                if (jsp->data.str.buff_pos >= (LWJSON_CFG_STREAM_STRING_MAX_LEN - 1)) {
                    jsp->data.str.buff[jsp->data.str.buff_pos] = '\0';

                    /* 
                     * - For array or key types - following one is always string
                     * - For object type - character is key
                     */
                    SEND_EVT(jsp, (t == LWJSON_STREAM_TYPE_KEY || t == LWJSON_STREAM_TYPE_ARRAY)
                                      ? LWJSON_STREAM_TYPE_STRING
                                      : LWJSON_STREAM_TYPE_KEY);
                    jsp->data.str.buff_pos = 0;
                }
            }
            break;
        }

        /*
         * Parse any type of primitive that is not a string.
         *
         * true, false, null or any number primitive
         */
        case LWJSON_STREAM_STATE_PARSING_PRIMITIVE: {
            /* Any character except space, comma, or end of array/object are valid */
            if (!prv_is_space_char_ext(c) && c != ',' && c != ']' && c != '}') {
                if (jsp->data.prim.buff_pos < sizeof(jsp->data.prim.buff) - 1) {
                    jsp->data.prim.buff[jsp->data.prim.buff_pos++] = c;
                }
            } else {
                lwjson_stream_type_t t = prv_stack_get_top(jsp);

#if defined(LWJSON_DEV)
                if (t == LWJSON_STREAM_TYPE_OBJECT) {
                    /* TODO: Handle error - primitive cannot be just after object */
                } else if (t == LWJSON_STREAM_TYPE_KEY) {
                    LWJSON_DEBUG(
                        jsp,
                        "End of primitive parsing - string value associated to previous key in an object: \"%s\"\r\n",
                        jsp->data.prim.buff);
                } else if (t == LWJSON_STREAM_TYPE_ARRAY) {
                    LWJSON_DEBUG(jsp, "End of primitive parsing - an array string entry: \"%s\"\r\n",
                                 jsp->data.prim.buff);
                }
#endif /* defined(LWJSON_DEV) */

                /*
                 * This is the end of primitive parsing
                 *
                 * It is assumed that buffer for primitive can handle at least
                 * true, false, null or all number characters (that being real or int number)
                 */
                if (jsp->data.prim.buff_pos == 4 && strncmp(jsp->data.prim.buff, "true", 4) == 0) {
                    LWJSON_DEBUG(jsp, "Primitive parsed as %s\r\n", "true");
                    SEND_EVT(jsp, LWJSON_STREAM_TYPE_TRUE);
                } else if (jsp->data.prim.buff_pos == 4 && strncmp(jsp->data.prim.buff, "null", 4) == 0) {
                    LWJSON_DEBUG(jsp, "Primitive parsed as %s\r\n", "null");
                    SEND_EVT(jsp, LWJSON_STREAM_TYPE_NULL);
                } else if (jsp->data.prim.buff_pos == 5 && strncmp(jsp->data.prim.buff, "false", 5) == 0) {
                    LWJSON_DEBUG(jsp, "Primitive parsed as %s\r\n", "false");
                    SEND_EVT(jsp, LWJSON_STREAM_TYPE_FALSE);
                } else if (jsp->data.prim.buff[0] == '-'
                           || (jsp->data.prim.buff[0] >= '0' && jsp->data.prim.buff[0] <= '9')) {
                    LWJSON_DEBUG(jsp, "Primitive parsed - number\r\n");
                    SEND_EVT(jsp, LWJSON_STREAM_TYPE_NUMBER);
                } else {
                    LWJSON_DEBUG(jsp, "Invalid primitive type. Got: %s\r\n", jsp->data.prim.buff);
                }
                if (t == LWJSON_STREAM_TYPE_KEY) {
                    prv_stack_pop(jsp);
                } else if (t == LWJSON_STREAM_TYPE_ARRAY) {
                    jsp->stack[jsp->stack_pos - 1].meta.index++;
                }

                /* 
                 * Received character is not part of the primitive and must be processed again
                 * 
                 * Set state to default state and start from beginning
                 */
                jsp->parse_state = LWJSON_STREAM_STATE_PARSING;
                goto start_over;
            }
            break;
        }

        /* TODO: Add other case statements */
        default:
            break;
    }
    jsp->prev_c = c; /* Save current c as previous for next round */
    return lwjsonSTREAMINPROG;
}
