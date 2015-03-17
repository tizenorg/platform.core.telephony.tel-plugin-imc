/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hayoon Ko <hayoon.ko@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __IMC_COMMON_H__
#define __IMC_COMMON_H__

#include <glib.h>

void util_hex_dump(char *pad, int size, const void *data);
unsigned char util_hexCharToInt(char c);
char *util_hex_to_string(const char *src, unsigned int src_len);
char* util_hexStringToBytes(char *s);
char* util_removeQuotes(void *data);

#endif	// __IMC_COMMON_H__