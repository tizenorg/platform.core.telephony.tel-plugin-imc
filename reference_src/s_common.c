/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Ja-young Gu <jygu@samsung.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <glib.h>
#include <log.h>


#include "s_common.h"

#undef  MAX
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

#undef  MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define bitsize(type) (sizeof(type) * 8)

#define copymask(type) ((0xffffffff) >> (32 - bitsize(type)))

#define MASK(width, offset, data) \
	(((width) == bitsize(data)) ? (data) :	 \
	 ((((copymask(data) << (bitsize(data) - ((width) % bitsize(data)))) & copymask(data)) >> (offset)) & (data))) \


#define MASK_AND_SHIFT(width, offset, shift, data)	\
	((((signed) (shift)) < 0) ?		  \
	 MASK((width), (offset), (data)) << -(shift) :	\
	 MASK((width), (offset), (data)) >> (((signed) (shift)))) \

char _util_unpackb(const char *src, int pos, int len);
char _util_convert_byte_hexChar(char val);
gboolean util_byte_to_hex(const char *byte_pdu, char *hex_pdu, int num_bytes);

void util_hex_dump(char *pad, int size, const void *data)
{
	char buf[255] = {0, };
	char hex[4] = {0, };
	int i;
	unsigned char *p;

	if (size <= 0) {
		msg("%sno data", pad);
		return;
	}

	p = (unsigned char *) data;

	snprintf(buf, 255, "%s%04X: ", pad, 0);
	for (i = 0; i < size; i++) {
		snprintf(hex, 4, "%02X ", p[i]);
		strcat(buf, hex);

		if ((i + 1) % 8 == 0) {
			if ((i + 1) % 16 == 0) {
				msg("%s", buf);
				memset(buf, 0, 255);
				snprintf(buf, 255, "%s%04X: ", pad, i + 1);
			} else {
				strcat(buf, "  ");
			}
		}
	}

	msg("%s", buf);
}

unsigned char util_hexCharToInt(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	else if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	else if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	else {
		dbg("invalid charater!!");
		return -1;
	}
}

char *util_hex_to_string(const char *src, unsigned int src_len)
{
	char *dest;
	int i;

	if (src == NULL)
		return NULL;

	dest = g_malloc0(src_len * 2 + 1);
	for (i = 0; i < src_len; i++) {
		sprintf(dest + (i * 2), "%02x", (unsigned char)src[i]);
	}

	dest[src_len * 2] = '\0';

	return dest;
}

char* util_hexStringToBytes(char *s)
{
	char *ret;
	int i;
	int sz;

	if (s == NULL)
		return NULL;

	sz = strlen(s);

	ret = g_try_malloc0((sz / 2) + 1);

	dbg("Convert String to Binary!!");

	for (i = 0; i < sz; i += 2) {
		ret[i / 2] = (char) ((util_hexCharToInt(s[i]) << 4) | util_hexCharToInt(s[i + 1]));
		msg("		[%02x]", ret[i / 2]);
	}

	return ret;
}

char _util_unpackb(const char *src, int pos, int len)
{
	char result = 0;
	int rshift = 0;

	src += pos / 8;
	pos %= 8;

	rshift = MAX(8 - (pos + len), 0);

	if (rshift > 0) {
		result = MASK_AND_SHIFT(len, pos, rshift, (unsigned char)*src);
	} else {
		result = MASK(8 - pos, pos, (unsigned char)*src);
		src++;
		len -= 8 - pos;

		if (len > 0) result = (result << len) | (*src >> (8 - len));   // if any bits left
	}

	return result;
}

char _util_convert_byte_hexChar(char val)
{
	char hex_char;

	if (val <= 9) {
		hex_char = (char) (val + '0');
	} else if (val >= 10 && val <= 15) {
		hex_char = (char) (val - 10 + 'A');
	} else {
		hex_char = '0';
	}

	return (hex_char);
}

gboolean util_byte_to_hex(const char *byte_pdu, char *hex_pdu, int num_bytes)
{
	int i;
	char nibble;
	int buf_pos = 0;

	for (i = 0; i < num_bytes * 2; i++) {
		nibble = _util_unpackb(byte_pdu, buf_pos, 4);
		buf_pos += 4;
		hex_pdu[i] = _util_convert_byte_hexChar(nibble);
	}

	return TRUE;
}

char* util_removeQuotes(void *data)
{
	char *tmp = NULL;
	int data_len = 0;

	data_len = strlen((const char *) data);
	dbg("data_len: %d----%s", data_len, data);
	if (data_len <= 0) {
		return NULL;
	}

	tmp = g_try_malloc0(data_len - 1);
	memcpy(tmp, data + 1, data_len - 2);
	dbg("tmp: [%s]", tmp);

	return tmp;
}
