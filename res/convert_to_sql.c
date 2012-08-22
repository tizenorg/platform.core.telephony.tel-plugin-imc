/**
 * tel-plugin-samsung
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Ja-young Gu <jygu@samsung.com>
 *
 * PROPRIETARY/CONFIDENTIAL
 *
 * This software is the confidential and proprietary information of SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall
 * use it only in accordance with the terms of the license agreement you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability
 * of the software, either express or implied, including but not
 * limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement.
 * SAMSUNG shall not be liable for any damages suffered by licensee as
 * a result of using, modifying or distributing this software or its derivatives.
 */

#include <stdio.h>
#include <string.h>

#define TABLE_NAME "mcc_mnc_oper_list"
#define TABLE_SCHEMA "create table " TABLE_NAME " (id integer primary key, country char(3), mcc integer, mnc char(3), oper char(45));"

#define dbg(fmt,args...) fprintf(stderr, fmt, ##args);

int main(int argc, char *argv[])
{
	FILE *fp_in;

	char buf[255];
	char brand[255];
	char oper[255];
	char *pos1, *pos2;
	char country[10];
	char mnc[10];
	char *oper_select;
	int mcc;

	if (argc != 2) {
		printf("%s filename.csv\n", argv[0]);
		return -1;
	}

	fp_in = fopen(argv[1], "r");
	if (fp_in == NULL) {
		printf("faild.\n");
		return -1;
	}

	printf("%s\n", TABLE_SCHEMA);

	printf("BEGIN;\n");
	while (1) {
		fgets (buf, 255, fp_in);

		if (feof(fp_in))  {
			break;
		}

		// remove '\n'
		buf[strlen(buf)-1] = '\0';

		dbg("\n%s\n", buf);

		pos1 = strchr (buf, ',');
		memset (country, 0, 10);
		memcpy(country, buf, pos1-buf);

		dbg("country=[%s]\n", country);

		sscanf (pos1+1, "%d", &mcc);
		dbg("mcc=[%d]\n", mcc);

		// get mnc
		pos1 = strchr (pos1+1, ',');
		pos2 = strchr (pos1+1, ',');

		dbg("mnc=[%s]\n", pos1+1);

		memset (mnc, 0, 10);
		strncpy (mnc, pos1+1, pos2-pos1-1);

		// get brand
		pos1 = pos2;
		pos2 = strchr (pos1+1, ',');

		dbg("brand=[%s]\n", pos1+1);

		memset (brand, 0, 255);
		strncpy (brand, pos1+1, pos2-pos1-1);

		// get oper
		pos1 = pos2;
		pos2 = strchr (pos1+1, ',');

		dbg("oper=[%s]\n", pos1+1);

		memset (oper, 0, 255);
		strcpy (oper, pos1+1);

		oper_select = brand;
		if (strlen(brand) == 0)
			oper_select = oper;

		if (oper_select[0] == '\"') {
			memset(buf, 0, 255);
			snprintf(buf, strlen(oper_select)-2, "%s", oper_select+1);
			snprintf(oper_select, 255, "%s", buf);
		}

		snprintf(buf, 255, "insert into %s "
				" (country, mcc, mnc, oper) "
				" values (\"%s\", %d, \"%s\", \"%s\");",
				TABLE_NAME, country, mcc, mnc, oper_select);
		printf("%s\n",buf);
	}
	printf("COMMIT;\n");

	fclose(fp_in);
}
