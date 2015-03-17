/**
 * tel-plugin-imc
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Ankit Jogi <ankit.jogi@samsung.com>
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
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <tcore.h>
#include <server.h>
#include <core_object.h>
#include <plugin.h>
#include <hal.h>
#include <user_request.h>
#include <at.h>

#include <co_phonebook.h>
#include <co_sim.h>

#include "imc_phonebook.h"

/* Constants */
#define VAL_ZERO	0
#define VAL_ONE		1
#define VAL_TWO		2
#define VAL_THREE	3
#define VAL_FOUR	4
#define VAL_FIVE		5
#define VAL_SIX		6
#define VAL_SEVEN	7
#define VAL_EIGHT	8
#define VAL_NINE	9

/* Type Of Number and Number Plan */
#define IMC_TON_INTERNATIONAL		145
#define IMC_TON_UNKNOWN		129
#define IMC_NUM_PLAN_INTERNATIONAL	0x0070
#define IMC_NUM_PLAN_UNKNOWN		0x0060

#define IMC_PB_INFO_LENGTH		5

typedef struct {
	GSList *used_index_fdn;
	gboolean used_index_fdn_valid;

	GSList *used_index_adn;
	gboolean used_index_adn_valid;

	GSList *used_index_sdn;
	gboolean used_index_sdn_valid;

	GSList *used_index_usim;
	gboolean used_index_usim_valid;
} PrivateInfo;

/******************************************************************************
 * Internal functions
 *****************************************************************************/
static gint __phonebook_compare_index(gconstpointer a, gconstpointer b)
{
	guint index1 = (guint)a;
	guint index2 = (guint)b;

	return index1 - index2;
}

static enum tel_phonebook_field_type __phonebook_convert_field_type(int field_type)
{
	switch (field_type) {
	case 1:
		return PB_FIELD_NUMBER;
	case 2:
		return PB_FIELD_NAME;
	case 3:
		return PB_FIELD_GRP;
	case 4:
		return PB_FIELD_SNE;
	case 5:
		return PB_FIELD_EMAIL1;
	default:
		return 0;
	}
}

static enum tel_phonebook_ton __phonebook_find_num_plan(int number_plan)
{
	enum tel_phonebook_ton result;
	dbg("number_plan : 0x%04x", number_plan);

	if (number_plan & IMC_NUM_PLAN_INTERNATIONAL) {
		result = PB_TON_INTERNATIONAL;
	}
	else {
		result = PB_TON_UNKNOWN;
	}
	dbg("result : %d", result);

	return result;
}

static gboolean __phonebook_get_pb_type_str(enum tel_phonebook_type pb_type,
		gchar **req_type_str)
{
	g_assert(req_type_str != NULL);

	switch (pb_type) {
	case PB_TYPE_FDN:
		*req_type_str = g_strdup("FD");
	break;
	case PB_TYPE_ADN:
	case PB_TYPE_USIM:
		*req_type_str = g_strdup("SM");
	break;
	case PB_TYPE_SDN:
		*req_type_str = g_strdup("SN");
	break;
	default:
		warn("Unsupported Phonebook type");
		*req_type_str = g_strdup("NS");
	break;
	}

	return TRUE;
}

static gboolean __phonebook_check_and_select_type(CoreObject *co,
	enum tel_phonebook_type req_pb_type, gchar **set_pb_cmd)
{
	struct tel_phonebook_support_list *support_list;
	enum tel_phonebook_type current_type;

	/* Check whether pb_type is supported or not */
	support_list = tcore_phonebook_get_support_list(co);
	if (support_list) {
		if ((req_pb_type == PB_TYPE_FDN && support_list->b_fdn == FALSE)
				|| (req_pb_type == PB_TYPE_ADN && support_list->b_adn == FALSE)
				|| (req_pb_type == PB_TYPE_SDN && support_list->b_sdn == FALSE)
				|| (req_pb_type == PB_TYPE_USIM && support_list->b_usim == FALSE)) {
			err("Not supported Phonebook type");

			g_free(support_list);
			return FALSE;
		}
		g_free(support_list);
	}

	/* Check Current type & Request type */
	current_type = tcore_phonebook_get_selected_type(co);
	if (current_type != req_pb_type) {
		gchar *req_pb_type_str = NULL;

		__phonebook_get_pb_type_str(req_pb_type, &req_pb_type_str);
		dbg("Add AT-Command to change [%s] Type", req_pb_type_str);

		/* Select Phonebook type */
		*set_pb_cmd = g_strdup_printf("AT+CPBS=\"%s\";", req_pb_type_str);

		g_free(req_pb_type_str);
	} else {
		*set_pb_cmd = g_strdup_printf("AT");
	}

	return TRUE;
}

static gboolean __phonebook_update_index_list_by_type(CoreObject *co,
	enum tel_phonebook_type pb_type, guint req_index)
{
	GSList *list = NULL;
	PrivateInfo *private_info = tcore_object_ref_user_data(co);
	g_assert(private_info != NULL);

	switch (pb_type) {
	case PB_TYPE_FDN:
		list = private_info->used_index_fdn;
	break;

	case PB_TYPE_ADN:
		list = private_info->used_index_adn;
	break;

	case PB_TYPE_SDN:
		list = private_info->used_index_sdn;
	break;

	case PB_TYPE_USIM:
		list = private_info->used_index_usim;
	break;

	default:
		warn("Unsupported Phonebook type: [%d]", pb_type);
		return FALSE;
	}

	/*
	 * Check if 'index' is already available (UPDATE operation).
	 */
	while (list) {
		if ((guint)list->data == req_index) {
			/*
			 * index 'present', no need to update
			 */
			dbg("Index: [%d] present in Phonebook type: [%d]",
				req_index, pb_type);

			return TRUE;
		}
		list = g_slist_next(list);
	}

	/*
	 * 'index' is NOT available (ADD operation),
	 * insert 'index' to corresponding index list.
	 */
	switch (pb_type) {
	case PB_TYPE_FDN:
		private_info->used_index_fdn = g_slist_insert_sorted(
			private_info->used_index_fdn,
			(gpointer)req_index,
			__phonebook_compare_index);

		/* Update Phonebook list valid */
		if (private_info->used_index_fdn_valid != TRUE)
			private_info->used_index_fdn_valid = TRUE;
	break;

	case PB_TYPE_ADN:
		private_info->used_index_adn = g_slist_insert_sorted(
			private_info->used_index_adn,
			(gpointer)req_index,
			__phonebook_compare_index);

		/* Update Phonebook list valid */
		if (private_info->used_index_adn_valid != TRUE)
			private_info->used_index_adn_valid = TRUE;
	break;

	case PB_TYPE_SDN:
		private_info->used_index_sdn = g_slist_insert_sorted(
			private_info->used_index_sdn,
			(gpointer)req_index,
			__phonebook_compare_index);

		/* Update Phonebook list valid */
		if (private_info->used_index_sdn_valid != TRUE)
			private_info->used_index_sdn_valid = TRUE;
	break;

	case PB_TYPE_USIM:
		private_info->used_index_usim = g_slist_insert_sorted(
			private_info->used_index_usim,
			(gpointer)req_index,
			__phonebook_compare_index);

		/* Update Phonebook list valid */
		if (private_info->used_index_usim_valid != TRUE)
			private_info->used_index_usim_valid = TRUE;
	break;

	default:
		warn("Unexpected Phonebook type: [%d]", pb_type);
		g_assert_not_reached();
	break;
	}

	return TRUE;
}

static gboolean __phonebook_get_index_list_by_type(CoreObject *co,
	enum tel_phonebook_type pb_type, GSList **list)
{
	PrivateInfo *private_info = tcore_object_ref_user_data(co);
	g_assert(private_info != NULL);

	switch (pb_type) {
	case PB_TYPE_FDN:
		if (private_info->used_index_fdn_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_fdn;
	break;

	case PB_TYPE_ADN:
		if (private_info->used_index_adn_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_adn;
	break;

	case PB_TYPE_SDN:
		if (private_info->used_index_sdn_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_sdn;
	break;

	case PB_TYPE_USIM:
		if (private_info->used_index_usim_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_usim;
	break;

	default:
		warn("Unsupported Phonebook type");
		return FALSE;
	break;
	}

	return TRUE;
}

static void __phonebook_check_used_index(CoreObject *co,
	enum tel_phonebook_type pb_type, guint req_index, guint *used_index)
{
	GSList *list = NULL;

	/* Get used_index list by req_type */
	if (__phonebook_get_index_list_by_type(co, pb_type, &list) != TRUE) {
		err("used_index list is NOT valid");
		*used_index = req_index;
		return;
	}

	/* Use first used_index in case req_index is not used */
	*used_index = (guint)g_slist_nth_data(list, VAL_ZERO);
	while (list) {
		if ((guint)list->data == req_index) {
			/*
			 * req_index is equal to one of used_index
			 */
			*used_index = req_index;
			return;
		}
		list = g_slist_next(list);
	}
}

static void __on_resp_phonebook_get_support_list(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;

	CoreObject *co_phonebook = tcore_pending_ref_core_object(p);
	TcorePlugin *plugin = tcore_object_ref_plugin(co_phonebook);

	struct tnoti_phonebook_status noti_data = {0, };

	dbg("Entry");

	noti_data.b_init = FALSE;

	if (resp && resp->success > VAL_ZERO) {
		const char *line;
		char *temp = NULL;

		GSList *tokens = NULL;
		char *pb_type = NULL;

		dbg("RESPONSE OK");

		if (resp->lines == NULL) {
			warn("Invalid notification");
			goto EXIT;
		}

		line = (const char*)resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < VAL_ONE) {
			warn("Invalid notification - 'number' of tokens: [%d]",
				g_slist_length(tokens));

			/* Free resources */
			tcore_at_tok_free(tokens);

			goto EXIT;
		}

		temp = (char*)g_slist_nth_data(tokens, VAL_ZERO);
		pb_type = strtok(temp, "(,)");
		while (pb_type != NULL) {
			temp =  tcore_at_tok_extract(pb_type);
			dbg("pbtype %s", temp);

			if (VAL_ZERO == g_strcmp0(temp, "FD")) {
				dbg("SIM fixed-dialing Phonebook");
				noti_data.support_list.b_fdn = TRUE;
			}
			else if (VAL_ZERO == g_strcmp0(temp, "SN")) {
				dbg("Service Dialing Number");
				noti_data.support_list.b_sdn = TRUE;
			}
			else if (VAL_ZERO == g_strcmp0(temp, "SM")) {
				CoreObject *co_sim = NULL;
				enum tel_sim_type sim_type = SIM_TYPE_UNKNOWN;

				/* Fecth SIM type */
				co_sim = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);
				if (co_sim == NULL) {
					err("SIM Core object is NULL");

					/* Free resources */
					tcore_at_tok_free(tokens);
					g_free(temp);

					goto EXIT;
				}

				sim_type = tcore_sim_get_type(co_sim);
				dbg("SIM type: [%d]", sim_type);
				if (sim_type == SIM_TYPE_USIM) {	/* 3G SIM */
					noti_data.support_list.b_usim = TRUE;
					dbg("3G SIM - USIM Phonebook");
				}
				else {	/* 2G SIM */
					noti_data.support_list.b_adn = TRUE;
					dbg("2G SIM - ADN Phonebook");
				}
			}
			else if (VAL_ZERO == g_strcmp0(temp, "LD")) {
				dbg("SIM/UICC - last-dialling-phonebook");
			}
			else if (VAL_ZERO == g_strcmp0(temp, "ON")) {
				dbg("SIM (or MT) own numbers (MSISDNs) list");
			}
			else if (VAL_ZERO == g_strcmp0(temp, "BL")) {
				dbg("Blacklist phonebook");
			}
			else if (VAL_ZERO == g_strcmp0(temp, "EC")) {
				dbg("SIM emergency-call-codes phonebook");
			}
			else if (VAL_ZERO == g_strcmp0(temp, "AP")) {
				dbg("Selected application phonebook");
			}
			else if (VAL_ZERO == g_strcmp0(temp, "BN")) {
				dbg("SIM barred-dialling-number");
			}

			pb_type = strtok (NULL, "(,)");
			g_free(temp);
		}

		/* Free resources */
		tcore_at_tok_free(tokens);

		dbg("FDN: [%s] ADN: [%s] SDN: [%s] USIM: [%s]",
			noti_data.support_list.b_fdn ? "TRUE" : "FALSE",
			noti_data.support_list.b_adn ? "TRUE" : "FALSE",
			noti_data.support_list.b_sdn ? "TRUE" : "FALSE",
			noti_data.support_list.b_usim ? "TRUE" : "FALSE");

		/* Phonebook initialized */
		noti_data.b_init = TRUE;

		/* Update states */
		tcore_phonebook_set_support_list(co_phonebook, &noti_data.support_list);
		tcore_phonebook_set_status(co_phonebook, noti_data.b_init);
	}
	else {
		dbg("RESPONSE NOK");

		/* Update state */
		tcore_phonebook_set_status(co_phonebook, noti_data.b_init);
	}

EXIT:
	/*
	 * Send notification
	 *
	 * Phonebook status (TNOTI_PHONEBOOK_STATUS)
	 */
	tcore_server_send_notification(tcore_plugin_ref_server(plugin),
		co_phonebook,
		TNOTI_PHONEBOOK_STATUS,
		sizeof(struct tnoti_phonebook_status), &noti_data);

	dbg("Exit");
}

/*
 * Operation - get_support_list
 *
 * Request -
 * AT-Command: AT+CPBS=?
 *
 * Response -
 * Success: (Single line)
 *	(list of supported <storage>s)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static void __phonebook_get_support_list(CoreObject *co_phonebook)
{
	TReturn ret;

	dbg("Entry");

	if (!co_phonebook) {
		err("Core object is NULL");
		return;
	}

	ret = tcore_prepare_and_send_at_request(co_phonebook,
		"AT+CPBS=?", "+CPBS",
		TCORE_AT_SINGLELINE,
		NULL,
		__on_resp_phonebook_get_support_list, NULL,
		NULL, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);
}

static void __on_resp_phonebook_get_used_index(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct tcore_at_response *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);

	g_assert(at_resp != NULL);

	dbg("Entry");

	if (at_resp->success > VAL_ZERO) {
		dbg("Response OK");

		if (at_resp->lines == NULL) {
			err("at_resp->lines is NULL");
		} else {
			GSList *lines = at_resp->lines;
			enum tel_phonebook_type req_pb_type;
			GSList **list = NULL;
			PrivateInfo *private_info = tcore_object_ref_user_data(co);

			g_assert(private_info != NULL);

			req_pb_type = (enum tel_phonebook_type)GPOINTER_TO_INT(user_data);

			/* Select used_index_list by req_type */
			switch (req_pb_type) {
			case PB_TYPE_FDN:
				list = &private_info->used_index_fdn;
				private_info->used_index_fdn_valid = TRUE;
			break;

			case PB_TYPE_ADN:
				list = &private_info->used_index_adn;
				private_info->used_index_adn_valid = TRUE;
			break;

			case PB_TYPE_SDN:
				list = &private_info->used_index_sdn;
				private_info->used_index_sdn_valid = TRUE;
			break;

			case PB_TYPE_USIM:
				list = &private_info->used_index_usim;
				private_info->used_index_usim_valid = TRUE;
			break;

			default:
				warn("Unsupported phonebook: [%d]", req_pb_type);
				return;
			}

			while (lines) {
				const gchar *line = lines->data;
				GSList *tokens = NULL;
				gchar *temp;

				dbg("Line: [%s]", line);

				tokens = tcore_at_tok_new(line);
				if (tokens == NULL) {
					err("tokens is NULL");
					return;
				}

				/* Get only used_index */
				temp = g_slist_nth_data(tokens, VAL_ZERO);
				if (temp) {
					/* Insert used_index in PrivateInfo sorted in ascending */
					*list = g_slist_insert_sorted(*list,
						(gpointer)atoi(temp),
						__phonebook_compare_index);
				}
				tcore_at_tok_free(tokens);

				/* Get next lines */
				lines = g_slist_next(lines);
			}

			dbg("pb_type: [%d], used_index Length: [%d]",
				req_pb_type, g_slist_length(*list));
		}
	}
	else {
		err("Response NOK");
	}
}

static void __phonebook_get_used_index(CoreObject *co,
	enum tel_phonebook_type pb_type, guint max_index)
{
	gchar *at_cmd;
	TReturn ret;

	dbg("Entry");

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CPBR=1,%d", max_index);

	/* Send Request to Modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, "+CPBR",
		TCORE_AT_MULTILINE,
		NULL,
		__on_resp_phonebook_get_used_index, GINT_TO_POINTER(pb_type),
		NULL, NULL,
		0, NULL, NULL);
	dbg("ret: [0x%x]", ret);

	/* Free resources */
	g_free(at_cmd);
}

/******************************************************************************
 * Phonebook Response functions
 *****************************************************************************/
static void on_resp_get_count(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct treq_phonebook_get_count *req_data = NULL;
	struct tresp_phonebook_get_count resp_get_count;
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (!ur) {
		dbg("ur is NULL");
		return;
	}

	req_data = (const struct treq_phonebook_get_count *)tcore_user_request_ref_data(ur, NULL);

	memset(&resp_get_count, 0x00, sizeof(struct tresp_phonebook_get_count));
	resp_get_count.result = PB_FAIL;
	resp_get_count.type = req_data->phonebook_type;

	if (resp && resp->success > VAL_ZERO) {
		PrivateInfo *private_info;
		CoreObject *co = tcore_pending_ref_core_object(p);
		enum tel_phonebook_type pb_type;

		GSList *tokens=NULL;
		char *temp = NULL;

		dbg("RESPONSE OK");

		if (resp->lines == NULL) {
			err("invalid message");
			goto EXIT;
		}

		temp = (char *)resp->lines->data;
		tokens = tcore_at_tok_new(temp);
		if (g_slist_length(tokens) < VAL_THREE) {
			/*
			 * No of tokens must be three.
			 * We cannot proceed without used and total count.
			 */
			err("Invalid response - 'number' of tokens: [%d]", g_slist_length(tokens));

			/* Free resources */
			tcore_at_tok_free(tokens);

			goto EXIT;
		}

		resp_get_count.result = PB_SUCCESS;

		/* Fetch <used> */
		temp = g_slist_nth_data(tokens, VAL_ONE);
		if (temp)
			resp_get_count.used_count = atoi(temp);

		/* Fetch <total> */
		temp = g_slist_nth_data(tokens, VAL_TWO);
		if (temp)
			resp_get_count.total_count = atoi(temp);

		dbg("Used count [%d] Total count: [%d]", resp_get_count.used_count, resp_get_count.total_count);

		/* Free resources */
		tcore_at_tok_free(tokens);

		pb_type = resp_get_count.type;

		/* Updated selected Phonebook type */
		tcore_phonebook_set_selected_type(co, pb_type);

		/*
		 * Cache 'used_index' by req_type if valid used_index is NOT TRUE.
		 */
		private_info = tcore_object_ref_user_data(co);
		if ((pb_type == PB_TYPE_FDN && private_info->used_index_fdn_valid == FALSE)
				|| (pb_type == PB_TYPE_ADN && private_info->used_index_adn_valid == FALSE)
				|| (pb_type == PB_TYPE_SDN && private_info->used_index_sdn_valid == FALSE)
				|| (pb_type == PB_TYPE_USIM && private_info->used_index_usim_valid == FALSE)) {
			/* Cache 'used' index list */
			__phonebook_get_used_index(co, pb_type, resp_get_count.total_count);
		}
	}
	else {
		dbg("RESPONSE NOK");
	}
EXIT:
	/* Send Response */
	tcore_user_request_send_response(ur,
		TRESP_PHONEBOOK_GETCOUNT,
		sizeof(struct tresp_phonebook_get_count), &resp_get_count);

	dbg("Exit");
}

static void on_resp_get_info(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct treq_phonebook_get_info *req_data = NULL;
	struct tresp_phonebook_get_info resp_get_info;
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (!ur) {
		dbg("ur is NULL");
		return;
	}

	req_data = (const struct treq_phonebook_get_info *)tcore_user_request_ref_data(ur, NULL);

	memset(&resp_get_info, 0x00, sizeof(struct tresp_phonebook_get_info));

	resp_get_info.result = PB_FAIL;
	resp_get_info.type = req_data->phonebook_type;
	dbg("Phonebook type: [%d]", resp_get_info.type);

	if (resp && resp->success > VAL_ZERO) {
		PrivateInfo *private_info;
		CoreObject *co = tcore_pending_ref_core_object(p);
		enum tel_phonebook_type pb_type;

		GSList *tokens = NULL;
		const char *line;
		GSList *lines = resp->lines;
		gchar *temp;

		dbg("RESPONSE OK");

		if (resp->lines == NULL) {
			err("invalid message");
			goto EXIT;
		}

		/*
		 * +CPBS: <storage>[,<used>][,total]
		 */
		line = g_slist_nth_data(lines, VAL_ZERO);
		dbg("First Line: [%s]", line);
		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("invalid message");
			goto EXIT;
		}

		/* Fetch <used> */
		temp = g_slist_nth_data(tokens, VAL_ONE);
		if (temp)
			resp_get_info.used_count =  atoi(temp);

		/* Fetch <total> */
		temp = g_slist_nth_data(tokens, VAL_TWO);
		if (temp)
			resp_get_info.index_max = atoi(temp);

		resp_get_info.index_min = 1;

		dbg("Used count: [%d] Total count (index_max): [%d] " \
			"Minimum count (index_min): [%d]",
			resp_get_info.used_count, resp_get_info.index_max,
			resp_get_info.index_min);

		/* Free resources */
		tcore_at_tok_free(tokens);

		resp_get_info.result = PB_SUCCESS;

		/*
		 * +CPBF: [<nlength>],[<tlength>],[<glength>],[<slength>],[<elength>]
		 */
		line = g_slist_nth_data(lines, VAL_ONE);
		dbg("Second Line: [%s]", line);
		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("invalid message");
			goto EXIT;
		}

		/* Fetch <nlength> */
		temp = g_slist_nth_data(tokens, VAL_ONE);
		if (temp)
			resp_get_info.number_length_max = atoi(temp);

		/* Fetch <tlength> */
		temp = g_slist_nth_data(tokens, VAL_ONE);
		if (temp)
			resp_get_info.text_length_max = atoi(temp);

		dbg("Number length: [%d] Test length: [%d]",
			resp_get_info.number_length_max, resp_get_info.text_length_max);

		/* Free resources */
		tcore_at_tok_free(tokens);

		pb_type = resp_get_info.type;

		/* Updated selected Phonebook type */
		tcore_phonebook_set_selected_type(co, pb_type);

		/*
		 * Cache 'used_index' by req_type if valid used_index is NOT TRUE.
		 */
		private_info = tcore_object_ref_user_data(co);
		if ((pb_type == PB_TYPE_FDN && private_info->used_index_fdn_valid == FALSE)
				|| (pb_type == PB_TYPE_ADN && private_info->used_index_adn_valid == FALSE)
				|| (pb_type == PB_TYPE_SDN && private_info->used_index_sdn_valid == FALSE)
				|| (pb_type == PB_TYPE_USIM && private_info->used_index_usim_valid == FALSE)) {
			/* Cache 'used' index list */
			__phonebook_get_used_index(co, pb_type, resp_get_info.index_max);
		}
	}
	else {
		dbg("RESPONSE NOK");
	}

EXIT:
	/* Send Response */
	tcore_user_request_send_response(ur,
		TRESP_PHONEBOOK_GETMETAINFO,
		sizeof(struct tresp_phonebook_get_info), &resp_get_info);

	dbg("Exit");
}

static void on_resp_get_usim_info(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	struct tresp_phonebook_get_usim_info res_get_usim_info;
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (!ur) {
		dbg("error - current ur is NULL");
		return;
	}

	memset(&res_get_usim_info, 0x00, sizeof(struct tresp_phonebook_get_usim_info));
	res_get_usim_info.result = PB_FAIL;

	if (resp && resp->success > VAL_ZERO) {
		PrivateInfo *private_info;
		CoreObject *co = tcore_pending_ref_core_object(p);

		GSList *tokens = NULL;
		const char *line;
		GSList *lines = resp->lines;
		int used = 0, total = 0;
		int nlen = 0, tlen = 0, glen = 0, slen = 0, elen = 0;
		enum tel_phonebook_field_type phonebook_field_type;
		int field_type;
		gchar *temp;

		dbg("RESPONSE OK");

		if (resp->lines == NULL) {
			err("invalid message");
			goto EXIT;
		}

		/*
		 * +CPBS: <storage>[,<used>][,total]
		 */
		line = g_slist_nth_data(lines, VAL_ZERO);
		dbg("First Line: [%s]", line);
		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("invalid message");
			goto EXIT;
		}

		/* Fetch <used> */
		temp = g_slist_nth_data(tokens, VAL_ONE);
		if (temp)
			used =  atoi(temp);

		/* Fetch <total> */
		temp = g_slist_nth_data(tokens, VAL_TWO);
		if (temp)
			total = atoi(temp);

		dbg("used_count %d index_max %d", used, total);

		/* Free resources */
		tcore_at_tok_free(tokens);

		/*
		 * +CPBF: [<nlength>],[<tlength>],[<glength>],[<slength>],[<elength>]
		 */
		line = g_slist_nth_data(lines, VAL_ONE);
		dbg("Second Line: [%s]", line);
		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("invalid message");
			goto EXIT;
		}

		/* Fetch <nlength> */
		temp = g_slist_nth_data(tokens, VAL_ZERO);
		if (temp)
			nlen = atoi(temp);

		/* Fetch <tlength> */
		temp = g_slist_nth_data(tokens, VAL_ONE);
		if (temp)
			tlen = atoi(temp);

		/* Fetch <glength> */
		temp = g_slist_nth_data(tokens, VAL_TWO);
		if (temp)
			glen = atoi(temp);

		/* Fetch <slength> */
		temp = g_slist_nth_data(tokens, VAL_THREE);
		if (temp)
			slen = atoi(temp);

		/* Fetch <elength> */
		temp = g_slist_nth_data(tokens, VAL_FOUR);
		if (temp)
			elen = atoi(temp);

		dbg("Length - Number: [%d] Test: [%d] Group: [%d] " \
			"Second name: [%d] e-mail: [%d]",
			nlen, tlen, glen, slen, elen);

		for (field_type = 1; field_type <= IMC_PB_INFO_LENGTH; field_type++) {
			phonebook_field_type = __phonebook_convert_field_type(field_type);

			res_get_usim_info.field_list[field_type-1].field = phonebook_field_type;
			res_get_usim_info.field_list[field_type-1].used_count = used;
			res_get_usim_info.field_list[field_type-1].index_max = total;

			switch (phonebook_field_type) {
			case PB_FIELD_NUMBER:
				res_get_usim_info.field_list[field_type-1].text_max = nlen;
			break;

			case PB_FIELD_NAME:
				res_get_usim_info.field_list[field_type-1].text_max = tlen;
			break;

			case PB_FIELD_GRP:
				res_get_usim_info.field_list[field_type-1].text_max = glen;
			break;

			case PB_FIELD_SNE:
				res_get_usim_info.field_list[field_type-1].text_max = slen;
			break;

			case PB_FIELD_EMAIL1:
				res_get_usim_info.field_list[field_type-1].text_max = elen;
			break;

			default:
				warn("Unsupported Phonebook field type: [%d]", phonebook_field_type);
			break;
			}
		}

		res_get_usim_info.field_count = IMC_PB_INFO_LENGTH;
		res_get_usim_info.result = PB_SUCCESS;

		/* Free resources */
		tcore_at_tok_free(tokens);

		/* Updated selected Phonebook type */
		tcore_phonebook_set_selected_type(co, PB_TYPE_USIM);

		/*
		 * Cache 'used_index' for PB_TYPE_USIM if valid used_index is NOT TRUE.
		 */
		private_info = tcore_object_ref_user_data(co);
		if (private_info->used_index_usim_valid == FALSE) {
			/* Cache 'used' index list */
			__phonebook_get_used_index(co, PB_TYPE_USIM, total);
		}
	}

EXIT:
	/* Send Response */
	tcore_user_request_send_response(ur,
		TRESP_PHONEBOOK_GETUSIMINFO,
		sizeof(struct tresp_phonebook_get_usim_info), &res_get_usim_info);
	dbg("Exit");
}

static void on_resp_read_record(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const struct treq_phonebook_read_record *req_data = NULL;
	struct tresp_phonebook_read_record resp_read_record;
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (!ur) {
		dbg("error - current ur is NULL");
		return;
	}

	req_data = tcore_user_request_ref_data(ur, NULL);

	memset(&resp_read_record, 0x00, sizeof(struct tresp_phonebook_read_record));

	resp_read_record.result = PB_FAIL;
	resp_read_record.phonebook_type = req_data->phonebook_type;

	if (resp && resp->success > VAL_ZERO) {
		CoreObject *co = tcore_pending_ref_core_object(p);
		GSList *list = NULL;

		GSList *tokens = NULL;
		const char *line;

		int num_plan = VAL_ZERO;
		char *number = NULL, *name = NULL, *additional_number = NULL;
		char *sne = NULL, *email = NULL;
		char *temp = NULL;

		dbg("RESPONSE OK");

		if (resp->lines == NULL) {
			err("invalid message");
			goto EXIT;
		}

		/*
		 * +CPBR: <index>,<number>,<type>,<text>[,<hidden>][,<group>]
		 *	[,<adnumber>][,<adtype>][,<secondtext>][,<email>]]
		 */
		line = (const char*)resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < VAL_ONE) {
			err("invalid message");
			goto EXIT;
		}

		/* Fetch <index> */
		temp = g_slist_nth_data(tokens, VAL_ZERO);
		if (temp == NULL) {
			err("No index");
			goto EXIT;
		}
		resp_read_record.index = atoi(temp);

		/* Fetch <number> */
		temp = g_slist_nth_data(tokens, VAL_ONE);
		if (temp == NULL) {
			err("No number");
			goto EXIT;
		}
		number = tcore_at_tok_extract(temp);
		g_strlcpy((char *)resp_read_record.number,
			(const gchar *)number, PHONEBOOK_NUMBER_BYTE_MAX+1);
		g_free(number);

		/* Fetch <type> */
		temp = g_slist_nth_data(tokens, VAL_TWO);
		if (temp == NULL) {
			err("No type");
			goto EXIT;
		}
		num_plan = atoi(temp);
		resp_read_record.ton = __phonebook_find_num_plan(num_plan);

		/* Fetch <text> */
		temp = g_slist_nth_data(tokens, VAL_THREE);
		if (temp == NULL) {
			err("No text");
			goto EXIT;
		}
		name = tcore_at_tok_extract(temp);
		if (name) {
			g_strlcpy((char *)resp_read_record.name,
				(const gchar *)name, PHONEBOOK_NAME_BYTE_MAX+1);
			resp_read_record.name_len = strlen((const char*)resp_read_record.name);
			resp_read_record.dcs = PB_TEXT_ASCII;
			g_free(name);
		}

		/* All 'mandatory' fields are extracted */
		resp_read_record.result = PB_SUCCESS;

		/* Updated selected Phonebook type */
		tcore_phonebook_set_selected_type(co, req_data->phonebook_type);

		/* Get used_index list by req_type */
		if (__phonebook_get_index_list_by_type(co,
				req_data->phonebook_type, &list) == TRUE) {
			while (list) {
				if ((guint)list->data == resp_read_record.index) {
					if ((list = g_slist_next(list)) != NULL) {
						/* If exist, set next_index */
						resp_read_record.next_index = (guint)list->data;
						dbg("next_index is [%u]", resp_read_record.next_index);
					} else {
						/* read_record.index is the end of used_index */
						resp_read_record.next_index = 0;
						dbg("End of used_index");
					}
					break;
				}
				list = g_slist_next(list);
			}
		} else {
			/* No PrivateInfo */
			resp_read_record.next_index = 0;
		}

		/* Fetch <hidden> */
		temp = g_slist_nth_data(tokens, VAL_FOUR);
		if (temp) {
			dbg("Phonebook entry is hidden");
		}

		/* Fetch <adnumber> */
		temp = g_slist_nth_data(tokens, VAL_SIX);
		additional_number = tcore_at_tok_extract(temp);
		if (additional_number) {
			g_strlcpy((char *)resp_read_record.anr1,
				(const gchar *)additional_number, PHONEBOOK_NUMBER_BYTE_MAX+1);
			g_free(additional_number);
		}

		/* Fetch <adtype> */
		temp = g_slist_nth_data(tokens, VAL_SEVEN);
		name = tcore_at_tok_extract(temp);
		if (temp) {
			num_plan = atoi(temp);
			resp_read_record.anr1_ton = __phonebook_find_num_plan(num_plan);
		}

		/* Fetch <secondtext> */
		temp = g_slist_nth_data(tokens, VAL_EIGHT);
		if (temp == NULL) {
			err("No text");
			goto EXIT;
		}
		sne = tcore_at_tok_extract(temp);
		if (sne) {
			g_strlcpy((char *)resp_read_record.sne,
				(const gchar *)sne, PHONEBOOK_NAME_BYTE_MAX+1);
			resp_read_record.sne_len = strlen((const char*)resp_read_record.sne);
			resp_read_record.sne_dcs = PB_TEXT_ASCII;
			g_free(sne);
		}

		/* Fetch <email> */
		temp = g_slist_nth_data(tokens, VAL_NINE);
		if (temp == NULL) {
			err("No text");
			goto EXIT;
		}
		email = tcore_at_tok_extract(temp);
		if (email) {
			g_strlcpy((char *)resp_read_record.email1,
				(const gchar *)email, PHONEBOOK_EMAIL_BYTE_MAX+1);
			resp_read_record.email1_len = strlen((const char*)resp_read_record.email1);
			g_free(email);
		}

EXIT:
		/* Free resources */
		tcore_at_tok_free(tokens);
	}
	else {
		dbg("RESPONSE NOK");
	}

	/* Send Response */
	tcore_user_request_send_response(ur,
		TRESP_PHONEBOOK_READRECORD,
		sizeof(struct tresp_phonebook_read_record), &resp_read_record);

	dbg("Exit");
}

static void on_resp_update_record(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_phonebook_update_record resp_update_record;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);

	if (resp && resp->success > VAL_ZERO) {
		const struct treq_phonebook_update_record *req_data = NULL;
		CoreObject *co = tcore_pending_ref_core_object(p);

		dbg("RESPONSE OK");

		resp_update_record.result = PB_SUCCESS;

		req_data = tcore_user_request_ref_data(ur, NULL);

		/* Updated selected Phonebook type */
		tcore_phonebook_set_selected_type(co, req_data->phonebook_type);

		/*
		 * Need to update the corresponding index list.
		 *
		 * in case 'not available' (ADD operation) - ADD index
		 * in case 'available' (UPDATE operation) - NO change
		 */
		__phonebook_update_index_list_by_type(co,
			req_data->phonebook_type, req_data->index);
	}
	else {
		dbg("RESPONSE NOK");
		resp_update_record.result = PB_FAIL;
	}

	if (ur) {
		/* Send Response */
		tcore_user_request_send_response(ur,
			TRESP_PHONEBOOK_UPDATERECORD,
			sizeof(struct tresp_phonebook_update_record), &resp_update_record);
	}
	else {
		err("ur is NULL");
	}

	dbg("Exit");
}

static void on_resp_delete_record(TcorePending *p,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_phonebook_delete_record resp_delete_record;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);

	if (resp && resp->success > VAL_ZERO) {
		const struct treq_phonebook_delete_record *req_data = NULL;
		CoreObject *co = tcore_pending_ref_core_object(p);
		GSList *list = NULL;

		dbg("RESPONSE OK");

		resp_delete_record.result = PB_SUCCESS;

		req_data = tcore_user_request_ref_data(ur, NULL);

		/* Updated selected Phonebook type */
		tcore_phonebook_set_selected_type(co, req_data->phonebook_type);

		/* Get used_index list by req_type */
		if (__phonebook_get_index_list_by_type(co,
				req_data->phonebook_type, &list) != TRUE) {
			err("used_index list is NOT valid");
		}
		else {
			const int del_index = (const int)req_data->index;
			list = g_slist_remove(list, (gconstpointer)del_index);
			dbg("Remove index: [%u] list: [0x%x]", req_data->index, list);
		}
	}
	else {
		dbg("RESPONSE NOK");
		resp_delete_record.result = PB_FAIL;
	}

	if (ur) {
		tcore_user_request_send_response(ur,
			TRESP_PHONEBOOK_DELETERECORD,
			sizeof(struct tresp_phonebook_delete_record), &resp_delete_record);
	}
	else {
		err("ur is NULL");
	}

	dbg("Exit");
}

/******************************************************************************
 * Phonebook Request functions
 *****************************************************************************/
/*
 * Operation - get_count
 *
 * Request -
 * AT-Command: AT+CPBS?
 *
 * Response -
 * Success: (Single line)
 *	+CPBS: <storage>[,<used>][,total]
 *	OK
 * where,
 * <storage> Phonebook storage type
 * <used> Number of records 'used'
 * <total> 'total' number of records available
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn imc_get_count(CoreObject *co, UserRequest *ur)
{
	struct treq_phonebook_get_count *req_data = NULL;
	gchar *at_cmd;
	gchar *set_pb_cmd;

	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	req_data = (struct treq_phonebook_get_count *)tcore_user_request_ref_data(ur, NULL);

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__phonebook_check_and_select_type(co,
			req_data->phonebook_type, &set_pb_cmd) != TRUE) {
		warn("Requested phonebok type '%d' is NOT supported",
			req_data->phonebook_type);
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBS?", set_pb_cmd);

	/* Send Request to Modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, "+CPBS",
		TCORE_AT_SINGLELINE,
		ur,
		on_resp_get_count, NULL,
		NULL, NULL,
		0, NULL, NULL);

	/* Free resources */
	g_free(at_cmd);
	g_free(set_pb_cmd);

	return ret;
}

/*
 * Operation - get_info
 *
 * Request -
 * AT-Command: AT+CPBS?;+CPBF=?
 *
 * Response -
 * Success: (Multi line)
 *	+CPBS: <storage>[,<used>][,total]
 *	+CPBF: [<nlength>],[<tlength>],[<glength>],[<slength>],[<elength>]
 *	OK
 * where,
 * <storage> Phonebook storage type
 * <used> Number of records 'used'
 * <total> 'total' number of records available
 * <nlength> Maximum length of field <number>
 * <tlength> Maximum length of field <text>
 * <glength> Maximum length of field <group>
 * <slength> Maximum length of field <secondtext>
 * <elength> Maximum length of field <email>
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn imc_get_info(CoreObject *co, UserRequest *ur)
{
	struct treq_phonebook_get_info *req_data = NULL;
	gchar *at_cmd;
	gchar *set_pb_cmd;

	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	req_data = (struct treq_phonebook_get_info *)tcore_user_request_ref_data(ur, NULL);

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__phonebook_check_and_select_type(co,
			req_data->phonebook_type, &set_pb_cmd) != TRUE) {
		warn("Requested phonebok type '%d' is NOT supported",
			req_data->phonebook_type);
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBS?;+CPBF=?", set_pb_cmd);

	/* Send Request to Modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, "+CPB",
		TCORE_AT_MULTILINE,
		ur,
		on_resp_get_info, NULL,
		NULL, NULL,
		0, NULL, NULL);

	/* Free resources */
	g_free(at_cmd);
	g_free(set_pb_cmd);

	return ret;
}

/*
 * Operation - get_usim_info
 *
 * Request -
 * AT-Command: AT+CPBS?;+CPBF=?
 *
 * Response -
 * Success: (Multi line)
 *	+CPBS: <storage>[,<used>][,total]
 *	+CPBF: [<nlength>],[<tlength>],[<glength>],[<slength>],[<elength>]
 *	OK
 * where,
 * <storage> Phonebook storage type
 * <used> Number of records 'used'
 * <total> 'total' number of records available
 * <nlength> Maximum length of field <number>
 * <tlength> Maximum length of field <text>
 * <glength> Maximum length of field <group>
 * <slength> Maximum length of field <secondtext>
 * <elength> Maximum length of field <email>
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn imc_get_usim_info(CoreObject *co, UserRequest *ur)
{
	gchar *at_cmd;
	gchar *set_pb_cmd;

	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__phonebook_check_and_select_type(co, PB_TYPE_USIM, &set_pb_cmd) != TRUE) {
		warn("Requested phonebok type '%d' is NOT supported", PB_TYPE_USIM);
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBS?;+CPBF=?", set_pb_cmd);

	/* Send Request to Modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, "+CPB",
		TCORE_AT_MULTILINE,
		ur,
		on_resp_get_usim_info, NULL,
		NULL, NULL,
		0, NULL, NULL);

	/* Free resources */
	g_free(at_cmd);
	g_free(set_pb_cmd);

	return ret;
}

/*
 * Operation - read_record
 *
 * Request -
 * AT-Command: AT+CPBR=<index>
 * where,
 * <index>
 * 1	Integer type values in range of location numbers of phonebook memory
 * ...
 *
 * Response -
 * Success: (Single line);
 *	+CPBR: <index>,<number>,<type>,<text>[,<hidden>][,<group>]
 *	[,<adnumber>][,<adtype>][,<secondtext>][,<email>]]
 *	OK
 * where,
 * <number> String type phone number of format <type>
 * <type> Type of address octet in integer format
 * <text> String type field of maximum length <tlength>
 * <hidden> Indicates if the entry is hidden or not – only available,
 * 		if a UICC with an active USIM application is present
 * 0	Phonebook entry not hidden
 * 1	Phonebook entry hidden
 * <group> String type field of maximum length <glength>
 * <adnumber> String type phone number of format <adtype>
 * <adtype> Type of address octet in integer format
 * <secondtext> String type field of maximum length <slength>
 * <email> String type field of maximum length <elength>
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn imc_read_record(CoreObject *co, UserRequest *ur)
{
	const struct treq_phonebook_read_record *req_data = NULL;
	gchar *at_cmd;
	gchar *set_pb_cmd;
	guint used_index = 0;

	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	req_data = tcore_user_request_ref_data(ur, NULL);

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__phonebook_check_and_select_type(co,
			req_data->phonebook_type, &set_pb_cmd) != TRUE) {
		warn("Requested phonebok type '%d' is NOT supported",
			req_data->phonebook_type);
		return ret;
	}

	/* Check whether index is used or not */
	__phonebook_check_used_index(co,
		req_data->phonebook_type, req_data->index, &used_index);

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBR=%u", set_pb_cmd, used_index);

	/* Send Request to Modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, "+CPBR",
		TCORE_AT_SINGLELINE,
		ur,
		on_resp_read_record, NULL,
		NULL, NULL,
		0, NULL, NULL);

	/* Free resources */
	g_free(at_cmd);
	g_free(set_pb_cmd);

	return ret;
}

/*
 * Operation - update_record
 *
 * Request -
 * AT-Command: AT+CPBW=[<index>][,<number>[,<type>[,<text>[,<group>[,<adnumber>
 *	[,<adtype>[,<secondtext>[,<email>[,<hidden>]]]]]]]]]
 * where,
 * ... same read_record Operation
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn imc_update_record(CoreObject *co, UserRequest *ur)
{
	const struct treq_phonebook_update_record *req_data = NULL;
	gchar *at_cmd;
	gchar *set_pb_cmd;

	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	req_data = tcore_user_request_ref_data(ur, NULL);

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__phonebook_check_and_select_type(co,
			req_data->phonebook_type, &set_pb_cmd) != TRUE) {
		warn("Requested phonebok type '%d' is NOT supported",
			req_data->phonebook_type);
		return ret;
	}

	/* Set AT-Command according pb_type */
	if (req_data->phonebook_type == PB_TYPE_USIM) {
		at_cmd = g_strdup_printf("%s+CPBW=%u,\"%s\",%d,\"%s\",,\"%s\",,\"%s\",\"%s\"",
			set_pb_cmd, req_data->index,
			req_data->number,
			((PB_TON_INTERNATIONAL == req_data->ton) ? IMC_TON_INTERNATIONAL: IMC_TON_UNKNOWN),
			req_data->name, req_data->anr1,
			req_data->sne, req_data->email1);
	} else {
		at_cmd = g_strdup_printf("%s+CPBW=%u,\"%s\",,\"%s\"",
			set_pb_cmd, req_data->index,
			req_data->number, req_data->name);
	}

	/* Send Request to Modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_resp_update_record, NULL,
		NULL, NULL,
		0, NULL, NULL);

	/* Free resources */
	g_free(at_cmd);
	g_free(set_pb_cmd);

	return ret;
}

/*
 * Operation - delete_record
 *
 * Request -
 * AT-Command: AT+CPBW=<index>
 * where,
 * <index>
 * 1	Integer type values in range of location numbers of phonebook memory
 * ...
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TReturn imc_delete_record(CoreObject *co, UserRequest *ur)
{
	const struct treq_phonebook_delete_record *req_data;
	gchar *at_cmd;
	gchar *set_pb_cmd;

	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	req_data = tcore_user_request_ref_data(ur, NULL);

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__phonebook_check_and_select_type(co,
			req_data->phonebook_type, &set_pb_cmd) != TRUE) {
		warn("Requested phonebok type '%d' is NOT supported",
			req_data->phonebook_type);
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBW=%u", set_pb_cmd, req_data->index);

	/* Send Request to Modem */
	ret = tcore_prepare_and_send_at_request(co,
		at_cmd, NULL,
		TCORE_AT_NO_RESULT,
		ur,
		on_resp_delete_record, NULL,
		NULL, NULL,
		0, NULL, NULL);

	/* Free resources */
	g_free(at_cmd);
	g_free(set_pb_cmd);

	return ret;
}

/******************************************************************************
 * Phonebook Notification function(s)
 *****************************************************************************/
static gboolean on_noti_phonebook_status(CoreObject *co_phonebook,
	const void *event_info, void *user_data)
{
	dbg("Received [+PBREADY]");

	/*
	 * Get supported list of Phonebook types
	 */
	__phonebook_get_support_list(co_phonebook);

	return TRUE;
}

/* Phonebook operations */
static struct tcore_phonebook_operations phonebook_ops = {
	.get_count = imc_get_count,
	.get_info = imc_get_info,
	.get_usim_info = imc_get_usim_info,
	.read_record = imc_read_record,
	.update_record = imc_update_record,
	.delete_record = imc_delete_record,
};

gboolean imc_phonebook_init(TcorePlugin *cp, CoreObject *co_phonebook)
{
	PrivateInfo *private_info;

	dbg("Entry");

	/* Set operations */
	tcore_phonebook_set_ops(co_phonebook, &phonebook_ops);

	/* Set PrivateInfo */
	private_info = g_malloc0(sizeof(PrivateInfo));
	tcore_object_link_user_data(co_phonebook, private_info);

	/* Add Callbacks */
	tcore_object_add_callback(co_phonebook,
		"+PBREADY",
		on_noti_phonebook_status, co_phonebook);

	dbg("Exit");

	return TRUE;
}

void imc_phonebook_exit(TcorePlugin *cp, CoreObject *co_phonebook)
{
	PrivateInfo *private_info;

	private_info = tcore_object_ref_user_data(co_phonebook);
	g_assert(private_info != NULL);

	/* Free PrivateInfo */
	g_slist_free_full(private_info->used_index_fdn, g_free);
	g_slist_free_full(private_info->used_index_adn, g_free);
	g_slist_free_full(private_info->used_index_sdn, g_free);
	g_slist_free_full(private_info->used_index_usim, g_free);
	g_free(private_info);

	/* Remove Callbacks */
	tcore_object_del_callback(co_phonebook,
		"+PBREADY", on_noti_phonebook_status);

	dbg("Exit");
}
