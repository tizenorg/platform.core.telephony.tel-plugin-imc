/*
 * tel-plugin-imc
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd. All rights reserved.
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
#include <plugin.h>
#include <core_object.h>
#include <hal.h>
#include <queue.h>
#include <storage.h>
#include <at.h>

#include <co_phonebook.h>
#include <co_sim.h>

#include "imc_phonebook.h"
#include "imc_common.h"

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

static gboolean __imc_phonebook_get_sim_type(CoreObject *co_pb,
		TelSimCardType *sim_type)
{
	TcorePlugin *plugin;
	CoreObject *co_sim;
	tcore_check_return_value_assert(co_pb != NULL, FALSE);
	tcore_check_return_value_assert(sim_type != NULL, FALSE);

	plugin = tcore_object_ref_plugin(co_pb);
	co_sim = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);
	return tcore_sim_get_type(co_sim, sim_type);
}

static gboolean __imc_phonebook_get_pb_type_str(TelPbType pb_type,
		gchar **req_type_str)
{
	tcore_check_return_value_assert(req_type_str != NULL, FALSE);

	switch (pb_type) {
	case TEL_PB_FDN:
		*req_type_str = g_strdup("FD");
		break;
	case TEL_PB_ADN:
	case TEL_PB_USIM:
		*req_type_str = g_strdup("SM");
		break;
	case TEL_PB_SDN:
		*req_type_str = g_strdup("SN");
		break;
	}

	return TRUE;
}

static gboolean __imc_phonebook_check_and_select_type(CoreObject *co,
		TelPbType req_type, gchar **set_pb_cmd)
{
	TelPbList *support_list;
	TelPbType current_type;

	/* Check whether pb_type is supported or not */
	tcore_phonebook_get_support_list(co, &support_list);
	if ((req_type == TEL_PB_FDN && support_list->fdn == FALSE)
			|| (req_type == TEL_PB_ADN && support_list->adn == FALSE)
			|| (req_type == TEL_PB_SDN && support_list->sdn == FALSE)
			|| (req_type == TEL_PB_USIM && support_list->usim == FALSE)) {
		err("Not supported pb_type");
		g_free(support_list);
		return FALSE;
	}
	g_free(support_list);

	/* Check Current type & Request type */
	tcore_phonebook_get_selected_type(co, &current_type);
	if (current_type != req_type) {
		gchar *req_type_str = NULL;
		__imc_phonebook_get_pb_type_str(req_type, &req_type_str);
		dbg("Add AT-Command to change [%s] Type", req_type_str);
		/* Select Phonebook type */
		*set_pb_cmd = g_strdup_printf("AT+CPBS=\"%s\";", req_type_str);
	} else {
		*set_pb_cmd = g_strdup_printf("AT");
	}

	return TRUE;
}

static gboolean __imc_phonebook_get_index_list_by_type(CoreObject *co,
		TelPbType pb_type, GSList **list)
{
	PrivateInfo *private_info = tcore_object_ref_user_data(co);
	tcore_check_return_value_assert(private_info != NULL, FALSE);

	switch (pb_type) {
	case TEL_PB_FDN:
		if (private_info->used_index_fdn_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_fdn;
		break;
	case TEL_PB_ADN:
		if (private_info->used_index_adn_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_adn;
		break;
	case TEL_PB_SDN:
		if (private_info->used_index_sdn_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_sdn;
		break;
	case TEL_PB_USIM:
		if (private_info->used_index_usim_valid != TRUE)
			return FALSE;
		*list = private_info->used_index_usim;
		break;
	}

	return TRUE;
}

static void __imc_phonebook_check_used_index(CoreObject *co,
		TelPbType pb_type, guint req_index, guint *used_index)
{
	GSList *list = NULL;

	/* Get used_index list by req_type */
	if (__imc_phonebook_get_index_list_by_type(co, pb_type, &list) != TRUE) {
		err("used_index list is NOT valid");
		*used_index = req_index;
		return;
	}

	/* Use first used_index in case req_index is not used */
	*used_index = (guint)g_slist_nth_data(list, 0);
	while (list) {
		if ((guint)list->data == req_index) {
			/* req_index is equal to one of used_index */
			*used_index = req_index;
			return;
		}
		list = g_slist_next(list);
	}
}

static gint __imc_phonebook_compare_index(gconstpointer a, gconstpointer b)
{
	guint index1 = (guint)a;
	guint index2 = (guint)b;

	return index1 - index2;
}

static void on_response_imc_phonebook_get_used_index(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	dbg("Entry");

	if (at_resp->success != TRUE) {
		err("Response NOK");
		return;
	}

	dbg("Response OK");

	if (at_resp->lines == NULL) {
		err("at_resp->lines is NULL");
	} else {
		GSList *lines = at_resp->lines;
		TelPbType *req_type;
		GSList **list = NULL;
		PrivateInfo *private_info = tcore_object_ref_user_data(co);
		tcore_check_return_assert(private_info != NULL);

		/* Select used_index_list by req_type */
		req_type = (TelPbType *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
		switch (*req_type) {
		case TEL_PB_FDN:
			list = &private_info->used_index_fdn;
			private_info->used_index_fdn_valid = TRUE;
			break;
		case TEL_PB_ADN:
			list = &private_info->used_index_adn;
			private_info->used_index_adn_valid = TRUE;
			break;
		case TEL_PB_SDN:
			list = &private_info->used_index_sdn;
			private_info->used_index_sdn_valid = TRUE;
			break;
		case TEL_PB_USIM:
			list = &private_info->used_index_usim;
			private_info->used_index_usim_valid = TRUE;
			break;
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
			temp = g_slist_nth_data(tokens, 0);
			if (temp) {
				/* Insert used_index in PrivateInfo sorted in ascending */
				*list = g_slist_insert_sorted(*list, (gpointer)atoi(temp),
					__imc_phonebook_compare_index);
			}
			tcore_at_tok_free(tokens);

			/* Get next lines */
			lines = g_slist_next(lines);
		}
		dbg("pb_type: [%d], used_index Length: [%d]",
			*req_type, g_slist_length(*list));
	}
}

static void __imc_phonebook_get_used_index(CoreObject *co, TelPbType pb_type, guint max_index)
{
	gchar *at_cmd;
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry");

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CPBR=1,%d", max_index);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(NULL, NULL,
		(void *)&pb_type, sizeof(TelPbType));

	/* Send Request to Modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CPBR",
		TCORE_AT_COMMAND_TYPE_MULTILINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_phonebook_get_used_index, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Used Index");

	/* Free resources */
	g_free(at_cmd);
}

static void on_response_imc_phonebook_get_support_list(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelPbInitInfo init_info = {0, };
	tcore_check_return_assert(at_resp != NULL);

	dbg("Entry");

	if (at_resp->success != TRUE) {
		err("Response NOK");
		return;
	}

	dbg("Response OK");

	if (at_resp->lines == NULL) {
		err("at_resp->lines is NULL");
		return;
	} else {
		const gchar *line = (const gchar *)at_resp->lines->data;
		GSList *tokens = NULL;
		gchar *pb_type_list;
		gchar *pb_type;

		dbg("Line: [%s]", line);

		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("tokens is NULL");
			return;
		}

		pb_type_list = g_slist_nth_data(tokens, 0);
		pb_type = strtok(pb_type_list, "(,)");
		while (pb_type) {
			pb_type = tcore_at_tok_extract(pb_type);
			if (g_strcmp0(pb_type, "FD") == 0) {
				init_info.pb_list.fdn = TRUE;
			} else if (g_strcmp0(pb_type, "SN") == 0) {
				init_info.pb_list.sdn = TRUE;
			} else if (g_strcmp0(pb_type, "SM") == 0) {
				TelSimCardType sim_type;
				__imc_phonebook_get_sim_type(co, &sim_type);
				if (sim_type == TEL_SIM_CARD_TYPE_USIM)
					init_info.pb_list.usim = TRUE;
				else
					init_info.pb_list.adn = TRUE;
			}
			g_free(pb_type);
			/* Get Next pb_type */
			pb_type = strtok(NULL, "(,)");
		}
		tcore_at_tok_free(tokens);
	}

	dbg("FDN: [%s], ADN: [%s], SDN: [%s], USIM: [%s]",
		init_info.pb_list.fdn ? "TRUE" : "FALSE",
		init_info.pb_list.adn ? "TRUE" : "FALSE",
		init_info.pb_list.sdn ? "TRUE" : "FALSE",
		init_info.pb_list.usim ? "TRUE" : "FALSE");

	init_info.init_status = TRUE;
	tcore_phonebook_set_support_list(co, &init_info.pb_list);
	tcore_phonebook_set_status(co, init_info.init_status);

	/* Send Notification */
	tcore_object_send_notification(co,
		TCORE_NOTIFICATION_PHONEBOOK_STATUS,
		sizeof(TelPbInitInfo), &init_info);
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
static void __imc_phonebook_get_support_list(CoreObject *co)
{
	TelReturn ret;

	dbg("Entry");

	/* Send Request to Modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CPBS=?", "+CPBS",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_phonebook_get_support_list, NULL,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, NULL, "Get Support List");
}

static gboolean on_notification_imc_phonebook_status(CoreObject *co,
		const void *event_info, void *user_data)
{
	dbg("Phonebook Init Completed");

	/* Get Supported list */
	__imc_phonebook_get_support_list(co);

	return TRUE;
}

static void on_response_imc_phonebook_get_info(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelPbResult result = TEL_PB_RESULT_FAILURE;
	TelPbInfo pb_info = {0, };
	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	dbg("Entry");

	if (at_resp->success != TRUE) {
		err("Response NOK");
		goto out;
	}

	dbg("Response OK");

	if (at_resp->lines == NULL) {
		err("at_resp->lines is NULL");
	} else {
		GSList *lines = at_resp->lines;
		const gchar *line;
		GSList *tokens = NULL;
		gchar *temp;
		gint used = 0, total = 0;
		gint nlen = 0, tlen = 0;
		TelPbType *req_type;
		PrivateInfo *private_info;

		/* +CPBS: <storage>[,<used>][,total] */
		line = g_slist_nth_data(lines, 0);
		dbg("First Line: [%s]", line);
		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("tokens is NULL");
			goto out;
		}

		/* Get used_count */
		temp = g_slist_nth_data(tokens, 1);
		if (temp)
			used = atoi(temp);
		/* Get total_count */
		temp = g_slist_nth_data(tokens, 2);
		if (temp)
			total = atoi(temp);

		tcore_at_tok_free(tokens);

		/* +CPBF: [<nlength>],[<tlength>],[<glength>],[<slength>],[<elength>] */
		line = g_slist_nth_data(lines, 1);
		dbg("Second Line: [%s]", line);
		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("tokens is NULL");
			goto out;
		}

		/* Get number Length */
		temp = g_slist_nth_data(tokens, 0);
		if (temp)
			nlen = atoi(temp);
		/* Get text Length */
		temp = g_slist_nth_data(tokens, 1);
		if (temp)
			tlen = atoi(temp);

		/* Set Response Data */
		req_type = (TelPbType *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
		pb_info.pb_type = *req_type;
		if (*req_type == TEL_PB_USIM) {
			pb_info.info_u.usim.max_count = total;
			pb_info.info_u.usim.used_count = used;
			pb_info.info_u.usim.max_num_len = nlen;
			pb_info.info_u.usim.max_text_len = tlen;
			/* Get group name Length */
			temp = g_slist_nth_data(tokens, 2);
			if (temp)
				pb_info.info_u.usim.max_gas_len = atoi(temp);
			/* Get second name Length */
			temp = g_slist_nth_data(tokens, 3);
			if (temp)
				pb_info.info_u.usim.max_sne_len = atoi(temp);
			/* Get email Length */
			temp = g_slist_nth_data(tokens, 4);
			if (temp)
				pb_info.info_u.usim.max_email_len = atoi(temp);
		} else {
			pb_info.info_u.sim.max_count = total;
			pb_info.info_u.sim.used_count = used;
			pb_info.info_u.sim.max_num_len = nlen;
			pb_info.info_u.sim.max_text_len = tlen;
		}

		/* Set Request type in PrivateObject */
		tcore_phonebook_set_selected_type(co, *req_type);
		result = TEL_PB_RESULT_SUCCESS;
		tcore_at_tok_free(tokens);

		/* If don't have valid used_index, get used_index by req_type */
		private_info = tcore_object_ref_user_data(co);
		if ((*req_type == TEL_PB_FDN && private_info->used_index_fdn_valid == FALSE)
				|| (*req_type == TEL_PB_ADN && private_info->used_index_adn_valid == FALSE)
				|| (*req_type == TEL_PB_SDN && private_info->used_index_sdn_valid == FALSE)
				|| (*req_type == TEL_PB_USIM && private_info->used_index_usim_valid == FALSE))
			__imc_phonebook_get_used_index(co, *req_type, total);
	}

out:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &pb_info, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_phonebook_read_record(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelPbResult result = TEL_PB_RESULT_FAILURE;
	GSList *tokens = NULL;
	gchar *index = NULL, *number = NULL, *name = NULL;
	TelPbReadRecord read_record = {0, };
	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	dbg("Entry");

	if (at_resp->success != TRUE) {
		err("Response NOK");
		goto out;
	}

	dbg("Response OK");

	if (at_resp->lines == NULL) {
		err("at_resp->lines is NULL");
	} else {
		const gchar *line = (const gchar *)at_resp->lines->data;
		TelPbType *req_type;
		GSList *list = NULL;

		dbg("Line: [%s]", line);

		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("tokens is NULL");
			goto out;
		}

		/* Get index */
		index = g_slist_nth_data(tokens, 0);
		if (index == NULL) {
			err("No index");
			goto out;
		}

		/* Get number */
		number = g_slist_nth_data(tokens, 1);
		if (number) {
			number = tcore_at_tok_extract(number);
		} else {
			err("No number");
			goto out;
		}

		/* Get name */
		name = g_slist_nth_data(tokens, 3);
		if (name) {
			name = tcore_at_tok_extract(name);
		} else {
			err("No name");
			goto out;
		}

		/* Set Request type in PrivateObject */
		req_type = (TelPbType *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
		tcore_phonebook_set_selected_type(co, *req_type);

		/* Set Response Data */
		read_record.index = atoi(index);
		read_record.pb_type = *req_type;

		/* Get used_index list by req_type */
		if (__imc_phonebook_get_index_list_by_type(co, *req_type, &list) == TRUE) {
			while (list) {
				if ((guint)list->data == read_record.index) {
					if ((list = g_slist_next(list)) != NULL) {
						/* If exist, set next_index */
						read_record.next_index = (guint)list->data;
						dbg("next_index is [%u]", read_record.next_index);
					} else {
						/* read_record.index is the end of used_index */
						read_record.next_index = -1;
						dbg("End of used_index");
					}
					break;
				}
				list = g_slist_next(list);
			}
		} else {
			/* No PrivateInfo */
			read_record.next_index = 0;
		}

		if (*req_type == TEL_PB_USIM) {
			gchar *hidden, *group, *anr, *sne, *email;

			/* Get Name and Number */
			g_strlcpy(read_record.rec_u.usim.name, name, TEL_PB_TEXT_MAX_LEN + 1);
			g_strlcpy(read_record.rec_u.usim.number, number, TEL_PB_NUMBER_MAX_LEN + 1);

			/* Get Hidden */
			hidden = g_slist_nth_data(tokens, 4);
			if (hidden) {
				read_record.rec_u.usim.hidden = atoi(hidden);
			}

			/* Get Group name */
			group = g_slist_nth_data(tokens, 5);
			if (group) {
				group = tcore_at_tok_extract(group);
				g_strlcpy(read_record.rec_u.usim.grp_name, group, TEL_PB_TEXT_MAX_LEN + 1);
				g_free(group);
			}

			/* Get ANR */
			anr = g_slist_nth_data(tokens, 6);
			if (anr) {
				anr = tcore_at_tok_extract(anr);
				if (strlen(anr)) {
					g_strlcpy(read_record.rec_u.usim.anr[0].number,
						anr, TEL_PB_NUMBER_MAX_LEN + 1);
					read_record.rec_u.usim.anr_count = 1;
				}
				g_free(anr);
			}

			/* Get SNE */
			sne = g_slist_nth_data(tokens, 8);
			if (sne) {
				sne = tcore_at_tok_extract(sne);
				g_strlcpy(read_record.rec_u.usim.sne, sne, TEL_PB_TEXT_MAX_LEN + 1);
				g_free(sne);
			}

			/* Get email */
			email = g_slist_nth_data(tokens, 9);
			if (email) {
				email = tcore_at_tok_extract(email);
				if (strlen(email)) {
					g_strlcpy(read_record.rec_u.usim.email[0], email, TEL_PB_TEXT_MAX_LEN + 1);
					read_record.rec_u.usim.email_count = 1;
				}
				g_free(email);
			}
		}
		else {
			/* Get Name and Number */
			g_strlcpy(read_record.rec_u.sim.name, name, TEL_PB_TEXT_MAX_LEN + 1);
			g_strlcpy(read_record.rec_u.sim.number, number, TEL_PB_NUMBER_MAX_LEN + 1);
		}

		result = TEL_PB_RESULT_SUCCESS;
	}

out:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &read_record, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);

	/* Free resources */
	tcore_at_tok_free(tokens);
	g_free(number);
	g_free(name);
}

static void on_response_imc_phonebook_update_record(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelPbUpdateRecord *req_data;
	TelPbResult result = TEL_PB_RESULT_FAILURE;
	GSList *list = NULL;
	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	dbg("Entry");

	if (at_resp->success != TRUE) {
		err("Response NOK");
		goto out;
	}

	dbg("Response OK");
	result = TEL_PB_RESULT_SUCCESS;

	/* Set Request type in PrivateObject */
	req_data = (TelPbUpdateRecord *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	tcore_phonebook_set_selected_type(co, req_data->pb_type);

	/* Get used_index list by req_type */
	if (__imc_phonebook_get_index_list_by_type(co,
			req_data->pb_type, &list) != TRUE) {
		err("used_index list is NOT valid");
	} else {
		list = g_slist_insert_sorted(list, (gpointer)req_data->index,
			__imc_phonebook_compare_index);
	}

out:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_phonebook_delete_record(TcorePending *p,
		guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelPbRecordInfo *req_data;
	GSList *list = NULL;
	TelPbResult result = TEL_PB_RESULT_FAILURE;
	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	dbg("Entry");

	if (at_resp->success != TRUE) {
		err("Response NOK");
		goto out;
	}

	dbg("Response OK");
	result = TEL_PB_RESULT_SUCCESS;

	/* Set Request type in PrivateObject */
	req_data = (TelPbRecordInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	tcore_phonebook_set_selected_type(co, req_data->pb_type);

	/* Get used_index list by req_type */
	if (__imc_phonebook_get_index_list_by_type(co,
			req_data->pb_type, &list) != TRUE) {
		err("used_index list is NOT valid");
	} else {
		list = g_slist_remove(list, (gconstpointer)req_data->index);
		dbg("Remove index: [%u]", req_data->index);
	}

out:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
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
 * <nlength> Maximum length of field <number>
 * <tlength> Maximum length of field <text>
 * <glength> Maximum length of field <group>
 * <slength> Maximum length of field <secondtext>
 * <elength> Maximum length of field <email>
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_phonebook_get_info(CoreObject *co,
		const TelPbType pb_type,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	gchar *set_pb_cmd;
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry");

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__imc_phonebook_check_and_select_type(co, pb_type, &set_pb_cmd) != TRUE) {
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBS?;+CPBF=?", set_pb_cmd);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		(void *)&pb_type, sizeof(TelPbType));

	/* Send Request to Modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CPB",
		TCORE_AT_COMMAND_TYPE_MULTILINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_phonebook_get_info, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Info");

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
static TelReturn imc_phonebook_read_record(CoreObject *co,
		const TelPbRecordInfo *record,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	gchar *set_pb_cmd;
	ImcRespCbData *resp_cb_data;
	guint used_index = 0;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry");

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__imc_phonebook_check_and_select_type(co, record->pb_type, &set_pb_cmd) != TRUE) {
		return ret;
	}

	/* Check whether index is used or not */
	__imc_phonebook_check_used_index(co, record->pb_type, record->index, &used_index);

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBR=%u", set_pb_cmd, used_index);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		(void *)&(record->pb_type), sizeof(TelPbType));

	/* Send Request to Modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CPBR",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_phonebook_read_record, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Read Record");

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
static TelReturn imc_phonebook_update_record(CoreObject *co,
		const TelPbUpdateRecord *req_data,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	gchar *set_pb_cmd;
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry");

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__imc_phonebook_check_and_select_type(co, req_data->pb_type, &set_pb_cmd) != TRUE) {
		return ret;
	}

	/* Set AT-Command according pb_type */
	if (req_data->pb_type == TEL_PB_USIM) {
		at_cmd = g_strdup_printf("%s+CPBW=%u,\"%s\",,\"%s\",\"%s\",\"%s\",,\"%s\",\"%s\",%d",
			set_pb_cmd, req_data->index,
			req_data->rec_u.usim.number, req_data->rec_u.usim.name,
			req_data->rec_u.usim.grp_name, req_data->rec_u.usim.anr[0].number,
			req_data->rec_u.usim.sne, req_data->rec_u.usim.email[0],
			req_data->rec_u.usim.hidden);
	} else {
		at_cmd = g_strdup_printf("%s+CPBW=%u,\"%s\",,\"%s\"",
			set_pb_cmd, req_data->index,
			req_data->rec_u.sim.number,
			req_data->rec_u.sim.name);
	}

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		(void *)req_data, sizeof(TelPbUpdateRecord));

	/* Send Request to Modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_phonebook_update_record, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Update Record");

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
static TelReturn imc_phonebook_delete_record(CoreObject *co,
		const TelPbRecordInfo *record,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	gchar *set_pb_cmd;
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry");

	/* Check whether pb_type is supported or not, and Select pb_type */
	if (__imc_phonebook_check_and_select_type(co, record->pb_type, &set_pb_cmd) != TRUE) {
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("%s+CPBW=%u", set_pb_cmd, record->index);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		(void *)record, sizeof(TelPbRecordInfo));

	/* Send Request to Modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_phonebook_delete_record, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Delete Record");

	/* Free resources */
	g_free(at_cmd);
	g_free(set_pb_cmd);

	return ret;
}

/* Phonebook Operations */
static TcorePbOps imc_phonebook_ops = {
	.get_info = imc_phonebook_get_info,
	.read_record = imc_phonebook_read_record,
	.update_record = imc_phonebook_update_record,
	.delete_record = imc_phonebook_delete_record,
};

gboolean imc_phonebook_init(TcorePlugin *p, CoreObject *co)
{
	PrivateInfo *private_info;

	dbg("Entry");

	/* Set PrivateInfo */
	private_info = tcore_malloc0(sizeof(PrivateInfo));
	tcore_object_link_user_data(co, private_info);

	/* Set operations */
	tcore_phonebook_set_ops(co, &imc_phonebook_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co, "+PBREADY", on_notification_imc_phonebook_status, NULL);

	dbg("Exit");
	return TRUE;
}

void imc_phonebook_exit(TcorePlugin *p, CoreObject *co)
{
	PrivateInfo *private_info;

	private_info = tcore_object_ref_user_data(co);
	tcore_check_return_assert(private_info != NULL);

	/* Free PrivateInfo */
	g_slist_free_full(private_info->used_index_fdn, g_free);
	g_slist_free_full(private_info->used_index_adn, g_free);
	g_slist_free_full(private_info->used_index_sdn, g_free);
	g_slist_free_full(private_info->used_index_usim, g_free);
	tcore_free(private_info);

	dbg("Exit");
}
