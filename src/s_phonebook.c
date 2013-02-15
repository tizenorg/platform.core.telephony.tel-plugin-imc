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
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_phonebook.h>
#include <co_sim.h>
#include <user_request.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_phonebook.h"

/* Constants */
#define VAL_ZERO	0
#define VAL_ONE		1
#define VAL_TWO		2
#define VAL_THREE	3
#define VAL_FOUR	4
#define VAL_FIVE	5
#define VAL_SIX		6
#define VAL_SEVEN	7
#define VAL_NINE	9

/* Type Of Number and Number Plan */
#define TON_INTERNATIONAL		145
#define TON_UNKNOWN				129
#define NUM_PLAN_INTERNATIONAL	0x0070
#define NUM_PLAN_UNKNOWN 		0x0060

enum pb_usim_file_type {
	PB_USIM_NAME = 0x01,		/**< Name */
	PB_USIM_NUMBER,				/**< Number */
	PB_USIM_ANR,				/**< Another number */
	PB_USIM_EMAIL,				/**< Email */
	PB_USIM_SNE,				/**< Second name entry */
	PB_USIM_GRP,				/**< Group file */
	PB_USIM_PBC,				/** <1 byte control info and 1 byte hidden info*/
	PB_USIM_ANRA,				/**< Another number a*/
	PB_USIM_ANRB,				/**< Another number b*/
	PB_USIM_ANRC,				/**< Another number c*/
	PB_USIM_EMAILA,				/**< email a*/
	PB_USIM_EMAILB,				/**< email b*/
	PB_USIM_EMAILC,				/**< email c*/
};

static TReturn _get_support_list(CoreObject *o);
static TReturn s_get_count(CoreObject *o, UserRequest *ur);
static TReturn s_get_info(CoreObject *o, UserRequest *ur);
static TReturn s_get_usim_info(CoreObject *o, UserRequest *ur);
static TReturn s_read_record(CoreObject *o, UserRequest *ur);
static TReturn s_update_record(CoreObject *o, UserRequest *ur);
static TReturn s_delete_record(CoreObject *o, UserRequest *ur);

static enum tcore_response_command _find_resp_command(UserRequest *ur)
{
	switch(tcore_user_request_get_command(ur))
	{
		case TREQ_PHONEBOOK_GETCOUNT:
			return TRESP_PHONEBOOK_GETCOUNT;
		case TREQ_PHONEBOOK_GETMETAINFO:
			return TRESP_PHONEBOOK_GETMETAINFO;
		case TREQ_PHONEBOOK_GETUSIMINFO:
			return TRESP_PHONEBOOK_GETUSIMINFO;
		case TREQ_PHONEBOOK_READRECORD:
			return TRESP_PHONEBOOK_READRECORD;
		case TREQ_PHONEBOOK_UPDATERECORD:
			return TRESP_PHONEBOOK_UPDATERECORD;
		case TREQ_PHONEBOOK_DELETERECORD:
			return TRESP_PHONEBOOK_DELETERECORD;
		default:
			return TRESP_UNKNOWN;
	}
}

static enum tel_phonebook_ton _find_num_plan(int number_plan)
{
	enum tel_phonebook_ton result;
	dbg("number_plan : 0x%04x", number_plan);

	if(number_plan & NUM_PLAN_INTERNATIONAL) {
		result = PB_TON_INTERNATIONAL;
	}
	else {
		result = PB_TON_UNKNOWN;
	}
	dbg("result : %d", result);
	return result;
}

static void on_confirmation_phonebook_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("msg out from queue");

	if (result == FALSE) {		/* Fail */
		dbg("SEND FAIL");
	}
	else {
		dbg("SEND OK");
	}
}

static char* _get_phonebook_type(enum tel_phonebook_type pb_type)
{
	char *phonebook_type = NULL;
	dbg(" Function entry ");
	dbg("pb_type = %d", pb_type);

	phonebook_type = (char*)calloc(sizeof(char), VAL_FIVE);
	if(NULL == phonebook_type) {
		err("Memory allcoation failed");
		return phonebook_type;
	}
	
	switch(pb_type)
	{
		case PB_TYPE_FDN:
			phonebook_type = "FD";
			break;
		case PB_TYPE_ADN:
		case PB_TYPE_AAS:
		case PB_TYPE_GAS:
			phonebook_type = "SM";
			break;
		case PB_TYPE_SDN:
			phonebook_type = "SN";
			break;
		case PB_TYPE_USIM:
			phonebook_type = "AP";
			break;
		default:
			dbg("Invalid pb_type [%02x]", pb_type);
			free(phonebook_type);
			phonebook_type = NULL;
			break;
	}
	dbg(" Function exit");
	return phonebook_type;
}

static enum tel_phonebook_type _get_phonebook_enum(const char* pb_type)
{
	enum tel_phonebook_type phonebook_type = PB_TYPE_UNKNOWNN;
	dbg(" Function entry ");
	dbg("pb_type = %s", pb_type);
	
	if(strcmp("FD", pb_type) == VAL_ZERO) {
		phonebook_type = PB_TYPE_FDN;
	}
	else if(strcmp("SM", pb_type) == VAL_ZERO) {
		phonebook_type = PB_TYPE_ADN;
	}
	else if(strcmp("SN", pb_type) == VAL_ZERO) {
		phonebook_type = PB_TYPE_SDN;
	}
	else if(strcmp("AP", pb_type) == VAL_ZERO) {
		phonebook_type = PB_TYPE_USIM;
	}
	
	dbg(" Function exit");
	return phonebook_type;
}

static gboolean on_event_phonebook_status(CoreObject *o, const void *event_info, void *user_data)
{
	dbg("Phonebook init received from modem");
	
	_get_support_list(o);
	
	return TRUE;
}

static void _on_response_select(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *o = NULL;
	enum tcore_request_command req_cmd = TREQ_UNKNOWN;
	int *selected_pb = user_data;
	GQueue *queue = NULL;
	dbg(" Function entry ");

	o = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	if (!ur){
		dbg("error - current ur is NULL");
		return;
	}

	queue = tcore_object_ref_user_data(o);
	if(queue) {
		ur = tcore_user_request_ref(ur);
	}
	
	req_cmd = tcore_user_request_get_command(ur);
	dbg("origin treq command [%x]", req_cmd);

	if(resp->success > VAL_ZERO) {
		dbg("RESPONSE OK");
		tcore_phonebook_set_selected_type(o, *selected_pb);
		switch (req_cmd)
		{
			case TREQ_PHONEBOOK_GETCOUNT:
				s_get_count(o, ur);
				break;
			case TREQ_PHONEBOOK_GETMETAINFO:
				s_get_info(o, ur);
				break;
			case TREQ_PHONEBOOK_GETUSIMINFO:
				s_get_usim_info(o, ur);
				break;
			case TREQ_PHONEBOOK_READRECORD:
				s_read_record(o, ur);
				break;
			case TREQ_PHONEBOOK_UPDATERECORD:
				s_update_record(o, ur);
				break;
			case TREQ_PHONEBOOK_DELETERECORD:
				s_delete_record(o, ur);
				break;
			default:
				dbg("not handled treq cmd[%d]", req_cmd);
				break;
		}
	}
	else
	{
		dbg("RESPONSE NOK");
		switch (req_cmd)
		{
			case TREQ_PHONEBOOK_GETCOUNT:
			{
				struct tresp_phonebook_get_count resp_getcount;
				dbg("error TREQ_PHONEBOOK_GETCOUNT");
				memset(&resp_getcount, 0x00, sizeof(struct tresp_phonebook_get_count));
				resp_getcount.result = PB_FAIL;
				tcore_user_request_send_response(ur, TRESP_PHONEBOOK_GETCOUNT, sizeof(struct tresp_phonebook_get_count), &resp_getcount);
			}
			break;
			case TREQ_PHONEBOOK_GETMETAINFO:
			{
				dbg("error TREQ_PHONEBOOK_GETMETAINFO");
			}
			break;
			case TREQ_PHONEBOOK_GETUSIMINFO:
			{
				dbg("error TREQ_PHONEBOOK_GETUSIMINFO");
			}
			break;
			case TREQ_PHONEBOOK_READRECORD:
			{
				struct tresp_phonebook_read_record resp_readrecord;
				dbg("error TREQ_PHONEBOOK_READRECORD");
				memset(&resp_readrecord, 0x00, sizeof(struct tresp_phonebook_read_record));
				resp_readrecord.result = PB_FAIL;
				resp_readrecord.phonebook_type = *selected_pb;
				tcore_user_request_send_response(ur, TRESP_PHONEBOOK_READRECORD, sizeof(struct tresp_phonebook_read_record), &resp_readrecord);
			}
			break;
			case TREQ_PHONEBOOK_UPDATERECORD:
			{
				struct tresp_phonebook_update_record resp_updaterecord;
				dbg("error TREQ_PHONEBOOK_UPDATERECORD");
				memset(&resp_updaterecord, 0x00, sizeof(struct tresp_phonebook_update_record));
				resp_updaterecord.result = PB_FAIL;
				tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_phonebook_update_record), &resp_updaterecord);
			}
			break;
			case TREQ_PHONEBOOK_DELETERECORD:
			{
				struct tresp_phonebook_delete_record resp_deleterecord;
				dbg("error TREQ_PHONEBOOK_DELETERECORD");
				memset(&resp_deleterecord, 0x00, sizeof(struct tresp_phonebook_delete_record));
				resp_deleterecord.result = PB_FAIL;
				tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_phonebook_delete_record), &resp_deleterecord);
			}
			break;
			default:
				dbg("not handled treq cmd[%d]", req_cmd);
			break;
		}

	}
	
	free(selected_pb);
	selected_pb = NULL;
	dbg(" Function exit");
}

static void on_response_get_count(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	GSList *tokens=NULL;
	const char *temp = NULL;
	struct tresp_phonebook_get_count res;
	char *pbtype = NULL;
	dbg(" Function entry ");

	ur = tcore_pending_ref_user_request(p);
	if (!ur){
		dbg("error - current ur is NULL");
		return;
	}

	memset(&res, 0x00, sizeof(struct tresp_phonebook_get_count));
	if(resp->success > VAL_ZERO) {
		dbg("RESPONSE OK");
		if(resp->lines) {
			temp = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(temp);
			if (g_slist_length(tokens) < VAL_ONE) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res.result = PB_SUCCESS;
		
		temp = (const char*)g_slist_nth_data(tokens, VAL_ZERO);
		pbtype =  util_removeQuotes((void*)temp);
		res.type = _get_phonebook_enum(pbtype);
		
		if(NULL != g_slist_nth_data(tokens, VAL_ONE)){
			res.used_count = atoi(g_slist_nth_data(tokens, VAL_ONE));
		}
		
		if(NULL != g_slist_nth_data(tokens, VAL_TWO)){
			res.total_count = atoi(g_slist_nth_data(tokens, VAL_TWO));
		}
		dbg("used count = %d,  total count= %d", res.used_count, res.total_count);
		free(pbtype);
		pbtype = NULL;
	}
	else{
		dbg("RESPONSE NOK");
		res.result = PB_FAIL;
	}

	tcore_user_request_send_response(ur, TRESP_PHONEBOOK_GETCOUNT, sizeof(struct tresp_phonebook_get_count), &res);
	
	tcore_at_tok_free(tokens);
	dbg(" Function exit");
}

static void on_response_get_info(TcorePending *p, int data_len, const void *data, void *user_data)
{
	struct tresp_phonebook_get_info res = {0,};
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	GSList *tokens=NULL;
	const char *line;
	int *selected_pb = (int*)user_data;

	dbg(" Function entry ");
	
	ur = tcore_pending_ref_user_request(p);
	if (!ur){
		dbg("error - current ur is NULL");
		return;
	}

	memset(&res, 0x00, sizeof(struct tresp_phonebook_get_info));
	res.type = *selected_pb;
	if(resp->success > VAL_ZERO) {
		dbg("RESPONSE OK");
		if(resp->lines) {
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < VAL_ONE) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res.result = PB_SUCCESS;
		
		res.number_length_max = atoi(g_slist_nth_data(tokens, VAL_ZERO));
		res.text_length_max = atoi(g_slist_nth_data(tokens, VAL_ONE));
		dbg("number_length_max %d text_length_max %d",res.number_length_max,res.text_length_max);
	}
	else{
		dbg("RESPONSE NOK");
		res.result = PB_FAIL;
	}

	tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_phonebook_get_info), &res);
	
	tcore_at_tok_free(tokens);
	free(selected_pb);
	selected_pb = NULL;
	dbg(" Function exit");
}

static void on_response_read_record(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	GSList *tokens=NULL;
	const char *line;
	struct tresp_phonebook_read_record res;
	int num_len = VAL_ZERO;
	int name_len = VAL_ZERO;
	int num_plan = VAL_ZERO;
	char *member = NULL;
	char *temp = NULL;
	int *selected_pb = (int*)user_data;

	dbg(" Function entry ");
	
	ur = tcore_pending_ref_user_request(p);
	if (!ur){
		dbg("error - current ur is NULL");
		return;
	}

	memset(&res, 0x00, sizeof(struct tresp_phonebook_read_record));
	res.phonebook_type = *selected_pb;
	
	if(resp->success > VAL_ZERO) {
		dbg("RESPONSE OK");
		if(resp->lines) {
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < VAL_ONE) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res.result = PB_SUCCESS;
		
		res.index = atoi(g_slist_nth_data(tokens, VAL_ZERO));
		res.next_index = (res.index + VAL_ONE);
		num_plan = atoi(g_slist_nth_data(tokens, VAL_TWO));
		res.ton = _find_num_plan(num_plan);

		temp = g_slist_nth_data(tokens, VAL_ONE);
		member =  util_removeQuotes((void*)temp);
		dbg("number %s - %d", member, (num_len-VAL_TWO));
		memcpy(res.number, member, strlen(member));
		free(member);
		member = NULL;

		temp = g_slist_nth_data(tokens, VAL_THREE);
		member =  util_removeQuotes((void*)temp);
		dbg("name %s - %d", member, strlen(member));
		memcpy(res.name, member, strlen(member));
		free(member);
		member = NULL;

		if(NULL != g_slist_nth_data(tokens, VAL_FOUR)) {
			if(atoi(g_slist_nth_data(tokens, VAL_FOUR)) == VAL_ZERO) {
				dbg("phonebook entry not hidden");
			}
			else{
				dbg("phonebook entry hidden");
			}
		}

		if(NULL != g_slist_nth_data(tokens, VAL_SIX)){
			num_len =  strlen(g_slist_nth_data(tokens, VAL_SIX));
			snprintf((char *)res.anr1, num_len+1, "%s", (char*)g_slist_nth_data(tokens, VAL_SIX));
		}
		
		if(NULL != g_slist_nth_data(tokens, VAL_SEVEN)){
			num_plan = atoi(g_slist_nth_data(tokens, VAL_SEVEN));
			res.anr1_ton = _find_num_plan(num_plan);
		}
		
		if(NULL != g_slist_nth_data(tokens, VAL_NINE)){
			name_len = strlen(g_slist_nth_data(tokens, VAL_NINE));
			memcpy(res.email1, g_slist_nth_data(tokens, VAL_NINE), name_len);
		}
	}
	else{
		dbg("RESPONSE NOK");
		res.result = PB_FAIL;
	}
	
	tcore_user_request_send_response(ur, TRESP_PHONEBOOK_READRECORD, sizeof(struct tresp_phonebook_read_record), &res);
	
	tcore_at_tok_free(tokens);
	free(selected_pb);
	selected_pb = NULL;
	dbg(" Function exit");
}

static void on_response_update_record(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_phonebook_update_record res;
	dbg(" Function entry ");

	if(resp->success > VAL_ZERO) {
		dbg("RESPONSE OK");
		res.result = PB_SUCCESS;
	}
	else{
		dbg("RESPONSE NOK");
		res.result = PB_FAIL;
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur){
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_phonebook_update_record),
				&res);
	}
	else{
		dbg("error - current ur is NULL");
	}

}

static void on_response_delete_record(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_phonebook_delete_record res;

	if(resp->success > VAL_ZERO) {
		dbg("RESPONSE OK");
		res.result = PB_SUCCESS;
	}
	else{
		dbg("RESPONSE NOK");
		res.result = PB_FAIL;
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur){
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_phonebook_delete_record), &res);
	}
	else{
		dbg("error - current ur is NULL");
	}
}

static void _response_get_support_list(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject*o = NULL;
	GSList *tokens=NULL;
	const char *line;
	char *temp = NULL;
	char *pbtype = NULL;
	struct tnoti_phonebook_status noti_data = {0,};

	dbg(" Function entry ");

	o = tcore_pending_ref_core_object(p);
	if(!o){
		dbg("error -  core object is null");
		return;
	}

	if(resp->success > VAL_ZERO) {
		dbg("RESPONSE OK");
		if(resp->lines) {
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < VAL_ONE) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}

		temp = (char*)g_slist_nth_data(tokens, VAL_ZERO);
		pbtype = strtok(temp, "(,)");
		while(pbtype != NULL) {
			temp =  util_removeQuotes((void*)pbtype);
			dbg("pbtype %s", temp);
			if (VAL_ZERO == strcmp(temp, "FD")) {
				dbg("SIM fixed-dialing phonebook");
				noti_data.support_list.b_fdn = VAL_ONE;
			}
			else if (VAL_ZERO == strcmp(temp, "SN")) {
				dbg("Service Dialing Number");
				noti_data.support_list.b_sdn = VAL_ONE;
			}
			else if (VAL_ZERO == strcmp(temp, "SM")) {
				dbg("2G SIM ADN phonebook");
				noti_data.support_list.b_adn = VAL_ONE;
			}
			else if (VAL_ZERO == strcmp(temp, "LD")) {
				dbg("SIM/UICC last-dialling-phonebook");
			}
			else if (VAL_ZERO == strcmp(temp, "ON")) {
				dbg("SIM (or MT) own numbers (MSISDNs) list");
			}
			else if (VAL_ZERO == strcmp(temp, "BL")) {
				dbg("Blacklist phonebook");
			}
			else if (VAL_ZERO == strcmp(temp, "EC")) {
				dbg("SIM emergency-call-codes phonebook");
			}
			else if (VAL_ZERO == strcmp(temp, "AP")) {
				dbg("Selected application phonebook");
			}
			else if (VAL_ZERO == strcmp(temp, "BN")) {
				dbg("SIM barred-dialling-number");
			}
			pbtype = strtok (NULL, "(,)");
			g_free(temp);
		}
		
		noti_data.b_init = TRUE;
		tcore_phonebook_set_support_list(o, &noti_data.support_list);
		tcore_phonebook_set_status(o, noti_data.b_init);
		tcore_at_tok_free(tokens);
	}
	else{
		dbg("RESPONSE NOK");
		noti_data.b_init = FALSE;
		tcore_phonebook_set_status(o, noti_data.b_init);
	}

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_PHONEBOOK_STATUS,
			sizeof(struct tnoti_phonebook_status), &noti_data);
}

static	TReturn _get_support_list(CoreObject *o)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;

	dbg(" Function entry ");

	if (!o){
		return TCORE_RETURN_EINVAL;
	}

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, VAL_ZERO);

	cmd_str = g_strdup_printf("AT+CPBS=?");
	req = tcore_at_request_new(cmd_str, "+CPBS:", TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, VAL_ZERO, req);
	tcore_pending_set_response_callback(pending, _response_get_support_list, NULL);
	tcore_pending_set_send_callback(pending, on_confirmation_phonebook_message_send, NULL);
	
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn _select(CoreObject *o, UserRequest *ur, enum tel_phonebook_type pbt)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_phonebook_get_count *req_data;
	int *pb_type = NULL;
	char *phonebook_type = NULL;

	dbg(" Function entry ");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	
	req_data = tcore_user_request_ref_data(ur, NULL);

	phonebook_type = (char*)_get_phonebook_type(req_data->phonebook_type);
	if(NULL == phonebook_type){
		err("phonebook_type is NULL");
		return TCORE_RETURN_FAILURE;
	}
	
	pb_type = calloc(sizeof(enum tel_phonebook_type),VAL_ONE);
	if(pb_type == NULL) {
		err("Failed to allocate memory");
		return TCORE_RETURN_FAILURE;
	}
	*pb_type = pbt;

	cmd_str = g_strdup_printf("AT+CPBS=\"%s\"", phonebook_type);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, VAL_ZERO);
	tcore_pending_set_request_data(pending, VAL_ZERO, req);
	tcore_pending_set_response_callback(pending, _on_response_select, (void*)pb_type);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_phonebook_message_send, NULL);
	
	tcore_hal_send_request(hal, pending);

	free(phonebook_type);
	g_free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn s_get_count(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_phonebook_get_count *req_data = NULL;
	enum tel_phonebook_type pbt = PB_TYPE_UNKNOWNN;

	dbg("Function Entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);
	pbt = tcore_phonebook_get_selected_type(o);
	if (req_data->phonebook_type != pbt) {
		dbg("req pb[%d] is different with tcore pb[%d]", req_data->phonebook_type, pbt);
		_select(o, ur, req_data->phonebook_type);
		return TCORE_RETURN_SUCCESS;
	}

	cmd_str = g_strdup_printf("AT+CPBS?");
	req = tcore_at_request_new(cmd_str, "+CPBS:", TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, VAL_ZERO);
	
	tcore_pending_set_request_data(pending, VAL_ZERO, req);
	tcore_pending_set_response_callback(pending, on_response_get_count, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_phonebook_message_send, NULL);
	
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	dbg("Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn s_get_info(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_phonebook_get_info *req_data = NULL;
	enum tel_phonebook_type pbt = PB_TYPE_UNKNOWNN;
	int *pb_type = NULL;

	dbg(" Function entry ");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);
	pbt = tcore_phonebook_get_selected_type(o);
	if (req_data->phonebook_type != pbt) {
		dbg("req pb[%d] is different with tcore pb[%d]", req_data->phonebook_type, pbt);
		_select(o, ur, req_data->phonebook_type);
		return TCORE_RETURN_SUCCESS;
	}

	pb_type = calloc(sizeof(enum tel_phonebook_type),VAL_ONE);
	if(pb_type == NULL) {
		err("Failed to allocate memory");
		return TCORE_RETURN_FAILURE;
	}
	*pb_type = pbt;
	dbg("pb_type %d", *pb_type);

	cmd_str = g_strdup_printf("AT+CPBF=?");
	req = tcore_at_request_new(cmd_str, "+CPBF:", TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, VAL_ZERO);

	tcore_pending_set_request_data(pending, VAL_ZERO, req);
	tcore_pending_set_response_callback(pending, on_response_get_info, (void*)pb_type);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_phonebook_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;

}

static TReturn s_get_usim_info(CoreObject *o, UserRequest *ur)
{
	dbg("NOT IMPLEMENTED");

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_read_record(CoreObject *o, UserRequest *ur)
{
	TcoreHal*hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_phonebook_read_record *req_data = NULL;
	enum tel_phonebook_type pbt = PB_TYPE_UNKNOWNN;
	int *pb_type = NULL;

	dbg(" Function entry ");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);
	pbt = tcore_phonebook_get_selected_type(o);
	if (req_data->phonebook_type != pbt) {
		dbg("req pb[%d] is different with tcore pb[%d]", req_data->phonebook_type, pbt);
		_select(o, ur, req_data->phonebook_type);
		return TCORE_RETURN_SUCCESS;
	}

	pb_type = calloc(sizeof(enum tel_phonebook_type),VAL_ONE);
	if(pb_type == NULL) {
		err("Failed to allocate memory");
		return TCORE_RETURN_FAILURE;
	}
	*pb_type = pbt;
	dbg("pb_type %d", *pb_type);

	cmd_str = g_strdup_printf("AT+CPBR=%d,%d", req_data->index, req_data->index);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, VAL_ZERO);

	tcore_pending_set_request_data(pending, VAL_ZERO, req);
	tcore_pending_set_response_callback(pending, on_response_read_record, (void*)pb_type);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_phonebook_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn s_update_record(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_phonebook_update_record *req_data = NULL;
	enum tel_phonebook_type pbt = PB_TYPE_UNKNOWNN;

	dbg(" Function entry ");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);
	pbt = tcore_phonebook_get_selected_type(o);
	if (req_data->phonebook_type != pbt) {
		dbg("req pb[%d] is different with tcore pb[%d]", req_data->phonebook_type, pbt);
		_select(o, ur, req_data->phonebook_type);
		return TCORE_RETURN_SUCCESS;
	}

	cmd_str = g_strdup_printf("AT+CPBW=,\"%s\",%d,\"%s\"", req_data->number, ((PB_TON_INTERNATIONAL == req_data->ton) ? TON_INTERNATIONAL: TON_UNKNOWN), req_data->name);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, VAL_ZERO);
	
	tcore_pending_set_request_data(pending, VAL_ZERO, req);
	tcore_pending_set_response_callback(pending, on_response_update_record, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_phonebook_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn s_delete_record(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_phonebook_delete_record *req_data;
	enum tel_phonebook_type pbt = PB_TYPE_UNKNOWNN;

	dbg(" Function entry ");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);
	pbt = tcore_phonebook_get_selected_type(o);
	if (req_data->phonebook_type != pbt) {
		dbg("req pb[%d] is different with tcore pb[%d]", req_data->phonebook_type, pbt);
		_select(o, ur, req_data->phonebook_type);
		return TCORE_RETURN_SUCCESS;
	}

	cmd_str = g_strdup_printf("AT+CPBW=%d", req_data->index);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, VAL_ZERO);

	tcore_pending_set_request_data(pending, VAL_ZERO, req);
	tcore_pending_set_response_callback(pending, on_response_delete_record, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_phonebook_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_phonebook_operations phonebook_ops = {
	.get_count = s_get_count,
	.get_info = s_get_info,
	.get_usim_info = s_get_usim_info,
	.read_record = s_read_record,
	.update_record = s_update_record,
	.delete_record = s_delete_record,
};

gboolean s_phonebook_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *o = NULL;

	dbg("Entry");
	o = tcore_phonebook_new(p, "phonebook", &phonebook_ops, h);
	if (!o)
		return FALSE;

	tcore_object_add_callback(o, "+PBREADY", on_event_phonebook_status, NULL);
	dbg("Exit");
	return TRUE;
}

void s_phonebook_exit(TcorePlugin *p)
{
	CoreObject *o = NULL;
	o = tcore_plugin_ref_core_object(p, "phonebook");
	if (!o)
		return;

	tcore_phonebook_free(o);
}
