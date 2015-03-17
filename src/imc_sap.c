/*
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
#include <co_sap.h>
#include <co_sim.h>
#include <user_request.h>
#include <server.h>
#include <at.h>

#include "imc_common.h"
#include "imc_sap.h"


static void on_confirmation_sap_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("on_confirmation_sap_message_send - msg out from queue.\n");

	if (result == FALSE) {
		/* Fail */
		dbg("SEND FAIL");
	} else {
		dbg("SEND OK");
	}
}

static gboolean on_event_sap_status(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_sap_status_changed noti;
	GSList *tokens = NULL;
	GSList *lines = NULL;
	const char *line = NULL;
	int status = 0;

	dbg(" Function entry ");

	lines = (GSList *) event_info;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		return FALSE;
	}
	line = (char *) (lines->data);

	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) != 1) {
		msg("invalid message");
		tcore_at_tok_free(tokens);
		return FALSE;
	}
	status = atoi(g_slist_nth_data(tokens, 0));

	switch(status){
		case 0:
			noti.status = SAP_CARD_STATUS_UNKNOWN;
			break;
		case 1:
			noti.status = SAP_CARD_STATUS_RESET;
			break;
		case 2:
			noti.status = SAP_CARD_STATUS_NOT_ACCESSIBLE;
			break;
		case 3:
			noti.status = SAP_CARD_STATUS_REMOVED;
			break;
		case 4:
			noti.status = SAP_CARD_STATUS_INSERTED;
			break;
		case 5:
			noti.status = SAP_CARD_STATUS_RECOVERED;
			break;
		default:
			noti.status = SAP_CARD_STATUS_NOT_ACCESSIBLE;
			break;
	}

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SAP_STATUS,
			sizeof(struct tnoti_sap_status_changed), &noti);
	return TRUE;
}

/*static void on_event_sap_disconnect(CoreObject *o, const void *event_info, void *user_data)
{
	//ToDo - Indication not present

	const ipc_sap_disconnect_noti_type *ipc = event_info;
	struct tnoti_sap_disconnect noti;

	dbg("NOTI RECEIVED");

	noti.type = ipc->disconnect_type;
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SAP_DISCONNECT,
				sizeof(struct tnoti_sap_disconnect), &noti);
}*/

static void on_response_connect(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_req_connect res;
	int *max_msg_size = (int *)user_data;

	dbg(" Function entry ");

	memset(&res, 0x00, sizeof(struct tresp_sap_req_connect));
	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");

		res.status = SAP_CONNECTION_STATUS_OK;
		res.max_msg_size = *max_msg_size;

	}else{
		dbg("RESPONSE NOK");
		res.status = SAP_CONNECTION_STATUS_UNABLE_TO_ESTABLISH;
		res.max_msg_size = 0;
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_REQ_CONNECT, sizeof(struct tresp_sap_req_connect), &res);
	}
	dbg(" Function exit");
}

static void on_response_disconnect(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_req_disconnect res;

	dbg(" Function entry ");
	memset(&res, 0x00, sizeof(struct tresp_sap_req_disconnect));
	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");

		res.result = SAP_RESULT_CODE_OK;

	}else{
		dbg("RESPONSE NOK");
		//ToDo - Error mapping
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_REQ_DISCONNECT, sizeof(struct tresp_sap_req_disconnect), &res);
	}
	dbg(" Function exit");
}

static void on_response_req_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_req_status res;

	dbg(" Function entry ");

	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");
		//ToDo - No AT command present
		//res.status = NULL;

	}else{
		dbg("RESPONSE NOK");
		//ToDo - Error mapping
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_REQ_STATUS, sizeof(struct tresp_sap_req_status), &res);
	}
	dbg(" Function exit");
}

static void on_response_set_transfort_protocol(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_set_protocol res;

	dbg(" Function entry ");

	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");
		//ToDo - No AT command present
		//res.result = NULL;

	}else{
		dbg("RESPONSE NOK");
		//ToDo - Error mapping
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_SET_PROTOCOL, sizeof(struct tresp_sap_set_protocol), &res);
	}
	dbg(" Function exit");
}

static void on_response_set_power(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_set_power res;
	GSList *tokens=NULL;
	const char *line;
	int sap_status = -1;

	dbg(" Function entry ");

	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");
		if(resp->lines) {
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sap_status = atoi(g_slist_nth_data(tokens, 0));

		switch(sap_status){
			case 0:
				res.result = SAP_RESULT_CODE_OK;
				break;
			case 1:
				res.result = SAP_RESULT_CODE_NO_REASON;
				break;
			case 2:
				res.result = SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE;
				break;
			case 3:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_OFF;
				break;
			case 4:
				res.result = SAP_RESULT_CODE_CARD_REMOVED;
				break;
			case 5:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_ON;
				break;
			case 6:
				res.result = SAP_RESULT_CODE_DATA_NOT_AVAILABLE;
				break;
			case 7:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
			default:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
		}

	}else{
		dbg("RESPONSE NOK");
		res.result = SAP_RESULT_CODE_NOT_SUPPORT;
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_SET_POWER, sizeof(struct tresp_sap_set_power), &res);
	}
	tcore_at_tok_free(tokens);
	dbg(" Function exit");
}

static void on_response_get_atr(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_req_atr res;
	GSList *tokens=NULL;
	const char *line;
	int sap_status = -1;
	char *atr_data = NULL;

	dbg(" Function entry ");

	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");

		if(resp->lines) {
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sap_status = atoi(g_slist_nth_data(tokens, 0));
		atr_data = (char *) g_slist_nth_data(tokens, 1);

		res.atr_length = strlen(atr_data);
		if( res.atr_length > 256 ) {
			dbg(" Memory overflow handling");
			return;
		}
		memcpy(res.atr, atr_data, res.atr_length);

		switch(sap_status){
			case 0:
				res.result = SAP_RESULT_CODE_OK;
				break;
			case 1:
				res.result = SAP_RESULT_CODE_NO_REASON;
				break;
			case 2:
				res.result = SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE;
				break;
			case 3:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_OFF;
				break;
			case 4:
				res.result = SAP_RESULT_CODE_CARD_REMOVED;
				break;
			case 5:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_ON;
				break;
			case 6:
				res.result = SAP_RESULT_CODE_DATA_NOT_AVAILABLE;
				break;
			case 7:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
			default:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
		}

	}else{
		dbg("RESPONSE NOK");
		res.result = SAP_RESULT_CODE_NOT_SUPPORT;
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_REQ_ATR, sizeof(struct tresp_sap_req_atr), &res);
	}
	dbg(" Function exit");
}

static void on_response_transfer_apdu(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_transfer_apdu res;
	GSList *tokens=NULL;
	const char *line;
	int sap_status = -1;
	char *apdu_data = NULL;

	dbg(" Function entry ");

	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");

		if(resp->lines) {
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sap_status = atoi(g_slist_nth_data(tokens, 0));
		apdu_data = (char *) g_slist_nth_data(tokens, 1);

		res.resp_apdu_length = strlen(apdu_data);
		if( res.resp_apdu_length > 256 ) {
			dbg(" Memory overflow handling");
			return;
		}
		memcpy(res.resp_adpdu, apdu_data, res.resp_apdu_length);

		switch(sap_status){
			case 0:
				res.result = SAP_RESULT_CODE_OK;
				break;
			case 1:
				res.result = SAP_RESULT_CODE_NO_REASON;
				break;
			case 2:
				res.result = SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE;
				break;
			case 3:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_OFF;
				break;
			case 4:
				res.result = SAP_RESULT_CODE_CARD_REMOVED;
				break;
			case 5:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_ON;
				break;
			case 6:
				res.result = SAP_RESULT_CODE_DATA_NOT_AVAILABLE;
				break;
			case 7:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
			default:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
		}

	}else{
		dbg("RESPONSE NOK");
		res.result = SAP_RESULT_CODE_NOT_SUPPORT;
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_TRANSFER_APDU, sizeof(struct tresp_sap_transfer_apdu), &res);
	}
	dbg(" Function exit");
}

static void on_response_get_cardreader_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	struct tresp_sap_req_cardreaderstatus res;
	GSList *tokens=NULL;
	const char *line;
	int sap_status = -1;
	char *card_reader_status = NULL;

	dbg(" Function entry ");

	ur = tcore_pending_ref_user_request(p);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");

		if(resp->lines) {
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sap_status = atoi(g_slist_nth_data(tokens, 0));
		card_reader_status = (char *) g_slist_nth_data(tokens, 1);

		res.reader_status = *card_reader_status;

		switch(sap_status){
			case 0:
				res.result = SAP_RESULT_CODE_OK;
				break;
			case 1:
				res.result = SAP_RESULT_CODE_NO_REASON;
				break;
			case 2:
				res.result = SAP_RESULT_CODE_CARD_NOT_ACCESSIBLE;
				break;
			case 3:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_OFF;
				break;
			case 4:
				res.result = SAP_RESULT_CODE_CARD_REMOVED;
				break;
			case 5:
				res.result = SAP_RESULT_CODE_CARD_ALREADY_POWER_ON;
				break;
			case 6:
				res.result = SAP_RESULT_CODE_DATA_NOT_AVAILABLE;
				break;
			case 7:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
			default:
				res.result = SAP_RESULT_CODE_NOT_SUPPORT;
				break;
		}

	}else{
		dbg("RESPONSE NOK");
		res.result = SAP_RESULT_CODE_NOT_SUPPORT;
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAP_REQ_CARDREADERSTATUS, sizeof(struct tresp_sap_req_cardreaderstatus), &res);
	}
	dbg(" Function exit");
}

static	TReturn imc_connect(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sap_req_connect *req_data;
	int *usr_data = NULL;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	req_data = tcore_user_request_ref_data(ur, NULL);
	usr_data = (int*)malloc(sizeof(int));
	*usr_data = req_data->max_msg_size;
	cmd_str = g_strdup_printf("AT+XBCON=0,0,0");

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_connect, usr_data);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn imc_disconnect(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	//const struct treq_sap_req_disconnect *req_data;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	//req_data = tcore_user_request_ref_data(ur, NULL);

	cmd_str = g_strdup_printf("AT+ XBDISC");

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_disconnect, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_req_status(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	//const struct treq_sap_req_status *req_data;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	//req_data = tcore_user_request_ref_data(ur, NULL);

	//cmd_str = g_strdup_printf("");//ToDo - No AT command present.

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_req_status, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_set_transport_protocol(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	//const struct treq_sap_set_protocol *req_data;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	//req_data = tcore_user_request_ref_data(ur, NULL);

	//cmd_str = g_strdup_printf("");//ToDo - No AT command present.

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_set_transfort_protocol, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn imc_set_power(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sap_set_power *req_data;
	int action = -1;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	req_data = tcore_user_request_ref_data(ur, NULL);

	if(req_data->mode == SAP_POWER_ON) {
		action = 0;
	} else if ( req_data->mode == SAP_POWER_OFF ) {
		action = 1;
	} else if ( req_data->mode == SAP_POWER_RESET ) {
		action = 2;
	} else {
		action = -1;;
	}

	cmd_str = g_strdup_printf("AT+ XBPWR=%d", action);

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_set_power, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn imc_get_atr(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	//const struct treq_sap_req_atr *req_data;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	//req_data = tcore_user_request_ref_data(ur, NULL);

	cmd_str = g_strdup_printf("AT+ XBATR");

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_get_atr, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn imc_transfer_apdu(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sap_transfer_apdu *req_data;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	req_data = tcore_user_request_ref_data(ur, NULL);

	cmd_str = g_strdup_printf("AT+ XBAPDU=\"%s\"", req_data->apdu_data); //ToDo - Need to check passing input as a string.

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_transfer_apdu, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static	TReturn imc_get_cardreader_status(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	//const struct treq_sap_req_cardreaderstatus *req_data;

	dbg(" Function entry");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	//req_data = tcore_user_request_ref_data(ur, NULL);

	cmd_str = g_strdup_printf("AT+ XBCRDSTAT");

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_get_cardreader_status, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sap_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_sap_operations sap_ops =
{
	.connect = imc_connect,
	.disconnect = imc_disconnect,
	.req_status = imc_req_status,
	.set_transport_protocol = imc_set_transport_protocol,
	.set_power = imc_set_power,
	.get_atr = imc_get_atr,
	.transfer_apdu = imc_transfer_apdu,
	.get_cardreader_status = imc_get_cardreader_status,
};


gboolean imc_sap_init(TcorePlugin *cp, CoreObject *co_sap)
{
	dbg("Entry");

	/* Set operations */
	tcore_sap_set_ops(co_sap, &sap_ops);

	tcore_object_add_callback(co_sap,"+XBCSTAT", on_event_sap_status, NULL);

	dbg("Exit");

	return TRUE;
}

void imc_sap_exit(TcorePlugin *cp, CoreObject *co_sap)
{
	dbg("Exit");
}
