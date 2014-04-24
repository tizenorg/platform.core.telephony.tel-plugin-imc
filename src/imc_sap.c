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

#include <co_sap.h>

#include "imc_sap.h"
#include "imc_common.h"

static TelSapResult __imc_sap_convert_cme_error_tel_sap_result(const TcoreAtResponse *at_resp)
{
	TelSapResult result = TEL_SAP_RESULT_FAILURE_NO_REASON;
	const gchar *line;
	GSList *tokens = NULL;

	dbg("Entry");

	if (!at_resp || !at_resp->lines) {
		err("Invalid response data");
		return result;
	}

	line = (const gchar *)at_resp->lines->data;
	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) > 0) {
		gchar *resp_str;
		gint cme_err;

		resp_str = g_slist_nth_data(tokens, 0);
		if (!resp_str) {
			err("Invalid CME Error data");
			tcore_at_tok_free(tokens);
			return result;
		}
		cme_err = atoi(resp_str);
		dbg("CME Error: [%d]", cme_err);

		switch (cme_err) {
		case 3:
		case 4:
			result = TEL_SAP_RESULT_OPERATION_NOT_PERMITTED;
		break;

		case 14:
			result = TEL_SAP_RESULT_ONGOING_CALL;
		break;

		default:
			result = TEL_SAP_RESULT_FAILURE_NO_REASON;
		}
	}
	tcore_at_tok_free(tokens);

	return result;
}

static TelSapResult __map_sap_status_to_result(int sap_status)
{
	switch(sap_status){
	case 0:
		return TEL_SAP_RESULT_SUCCESS;
	case 1:
		return TEL_SAP_RESULT_FAILURE_NO_REASON;
	case 2:
		return TEL_SAP_RESULT_CARD_NOT_ACCESSIBLE;
	case 3:
		return TEL_SAP_RESULT_CARD_ALREADY_POWERED_OFF;
	case 4:
		return TEL_SAP_RESULT_CARD_REMOVED;
	case 5:
		return TEL_SAP_RESULT_CARD_ALREADY_POWERED_ON;
	case 6:
		return TEL_SAP_RESULT_DATA_NOT_AVAILABLE;
	case 7:
		return TEL_SAP_RESULT_NOT_SUPPORTED;
	default:
		return TEL_SAP_RESULT_FAILURE_NO_REASON;
	}
}

/* Notification */
static gboolean on_notification_imc_sap_status(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	const char *line = NULL;
	TelSapCardStatus status;

	dbg("Entry");

	lines = (GSList *) event_info;
	if (g_slist_length(lines) != 1) {
		err("unsolicited msg but multiple lines");
		return FALSE;
	}

	line = (char *)lines->data;
	tokens = tcore_at_tok_new(line);
	tcore_check_return_value(tokens != NULL, FALSE);

	status = atoi(g_slist_nth_data(tokens, 0));

	switch(status){
	case 0:
		status = TEL_SAP_CARD_STATUS_UNKNOWN;
		break;
	case 1:
		status = TEL_SAP_CARD_STATUS_RESET;
		break;
	case 2:
		status = TEL_SAP_CARD_STATUS_NOT_ACCESSIBLE;
		break;
	case 3:
		status = TEL_SAP_CARD_STATUS_REMOVED;
		break;
	case 4:
		status = TEL_SAP_CARD_STATUS_INSERTED;
		break;
	case 5:
		status = TEL_SAP_CARD_STATUS_RECOVERED;
		break;
	default:
		status = TEL_SAP_CARD_STATUS_NOT_ACCESSIBLE;
		break;
	}

	tcore_at_tok_free(tokens);
	tcore_object_send_notification(co,
		TCORE_NOTIFICATION_SAP_STATUS,
	 	sizeof(TelSapCardStatus), &status);
	return TRUE;
}

/* Response */
static void on_response_imc_sap_req_connect(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSapResult result = TEL_SAP_RESULT_UNABLE_TO_ESTABLISH;
	unsigned int max_msg_size = 0;
	dbg("entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_SAP_RESULT_SUCCESS;
		memcpy(&max_msg_size, IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data), sizeof(unsigned int));
	} else {
		err("RESPONSE NOK");

		if (at_resp->lines){
			err("CME error[%s]", at_resp->lines->data);
			result = __imc_sap_convert_cme_error_tel_sap_result(at_resp);
			if (result == TEL_SAP_RESULT_FAILURE_NO_REASON)
				result = TEL_SAP_RESULT_UNABLE_TO_ESTABLISH;
		}
	}

	dbg("Request to sap connection : [%s]",
	(result == TEL_SAP_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &max_msg_size, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sap_req_disconnect(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSapResult result = TEL_SAP_RESULT_FAILURE_NO_REASON;
	dbg("entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_SAP_RESULT_SUCCESS;
	} else {
		err("RESPONSE NOK");

		if (at_resp->lines){
			err("CME error[%s]", at_resp->lines->data);
			result = __imc_sap_convert_cme_error_tel_sap_result(at_resp);
		}
	}

	dbg("Request to sap connection : [%s]",
	(result == TEL_SAP_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sap_get_atr(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSapResult result = TEL_SAP_RESULT_FAILURE_NO_REASON;
	TelSapAtr atr_resp = {0,};

	dbg("entry");

	if (at_resp && at_resp->success) {
		const gchar *line;
		char *atr_data;
		GSList *tokens = NULL;

		dbg("RESPONSE OK");
		if (at_resp->lines == NULL) {
			err("invalid response recieved");
			goto END;
		}

		line = (const char*)at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("invalid response message");
			tcore_at_tok_free(tokens);
			goto END;
		}
		atr_data = (char *) g_slist_nth_data(tokens, 1);
		atr_resp.atr_len = strlen(atr_data);
		if (atr_resp.atr_len > TEL_SAP_ATR_LEN_MAX) {
			err(" invalid atr data length");
			tcore_at_tok_free(tokens);
			goto END;
		}
		memcpy(atr_resp.atr, atr_data, atr_resp.atr_len);

		result = __map_sap_status_to_result(atoi(g_slist_nth_data(tokens, 0)));
		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");

		if (at_resp->lines){
			err("CME error[%s]", at_resp->lines->data);
			result = __imc_sap_convert_cme_error_tel_sap_result(at_resp);
		}
	}

END:
	dbg("Request to get sap atr : [%s]",
		(result == TEL_SAP_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &atr_resp, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sap_req_transfer_apdu(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSapResult result = TEL_SAP_RESULT_FAILURE_NO_REASON;
	TelSapApduResp apdu_resp = {0,};

	dbg("entry");

	if (at_resp && at_resp->success) {
		const gchar *line;
		int sap_status;
		char *apdu_data;
		GSList *tokens = NULL;

		dbg("RESPONSE OK");
		if (at_resp->lines == NULL) {
			err("invalid response recieved");
			goto END;
		}

		line = (const char*)at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("invalid response message");
			tcore_at_tok_free(tokens);
			goto END;
		}

		apdu_data = (char *) g_slist_nth_data(tokens, 1);
		apdu_resp.apdu_resp_len = strlen(apdu_data);
		if (apdu_resp.apdu_resp_len > TEL_SAP_APDU_RESP_LEN_MAX) {
			err(" invalid apdu data length");
			tcore_at_tok_free(tokens);
			goto END;
		}
		memcpy(apdu_resp.apdu_resp, apdu_data, apdu_resp.apdu_resp_len);

		sap_status = atoi(g_slist_nth_data(tokens, 0));
		if (sap_status > 4)
		/* In this case modem does not provide sap_status 5 ('Card already powered ON'),
		   instead it will provide status 5 ('Data not available') and 6 ('Not Supported'),
		   So to align 'sap_status' value with __map_sap_status_to_result(), it is increased by 1.
		*/
			result = __map_sap_status_to_result(sap_status + 1);
		else
			result = __map_sap_status_to_result(sap_status);

		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");

		if (at_resp->lines){
			err("CME error[%s]", at_resp->lines->data);
			result = __imc_sap_convert_cme_error_tel_sap_result(at_resp);
		}
	}

END:
	dbg("Request to transfer apdu : [%s]",
		(result == TEL_SAP_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &apdu_resp, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sap_req_power_operation(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSapResult result = TEL_SAP_RESULT_FAILURE_NO_REASON;

	dbg("entry");

	if (at_resp && at_resp->success) {
		const gchar *line;
		GSList *tokens = NULL;

		dbg("RESPONSE OK");
		if (at_resp->lines == NULL) {
			err("invalid response recieved");
			goto END;
		}

		line = (const char*)at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("invalid response message");
			tcore_at_tok_free(tokens);
			goto END;
		}
		result = __map_sap_status_to_result(atoi(g_slist_nth_data(tokens, 0)));
		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");

		if (at_resp->lines){
			err("CME error[%s]", at_resp->lines->data);
			result = __imc_sap_convert_cme_error_tel_sap_result(at_resp);
		}
	}

END:
	dbg("Request to sap power operation : [%s]",
		(result == TEL_SAP_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sap_get_cardreader_status(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSapResult result = TEL_SAP_RESULT_FAILURE_NO_REASON;
	TelSapCardStatus card_status = TEL_SAP_CARD_STATUS_UNKNOWN;
	dbg("entry");

	if (at_resp && at_resp->success) {
		const gchar *line;
		GSList *tokens = NULL;
		unsigned char card_reader_status;
		int count;

		dbg("RESPONSE OK");
		if (at_resp->lines == NULL) {
			err("invalid response recieved");
			goto END;
		}

		line = (const char*)at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("invalid response message");
			tcore_at_tok_free(tokens);
			goto END;
		}
		result = __map_sap_status_to_result(atoi(g_slist_nth_data(tokens, 0)));

		card_reader_status = (unsigned char)atoi(g_slist_nth_data(tokens, 1));
		card_reader_status = card_reader_status >> 3;
		for (count = 8; count > 3; count--) { //check bit 8 to 3
			if ((card_reader_status & 0x80) == TRUE) { //Check most significant bit
				//card_status =  //TODO - Need to map card reader status to TelSapCardStatus.
				break;
			}
			card_reader_status = card_reader_status << 1; //left shift by 1
		}
		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");
		if (at_resp->lines){
			err("CME error[%s]", at_resp->lines->data);
			result = __imc_sap_convert_cme_error_tel_sap_result(at_resp);
		}
	}

END:
	dbg("Request to get card reader status : [%s]",
		(result == TEL_SAP_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &card_status, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

/* Sap operations */

/*
 * Operation - switch the modem to the  BT SAP server mode.
 *
 * Request -
 * AT-Command: AT+ XBCON = <op_mode>, <change_mode>, <reject_mode>
 * where,
 * <op_mode>
 * 0 - BT SAP Server modes
 * 1 - BT SAP Client mode (Client mode is currently not supported)
 * <change_mode>
 * 0 - gracefully, or Time out
 * 1 - immediately
 * <reject_mode>
 * 0 - Reject is not allowed.
 * 1 - Reject is allowed.
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_sap_req_connect(CoreObject *co, unsigned int max_msg_size,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				&max_msg_size, sizeof(unsigned int));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XBCON=0,0,0", NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_sap_req_connect, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_sap_req_connect");

	return ret;
}

/*
 * Operation - disconnects BT SAP.
 *
 * Request -
 * AT-Command: AT+ XBDISC
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_sap_req_disconnect(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XBDISC", NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_sap_req_disconnect, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_sap_req_disconnect");

	return ret;
}

/*
 * Operation - In BT SAP server mode, request the ATR from the stack to the Application.
 *
 * Request -
 * AT-Command: AT+ XBATR
 *
 * Response -
 * Success: +XBATR: <status>, <data_ATR>
 * OK
 * where
 * <status>
 * 0 OK, request processed correctly
 * 1 No Reason defined
 * 2 Card not accessible
 * 3 Card (already) powered off
 * 4 Card Removed
 * 6 Data Not available
 * 7 Not Supported
 * <data_ATR>
 * Hex Data (an array of bytes)
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_sap_get_atr(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XBATR", "+XBATR:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sap_get_atr, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_sap_get_atr");

	return ret;
}

/*
 * Operation - BT SAP server mode, Forward command APDU from application to SIM.
 *
 * Request -
 * AT-Command: AT+ XBAPDU = <data: command_APDU >
 * where
 * <data: command_APDU >
 * Hex Data (an array of bytes). CP supports Command_APDU up to 261 bytes long.
 *
 * Response -
 * Success: +XBAPDU: <status>, [<data:Response_APDU>]
 * OK
 * where
 * <status>
 * 0 OK, request processed correctly
 * 1 No Reason defined
 * 2 Card not accessible
 * 3 Card (already) powered off
 * 4 Card Removed
 * 5 Data not available
 * 6 Not Supported
 * <data:Response_APDU>
 * Hex Data (an array of bytes). CP supports Response_APDU up to 258 bytes long
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_sap_req_transfer_apdu(CoreObject *co, const TelSapApdu *apdu_data,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	gchar *at_cmd;

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+XBAPDU=\"%s\"", apdu_data->apdu);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+XBAPDU:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sap_req_transfer_apdu, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_sap_req_transfer_apdu");

	g_free(at_cmd);
	return ret;
}

static TelReturn imc_sap_req_transport_protocol(CoreObject *co, TelSimSapProtocol protocol,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	err("Operation not supported");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

/*
 * Operation - In BT SAP server mode, Power ON,OFF and Reset the SIM.
 *
 * Request -
 * AT-Command: AT+ XBPWR =<action>
 * where
 * <Action>:
 * 0 SIM Power ON
 * 1 SIM Power OFF
 * 2 SIM RESET
 *
 * Response -
 * Success: + XBPWR: <status>
 * OK
 * where
 * <status>
 * 0 OK, Request processed correctly
 * 1 Error no reason defined
 * 2 Card not Accessible
 * 3 Card already powered OFF
 * 4 Card removed
 * 5 Card already powered ON
 * 6 Data Not vailable
 * 7 Not Supported
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_sap_req_power_operation(CoreObject *co, TelSapPowerMode power_mode,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_FAILURE;
	gchar *at_cmd;
	int action;

	if(power_mode == TEL_SAP_SIM_POWER_ON_REQ) {
		action = 0;
	} else if(power_mode == TEL_SAP_SIM_POWER_OFF_REQ) {
		action  = 1;
	} else if (power_mode == TEL_SAP_SIM_RESET_REQ) {
		action = 2;
	} else {
		err("invalid power mode");
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+XBPWR=%d", action);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+XBPWR:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sap_req_power_operation, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_sap_req_power_operation");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation - In BT SAP server mode, get the Card reader Status.
 *
 * Request -
 * AT-Command: AT+XBCRDSTAT
 *
 * Response -
 * Success: +XBCRDSTAT: <status>, <card_reader_status>
 * OK
 * where
 * <status>
 * 0 OK, Request processed correctly
 * 1 Error no reason defined
 * 2 Card not Accessible
 * 3 Card already powered OFF
 * 4 Card removed
 * 5 Card already powered ON
 * 6 Data Not vailable
 * 7 Not Supported
 * <card_reader_status>
 * One byte. It represents card reader identity and status.
 * The value of this byte indicates the identity and status of a card reader.
 * Bits 1-3 = identity of card reader x.
 * bit 4, 0 = Card reader is not removable, 1 = Card reader is removable
 * bit 5, 0 = Card reader is not present, 1 = Card reader is present
 * bit 6, 0 = Card reader present is not ID-1 size, 1 = Card reader present is ID-1 size
 * bit 7, 0 = No card present, 1 = Card is present in reader
 * bit 8, 0 = No card powered, 1 = Card in reader is powered
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_sap_get_cardreader_status(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XBCRDSTAT", "+XBCRDSTAT:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sap_get_cardreader_status, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_sap_get_cardreader_status");

	return ret;
}

/* SAP Operations */
static TcoreSapOps imc_sap_ops = {
	.req_connect = imc_sap_req_connect,
	.req_disconnect = imc_sap_req_disconnect,
	.get_atr = imc_sap_get_atr,
	.req_transfer_apdu = imc_sap_req_transfer_apdu,
	.req_transport_protocol = imc_sap_req_transport_protocol,
	.req_power_operation = imc_sap_req_power_operation,
	.get_cardreader_status = imc_sap_get_cardreader_status
};

gboolean imc_sap_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Entry");

	/* Set operations */
	tcore_sap_set_ops(co, &imc_sap_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co, "+XBCSTAT", on_notification_imc_sap_status, NULL);

	dbg("Exit");
	return TRUE;
}

void imc_sap_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
