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

#include <co_sat.h>

#include "imc_sat.h"
#include "imc_common.h"

#define PROACTV_CMD_LEN	256

static void on_response_enable_sat(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;

	if (at_resp && at_resp->success) {
		dbg("Enable SAT (Proactive command) - [OK]");
	}
	else {
		err("Enable SAT (Proactive command) - [NOK]");
	}
}

/* Hook functions */
static TcoreHookReturn on_hook_imc_sim_status(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	const TelSimCardStatus *sim_status = (TelSimCardStatus *)data;
	CoreObject *co = (CoreObject *)user_data;

	tcore_check_return_value(sim_status != NULL, TCORE_HOOK_RETURN_CONTINUE);

	/*
	 * If SIM is initialized -
	 *	* Enable SAT
	 */
	dbg("SIM Status: [%d]", *sim_status);
	if (*sim_status == TEL_SIM_STATUS_SIM_INIT_COMPLETED) {
		dbg("SIM Initialized!!! Enable SAT");

		/* Enable SAT - Send AT+CFUN=6 */
		tcore_at_prepare_and_send_request(co,
			"AT+CFUN=6", NULL,
			TCORE_AT_COMMAND_TYPE_NO_RESULT,
			TCORE_PENDING_PRIORITY_DEFAULT,
			NULL,
			on_response_enable_sat, NULL,
			on_send_imc_request, NULL,
			0, NULL, NULL);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

static gboolean on_response_imc_sat_terminal_response_confirm
	(CoreObject *co, const void *event_info, void *user_data)
{
	dbg("Entry");
	return TRUE;
}

static gboolean on_notification_imc_sat_proactive_command
	(CoreObject *co, const void *event_info, void *user_data)
{
	TelSatDecodedProactiveData decoded_data;
	TelSatNotiProactiveData proactive_noti;
	gint proactive_cmd_len = 0;
	GSList *lines = NULL;
	GSList *tokens = NULL;
	gchar *line = NULL;
	gchar *hex_data = NULL;
	gchar *tmp = NULL;
	gchar *record_data = NULL;
	guint record_data_len;
	gint decode_err;
	gboolean decode_ret = FALSE;

	dbg("Entry");

	tcore_check_return_value_assert(co != NULL, FALSE);
	memset(&proactive_noti, 0x00, sizeof(TelSatNotiProactiveData));
	memset(&decoded_data, 0x00, sizeof(TelSatDecodedProactiveData));

	lines = (GSList *) event_info;
	line = (gchar *) lines->data;
	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) != 1) {
		err("Invalid message");
		tcore_at_tok_free(tokens);
		return TRUE;
	}

	hex_data = (gchar *)g_slist_nth_data(tokens, 0);
	dbg("SAT data: [%s] SAT data length: [%d]", hex_data, strlen(hex_data));

	tmp = (gchar *)tcore_at_tok_extract((gchar *)hex_data);
	tcore_util_hexstring_to_bytes(tmp, &record_data, &record_data_len);
	dbg("record_data: %x", record_data);
	tcore_free(tmp);

	tcore_util_hex_dump("    ", strlen(hex_data) / 2, record_data);
	proactive_cmd_len = strlen(record_data);
	dbg("proactive_cmd_len = %d", proactive_cmd_len);

	decode_ret = tcore_sat_decode_proactive_command((guchar *) record_data,
		record_data_len, &decoded_data, &decode_err);
	if (!decode_ret) {
		err("Proactive Command decoding failed");
		tcore_at_tok_free(tokens);
		return TRUE;
	}

	tcore_free(record_data);

	proactive_noti.cmd_number = decoded_data.cmd_num;
	proactive_noti.cmd_type = decoded_data.cmd_type;
	proactive_noti.decode_err_code = decode_err;

	switch (decoded_data.cmd_type) {
	case TEL_SAT_PROATV_CMD_DISPLAY_TEXT:
		dbg("decoded command is display text!!");
		memcpy(&proactive_noti.proactive_ind_data.display_text,
			&decoded_data.data.display_text,
			sizeof(TelSatDisplayTextTlv));
		break;

	case TEL_SAT_PROATV_CMD_GET_INKEY:
		dbg("decoded command is get inkey!!");
		memcpy(&proactive_noti.proactive_ind_data.get_inkey,
			&decoded_data.data.get_inkey,
			sizeof(TelSatGetInkeyTlv));
		break;

	case TEL_SAT_PROATV_CMD_GET_INPUT:
		dbg("decoded command is get input!!");
		memcpy(&proactive_noti.proactive_ind_data.get_input,
			&decoded_data.data.get_input,
			sizeof(TelSatGetInputTlv));
		break;

	case TEL_SAT_PROATV_CMD_MORE_TIME:
		dbg("decoded command is more time!!");
		memcpy(&proactive_noti.proactive_ind_data.more_time,
			&decoded_data.data.more_time,
			sizeof(TelSatMoreTimeTlv));
		break;

	case TEL_SAT_PROATV_CMD_PLAY_TONE:
		dbg("decoded command is play tone!!");
		memcpy(&proactive_noti.proactive_ind_data.play_tone,
			&decoded_data.data.play_tone,
			sizeof(TelSatPlayToneTlv));
		break;

	case TEL_SAT_PROATV_CMD_SETUP_MENU:
		dbg("decoded command is SETUP MENU!!");
		memcpy(&proactive_noti.proactive_ind_data.setup_menu,
			&decoded_data.data.setup_menu, sizeof(TelSatSetupMenuTlv));
		break;

	case TEL_SAT_PROATV_CMD_SELECT_ITEM:
		dbg("decoded command is select item!!");
		memcpy(&proactive_noti.proactive_ind_data.select_item,
			&decoded_data.data.select_item,
			sizeof(TelSatSelectItemTlv));
		break;

	case TEL_SAT_PROATV_CMD_SEND_SMS:
		dbg("decoded command is send sms!!");
		memcpy(&proactive_noti.proactive_ind_data.send_sms,
			&decoded_data.data.send_sms,
			sizeof(TelSatSendSmsTlv));
		break;

	case TEL_SAT_PROATV_CMD_SEND_SS:
		dbg("decoded command is send ss!!");
		memcpy(&proactive_noti.proactive_ind_data.send_ss,
			&decoded_data.data.send_ss,
			sizeof(TelSatSendSsTlv));
		break;

	case TEL_SAT_PROATV_CMD_SEND_USSD:
		dbg("decoded command is send ussd!!");
		memcpy(&proactive_noti.proactive_ind_data.send_ussd,
			&decoded_data.data.send_ussd,
			sizeof(TelSatSendUssdTlv));
		break;

	case TEL_SAT_PROATV_CMD_SETUP_CALL:
		dbg("decoded command is setup call!!");
		memcpy(&proactive_noti.proactive_ind_data.setup_call,
			&decoded_data.data.setup_call,
			sizeof(TelSatSetupCallTlv));
		break;

	case TEL_SAT_PROATV_CMD_REFRESH:
		dbg("decoded command is refresh");
		memcpy(&proactive_noti.proactive_ind_data.refresh,
			&decoded_data.data.refresh, sizeof(TelSatRefreshTlv));
		break;

	case TEL_SAT_PROATV_CMD_PROVIDE_LOCAL_INFO:
		dbg("decoded command is provide local info");
		memcpy(&proactive_noti.proactive_ind_data.provide_local_info,
			&decoded_data.data.provide_local_info,
			sizeof(TelSatProvideLocalInfoTlv));
		break;

	case TEL_SAT_PROATV_CMD_SETUP_EVENT_LIST:
		dbg("decoded command is setup event list!!");
		memcpy(&proactive_noti.proactive_ind_data.setup_event_list,
			&decoded_data.data.setup_event_list,
			sizeof(TelSatSetupEventListTlv));
		// setup_event_rsp_get(o, &decoded_data.data.setup_event_list);
		break;

	case TEL_SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT:
		dbg("decoded command is setup idle mode text");
		memcpy(&proactive_noti.proactive_ind_data.setup_idle_mode_text,
			&decoded_data.data.setup_idle_mode_text,
			sizeof(TelSatSetupIdleModeTextTlv));
		break;

	case TEL_SAT_PROATV_CMD_SEND_DTMF:
		dbg("decoded command is send dtmf");
		memcpy(&proactive_noti.proactive_ind_data.send_dtmf,
			&decoded_data.data.send_dtmf,
			sizeof(TelSatSendDtmfTlv));
		break;

	case TEL_SAT_PROATV_CMD_LANGUAGE_NOTIFICATION:
		dbg("decoded command is language notification");
		memcpy(&proactive_noti.proactive_ind_data.language_notification,
			&decoded_data.data.language_notification,
			sizeof(TelSatLanguageNotificationTlv));
		break;

	case TEL_SAT_PROATV_CMD_LAUNCH_BROWSER:
		dbg("decoded command is launch browser");
		memcpy(&proactive_noti.proactive_ind_data.launch_browser,
			&decoded_data.data.launch_browser,
			sizeof(TelSatLaunchBrowserTlv));
		break;

	case TEL_SAT_PROATV_CMD_OPEN_CHANNEL:
		dbg("decoded command is open channel!!");
		memcpy(&proactive_noti.proactive_ind_data.open_channel,
			&decoded_data.data.open_channel,
			sizeof(TelSatOpenChannelTlv));
		break;

	case TEL_SAT_PROATV_CMD_CLOSE_CHANNEL:
		dbg("decoded command is close channel!!");
		memcpy(&proactive_noti.proactive_ind_data.close_channel,
			&decoded_data.data.close_channel,
			sizeof(TelSatCloseChannelTlv));
		break;

	case TEL_SAT_PROATV_CMD_RECEIVE_DATA:
		dbg("decoded command is receive data!!");
		memcpy(&proactive_noti.proactive_ind_data.receive_data,
			&decoded_data.data.receive_data,
			sizeof(TelSatReceiveChannelTlv));
		break;

	case TEL_SAT_PROATV_CMD_SEND_DATA:
		dbg("decoded command is send data!!");
		memcpy(&proactive_noti.proactive_ind_data.send_data,
			&decoded_data.data.send_data,
			sizeof(TelSatSendChannelTlv));
		break;

	case TEL_SAT_PROATV_CMD_GET_CHANNEL_STATUS:
		dbg("decoded command is get channel status!!");
		memcpy(&proactive_noti.proactive_ind_data.get_channel_status,
			&decoded_data.data.get_channel_status,
			sizeof(TelSatGetChannelStatusTlv));
		break;

	default:
		dbg("invalid command:[%d]", decoded_data.cmd_type);
		break;
	}

	if (decoded_data.cmd_type == TEL_SAT_PROATV_CMD_REFRESH) {
		/*Not supported*/
		dbg("Not suported Proactive command");
		tcore_at_tok_free(tokens);
		return TRUE;
	}

	/* Send notification */
	tcore_object_send_notification(co,
		TCORE_NOTIFICATION_SAT_PROACTIVE_CMD,
		sizeof(TelSatNotiProactiveData), &proactive_noti);

	tcore_at_tok_free(tokens);

	dbg("Exit");
	return TRUE;
}

/* SAT Responses */
static void on_response_imc_sat_send_envelop_cmd(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSatEnvelopeResp envelop_resp;
	TelSatResult result = TEL_SAT_RESULT_FAILURE;
	GSList *tokens = NULL;
	const gchar *line = NULL;
	const gchar *env_res = NULL;
	gint sw2 = -1;

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);
	tcore_check_return_assert(resp_cb_data->cb != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_SAT_RESULT_SUCCESS;
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			line = (const gchar *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				err("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		env_res = g_slist_nth_data(tokens, 0);
		envelop_resp = TEL_SAT_ENVELOPE_SUCCESS;
		dbg("RESPONSE tokens present");
		if (NULL != g_slist_nth_data(tokens, 1)) {
			sw2 = atoi(g_slist_nth_data(tokens, 1));
			dbg("status word SW2:[%d]", sw2);
			if (sw2 == 0) {
				dbg("Response is processed completely and sending session end notification");
				/* Send Session End notification */
				tcore_object_send_notification(co,
				TCORE_NOTIFICATION_SAT_SESSION_END, 0, NULL);
			}
		}
	} else {
		dbg("RESPONSE NOK");
		envelop_resp = TEL_SAT_ENVELOPE_FAILED;
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &envelop_resp, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
	tcore_at_tok_free(tokens);
	dbg("Exit");
}

static void on_response_imc_sat_send_terminal_response(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSatResult result = TEL_SAT_RESULT_FAILURE;

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);
	tcore_check_return_assert(resp_cb_data->cb != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_SAT_RESULT_SUCCESS;
		dbg("RESPONSE OK");
		dbg(" at_resp->success = %d", at_resp->success);
		/* Send Session End notification */
		tcore_object_send_notification(co, TCORE_NOTIFICATION_SAT_SESSION_END, 0, NULL);
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
	dbg("Exit");
}

static void on_response_imc_sat_send_user_confirmation(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSatResult result = TEL_SAT_RESULT_FAILURE;

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);
	tcore_check_return_assert(resp_cb_data->cb != NULL);

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		result = TEL_SAT_RESULT_SUCCESS;
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
	dbg("Exit");
}

/* SAT Requests */
/*
 * Operation - Send Envelop Command
 *
 * Request -
 * AT-Command: AT+SATE
 *
 * Response - SW
 * Success: (Single line)
 * <sw1>,<sw2>
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_sat_send_envelope(CoreObject *co,
	const TelSatRequestEnvelopCmdData *envelop_data,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	gint envelope_cmd_len = 0;
	gchar envelope_cmd[PROACTV_CMD_LEN];
	gint count = 0;
	gchar hex_string[PROACTV_CMD_LEN * 2];
	gchar *buffer = NULL;
	gboolean encode_ret = FALSE;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	dbg("Entry");
	memset(&hex_string, 0x00, sizeof(hex_string));
	buffer = hex_string;

	encode_ret = tcore_sat_encode_envelop_cmd(envelop_data,
		(gchar *)envelope_cmd, (gint *)&envelope_cmd_len);
	if (!encode_ret) {
		err("Envelope Command encoding failed");
		return TEL_RETURN_FAILURE;
	}

	dbg("envelope_cmd_len after encoding :[%d]", envelope_cmd_len);
	if (envelope_cmd_len == 0) {
		err("Envelope command length after encoding is NULL");
		return TEL_RETURN_INVALID_PARAMETER;
	}

	for (count = 0; count < envelope_cmd_len; count++) {
		dbg("envelope_cmd: %02x", (guchar)envelope_cmd[count]);
		sprintf(buffer, "%02x", (guchar)envelope_cmd[count]);
		buffer += 2;
	}
	dbg("hex_string: %s", hex_string);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+SATE=\"%s\"", hex_string);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		(void *)&envelop_data->sub_cmd, sizeof(TelSatEnvelopSubCmd));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_sat_send_envelop_cmd, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Send Envelop Command");

	/* Free resources */
	tcore_free(at_cmd);
	dbg("Exit");
	return ret;
}

/*
 * Operation - Send Terminal Response
 *
 * Request -
 * AT-Command: AT+SATR
 *
 * Response - OK
 * Success: (NO Result)
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_sat_send_terminal_response(CoreObject *co,
	const TelSatRequestTerminalResponseData *terminal_rsp_data,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	gint terminal_resp_len = 0;
	gchar terminal_resp[PROACTV_CMD_LEN];
	gint i = 0;
	gchar *hex_string = NULL;
	gboolean encode_ret = FALSE;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	dbg("Entry");

	encode_ret = tcore_sat_encode_terminal_response(terminal_rsp_data,
		(gchar *)terminal_resp, (gint *)&terminal_resp_len);
	if (!encode_ret) {
		err("Envelope Command encoding failed");
		return TEL_RETURN_FAILURE;
	}

	dbg("terminal_resp after encoding: %s", terminal_resp);
	dbg("terminal_resp length after encoding:[%d]", strlen(terminal_resp));
	if (terminal_resp_len == 0) {
		err("Terminal Response length after encoding is NULL");
		return TEL_RETURN_INVALID_PARAMETER;
	}
	hex_string = calloc((terminal_resp_len * 2) + 1, 1);

	for (i = 0; i < terminal_resp_len * 2; i += 2) {
		gchar value = 0;
		value = (terminal_resp[i / 2] & 0xf0) >> 4;
		if (value < 0xA)
			hex_string[i] = ((terminal_resp[i / 2] & 0xf0) >> 4) + '0';
		else
			hex_string[i] = ((terminal_resp[i / 2] & 0xf0) >> 4) + 'A' - 10;

		value = terminal_resp[i / 2] & 0x0f;
		if (value < 0xA)
			hex_string[i + 1] = (terminal_resp[i / 2] & 0x0f) + '0';
		else
			hex_string[i + 1] = (terminal_resp[i / 2] & 0x0f) + 'A' - 10;
	}
	dbg("hex_string: %s", hex_string);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+SATR=\"%s\"", hex_string);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_sat_send_terminal_response, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Send Terminal Response");

	/* Free resources */
	tcore_free(at_cmd);
	dbg("Exit");
	return ret;
}

/*
 * Operation - Send User Confirmation
 *
 * Request -
 * AT-Command: AT+SATD
 *
 * Response - OK
 * Success: (NO Result)
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_sat_send_user_confirmation(CoreObject *co,
	const TelSatRequestUserConfirmationData *user_conf_data,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	guint usr_conf;
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	dbg("Entry");

	usr_conf = (guint)user_conf_data->user_conf;
	dbg("User confirmation:[%d]", usr_conf);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+SATD=%d", usr_conf);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_sat_send_user_confirmation, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Send User Confirmation");

	/* Free resources */
	tcore_free(at_cmd);
	dbg("Exit");
	return ret;

}

/* SAT Operations */
static TcoreSatOps imc_sat_ops = {
	.send_envelope = imc_sat_send_envelope,
	.send_terminal_response = imc_sat_send_terminal_response,
	.send_user_confirmation = imc_sat_send_user_confirmation
};

/* SAT Init */
gboolean imc_sat_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Entry");

	/* Set operations */
	tcore_sat_set_ops(co, &imc_sat_ops);

	/* Add Callbacks */
	/*
	 * At present keeping the same notification processing for
	 * both SATI and SATN command. But in future notification processing
	 * will be seperated for both command depending on SAT re-architecure.
	 */
	tcore_object_add_callback(co, "+SATI",
		on_notification_imc_sat_proactive_command, NULL);
	tcore_object_add_callback(co, "+SATN",
		on_notification_imc_sat_proactive_command, NULL);
	tcore_object_add_callback(co, "+SATF",
		on_response_imc_sat_terminal_response_confirm, NULL);

	/* Hooks */
	tcore_plugin_add_notification_hook(p,
		TCORE_NOTIFICATION_SIM_STATUS, on_hook_imc_sim_status, co);

	dbg("Exit");
	return TRUE;
}

/* SAT Exit */
void imc_sat_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
