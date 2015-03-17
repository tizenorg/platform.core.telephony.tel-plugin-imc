/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Chandan Swarup Patra <chandan.sp@samsung.com>
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
#include <server.h>
#include <co_sat.h>
#include <user_request.h>
#include <at.h>

#include "imc_common.h"
#include "imc_sat.h"
#define ENVELOPE_CMD_LEN        256

static TReturn imc_terminal_response(CoreObject *o, UserRequest *ur);
static void on_confirmation_sat_message_send(TcorePending *p, gboolean result, void *user_data);      // from Kernel

static void on_confirmation_sat_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("on_confirmation_modem_message_send - msg out from queue.\n");

	if (result == FALSE) {
		/* Fail */
		dbg("SEND FAIL");
	} else {
		dbg("SEND OK");
	}
}

static gboolean on_response_terminal_response_confirm(CoreObject *o, const void *event_info, void *user_data)
{
	dbg("Function Entry");
	return TRUE;
	dbg("Function Exit");
}

static gboolean on_event_sat_proactive_command(CoreObject *o, const void *event_info, void *user_data)
{
	struct tcore_sat_proactive_command decoded_data;
	struct tnoti_sat_proactive_ind proactive_noti;
	int len_proactive_cmd = 0;
	GSList *lines = NULL;
	GSList *tokens = NULL;
	char *line = NULL;
	char *hexData = NULL;
	char *tmp = NULL;
	char *recordData = NULL;

	dbg("Function Entry");

	memset(&proactive_noti, 0x00, sizeof(struct tnoti_sat_proactive_ind));
	memset(&decoded_data, 0x00, sizeof(struct tcore_sat_proactive_command));
	lines = (GSList *) event_info;
	line = (char *) lines->data;
	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) != 1) {
		err("Invalid message");
		tcore_at_tok_free(tokens);
		return FALSE;
	}

	hexData = (char *)g_slist_nth_data(tokens, 0);
	dbg("SAT data: [%s] SAT data length: [%d]", hexData, strlen(hexData));

	tmp = util_removeQuotes(hexData);
	recordData = util_hexStringToBytes(tmp);
	dbg("recordData: %x", recordData);
	g_free(tmp);
	util_hex_dump("    ", strlen(hexData) / 2, recordData);
	len_proactive_cmd = strlen(recordData);
	dbg("len_proactive_cmd = %d", len_proactive_cmd);
	tcore_sat_decode_proactive_command((unsigned char *) recordData, (strlen(hexData) / 2) - 1, &decoded_data);
	g_free(recordData);

	proactive_noti.cmd_number = decoded_data.cmd_num;
	proactive_noti.cmd_type = decoded_data.cmd_type;

	switch (decoded_data.cmd_type) {
	case SAT_PROATV_CMD_DISPLAY_TEXT:
		dbg("decoded command is display text!!");
		memcpy(&proactive_noti.proactive_ind_data.display_text, &decoded_data.data.display_text, sizeof(struct tel_sat_display_text_tlv));
		break;

	case SAT_PROATV_CMD_GET_INKEY:
		dbg("decoded command is get inkey!!");
		memcpy(&proactive_noti.proactive_ind_data.get_inkey, &decoded_data.data.get_inkey, sizeof(struct tel_sat_get_inkey_tlv));
		break;

	case SAT_PROATV_CMD_GET_INPUT:
		dbg("decoded command is get input!!");
		memcpy(&proactive_noti.proactive_ind_data.get_input, &decoded_data.data.get_input, sizeof(struct tel_sat_get_input_tlv));
		break;

	case SAT_PROATV_CMD_MORE_TIME:
		dbg("decoded command is more time!!");
		memcpy(&proactive_noti.proactive_ind_data.more_time, &decoded_data.data.more_time, sizeof(struct tel_sat_more_time_tlv));
		break;

	case SAT_PROATV_CMD_PLAY_TONE:
		dbg("decoded command is play tone!!");
		memcpy(&proactive_noti.proactive_ind_data.play_tone, &decoded_data.data.play_tone, sizeof(struct tel_sat_play_tone_tlv));
		break;

	case SAT_PROATV_CMD_SETUP_MENU:
		dbg("decoded command is SETUP MENU!!");
		memcpy(&proactive_noti.proactive_ind_data.setup_menu, &decoded_data.data.setup_menu, sizeof(struct tel_sat_setup_menu_tlv));
		break;

	case SAT_PROATV_CMD_SELECT_ITEM:
		dbg("decoded command is select item!!");
		memcpy(&proactive_noti.proactive_ind_data.select_item, &decoded_data.data.select_item, sizeof(struct tel_sat_select_item_tlv));
		break;

	case SAT_PROATV_CMD_SEND_SMS:
		dbg("decoded command is send sms!!");
		memcpy(&proactive_noti.proactive_ind_data.send_sms, &decoded_data.data.send_sms, sizeof(struct tel_sat_send_sms_tlv));
		break;

	case SAT_PROATV_CMD_SEND_SS:
		dbg("decoded command is send ss!!");
		memcpy(&proactive_noti.proactive_ind_data.send_ss, &decoded_data.data.send_ss, sizeof(struct tel_sat_send_ss_tlv));
		break;

	case SAT_PROATV_CMD_SEND_USSD:
		dbg("decoded command is send ussd!!");
		memcpy(&proactive_noti.proactive_ind_data.send_ussd, &decoded_data.data.send_ussd, sizeof(struct tel_sat_send_ussd_tlv));
		break;

	case SAT_PROATV_CMD_SETUP_CALL:
		dbg("decoded command is setup call!!");
		memcpy(&proactive_noti.proactive_ind_data.setup_call, &decoded_data.data.setup_call, sizeof(struct tel_sat_setup_call_tlv));
		break;

	case SAT_PROATV_CMD_REFRESH:
		dbg("decoded command is refresh");
		memcpy(&proactive_noti.proactive_ind_data.refresh, &decoded_data.data.refresh, sizeof(struct tel_sat_refresh_tlv));
		break;

	case SAT_PROATV_CMD_PROVIDE_LOCAL_INFO:
		dbg("decoded command is provide local info");
		memcpy(&proactive_noti.proactive_ind_data.provide_local_info, &decoded_data.data.provide_local_info, sizeof(struct tel_sat_provide_local_info_tlv));
		break;

	case SAT_PROATV_CMD_SETUP_EVENT_LIST:
		dbg("decoded command is setup event list!!");
		memcpy(&proactive_noti.proactive_ind_data.setup_event_list, &decoded_data.data.setup_event_list, sizeof(struct tel_sat_setup_event_list_tlv));
		// setup_event_rsp_get(o, &decoded_data.data.setup_event_list);
		break;

	case SAT_PROATV_CMD_SETUP_IDLE_MODE_TEXT:
		dbg("decoded command is setup idle mode text");
		memcpy(&proactive_noti.proactive_ind_data.setup_idle_mode_text, &decoded_data.data.setup_idle_mode_text, sizeof(struct tel_sat_setup_idle_mode_text_tlv));
		break;

	case SAT_PROATV_CMD_SEND_DTMF:
		dbg("decoded command is send dtmf");
		memcpy(&proactive_noti.proactive_ind_data.send_dtmf, &decoded_data.data.send_dtmf, sizeof(struct tel_sat_send_dtmf_tlv));
		break;

	case SAT_PROATV_CMD_LANGUAGE_NOTIFICATION:
		dbg("decoded command is language notification");
		memcpy(&proactive_noti.proactive_ind_data.language_notification, &decoded_data.data.language_notification, sizeof(struct tel_sat_language_notification_tlv));
		break;

	case SAT_PROATV_CMD_LAUNCH_BROWSER:
		dbg("decoded command is launch browser");
		memcpy(&proactive_noti.proactive_ind_data.launch_browser, &decoded_data.data.launch_browser, sizeof(struct tel_sat_launch_browser_tlv));
		break;

	case SAT_PROATV_CMD_OPEN_CHANNEL:
		dbg("decoded command is open channel!!");
		memcpy(&proactive_noti.proactive_ind_data.open_channel, &decoded_data.data.open_channel, sizeof(struct tel_sat_open_channel_tlv));
		break;

	case SAT_PROATV_CMD_CLOSE_CHANNEL:
		dbg("decoded command is close channel!!");
		memcpy(&proactive_noti.proactive_ind_data.close_channel, &decoded_data.data.close_channel, sizeof(struct tel_sat_close_channel_tlv));
		break;

	case SAT_PROATV_CMD_RECEIVE_DATA:
		dbg("decoded command is receive data!!");
		memcpy(&proactive_noti.proactive_ind_data.receive_data, &decoded_data.data.receive_data, sizeof(struct tel_sat_receive_channel_tlv));
		break;

	case SAT_PROATV_CMD_SEND_DATA:
		dbg("decoded command is send data!!");
		memcpy(&proactive_noti.proactive_ind_data.send_data, &decoded_data.data.send_data, sizeof(struct tel_sat_send_channel_tlv));
		break;

	case SAT_PROATV_CMD_GET_CHANNEL_STATUS:
		dbg("decoded command is get channel status!!");
		memcpy(&proactive_noti.proactive_ind_data.get_channel_status, &decoded_data.data.get_channel_status, sizeof(struct tel_sat_get_channel_status_tlv));
		break;

	default:
		dbg("wrong input");
		break;
	}
	if (decoded_data.cmd_type == SAT_PROATV_CMD_REFRESH) {
		/*Not supported*/
		dbg("Not suported Proactive command");
		return FALSE;
	}
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SAT_PROACTIVE_CMD,
								   sizeof(struct tnoti_sat_proactive_ind), &proactive_noti);
	tcore_at_tok_free(tokens);
	dbg("Function Exit");
	return TRUE;
}

static void on_response_envelop_cmd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *o = NULL;
	const struct                treq_sat_envelop_cmd_data *req_data = NULL;
	GSList *tokens = NULL;
	struct                      tresp_sat_envelop_data res;
	const char *line = NULL;
	//const char *env_res = NULL;
	int sw2 = -1;

	ur = tcore_pending_ref_user_request(p);
	req_data = tcore_user_request_ref_data(ur, NULL);
	o = tcore_pending_ref_core_object(p);

	if (!req_data) {
		dbg("request data is NULL");
		return;
	}
	memset(&res, 0, sizeof(struct tresp_sat_envelop_data));

	res.sub_cmd = req_data->sub_cmd;

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		//env_res = g_slist_nth_data(tokens, 0);
		res.result = 0x8000;
		res.envelop_resp = ENVELOPE_SUCCESS;
		dbg("RESPONSE OK 3");
		if (NULL != g_slist_nth_data(tokens, 1)) {
			sw2 = atoi(g_slist_nth_data(tokens, 1));
			dbg("RESPONSE OK 4");
			if (sw2 == 0) {
				dbg("RESPONSE OK 5");
				tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SAT_SESSION_END, 0, NULL);
			}
		}
	} else {
		dbg("RESPONSE NOK");
		res.result = -1;
		res.envelop_resp = ENVELOPE_FAILED;
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SAT_REQ_ENVELOPE, sizeof(struct tresp_sat_envelop_data), &res);
	}
	tcore_at_tok_free(tokens);
	dbg(" Function exit");
}


static void on_response_terminal_response(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	CoreObject *o = NULL;
	const TcoreATResponse *resp = data;
	gpointer tmp = NULL;

	dbg("Function Entry");

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		dbg(" resp->success = %d", resp->success);
		ur = tcore_pending_ref_user_request(p);
		tmp = (gpointer) tcore_user_request_ref_communicator(ur);
		if (!ur || !tmp) {
			dbg("error - current ur is NULL");
			return;
		}

		o = tcore_pending_ref_core_object(p);
		if (!o)
			dbg("error - current sat core is NULL");
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SAT_SESSION_END, 0, NULL);
	}
	dbg("Function Exit");
}

static TReturn imc_envelope(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct            treq_sat_envelop_cmd_data *req_data = NULL;
	int envelope_cmd_len = 0;
	char envelope_cmd[ENVELOPE_CMD_LEN];
	int count = 0;
	char envelope_cmdhex[ENVELOPE_CMD_LEN * 2];
	char *pbuffer = NULL;

	dbg("Function Entry");
	memset(&envelope_cmdhex, 0x00, sizeof(envelope_cmdhex));
	pbuffer = envelope_cmdhex;

	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);
	dbg("new pending sub cmd(%d)", req_data->sub_cmd);

	envelope_cmd_len = tcore_sat_encode_envelop_cmd(req_data, (char *) envelope_cmd);

	dbg("envelope_cmd_len %d", envelope_cmd_len);
	if (envelope_cmd_len == 0) {
		return TCORE_RETURN_EINVAL;
	}
	for (count = 0; count < envelope_cmd_len; count++) {
		dbg("envelope_cmd %02x", (unsigned char)envelope_cmd[count]);
		sprintf(pbuffer, "%02x", (unsigned char)envelope_cmd[count]);
		pbuffer += 2;
	}
	dbg("pbuffer %s", envelope_cmdhex);
	cmd_str = g_strdup_printf("AT+SATE=\"%s\"", envelope_cmdhex);
	req = tcore_at_request_new(cmd_str, "+SATE:", TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_envelop_cmd, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sat_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	dbg("Function Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_terminal_response(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct            treq_sat_terminal_rsp_data *req_data = NULL;
	int proactive_resp_len = 0;
	char proactive_resp[ENVELOPE_CMD_LEN];
	char proactive_resphex[ENVELOPE_CMD_LEN * 2];
	int i = 0;
	char *hexString = NULL;

	dbg("Function Entry");
	memset(&proactive_resphex, 0x00, sizeof(proactive_resphex));
	hal = tcore_object_get_hal(o);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	proactive_resp_len = tcore_sat_encode_terminal_response(req_data, (char *) proactive_resp);
	dbg("proactive_resp %s", proactive_resp);
	dbg("proactive_resp length %d", strlen(proactive_resp));
	if (proactive_resp_len == 0) {
		tcore_pending_free(pending);
		return TCORE_RETURN_EINVAL;
	}
	hexString = calloc((proactive_resp_len * 2) + 1, 1);

	for (i = 0; i < proactive_resp_len * 2; i += 2) {
		char value = 0;
		value = (proactive_resp[i / 2] & 0xf0) >> 4;
		if (value < 0xA)
			hexString[i] = ((proactive_resp[i / 2] & 0xf0) >> 4) + '0';
		else
			hexString[i] = ((proactive_resp[i / 2] & 0xf0) >> 4) + 'A' - 10;

		value = proactive_resp[i / 2] & 0x0f;
		if (value < 0xA)
			hexString[i + 1] = (proactive_resp[i / 2] & 0x0f) + '0';
		else
			hexString[i + 1] = (proactive_resp[i / 2] & 0x0f) + 'A' - 10;
	}

	dbg("hexString %s", hexString);
	cmd_str = g_strdup_printf("AT+SATR=\"%s\"", hexString);

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_terminal_response, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sat_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	g_free(hexString);
	dbg("Function Exit");
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_sat_operations sat_ops = {
	.envelope = imc_envelope,
	.terminal_response = imc_terminal_response,
};

gboolean imc_sat_init(TcorePlugin *cp, CoreObject *co_sat)
{
	dbg("Entry");

	/* Set operations */
	tcore_sat_set_ops(co_sat, &sat_ops);

	tcore_object_add_callback(co_sat, "+SATI", on_event_sat_proactive_command, NULL);
	tcore_object_add_callback(co_sat, "+SATN", on_event_sat_proactive_command, NULL);
	tcore_object_add_callback(co_sat, "+SATF", on_response_terminal_response_confirm, NULL);

	dbg("Exit");

	return TRUE;
}

void imc_sat_exit(TcorePlugin *cp, CoreObject *co_sat)
{
	dbg("Exit");
}
