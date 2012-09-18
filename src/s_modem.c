/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Harish Bishnoi <hbishnoi@samsung.com>
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
#include <unistd.h>

#include <glib.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <user_request.h>
#include <queue.h>
#include <co_modem.h>
#include <storage.h>
#include <server.h>
#include <at.h>
#include <mux.h>

#include "s_common.h"
#include "s_modem.h"


#define ID_RESERVED_AT 0x0229

#define MAX_VERSION_LEN 32
#define TAPI_MISC_ME_SN_LEN_MAX             32
#define TAPI_MISC_PRODUCT_CODE_LEN_MAX      32
#define TAPI_MISC_MODEL_ID_LEN_MAX          17
#define TAPI_MISC_PRL_ERI_VER_LEN_MAX       17

#define CPAS_RES_READY          0
#define CPAS_RES_UNAVAIL            1
#define CPAS_RES_UNKNOWN            2
#define CPAS_RES_RINGING            3
#define CPAS_RES_CALL_PROGRESS  4
#define CPAS_RES_ASLEEP           5
#define AT_VER_LEN 20


enum cp_state {
	CP_STATE_OFFLINE,
	CP_STATE_CRASH_RESET,
	CP_STATE_CRASH_EXIT,
	CP_STATE_BOOTING,
	CP_STATE_ONLINE,
	CP_STATE_NV_REBUILDING,
	CP_STATE_LOADER_DONE,
};

typedef enum {
	TAPI_MISC_ME_IMEI = 0x00, /**< 0x00: IMEI, GSM/UMTS device */
	TAPI_MISC_ME_ESN = 0x01, /**< 0x01: ESN(Electronic Serial Number), It`s essentially run out. CDMA device */
	TAPI_MISC_ME_MEID = 0x02, /**< 0x02: MEID, This value can have hexa decimal digits. CDMA device */
	TAPI_MISC_ME_MAX = 0xff /**< 0xff: reserved */
} TelMiscSNIndexType_t;

typedef struct {
	TelMiscSNIndexType_t sn_index; /**< serial number index */
	int sn_len; /**< Length */
	unsigned char szNumber[TAPI_MISC_ME_SN_LEN_MAX]; /**< Number */
} TelMiscSNInformation;

/**
 * Mobile Equipment Version Information
 */
typedef struct {
	unsigned char ver_mask; /**< version mask  - 0x01:SW_ver, 0x02:HW_ver, 0x04:RF_CAL_date, 0x08:Product_code, 0x10:Model_ID, 0x20:PRL, 0x04:ERI, 0xff:all */
	unsigned char szSwVersion[MAX_VERSION_LEN]; /**< Software version, null termination */
	unsigned char szHwVersion[MAX_VERSION_LEN]; /**< Hardware version, null termination */
	unsigned char szRfCalDate[MAX_VERSION_LEN]; /**< Calculation Date, null termination */
	unsigned char szProductCode[TAPI_MISC_PRODUCT_CODE_LEN_MAX]; /**< product code, null termination */
	unsigned char szModelId[TAPI_MISC_MODEL_ID_LEN_MAX]; /**< model id (only for CDMA), null termination */
	unsigned char prl_nam_num; /**< number of PRL NAM fields */
	unsigned char szPrlVersion[TAPI_MISC_PRL_ERI_VER_LEN_MAX * 3]; /**< prl version (only for CDMA), null termination */
	unsigned char eri_nam_num; /**< number of PRL NAM fields */
	unsigned char szEriVersion[TAPI_MISC_PRL_ERI_VER_LEN_MAX * 3]; /**< eri version (only for CDMA), null termination */
} TelMiscVersionInformation;


static void prepare_and_send_pending_request(CoreObject *co, const char *at_cmd, const char *prefix, enum tcore_at_command_type at_cmd_type, TcorePendingResponseCallback callback);
static void on_confirmation_modem_message_send(TcorePending *p, gboolean result, void *user_data);     // from Kernel
static void on_response_network_registration(TcorePending *p, int data_len, const void *data, void *user_data);
static void on_response_enable_proactive_command(TcorePending *p, int data_len, const void *data, void *user_data);

static void on_confirmation_modem_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("on_confirmation_modem_message_send - msg out from queue.\n");

	if (result == FALSE) {
		/* Fail */
		dbg("SEND FAIL");
	} else {
		dbg("SEND OK");
	}
}

static void on_response_enable_proactive_command(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;

	if (resp->success > 0) {
		dbg("RESPONSE OK proactive command enabled");
	} else {
		dbg("RESPONSE NOK proactive command disabled");
	}
}

static void on_response_network_registration(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;

	if (resp->success > 0) {
		dbg("registration attempt OK");
	} else {
		dbg("registration attempt failed");
	}
}

void prepare_and_send_pending_request(CoreObject *co, const char *at_cmd, const char *prefix, enum tcore_at_command_type at_cmd_type, TcorePendingResponseCallback callback)
{
	TcoreATRequest *req = NULL;
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	TReturn ret;

	hal = tcore_object_get_hal(co);
	dbg("hal: %p", hal);

	pending = tcore_pending_new(co, 0);
	if (!pending)
		dbg("Pending is NULL");
	req = tcore_at_request_new(at_cmd, prefix, at_cmd_type);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, callback, NULL);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);
	ret = tcore_hal_send_request(hal, pending);
}

static void on_response_power_off(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *o = 0;
	TcoreHal *h = 0;

	o = tcore_pending_ref_core_object(p);
	h = tcore_object_get_hal(o);

	dbg("modem power off");

	tcore_hal_set_power_state(h, FALSE);
}

static void on_response_set_flight_mode(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *o = NULL;
	UserRequest *ur = NULL;
	const TcoreATResponse *ATresp = data;
	GSList *tokens = NULL;
	const char *line = NULL;
	struct tresp_modem_set_flightmode res = {0};
	int response = 0;
	struct tnoti_modem_flight_mode modem_flight_mode = {0};
	const struct treq_modem_set_flightmode *req_data = NULL;

	o = tcore_pending_ref_core_object(p);

	if (ATresp->success > 0) {
		dbg("RESPONSE OK - flight mode operation finished");
		res.result = TCORE_RETURN_SUCCESS;
	} else {
		dbg("RESPONSE NOK");
		line = (const char *) ATresp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			response = atoi(g_slist_nth_data(tokens, 0));
			/* TODO: CMEE error mapping is required. */
			res.result = TCORE_RETURN_3GPP_ERROR;
		}
	}

	ur = tcore_pending_ref_user_request(p);
	if (NULL == ur) {
		dbg("No user request. Internal request created during boot-up sequence");

		if (ATresp->success > 0) {
			modem_flight_mode.enable = tcore_modem_get_flight_mode_state(o);
			dbg("sucess case - Sending Flight Mode Notification (%d) to Telephony Server", modem_flight_mode.enable);

			tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_MODEM_FLIGHT_MODE,
										   sizeof(struct tnoti_modem_flight_mode), &modem_flight_mode);
		}
	} else {
		dbg("Sending response for Flight mode operation");

		req_data = tcore_user_request_ref_data(ur, NULL);

		if (TCORE_RETURN_SUCCESS == res.result) {
			if (TRUE == req_data->enable)
				res.result = 1;
			else
				res.result = 2;
		} else {
			res.result = 3;
		}

		tcore_user_request_send_response(ur, TRESP_MODEM_SET_FLIGHTMODE, sizeof(struct tresp_modem_set_flightmode), &res);

		if (req_data->enable == 0) {
			dbg("Flight mode is disabled, trigger COPS to register on network");
			/* Trigger Network registration (for the moment automatic) */
			prepare_and_send_pending_request(o, "AT+COPS=0", NULL, TCORE_AT_NO_RESULT, NULL);
		}
	}

	tcore_at_tok_free(tokens);
}

static void on_response_imei(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	TcorePlugin *plugin = NULL;
	struct tresp_modem_get_imei res;
	TelMiscSNInformation *imei_property = NULL;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line;
	int response = 0;

	memset(&res, 0, sizeof(struct tresp_modem_get_imei));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("invalid message");
				goto OUT;
			}
		}
		res.result = TCORE_RETURN_SUCCESS;
		strncpy(res.imei, g_slist_nth_data(tokens, 0), 16);

		dbg("imei = [%s]", res.imei);

		plugin = tcore_pending_ref_plugin(p);
		imei_property = tcore_plugin_ref_property(plugin, "IMEI");
		if (imei_property) {
			imei_property->sn_index = TAPI_MISC_ME_IMEI;
			imei_property->sn_len = strlen(res.imei);
			memcpy(imei_property->szNumber, res.imei, imei_property->sn_len);
		}
	} else {
		dbg("RESPONSE NOK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
		}


		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			response = atoi(g_slist_nth_data(tokens, 0));
			/* TODO: CMEE error mapping is required. */
			res.result = TCORE_RETURN_3GPP_ERROR;
		}
	}

	ur = tcore_pending_ref_user_request(p);
	tcore_user_request_send_response(ur, TRESP_MODEM_GET_IMEI, sizeof(struct tresp_modem_get_imei), &res);

OUT:
	if (tokens != NULL)
		tcore_at_tok_free(tokens);

	return;
}

static void on_response_version(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	TcorePlugin *plugin = NULL;
	struct tresp_modem_get_version res = {0};
	TelMiscVersionInformation *vi_property = NULL;
	TelMiscVersionInformation *vi = NULL;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	char *swver = NULL;
	char *hwver = NULL;
	char *caldate = NULL;
	char *pcode = NULL;
	char *id = NULL;

	int response = 0;

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) == 1) {
				swver = g_slist_nth_data(tokens, 0);
				dbg("version: sw=[%s]", swver);
			} else if (g_slist_length(tokens) == 5) {
				swver = g_slist_nth_data(tokens, 0);
				hwver = g_slist_nth_data(tokens, 1);
				caldate = g_slist_nth_data(tokens, 2);
				pcode = g_slist_nth_data(tokens, 3);
				id = g_slist_nth_data(tokens, 4);

				dbg("version: sw=[%s], hw=[%s], rf_cal=[%s], product_code=[%s], model_id=[%s]", swver, hwver, caldate, pcode, id);
			} else {
				msg("invalid message");
				goto OUT;
			}
		}

		vi = calloc(sizeof(TelMiscVersionInformation), 1);
		if (NULL != swver)
			memcpy(vi->szSwVersion, swver, strlen(swver));
		if (NULL != hwver)
			memcpy(vi->szHwVersion, hwver, strlen(hwver));
		if (NULL != caldate)
			memcpy(vi->szRfCalDate, caldate, strlen(caldate));
		if (NULL != pcode)
			memcpy(vi->szProductCode, pcode, strlen(pcode));
		if (NULL != id)
			memcpy(vi->szModelId, id, strlen(id));

		memset(&res, 0, sizeof(struct tresp_modem_get_version));

		if (NULL != swver)
			snprintf(res.software, (AT_VER_LEN > strlen(swver) ? strlen(swver) : AT_VER_LEN), "%s", swver);
		if (NULL != hwver)
			snprintf(res.hardware, (AT_VER_LEN > strlen(hwver) ? strlen(hwver) : AT_VER_LEN), "%s", hwver);

		plugin = tcore_pending_ref_plugin(p);
		vi_property = tcore_plugin_ref_property(plugin, "VERSION");
		memcpy(vi_property, vi, sizeof(TelMiscVersionInformation));
		free(vi);
	} else {
		dbg("RESPONSE NOK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
		}

		memset(&res, 0, sizeof(struct tresp_modem_get_version));


		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			response = atoi(g_slist_nth_data(tokens, 0));
			/* TODO: CMEE error mapping is required. */
			res.result = TCORE_RETURN_3GPP_ERROR;
		}
	}

	ur = tcore_pending_ref_user_request(p);
	tcore_user_request_send_response(ur, TRESP_MODEM_GET_VERSION, sizeof(struct tresp_modem_get_version), &res);

OUT:
	if (tokens != NULL)
		tcore_at_tok_free(tokens);

	return;
}

static gboolean on_event_bootup_sim_status(CoreObject *o, const void *event_info, void *user_data)
{
	GSList *tok = NULL;
	GSList *lines = NULL;
	int value = -1;
	char *line = NULL;

	lines = (GSList *) event_info;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}
	line = (char *) (lines->data);
	dbg("on_bootup_event_sim_status notification : %s", line);

	tok = tcore_at_tok_new(line);
	value = atoi(g_slist_nth_data(tok, 0));

	if (7 == value) {
		dbg("SIM ready. request COPS & remove callback");
		dbg("power on done set for proactive command receiving mode");
		prepare_and_send_pending_request(o, "AT+CFUN=6", NULL, TCORE_AT_NO_RESULT, on_response_enable_proactive_command);
		prepare_and_send_pending_request(o, "AT+COPS=0", NULL, TCORE_AT_NO_RESULT, on_response_network_registration);
		return FALSE;
	}

OUT:
	if (tok != NULL)
		tcore_at_tok_free(tok);

	return TRUE;
}



gboolean modem_power_on(TcorePlugin *p)
{
	CoreObject *co_modem = NULL;
	struct treq_modem_set_flightmode flight_mode_set = {0};
	struct tnoti_modem_power modem_power = {0};
	TcoreHal *h = NULL;
	Storage *strg = NULL;

	co_modem = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_MODEM);

	strg = tcore_server_find_storage(tcore_plugin_ref_server(p), "vconf");
	flight_mode_set.enable = tcore_storage_get_bool(strg, STORAGE_KEY_FLIGHT_MODE_BOOL);

	h = tcore_object_get_hal(co_modem);
	tcore_hal_set_power_state(h, TRUE);

	/* Set Flight mode as per AP settings */
	if (flight_mode_set.enable) { /* Radio Off */
		prepare_and_send_pending_request(co_modem, "AT+CFUN=4", NULL, TCORE_AT_NO_RESULT, on_response_set_flight_mode);
		tcore_modem_set_flight_mode_state(co_modem, TRUE);
	} else { /* Radio On */
		prepare_and_send_pending_request(co_modem, "AT+CFUN=1", NULL, TCORE_AT_NO_RESULT, on_response_set_flight_mode);
		tcore_modem_set_flight_mode_state(co_modem, FALSE);
	}

	/* Get IMEI */
	prepare_and_send_pending_request(co_modem, "AT+CGSN", NULL, TCORE_AT_NUMERIC, on_response_imei);

	/* Get Version Number  */
	prepare_and_send_pending_request(co_modem, "AT+CGMR", NULL, TCORE_AT_SINGLELINE, on_response_version);

	tcore_modem_set_powered(co_modem, TRUE);

	modem_power.state = MODEM_STATE_ONLINE;

	tcore_server_send_notification(tcore_plugin_ref_server(p), co_modem, TNOTI_MODEM_POWER,
								   sizeof(struct tnoti_modem_power), &modem_power);

	return TRUE;
}

static TReturn power_off(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	req = tcore_at_request_new("AT+CFUN=0", NULL, TCORE_AT_NO_RESULT);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_power_off, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn get_imei(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	pending = tcore_pending_new(o, 0);

	req = tcore_at_request_new("AT+CGSN", NULL, TCORE_AT_NUMERIC);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_imei, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	return TCORE_RETURN_SUCCESS;
}


static TReturn get_version(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	pending = tcore_pending_new(o, 0);

	req = tcore_at_request_new("AT+CGMR", NULL, TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_version, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn set_flight_mode(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	const struct treq_modem_set_flightmode *req_data = NULL;
	char *cmd_str = NULL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	pending = tcore_pending_new(o, 0);

	req_data = tcore_user_request_ref_data(ur, NULL);

	if (req_data->enable) {
		dbg("Flight mode on/n");
		cmd_str = g_strdup("AT+CFUN=4");
	} else {
		dbg("Flight mode off/n");
		cmd_str = g_strdup("AT+CFUN=1");
	}

	req = tcore_at_request_new((const char *) cmd_str, NULL, TCORE_AT_NO_RESULT);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_set_flight_mode, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	return TCORE_RETURN_SUCCESS;
}


static struct tcore_modem_operations modem_ops = {
	.power_on = NULL,
	.power_off = power_off,
	.power_reset = NULL,
	.set_flight_mode = set_flight_mode,
	.get_imei = get_imei,
	.get_version = get_version,
	.get_sn = NULL,
	.dun_pin_ctrl = NULL,
};

gboolean s_modem_init(TcorePlugin *cp, CoreObject *co_modem)
{
	TelMiscVersionInformation *vi_property;
	TelMiscSNInformation *imei_property;
	TelMiscSNInformation *sn_property;

	dbg("Enter");

	tcore_modem_override_ops(co_modem, &modem_ops);

	vi_property = g_try_new0(TelMiscVersionInformation, 1);
	tcore_plugin_link_property(cp, "VERSION", vi_property);

	imei_property = g_try_new0(TelMiscSNInformation, 1);
	tcore_plugin_link_property(cp, "IMEI", imei_property);

	sn_property = g_try_new0(TelMiscSNInformation, 1);
	tcore_plugin_link_property(cp, "SN", sn_property);

	dbg("Registering for +XSIM event");
	tcore_object_override_callback(co_modem, "+XSIM", on_event_bootup_sim_status, NULL);

	dbg("Exit");

	return TRUE;
}

void s_modem_exit(TcorePlugin *cp, CoreObject *co_modem)
{
	TelMiscVersionInformation *vi_property;
	TelMiscSNInformation *imei_property;
	TelMiscSNInformation *sn_property;
	TcorePlugin *plugin = tcore_object_ref_plugin(co_modem);

	vi_property = tcore_plugin_ref_property(plugin, "VERSION");
	g_free(vi_property);

	imei_property = tcore_plugin_ref_property(plugin, "IMEI");
	g_free(imei_property);

	sn_property = tcore_plugin_ref_property(plugin, "SN");
	g_free(sn_property);

	dbg("Exit");
}
