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

#include "imc_common.h"
#include "imc_modem.h"
#include "nvm/nvm.h"


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
static void on_confirmation_modem_message_send(TcorePending *p, gboolean result, void *user_data);
static void on_response_network_registration(TcorePending *p, int data_len, const void *data, void *user_data);
static void on_response_enable_proactive_command(TcorePending *p, int data_len, const void *data, void *user_data);

/* NVM */
static gboolean on_event_nvm_update(CoreObject *o, const void *event_info, void *user_data);
static void modem_unsuspend_nvm_updates(CoreObject *o);
static void modem_send_nvm_update_ack(CoreObject *o);
static void modem_send_nvm_update_request_ack(CoreObject *o);

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

	if (ret != TCORE_RETURN_SUCCESS)
		err("Failed to send AT request - ret: [0x%x]", ret);

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
	struct tresp_modem_set_flightmode res = {0};
	int response = 0;
	struct tnoti_modem_flight_mode modem_flight_mode = {0};

	o = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	if (ATresp->success > 0) {
		dbg("RESPONSE OK - flight mode operation finished");
		res.result = TCORE_RETURN_SUCCESS;
	} else {
		GSList *tokens = NULL;
		const char *line = NULL;
		dbg("RESPONSE NOK");

		line = (const char *) ATresp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
		} else {
			response = atoi(g_slist_nth_data(tokens, 0));
			err("error response: %d", response);
			/* TODO: CMEE error mapping is required. */
		}
		tcore_at_tok_free(tokens);
		res.result = TCORE_RETURN_3GPP_ERROR;
	}

	if (NULL == ur) {
		dbg("No user request. Internal request created during boot-up sequence");

		if (ATresp->success > 0) {
			modem_flight_mode.enable = tcore_modem_get_flight_mode_state(o);
			dbg("sucess case - Sending Flight Mode Notification (%d) to Telephony Server", modem_flight_mode.enable);

			tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_MODEM_FLIGHT_MODE,
										   sizeof(struct tnoti_modem_flight_mode), &modem_flight_mode);
		}
	} else {
		const struct treq_modem_set_flightmode *req_data = NULL;

		dbg("Sending response for Flight mode operation");

		req_data = tcore_user_request_ref_data(ur, NULL);

		if (TCORE_RETURN_SUCCESS == res.result) {
			if (TRUE == req_data->enable){
				tcore_modem_set_flight_mode_state(o, TRUE);
			} else {
				tcore_modem_set_flight_mode_state(o, FALSE);
			}
		}
		tcore_user_request_send_response(ur, TRESP_MODEM_SET_FLIGHTMODE, sizeof(struct tresp_modem_set_flightmode), &res);

		modem_flight_mode.enable = tcore_modem_get_flight_mode_state(o);
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_MODEM_FLIGHT_MODE,
										   sizeof(struct tnoti_modem_flight_mode), &modem_flight_mode);

		if (req_data->enable == 0) {
			dbg("Flight mode is disabled, trigger COPS to register on network");
			/* Trigger Network registration (for the moment automatic) */
			prepare_and_send_pending_request(o, "AT+COPS=0", NULL, TCORE_AT_NO_RESULT, NULL);
		}
	}
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
			err("error response: %d", response);
			/* TODO: CMEE error mapping is required. */
			res.result = TCORE_RETURN_3GPP_ERROR;
		}
	}

	ur = tcore_pending_ref_user_request(p);
	tcore_user_request_send_response(ur, TRESP_MODEM_GET_IMEI,
					sizeof(struct tresp_modem_get_imei), &res);

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

				dbg("version: sw=[%s], hw=[%s], rf_cal=[%s], product_code=[%s], model_id=[%s]",
								swver, hwver, caldate, pcode, id);
			} else {
				msg("invalid message");
				goto OUT;
			}
		}

		vi = g_try_new0(TelMiscVersionInformation, 1);
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

		if (NULL != swver) {
			snprintf(res.software,
				(AT_VER_LEN > strlen(swver) ? strlen(swver) : AT_VER_LEN),
				"%s", swver);
		}

		if (NULL != hwver) {
			snprintf(res.hardware,
				(AT_VER_LEN > strlen(hwver) ? strlen(hwver) : AT_VER_LEN),
				"%s", hwver);
		}

		plugin = tcore_pending_ref_plugin(p);
		vi_property = tcore_plugin_ref_property(plugin, "VERSION");
		memcpy(vi_property, vi, sizeof(TelMiscVersionInformation));
		g_free(vi);
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
			err("error response: %d", response);
			/* TODO: CMEE error mapping is required. */
			res.result = TCORE_RETURN_3GPP_ERROR;
		}
	}

	ur = tcore_pending_ref_user_request(p);
	tcore_user_request_send_response(ur, TRESP_MODEM_GET_VERSION,
						sizeof(struct tresp_modem_get_version), &res);

OUT:
	if (tokens != NULL)
		tcore_at_tok_free(tokens);

	return;
}

static enum tcore_hook_return on_hook_sim_status(Server *s,
				CoreObject *source, enum tcore_notification_command command,
				unsigned int data_len, void *data, void *user_data)
{
	TcorePlugin *plugin;
	const struct tnoti_sim_status *noti_sim_status;
	CoreObject *co_sat;
	CoreObject *co_network;

	plugin = tcore_object_ref_plugin(source);
	co_sat = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SAT);
	if (co_sat == NULL)
		return TCORE_HOOK_RETURN_CONTINUE;

	co_network = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_NETWORK);
	if (co_network == NULL)
		return TCORE_HOOK_RETURN_CONTINUE;

	dbg("Get SIM status");
	noti_sim_status = data;
	if (noti_sim_status == NULL)
		return TCORE_HOOK_RETURN_CONTINUE;

	/* If SIM is initialized, Enable STK and and attach to Network */
	dbg("SIM Status: [%d]", noti_sim_status->sim_status);
	if (noti_sim_status->sim_status == SIM_STATUS_INIT_COMPLETED) {
		dbg("SIM ready for attach!!! Enable STK and attach to Network");

		/* Sending AT+CFUN=6 */
		prepare_and_send_pending_request(co_sat, "AT+CFUN=6", NULL,
						TCORE_AT_NO_RESULT, on_response_enable_proactive_command);

		/* Sending AT+COPS */
		prepare_and_send_pending_request(co_network, "AT+COPS=0", NULL,
						TCORE_AT_NO_RESULT, on_response_network_registration);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

gboolean modem_power_on(TcorePlugin *plugin)
{
	CoreObject *co_modem = NULL;
	struct treq_modem_set_flightmode flight_mode_set = {0};
	struct tnoti_modem_power modem_power = {0};
	Storage *strg = NULL;

	co_modem = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
	if (co_modem == NULL) {
		err("Modem Core object is NULL");
		return FALSE;
	}

	/* Set Modem Power State to 'ON' */
	tcore_modem_set_powered(co_modem, TRUE);

	/* Get Flight mode from VCONFKEY */
	strg = tcore_server_find_storage(tcore_plugin_ref_server(plugin), "vconf");
	flight_mode_set.enable = tcore_storage_get_bool(strg, STORAGE_KEY_FLIGHT_MODE_BOOL);

	/* Set Flight mode as per AP settings */
	if (flight_mode_set.enable) {		/* Radio OFF */
		prepare_and_send_pending_request(co_modem, "AT+CFUN=4", NULL,
							TCORE_AT_NO_RESULT, on_response_set_flight_mode);

		/* Set Flight mode TRUE */
		tcore_modem_set_flight_mode_state(co_modem, TRUE);
	} else {							/* Radio ON */
		prepare_and_send_pending_request(co_modem, "AT+CFUN=1", NULL,
							TCORE_AT_NO_RESULT, on_response_set_flight_mode);

		/* Set Flight mode FALSE */
		tcore_modem_set_flight_mode_state(co_modem, FALSE);
	}

	/* Get IMEI */
	prepare_and_send_pending_request(co_modem, "AT+CGSN", NULL,
							TCORE_AT_NUMERIC, on_response_imei);

	/* Get Version Number  */
	prepare_and_send_pending_request(co_modem, "AT+CGMR", NULL,
							TCORE_AT_SINGLELINE, on_response_version);

	/* Send Notification to TAPI - MODEM_POWER */
	modem_power.state = MODEM_STATE_ONLINE;

	dbg("Sending notification - Modem Power state: [ONLINE]");
	tcore_server_send_notification(tcore_plugin_ref_server(plugin),
		co_modem, TNOTI_MODEM_POWER, sizeof(modem_power), &modem_power);

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

	dbg("Command: [%s], Prefix(if any): [%s], Command Length: [%d]",
						req->cmd, req->prefix, strlen(req->cmd));

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

	dbg("Command: [%s], Prefix(if any): [%s], Command Length: [%d]",
						req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_imei, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	return tcore_hal_send_request(hal, pending);
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

	dbg("Command: [%s], Prefix(if any): [%s], Command Length: [%d]",
						req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_version, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	return tcore_hal_send_request(hal, pending);
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

	req = tcore_at_request_new((const char *)cmd_str, NULL, TCORE_AT_NO_RESULT);
	g_free(cmd_str);

	dbg("Command: [%s], Prefix(if any): [%s], Command Length: [%d]",
						req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_set_flight_mode, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_modem_message_send, NULL);

	return tcore_hal_send_request(hal, pending);
}

static TReturn get_flight_mode(CoreObject *co_modem, UserRequest *ur)
{
	struct tresp_modem_get_flightmode resp_data;
	TReturn ret;

	memset(&resp_data, 0x0, sizeof(struct tresp_modem_get_flightmode));

	resp_data.enable = tcore_modem_get_flight_mode_state(co_modem);
	resp_data.result = TCORE_RETURN_SUCCESS;
	dbg("Get Flight mode: Flight mdoe: [%s]", (resp_data.enable ? "ON" : "OFF"));

	ret = tcore_user_request_send_response(ur,
		TRESP_MODEM_GET_FLIGHTMODE,
		sizeof(struct tresp_modem_get_flightmode), &resp_data);
	dbg("ret: [0x%x]", ret);

	return ret;
}

static struct tcore_modem_operations modem_ops = {
	.power_on = NULL,
	.power_off = power_off,
	.power_reset = NULL,
	.set_flight_mode = set_flight_mode,
	.get_flight_mode = get_flight_mode,
	.get_imei = get_imei,
	.get_version = get_version,
	.get_sn = NULL,
	.dun_pin_ctrl = NULL,
};

gboolean imc_modem_init(TcorePlugin *cp, CoreObject *co_modem)
{
	TelMiscVersionInformation *vi_property;
	TelMiscSNInformation *imei_property;
	TelMiscSNInformation *sn_property;

	dbg("Enter");

	/* Set operations */
	tcore_modem_set_ops(co_modem, &modem_ops);

	vi_property = g_try_new0(TelMiscVersionInformation, 1);
	tcore_plugin_link_property(cp, "VERSION", vi_property);

	imei_property = g_try_new0(TelMiscSNInformation, 1);
	tcore_plugin_link_property(cp, "IMEI", imei_property);

	sn_property = g_try_new0(TelMiscSNInformation, 1);
	tcore_plugin_link_property(cp, "SN", sn_property);

	tcore_server_add_notification_hook(tcore_plugin_ref_server(cp),
							TNOTI_SIM_STATUS, on_hook_sim_status, NULL);
	dbg("Registering for +XDRVI event");
	tcore_object_add_callback(co_modem, "+XDRVI", on_event_nvm_update, NULL);

	dbg("Exit");
	return TRUE;
}

void imc_modem_exit(TcorePlugin *cp, CoreObject *co_modem)
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

/*
 * NV Manager - Support for Remote File System
 */
/* NVM Hook */
static gboolean modem_rfs_hook(const char *data)
{
	if (data != NULL)
		if (data[NVM_FUNCTION_ID_OFFSET] == XDRV_INDICATION)
			return TRUE;

	return FALSE;
}

/* NVM event Notification */
static gboolean on_event_nvm_update(CoreObject *o, const void *event_info, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines;
	const char *line;
	int function_id;

	gboolean ret = TRUE;
	dbg("Entered");

	lines = (GSList *)event_info;
	line = lines->data;
	dbg("Line: [%s]", line);

	function_id = nvm_sum_4_bytes(&line[NVM_FUNCTION_ID_OFFSET]);
	dbg("Function ID: [%d]", function_id);
	if (IUFP_UPDATE == function_id) {
		dbg("Calling process nvm_update");

		/*
		 * Process NV Update indication
		 *
		 * +XDRVI: IUFP_GROUP, IUFP_UPDATE, <xdrv_result>, <data>
		 */
		if (NVM_NO_ERR == nvm_process_nv_update(line)) {
			dbg("NV data processed successfully");

			/* Acknowledge NV Update */
			modem_send_nvm_update_ack(o);

			return ret;
		} else {
			err("NV data processing failed");
			ret = FALSE;
		}
	} else {
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 3) {
			err("XDRVI event with less number of tokens, Ignore!!!");
			ret = FALSE;
		}
		else if (IUFP_GROUP_ID != atoi(g_slist_nth_data(tokens, 0))) {
			err("Group ID mismatch, Ignore!!!");
			ret = FALSE;
		}
		else {
			switch (atoi(g_slist_nth_data(tokens, 1))) {
				case IUFP_UPDATE_REQ:
					dbg("NV Update Request");

					/* Acknowledge the Update Request */
					modem_send_nvm_update_request_ack(o);
				break;

				case IUFP_NO_PENDING_UPDATE:
					dbg("NO pending NV Update(s)!!!");
					/* Can send FLUSH request to get fresh updates */
				break;

				default:
					err("Unspported Function ID [%d], Ignore", atoi(g_slist_nth_data(tokens, 1)));
					ret = FALSE;
			}
		}

		tcore_at_tok_free(tokens);
	}

	dbg("Exit");
	return ret;
}

/* NVM Responses */
static gboolean __modem_check_nvm_response(const void *data, int command)
{
	const TcoreATResponse *resp = data;
	const char *line;
	char *resp_str;
	GSList *tokens = NULL;
	gboolean ret = FALSE;
	dbg("Entered");

	/* +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>] */
	if (NULL == resp) {
		err("Input data is NULL");
		return FALSE;
	}

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		line = (const char *) (((GSList *) resp->lines)->data);
		tokens = tcore_at_tok_new(line);

		/* Group ID */
		resp_str = g_slist_nth_data(tokens, 0);
		if (NULL == resp_str) {
			err("Group ID is missing ");
			goto OUT;
		}
		else if (IUFP_GROUP_ID != atoi(resp_str)) {
			err("Group ID mismatch");
			goto OUT;
		}

		/* Function ID */
		resp_str =  g_slist_nth_data(tokens, 1);
		if (NULL == resp_str) {
			err("Function ID is missing ");
			goto OUT;
		}
		else if (command != atoi(resp_str)) {
			err("Function ID mismatch");
			goto OUT;
		}

		/* XDRV Result */
		resp_str =  g_slist_nth_data(tokens, 2);
		if (NULL == resp_str) {
			err("XDRV result is missing ");
			goto OUT;
		}
		else if (XDRV_RESULT_OK != atoi(resp_str)) {
			err("XDRV result[%d] ", atoi(resp_str));
			goto OUT;
		}

		/* Result code */
		resp_str =  g_slist_nth_data(tokens, 3);
		if (NULL == resp_str) {
			err("UTA result is missing ");
			goto OUT;
		}
		else if (UTA_SUCCESS != atoi(resp_str)) {
			err("uta result[%d] ", atoi(resp_str));
			goto OUT;
		}

		ret = TRUE;
	} else {
		dbg("Response NOK");
	}

OUT:
	tcore_at_tok_free(tokens);

	dbg("Exit");
	return ret;
}

static void _on_response_modem_unsuspend_nvm_updates(TcorePending *p,
							int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __modem_check_nvm_response(data, IUFP_SUSPEND)) {
		dbg("Priority level is set to get all updates since Boot-up");

		/* Create NV data file */
		if (nvm_create_nvm_data() == FALSE) {
			err("Failed to Create NV data file");
		}

		return;
	}

	err("Response NOT OK");
}

static void _on_response_modem_send_nvm_update_ack(TcorePending *p,
							int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE ==  __modem_check_nvm_response(data, IUFP_UPDATE_ACK)) {
		dbg("[UPDATE ACK] OK");
		return;
	}

	err("[UPDATE ACK] NOT OK");
}

static void _on_response_modem_send_nvm_update_request_ack(TcorePending *p,
							int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __modem_check_nvm_response(data, IUFP_UPDATE_REQ_ACK)) {
		dbg("[REQUEST ACK] OK");
		return;
	}

	err("[REQUEST ACK] NOT OK");
}

static void _on_response_modem_register_nvm(TcorePending *p,
						int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __modem_check_nvm_response(data, IUFP_REGISTER)) {
		dbg("Registering successful");

		/* Send SUSPEND_UPDATE for all UPDATES */
		modem_unsuspend_nvm_updates(tcore_pending_ref_core_object(p));

		dbg("Exit");
		return;
	}

	err("Response NOT OK");
}

/* NVM Requests */
static void modem_unsuspend_nvm_updates(CoreObject *o)
{
	TcorePending *pending = NULL;
	char *cmd_str;
	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%d, %d, %d, %d",
					IUFP_GROUP_ID, IUFP_SUSPEND,
					0, UTA_FLASH_PLUGIN_PRIO_UNSUSPEND_ALL);

	/* Prepare pending request */
	pending = tcore_at_pending_new(o,
								cmd_str,
								"+XDRV:",
								TCORE_AT_SINGLELINE,
								_on_response_modem_unsuspend_nvm_updates,
								NULL);
	if (pending == NULL) {
		err("Failed to form pending request");
	}
	else if (tcore_hal_send_request(tcore_object_get_hal(o), pending)
			!= TCORE_RETURN_SUCCESS) {
		err("IUFP_SUSPEND - Unable to send AT-Command");
	}
	else {
		dbg("IUFP_SUSPEND - Successfully sent AT-Command");
	}

	g_free(cmd_str);
}

static void modem_send_nvm_update_ack(CoreObject *o)
{
	TcorePending *pending = NULL;
	char *cmd_str;
	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s", IUFP_GROUP, IUFP_UPDATE_ACK_STR);

	/* Prepare pending request */
	pending = tcore_at_pending_new(o,
								cmd_str,
								"+XDRV:",
								TCORE_AT_SINGLELINE,
								_on_response_modem_send_nvm_update_ack,
								NULL);
	if (pending == NULL) {
		err("Failed to form pending request");
	}
	else if (tcore_hal_send_request(tcore_object_get_hal(o), pending)
										!= TCORE_RETURN_SUCCESS) {
		err("IUFP_UPDATE_ACK - Unable to send AT-Command");
	}
	else {
		dbg("IUFP_UPDATE_ACK - Successfully sent AT-Command");
	}

	g_free(cmd_str);
}

static void modem_send_nvm_update_request_ack(CoreObject *o)
{
	TcorePending *pending = NULL;
	char *cmd_str;
	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s", IUFP_GROUP, IUFP_UPDATE_REQ_ACK_STR);

	/* Prepare pending request */
	pending = tcore_at_pending_new(o,
								cmd_str,
								"+XDRV:",
								TCORE_AT_SINGLELINE,
								_on_response_modem_send_nvm_update_request_ack,
								NULL);


	if (pending == NULL) {
		err("Failed to form pending request");
	}
	else if (tcore_hal_send_request(tcore_object_get_hal(o), pending)
									!= TCORE_RETURN_SUCCESS) {
		err("IUFP_UPDATE_REQ_ACK - Unable to send AT-Ccommand");
	}
	else {
		dbg("IUFP_UPDATE_REQ_ACK - Successfully sent AT-Command");
	}

	g_free(cmd_str);
}

void modem_register_nvm(CoreObject *co_modem)
{
	TcorePending *pending = NULL;
	char *cmd_str;
	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s, %s",
					IUFP_GROUP, IUFP_REGISTER_STR, XDRV_ENABLE);

	/* Prepare pending request */
	pending = tcore_at_pending_new(co_modem,
								cmd_str,
								"+XDRV:",
								TCORE_AT_SINGLELINE,
								_on_response_modem_register_nvm,
								NULL);
	if (pending == NULL) {
		err("Failed to form pending request");
	}
	else if (tcore_hal_send_request(tcore_object_get_hal(co_modem), pending)
									!= TCORE_RETURN_SUCCESS) {
		err("IUFP_REGISTER (Enable) -Unable to send AT-Command");
	}
	else {
		dbg("IUFP_REGISTER (Enable) -Successfully sent AT-Command");

		/* Add RFS hook */
		/* Todo unblock this api */
		tcore_at_add_hook(tcore_object_get_hal(co_modem), modem_rfs_hook);
	}

	g_free(cmd_str);
}
