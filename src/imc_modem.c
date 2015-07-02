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

#include "imc_common.h"
#include "imc_modem.h"
#include "nvm/nvm.h"

/*
 * Modem Private data
 */
typedef struct {
	/* IMEI */
	gboolean imei_valid;	/**< IMEI validatity flag */
	char imei[MODEM_DEVICE_IMEI_LEN_MAX];

	/* Version information */
	gboolean version_valid;	/**< Version validatity flag */
	char software[33];
	char hardware[33];
	char calibration[33];
	char product_code[33];
} PrivateData;

static void on_confirmation_modem_message_send(TcorePending *pending,
	gboolean result, void *user_data);
static void on_response_network_registration(TcorePending *pending,
	int data_len, const void *data, void *user_data);
static void on_response_enable_proactive_command(TcorePending *pending,
	int data_len, const void *data, void *user_data);

/* NVM */
static gboolean on_event_modem_nvm_update(CoreObject *co_modem,
	const void *event_info, void *user_data);
static void modem_unsuspend_nvm_updates(CoreObject *co_modem);
static void modem_send_nvm_update_ack(CoreObject *co_modem);
static void modem_send_nvm_update_request_ack(CoreObject *co_modem);

static void on_confirmation_modem_message_send(TcorePending *pending,
	gboolean result, void *user_data)
{
	dbg("Request send: [%s]", (result == TRUE ? "Success" : "Fail"));
}

static void on_response_enable_proactive_command(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;

	dbg("[Response] Pro-active command enabling - RESPONSE '%s'",
		(at_resp->success > 0 ? "OK" : "NOK"));
}

static void on_response_network_registration(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;

	dbg("[Response] Network Registration enable - RESPONSE '%s'",
		(at_resp->success > 0 ? "OK" : "NOK"));
}

static void on_response_modem_power_off(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct tresp_modem_power_off modem_power_off_resp;
	CoreObject *co_modem = 0;
	UserRequest *ur;
	TcoreHal *h = 0;

	dbg("[Response] Modem Power OFF - RESPONSE '%s'",
		(at_resp->success > 0 ? "OK" : "NOK"));

	co_modem = tcore_pending_ref_core_object(pending);
	h = tcore_object_get_hal(co_modem);

	if (at_resp->success > 0) {
		modem_power_off_resp.result = TCORE_RETURN_SUCCESS;

		/* Update HAL state */
		tcore_hal_set_power_state(h, FALSE);
	} else {
		modem_power_off_resp.result = TCORE_RETURN_FAILURE;
	}

	/* Send Response */
	ur = tcore_pending_ref_user_request(pending);
	tcore_user_request_send_response(ur,
		TRESP_MODEM_POWER_OFF,
		sizeof(struct tresp_modem_power_off), &modem_power_off_resp);
}

static void on_response_modem_set_flight_mode(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	CoreObject *co_modem = NULL;
	UserRequest *ur = NULL;
	const TcoreATResponse *at_resp = data;
	struct tresp_modem_set_flightmode modem_set_flightmode_resp = {0};
	int response = 0;
	struct tnoti_modem_flight_mode modem_flight_mode = {0};

	co_modem = tcore_pending_ref_core_object(pending);
	ur = tcore_pending_ref_user_request(pending);

	dbg("[Response] Modem Set Flight mode - RESPONSE '%s'",
		(at_resp->success > 0 ? "OK" : "NOK"));

	if (at_resp->success > 0) {
		modem_set_flightmode_resp.result = TCORE_RETURN_SUCCESS;
	} else {
		GSList *tokens = NULL;
		const char *line = NULL;

		line = (const char *) at_resp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
		} else {
			response = atoi(g_slist_nth_data(tokens, 0));
			err("error response: %d", response);
			/* TODO: CMEE error mapping is required. */
		}
		tcore_at_tok_free(tokens);
		modem_set_flightmode_resp.result = TCORE_RETURN_3GPP_ERROR;
	}

	if (NULL == ur) {
		dbg("Internal request created during boot-up sequence");

		if (at_resp->success > 0) {
			Server *server;

			modem_flight_mode.enable =
				tcore_modem_get_flight_mode_state(co_modem);
			dbg("Sending Flight Mode Notification (%d) to Telephony Server",
				modem_flight_mode.enable);

			server = tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem));

			/* Send Notification */
			tcore_server_send_notification(server,
				co_modem, TNOTI_MODEM_FLIGHT_MODE,
				sizeof(struct tnoti_modem_flight_mode), &modem_flight_mode);
		}
	} else {
		Server *server;
		const struct treq_modem_set_flightmode *req_data = NULL;

		dbg("Sending response for Flight mode operation");

		req_data = tcore_user_request_ref_data(ur, NULL);

		if (TCORE_RETURN_SUCCESS == modem_set_flightmode_resp.result) {
			if (TRUE == req_data->enable)
				tcore_modem_set_flight_mode_state(co_modem, TRUE);
			else
				tcore_modem_set_flight_mode_state(co_modem, FALSE);
		}

		/* Send Response */
		tcore_user_request_send_response(ur,
			TRESP_MODEM_SET_FLIGHTMODE,
			sizeof(struct tresp_modem_set_flightmode), &modem_set_flightmode_resp);

		modem_flight_mode.enable = tcore_modem_get_flight_mode_state(co_modem);


		server = tcore_plugin_ref_server(tcore_object_ref_plugin(co_modem));

		/* Send Notification */
		tcore_server_send_notification(server,
			co_modem, TNOTI_MODEM_FLIGHT_MODE,
			sizeof(struct tnoti_modem_flight_mode), &modem_flight_mode);

		if (req_data->enable == 0) {
			dbg("Flight mode is disabled, trigger COPS to register on network");

			/* Trigger Network registration (for the moment automatic) */
			tcore_prepare_and_send_at_request(co_modem,
				"AT+COPS=0", NULL,
				TCORE_AT_NO_RESULT, NULL,
				NULL, NULL,
				NULL, NULL, 0, NULL, NULL);
		}
	}
}

static void on_response_modem_get_imei(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct tresp_modem_get_imei modem_get_imei_resp;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line;

	memset(&modem_get_imei_resp, 0x0, sizeof(struct tresp_modem_get_imei));

	if (at_resp->success > 0) {
		CoreObject *co = NULL;
		PrivateData *priv_data = NULL;

		dbg("RESPONSE OK");

		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("invalid message");
				goto OUT;
			}
		}

		modem_get_imei_resp.result = TCORE_RETURN_SUCCESS;
		strncpy(modem_get_imei_resp.imei, g_slist_nth_data(tokens, 0), MODEM_DEVICE_IMEI_LEN_MAX - 1);
		dbg("IMEI: [%s]", modem_get_imei_resp.imei);

		/* Cache IMEI */
		co = tcore_pending_ref_core_object(pending);
		priv_data = tcore_object_ref_user_data(co);
		priv_data->imei_valid = TRUE;
		strncpy(priv_data->imei, modem_get_imei_resp.imei, MODEM_DEVICE_IMEI_LEN_MAX - 1);
	} else {
		dbg("RESPONSE NOK");

		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
		}

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");

			modem_get_imei_resp.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			int response = atoi(g_slist_nth_data(tokens, 0));
			err("error response: %d", response);

			/* TODO: CMEE error mapping is required. */
			modem_get_imei_resp.result = TCORE_RETURN_3GPP_ERROR;
		}
	}

	/* Send Response */
	ur = tcore_pending_ref_user_request(pending);
	tcore_user_request_send_response(ur,
		TRESP_MODEM_GET_IMEI,
		sizeof(struct tresp_modem_get_imei), &modem_get_imei_resp);

OUT:
	tcore_at_tok_free(tokens);
}

static void on_response_modem_get_version(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_resp = data;
	struct tresp_modem_get_version modem_get_version_resp;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;

	memset(&modem_get_version_resp, 0, sizeof(struct tresp_modem_get_version));

	if (at_resp->success > 0) {
		CoreObject *co = NULL;
		PrivateData *priv_data = NULL;

		char *software_version = NULL;
		char *hardware_version = NULL;
		char *calibration_date = NULL;
		char *product_code = NULL;
		char *model_id = NULL;

		dbg("RESPONSE OK");

		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;

			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) == 1) {
				software_version = g_slist_nth_data(tokens, 0);
				dbg("Software version: [%s]", software_version);
			} else if (g_slist_length(tokens) == 5) {
				software_version = g_slist_nth_data(tokens, 0);
				hardware_version = g_slist_nth_data(tokens, 1);
				calibration_date = g_slist_nth_data(tokens, 2);
				product_code = g_slist_nth_data(tokens, 3);
				model_id = g_slist_nth_data(tokens, 4);

				dbg("Software version: [%s] Hardware version: [%s] " \
					"Calibration: [%s] Product code: [%s] Model ID: [%s]",
					software_version, hardware_version,
					calibration_date, product_code, model_id);
			} else {
				err("Invalid message");
				goto OUT;
			}
		}

		co = tcore_pending_ref_core_object(pending);
		priv_data = tcore_object_ref_user_data(co);

		/*
		 * Update response structure and Cache data
		 */
		priv_data->version_valid = TRUE;

		/* Software version */
		if (software_version) {
			snprintf(modem_get_version_resp.software,
				33,  "%s", software_version);
			snprintf(priv_data->software,
				33,  "%s", software_version);
		}

		/* Hardware version */
		if (hardware_version) {
			snprintf(modem_get_version_resp.hardware,
				33,  "%s", hardware_version);
			snprintf(priv_data->hardware,
				33,  "%s", hardware_version);
		}

		/* Calibration date */
		if (calibration_date) {
			snprintf(modem_get_version_resp.calibration,
				33,  "%s", calibration_date);
			snprintf(priv_data->calibration,
				33,  "%s", calibration_date);
		}

		/* Product code */
		if (product_code) {
			snprintf(modem_get_version_resp.product_code,
				33,  "%s", product_code);
			snprintf(priv_data->product_code,
				33,  "%s", product_code);
		}
	} else {
		dbg("RESPONSE NOK");
		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
		}

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");

			modem_get_version_resp.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			int response = atoi(g_slist_nth_data(tokens, 0));
			err("error response: %d", response);

			/* TODO: CMEE error mapping is required. */
			modem_get_version_resp.result = TCORE_RETURN_3GPP_ERROR;
		}
	}

	/* Send Response */
	ur = tcore_pending_ref_user_request(pending);
	tcore_user_request_send_response(ur,
		TRESP_MODEM_GET_VERSION,
		sizeof(struct tresp_modem_get_version), &modem_get_version_resp);

OUT:
	tcore_at_tok_free(tokens);
}

static enum tcore_hook_return on_hook_modem_sim_init_status(Server *s,
	CoreObject *source, enum tcore_notification_command command,
	unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_sim_status *noti_sim_status;

	dbg("SIM INIT Status");

	noti_sim_status = data;
	if (noti_sim_status == NULL) {
		err("SIM notification data is NULL");
		return TCORE_HOOK_RETURN_CONTINUE;
	}

	/* If SIM is initialized, Enable STK and and attach to Network */
	dbg("SIM Status: [%d]", noti_sim_status->sim_status);
	if (noti_sim_status->sim_status == SIM_STATUS_INIT_COMPLETED) {
		TcorePlugin *plugin;
		CoreObject *co_network;
		CoreObject *co_sat;

		dbg("SIM ready for attach!!! Enable STK and attach to Network");

		plugin = tcore_object_ref_plugin(source);

		co_network = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_NETWORK);
		if (co_network) {
			/* Sending AT+COPS */
			tcore_prepare_and_send_at_request(co_network,
				"AT+COPS=0", NULL,
				TCORE_AT_NO_RESULT, NULL,
				on_response_network_registration, NULL,
				NULL, NULL, 0, NULL, NULL);
		}

		co_sat = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SAT);
		if (co_sat) {
			/* Sending AT+CFUN=6 */
			tcore_prepare_and_send_at_request(co_sat,
				"AT+CFUN=6", NULL,
				TCORE_AT_NO_RESULT, NULL,
				on_response_enable_proactive_command, NULL,
				NULL, NULL, 0, NULL, NULL);
		}

	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

gboolean modem_power_on(TcorePlugin *plugin)
{
	Server *server;
	CoreObject *co_modem = NULL;
	struct treq_modem_set_flightmode flight_mode_set;
	struct tnoti_modem_power modem_power;
	Storage *strg = NULL;

	co_modem = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
	if (co_modem == NULL) {
		err("Modem Core object is NULL");
		return FALSE;
	}

	/* Set Modem Power State to 'ON' */
	tcore_modem_set_powered(co_modem, TRUE);

	server = tcore_plugin_ref_server(plugin);

	/* Get Flight mode from VCONFKEY */
	strg = tcore_server_find_storage(server, "vconf");
	flight_mode_set.enable = tcore_storage_get_bool(strg, STORAGE_KEY_FLIGHT_MODE_BOOL);

	/*
	 * Set Flight mode as per AP settings
	 */
	if (flight_mode_set.enable) {		/* Radio OFF */
		dbg("Enabling Flight mode");

		tcore_prepare_and_send_at_request(co_modem,
			"AT+CFUN=4", NULL,
			TCORE_AT_NO_RESULT, NULL,
			on_response_modem_set_flight_mode, NULL,
			NULL, NULL, 0, NULL, NULL);

		/* Set Flight mode TRUE */
		tcore_modem_set_flight_mode_state(co_modem, TRUE);
	} else {				/* Radio ON */
		dbg("Disabling Flight mode");

		tcore_prepare_and_send_at_request(co_modem,
			"AT+CFUN=1", NULL,
			TCORE_AT_NO_RESULT, NULL,
			on_response_modem_set_flight_mode, NULL,
			NULL, NULL, 0, NULL, NULL);

		/* Set Flight mode FALSE */
		tcore_modem_set_flight_mode_state(co_modem, FALSE);
	}

	/* Get IMEI */
	tcore_prepare_and_send_at_request(co_modem,
		"AT+CGSN", NULL,
		TCORE_AT_NUMERIC, NULL,
		on_response_modem_get_imei, NULL,
		NULL, NULL, 0, NULL, NULL);

	/* Get Version Number  */
	tcore_prepare_and_send_at_request(co_modem,
		"AT+CGMR", NULL,
		TCORE_AT_SINGLELINE, NULL,
		on_response_modem_get_version, NULL,
		NULL, NULL, 0, NULL, NULL);

	/* Send Notification - MODEM_POWER */
	modem_power.state = MODEM_STATE_ONLINE;

	dbg("Sending notification - Modem Power state: [ONLINE]");
	tcore_server_send_notification(server, co_modem,
		TNOTI_MODEM_POWER,
		sizeof(modem_power), &modem_power);

	return TRUE;
}

static TReturn modem_power_off(CoreObject *co_modem, UserRequest *ur)
{
	TcoreHal *hal;

	hal = tcore_object_get_hal(co_modem);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		struct tresp_modem_power_off modem_power_off_resp;

		err("Modem is in Powered OFF state!");

		modem_power_off_resp.result = TCORE_RETURN_SUCCESS;

		tcore_user_request_send_response(ur,
			TRESP_MODEM_POWER_OFF,
			sizeof(struct tresp_modem_power_off), &modem_power_off_resp);

		return TCORE_RETURN_SUCCESS;
	}

	dbg("[Request] Modem Power OFF - Command: [%s]", "AT+CFUN=0");

	return tcore_prepare_and_send_at_request(co_modem,
		"AT+CFUN=0", NULL,
		TCORE_AT_NO_RESULT, ur,
		on_response_modem_power_off, hal,
		on_confirmation_modem_message_send, NULL,
		0, NULL, NULL);
}

static TReturn modem_get_imei(CoreObject *co_modem, UserRequest *ur)
{
	PrivateData *priv_data = NULL;
	TcoreHal *hal;

	dbg("Exit");

	hal = tcore_object_get_hal(co_modem);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP not ready!");
		return TCORE_RETURN_ENOSYS;
	}

	/*
	 * Check if valid IMEI is available in Cache -
	 *	if Yes, then provide form Cache;
	 *	else, fetch from CP
	 */
	priv_data = tcore_object_ref_user_data(co_modem);
	if (priv_data && priv_data->imei_valid) {
		struct tresp_modem_get_imei modem_get_imei_resp;
		TReturn ret;

		memset(&modem_get_imei_resp, 0x0, sizeof(struct tresp_modem_get_imei));

		modem_get_imei_resp.result = TCORE_RETURN_SUCCESS;
		memcpy(modem_get_imei_resp.imei,
			priv_data->imei, MODEM_DEVICE_IMEI_LEN_MAX);

		dbg("Valid IMEI information present in cache - IMEI: [%s]",
			modem_get_imei_resp.imei);

		/* Send Response */
		ret = tcore_user_request_send_response(ur,
			TRESP_MODEM_GET_IMEI,
			sizeof(struct tresp_modem_get_imei), &modem_get_imei_resp);
		if (ret == TCORE_RETURN_SUCCESS)
			tcore_user_request_unref(ur);

		return ret;
	}

	dbg("[Request] Get IMEI - Command: [%s]", "AT+CGSN");

	return tcore_prepare_and_send_at_request(co_modem,
		"AT+CGSN", NULL,
		TCORE_AT_NUMERIC, ur,
		on_response_modem_get_imei, hal,
		on_confirmation_modem_message_send, NULL,
		0, NULL, NULL);
}


static TReturn modem_get_version(CoreObject *co_modem, UserRequest *ur)
{
	PrivateData *priv_data = NULL;
	TcoreHal *hal;

	hal = tcore_object_get_hal(co_modem);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP not ready!");
		return TCORE_RETURN_ENOSYS;
	}

	/*
	 * Check if valid Version information is available in Cache -
	 *	if Yes, then provide form Cache;
	 *	else, fetch from CP
	 */
	priv_data = tcore_object_ref_user_data(co_modem);
	if (priv_data && priv_data->version_valid) {
		struct tresp_modem_get_version modem_get_version_resp;
		TReturn ret;

		memset(&modem_get_version_resp, 0x0, sizeof(struct tresp_modem_get_version));

		modem_get_version_resp.result = TCORE_RETURN_SUCCESS;
		snprintf(modem_get_version_resp.software,
			33, "%s", priv_data->software);
		snprintf(modem_get_version_resp.hardware,
			33, "%s", priv_data->hardware);
		snprintf(modem_get_version_resp.calibration,
			33, "%s", priv_data->calibration);
		snprintf(modem_get_version_resp.product_code,
			33, "%s", priv_data->product_code);

		dbg("Valid Version information present in cache -" \
			"Software: [%s] Hardware: [%s] Calibration: [%s] Product code: [%s]",
			modem_get_version_resp.software, modem_get_version_resp.hardware,
			modem_get_version_resp.calibration, modem_get_version_resp.product_code);

		/* Send Response */
		ret = tcore_user_request_send_response(ur,
			TRESP_MODEM_GET_VERSION,
			sizeof(struct tresp_modem_get_version), &modem_get_version_resp);
		if (ret == TCORE_RETURN_SUCCESS)
			tcore_user_request_unref(ur);

		return ret;
	}

	dbg("[Request] Get VERSION - Command: [%s]", "AT+CGMR");

	return tcore_prepare_and_send_at_request(co_modem,
		"AT+CGMR", NULL,
		TCORE_AT_SINGLELINE, ur,
		on_response_modem_get_version, hal,
		on_confirmation_modem_message_send, NULL,
		0, NULL, NULL);
}

static TReturn modem_set_flight_mode(CoreObject *co_modem, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	const struct treq_modem_set_flightmode *req_data = NULL;
	char *cmd_str = NULL;

	hal = tcore_object_get_hal(co_modem);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP not ready!");
		return TCORE_RETURN_ENOSYS;
	}

	req_data = tcore_user_request_ref_data(ur, NULL);
	if (req_data->enable)
		cmd_str = "AT+CFUN=4";
	else
		cmd_str = "AT+CFUN=1";

	dbg("[Request] Set Modem Flight mode [%s] - Command: [%s]",
		(req_data->enable ? "ON" : "OFF"), cmd_str);

	return tcore_prepare_and_send_at_request(co_modem,
		(const char *)cmd_str, NULL,
		TCORE_AT_NO_RESULT, ur,
		on_response_modem_set_flight_mode, hal,
		on_confirmation_modem_message_send, NULL,
		0, NULL, NULL);
}

static TReturn modem_get_flight_mode(CoreObject *co_modem, UserRequest *ur)
{
	struct tresp_modem_get_flightmode modem_get_flightmode_resp;
	TReturn ret;

	dbg("[Request] Get Modem Flight mode");

	memset(&modem_get_flightmode_resp, 0x0, sizeof(struct tresp_modem_get_flightmode));

	modem_get_flightmode_resp.result = TCORE_RETURN_SUCCESS;
	modem_get_flightmode_resp.enable = tcore_modem_get_flight_mode_state(co_modem);
	dbg("Flight mode: [%s]", (modem_get_flightmode_resp.enable ? "ON" : "OFF"));

	ret = tcore_user_request_send_response(ur,
		TRESP_MODEM_GET_FLIGHTMODE,
		sizeof(struct tresp_modem_get_flightmode), &modem_get_flightmode_resp);
	if (ret == TCORE_RETURN_SUCCESS)
		tcore_user_request_unref(ur);

	return ret;
}

/* Modem operations */
static struct tcore_modem_operations modem_ops = {
	.power_on = NULL,
	.power_off = modem_power_off,
	.power_reset = NULL,
	.set_flight_mode = modem_set_flight_mode,
	.get_flight_mode = modem_get_flight_mode,
	.get_imei = modem_get_imei,
	.get_version = modem_get_version,
	.get_sn = NULL,
	.dun_pin_ctrl = NULL,
};

gboolean imc_modem_init(TcorePlugin *plugin, CoreObject *co_modem)
{
	PrivateData *priv_data = NULL;

	dbg("Enter");

	/* Set operations */
	tcore_modem_set_ops(co_modem, &modem_ops, TCORE_OPS_TYPE_CP);

	/* Private data */
	priv_data = g_malloc0(sizeof(PrivateData));
	priv_data->imei_valid = FALSE;
	priv_data->version_valid = FALSE;
	tcore_object_link_user_data(co_modem, priv_data);

	/* Notification hooks */
	tcore_server_add_notification_hook(tcore_plugin_ref_server(plugin),
		TNOTI_SIM_STATUS, on_hook_modem_sim_init_status, NULL);

	dbg("Registering for +XDRVI event");
	tcore_object_add_callback(co_modem,
		"+XDRVI", on_event_modem_nvm_update, NULL);

	dbg("Exit");
	return TRUE;
}

void imc_modem_exit(TcorePlugin *plugin, CoreObject *co_modem)
{
	PrivateData *priv_data = NULL;

	dbg("Exit");

	priv_data = tcore_object_ref_user_data(co_modem);
	g_free(priv_data);
}

/*
 * NV Manager - Support for Remote File System
 */
/* NVM Hook */
static gboolean __modem_rfs_hook(const char *data)
{
	if (data && data[NVM_FUNCTION_ID_OFFSET] == XDRV_INDICATION)
		return TRUE;

	return FALSE;
}

/* NVM event Notification */
static gboolean on_event_modem_nvm_update(CoreObject *co_modem,
	const void *event_info, void *user_data)
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
			modem_send_nvm_update_ack(co_modem);

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
		} else if (IUFP_GROUP_ID != atoi(g_slist_nth_data(tokens, 0))) {
			err("Group ID mismatch, Ignore!!!");
			ret = FALSE;
		} else {
			int command = atoi(g_slist_nth_data(tokens, 1));
			switch (command) {
			case IUFP_UPDATE_REQ:
				dbg("NV Update Request");

				/* Acknowledge the Update Request */
				modem_send_nvm_update_request_ack(co_modem);
			break;

			case IUFP_NO_PENDING_UPDATE:
				dbg("NO pending NV Update(s)!!!");
				/* Can send FLUSH request to get fresh updates */
			break;

			default:
				err("Unspported Function ID [%d], Ignore", command);
				ret = FALSE;
			break;
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
	const TcoreATResponse *at_resp = data;
	const char *line;
	char *resp_str;
	GSList *tokens = NULL;
	gboolean ret = FALSE;
	dbg("Entered");

	/* +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>] */
	if (NULL == at_resp) {
		err("Input data is NULL");
		return FALSE;
	}

	if (at_resp->success <= 0) {
		dbg("Response NOK");
		return FALSE;
	}

	dbg("RESPONSE OK");
	line = (const char *) (((GSList *) at_resp->lines)->data);
	tokens = tcore_at_tok_new(line);

	/* Group ID */
	resp_str = g_slist_nth_data(tokens, 0);
	if (NULL == resp_str) {
		err("Group ID is missing ");
		goto OUT;
	} else if (IUFP_GROUP_ID != atoi(resp_str)) {
		err("Group ID mismatch");
		goto OUT;
	}

	/* Function ID */
	resp_str =  g_slist_nth_data(tokens, 1);
	if (NULL == resp_str) {
		err("Function ID is missing ");
		goto OUT;
	} else if (command != atoi(resp_str)) {
		err("Function ID mismatch");
		goto OUT;
	}

	/* XDRV Result */
	resp_str =  g_slist_nth_data(tokens, 2);
	if (NULL == resp_str) {
		err("XDRV result is missing ");
		goto OUT;
	} else if (XDRV_RESULT_OK != atoi(resp_str)) {
		err("XDRV result[%d] ", atoi(resp_str));
		goto OUT;
	}

	/* Result code */
	resp_str =  g_slist_nth_data(tokens, 3);
	if (NULL == resp_str) {
		err("UTA result is missing ");
		goto OUT;
	} else if (UTA_SUCCESS != atoi(resp_str)) {
		err("uta result[%d] ", atoi(resp_str));
		goto OUT;
	}

	ret = TRUE;

OUT:
	tcore_at_tok_free(tokens);

	dbg("Exit");
	return ret;
}

static void on_response_modem_unsuspend_nvm_updates(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __modem_check_nvm_response(data, IUFP_SUSPEND)) {
		dbg("Priority level is set to get all updates since Boot-up");

		/* Create NV data file */
		if (nvm_create_nvm_data() == FALSE)
			err("Failed to Create NV data file");

		return;
	}

	err("Response NOT OK");
}

static void on_response_modem_send_nvm_update_ack(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE ==  __modem_check_nvm_response(data, IUFP_UPDATE_ACK)) {
		dbg("[UPDATE ACK] OK");
		return;
	}

	err("[UPDATE ACK] NOT OK");
}

static void on_response_modem_send_nvm_update_request_ack(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __modem_check_nvm_response(data, IUFP_UPDATE_REQ_ACK)) {
		dbg("[REQUEST ACK] OK");
		return;
	}

	err("[REQUEST ACK] NOT OK");
}

static void on_response_modem_register_nvm(TcorePending *pending,
	int data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __modem_check_nvm_response(data, IUFP_REGISTER)) {
		dbg("Registering successful!");

		/* Send SUSPEND_UPDATE for all UPDATES */
		modem_unsuspend_nvm_updates(tcore_pending_ref_core_object(pending));

		dbg("Exit");
		return;
	}

	err("Response NOT OK");
}

/* NVM Requests */
static void modem_unsuspend_nvm_updates(CoreObject *co_modem)
{
	char *cmd_str;
	TReturn ret;

	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%d, %d, %d, %d",
		IUFP_GROUP_ID, IUFP_SUSPEND,
		0, UTA_FLASH_PLUGIN_PRIO_UNSUSPEND_ALL);

	/* Prepare pending request */
	ret = tcore_prepare_and_send_at_request(co_modem,
		cmd_str, "+XDRV:",
		TCORE_AT_SINGLELINE, NULL,
		on_response_modem_unsuspend_nvm_updates, NULL,
		NULL, NULL, 0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS)
		err("IUFP_SUSPEND - Unable to send AT-Command");
	else
		dbg("IUFP_SUSPEND - Successfully sent AT-Command");

	g_free(cmd_str);
}

static void modem_send_nvm_update_ack(CoreObject *co_modem)
{
	char *cmd_str;
	TReturn ret;

	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s", IUFP_GROUP, IUFP_UPDATE_ACK_STR);

	/* Prepare pending request */
	ret = tcore_prepare_and_send_at_request(co_modem,
		cmd_str, "+XDRV:",
		TCORE_AT_SINGLELINE, NULL,
		on_response_modem_send_nvm_update_ack, NULL,
		NULL, NULL, 0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS)
		err("IUFP_UPDATE_ACK - Unable to send AT-Command");
	else
		dbg("IUFP_UPDATE_ACK - Successfully sent AT-Command");

	g_free(cmd_str);
}

static void modem_send_nvm_update_request_ack(CoreObject *co_modem)
{
	char *cmd_str;
	TReturn ret;

	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s", IUFP_GROUP, IUFP_UPDATE_REQ_ACK_STR);

	/* Prepare pending request */
	ret = tcore_prepare_and_send_at_request(co_modem,
		cmd_str, "+XDRV:",
		TCORE_AT_SINGLELINE, NULL,
		on_response_modem_send_nvm_update_request_ack, NULL,
		NULL, NULL, 0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS)
		err("IUFP_UPDATE_REQ_ACK - Unable to send AT-Ccommand");
	else
		dbg("IUFP_UPDATE_REQ_ACK - Successfully sent AT-Command");

	g_free(cmd_str);
}

void modem_register_nvm(CoreObject *co_modem)
{
	char *cmd_str;
	TReturn ret;

	dbg("Entered");

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s, %s",
		IUFP_GROUP, IUFP_REGISTER_STR, XDRV_ENABLE);

	/* Prepare pending request */
	ret = tcore_prepare_and_send_at_request(co_modem,
		cmd_str, "+XDRV:",
		TCORE_AT_SINGLELINE, NULL,
		on_response_modem_register_nvm, NULL,
		NULL, NULL, 0, NULL, NULL);
	if (ret != TCORE_RETURN_SUCCESS) {
		err("IUFP_REGISTER (Enable) -Unable to send AT-Command");
	} else {
		dbg("IUFP_REGISTER (Enable) -Successfully sent AT-Command");

		/* Add RFS hook */
		/* Todo unblock this api */
		tcore_at_add_hook(tcore_object_get_hal(co_modem),
			__modem_rfs_hook);
	}

	g_free(cmd_str);
}
