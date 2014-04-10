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

#include <co_modem.h>

#include "imc_modem.h"
#include "imc_common.h"
#include "nvm/nvm.h"

static gboolean on_event_imc_nvm_update(CoreObject *co,
	const void *event_info, void *user_data);

/* NVM Req/Response */
static gboolean __imc_modem_check_nvm_response(const void *data, int command)
{
	const TcoreAtResponse *at_resp = data;
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

	if (at_resp->success > 0) {
		dbg("RESPONSE OK");
		line = (const char *) (((GSList *) at_resp->lines)->data);
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

static void __on_response_modem_unsuspend_nvm_updates(TcorePending *p,
							guint data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __imc_modem_check_nvm_response(data, IUFP_SUSPEND)) {
		dbg("Priority level is set to get all updates since Boot-up");

		/* Create NV data file */
		if (nvm_create_nvm_data() == FALSE) {
			err("Failed to Create NV data file");
		}

		return;
	}

	err("Response NOT OK");
}

static void __imc_modem_unsuspend_nvm_updates(CoreObject *co)
{
	char *cmd_str;
	TelReturn ret;

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%d, %d, %d, %d",
					IUFP_GROUP_ID, IUFP_SUSPEND,
					0, UTA_FLASH_PLUGIN_PRIO_UNSUSPEND_ALL);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+XDRV:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_modem_unsuspend_nvm_updates, NULL,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, NULL, "Unsuspend Nvm Updates");

	g_free(cmd_str);
}

static void __on_response_modem_send_nvm_update_ack(TcorePending *p,
							guint data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE ==  __imc_modem_check_nvm_response(data, IUFP_UPDATE_ACK)) {
		dbg("[UPDATE ACK] OK");
		return;
	}

	err("[UPDATE ACK] NOT OK");
}

static void __imc_modem_send_nvm_update_ack(CoreObject *co)
{
	char *cmd_str;
	TelReturn ret;

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s", IUFP_GROUP, IUFP_UPDATE_ACK_STR);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+XDRV:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_modem_send_nvm_update_ack, NULL,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, NULL, "Nvm Update Ack");

	g_free(cmd_str);
}

static void __on_response_modem_send_nvm_update_request_ack(TcorePending *p,
							guint data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __imc_modem_check_nvm_response(data, IUFP_UPDATE_REQ_ACK)) {
		dbg("[REQUEST ACK] OK");
		return;
	}

	err("[REQUEST ACK] NOT OK");
}

static void __imc_modem_send_nvm_update_request_ack(CoreObject *co)
{
	char *cmd_str;
	TelReturn ret;

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s", IUFP_GROUP, IUFP_UPDATE_REQ_ACK_STR);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+XDRV:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_modem_send_nvm_update_request_ack, NULL,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, NULL, "Nvm Update Request Ack");

	g_free(cmd_str);
}

static void __on_response_modem_register_nvm(TcorePending *p,
						guint data_len, const void *data, void *user_data)
{
	/* Check NVM response */
	if (TRUE == __imc_modem_check_nvm_response(data, IUFP_REGISTER)) {
		dbg("Registering successful");

		/* Send SUSPEND_UPDATE for all UPDATES */
		__imc_modem_unsuspend_nvm_updates(tcore_pending_ref_core_object(p));

		dbg("Exit");
		return;
	}

	err("Response NOT OK");
}

/* System function responses */
static void on_response_modem_set_flight_mode_internal(TcorePlugin *plugin,
	gint result, const void *response, void *user_data)
{
	CoreObject *co;
	gboolean flight_mode;
	dbg("Enter");

	co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
	tcore_check_return_assert(co != NULL);

	tcore_check_return(result == TEL_MODEM_RESULT_SUCCESS);

	/* Get Flight mode state */
	(void)tcore_modem_get_flight_mode_state(co, &flight_mode);

	dbg("Setting Modem Fiight mode (internal) - [%s] - [SUCCESS]",
		(flight_mode ? "ON": "OFF"));

	/*
	 * Send notification
	 *
	 * This is an internal request to set Flight mode, which is sent during
	 * boot-up based on AP-side configuration (VCONF).
	 *
	 * Need to notify TAPI through Notiifcation -
	 *	TCORE_NOTIFICATION_MODEM_FLIGHT_MODE
	 */
	(void)tcore_object_send_notification(co,
		TCORE_NOTIFICATION_MODEM_FLIGHT_MODE,
		sizeof(gboolean), &flight_mode);
}

/* System functions */
gboolean imc_modem_power_on_modem(TcorePlugin *plugin)
{
	CoreObject *co;
	TcoreStorage *strg;
	gboolean flight_mode;
	TelModemPowerStatus power_status;

	co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
	tcore_check_return_value_assert(co != NULL, FALSE);

	/* Set Modem Power State to 'ON' */
	tcore_modem_set_powered(co, TRUE);

	/*
	 * Set Flight mode (as per AP settings -VCONF)
	 */
	/* Get Flight mode from VCONFKEY */
	strg = tcore_server_find_storage(tcore_plugin_ref_server(plugin), "vconf");
	tcore_check_return_value_assert(strg != NULL, FALSE);

	flight_mode = tcore_storage_get_bool(strg, STORAGE_KEY_FLIGHT_MODE);

	/*
	 * Set Flight mode request is dispatched to Core Object (Modem)
	 * to ensure that 'Request Hooks' get executed.
	 */
	(void)tcore_object_dispatch_request(co, TRUE,
		TCORE_COMMAND_MODEM_SET_FLIGHTMODE,
		&flight_mode, sizeof(gboolean),
		on_response_modem_set_flight_mode_internal, NULL);

	/*
	 * Send notification
	 *
	 * Need to notify Modem is Powered UP through Notiifcation -
	 *	TCORE_NOTIFICATION_MODEM_POWER
	 */
	power_status = TEL_MODEM_POWER_ON;
	(void)tcore_object_send_notification(co,
		TCORE_NOTIFICATION_MODEM_POWER,
		sizeof(TelModemPowerStatus), &power_status);

	return TRUE;
}

/* Modem Responses */
static void on_response_imc_modem_set_power_status(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelModemPowerStatus *status;
	gboolean powered = FALSE;

	TelModemResult result = TEL_MODEM_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_MODEM_RESULT_SUCCESS;

	status = (TelModemPowerStatus *)
		IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	/* Update Core Object */
	switch (*status) {
	case TEL_MODEM_POWER_ON:
		dbg("Setting Modem Power status [ON] - [%s]",
			(result == TEL_MODEM_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
		powered = TRUE;
	break;
	case TEL_MODEM_POWER_OFF:
		dbg("Setting Modem Power status [OFF] - [%s]",
			(result == TEL_MODEM_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
		powered = FALSE;
	break;
	default:
		warn("Unexpected - Setting Modem Power status [RESET] - [%s]",
			(result == TEL_MODEM_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
	break;
	}
	tcore_modem_set_powered(co, powered);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_modem_set_flight_mode(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	gboolean *enable;

	TelModemResult result = TEL_MODEM_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success)
		result = TEL_MODEM_RESULT_SUCCESS;

	enable = (gboolean *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Setting Modem Fiight mode - [%s] - [%s]",
		(*enable ? "ON": "OFF"),
		(result == TEL_MODEM_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Update Core Object */
	(void)tcore_modem_set_flight_mode_state(co, *enable);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);

	/*
	 * In case Flight mode is set to OFF, we need to trigger
	 * Network Registration.
	 *
	 * This is taken care by Network module which hooks on
	 * Set Flight mode Request of Modem module.
	 */
}

/* Current modem does not support this operation */
#if 0
static void on_response_imc_modem_get_version(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelModemVersion version = {{0}, {0}, {0}, {0}};

	TelModemResult result = TEL_MODEM_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) > 0) {
				if (at_resp->success) {
					gchar *sw_ver = NULL, *hw_ver = NULL;
					gchar *calib_date = NULL, *p_code = NULL;

					sw_ver = g_slist_nth_data(tokens, 0);
					hw_ver = g_slist_nth_data(tokens, 1);
					calib_date = g_slist_nth_data(tokens, 2);
					p_code = g_slist_nth_data(tokens, 3);
					if (sw_ver != NULL){
						g_strlcpy(version.software_version,
							sw_ver,
							TEL_MODEM_VERSION_LENGTH_MAX + 1);
					}
					if (hw_ver != NULL){
						g_strlcpy(version.hardware_version,
							hw_ver,
							TEL_MODEM_VERSION_LENGTH_MAX + 1);
					}
					if (calib_date != NULL){
						g_strlcpy(version.calibration_date,
							calib_date,
							TEL_MODEM_VERSION_LENGTH_MAX + 1);
					}
					if (p_code != NULL){
						g_strlcpy(version.product_code,
							p_code,
							TEL_MODEM_VERSION_LENGTH_MAX + 1);
					}
					dbg("Version - Software: [%s] Hardware: [%s] "
						"Calibration date: [%s] Product "
						"Code: [%s]", sw_ver, hw_ver,
						calib_date, p_code);

					result = TEL_MODEM_RESULT_SUCCESS;
				} else {
					err("RESPONSE - [NOK]");
					err("[%s]", g_slist_nth_data(tokens, 0));
				}
			} else {
				err("Invalid response message");
				result = TEL_MODEM_RESULT_UNKNOWN_FAILURE;
			}
			tcore_at_tok_free(tokens);
		}
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &version, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}
#endif

static void on_response_imc_modem_get_imei(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	gchar imei[TEL_MODEM_IMEI_LENGTH_MAX +1] = {0};

	TelModemResult result = TEL_MODEM_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens = NULL;

			line = (const gchar *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) == 1) {
				if (at_resp->success) {
					dbg("RESPONSE - [OK]");
					g_strlcpy(imei,
						(const gchar *)g_slist_nth_data(tokens, 0),
						TEL_MODEM_IMEI_LENGTH_MAX+1);
					dbg("IMEI: [%s]", imei);

					result = TEL_MODEM_RESULT_SUCCESS;
				} else {
					err("RESPONSE - [NOK]");
					err("[%s]", g_slist_nth_data(tokens, 0));
				}
			}  else {
				err("Invalid response message");
				result = TEL_MODEM_RESULT_UNKNOWN_FAILURE;
			}
			tcore_at_tok_free(tokens);
		}
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, imei, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

/* Modem Operations */
/*
 * Operation - set_power_status
 *
 * Request -
 * AT-Command: AT+CFUN=<fun>
 * where,
 * <fun>
 * 0	Mode to switch off MS
 * ...	Other modes are available for other oprations
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_modem_set_power_status(CoreObject *co,
	TelModemPowerStatus status,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	guint power_mode;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	if (status == TEL_MODEM_POWER_ON) {
		warn("Modem Power ON - Not supported by CP");
		return TEL_RETURN_OPERATION_NOT_SUPPORTED;
	} else if (status == TEL_MODEM_POWER_ERROR) {
		err("Modem Power ERROR - Invalid mode");
		return TEL_RETURN_INVALID_PARAMETER;
	} else {
		dbg("Modem Power OFF");
		power_mode = 0;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CFUN=%d", power_mode);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				&status, sizeof(TelModemPowerStatus));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_modem_set_power_status, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Power Status");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - set_flight_mode
 *
 * Request -
 * AT-Command: AT+CFUN=<fun>
 * where,
 * <fun>
 * 0	Mode to switch off MS
 * 1	Full functionality
 * 4	Mode to disable phone both transmit and receive
 *	RF circuits. Airplane mode.
 * ...	Other modes are available for other oprations
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_modem_set_flight_mode(CoreObject *co, gboolean enable,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	guint power_mode;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	if (enable) {
		dbg("Flight mode - [ON]");
		power_mode = 4;
	} else {
		dbg("Flight mode - [OFF]");
		power_mode = 1;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CFUN=%d", power_mode);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				&enable, sizeof(gboolean));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_modem_set_flight_mode, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Flight mode");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get_flight_mode
 *
 * Request -
 * AT-Command: None
 *	Fetch information from Core Object
 *
 * Response - flight_mode (gboolean)
 */
static TelReturn imc_modem_get_flight_mode(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gboolean flight_mode;

	/* Fetch Flight mode from Core Object */
	(void)tcore_modem_get_flight_mode_state(co, &flight_mode);
	dbg("Modem Flight mode - [%s]", (flight_mode ? "ON": "OFF"));

	/* Invoke response callback */
	if (cb)
		cb(co, (gint)TEL_MODEM_RESULT_SUCCESS, &flight_mode, cb_data);

	return TEL_RETURN_SUCCESS;
}

/*
 * Operation - get_version
 *
 * Request -
 * AT-Command: AT+CGMR
 *
 * Response - version (TelModemVersion)
 * Success: (Single line) -
 *	<sw_ver>, <hw_ver>, <calib_date>, <p_code>
 *	OK
 * Note:
 *	Success Response is different from standard 3GPP AT-Command (+CGMR)
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_modem_get_version(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	dbg("entry");

	/* Current modem does not support this operation */
#if 0
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CGMR", NULL,
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_modem_get_version, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Version");

	return ret;
#endif

	dbg("exit");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

/*
 * Operation - get_imei
 *
 * Request -
 * AT-Command: AT+CGSN
 *
 * Response - imei (gchar array of length 20+'\0' bytes)
 * Success: (Single line)
 *	<IMEI>
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_modem_get_imei(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	dbg("Enter");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CGSN", NULL,
		TCORE_AT_COMMAND_TYPE_NUMERIC,
		NULL,
		on_response_imc_modem_get_imei, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get IMEI");

	return ret;
}

/* Modem Operations */
static TcoreModemOps imc_modem_ops = {
	.set_power_status = imc_modem_set_power_status,
	.set_flight_mode = imc_modem_set_flight_mode,
	.get_flight_mode = imc_modem_get_flight_mode,
	.get_version = imc_modem_get_version,
	.get_imei = imc_modem_get_imei
};

gboolean imc_modem_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Enter");

	/* Set operations */
	tcore_modem_set_ops(co, &imc_modem_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co, "+XDRVI:", on_event_imc_nvm_update, NULL);

	dbg("Exit");
	return TRUE;
}

void imc_modem_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}

/*
 * NV Manager - Support for Remote File System
 */
/* NVM Hook */
static gboolean __imc_nvm_modem_rfs_hook(const char *data)
{
	if (data != NULL)
		if (data[NVM_FUNCTION_ID_OFFSET] == XDRV_INDICATION)
			return TRUE;

	return FALSE;
}

/* NVM Event */
gboolean on_event_imc_nvm_update(CoreObject *co,
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
			__imc_modem_send_nvm_update_ack(co);

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
					__imc_modem_send_nvm_update_request_ack(co);
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

/* NVM Register */
void imc_modem_register_nvm(CoreObject *co)
{
	char *cmd_str;
	TelReturn ret;

	/* Prepare AT-Command */
	cmd_str = g_strdup_printf("AT+XDRV=%s, %s, %s",
					IUFP_GROUP, IUFP_REGISTER_STR, XDRV_ENABLE);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		cmd_str, "+XDRV:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_modem_register_nvm, NULL,
		on_send_imc_request, NULL);
	if (ret != TEL_RETURN_SUCCESS) {
		err("Failed to process request - [Register NVM]");
	}
	else {
		/* Add RFS hook */
		dbg("Adding NVM hook");
		tcore_at_add_hook(tcore_object_get_hal(co), __imc_nvm_modem_rfs_hook);
	}

	g_free(cmd_str);
}
