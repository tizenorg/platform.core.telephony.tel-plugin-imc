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
#include <tzplatform_config.h>

#include <co_network.h>

#include "imc_network.h"
#include "imc_common.h"

#define IMC_NETWORK_BASE_16	16

typedef enum {
	IMC_NETWORK_SEARCH_STATE_NO_SEARCH,
	IMC_NETWORK_SEARCH_STATE_IN_PROGRESS,
	IMC_NETWORK_SEARCH_STATE_CANCELLED
} ImcNetworkSearchState;

typedef struct {
	ImcNetworkSearchState search_state;
} CustomData;

typedef struct {
	CoreObject *co;
	TelNetworkResult result;
} ImcNetworkCancelSearch;

static TelNetworkAct __imc_network_map_act(guint act)
{
	/*
	 * <ACT>
	 * 0	GSM
	 * 2	UTRAN
	 * 3	GSM w/EGPRS
	 * 4	UTRAN w/HSDPA
	 * 5	UTRAN w/HSUPA
	 * 6	UTRAN w/HSDPA and HSUPA
	 */
	switch (act) {
	case 0:
		return TEL_NETWORK_ACT_GSM;
	case 2:
		return TEL_NETWORK_ACT_UMTS;
	case 3:
		return TEL_NETWORK_ACT_EGPRS;
	case 4:
		return TEL_NETWORK_ACT_HSDPA;
	case 5:
		return TEL_NETWORK_ACT_HSUPA;
	case 6:
		return TEL_NETWORK_ACT_HSPA;
	default:
		return TEL_NETWORK_ACT_UNKNOWN;
	}
}

static TelNetworkRegStatus __imc_network_map_stat(guint stat)
{
	/*
	 * <stat>
	 * 0	Not registered, ME is not currently searching a
	 *	new operator to register to
	 * 1	Registered, home network
	 * 2	Not registered, but ME is currently searching a
	 *	new operator to register
	 * 3	Registration denied
	 * 4	Unknown
	 * 5	Registered, in roaming
	 */
	switch (stat) {
	case 0:
		return TEL_NETWORK_REG_STATUS_UNREGISTERED;
	case 1:
		return TEL_NETWORK_REG_STATUS_REGISTERED;
	case 2:
		return TEL_NETWORK_REG_STATUS_SEARCHING;
	case 3:
		return TEL_NETWORK_REG_STATUS_DENIED;
	case 4:
		return TEL_NETWORK_REG_STATUS_UNKNOWN;
	case 5:
		return TEL_NETWORK_REG_STATUS_ROAMING;
	default:
		return TEL_NETWORK_REG_STATUS_UNKNOWN;
	}
}

static void __on_response_imc_network_registration(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	dbg("Entry");

	if (at_resp && at_resp->success) {
		dbg("Network Registration - [OK]");
	} else {
		err("Network Registration - [NOK]");
	}
}

static void __imc_network_register_to_network(CoreObject *co)
{
	TelReturn ret;

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+COPS=0", NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		__on_response_imc_network_registration, NULL,
		on_send_imc_request, NULL);
	dbg("Sending Network Registration request: [%s]",
		(ret == TEL_RETURN_SUCCESS ? "SUCCESS" : "FAIL"));
}

static void __on_response_imc_network_fetch_nw_name_internal(CoreObject *co,
	gint result, const void *response, void *user_data)
{
	TelNetworkIdentityInfo *identity = (TelNetworkIdentityInfo *)response;

	/* Send notification if result is SUCCESS */
	if (result == TEL_NETWORK_RESULT_SUCCESS)
		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_NETWORK_IDENTITY,
			sizeof(TelNetworkIdentityInfo), identity);
}

static TcoreHookReturn __on_response_imc_hook_set_flight_mode(CoreObject *co,
	gint result, TcoreCommand command, const void *response, const void *user_data)
{

	tcore_check_return_value(result == TEL_MODEM_RESULT_SUCCESS,
		TCORE_HOOK_RETURN_CONTINUE);

	dbg("Flight mode 'disabled', register to Network");

	/*
	 * TODO - Check for selection_mode
	 *	Need to check if it is Manual or Automatic and based on
	 *	that need to initiate Network Registratin accordingly.
	 */
	__imc_network_register_to_network(co);

	return TCORE_HOOK_RETURN_CONTINUE;
}

static void __on_response_imc_network_fetch_nw_name(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelNetworkIdentityInfo identity = {0, };

	TelNetworkResult result = TEL_NETWORK_RESULT_FAILURE;

	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens = NULL;
			gchar *token_str;
			guint i, nol;

			/* Validate that only 3 lines of response is received */
			nol = g_slist_length(at_resp->lines);
			if (nol > 3) {
				err("Invalid response message");
				return;
			}

			/* Process the Multi-line response */
			for (i = 0; i < nol; i++) {
				line = g_slist_nth_data(at_resp->lines, i);

				/*
				 * Tokenize
				 *
				 * +XCOPS: <type>[,<name>[,<display_condition>]]
				 */
				dbg("<line> : [%s]", line);
				tokens = tcore_at_tok_new(line);

				if ((token_str = tcore_at_tok_nth(tokens, 0))) {
					guint type = atoi(token_str);
					dbg("<type> : [%d]", type);

					switch (type) {
					case 0:	/* PLMN (mcc, mnc) */
						if ((token_str = tcore_at_tok_nth(tokens, 1))) {
							if (strlen(token_str) > 0) {
								identity.plmn = tcore_at_tok_extract((const char *)token_str);

								/* Update PLMN */
								tcore_network_set_plmn( co, identity.plmn);
							}
						}
					break;

					case 1:	/* Short Name in ROM (NV-RAM) */
					case 3:	/* Short Network Operator Name (CPHS) */
					case 5:	/* Short NITZ Name */
						if ((token_str = tcore_at_tok_nth(tokens, 1))) {
							if (strlen(token_str) > 0) {
								identity.short_name = tcore_at_tok_extract((const char *)token_str);


								/* Update Short name */
								tcore_network_set_short_name(co, identity.short_name);
							}
						}
					break;

					case 2:	/* Long Name in ROM (NV-RAM) */
					case 4:	/* Long Network Operator Name (CPHS) */
					case 6:	/* Full NITZ Name */
						if ((token_str = tcore_at_tok_nth(tokens, 1))) {
							if (strlen(token_str) > 0) {
								identity.long_name = tcore_at_tok_extract((const char *)token_str);

								/* Update Long name */
								tcore_network_set_long_name(co, identity.long_name);
							}
						}
					break;

					default:
					break;
					}
				}

				/* Free resource */
				tcore_at_tok_free(tokens);
			}

			/* Send Notification - Network identity */
			dbg("Network name - Long name: [%s] Short name: [%s] "
				"PLMN: [%s]", identity.long_name,
				identity.short_name, identity.plmn);

			result = TEL_NETWORK_RESULT_SUCCESS;
		}
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &identity, resp_cb_data->cb_data);

	/* Free resource */
	tcore_free(identity.long_name);
	tcore_free(identity.short_name);
	tcore_free(identity.plmn);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

/*
 * Operation - fetch_nw_name
 *
 * Request -
 * AT-Command: AT+XCOPS=<Type>
 *
 * <type> may be
 * 0	numeric format of network MCC/MNC (three BCD
 *	digit country code and two/three BCD digit network code)
 * 1	Short Name in ROM (NV-RAM)
 * 2	Long Name in ROM (NV-RAM)
 * 3	Short Network Operator Name (CPHS)
 * 4	Long Network Operator Name (CPHS)
 * 5	Short NITZ Name
 * 6	Full NITZ Name
 * 7	Service Provider Name
 * 8	EONS short operator name from EF-PNN
 * 9	EONS long operator name from EF-PNN
 * 11	Short PLMN name (When PS or CS is registered)
 * 12	Long PLMN name (When PS or CS is registered)
 * 13	numeric format of network MCC/MNC even in limited service
 *
 * Response - Network name
 * Success: (Multiple Single line)
 *	+XCOPS: <type>[,<name>[,<display_condition>]]
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn __imc_network_fetch_nw_name(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data = NULL;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XCOPS=0;+XCOPS=5;+XCOPS=6", "+XCOPS",
		TCORE_AT_COMMAND_TYPE_MULTILINE,
		NULL,
		__on_response_imc_network_fetch_nw_name, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Fetch Network name");

	return ret;
}

/* Hook functions */
static TcoreHookReturn on_hook_imc_set_flight_mode(CoreObject *co,
	TcoreCommand command, const void *request, const void *user_data,
	TcoreObjectResponseCallback cb, const void *cb_data)
{
	gboolean *flight_mode = (gboolean *)request;

	/*
	 * Hook Set Flight mode request.
	 *
	 * Disable Flight mode - Hook response (if success Register to Network)
	 * Enable Flight mode - return
	 */
	if (*flight_mode != TRUE) {
		/* Add response hook */
		tcore_object_add_response_hook(co, command, request,
			__on_response_imc_hook_set_flight_mode, NULL);

		return TCORE_HOOK_RETURN_CONTINUE;
	}

	dbg("Flight mode - [Enabled]");
	return TCORE_HOOK_RETURN_CONTINUE;
}

static TcoreHookReturn on_hook_imc_sim_status(TcorePlugin *plugin,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	const TelSimCardStatus *sim_status = (TelSimCardStatus *)data;

	tcore_check_return_value(sim_status != NULL,
		TCORE_HOOK_RETURN_CONTINUE);

	/*
	 * Hook SIM initialization Notification
	 *
	 * SIM INIT complete - Attach to network (Register to network)
	 * SIM INIT not complete - return
	 */
	if (*sim_status == TEL_SIM_STATUS_SIM_INIT_COMPLETED) {
		CoreObject *co = (CoreObject *)user_data;
		dbg("SIM Initialized!!! Attach to Network");

		tcore_check_return_value_assert(co != NULL,
			TCORE_HOOK_RETURN_CONTINUE);

		/*
		 * TODO - Check for selection_mode
		 *	Need to check if it is Manual or Automatic and based on
		 *	that need to initiate Network Registratin accordingly.
		 */
		__imc_network_register_to_network(co);

		return TCORE_HOOK_RETURN_CONTINUE;
	}

	dbg("SIM not yet initialized - SIM Status: [%d]", *sim_status);
	return TCORE_HOOK_RETURN_CONTINUE;
}

/* Notification callbacks */
/*
 * Notification: +CREG: <stat>[,<lac>,<ci>[,<AcT>]]
 *
 * Possible values of <stat> can be
 * 0	Not registered, ME is not currently searching
 *	a new operator to register to
 * 1	Registered, home network
 * 2	Not registered, but ME is currently searching
 *	a new operator to register
 * 3	Registration denied
 * 4	Unknown
 * 5	Registered, in roaming
 *
 * <lac>
 *	string type; two byte location area code in
 *	hexadecimal format (e.g. 00C3)
 *
 * <ci>
 *	string type; four byte cell ID in hexadecimal
 *	format (e.g. 0000A13F)
 *
 * <ACT>
 * 0	GSM
 * 2	UTRAN
 * 3	GSM w/EGPRS
 * 4	UTRAN w/HSDPA
 * 5	UTRAN w/HSUPA
 * 6	UTRAN w/HSDPA and HSUPA
 */
static gboolean on_notification_imc_cs_network_info(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *lines = NULL;
	gchar *line = NULL;

	dbg("Network notification - CS network info: [+CREG]");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("+CREG unsolicited message expected to be Single line "
			"but received multiple lines");
		return TRUE;
	}

	line = (gchar *) (lines->data);
	if (line != NULL) {
		TelNetworkRegStatusInfo registration_status = {0, };
		TelNetworkCellInfo cell_info = {0, };
		GSList *tokens = NULL;
		gchar *token_str;
		guint stat = 0, act = 0, lac = 0, ci = 0;
		gboolean roam_state = FALSE;

		/*
		 * Tokenize
		 *
		 * +CREG: <stat>[,<lac>,<ci>[,<AcT>]]
		 */
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("Invalid notification message");
			goto out;
		}

		/* <stat> */
		if ((token_str = g_slist_nth_data(tokens, 0)) == NULL) {
			err("No <stat> in +CREG");
			goto out;
		}
		stat = __imc_network_map_stat(atoi(token_str));
		(void)tcore_network_set_cs_reg_status(co, stat);

		/* <lac> */
		if ((token_str = g_slist_nth_data(tokens, 1))) {
			token_str = tcore_at_tok_extract((const gchar *)token_str);

			lac = (guint)strtol(token_str, NULL, IMC_NETWORK_BASE_16);

			/* Update Location Area Code (lac) information */
			(void)tcore_network_set_lac(co, lac);

			tcore_free(token_str);
		} else {
			dbg("No <lac> in +CREG");
			(void)tcore_network_get_lac(co, &lac);
		}

		/* <ci> */
		if ((token_str = g_slist_nth_data(tokens, 2))) {
			token_str = tcore_at_tok_extract((const gchar *)token_str);

			ci = (guint)strtol(token_str, NULL, IMC_NETWORK_BASE_16);

			/* Update Cell ID (ci) information */
			(void)tcore_network_set_cell_id(co, ci);

			tcore_free(token_str);
		} else {
			dbg("No <ci> in +CREG");
			(void)tcore_network_get_cell_id(co, &ci);
		}

		/* <AcT> */
		if ((token_str = g_slist_nth_data(tokens, 3))) {
			act = __imc_network_map_act(atoi(token_str));
			(void)tcore_network_set_access_technology(co, act);
		} else {
			dbg("No <AcT> in +CREG");
			(void)tcore_network_get_access_technology(co, &act);
		}
		dbg("<stat>: %d <lac>: 0x%x <ci>: 0x%x <AcT>: %d", stat, lac, ci, act);

		/* Send Notification - Network (CS) Registration status */
		registration_status.cs_status = stat;
		registration_status.act = act;
		(void)tcore_network_get_ps_reg_status(co, &registration_status.ps_status);

		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_NETWORK_REGISTRATION_STATUS,
			sizeof(TelNetworkRegStatusInfo), &registration_status);

		switch (stat) {
		case TEL_NETWORK_REG_STATUS_ROAMING:
			roam_state = TRUE; // no break
		case TEL_NETWORK_REG_STATUS_REGISTERED:
			/* Fetch Network name - Internal request */
			(void)__imc_network_fetch_nw_name(co,
				__on_response_imc_network_fetch_nw_name_internal, NULL);
		break;
		default:
		break;
		}

		/* Set Roaming state */
		tcore_network_set_roam_state(co, roam_state);

		/* Send Notification - Cell info */
		cell_info.lac = (gint)lac;
		cell_info.cell_id = (gint)ci;
		(void)tcore_network_get_rac(co, &cell_info.rac);

		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_NETWORK_LOCATION_CELLINFO,
			sizeof(TelNetworkCellInfo), &cell_info);

out:
		/* Free resource */
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

/*
 * Notification: +CGREG: <stat>[,<lac>,<ci>[,<AcT>,<rac>]]
 *
 * Possible values of <stat> can be
 * 0	Not registered, ME is not currently searching a
 *	new operator to register to
 * 1	Registered, home network
 * 2	Not registered, but ME is currently searching a
 *	new operator to register
 * 3	Registration denied
 * 4	Unknown
 * 5	Registered, in roaming
 *
 * <lac>
 *	string type; two byte location area code in
 *	hexadecimal format (e.g. 00C3)
 *
 * <ci>
 *	string type; four byte cell ID in hexadecimal
 *	format (e.g. 0000A13F)
 *
 * <ACT>
 * 0	GSM
 * 2	UTRAN
 * 3	GSM w/EGPRS
 * 4	UTRAN w/HSDPA
 * 5	UTRAN w/HSUPA
 * 6	UTRAN w/HSDPA and HSUPA
 *
 * <rac>:
 *	string type; one byte routing area code in hexadecimal format
 */
static gboolean on_notification_imc_ps_network_info(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *lines = NULL;
	gchar *line = NULL;

	dbg("Network notification - PS network info: [+CGREG]");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("+CGREG unsolicited message expected to be Single line "
			"but received multiple lines");
		return TRUE;
	}

	line = (gchar *) (lines->data);
	if (line != NULL) {
		TelNetworkRegStatusInfo registration_status = {0, };
		TelNetworkCellInfo cell_info = {0, };
		GSList *tokens = NULL;
		gchar *token_str;
		guint stat = 0, act = 0, lac = 0, ci = 0, rac = 0;
		gboolean roam_state = FALSE;

		/*
		 * Tokenize
		 *
		 * +CGREG: <stat>[,<lac>,<ci>[,<AcT>,<rac>]]
		 */
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("Invalid notification message");
			goto out;
		}

		/* <stat> */
		if ((token_str = g_slist_nth_data(tokens, 0)) == NULL) {
			err("No <stat> in +CGREG");
			goto out;
		}
		stat = __imc_network_map_stat(atoi(token_str));
		(void)tcore_network_set_ps_reg_status(co, stat);

		/* <lac> */
		if ((token_str = g_slist_nth_data(tokens, 1))) {
			token_str = tcore_at_tok_extract((const gchar *)token_str);

			lac = (guint)strtol(token_str, NULL, IMC_NETWORK_BASE_16);

			/* Update Location Area Code (lac) information */
			(void)tcore_network_set_lac(co, lac);

			tcore_free(token_str);
		} else {
			dbg("No <lac> in +CGREG");
			(void)tcore_network_get_lac(co, &lac);
		}

		/* <ci> */
		if ((token_str = g_slist_nth_data(tokens, 2))) {
			token_str = tcore_at_tok_extract((const gchar *)token_str);

			ci = (guint)strtol(token_str, NULL, IMC_NETWORK_BASE_16);

			/* Update Cell ID (ci) information */
			(void)tcore_network_set_cell_id(co, ci);

			tcore_free(token_str);
		} else {
			dbg("No <ci> in +CGREG");
			(void)tcore_network_get_cell_id(co, &ci);
		}

		/* <AcT> */
		if ((token_str = g_slist_nth_data(tokens, 3))) {
			act = __imc_network_map_act(atoi(token_str));
			(void)tcore_network_set_access_technology(co, act);
		} else {
			dbg("No <AcT> in +CGREG");
			(void)tcore_network_get_access_technology(co, &act);
		}

		/* <rac> */
		if ((token_str = g_slist_nth_data(tokens, 4))) {
			token_str = tcore_at_tok_extract((const gchar *)token_str);

			rac = (guint)strtol(token_str, NULL, IMC_NETWORK_BASE_16);

			/* Update Routing Area Code (rac) information */
			(void)tcore_network_set_rac(co, rac);

			tcore_free(token_str);
		} else {
			err("No <ci> in +CGREG");
			(void)tcore_network_get_rac(co, &rac);
		}
		dbg("<stat>: %d <lac>: 0x%x <ci>: 0x%x <AcT>: %d <rac>: 0x%x", stat, lac, ci, act, rac);

		/* Send Notification - Network (PS) Registration status */
		registration_status.ps_status = stat;
		registration_status.act = act;
		(void)tcore_network_get_cs_reg_status(co, &registration_status.cs_status);

		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_NETWORK_REGISTRATION_STATUS,
			sizeof(TelNetworkRegStatusInfo), &registration_status);

		/* Set Roaming state */
		if (registration_status.ps_status == TEL_NETWORK_REG_STATUS_ROAMING)
			roam_state = TRUE;

		tcore_network_set_roam_state(co, roam_state);

		/* Send Notification - Cell info */
		cell_info.lac = lac;
		cell_info.cell_id = ci;
		cell_info.rac = rac;
		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_NETWORK_LOCATION_CELLINFO,
			sizeof(TelNetworkCellInfo), &cell_info);

out:
		/* Free resource */
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

/*
 * Notification: +XNITZINFO: <fullname>,<shortname>,<LTZ>,<UT>,<DST>
 *
 * <longname>
 *	string type; Network name in long alphanumeric format.
 *
 * <shortname>
 *	string type; Network name in short alphanumeric format.
 *
 * <LTZ>
 *	Local Time Zone; represented as 1 unit = 15 minutes.
 *
 * <UT>
 *	string type value; Universal Time
 *	format is "yy/MM/dd,hh:mm:ss",
 *	wherein characters indicates year, month, day, hour,
 *	minutes, seconds.
 * <DST>
 *	Daylight Saving Time; represented in hours.
 */
static gboolean on_notification_imc_network_time_info(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *lines = NULL;
	gchar *line = NULL;

	dbg("Network notification - Time info: [+XNITZINFO]");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("+XNITZINFO unsolicited message expected to be Single line "
			"but received multiple lines");
		return TRUE;
	}

	line = (gchar *)lines->data;
	if (line != NULL) {
		GSList *tokens = NULL;
		TelNetworkNitzInfoNoti nitz_info = {0, };
		gchar *fullname, *shortname;
		gchar *ltz, *time;
		gchar tmp_time[8] = {0};
		gchar *dstoff;

		/*
		 * Tokenize
		 *
		 * +XNITZINFO: <fullname>,<shortname>,<LTZ>,<UT>,<DST>
		 */
		tokens = tcore_at_tok_new(line);

		/* <fullname> */
		if ((fullname = tcore_at_tok_nth(tokens, 1))) {
			if (strlen(fullname) > 0) {
				fullname = tcore_at_tok_extract((const char *)fullname);

				/* Update Long name */
				tcore_network_set_long_name(co, fullname);

				tcore_free(fullname);
			}
		}

		/* <shortname> */
		if ((shortname = tcore_at_tok_nth(tokens, 1))) {
			if (strlen(shortname) > 0) {
				shortname = tcore_at_tok_extract((const char *)shortname);

				/* Update Short name */
				tcore_network_set_short_name(co, shortname);

				tcore_free(shortname);
			}
		}

		/* <LTZ> */
		if ((ltz = g_slist_nth_data(tokens, 2)))
			nitz_info.gmtoff = atoi(ltz) * 15;/* gmtoff in minutes */

		if ((time = g_slist_nth_data(tokens, 3))
				&& (strlen(time) > 18)) {
			/* (time + 1) - Skip past initial quote (") */
			g_strlcpy(tmp_time, time + 1, 2+1);
			nitz_info.year = atoi(tmp_time);

			/* skip slash (/) after year param */
			g_strlcpy(tmp_time, time + 4, 2+1);
			nitz_info.month = atoi(tmp_time);

			/* skip past slash (/) after month param */
			g_strlcpy(tmp_time, time + 7, 2+1);
			nitz_info.day = atoi(tmp_time);

			/* skip past comma (,) after day param */
			g_strlcpy(tmp_time, time + 10, 2+1);
			nitz_info.hour = atoi(tmp_time);

			/* skip past colon (:) after hour param */
			g_strlcpy(tmp_time, time + 13, 2+1);
			nitz_info.minute = atoi(tmp_time);

			 /* skip past colon (:) after minute param */
			 g_strlcpy(tmp_time, time + 16, 2+1);
			nitz_info.second = atoi(tmp_time);
		}

		/* <DST> */
		if ((dstoff = g_slist_nth_data(tokens, 4))) {
			nitz_info.dstoff = atoi(dstoff);
			nitz_info.isdst = TRUE;
		}

		/* Get PLMN */
		tcore_network_get_plmn(co, &nitz_info.plmn);

		/* Send Notification - Network time info */
		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_NETWORK_TIMEINFO,
			sizeof(TelNetworkNitzInfoNoti), &nitz_info);

		/* Free resource */
		tcore_free(nitz_info.plmn);
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

/*
 * Notification:
 *	+XCIEV: <rssi>,
 * or
 *	+XCIEV:,<battery_level>
 *
 * 'Radio Signal Strength' <rssi> can have the values
 * 0	-107 dBm or less or unknown
 * 1	-99 dBm or less
 * 2	-91 dBm or less
 * 3	-83 dBm or less
 * 4	-75 dBm or less
 * 5	-67 dBm or less
 * 6	-59 dBm or less
 * 7	-51 dBm or less
 *
 * 'Battery Level' <battery_level> can have the values
 * 0	0 % <= level < 5 %
 * 1	5 % <= level < 15 %
 * 2	15 % <= level < 25 %
 * 3	25 % <= level < 40 %
 * 4	40 % <= level < 55 %
 * 5	55 % <= level < 70 %
 * 6	70 % <= level < 85 %
 * 7	85 % <= level <= 100 %
 *
 * NOTE:
 *	<battery_level> is not consider for
 *	TCORE_NOTIFICATION_NETWORK_RSSI notification
 */
static gboolean on_notification_imc_network_rssi(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *lines = NULL;
	gchar *line = NULL;

	dbg("Network notification - Icon (rssi) info: [+XCIEV]");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("+XCIEV unsolicited message expected to be Single line "
			"but received multiple lines");
		return TRUE;
	}

	line = (gchar *)lines->data;
	if (line != NULL) {
		GSList *tokens = NULL;
		gchar *rssi_token;

		/*
		 * Tokenize
		 *
		 * +XCIEV: <rssi>,
		 */
		tokens = tcore_at_tok_new(line);

		rssi_token = (gchar *)g_slist_nth_data(tokens, 0);
		if (rssi_token && strlen(rssi_token)) {
			guint rssi_bar = atoi(rssi_token);
			dbg("RSSI Level: [%d]", rssi_bar);

			/* Send Notification - Network Rssi */
			tcore_object_send_notification(co,
				TCORE_NOTIFICATION_NETWORK_RSSI,
				sizeof(guint), &rssi_bar);
		}

		/* Free resource */
		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

/* Network Responses */

static void on_response_imc_network_search(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	CustomData *custom_data;

	ImcRespCbData *resp_cb_data = user_data;
	TelNetworkResult result = TEL_NETWORK_RESULT_FAILURE; //TODO - CME Error mapping required.
	TelNetworkPlmnList plmn_list = {0, };
	guint num_network_avail = 0;
	guint count;
	GSList *tokens = NULL;

	dbg("Enter");
	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	custom_data = tcore_object_ref_user_data(co);
	tcore_check_return_assert(custom_data != NULL);

	if (at_resp && at_resp->success) {
		const gchar *line;
		GSList *net_token = NULL;
		gchar *resp;
		gint act;

		/* If Request is Cancelled then return back SUCCESS/SEARCH_CANCELLED */
		if (custom_data->search_state
			== IMC_NETWORK_SEARCH_STATE_CANCELLED) {
			dbg("Network Search has been Cancelled!!!");

			/*
			 * TODO:
			 *
			 * Need to introduce new Result -
			 *	TEL_NETWORK_RESULT_SEARCH_ABORTED/CANCELLED
			 *
			 * Presently sending TEL_NETWORK_RESULT_FAILURE
			 */
			result = TEL_NETWORK_RESULT_FAILURE;

			goto END;
		}

		if (!at_resp->lines) {
			err("invalid response received");
			goto END;
		}

		line = (char *) at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		num_network_avail = g_slist_length(tokens);
		if (num_network_avail < 1) {
			err("invalid message");
			goto END;
		}

		plmn_list.network_list = tcore_malloc0(sizeof(TelNetworkInfo) * num_network_avail);
		dbg("RESPONSE OK");
		plmn_list.count = 0;
		for (count = 0; count < num_network_avail; count++) {

			net_token = tcore_at_tok_new(g_slist_nth_data(tokens, count));
			if (NULL == net_token)
				continue;

			resp = tcore_at_tok_nth(net_token, 0);
			if (resp != NULL) {
				plmn_list.network_list[count].plmn_status = atoi(resp);
				dbg("status[%d]", plmn_list.network_list[count].plmn_status);
			}

			if ((resp = tcore_at_tok_nth(net_token, 1))) {
				/* Long Alpha name */
				dbg("long alpha name[%s]", resp);
				plmn_list.network_list[count].network_identity.long_name =
					tcore_at_tok_extract(resp);
			}

			if ((resp = tcore_at_tok_nth(net_token, 2))) {
				/* Short Alpha name */
				dbg("Short Alpha name[%s]", resp);
				plmn_list.network_list[count].network_identity.short_name =
					tcore_at_tok_extract(resp);
			}

			/* PLMN ID */
			if ((resp = tcore_at_tok_nth(net_token, 3))) {
				dbg("PLMN ID[%s]", resp);
				plmn_list.network_list[count].network_identity.plmn =
					tcore_at_tok_extract(resp);
			}

			/* Parse Access Technology */
			if ((resp = tcore_at_tok_nth(tokens, 4))) {
					act = atoi(resp);
					if (0 == act)
						plmn_list.network_list[count].act = TEL_NETWORK_ACT_GSM;
					else if (2 == act)
						plmn_list.network_list[count].act = TEL_NETWORK_ACT_UMTS;
				}

			dbg("Operator [%d] :: status = %d, long_name = %s, short_name = %s plmn = %s, AcT=%d",
					plmn_list.count,
					plmn_list.network_list[count].plmn_status,
					plmn_list.network_list[count].network_identity.long_name,
					plmn_list.network_list[count].network_identity.short_name,
					plmn_list.network_list[count].network_identity.plmn,
					plmn_list.network_list[count].act);

			plmn_list.count ++;
			tcore_at_tok_free(net_token);
		}
		result = TEL_NETWORK_RESULT_SUCCESS;
	} else {
		err("RESPONSE NOK");
		if (at_resp->lines)
			err("CME Error[%s]",(char *)at_resp->lines->data);
	}

END:
	dbg("Network search : [%s]",
			(result == TEL_NETWORK_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Update Search state */
	custom_data->search_state = IMC_NETWORK_SEARCH_STATE_NO_SEARCH;

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &plmn_list, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);

	/* Free resources*/
	for (count = 0; count < num_network_avail; count++) {
		g_free(plmn_list.network_list[count].network_identity.long_name);
		g_free(plmn_list.network_list[count].network_identity.short_name);
		g_free(plmn_list.network_list[count].network_identity.plmn);
	}

	tcore_free(plmn_list.network_list);
	tcore_at_tok_free(tokens);
}

static gboolean on_response_imc_network_cancel_search(gpointer data)
{
	ImcRespCbData *resp_cb_data = data;
	ImcNetworkCancelSearch *cancel_search =
		(ImcNetworkCancelSearch *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(cancel_search->co, (gint)cancel_search->result,
			NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);

	/* To stop the cycle, need to return FALSE */
	return FALSE;
}

static void on_response_imc_network_get_selection_mode(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelNetworkSelectionMode selection_mode = -1;
	GSList *tokens = NULL;

	TelNetworkResult result = TEL_NETWORK_RESULT_FAILURE; //TODO - CME Error mapping required.
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		const gchar *line;
		gint mode;

		if (!at_resp->lines) {
			err("invalid response received");
			goto END;
		}

		line = (char *) at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			msg("invalid message");
			goto END;
		}
		dbg("RESPONSE OK");

		mode = atoi(tcore_at_tok_nth(tokens, 0));
		if (mode == 0)
			selection_mode = TEL_NETWORK_SELECTION_MODE_AUTOMATIC;
		else if (mode == 1)
			selection_mode = TEL_NETWORK_SELECTION_MODE_MANUAL;

		result = TEL_NETWORK_RESULT_SUCCESS;
		dbg("selection mode[%d]", selection_mode);

	} else {
		err("RESPONSE NOK");
	}

END:
	dbg("Get selection mode : [%s]",
			(result == TEL_NETWORK_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &selection_mode, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
	/* Free resource*/
	tcore_at_tok_free(tokens);
}

static void on_response_imc_network_default(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelNetworkResult result = TEL_NETWORK_RESULT_FAILURE; //TODO - CME Error mapping required.

	dbg("Enter");
	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		result = TEL_NETWORK_RESULT_SUCCESS;
	} else {
		err("RESPONSE NOK");
		if (at_resp->lines)
			err("CME Error[%s]",(char *)at_resp->lines->data);
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
}


static void on_response_imc_network_get_mode(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelNetworkResult result = TEL_NETWORK_RESULT_FAILURE; //TODO - CME Error mapping required.
	TelNetworkMode mode = -1;
	GSList *tokens = NULL;

	dbg("Enter");
	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		const gchar *line;
		gint net_mode;

		if (!at_resp->lines) {
			err("invalid response received");
			goto END;
		}

		line = (char *) at_resp->lines->data;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("invalid message");
			goto END;
		}

		dbg("RESPONSE OK");
		net_mode = atoi(tcore_at_tok_nth(tokens, 0));
		dbg("mode = %d", net_mode);

		switch(net_mode) {
		case 0:
			mode = TEL_NETWORK_MODE_2G;
			break;
		case 1:
			mode = TEL_NETWORK_MODE_AUTO;
			break;
		case 2:
			mode = TEL_NETWORK_MODE_3G;
			break;
		default:
			err("Unsupported  mode [%d]", net_mode);
			goto END;
		}
		result = TEL_NETWORK_RESULT_SUCCESS;
	} else {
		err("RESPONSE NOK");
	}
END:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &mode, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
	/* Free resource*/
	tcore_at_tok_free(tokens);
}

static void on_response_imc_network_get_preferred_plmn(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelNetworkPreferredPlmnList plmn_list = {0,};
	guint count = 0, total_lines = 0;
	TelNetworkResult result = TEL_NETWORK_RESULT_FAILURE; //TODO - CME Error mapping required.
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		GSList *tokens;
		gchar *resp;
		gchar *line;
		gboolean gsm_act2 = FALSE, gsm_compact_act2 = FALSE;
		gboolean utran_act2 = FALSE;

		if (!at_resp->lines) {
			err("invalid response received");
			goto END;
		}

		total_lines = g_slist_length(at_resp->lines);
		if (total_lines < 1) {
			msg("invalid message");
			goto END;
		}

		dbg("RESPONSE OK");
		result = TEL_NETWORK_RESULT_SUCCESS;

		plmn_list.list = tcore_malloc0(sizeof(TelNetworkPreferredPlmnInfo) * total_lines);
		plmn_list.count = 0;

		for (count = 0; count < total_lines; count++) {
			/* Take each line response at a time & parse it */
			line = tcore_at_tok_nth(at_resp->lines, count);
			tokens = tcore_at_tok_new(line);

			/*Index */
			if ((resp = tcore_at_tok_nth(tokens, 0))) {
				plmn_list.list[count].index = atoi(resp);
			}

			/* PLMN ID */
			if ((resp = tcore_at_tok_nth(tokens, 2))) {
				plmn_list.list[count].plmn = tcore_at_tok_extract(resp);
			}

			/*GSM_AcT1 */
			if ((resp = tcore_at_tok_nth(tokens, 3))) {
				gsm_act2 = atoi(resp);
			}

			/*GSM_Compact_AcT2 */
			if ((resp = tcore_at_tok_nth(tokens, 4))) {
				gsm_compact_act2 = atoi(resp);
			}

			/*UTRAN_AcT2 */
			if ((resp = tcore_at_tok_nth(tokens, 5))) {
				utran_act2 = atoi(resp);
			}

			if (gsm_act2)
				plmn_list.list[count].act = TEL_NETWORK_ACT_UMTS;
			else if (utran_act2 || gsm_compact_act2)
				plmn_list.list[count].act = TEL_NETWORK_ACT_GSM;

			/* free tokens*/
			tcore_at_tok_free(tokens);

			dbg("index[%d], plmn[%s], act[%d]",
				plmn_list.list[count].index,
				plmn_list.list[count].plmn,
				plmn_list.list[count].act);

		}
		plmn_list.count = count;
	} else {
		err("RESPONSE NOK");
		if (at_resp->lines)
			err("CME Error[%s]",(char *)at_resp->lines->data);
	}

END:
	dbg("get preferred plmn : [%s]",
			(result == TEL_NETWORK_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &plmn_list, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);

	for(count = 0; count < total_lines; count++) {
		g_free(plmn_list.list[count].plmn);
	}
	tcore_free(plmn_list.list);
}


/* Network Operations */
/*
 * Operation - set_power_status
 *
 * Request -
 * AT-Command: AT+XCOPS=<Type>
 *
 * <type> may be
 * 0	numeric format of network MCC/MNC (three BCD
 *	digit country code and two/three BCD digit network code)
 * 1	Short Name in ROM (NV-RAM)
 * 2	Long Name in ROM (NV-RAM)
 * 3	Short Network Operator Name (CPHS)
 * 4	Long Network Operator Name (CPHS)
 * 5	Short NITZ Name
 * 6	Full NITZ Name
 * 7	Service Provider Name
 * 8	EONS short operator name from EF-PNN
 * 9	EONS long operator name from EF-PNN
 * 11	Short PLMN name (When PS or CS is registered)
 * 12	Long PLMN name (When PS or CS is registered)
 * 13	numeric format of network MCC/MNC even in limited service
 *
 * Response - Network name
 * Success: (Multiple Single line)
 *	+XCOPS: <type>[,<name>[,<display_condition>]]
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_network_get_identity_info(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	return __imc_network_fetch_nw_name(co, cb, cb_data);
}

/*
 * Operation -  network search
 * Request -
 * AT-Command: AT+COPS=?
 *
 * Response -
 * Success: (Single line)
 * +COPS: [list of supported (<stat>,long alphanumeric <oper>
 * ,short alphanumeric <oper>,numeric <oper>[,< AcT>]
 * [,,(list of supported <mode>s),(list of supported <format>s)]

 * <format>
 * describes the format in which operator name is to be displayed. Different values of <format> can be:
 * 0 <oper> format presentations are set to long alphanumeric. If Network name not available it displays
 *   combination of Mcc and MNC in string format.
 * 1 <oper> format presentation is set to short alphanumeric.
 * 2 <oper> format presentations set to numeric.
 * <oper>:
 * string type given in format <format>; this field may be up to 16 character long for long alphanumeric format, up
 * to 8 characters for short alphanumeric format and 5 Characters long for numeric format (MCC/MNC codes)
 * <stat>:
 * describes the status of the network. It is one of the response parameter for test command.
 * 0 Unknown Networks
 * 1 Network Available
 * 2 Current
 * 3 Forbidden Network
 * <AcT>
 * indicates the radio access technology and values can be:
 * 0 GSM
 * 2 UMTS
 * OK
 * Failure:
 * +CME ERROR: <error>
 */

static TelReturn imc_network_search(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	CustomData *custom_data;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	custom_data = tcore_object_ref_user_data(co);
	if (custom_data->search_state
			== IMC_NETWORK_SEARCH_STATE_IN_PROGRESS) {
		warn("Network Search: [ALREADY IN PROGRESS]");
		return TEL_RETURN_FAILURE;
	}

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request_ex(co,
		"AT+COPS=?", "+COPS",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		on_response_imc_network_search, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL,
		FALSE, TRUE);
	if (ret != TEL_RETURN_SUCCESS) {
		err("Failed to process request - [%s]", "Network Search");
		imc_destroy_resp_cb_data(resp_cb_data);
	}
	else {
		custom_data->search_state = IMC_NETWORK_SEARCH_STATE_IN_PROGRESS;
		dbg("Search State: [IN PROGRESS]");
	}

	return ret;
}

static TelReturn imc_network_cancel_search(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;
	ImcRespCbData *resp_cb_data;
	CustomData *custom_data;
	ImcNetworkCancelSearch cancel_search = {0, };

	custom_data = tcore_object_ref_user_data(co);
	if (custom_data->search_state
			== IMC_NETWORK_SEARCH_STATE_IN_PROGRESS) {
		dbg("Search in Progress...");

		/* Send Request to modem */
		ret = tcore_at_prepare_and_send_request_ex(co,
			"\e", NULL,
			TCORE_AT_COMMAND_TYPE_NO_RESULT,
			TCORE_PENDING_PRIORITY_IMMEDIATELY,
			NULL,
			NULL, NULL,
			on_send_imc_request, NULL,
			0, NULL, NULL,
			TRUE, FALSE);
		if (ret != TEL_RETURN_SUCCESS) {
			err("Failed to process request - [%s]", "Cancel network search");
			goto out;
		}
		else {
			custom_data->search_state = IMC_NETWORK_SEARCH_STATE_CANCELLED;
			dbg("Search State: [CANCELLED]");
		}
	}
	else {
		dbg("No Search in Progress...");
		ret = TEL_RETURN_SUCCESS;
	}

	cancel_search.co = co;
	cancel_search.result = TEL_NETWORK_RESULT_SUCCESS;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		&cancel_search, sizeof(ImcNetworkCancelSearch));

	/* Send response */
	g_idle_add(on_response_imc_network_cancel_search, (gpointer)resp_cb_data);

out:
	return ret;
}

/*
 * Operation -  automatic network selection
 * Request -
 * AT-Command: AT+COPS= [<mode> [, <format> [, <oper>> [, <AcT>]]]]
 * where
 * <mode>
 * is used to select, whether the selection is done automatically by the ME or is forced by this command to
 * operator <oper> given in the format <format>.
 * The values of <mode> can be:
 * 0 Automatic, in this case other fields are ignored and registration is done automatically by ME
 * 1 Manual. Other parameters like format and operator need to be passed
 * 2 Deregister from network
 * 3 It sets <format> value. In this case <format> becomes a mandatory input
 * 4 Manual / Automatic. In this case if manual selection fails then automatic mode is entered
 *
 * Response -
 * Success:(No result)
 * OK or
 * +CME ERROR: <err>
 */
static TelReturn imc_network_select_automatic(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;
	dbg("entry");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+COPS=0", NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_network_default, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Automatic network selection");

	return ret;
}

/*
 * Operation -  manual network selection
 * Request -
 * AT-Command: AT+COPS= [<mode> [, <format> [, <oper>> [, <AcT>]]]]
 * where
 * <mode>
 * is used to select, whether the selection is done automatically by the ME or is forced by this command to
 * operator <oper> given in the format <format>.
 * The values of <mode> can be:
 * 0 Automatic, in this case other fields are ignored and registration is done automatically by ME
 * 1 Manual. Other parameters like format and operator need to be passed
 * 2 Deregister from network
 * 3 It sets <format> value. In this case <format> becomes a mandatory input
 * 4 Manual / Automatic. In this case if manual selection fails then automatic mode is entered.
 * <oper>
 * string type given in format <format>; this field may be up to 16 character long for long alphanumeric format, up
 * to 8 characters for short alphanumeric format and 5 Characters long for numeric format (MCC/MNC codes)
 * <AcT>
 * indicates the radio access technology and values can be:
 * 0 GSM
 * 2 UMTS
 *
 * Response -
 * Success:(No result)
 * OK or
 * +CME ERROR: <err>
 */
static TelReturn imc_network_select_manual(CoreObject *co,
	const TelNetworkSelectManualInfo *sel_manual,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;
	gchar *at_cmd;
	gint act;
	dbg("entry");

	switch(sel_manual->act) {
	case TEL_NETWORK_ACT_GSM:
	case TEL_NETWORK_ACT_GPRS:
	case TEL_NETWORK_ACT_EGPRS:
		act = 0;
		break;
	case TEL_NETWORK_ACT_UMTS:
	case TEL_NETWORK_ACT_GSM_AND_UMTS:
	case TEL_NETWORK_ACT_HSDPA:
	case TEL_NETWORK_ACT_HSPA:
		act = 2;
		break;
	default:
		err("unsupported AcT");
		return ret;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+COPS=1,2,\"%s\",%d", sel_manual->plmn, act);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_network_default, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Manual network selection");

	/* Free resources*/
	g_free(at_cmd);
	return ret;
}

/*
 * Operation -  get network selection mode
 * Request -
 * AT-Command: AT+COPS?
 *
 * Response -
 * Success: (Single line)
 * +COPS: <mode>[,<format>,<oper>[,< AcT>]]
 * <mode>
 * is used to select, whether the selection is done automatically by the ME or is forced by this command to
 * operator <oper> given in the format <format>.
 * The values of <mode> can be:
 * 0 Automatic, in this case other fields are ignored and registration is done automatically by ME
 * 1 Manual. Other parameters like format and operator need to be passed
 * 2 Deregister from network
 * 3 It sets <format> value. In this case <format> becomes a mandatory input
 * 4 Manual / Automatic. In this case if manual selection fails then automatic mode is entered
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_network_get_selection_mode(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+COPS?", "+COPS",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_network_get_selection_mode, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get selection mode");

	return ret;
}

/*
 * Operation -  set preferred plmn
 * Request -
 * AT-Command: AT+CPOL=<index>][,<format>[,<oper>[,<GSM_AcT>,<GSM_Compact_AcT>,<UTRAN_AcT>]]]
 * where
 * <indexn> integer type; the order number of operator in the SIM/USIM preferred operator list
 * <format>
 * 0 long format alphanumeric <oper>
 * 1 short format alphanumeric <oper>
 * 2 numeric <oper>
 * <opern> string type; <format> indicates if the format is alphanumeric or numeric (see +COPS)
 * <GSM_AcTn>: GSM access technology
 * 0 access technology not selected
 * 1 access technology selected
 * <GSM_Compact_AcTn>: GSM compact access technology
 * 0 access technology not selected
 * 1 access technology selected
 * <UTRA_AcTn>: UTRA access technology
 * 0 access technology not selected
 * 1 access technology selected
 *
 * Response -
 * Success:(No Result)
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_network_set_preferred_plmn(CoreObject *co,
	const TelNetworkPreferredPlmnInfo *pref_plmn,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	gchar *at_cmd;
	gboolean gsm_act = FALSE;
	gboolean gsm_compact_act = FALSE;
	gboolean utran_act = FALSE;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;
	dbg("entry");

	switch(pref_plmn->act) {
	case TEL_NETWORK_ACT_GSM:
	case TEL_NETWORK_ACT_GPRS:
	case TEL_NETWORK_ACT_EGPRS:
		gsm_act = TRUE;
		break;
	case TEL_NETWORK_ACT_UMTS:
	case TEL_NETWORK_ACT_HSDPA:
	case TEL_NETWORK_ACT_HSPA:
		utran_act = TRUE;
		break;
	case TEL_NETWORK_ACT_GSM_AND_UMTS:
		gsm_act = utran_act = TRUE;
		break;
	default:
		warn("unsupported AcT");
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CPOL=%d,%d,\"%s\",%d,%d,%d",
			pref_plmn->index, 2, pref_plmn->plmn, gsm_act, gsm_compact_act, utran_act);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_network_default, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set preferred plmn");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation -  get preferred plmn
 * Request -
 * AT-Command: AT+CPOL?
 * Response -
 * Success: (multiline)
 * +CPOL: <index1>,<format>,<oper1>
 * [,<GSM_AcT1>,<GSM_Compact_AcT1>,<UTRAN_AcT1>][<CR><LF>
 * +CPOL: <index2>,<format>,<oper2>[,<GSM_AcT2>,<GSM_Compact_AcT2>,<UTRAN_AcT2>] […]]
 *  OK
 * Failure
 * +CME ERROR: <err>
 */
static TelReturn imc_network_get_preferred_plmn(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;
	dbg("entry");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CPOL=,2;+CPOL?", "+CPOL", //to make sure <oper> is numeric type in reponse.
		TCORE_AT_COMMAND_TYPE_MULTILINE,
		NULL,
		on_response_imc_network_get_preferred_plmn, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get preferred plmn");

	return ret;
}

/*
 * Operation -  set network mode
 * Request -
 * AT-Command: AT+XRAT=<AcT> [, <PreferredAct>]
 * where
 * <AcT> indicates the radio access technology and may be
 * 0 GSM single mode
 * 1 GSM / UMTS Dual mode
 * 2 UTRAN (UMTS)
 * 3-7 Reserved for future use.
 * 8 This option is to swap the RAT mode between the two stacks. Example: If Stack1 is in GSM mode and
 * Stack2 is in UMTS mode, this will configure Stack1 in UMTS mode and Stack2 in GSM mode.
 * Note : <Act> = 8 is used only for dual sim configuration. In this case < PreferredAct > is ignored
 * <PreferredAct>
 * This parameter is used for network registration in case of <AcT>=1.
 * 0 RAT GSM
 * 2 RAT UMTS
 * Response -
 * Success: (No result)
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_network_set_mode(CoreObject *co, TelNetworkMode mode,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;
	int act;
	gchar *at_cmd;

	switch(mode) {
	case TEL_NETWORK_MODE_AUTO:
		act = 1;
		break;
	case TEL_NETWORK_MODE_2G:
		act = 0;
		break;
	case TEL_NETWORK_MODE_3G:
		act = 2;
		break;
	case TEL_NETWORK_MODE_LTE:
	default:
		err("Unsupported  mode");
		return ret;
	}

	if (act == 1)
		/* AT-Command */
		at_cmd = g_strdup_printf("AT+XRAT=%d,2", act); //PreferredAct is UMTS
	else
		/* AT-Command */
		at_cmd = g_strdup_printf("AT+XRAT=%d", act);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL ,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_network_default, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set network mode");

	g_free(at_cmd);
	return ret;
}

/*
 * Operation -  get network mode
 * Request -
 * AT-Command: AT+XRAT?
 *
 * Response -
 * Success: (Single line)
 * +XRAT : <Act>,<PreferredAct>
 * <AcT> indicates the radio access technology and may be
 * 0 GSM single mode
 * 1 GSM / UMTS Dual mode
 * 2 UTRAN (UMTS)
 * 3-7 Reserved for future use.
 * 8 This option is to swap the RAT mode between the two stacks. Example: If Stack1 is in GSM mode and
 * Stack2 is in UMTS mode, this will configure Stack1 in UMTS mode and Stack2 in GSM mode.
 * Note : <Act> = 8 is used only for dual sim configuration. In this case < PreferredAct > is ignored
 * <PreferredAct>
 * This parameter is used for network registration in case of <AcT>=1.
 * 0 RAT GSM
 * 2 RAT UMTS
 * OK
 * Failure:
 * +CME ERROR: <error>
 */

static TelReturn imc_network_get_mode(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("entry");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XRAT?", "+XRAT",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_network_get_mode, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get network mode");

	return ret;
}

static TelReturn imc_network_get_neighboring_cell_info(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	/* TODO*/
	dbg("entry");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

/* Network Operations */
static TcoreNetworkOps imc_network_ops = {
	.get_identity_info = imc_network_get_identity_info,
	.search = imc_network_search,
	.cancel_search = imc_network_cancel_search,
	.select_automatic = imc_network_select_automatic,
	.select_manual = imc_network_select_manual,
	.get_selection_mode = imc_network_get_selection_mode,
	.set_preferred_plmn = imc_network_set_preferred_plmn,
	.get_preferred_plmn = imc_network_get_preferred_plmn,
	.set_mode = imc_network_set_mode,
	.get_mode = imc_network_get_mode,
	.get_neighboring_cell_info = imc_network_get_neighboring_cell_info
};

gboolean imc_network_init(TcorePlugin *p, CoreObject *co)
{
	CustomData *custom_data;
	dbg("Enter");

	/* Set operations */
	tcore_network_set_ops(co, &imc_network_ops);

	/* Custom data */
	custom_data = tcore_malloc0(sizeof(CustomData));
	custom_data->search_state = IMC_NETWORK_SEARCH_STATE_NO_SEARCH;

	/* Link Custom data */
	tcore_object_link_user_data(co, custom_data);

	/* Add Callbacks */
	tcore_object_add_callback(co, "+CREG", on_notification_imc_cs_network_info, NULL);
	tcore_object_add_callback(co, "+CGREG", on_notification_imc_ps_network_info, NULL);
	tcore_object_add_callback(co, "+XNITZINFO", on_notification_imc_network_time_info, NULL);
	tcore_object_add_callback(co, "+XCIEV", on_notification_imc_network_rssi, NULL);

	/*
	 * Add Hooks - Request and Notification
	 */
	tcore_plugin_add_request_hook(p,
		TCORE_COMMAND_MODEM_SET_FLIGHTMODE,
		on_hook_imc_set_flight_mode, NULL);
	tcore_plugin_add_notification_hook(p,
		TCORE_NOTIFICATION_SIM_STATUS,
		on_hook_imc_sim_status, co);

	//_insert_mcc_mnc_oper_list(cp, co_network);

	dbg("Exit");
	return TRUE;
}

void imc_network_exit(TcorePlugin *p, CoreObject *co)
{
	CustomData *custom_data;

	custom_data = tcore_object_ref_user_data(co);
	if (custom_data != NULL)
		tcore_free(custom_data);

	dbg("Exit");
}
