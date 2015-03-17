/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: sharanayya mathapati <sharan.m@samsung.com>
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
#include <co_call.h>
#include <co_ss.h>
#include <user_request.h>
#include <util.h>
#include <server.h>
#include <at.h>

#include "imc_common.h"
#include "imc_ss.h"

#define NUM_TYPE_INTERNATIONAL      0x01
#define NUM_PLAN_ISDN                   0x01

// To avoid sending multiple response to application
static gboolean UssdResp = FALSE;

enum  telephony_ss_opcode {
	SS_OPCO_REG = 0x01,       /* 0x01 : Registration */
	SS_OPCO_DEREG,            /* 0x02 : De-registration(erase) */
	SS_OPCO_ACTIVATE,         /* 0x03 : Activation */
	SS_OPCO_DEACTIVATE,       /* 0x04 : De-activation */
	SS_OPCO_MAX
};

struct ss_confirm_info {
	enum telephony_ss_class class;
	int flavor_type;
	enum tcore_response_command resp;
	void *data;
	int data_len;
};

static gboolean _ss_request_message(TcorePending *pending, CoreObject *o, UserRequest *ur, void *on_resp, void *user_data);

static TReturn _ss_barring_get(CoreObject *o, UserRequest *ur, enum telephony_ss_class class, enum telephony_ss_barring_mode type, enum tcore_response_command resp);

static TReturn _ss_forwarding_get(CoreObject *o, UserRequest *ur, enum telephony_ss_class class, enum telephony_ss_forwarding_mode type, enum tcore_response_command resp);

static TReturn _ss_waiting_get(CoreObject *o, UserRequest *ur, enum telephony_ss_class class, enum tcore_response_command resp);

static TReturn imc_ss_barring_activate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_barring_deactivate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_barring_change_password(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_barring_get_status(CoreObject *o, UserRequest *ur);

static TReturn imc_ss_forwarding_activate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_forwarding_deactivate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_forwarding_register(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_forwarding_deregister(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_forwarding_get_status(CoreObject *o, UserRequest *ur);

static TReturn imc_ss_waiting_activate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_waiting_deactivate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_waiting_get_status(CoreObject *o, UserRequest *ur);

static TReturn imc_ss_cli_activate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_cli_deactivate(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_cli_get_status(CoreObject *o, UserRequest *ur);

static TReturn imc_ss_send_ussd(CoreObject *o, UserRequest *ur);

static TReturn imc_ss_set_aoc(CoreObject *o, UserRequest *ur);
static TReturn imc_ss_get_aoc(CoreObject *o, UserRequest *ur);

static TReturn imc_ss_manage_call_0_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data);
static TReturn imc_ss_manage_call_1_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data);
static TReturn imc_ss_manage_call_1x_send(CoreObject *o, UserRequest *ur, const int id, ConfirmCallback cb, void *user_data);
static TReturn imc_ss_manage_call_2_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data);
static TReturn imc_ss_manage_call_2x_send(CoreObject *o, UserRequest *ur, const int id, ConfirmCallback cb, void *user_data);
static TReturn imc_ss_manage_call_3_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data);
static TReturn imc_ss_manage_call_4_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data);
static TReturn imc_ss_manage_call_4dn_send(CoreObject *o, UserRequest *ur, const char *number, ConfirmCallback cb, void *user_data);

static void on_confirmation_ss_message_send(TcorePending *p, gboolean result, void *user_data);

static void _ss_ussd_response(UserRequest *ur, const char *ussd_str, enum telephony_ss_ussd_type type, enum telephony_ss_ussd_status status);
static void _ss_ussd_notification(TcorePlugin *p, const char *ussd_str, enum telephony_ss_ussd_status status);

static gboolean on_notification_ss_info(CoreObject *o, const void *data, void *user_data);
static gboolean on_notification_ss_ussd(CoreObject *o, const void *data, void *user_data);


static gboolean _ss_request_message(TcorePending *pending,
									CoreObject *o,
									UserRequest *ur,
									void *on_resp,
									void *user_data)
{
	TcoreHal *hal = NULL;
	TReturn ret;
	dbg("Entry");

	if (on_resp) {
		tcore_pending_set_response_callback(pending, on_resp, user_data);
	}
	tcore_pending_set_send_callback(pending, on_confirmation_ss_message_send, NULL);
	if (ur) {
		tcore_pending_link_user_request(pending, ur);
	} else {
		err("User Request is NULL, is this internal request??");
	}

	hal = tcore_object_get_hal(o);

	// Send request to HAL
	ret = tcore_hal_send_request(hal, pending);
	if (TCORE_RETURN_SUCCESS != ret) {
		err("Request send failed");
		return FALSE;
	}

	dbg("Exit");
	return TRUE;
}

static void _ss_ussd_response(UserRequest *ur, const char *ussd_str, enum telephony_ss_ussd_type type, enum telephony_ss_ussd_status status)
{
	struct tresp_ss_ussd resp;
	dbg("Entry");

	if (ur) {
		memset(&resp, 0x0, sizeof(struct tresp_ss_ussd));
		resp.type = type;
		resp.status = status;
		resp.err = SS_ERROR_NONE;
		dbg("ussd_str = %s resp.type - %d resp.status - %d", ussd_str, resp.type, resp.status);

		if (ussd_str) {
			int len = strlen(ussd_str);
			if (len < MAX_SS_USSD_LEN) {
				memcpy(resp.str, ussd_str, len);
				resp.str[len] = '\0';
			} else {
				memcpy(resp.str, ussd_str, MAX_SS_USSD_LEN);
				resp.str[MAX_SS_USSD_LEN - 1] = '\0';
			}
			dbg("Response string: %s", resp.str);
		} else {
			dbg("USSD string is not present");
			memset(resp.str, '\0', MAX_SS_USSD_LEN);
		}
		UssdResp = TRUE;
		// Send response to TAPI
		tcore_user_request_send_response(ur, TRESP_SS_SEND_USSD, sizeof(struct tresp_ss_ussd), &resp);
	} else {
		err("User request is NULL");
	}

	dbg("Exit");
	return;
}

static void _ss_ussd_notification(TcorePlugin *p, const char *ussd_str, enum telephony_ss_ussd_status status)
{
	CoreObject *core_obj = 0;
	struct tnoti_ss_ussd noti;

	dbg("function enter");
	if (!p) {
		dbg("[ error ] p : (NULL)");
		return;
	}
	noti.status = status;
	if (ussd_str) {
		int len = strlen(ussd_str);
		if (len < MAX_SS_USSD_LEN) {
			memcpy(noti.str, ussd_str, len);
			noti.str[len] = '\0';
		} else {
			memcpy(noti.str, ussd_str, MAX_SS_USSD_LEN);
			noti.str[MAX_SS_USSD_LEN - 1] = '\0';
		}
	} else {
		memset(noti.str, '\0', MAX_SS_USSD_LEN);
	}
	dbg("noti.str - %s", noti.str);

	core_obj = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_SS);
	tcore_server_send_notification(tcore_plugin_ref_server(p),
								   core_obj,
								   TNOTI_SS_USSD,
								   sizeof(struct tnoti_ss_ussd),
								   (void *) &noti);
}

static gboolean on_notification_ss_ussd(CoreObject *o, const void *data, void *user_data)
{
	enum telephony_ss_ussd_status status;
	UssdSession *ussd_session = 0;
	char *ussd_str = 0, *cmd = 0;
	TcorePlugin *plugin = 0;
	int m = -1, dcs = 0;
	char *ussdnoti = NULL, *str = NULL, *dcs_str = NULL;
	GSList *tokens = NULL;
	GSList *lines = NULL;
	char *ussd_string = NULL;
	unsigned int len;

	plugin = tcore_object_ref_plugin(o);
	ussd_session = tcore_ss_ussd_get_session(o);

	dbg("function enter");
	lines = (GSList *) data;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		return TRUE;
	}
	cmd = (char *) (lines->data);
	// parse ussd status
	tokens = tcore_at_tok_new(cmd);

	// parse <m>
	ussdnoti = g_slist_nth_data(tokens, 0);
	if (!ussdnoti) {
		dbg("+CUSD<m> is missing from %CUSD Notification");
	} else {
		m = atoi(ussdnoti);
		dbg("USSD status  %d", m);
		// parse [ <str>, <dcs>]
		ussd_string = g_slist_nth_data(tokens, 1);
		if (ussd_string) {
			/* Strike off starting & ending quotes. 1 extra character for NULL termination */
			str = malloc(strlen(ussd_string) - 1);
			dbg("length of Ussd Stirng - %d", strlen(ussd_string));
			if (str) {
				memset(str, 0x00, strlen(ussd_string) - 1);
			} else {
				dbg("malloc failed");
				if (NULL != tokens) {
					tcore_at_tok_free(tokens);
				}
				return FALSE;
			}
			len = strlen(ussd_string) - 1;
			++ussd_string;
			strncpy(str, ussd_string, len);

			dbg("USSD String - %s len = %d", str, strlen(str));
		}
		if ((dcs_str = g_slist_nth_data(tokens, 2))) {
			dcs = atoi(dcs_str);
			dbg("USSD dcs %d", dcs);
		}
	}

	switch (m) {
	case 0:
		status = SS_USSD_NO_ACTION_REQUIRE;
		break;

	case 1:
		status = SS_USSD_ACTION_REQUIRE;
		break;

	case 2:
		status = SS_USSD_TERMINATED_BY_NET;
		break;

	case 3:
		status = SS_USSD_OTHER_CLIENT;
		break;

	case 4:
		status = SS_USSD_NOT_SUPPORT;
		break;

	case 5:
		status = SS_USSD_TIME_OUT;
		break;

	default:
		dbg("unsupported m : %d", m);
		status = SS_USSD_MAX;
		break;
	}

	switch (tcore_util_get_cbs_coding_scheme(dcs)) {
	case TCORE_DCS_TYPE_7_BIT:
	case TCORE_DCS_TYPE_UNSPECIFIED:
	// ussd_str = tcore_util_unpack_gsm7bit(str, strlen(str));
	// break;

	case TCORE_DCS_TYPE_UCS2:
	case TCORE_DCS_TYPE_8_BIT:
		if ((str != NULL) && (strlen(str) > 0)) {
			ussd_str = g_new0(char, strlen(str) + 1);
			if (ussd_str != NULL) {
				memcpy(ussd_str, str, strlen(str));
				ussd_str[strlen(str)] = '\0';
			}
		}
		break;

	default:
		dbg("[ error ] unknown dcs type. ussd_session : %x", ussd_session);
		if (ussd_session) {
			UserRequest *ur = 0;
			enum telephony_ss_ussd_type type;

			tcore_ss_ussd_get_session_data(ussd_session, (void **) &ur);
			if (!ur) {
				dbg("[ error ] ur : (0)");
				goto CATCH;
			}

			type = (enum telephony_ss_ussd_type) tcore_ss_ussd_get_session_type(ussd_session);
			dbg("ussd type  - %d", type);

			_ss_ussd_response(ur, ussd_str, type, status);
		}

CATCH:
		if (NULL != tokens) {
			tcore_at_tok_free(tokens);
		}

		if (NULL != str) {
			free(str);
		}
		return FALSE;
	}

	switch (status) {
	case SS_USSD_NO_ACTION_REQUIRE:
	case SS_USSD_ACTION_REQUIRE:
	case SS_USSD_OTHER_CLIENT:
	case SS_USSD_NOT_SUPPORT:
	case SS_USSD_TIME_OUT:
	{
		if (ussd_session) {
			UserRequest *ur = 0;
			enum telephony_ss_ussd_type type;

			tcore_ss_ussd_get_session_data(ussd_session, (void **) &ur);
			if (!ur) {
				dbg("[ error ] ur : (0)");
				if (NULL != tokens) {
					tcore_at_tok_free(tokens);
				}

				if (NULL != str) {
					free(str);
				}

				if (ussd_str) {
					g_free(ussd_str);
				}
				return FALSE;
			}
			type = (enum telephony_ss_ussd_type) tcore_ss_ussd_get_session_type(ussd_session);
			dbg("ussd type  - %d", type);
			_ss_ussd_response(ur, (const char *) ussd_str, type, status);
			if (ussd_str)
				g_free(ussd_str);
		} else {
			tcore_ss_ussd_create_session(o, TCORE_SS_USSD_TYPE_NETWORK_INITIATED, 0, 0);
			_ss_ussd_notification(plugin, (const char *) ussd_str, status);

			if (ussd_str)
				g_free(ussd_str);
		}
	}
	break;

	case SS_USSD_TERMINATED_BY_NET:
	{
		if (ussd_session) {
			UserRequest *ur = 0;
			tcore_ss_ussd_get_session_data(ussd_session, (void **) &ur);
			if (ur) {
				tcore_user_request_unref(ur);
			}
			tcore_ss_ussd_destroy_session(ussd_session);
		}
	}
	break;

	default:
		break;
	}

	if (NULL != tokens) {
		tcore_at_tok_free(tokens);
	}

	if (NULL != str) {
		free(str);
	}

	dbg("Exit");
	return TRUE;
}

static gboolean on_notification_ss_info(CoreObject *o, const void *data, void *user_data)
{
	TcorePlugin *plugin = 0;
	CoreObject *co = 0;
	char *cmd = 0, *number = 0, *pos;
	int code1 = -1, code2 = -1, index = 0, ton = 0;
	char *str_code1, *str_code2, *str_ton, *str_index;
	GSList *tokens = NULL;
	char *buf;
	gboolean cssu = FALSE, cssi = FALSE;
	GSList *lines = NULL;
	char *resp = NULL;
	dbg("function enter");

	plugin = tcore_object_ref_plugin(o);
	co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);
	if (!co) {
		dbg("[ error ] plugin_ref_core_object : call");
		return FALSE;
	}

	lines = (GSList *) data;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}

	cmd = (char *) (lines->data);
	pos = strchr(cmd, ':');
	if (!pos) {
		dbg("[ error ] not valid SS- notification ");
		return TRUE;
	}
	buf = calloc(pos - cmd + 2, 1);
	memcpy(buf, cmd, pos - cmd);
	dbg("buf is %s", buf);

	if (!strcmp(buf, "+CSSU")) {
		dbg("SS - +CSSU indication");
		cssu = TRUE;
	} else if (!strcmp(buf, "+CSSI")) {
		dbg("SS - +CSSI indication");
		cssi = TRUE;
	}
	free(buf);

	// handle %CSSU notification
	if (cssu) {
		tokens = tcore_at_tok_new(cmd);
		// parse <code2>
		str_code2 = g_slist_nth_data(tokens, 0);
		if (!str_code2) {
			dbg("Code2 is missing from %CSSU indiaction");
		} else {
			code2 = atoi(str_code2);
			// parse [ <index>, <number> <type>]
			if ((str_index = g_slist_nth_data(tokens, 1))) {
				index = atoi(str_index);
			}

			if ((resp = g_slist_nth_data(tokens, 2))) {
				// Strike off double quotes
				number = util_removeQuotes(resp);
				str_ton = g_slist_nth_data(tokens, 3);

				if (str_ton) {
					ton = atoi(str_ton);
				}
			}
		}

		dbg("CSSU - code2 = %d index = %d number = %s type = %d", code2, index, number, ton);
		switch (code2) {
		case 0:      // this is a forwarded call (MT call setup)
			tcore_call_information_mt_forwarded_call(co, number);
			break;

		case 2:     // call has been put on hold (during a voice call)
			tcore_call_information_held(co, number);
			break;

		case 3:     // call has been retrieved (during a voice call)
			tcore_call_information_active(co, number);
			break;

		case 4:     // multiparty call entered (during a voice call)
			tcore_call_information_joined(co, number);
			break;

		case 5:     // call on hold has been released
			tcore_call_information_released_on_hold(co, number);
			break;

		case 6:     // forward check SS message received (can be received whenever)
			tcore_call_information_cf_check_ss_message(co, number);
			break;

		case 7:     // call is being connected (alerting) with the remote party in alerting state in explicit call transfer operation (during a voice call)
			tcore_call_information_transfer_alert(co, number);
			break;

		case 8:     // call has been connected with the other remote party in explicit call transfer operation (also number and subaddress parameters may be present) (during a voice call or MT call setup)
			tcore_call_information_transfered(co, number);
			break;

		case 9:     // this is a deflected call (MT call setup):
			tcore_call_information_mt_deflected_call(co, number);
			break;

		default:
			dbg("CSSU - unsupported code2 : %d", code2);
			break;
		}
	}
	// handle %CSSI notification

	if (cssi) {
		tokens = tcore_at_tok_new(cmd);
		// parse <code1>
		str_code1 = g_slist_nth_data(tokens, 0);
		if (!str_code1) {
			dbg("Code1 is missing from %CSSI indiaction");
		} else {
			code1 = atoi(str_code1);
			// parse [ <index> ]
			if ((str_index = g_slist_nth_data(tokens, 1))) {
				index = atoi(str_index);
			}
		}

		dbg("CSSI - code1 - %d index - %d ", code1, index);

		switch (code1) {
		case 0:      // Unconditional CF is active
			tcore_call_information_mo_cfu(co);
			break;

		case 1:         // some of the conditional call forwarding are active
			tcore_call_information_mo_cfc(co);
			break;

		case 2:        // outgoing call is forwarded
			tcore_call_information_mo_forwarded(co);
			break;

		case 3:         // this call is waiting
			tcore_call_information_mo_waiting(co);
			break;

		case 5:         // outgoing call is barred
			tcore_call_information_mo_barred_outgoing(co);
			break;

		case 6:         // incoming call is barred
			tcore_call_information_mo_barred_incoming(co);
			break;

		case 7:         // CLIR suppression rejected
			tcore_call_information_mo_clir_suppression_reject(co);
			break;

		case 8:         // outgoing call is deflected
			tcore_call_information_mo_deflected(co);
			break;

		default:
			dbg("unsupported cmd : %d", code1);
			break;
		}
	}
OUT:
	if (NULL != tokens) {
		tcore_at_tok_free(tokens);
	}

	g_free(number);
	return TRUE;
}

static void on_confirmation_ss_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("");

	if (result == FALSE) {
		// Fail
		dbg("FAIL");
	} else {
		dbg("SEND OK");
	}
}

static void on_response_ss_barring_set(TcorePending *p, int data_len, const void *data, void *user_data)
{
	struct ss_confirm_info *info = 0;
	enum telephony_ss_class class;
	CoreObject *o = 0;
	UserRequest *ur;
	struct tresp_ss_barring resp = {0, };
	UserRequest *ur_dup = 0;
	GSList *tokens = NULL;
	const char *line;
	int error;
	const TcoreATResponse *response;

	dbg("function enter");
	response = data;
	o = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	info = (struct ss_confirm_info *)user_data;
	class = info->class;

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");
		line = (const char *)response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", error);
			/* TODO: CMEE error mapping is required. */
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}
		tcore_at_tok_free(tokens);
	}

	dbg("on_response_ss_barring_set - rsp.err : %d, ur : %x flavor_type = %d", resp.err, ur, info->flavor_type);
	dbg("[ check ] class : 0x%x", info->class);

	if (response->success > 0) {
		if (info->class == SS_CLASS_VOICE) {
			class = SS_CLASS_ALL_TELE_BEARER;
		}

		ur_dup = tcore_user_request_ref(ur);

		if (info->flavor_type == SS_BARR_MODE_AB || info->flavor_type == SS_BARR_MODE_AOB) {
			_ss_barring_get(o, ur_dup, class, SS_BARR_MODE_BAOC, info->resp);
		} else if (info->flavor_type == SS_BARR_MODE_AIB) {
			_ss_barring_get(o, ur_dup, class, SS_BARR_MODE_BAIC, info->resp);
		} else {
			_ss_barring_get(o, ur_dup, class, info->flavor_type, info->resp);
		}
	} else {
		if (ur) {
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_barring), &resp);
		} else {
			dbg("[ error ] ur is 0");
		}
	}
	g_free(user_data);
}

static void on_response_ss_barring_change_pwd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *response = data;
	struct ss_confirm_info *info = 0;
	UserRequest *ur;
	struct tresp_ss_general resp;
	int error;
	GSList *tokens = NULL;
	const char *line;

	dbg("function enter");
	ur = tcore_pending_ref_user_request(p);
	info = (struct ss_confirm_info *) user_data;

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", error);
			// TODO: CMEE error mapping is required.
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}
		tcore_at_tok_free(tokens);
	}

	dbg("on_response_ss_barring_change_pwd: rsp.err : %d, usr : %x", resp.err, ur);
	if (ur) {
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_general), &resp);
	} else {
		dbg("[ error ] ur is 0");
	}

	g_free(user_data);
}

static void on_response_ss_forwarding_set(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *o = 0;
	UserRequest *ur = 0, *dup_ur = 0;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_forwarding resp = {0,};
	GSList *tokens = NULL;
	const char *line;
	int error;
	const TcoreATResponse *response;

	dbg("function enter");

	response = data;
	o = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	info = (struct ss_confirm_info *) user_data;

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");

		/* Extract Error */
		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("Error cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", error);
			// / TODO: CMEE error mapping is required.
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}

		tcore_at_tok_free(tokens);
	}

	dbg("[ check ] class : 0x%x", info->class);
	dbg("[ check ] flavor_type : 0x%x", info->flavor_type);

	dbg("on_response_ss_forwarding_set - rsp.err : %d, ur : %x", resp.err, ur);

	if (response->success > 0) {
		if (info->flavor_type == SS_CF_MODE_CF_ALL ||
			info->flavor_type == SS_CF_MODE_CFC) {
			if (ur) {
				tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_forwarding), &resp);
			} else {
				dbg("[ error ] ur is 0");
			}
		} else {
			dup_ur = tcore_user_request_ref(ur);
			_ss_forwarding_get(o, dup_ur, info->class, info->flavor_type, info->resp);
		}
	} else {
		if (ur) {
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_forwarding), &resp);
		} else {
			dbg("[ error ] ur is 0");
		}
	}
	g_free(user_data);
}

static void on_response_ss_waiting_set(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *core_obj = 0;
	UserRequest *ur = 0;
	UserRequest *ur_dup = 0;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_waiting resp = {0,};
	GSList *tokens = NULL;
	const char *line;
	int error;
	const TcoreATResponse *response;

	dbg("function enter");
	response = data;
	core_obj = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	info = (struct ss_confirm_info *)user_data;

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");

		/* Extract Error */
		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("Error cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", error);
			/* TODO: CMEE error mapping is required. */
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}

		/* Free tokens */
		tcore_at_tok_free(tokens);
	}

	dbg("Call Waiting - Error: [%d], UR: [0x%x] class: [0x%2x]", resp.err, ur, info->class);
	if (resp.err == SS_ERROR_NONE) {
		ur_dup = tcore_user_request_ref(ur);

		dbg("Get Call Waiting status");
		_ss_waiting_get(core_obj, ur_dup, info->class, info->resp);
	} else {
		if (ur) {
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_waiting), &resp);
		} else {
			err("User request is NULL");
		}
	}
	g_free(user_data);
}


static void on_confirmation_ss_ussd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *core_obj = 0;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_ussd resp;
	UserRequest *ur = NULL, *ussd_ur = NULL;
	GSList *tokens = NULL;
	const char *line;
	int error;
	UssdSession *ussd_s = NULL;
	enum tcore_ss_ussd_type type = TCORE_SS_USSD_TYPE_MAX;
	const TcoreATResponse *response;

	dbg("function enter");
	response = data;
	ur = tcore_pending_ref_user_request(p);
	info = (struct ss_confirm_info *) user_data;

	memset(resp.str, 0x00, MAX_SS_USSD_LEN);

	core_obj = tcore_pending_ref_core_object(p);
	ussd_s = tcore_ss_ussd_get_session(core_obj);

	if (ussd_s)
		type = tcore_ss_ussd_get_session_type(ussd_s);
	else
		dbg("[ error ] ussd_s : (0)");

	resp.type = (enum telephony_ss_ussd_type) type;
	resp.status = SS_USSD_MAX; // hardcoded value.

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", error);
			// TODO: CMEE error mapping is required.
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}
		tcore_at_tok_free(tokens);
	}

	dbg("on_confirmation_ss_ussd - rsp.err : %d, ur : %x", resp.err, ur);

	if (response->success > 0) {
		if (type == TCORE_SS_USSD_TYPE_USER_INITIATED) {
			dbg("ussd type %d", resp.type);

			if (ussd_s) {
				tcore_ss_ussd_get_session_data(ussd_s, (void **) &ussd_ur);
				if (ussd_ur)
					tcore_user_request_free(ussd_ur);
			}
		}
	}

	if (ussd_s)
		tcore_ss_ussd_destroy_session(ussd_s);

	if (ur) {
		if (UssdResp == FALSE) { // to avoid sending multiple response to application.
			tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_ussd), &resp);
		}
		UssdResp = FALSE;
	} else
		dbg("[ error ] ur : (0)");

	g_free(user_data);
}

static void on_response_ss_barring_get(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = 0;
	int status = 0, classx = 0, ss_err = 0;
	GSList *respdata;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_barring resp;
	int countRecords = 0, countValidRecords = 0;
	GSList *tokens = NULL;
	const char *line;
	char *classx_str;
	char *stat = NULL;
	const TcoreATResponse *response;

	dbg("function enter");

	response = data;
	ur = tcore_pending_ref_user_request(p);
	info = (struct ss_confirm_info *) user_data;

	if (response->lines) {
		respdata = (GSList *) response->lines;
		countRecords = g_slist_length(respdata);
		dbg("total records : %d", countRecords);
	} else {
		countRecords = 0;
		dbg("no active status - return to user");
	}
	resp.record_num = countRecords;
	resp.record = 0;
	if (resp.record_num > 0) {
		resp.record = g_new0(struct barring_info, resp.record_num);
		for (countValidRecords = 0; respdata != NULL; respdata = respdata->next) {
			line = (const char *) (respdata->data);
			tokens = tcore_at_tok_new(line);

			// parse <status>
			stat = g_slist_nth_data(tokens, 0);
			if (!stat) {
				dbg("Stat is missing");
				goto error;
			}

			status = atoi(stat);
			if (status == 1) {
				resp.record[countValidRecords].status = SS_STATUS_ACTIVATE;
			} else {
				resp.record[countValidRecords].status = SS_STATUS_DEACTIVATE;
			}
			dbg("call barring status - %d", status);

			// Parse <class>
			classx_str = g_slist_nth_data(tokens, 1);

			if (!classx_str) {
				dbg("class error. classx not exist - set to requested one : %d", info->class);
				switch (info->class) {
				case SS_CLASS_ALL_TELE:
					classx = 7;
					break;

				case SS_CLASS_VOICE:
					classx = 1;
					break;

				case SS_CLASS_ALL_DATA_TELE:
					classx = 2;
					break;

				case SS_CLASS_FAX:
					classx = 4;
					break;

				case SS_CLASS_SMS:
					classx = 8;
					break;

				case SS_CLASS_ALL_CS_SYNC:
					classx = 16;
					break;

				default:
					classx = 7;
					dbg("unsupported class %d. set to default : 7", info->class);
					break;
				}
			} else {
				classx = atoi(classx_str);
				dbg("call barring classx - %d", classx);
			}

			switch (classx) {
			case 1:
				resp.record[countValidRecords].class = SS_CLASS_VOICE;
				break;

			case 2:
				resp.record[countValidRecords].class = SS_CLASS_ALL_DATA_TELE;
				break;

			case 4:
				resp.record[countValidRecords].class = SS_CLASS_FAX;
				break;

			case 7:
				resp.record[countValidRecords].class = SS_CLASS_ALL_TELE;
				break;

			case 8:
				resp.record[countValidRecords].class = SS_CLASS_SMS;
				break;

			case 16:
				resp.record[countValidRecords].class = SS_CLASS_ALL_CS_SYNC;
				break;

			case 32:
				resp.record[countValidRecords].class = SS_CLASS_ALL_CS_ASYNC;
				break;

			default:
				dbg("unspoorted class : [%d]\n", classx);
				goto error;
				break;
			}
			resp.record[countValidRecords].mode = (enum telephony_ss_barring_mode) (info->flavor_type);
			countValidRecords++;
			tcore_at_tok_free(tokens);
			continue;

error:
			dbg("invalid field found. coutinue");
			tcore_at_tok_free(tokens);
			continue;
		}

		dbg("valid count :%d", countValidRecords);
		resp.record_num = countValidRecords;
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("no active status - return to user");
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");
		resp.err = TCORE_RETURN_FAILURE;
		resp.record = 0;
		resp.record_num = 0;

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			ss_err = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", ss_err);
			// TODO: CMEE error mapping is required.
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}
		tcore_at_tok_free(tokens);
	}

	dbg("on_response_ss_barring_get- rsp.err : %d, ur : %x", resp.err, ur);

	if (ur)
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_barring), &resp);
	else
		dbg("[ error ] ur is 0");

	if (resp.record) {
		g_free(resp.record);
		resp.record = NULL;
	}

	g_free(user_data);
}

static void on_response_ss_forwarding_get(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = 0;
	int classx = 0, ss_err = 0, time = 0;
	char *num;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_forwarding resp;
	int countRecords = 0, countValidRecords = 0;

	GSList *respdata = NULL, *tokens = NULL;
	const char *line;
	char *classx_str, *status, *ton, *time_str;
	const TcoreATResponse *response;

	dbg("function enter");
	response = data;

	ur = tcore_pending_ref_user_request(p);
	info = (struct ss_confirm_info *) user_data;
	if (response->lines) {
		respdata = (GSList *) response->lines;
		countRecords = g_slist_length(respdata);
		dbg("total records : %d", countRecords);
	} else {
		countRecords = 0;
		dbg("no active status - return to user");
	}
	resp.record_num = countRecords;
	resp.record = 0;
	if (resp.record_num > 0) {
		resp.record = g_new0(struct forwarding_info, resp.record_num);

		for (countValidRecords = 0; respdata != NULL; respdata = respdata->next) {
			line = (const char *) (respdata->data);
			tokens = tcore_at_tok_new(line);

			// parse <status>
			status = g_slist_nth_data(tokens, 0);
			if (!status) {
				dbg("start line error. skip this line");
				goto error;
			} else {
				if (atoi(status) == 1) {
					resp.record[countValidRecords].status = SS_STATUS_ACTIVATE;
				} else {
					resp.record[countValidRecords].status = SS_STATUS_DEACTIVATE;
				}
			}

			// Parse <class>
			classx_str = g_slist_nth_data(tokens, 1);
			if (!classx_str) {
				dbg("class error. skip this line");
				goto error;
			} else {
				switch (atoi(classx_str)) {
				case 1:
					resp.record[countValidRecords].class = SS_CLASS_VOICE;
					break;

				case 2:
					resp.record[countValidRecords].class = SS_CLASS_ALL_DATA_TELE;
					break;

				case 4:
					resp.record[countValidRecords].class = SS_CLASS_FAX;
					break;

				case 7:
					resp.record[countValidRecords].class = SS_CLASS_ALL_TELE;
					break;

				case 8:
					resp.record[countValidRecords].class = SS_CLASS_SMS;
					break;

				case 16:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_SYNC;
					break;

				case 32:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_ASYNC;
					break;

				default:
					dbg("unspoorted class : [%d]\n", classx);
					goto error;
					break;
				}
			}

			// parse  <numer> <type>
			num = g_slist_nth_data(tokens, 2);
			if (num) {
				dbg("number  - %s", num);
				memcpy((resp.record[countValidRecords].number), num, strlen(num));
				resp.record[countValidRecords].number_present = TRUE;

				ton = g_slist_nth_data(tokens, 3);
				if (ton) {
					resp.record[countValidRecords].ton = atoi(ton);
					dbg("number  type - %d", resp.record[countValidRecords].ton);
				}
			}

			// skip  <subaddr> <satype>
			// parse  <time>
			time_str = g_slist_nth_data(tokens, 6);
			if (time_str) {
				time = atoi(time_str);
				resp.record[countValidRecords].time = (enum telephony_ss_forwarding_no_reply_time) time;
				dbg("time  - %d", time);
			}

			resp.record[countValidRecords].mode = (enum telephony_ss_forwarding_mode) (info->flavor_type);
			dbg("flavor_type  - %d", (enum telephony_ss_forwarding_mode) (info->flavor_type));

			countValidRecords++;
			tcore_at_tok_free(tokens);
			continue;
error:
			dbg("invalid field found. coutinue");
			tcore_at_tok_free(tokens);
			continue;
		}
		dbg("valid count :%d", countValidRecords);
		resp.record_num = countValidRecords;
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("no active status - return to user");
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");
		resp.record = 0;
		resp.record_num = 0;
		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			ss_err = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", ss_err);
			/* TODO: CMEE error mapping is required. */
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}
		tcore_at_tok_free(tokens);
	}

	dbg("on_response_ss_forwarding_get- rsp.err : %d, ur : %x", resp.err, ur);
	if (ur)
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_forwarding), &resp);
	else
		dbg("[ error ] ur is 0");

	if (resp.record) {
		g_free(resp.record);
		resp.record = NULL;
	}
	g_free(user_data);
}

static void on_response_ss_waiting_get(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = 0;
	GSList *respdata, *tokens = NULL;
	int classx = 0, ss_err = 0;
	struct ss_confirm_info *info = 0;
	struct tresp_ss_waiting resp;
	int countRecords = 0, countValidRecords = 0;
	const char *line;
	char *classx_str, *status;
	const TcoreATResponse *response;

	dbg("function enter");
	response = data;
	ur = tcore_pending_ref_user_request(p);
	info = (struct ss_confirm_info *) user_data;

	if (response->lines) {
		respdata = (GSList *) response->lines;
		countRecords = g_slist_length(respdata);
		dbg("total records : %d", countRecords);
	} else {
		countRecords = 0;
		dbg("no active status - return to user");
	}
	resp.record_num = countRecords;
	resp.record = 0;

	if (resp.record_num > 0) {
		resp.record = g_new0(struct waiting_info, resp.record_num);

		for (countValidRecords = 0; respdata != NULL; respdata = respdata->next) {
			line = (const char *) (respdata->data);
			tokens = tcore_at_tok_new(line);

			// parse <status>
			status = g_slist_nth_data(tokens, 0);
			if (!status) {
				dbg("Missing stat  in responce ");
				goto error;
			} else {
				if (atoi(status) == 1) {
					resp.record[countValidRecords].status = SS_STATUS_ACTIVATE;
				} else {
					resp.record[countValidRecords].status = SS_STATUS_DEACTIVATE;
				}
			}
			dbg("status = %d", resp.record[countValidRecords].status);

			// Parse <class>
			classx_str = g_slist_nth_data(tokens, 1);
			if (!classx_str) {
				dbg("error - class is missing");
				goto error;
			} else {
				switch (atoi(classx_str)) {
				case 1:
					resp.record[countValidRecords].class = SS_CLASS_VOICE;
					break;

				case 2:
					resp.record[countValidRecords].class = SS_CLASS_ALL_DATA_TELE;
					break;

				case 4:
					resp.record[countValidRecords].class = SS_CLASS_FAX;
					break;

				case 7:
					resp.record[countValidRecords].class = SS_CLASS_ALL_TELE;
					break;

				case 8:
					resp.record[countValidRecords].class = SS_CLASS_SMS;
					break;

				case 16:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_SYNC;
					break;

				case 32:
					resp.record[countValidRecords].class = SS_CLASS_ALL_CS_ASYNC;
					break;

				default:
					dbg("unspoorted class : [%d]\n", classx);
					goto error;
					break;
				}
				dbg("class info %d", resp.record[countValidRecords].class);
			}

			countValidRecords++;
			tcore_at_tok_free(tokens);
			continue;
error:
			dbg("invalid field found. coutinue");
			tcore_at_tok_free(tokens);
			continue;
		}

		dbg("valid count :%d", countValidRecords);
		resp.record_num = countValidRecords;
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("no active status - return to user");
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");
		resp.record = 0;
		resp.record_num = 0;
		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			ss_err = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", ss_err);
			// TODO: CMEE error mapping is required.
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}
		tcore_at_tok_free(tokens);
	}

	dbg("on_response_ss_waiting_get - rsp.err : %d, ur : %x", resp.err, ur);
	if (ur)
		tcore_user_request_send_response(ur, info->resp, sizeof(struct tresp_ss_waiting), &resp);
	else
		dbg("[ error ] ur is 0");

	if (resp.record) {
		g_free(resp.record);
		resp.record = NULL;
	}
	g_free(user_data);
}


static void on_response_ss_cli_get(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = 0;
	struct tresp_ss_cli resp;
	enum telephony_ss_cli_type *p_type = NULL;
	char *line = NULL, *status;
	int error = FALSE;
	int cli_adj, stat;
	GSList *tokens = NULL;
	const TcoreATResponse *response;

	dbg("function enter");
	response = data;
	ur = tcore_pending_ref_user_request(p);
	p_type = (enum telephony_ss_cli_type *) (user_data);

	if (response->success > 0) {
		line = (char *) (((GSList *) response->lines)->data);
		tokens = tcore_at_tok_new(line);

		if (*p_type == SS_CLI_TYPE_CLIR) {
			// +CLIR: <n> <m>
			dbg("CLI type is CLIR");
			// parse <n>
			status = g_slist_nth_data(tokens, 0);

			if (!status) {
				dbg("Call line identification adjustment missing <n>");
			} else {
				cli_adj = atoi(status);
				dbg("CLIR response value of <n> - %d", cli_adj);

				if (cli_adj == 0) {
					// parse <m>
					status = g_slist_nth_data(tokens, 1);
					if (!status) {
						dbg("status is missing<m>");
					}
					stat = atoi(status);
					dbg("CLIR response value of <m> - %d", stat);

					if (stat == 1 || stat == 3) {
						resp.status = TRUE;
					} else {
						resp.status = FALSE;
					}
				} else if (cli_adj == 1) {
					resp.status = TRUE;
				} else {
					resp.status = FALSE;
				}
				dbg("resp.status -  %d", resp.status);
			}
			tcore_at_tok_free(tokens);
		} else {
			// parse <n>
			status = g_slist_nth_data(tokens, 0);
			if (!status) {
				dbg("Stat is missing");
			} else {
				stat = atoi(status);
				if (stat == 1)
					resp.status = TRUE;
				else
					resp.status = FALSE;

				dbg("resp.status -  %d", resp.status);
			}
			tcore_at_tok_free(tokens);
		}
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");
		resp.err = SS_ERROR_NONE;
	} else {
		dbg("RESPONSE NOT OK");

		line = (char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			resp.err = SS_ERROR_SYSTEMFAILURE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));
			err("Error: [%d]", error);
			// TODO: CMEE error mapping is required.
			resp.err = SS_ERROR_SYSTEMFAILURE;
		}
		tcore_at_tok_free(tokens);
	}

	resp.type = *p_type;
	dbg("check - resp.type = %d ", resp.type);
	if (ur)
		tcore_user_request_send_response(ur, TRESP_SS_CLI_GET_STATUS, sizeof(struct tresp_ss_cli), &resp);
	else
		dbg("[ error ] ur : (0)");

	g_free(user_data);
}

static struct tcore_ss_operations ss_ops = {
	.barring_activate = imc_ss_barring_activate,
	.barring_deactivate = imc_ss_barring_deactivate,
	.barring_change_password = imc_ss_barring_change_password,
	.barring_get_status = imc_ss_barring_get_status,
	.forwarding_activate = imc_ss_forwarding_activate,
	.forwarding_deactivate = imc_ss_forwarding_deactivate,
	.forwarding_register = imc_ss_forwarding_register,
	.forwarding_deregister = imc_ss_forwarding_deregister,
	.forwarding_get_status = imc_ss_forwarding_get_status,
	.waiting_activate = imc_ss_waiting_activate,
	.waiting_deactivate = imc_ss_waiting_deactivate,
	.waiting_get_status = imc_ss_waiting_get_status,
	.cli_activate = imc_ss_cli_activate,
	.cli_deactivate = imc_ss_cli_deactivate,
	.cli_get_status = imc_ss_cli_get_status,
	.send_ussd = imc_ss_send_ussd,
	.set_aoc = imc_ss_set_aoc,
	.get_aoc = imc_ss_get_aoc,
};


static TReturn _ss_barring_set(CoreObject *o, UserRequest *ur, enum telephony_ss_opcode op)
{
	struct treq_ss_barring *barring = 0;
	struct ss_confirm_info *user_data = 0;
	char *cmd_str = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req;
	char passwd[MAX_SS_BARRING_PASSWORD_LEN + 1];
	int opco;
	int classx;
	char *facility = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	barring = (struct treq_ss_barring *) tcore_user_request_ref_data(ur, 0);

	switch (op) {
	case SS_OPCO_ACTIVATE:
		opco = 1;
		break;

	case SS_OPCO_DEACTIVATE:
		opco = 0;
		break;

	default:
		dbg("unsupported opco : %d", op);
		return TCORE_RETURN_FAILURE;
	}
	dbg("opco - %d", opco);

	switch (barring->mode) {
	case SS_BARR_MODE_BAOC:
		facility = "AO";
		break;

	case SS_BARR_MODE_BOIC:
		facility = "OI";
		break;

	case SS_BARR_MODE_BOIC_NOT_HC:
		facility = "OX";
		break;

	case SS_BARR_MODE_BAIC:
		facility = "AI";
		break;

	case SS_BARR_MODE_BIC_ROAM:
		facility = "IR";
		break;

	case SS_BARR_MODE_AB:
		facility = "AB";
		break;

	case SS_BARR_MODE_AOB:
		facility = "AG";
		break;

	case SS_BARR_MODE_AIB:
		facility = "AC";
		break;

	case SS_BARR_MODE_BIC_NOT_SIM:
	// facility = "NS";
	default:
		dbg("unspported mode %d", barring->mode);
		return TCORE_RETURN_FAILURE;
	}

	dbg("facility - %s", facility);

	switch (barring->class) {
	case SS_CLASS_ALL_TELE:
		classx = 7;
		break;

	case SS_CLASS_VOICE:
		classx = 1;
		break;

	case SS_CLASS_ALL_DATA_TELE:
		classx = 2;
		break;

	case SS_CLASS_FAX:
		classx = 4;
		break;

	case SS_CLASS_SMS:
		classx = 8;
		break;

	case SS_CLASS_ALL_CS_SYNC:
		classx = 16;
		break;

	default:
		classx = 7;
		dbg("unsupported class %d. set to default : 7", barring->class);
		break;
	}

	dbg("classx - %d", classx);

	user_data = g_new0(struct ss_confirm_info, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		return TCORE_RETURN_ENOMEM;
	}

	// null-ended pwd handling added - unexpected  0x11 value observed in req string
	memcpy(passwd, barring->password, MAX_SS_BARRING_PASSWORD_LEN);
	passwd[MAX_SS_BARRING_PASSWORD_LEN] = '\0';
	dbg("passwd - %s", passwd);

	pending = tcore_pending_new(o, 0);

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\",%d,\"%s\",%d", facility, opco, passwd, classx);
	dbg("request command : %s", cmd_str);

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	if (op == SS_OPCO_ACTIVATE) {
		user_data->resp = TRESP_SS_BARRING_ACTIVATE;
	} else if (op == SS_OPCO_DEACTIVATE) {
		user_data->resp = TRESP_SS_BARRING_DEACTIVATE;
	} else {
		dbg("[ error ] wrong ss opco (0x%x)", op);
		if (user_data != NULL) {
			g_free(user_data);
		}
		g_free(cmd_str);
		tcore_pending_free(pending);
		tcore_at_request_free(req);
		return TCORE_RETURN_FAILURE;
	}
	user_data->flavor_type = (int) (barring->mode);
	user_data->class = barring->class;

	ret = _ss_request_message(pending, o, ur, on_response_ss_barring_set, user_data);
	g_free(cmd_str);

	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
			tcore_pending_free(pending);
			tcore_at_request_free(req);
		}
		return TCORE_RETURN_FAILURE;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn _ss_barring_get(CoreObject *o,
							   UserRequest *ur,
							   enum telephony_ss_class class,
							   enum telephony_ss_barring_mode mode,
							   enum tcore_response_command resp)
{
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;
	char *cmd_str = NULL;
	int opco, classx;
	char *facility = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req;

	dbg("function enter");

	// query status - opco is fixed to 2
	opco = 2;
	// barring mode
	switch (mode) {
	case SS_BARR_MODE_BAOC:
		facility = "AO";
		break;

	case SS_BARR_MODE_BOIC:
		facility = "OI";
		break;

	case SS_BARR_MODE_BOIC_NOT_HC:
		facility = "OX";
		break;

	case SS_BARR_MODE_BAIC:
		facility = "AI";
		break;

	case SS_BARR_MODE_BIC_ROAM:
		facility = "IR";
		break;

	case SS_BARR_MODE_AB:
	case SS_BARR_MODE_AOB:
	case SS_BARR_MODE_AIB:
	case SS_BARR_MODE_BIC_NOT_SIM:
	default:
		dbg("unsupported mode %d", mode);
		return TCORE_RETURN_FAILURE;
	}

	dbg("facility - %s", facility);

	switch (class) {
	case SS_CLASS_ALL_TELE:
		classx = 7;
		break;

	case SS_CLASS_VOICE:
		classx = 1;
		break;

	case SS_CLASS_ALL_DATA_TELE:
		classx = 2;
		break;

	case SS_CLASS_FAX:
		classx = 4;
		break;

	case SS_CLASS_SMS:
		classx = 8;
		break;

	case SS_CLASS_ALL_CS_SYNC:
		classx = 16;
		break;

	default:
		classx = 7;
		dbg("unsupported class %d. set to default : 7", class);
		break;
	}

	user_data = g_new0(struct ss_confirm_info, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		return TCORE_RETURN_ENOMEM;
	}

	dbg("class - %d", classx);
	if (classx == 7)
		cmd_str = g_strdup_printf("AT+CLCK=\"%s\",%d", facility, opco);
	else
		cmd_str = g_strdup_printf("AT+CLCK=\"%s\",%d,,%d", facility, opco, classx);

	dbg("request command : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, "+CLCK", TCORE_AT_MULTILINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	user_data->resp = resp;
	user_data->flavor_type = (int) (mode);
	user_data->class = class;

	ret = _ss_request_message(pending, o, ur, on_response_ss_barring_get, user_data);
	g_free(cmd_str);

	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
			tcore_pending_free(pending);
			tcore_at_request_free(req);
		}
		return TCORE_RETURN_FAILURE;
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_barring_activate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_barring_set(o, ur, SS_OPCO_ACTIVATE);
}

static TReturn imc_ss_barring_deactivate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_barring_set(o, ur, SS_OPCO_DEACTIVATE);
}

static TReturn imc_ss_barring_change_password(CoreObject *o, UserRequest *ur)
{
	TcorePending *pending = NULL;
	TcoreATRequest *req;
	struct treq_ss_barring_change_password *barring = 0;
	struct ss_confirm_info *user_data = 0;
	char *cmd_str = NULL;
	gboolean ret = FALSE;
	char old_password[MAX_SS_BARRING_PASSWORD_LEN + 1];
	char new_password[MAX_SS_BARRING_PASSWORD_LEN + 1];

	dbg("function enter");

	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	barring = (struct treq_ss_barring_change_password *) tcore_user_request_ref_data(ur, 0);

	if (barring->password_old == NULL || barring->password_new == NULL) {
		dbg("[error]password is null");
		return TCORE_RETURN_FAILURE;
	}
	memcpy(old_password, barring->password_old, MAX_SS_BARRING_PASSWORD_LEN);
	old_password[MAX_SS_BARRING_PASSWORD_LEN] = '\0';
	memcpy(new_password, barring->password_new, MAX_SS_BARRING_PASSWORD_LEN);
	new_password[MAX_SS_BARRING_PASSWORD_LEN] = '\0';

	user_data = g_new0(struct ss_confirm_info, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		return TCORE_RETURN_ENOMEM;
	}
	user_data->resp = TRESP_SS_BARRING_CHANGE_PASSWORD;

	dbg("old passwd - %s new passwd- %s", old_password, new_password);
	cmd_str = g_strdup_printf("AT+CPWD=\"%s\",\"%s\",\"%s\"", "AB", old_password, new_password);
	dbg("request command : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	ret = _ss_request_message(pending, o, ur, on_response_ss_barring_change_pwd, user_data);
	g_free(cmd_str);
	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
		}
		tcore_pending_free(pending);
		tcore_at_request_free(req);
		return TCORE_RETURN_FAILURE;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_barring_get_status(CoreObject *o, UserRequest *ur)
{
	struct treq_ss_barring *barring = 0;

	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	barring = (struct treq_ss_barring *) tcore_user_request_ref_data(ur, 0);

	return _ss_barring_get(o, ur, barring->class, barring->mode, TRESP_SS_BARRING_GET_STATUS);
}

static TReturn _ss_forwarding_set(CoreObject *o, UserRequest *ur, enum telephony_ss_opcode op)
{
	struct treq_ss_forwarding *forwarding = 0;
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;
	int len = 0;
	char *cmd_str = NULL;
	char *tmp_str = NULL;
	int reason = 0, mode = 0, num_type = 0, classx = 0, time = 0;
	TcorePending *pending = NULL;
	TcoreATRequest *req;

	dbg("_ss_forwarding_set with opco %d ", op);

	forwarding = (struct treq_ss_forwarding *) tcore_user_request_ref_data(ur, 0);
	switch (forwarding->mode) {
	case SS_CF_MODE_CFU:
		reason = 0;
		break;

	case SS_CF_MODE_CFB:
		reason = 1;
		break;

	case SS_CF_MODE_CFNRy:
		reason = 2;
		break;

	case SS_CF_MODE_CFNRc:
		reason = 3;
		break;

	case SS_CF_MODE_CF_ALL:
		reason = 4;
		break;

	case SS_CF_MODE_CFC:
		reason = 5;
		break;

	default:
		dbg("unsupported reason : %d");
		return TCORE_RETURN_FAILURE;
		break;
	}

	dbg("reason = %d", reason);
	switch (op) {
	case SS_OPCO_DEACTIVATE:
		mode = 0;
		break;

	case SS_OPCO_ACTIVATE:
		mode = 1;
		break;

	case SS_OPCO_REG:
		mode = 3;
		break;

	case SS_OPCO_DEREG:
		mode = 4;
		break;

	default:
		dbg("unsupported opco : %d", op);
		return TCORE_RETURN_FAILURE;
	}

	dbg("mode = %d", mode);

	// class
	switch (forwarding->class) {
	case SS_CLASS_ALL_TELE:
		classx = 7;
		break;

	case SS_CLASS_VOICE:
		classx = 1;
		break;

	case SS_CLASS_ALL_DATA_TELE:
		classx = 2;
		break;

	case SS_CLASS_FAX:
		classx = 4;
		break;

	case SS_CLASS_SMS:
		classx = 8;
		break;

	case SS_CLASS_ALL_CS_SYNC:
		classx = 16;
		break;

	default:
		classx = 7;
		dbg("unsupported class %d. set to default : 7", forwarding->class);
		break;
	}
	dbg("classx = %d", classx);

	// number
	len = strlen(forwarding->number);
	if (len > 0) {
		if (forwarding->number[0] == '+')
			num_type = ((NUM_TYPE_INTERNATIONAL << 4) | NUM_PLAN_ISDN);
		else
			num_type = 0;
	}
	dbg("number = %s", forwarding->number);

	user_data = g_new0(struct ss_confirm_info, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		return TCORE_RETURN_ENOMEM;
	}

	switch (op) {
	case SS_OPCO_REG:
		user_data->resp = TRESP_SS_FORWARDING_REGISTER;
		break;

	case SS_OPCO_DEREG:
		user_data->resp = TRESP_SS_FORWARDING_DEREGISTER;
		break;

	case SS_OPCO_ACTIVATE:
		user_data->resp = TRESP_SS_FORWARDING_ACTIVATE;
		break;

	case SS_OPCO_DEACTIVATE:
		user_data->resp = TRESP_SS_FORWARDING_DEACTIVATE;
		break;

	default:
		dbg("[ error ] unknown op (0x%x)", op);
		break;
	}

	if (forwarding->number[0] == '+')
		num_type = 145;
	else
		num_type = 129;

	if (op == SS_OPCO_REG)
		tmp_str = g_strdup_printf("AT+CCFC=%d,%d,\"%s\",%d,%d", reason, mode, forwarding->number, num_type, classx);
	else // other opcode does not need num field
		tmp_str = g_strdup_printf("AT+CCFC=%d,%d,,,%d", reason, mode, classx);

	if (forwarding->mode == SS_CF_MODE_CFNRy) {
		// add time info to 'no reply' case
		time = (int) (forwarding->time);
		cmd_str = g_strdup_printf("%s,,,%d", tmp_str, time);
	} else {
		cmd_str = g_strdup_printf("%s", tmp_str);
	}

	dbg("request command : %s", cmd_str);
	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	user_data->flavor_type = forwarding->mode;
	user_data->class = forwarding->class;

	ret = _ss_request_message(pending, o, ur, on_response_ss_forwarding_set, user_data);

	g_free(tmp_str);
	g_free(cmd_str);

	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
		}
		return TCORE_RETURN_FAILURE;
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn _ss_forwarding_get(CoreObject *o,
								  UserRequest *ur,
								  enum telephony_ss_class class,
								  enum telephony_ss_forwarding_mode type,
								  enum tcore_response_command resp)
{
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;
	char *cmd_str = NULL;
	int reason = 0, mode = 0, classx = 0;
	TcorePending *pending = NULL;
	TcoreATRequest *req;

	dbg("function enter");

	switch (type) {
	case SS_CF_MODE_CFU:
		reason = 0;
		break;

	case SS_CF_MODE_CFB:
		reason = 1;
		break;

	case SS_CF_MODE_CFNRy:
		reason = 2;
		break;

	case SS_CF_MODE_CFNRc:
		reason = 3;
		break;

	case SS_CF_MODE_CF_ALL:
		reason = 4;
		break;

	case SS_CF_MODE_CFC:
		reason = 5;
		break;

	default:
		dbg("unsupported reason : %d");
		break;
	}
	dbg("reason  = %d", reason);

	switch (class) {
	case SS_CLASS_ALL_TELE:
		classx = 7;
		break;

	case SS_CLASS_VOICE:
		classx = 1;
		break;

	case SS_CLASS_ALL_DATA_TELE:
		classx = 2;
		break;

	case SS_CLASS_FAX:
		classx = 4;
		break;

	case SS_CLASS_SMS:
		classx = 8;
		break;

	case SS_CLASS_ALL_CS_SYNC:
		classx = 16;
		break;

	default:
		classx = 7;
		dbg("unsupported class %d. set to default : 7", class);
		break;
	}

	dbg("classx  = %d", classx);

	// query status - mode set to 2
	mode = 2;
	user_data = g_new0(struct ss_confirm_info, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		return TCORE_RETURN_ENOMEM;
	}
	user_data->resp = resp;
	user_data->class = class;
	user_data->flavor_type = type;

	if (classx == 7)
		cmd_str = g_strdup_printf("AT+CCFC=%d,%d", reason, mode);
	else
		cmd_str = g_strdup_printf("AT+CCFC=%d,%d,,,%d", reason, mode, classx);

	dbg("request command : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, "+CCFC", TCORE_AT_MULTILINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	ret = _ss_request_message(pending, o, ur, on_response_ss_forwarding_get, user_data);
	g_free(cmd_str);

	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
			tcore_pending_free(pending);
			tcore_at_request_free(req);
		}
		return TCORE_RETURN_FAILURE;
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_forwarding_activate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_forwarding_set(o, ur, SS_OPCO_ACTIVATE);
}

static TReturn imc_ss_forwarding_deactivate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_forwarding_set(o, ur, SS_OPCO_DEACTIVATE);
}

static TReturn imc_ss_forwarding_register(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_forwarding_set(o, ur, SS_OPCO_REG);
}

static TReturn imc_ss_forwarding_deregister(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_forwarding_set(o, ur, SS_OPCO_DEREG);
}

static TReturn imc_ss_forwarding_get_status(CoreObject *o, UserRequest *ur)
{
	struct treq_ss_forwarding *forwarding = 0;

	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	forwarding = (struct treq_ss_forwarding *) tcore_user_request_ref_data(ur, 0);

	return _ss_forwarding_get(o, ur, forwarding->class, forwarding->mode, TRESP_SS_FORWARDING_GET_STATUS);
}


static TReturn _ss_waiting_set(CoreObject *o, UserRequest *ur, enum telephony_ss_opcode opco)
{
	struct treq_ss_waiting *waiting = 0;
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;
	int mode = 0, classx = 0;
	char *cmd_str;
	TcorePending *pending = NULL;
	TcoreATRequest *req;

	dbg("function enter ");
	waiting = (struct treq_ss_waiting *) tcore_user_request_ref_data(ur, 0);
	user_data = g_new0(struct ss_confirm_info, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		return TCORE_RETURN_ENOMEM;
	}

	if (opco == SS_OPCO_ACTIVATE) {
		user_data->resp = TRESP_SS_WAITING_ACTIVATE;
		mode = 1; // enable
	} else if (opco == SS_OPCO_DEACTIVATE) {
		user_data->resp = TRESP_SS_WAITING_DEACTIVATE;
		mode = 0; // disable
	} else
		dbg("[ error ] unknown ss mode (0x%x)", opco);

	switch (waiting->class) {
	case SS_CLASS_ALL_TELE:
		classx = 7;
		break;

	case SS_CLASS_VOICE:
		classx = 1;
		break;

	case SS_CLASS_ALL_DATA_TELE:
		classx = 2;
		break;

	case SS_CLASS_FAX:
		classx = 4;
		break;

	case SS_CLASS_SMS:
		classx = 8;
		break;

	default:
		classx = 1;
		dbg("unsupported class %d. set to default : 1", waiting->class);
		break;
	}
	dbg("mode = %d classxx- %d", mode, classx);

	user_data->class = waiting->class;
	user_data->flavor_type = (int) opco;

	cmd_str = g_strdup_printf("AT+CCWA=1,%d,%d", mode, classx); // always enable +CCWA: unsolicited cmd
	dbg("request command : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	ret = _ss_request_message(pending, o, ur, on_response_ss_waiting_set, user_data);
	g_free(cmd_str);
	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
			tcore_pending_free(pending);
			tcore_at_request_free(req);
		}
		return TCORE_RETURN_FAILURE;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn _ss_waiting_get(CoreObject *o,
							   UserRequest *ur,
							   enum telephony_ss_class class,
							   enum tcore_response_command resp)
{
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;
	int classx; // mode,
	char *cmd_str;
	TcorePending *pending = NULL;
	TcoreATRequest *req;

	dbg("function  enter");
	switch (class) {
	case SS_CLASS_ALL_TELE:
		classx = 7;
		break;

	case SS_CLASS_VOICE:
		classx = 1;
		break;

	case SS_CLASS_ALL_DATA_TELE:
		classx = 2;
		break;

	case SS_CLASS_FAX:
		classx = 4;
		break;

	case SS_CLASS_SMS:
		classx = 8;
		break;

	default:
		classx = 7;
		dbg("unsupported class %d. set to default : 7", class);
		break;
	}
	dbg("classx - %d", classx);

	dbg("allocating user data");
	user_data = g_new0(struct ss_confirm_info, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		return TCORE_RETURN_ENOMEM;
	}
	user_data->resp = resp;
	user_data->class = class;

	cmd_str = g_strdup_printf("AT+CCWA=1,2,%d", classx); // always enable +CCWA: unsolicited cmd , mode is fixed to 2(query status)
	dbg("request cmd : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, "+CCWA", TCORE_AT_MULTILINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	ret = _ss_request_message(pending, o, ur, on_response_ss_waiting_get, user_data);
	g_free(cmd_str);
	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
			tcore_pending_free(pending);
			tcore_at_request_free(req);
		}
		return TCORE_RETURN_FAILURE;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_waiting_activate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_waiting_set(o, ur, SS_OPCO_ACTIVATE);
}

static TReturn imc_ss_waiting_deactivate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return _ss_waiting_set(o, ur, SS_OPCO_DEACTIVATE);
}

static TReturn imc_ss_waiting_get_status(CoreObject *o, UserRequest *ur)
{
	struct treq_ss_waiting *waiting = 0;

	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	waiting = (struct treq_ss_waiting *) tcore_user_request_ref_data(ur, 0);

	return _ss_waiting_get(o, ur, waiting->class, TRESP_SS_WAITING_GET_STATUS);
}

static TReturn imc_ss_cli_activate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_cli_deactivate(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_cli_get_status(CoreObject *o, UserRequest *ur)
{
	struct treq_ss_cli *cli = 0;
	gboolean ret = FALSE;
	char *cmd_prefix = NULL, *rsp_prefix = NULL, *cmd_str = NULL;
	enum  telephony_ss_cli_type *user_data = 0;
	TcorePending *pending = NULL;
	TcoreATRequest *req;

	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	cli = (struct treq_ss_cli *) tcore_user_request_ref_data(ur, 0);
	switch (cli->type) {
	case SS_CLI_TYPE_CLIP:
		cmd_prefix = "+CLIP";
		rsp_prefix = "+CLIP";
		break;

	case SS_CLI_TYPE_CLIR:
		cmd_prefix = "+CLIR";
		rsp_prefix = "+CLIR";
		break;

	case SS_CLI_TYPE_COLP:
		cmd_prefix = "+COLP";
		rsp_prefix = "+COLP";
		break;

	case SS_CLI_TYPE_COLR:
		cmd_prefix = "+COLR";
		rsp_prefix = "+COLR";
		break;

	case SS_CLI_TYPE_CNAP:
		cmd_prefix = "+CNAP";
		rsp_prefix = "+CNAP";
		break;

	case SS_CLI_TYPE_CDIP:
	default:
		dbg("unsupported cli_type : %d", cli->type);
		return TCORE_RETURN_FAILURE;
		break;
	}
	dbg("cmd_prefix : %s", cmd_prefix);

	cmd_str = g_strdup_printf("AT%s?", cmd_prefix);
	dbg("request cmd : %s", cmd_str);

	user_data = g_new0(enum telephony_ss_cli_type, 1);
	if (!user_data) {
		dbg("[ error ] failed to allocate memory");
		g_free(cmd_str);
		return TCORE_RETURN_ENOMEM;
	}
	*user_data = cli->type;

	pending = tcore_pending_new(o, 0);

	req = tcore_at_request_new(cmd_str, rsp_prefix, TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));
	tcore_pending_set_request_data(pending, 0, req);

	ret = _ss_request_message(pending, o, ur, on_response_ss_cli_get, user_data);
	g_free(cmd_str);
	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
			tcore_pending_free(pending);
			tcore_at_request_free(req);
		}
		return TCORE_RETURN_FAILURE;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_send_ussd(CoreObject *o, UserRequest *ur)
{
	UssdSession *ussd_s = 0;
	struct treq_ss_ussd *ussd = 0;
	struct ss_confirm_info *user_data = 0;
	gboolean ret = FALSE;
	char *cmd_str;
	TcorePending *pending = NULL;
	TcoreATRequest *req;

	dbg("function enter");

	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	ussd = (struct treq_ss_ussd *) tcore_user_request_ref_data(ur, 0);

	user_data = g_new0(struct ss_confirm_info, 1);

	user_data->resp = TRESP_SS_SEND_USSD;
	ussd_s = tcore_ss_ussd_get_session(o);
	if (!ussd_s) {
		dbg("USSD session does not  exist");
		tcore_ss_ussd_create_session(o, (enum tcore_ss_ussd_type) ussd->type, (void *) tcore_user_request_ref(ur), 0);
	} else {
		if (ussd->type == SS_USSD_TYPE_USER_INITIATED) {
			dbg("[ error ] ussd session is already exist");
			g_free(user_data);
			return TCORE_RETURN_FAILURE;
		}

		tcore_ss_ussd_set_session_type(ussd_s, (enum tcore_ss_ussd_type) ussd->type);
	}

	cmd_str = g_strdup_printf("AT+CUSD=1,\"%s\",%d", ussd->str, 0x0f); // always enable +CUSD: unsolicited cmd. set to dcs to 0x0f. only supports HEX type
	dbg("request command : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	ret = _ss_request_message(pending, o, ur, on_confirmation_ss_ussd, user_data);
	g_free(cmd_str);

	if (!ret) {
		dbg("AT request sent failed ");
		if (user_data != NULL) {
			g_free(user_data);
			tcore_pending_free(pending);
			tcore_at_request_free(req);
		}
		return TCORE_RETURN_FAILURE;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_set_aoc(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("[ error ] unsupported function");
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_get_aoc(CoreObject *o, UserRequest *ur)
{
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("[ error ] unsupported function");
	return TCORE_RETURN_SUCCESS;
}


static struct tcore_call_control_operations call_ops = {
	.answer_hold_and_accept = imc_ss_manage_call_2_send,
	.answer_replace = imc_ss_manage_call_1_send,
	.answer_reject = imc_ss_manage_call_0_send,
	.end_specific = imc_ss_manage_call_1x_send,
	.end_all_active = imc_ss_manage_call_1_send,
	.end_all_held = imc_ss_manage_call_0_send,
	.active = imc_ss_manage_call_2_send,
	.hold = imc_ss_manage_call_2_send,
	.swap = imc_ss_manage_call_2_send,
	.join = imc_ss_manage_call_3_send,
	.split = imc_ss_manage_call_2x_send,
	.transfer = imc_ss_manage_call_4_send,
	.deflect = imc_ss_manage_call_4dn_send,
};

static TReturn imc_ss_manage_call_send(CoreObject *o, UserRequest *ur, const char *cmd, ConfirmCallback cb, void *user_data)
{
	TcorePending *pending = NULL;
	TcoreATRequest *req;
	gboolean ret = FALSE;

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));
	tcore_pending_set_request_data(pending, 0, req);

	ret = _ss_request_message(pending, o, ur, (TcorePendingResponseCallback) cb, user_data);
	if (!ret) {
		dbg("AT request sent failed ");
		return TCORE_RETURN_FAILURE;
	}
	return TCORE_RETURN_SUCCESS;
}

static TReturn imc_ss_manage_call_0_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s", "AT+CHLD=0");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d", cmd_str, "N/A", strlen(cmd_str));

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);
	return ret;
}

static TReturn imc_ss_manage_call_1_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s", "AT+CHLD=1");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d", cmd_str, "N/A", strlen(cmd_str));

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);
	return ret;
}

static TReturn imc_ss_manage_call_1x_send(CoreObject *o, UserRequest *ur, const int id, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s%d", "AT+CHLD=1", id);
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d", cmd_str, "N/A", strlen(cmd_str));

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);
	return ret;
}

static TReturn imc_ss_manage_call_2_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d", cmd_str, "N/A", strlen(cmd_str));

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);
	return ret;
}

static TReturn imc_ss_manage_call_2x_send(CoreObject *o, UserRequest *ur, const int id, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s%d", "AT+CHLD=2", id);
	dbg("cmd : %s, prefix(if any) : %s, cmd_len : %d", cmd_str, "N/A", strlen(cmd_str));

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);
	return ret;
}

static TReturn imc_ss_manage_call_3_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s", "AT+CHLD=3");

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);
	return ret;
}


static TReturn imc_ss_manage_call_4_send(CoreObject *o, UserRequest *ur, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s", "AT+CHLD=4");

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);
	return ret;
}

static TReturn imc_ss_manage_call_4dn_send(CoreObject *o, UserRequest *ur, const char *number, ConfirmCallback cb, void *user_data)
{
	char *cmd_str = NULL;
	gboolean ret = FALSE;

	dbg("function enter");
	cmd_str = g_strdup_printf("%s%s", "AT+CHLD=4", number);

	ret = imc_ss_manage_call_send(o, ur, cmd_str, cb, user_data);
	g_free(cmd_str);

	return ret;
}

gboolean imc_ss_init(TcorePlugin *cp, CoreObject *co_ss)
{
	CoreObject *co_call = NULL;

	/* Set operations */
	tcore_ss_set_ops(co_ss, &ss_ops);


	co_call = tcore_plugin_ref_core_object(cp,
						CORE_OBJECT_TYPE_CALL);
	if (co_call == NULL) {
		err("Can't find CALL core object");
		return FALSE;
	}

	/* Set operations */
	tcore_call_control_set_operations(co_call, &call_ops);

	tcore_object_add_callback(co_ss, "+CSSU", on_notification_ss_info, NULL);
	tcore_object_add_callback(co_ss, "+CSSI", on_notification_ss_info, NULL);
	tcore_object_add_callback(co_ss, "+CUSD", on_notification_ss_ussd, NULL);

	return TRUE;
}

void imc_ss_exit(TcorePlugin *cp, CoreObject *co_ss)
{
	dbg("Exit");
}
