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
#include <vconf.h>
#include <co_call.h>

#include "imc_call.h"
#include "imc_common.h"

#define COMMA	0X2c
#define STATUS_INCOMING    4
#define STATUS_WAITING     5
#define STATUS_CONNECTED   7

#define find_call_object(co, call_id, call_obj) \
	do { \
		call_obj = tcore_call_object_find_by_id(co, call_id); \
		if (!call_obj) { \
			err("unable to find call object"); \
			return; \
		} \
	} while (0)

struct imc_set_volume_info {
	guint next_index;
	guint volume;
};

static gchar *xdrv_set_volume[] = {
	"AT+XDRV=40,7,3,88",
	"AT+XDRV=40,7,0,88",
	"AT+XDRV=40,8,0,88",
	"AT+XDRV=40,8,2,",
	NULL
};

/*Forward Declarations*/
static void on_response_imc_call_default(TcorePending *p,
	guint data_len, const void *data, void *user_data);

static TelReturn __call_list_get(CoreObject *co, gboolean flag);


static TelCallType __call_type(int type)
{
	dbg("Entry");

	switch (type) {
	case 0:
		return TEL_CALL_TYPE_VOICE;

	case 1:
		return TEL_CALL_TYPE_VIDEO;

	default:
		err("invalid call type, returing default call type as voice");
		return TEL_CALL_TYPE_VOICE;
	}
}

static TelCallState __call_state(int state)
{
	dbg("Entry");

	switch (state) {
	case 0:
		return TEL_CALL_STATE_ACTIVE;

	case 1:
		return TEL_CALL_STATE_HELD;

	case 2:
		return TEL_CALL_STATE_DIALING;

	case 3:
		return TEL_CALL_STATE_ALERT;

	case 4:
	case 5:
		return TEL_CALL_STATE_INCOMING;

	default:
		return TEL_CALL_STATE_IDLE;
	}
}

static void __call_branch_by_status(CoreObject *co, CallObject *call_obj, TelCallState call_state)
{
	unsigned int call_id;
	TelCallType call_type;
	TelCallState state;
	TcoreNotification command = TCORE_NOTIFICATION_UNKNOWN;
	dbg("Call State[%d]", call_state);

	if (tcore_call_object_get_state(call_obj, &state) == FALSE) {
		err("unable to get call status");
		return;
	}

	if (call_state == state) {
		dbg("current call state and existing call state are same");
		return;
	}

	if (tcore_call_object_get_call_type(call_obj, &call_type) == FALSE) {
		err("unable to get call type");
		return;
	}

	if (tcore_call_object_get_id(call_obj, &call_id) == FALSE) {
		err("unable to get call id");
		return;
	}

	/* Set Status */
	tcore_call_object_set_state(call_obj, call_state);

	if (call_type == TEL_CALL_TYPE_VOICE) {
		/* voice call notification */
		switch (call_state) {
		case TEL_CALL_STATE_ACTIVE:
			command = TCORE_NOTIFICATION_CALL_STATUS_ACTIVE;
		break;

		case TEL_CALL_STATE_HELD:
			command = TCORE_NOTIFICATION_CALL_STATUS_HELD;
		break;

		case TEL_CALL_STATE_DIALING:
			command = TCORE_NOTIFICATION_CALL_STATUS_DIALING;
		break;

		case TEL_CALL_STATE_ALERT:
			command = TCORE_NOTIFICATION_CALL_STATUS_ALERT;
		break;

		case TEL_CALL_STATE_INCOMING:
		case TEL_CALL_STATE_WAITING: {
			TelCallIncomingInfo incoming = {0,};
			command = TCORE_NOTIFICATION_CALL_STATUS_INCOMING;
			incoming.call_id = call_id;
			tcore_call_object_get_cli_validity(call_obj, &incoming.cli_validity);
			tcore_call_object_get_number(call_obj, incoming.number);
			tcore_call_object_get_cni_validity(call_obj, &incoming.cni_validity);
			tcore_call_object_get_name(call_obj, incoming.name);
			tcore_call_object_get_mt_forward(call_obj, &incoming.forward);
			tcore_call_object_get_active_line(call_obj, &incoming.active_line);

			/* Send notification */
			tcore_object_send_notification(co, command, sizeof(TelCallIncomingInfo), &incoming);
			return;
		}

		case TEL_CALL_STATE_IDLE: {
			TelCallStatusIdleNoti idle;
			command = TCORE_NOTIFICATION_CALL_STATUS_IDLE;
			idle.call_id = call_id;

			/* TODO - get proper call end cause. */
			idle.cause = TEL_CALL_END_CAUSE_NONE;

			/* Send notification */
			tcore_object_send_notification(co, command,
				sizeof(TelCallStatusIdleNoti), &idle);

			/* Free Call object */
			tcore_call_object_free(co, call_obj);
			return;
		}
		}

	}
	else if (call_type == TEL_CALL_TYPE_VIDEO) {
		/* video call notification */
		switch (call_state) {
		case TEL_CALL_STATE_ACTIVE:
			command = TCORE_NOTIFICATION_VIDEO_CALL_STATUS_ACTIVE;
		break;

		case TEL_CALL_STATE_HELD:
			err("invalid state");
		break;

		case TEL_CALL_STATE_DIALING:
			command = TCORE_NOTIFICATION_VIDEO_CALL_STATUS_DIALING;
		break;

		case TEL_CALL_STATE_ALERT:
			command = TCORE_NOTIFICATION_VIDEO_CALL_STATUS_ALERT;
		break;

		case TEL_CALL_STATE_INCOMING:
		case TEL_CALL_STATE_WAITING:
			command = TCORE_NOTIFICATION_VIDEO_CALL_STATUS_INCOMING;
		break;

		case TEL_CALL_STATE_IDLE: {
			TelCallStatusIdleNoti idle;
			command = TCORE_NOTIFICATION_VIDEO_CALL_STATUS_IDLE;
			idle.call_id = call_id;

			/* TODO - get proper call end cause. */
			idle.cause = TEL_CALL_END_CAUSE_NONE;

			/* Send notification */
			tcore_object_send_notification(co, command,
				sizeof(TelCallStatusIdleNoti), &idle);

			/* Free Call object */
			tcore_call_object_free(co, call_obj);
			return;
		}
		}
	}
	else {
		err("Unknown Call type: [%d]", call_type);
	}

	if (command != TCORE_NOTIFICATION_UNKNOWN)
		tcore_object_send_notification(co, command, sizeof(call_id), &call_id);
}

static void __handle_call_list_get(CoreObject *co, gboolean flag, void *data)
{
	int call_id;
	int direction;
	int call_type;
	int state;
	int mpty;
	int ton;
	GSList *tokens = NULL;
	char *resp = NULL;
	char *line;
	char *num = NULL;
	int num_type;
	char number[TEL_CALL_CALLING_NUMBER_LEN_MAX +1] = {0,};
	GSList *lines = data;
	CallObject *call_obj = NULL;

	 while (lines != NULL) {
		line = (char *)lines->data;
		/* point to next node */
		lines = lines->next;
		/* free previous tokens*/
		tcore_at_tok_free(tokens);

		tokens = tcore_at_tok_new(line);

		/* <id1> */
		resp = g_slist_nth_data(tokens, 0);
		if (NULL == resp) {
			err("Invalid call_id");
			continue;
		}
		call_id = atoi(resp);

		/* <dir> */
		resp = g_slist_nth_data(tokens, 1);
		if (NULL == resp) {
			err("Invalid direction");
			continue;
		}
		direction = (atoi(resp) == 0) ? 1 : 0;

		/* <stat> */
		resp = g_slist_nth_data(tokens, 2);
		if (NULL == resp) {
			err("Invalid state");
			continue;
		}
		state = __call_state(atoi(resp));

		/* <mode> */
		resp = g_slist_nth_data(tokens, 3);
		if (NULL == resp) {
			err("Invalid call_type");
			continue;
		}
		call_type = __call_type(atoi(resp));

		/* <mpty> */
		resp = g_slist_nth_data(tokens, 4);
		if (NULL == resp) {
			err("Invalid mpty");
			continue;
		}
		mpty = atoi(resp);

		/* <number> */
		resp = g_slist_nth_data(tokens, 5);
		if (NULL == resp) {
			err("Number is NULL");
		} else {
			// Strike off double quotes
			num = tcore_at_tok_extract(resp);
			dbg("Number: [%s]", num);

			/* <type> */
			resp = g_slist_nth_data(tokens, 6);
			if (!resp) {
				err("Invalid num type");
			} else {
				num_type = atoi(resp);
				/* check number is international or national. */
				ton = ((num_type) >> 4) & 0x07;
				if (ton == 1 && num[0] != '+') {
					/* international number */
					number[0] = '+';
					memcpy(&number[1], num, strlen(num));
				} else {
					memcpy(number, num, strlen(num));
				}
			}
			g_free(num);
		}

		dbg("Call ID: [%d] Direction: [%s] Call Type: [%d] Multi-party: [%s] "
			"Number: [%s] TON: [%d] State: [%d]",
			call_id, (direction ? "Outgoing" : "Incoming"), call_type,
			(mpty ? "YES" : "NO"), number, ton, state);

		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (NULL == call_obj) {
			call_obj = tcore_call_object_new(co, call_id);
			if (NULL == call_obj) {
				err("unable to create call object");
				continue;
			}
		}

		/* Set Call parameters */
		tcore_call_object_set_type(call_obj, call_type);
		tcore_call_object_set_direction(call_obj, direction);
		tcore_call_object_set_multiparty_state(call_obj, mpty);
		tcore_call_object_set_cli_info(call_obj, TEL_CALL_CLI_VALIDITY_VALID, number);
		tcore_call_object_set_active_line(call_obj, TEL_CALL_ACTIVE_LINE1);
		if (flag == TRUE)
			__call_branch_by_status(co, call_obj, state);
		else
			tcore_call_object_set_state(call_obj, state);
	}
}

/* internal notification operation */
static void __on_notification_imc_call_incoming(CoreObject *co, unsigned int call_id,
	void *user_data)
{
	GSList *list = NULL;
	CallObject *call_obj = NULL;
	dbg("entry");

	/* check call with incoming status already exist */
	list = tcore_call_object_find_by_status(co, TEL_CALL_STATE_INCOMING);
	if (list != NULL) {
		err("Incoming call already exist! Skip...");
		g_slist_free(list);
		return;
	}
	g_slist_free(list);

	call_obj = tcore_call_object_find_by_id(co, call_id);
	if (call_obj != NULL) {
		err("Call object for Call ID [%d] already exist! Skip...", call_id);
		return;
	}

	/* Create new Call object */
	call_obj = tcore_call_object_new(co, (unsigned int)call_id);
	if (NULL == call_obj) {
		err("Failed to create Call object");
		return;
	}

	/* Make request to get current Call list */
	__call_list_get(co, TRUE);
}

static void __on_notification_imc_call_status(CoreObject *co, unsigned int call_id,
	unsigned int call_state, void *user_data)
{
	CallObject *call_obj = NULL;
	TelCallState state;

	state = __call_state(call_state);
	dbg("state [%d]", state);

	switch (state) {
	case TEL_CALL_STATE_ACTIVE: {
		find_call_object(co, call_id, call_obj);
		/* Send notification to application */
		__call_branch_by_status(co, call_obj, state);
	}
	break;

	case TEL_CALL_STATE_HELD: {
		find_call_object(co, call_id, call_obj);
		/* Send notification to application */
		__call_branch_by_status(co, call_obj, state);
	}
	break;

	case TEL_CALL_STATE_DIALING: {
		call_obj = tcore_call_object_find_by_id(co, call_id);
		if (!call_obj) {
			call_obj = tcore_call_object_new(co, call_id);
			if (!call_obj) {
				err("unable to create call object");
				return;
			}
		}
		/* Make request to get current call list.Update CallObject with <number>
		 * and send notification to application */
		__call_list_get(co, TRUE);
	}
	break;

	case TEL_CALL_STATE_ALERT: {
		find_call_object(co, call_id, call_obj);
		/* Send notification to application */
		__call_branch_by_status(co, call_obj, TEL_CALL_STATE_ALERT);
	}
	break;

	case TEL_CALL_STATE_IDLE: {
		find_call_object(co, call_id, call_obj);
		/* Send notification to application */
		__call_branch_by_status(co, call_obj, state);
	}
	break;

	default:
		err("invalid call status");
		break;
	}
}

/*internal response operation */
static void __on_response_imc_call_list_get(TcorePending *p, guint data_len, const void *data,
	void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	GSList *lines = NULL;
	TelCallResult result = TEL_CALL_RESULT_FAILURE; //TODO - CME error mapping required
	gboolean *flag = IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	int count;
	dbg("entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_CALL_RESULT_SUCCESS;
		if (NULL == at_resp->lines) {
			err("invalid response received");
			return;
		}

		lines = (GSList *) at_resp->lines;
		count = g_slist_length(lines);
		dbg("Total records : %d", g_slist_length(lines));
		if (0 == count) {
			err("Call count is zero");
			return;
		}

		dbg("RESPONSE OK");

		/* parse +CLCC notification parameter */
		__handle_call_list_get(co, *flag, lines);

	} else {
		err("RESPONSE NOK");
	}
}

/*internal request operation */
static TelReturn __send_call_request(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data, gchar *at_cmd, gchar *func_name)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, func_name, strlen(func_name) + 1);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_call_default, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, func_name);

	/* Free resources */
	g_free(at_cmd);
	return ret;
}

 /*
 * Operation -  Get current call list.
 *
 * Request -
 * AT-Command: AT+CLCC
 *
 * Response -
 * Success:
 *[+CLCC: <id1>, <dir>, <stat>, <mode>,<mpty>[,<number>,<type>[,<alpha>[,<priority>]]]
 *[<CR><LF> +CLCC: <id2>,<dir>,<stat>,<mode>,<mpty>[,<number>,<type>[,<alpha>[,<priority>]]][…]]]
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn __call_list_get(CoreObject *co, gboolean flag)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret =TEL_RETURN_FAILURE;
	dbg("Entry");

	if (NULL == co) {
		err("Core Object is NULL");
		return ret;
	}

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(NULL, NULL, &flag, sizeof(gboolean));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+CLCC","+CLCC",
		TCORE_AT_COMMAND_TYPE_MULTILINE,
		NULL,
		__on_response_imc_call_list_get, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get current call list");

	return ret;
}

/* Notification */

/*
* Operation -  call status notification from network.
* notification message format:
* +XCALLSTAT: <call_id><stat>
* where
* <call_id>
* indicates the call identification (GSM02.30 4.5.5.1)
* <stat>
* 0 active
* 1 hold
* 2 dialling (MO call)
* 3 alerting (MO call; ringing for the remote party)
* 4 ringing (MT call)
* 5 waiting (MT call)
* 6 disconnected
* 7 connected (indicates the completion of a call setup first time for MT and MO calls – this is reported in
addition to state active)
*/
static gboolean on_notification_imc_call_status(CoreObject *co, const void *data,
	void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	const char *line = NULL;
	char *state = NULL, *call_handle = NULL;
	unsigned int status, call_id;

	dbg("Entry");

	lines = (GSList *) data;
	if (lines == NULL) {
		err("Invalid response received");
		return TRUE;
	}
	line = (char *) (lines->data);
	tokens = tcore_at_tok_new(line);

	call_handle = g_slist_nth_data(tokens, 0);
	if (NULL == call_handle) {
		err("call_id missing from %XCALLSTAT indiaction");
		goto OUT;
	}
	call_id = atoi(call_handle);
	state = g_slist_nth_data(tokens, 1);
	if (NULL == state) {
		err("State is missing from %XCALLSTAT indication");
		goto OUT;
	}
	status = atoi(state);
	dbg("call_id[%d], status[%d]", call_id, status);

	switch (status) {
	case STATUS_INCOMING:
	case STATUS_WAITING:
		__on_notification_imc_call_incoming(co, call_id, user_data);
		break;

	case STATUS_CONNECTED:     /* ignore Connected state. */
		dbg("ignore connected state");
		break;

	default:
		__on_notification_imc_call_status(co, call_id, status, user_data);
		break;
	}
OUT:
	// Free tokens
	tcore_at_tok_free(tokens);
	return TRUE;
}

/*
 * Operation -  SS network initiated notification.
 *
 * notification message format:
 * +CSSU: <code2>[<index> [,<number>,<type>]]
 * <code2>
 * (it is manufacturer specific, which of these codes are supported):
 * 0 this is a forwarded call (MT call setup)
 * 1 this is a CUG call (<index> present) (MT call setup)
 * 2 call has been put on hold (during a voice call)
 * 3 call has been retrieved (during a voice call)
 * 4 multiparty call entered (during a voice call)
 * 5 Call has been released - not a SS notification (during a voice call)
 * 6 forward check SS message received (can be received whenever)
 * 7 call is being connected (alerting) with the remote party in alerting state
 *   in explicit call transfer operation
 *   (during a voice call)
 * 8 call has been connected with the other remote party in explicit call transfer
 *   operation (during a voice call or MT call setup)
 * 9 this is a deflected call (MT call setup)
 * 10 additional incoming call forwarded
 * <index>
 * refer Closed user group +CCUG
 * <number>
 *  string type phone of format specified by <type>
 * <type>
 * type of address octet in integer format.
 */
static gboolean on_notification_imc_call_ss_cssu_info(CoreObject *co, const void *event_data,
	void *user_data)
{
	GSList *tokens = NULL;
	TcoreNotification command = TCORE_NOTIFICATION_UNKNOWN;
	char *resp = NULL;
	char *cmd = 0;
	int index = 0;
	int code2 = -1;
	char number[TEL_CALL_CALLING_NUMBER_LEN_MAX + 1] = {'\0',};

	dbg("entry");

	if (1 != g_slist_length((GSList *) event_data)) {
		err("unsolicited msg but multiple line");
		return TRUE;
	}

	cmd = (char *) ((GSList *) event_data)->data;
	dbg("ss notification message[%s]", cmd);

	tokens = tcore_at_tok_new(cmd);

	/* parse <code2> */
	resp = g_slist_nth_data(tokens, 0);
	if (NULL == resp) {
		err("Code2 is missing from %CSSU indiaction");
		tcore_at_tok_free(tokens);
		return TRUE;
	}

	code2 = atoi(resp);

	/* parse [ <index>, <number> <type>] */
	if ((resp = g_slist_nth_data(tokens, 1)))
		index = atoi(resp);

	if ((resp = g_slist_nth_data(tokens, 2))) {
		/* Strike off double quotes */
		int len = strlen(resp) - 2;
		memcpy(number, resp + 1, len);
		number[len] = '\0';;
	}

	dbg("+CSSU: <code2> = %d <index> = %d <number> = %s ", code2, index, number);

	/* <code2> - other values will be ignored */
	switch (code2) {
	case 0:
		command = TCORE_NOTIFICATION_CALL_INFO_MT_FORWARDED;
		break;
	case 2:
		command = TCORE_NOTIFICATION_CALL_INFO_HELD;
		break;
	case 3:
		command = TCORE_NOTIFICATION_CALL_INFO_ACTIVE;
		break;
	case 4:
		command = TCORE_NOTIFICATION_CALL_INFO_JOINED;
		break;
	case 7:
	case 8:
		command = TCORE_NOTIFICATION_CALL_INFO_TRANSFERED;
		break;
	case 9:
		command = TCORE_NOTIFICATION_CALL_INFO_MT_DEFLECTED;
		break;
	default:
		dbg("Unsupported +CSSU notification : %d", code2);
		break;
	}

	if (command != TCORE_NOTIFICATION_UNKNOWN)
		tcore_object_send_notification(co, command, 0, NULL);
	tcore_at_tok_free(tokens);

	return TRUE;
}

/*
* Operation -  SS network initiated notification.
* notification message format:
* +CSSI : <code1>[,<index>]
* where
* <code1>
* 0 unconditional call forwarding is active
* 1 some of the conditional call forwarding are active
* 2 call has been forwarded
* 3 call is waiting
* 4 this is a CUG call (also <index> present)
* 5 outgoing calls are barred
* 6 incoming calls are barred
* 7 CLIR suppression rejected
* 8 call has been deflected

* <index>
* refer Closed user group +CCUG.
*/
static gboolean on_notification_imc_call_ss_cssi_info(CoreObject *co, const void *event_data,
	void *user_data)
{
	GSList *tokens = NULL;
	TcoreNotification command = TCORE_NOTIFICATION_UNKNOWN;
	char *resp = NULL;
	char *cmd = 0;
	int index = 0;
	int code1 = -1;

	dbg("entry");

	if (1 != g_slist_length((GSList *) event_data)) {
		err("unsolicited msg but multiple line");
		return TRUE;
	}
	cmd = (char *) ((GSList *) event_data)->data;
	dbg("ss notification message[%s]", cmd);

	tokens = tcore_at_tok_new(cmd);
	/* parse <code1> */
	resp = g_slist_nth_data(tokens, 0);
	if (NULL == resp) {
		err("<code1> is missing from %CSSI indiaction");
		tcore_at_tok_free(tokens);
		return TRUE;
	}

	code1 = atoi(resp);

	/* parse [ <index>] */
	if ((resp = g_slist_nth_data(tokens, 1)))
		index = atoi(resp);

	dbg("+CSSI: <code1> = %d <index> = %d ", code1, index);

	/* <code1> - other values will be ignored */
	switch (code1) {
	case 0:
		command = TCORE_NOTIFICATION_CALL_INFO_MO_FORWARD_UNCONDITIONAL;
		break;
	case 1:
		command = TCORE_NOTIFICATION_CALL_INFO_MO_FORWARD_CONDITIONAL;
		break;
	case 2:
		command = TCORE_NOTIFICATION_CALL_INFO_MO_FORWARDED;
		break;
	case 3:
		command = TCORE_NOTIFICATION_CALL_INFO_MO_WAITING;
		break;
	case 5:
		command = TCORE_NOTIFICATION_CALL_INFO_MO_BARRED_OUTGOING;
		break;
	case 6:
		command = TCORE_NOTIFICATION_CALL_INFO_MO_BARRED_INCOMING;
		break;
	case 8:
		command  = TCORE_NOTIFICATION_CALL_INFO_MO_DEFLECTED;
		break;
	default:
		dbg("Unsupported +CSSI notification : %d", code1);
		break;
	}

	if (command != TCORE_NOTIFICATION_UNKNOWN)
		tcore_object_send_notification(co, command, 0, NULL);
	tcore_at_tok_free(tokens);

	return TRUE;
}

static gboolean on_notification_imc_call_clip_info(CoreObject *co, const void *data,
	void *user_data)
{
	dbg("entry");
	/* TODO - handle +CLIP notification*/
	return TRUE;
}

/* Response */
static void on_response_imc_call_default(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelCallResult result;
	dbg("entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_CALL_RESULT_SUCCESS;
	} else {
		err("ERROR[%s]",at_resp->final_response);
		result = TEL_CALL_RESULT_FAILURE;
		/*TODO - need to map CME error and final response error to TelCallResult */
	}

	dbg("%s: [%s]", IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data),
		 (result == TEL_CALL_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_call_set_volume_info(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	GSList *tokens = NULL;
	GSList *line = NULL;
	char *resp_str = NULL;
	gboolean error;

	TelCallResult result = TEL_CALL_RESULT_FAILURE;  // TODO: XDRV error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		line = at_resp->lines;
		tokens = tcore_at_tok_new(line->data);

		if (!g_slist_nth_data(tokens, 0)) {
			err("group_id is missing");
			goto OUT;
		}

		if (!g_slist_nth_data(tokens, 1)) {
			err(" function_id is missing");
			goto OUT;
		}

		resp_str = g_slist_nth_data(tokens, 2);
		if (!resp_str) {
			err("xdrv result missing");
			goto OUT;
		} else {
			struct imc_set_volume_info *volume_info;
			gchar *vol = "";
			gchar *at_cmd;
			TelReturn ret;

			error = atoi(resp_str);
			if (error) {
				err("RESPONSE NOK");
				goto OUT;
			}

			/* Fetch from resp_cb_data */
			volume_info = (struct imc_set_volume_info *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
			dbg("volume info index[%d]", volume_info->next_index);

			if (xdrv_set_volume[volume_info->next_index] == NULL) {
				/*Processing of xdrv commands  completed */
				dbg("RESPONSE OK");
				result = TEL_CALL_RESULT_SUCCESS;
				goto OUT;
			} else if (volume_info->next_index == 3) {
				switch ((volume_info->volume) / 10) {
				case 0 :
					vol = "0";
				break;
				case 1 :
					vol = "40";
				break;
				case 2 :
					vol = "46";
				break;
				case 3 :
					vol = "52";
				break;
				case 4 :
					vol = "58";
				break;
				case 5 :
					vol = "64";
				break;
				case 6 :
					vol = "70";
				break;
				case 7 :
					vol = "76";
				break;
				case 8 :
					vol = "82";
				break;
				case 9 :
				default :
					vol = "88";
				}
			}

			at_cmd = g_strdup_printf("%s%s",
					xdrv_set_volume[volume_info->next_index], vol);

			/* Increament index to point to next command */
			volume_info->next_index += 1;

			/* Send Request to modem */
			ret = tcore_at_prepare_and_send_request(co,
					at_cmd, "+XDRV",
					TCORE_AT_COMMAND_TYPE_SINGLELINE,
					NULL,
					on_response_imc_call_set_volume_info, resp_cb_data,
					on_send_imc_request, NULL);
			IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_call_set_volume_info");
			g_free(at_cmd);

			return;
		}
	}

OUT :
	dbg("Set Volume Info: [%s]",
			(result == TEL_CALL_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
	tcore_at_tok_free(tokens);
}

static void on_response_imc_call_set_sound_path(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	GSList *tokens = NULL;
	GSList *line = NULL;
	char *resp_str = NULL;
	gboolean error;
	gint xdrv_func_id = -1;

	TelCallResult result = TEL_CALL_RESULT_FAILURE;  // TODO: XDRV error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		line = at_resp->lines;
		tokens = tcore_at_tok_new(line->data);
		if (!g_slist_nth_data(tokens, 0)) {
			err("group_id is missing");
			goto OUT;
		}

		if (!(resp_str = g_slist_nth_data(tokens, 1))) {
			err(" function_id is missing");
			goto OUT;
		}

		xdrv_func_id = atoi(resp_str);

		resp_str = g_slist_nth_data(tokens, 2);
		if (resp_str) {
			error = atoi(resp_str);
			if (error) {
				err("RESPONSE NOK");
				goto OUT;
			} else {
				if (xdrv_func_id == 4) {
					/* Send next command to configure destination device type */
					gchar *at_cmd;
					TelReturn ret;
					gint *device_type = IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

					at_cmd = g_strdup_printf("AT+XDRV=40,5,2,0,0,0,0,0,1,0,1,0,%d",
								*device_type);

					ret = tcore_at_prepare_and_send_request(co,
							at_cmd, "+XDRV",
							TCORE_AT_COMMAND_TYPE_SINGLELINE,
							NULL,
							on_response_imc_call_set_sound_path, resp_cb_data,
							on_send_imc_request, NULL);
					IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_call_set_sound_path");
					g_free(at_cmd);

					return;
				}
				dbg("RESPONSE OK");
				result = TEL_CALL_RESULT_SUCCESS;
			}
		}
	}

OUT :
	dbg("Set Sound Path: [%s]",
			(result == TEL_CALL_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));

	tcore_at_tok_free(tokens);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_set_sound_path(TcorePending *p, guint data_len,
					const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	TelCallResult result = TEL_CALL_RESULT_FAILURE;
	CoreObject *co_call = tcore_pending_ref_core_object(p);

	if (at_resp && at_resp->success)
			result = TEL_CALL_RESULT_SUCCESS;

	if(resp_cb_data->cb)
		resp_cb_data->cb(co_call, (gint)result, NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_call_set_mute(TcorePending *p, guint data_len,
	const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	GSList *tokens = NULL;
	const char *line = NULL;
	char *resp_str = NULL;
	gboolean error;

	TelCallResult result = TEL_CALL_RESULT_FAILURE;  // TODO: XDRV error mapping is required
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		result = TEL_CALL_RESULT_SUCCESS;
		line = (((GSList *)at_resp->lines)->data);
		tokens = tcore_at_tok_new(line);

		resp_str = g_slist_nth_data(tokens, 0);
		if (!g_slist_nth_data(tokens, 0)) {
			err("group_id is missing");
			result = TEL_CALL_RESULT_FAILURE;
			goto OUT;
		}

		if (!g_slist_nth_data(tokens, 1)) {
			err(" function_id is missing");
			result = TEL_CALL_RESULT_FAILURE;
			goto OUT;
		}

		resp_str = g_slist_nth_data(tokens, 2);
		if (resp_str) {
			error = atoi(resp_str);
			if (error) {
				result = TEL_CALL_RESULT_FAILURE;
				goto OUT;
			} else {
				result = TEL_CALL_RESULT_SUCCESS;
			}
		}
	}

OUT :
	dbg("Set Mute: [%s]",
			(result == TEL_CALL_RESULT_SUCCESS ? "SUCCESS" : "FAIL"));
	tcore_at_tok_free(tokens);

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	imc_destroy_resp_cb_data(resp_cb_data);
}


 /* Request */
 /*
 * Operation - dial
 *
 * Request -
 * AT-Command: ATD <num> [I] [G] [;]
 * <num> - dialed number
 * [I][i] - CLI presentation(supression or invocation)
 * [G] - control the CUG supplementary service information for this call.
 *
 * Response -
 * Success:
 * OK or CONNECT
 * Failure:
 * "ERROR"
 * "NO ANSWER"
 * "NO CARRIER"
 * "BUSY"
 * "NO DIALTONE"
 * +CME ERROR: <error>
 */
static TelReturn imc_call_dial(CoreObject *co, const TelCallDial *dial_info,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	const gchar *clir;
	gchar *num;

	dbg("entry");

	if (dial_info->call_type == TEL_CALL_TYPE_VIDEO) {
		err("Video call is not supported in imc modem");
		 return TEL_RETURN_OPERATION_NOT_SUPPORTED;
	}

	if (!strncmp(dial_info->number, "*31#", 4)) {
		dbg("clir suppression");
		clir = "i";
		num = (gchar *)&(dial_info->number[4]);
	} else if (!strncmp(dial_info->number, "#31#", 4)) {
		dbg("clir invocation");
		clir = "I";
		num = (gchar *)&(dial_info->number[4]);
	} else {
		int cli = 0;

		dbg("no clir string in number");

		/* it will be removed when setting application use tapi_ss_set_cli()
		 * instead of his own vconfkey. (0 : By network, 1 : Show, 2 : Hide)
		 */
		vconf_get_int("db/ciss/show_my_number", &cli);
		if(cli == 2){
			dbg("clir invocation from setting application");
			clir = "I";
		} else {
			dbg("set clir state to default");
			clir = "";
		}
		num = (gchar *)dial_info->number;
	}

	/* AT-Command */
	at_cmd = g_strdup_printf("ATD%s%s;", num, clir);
	dbg(" at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_dial");
}

/*
 * Operation - Answer/Reject/Replace/hold(current call) & accept incoming call.
 *
 * Request -
 *
 * 1. AT-Command: ATA
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 *
 * 2. AT-Command: AT+CHLD=[<n>]
 * <n>
 * 0 - (deafult)release all held calls or set User Determined User Busy for a waiting/incoming
 * call; if both exists then only the waiting call will be rejected.
 * 1 -  release all active calls and accepts the other (held or waiting)
 * Note: In the scenario: An active call, a waiting call and held call, when the active call is
 * terminated, we will make the Waiting call as active.
 * 2 - 	place all active calls (if exist) on hold and accepts the other call (held or waiting/in-coming).
 * If only one call exists which is active, place it on hold and if only held call exists make it active call.
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 * For more informatiion refer 3GPP TS 27.007.
 */
static TelReturn imc_call_answer(CoreObject *co, TelCallAnswerType ans_type,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	if (ans_type == TEL_CALL_ANSWER_ACCEPT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "ATA");
	}else if (ans_type == TEL_CALL_ANSWER_REJECT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=0");
	} else if (ans_type == TEL_CALL_ANSWER_REPLACE) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=1");
	} else if (ans_type == TEL_CALL_ANSWER_HOLD_AND_ACCEPT) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	}else {
		err("Unsupported call answer type");
		return TEL_RETURN_FAILURE;
	}

	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_answer");
}

/*
 * Operation - release all calls/release specific call/release all active call/release all held calls.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * <n>
 * 0  - (defualt)release all held calls or set User Determined User Busy for a waiting/incoming.
 * call; if both exists then only the waiting call will be rejected.
 * 1  - release all active calls and accepts the other (held or waiting).
 * 1x - release a specific call (x specific call number as indicated by call id).
 * 8  -	release all calls.
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_end(CoreObject *co, const TelCallEnd *end_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	if (end_info->end_type == TEL_CALL_END_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=8");
	}else if (end_info->end_type == TEL_CALL_END) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s%d", "AT+CHLD=1",end_info->call_id);
	} else if (end_info->end_type == TEL_CALL_END_ACTIVE_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=1");
	} else if (end_info->end_type == TEL_CALL_END_HOLD_ALL) {
		/* AT-Command */
		at_cmd = g_strdup_printf("%s", "AT+CHLD=0");
	}else {
		err("Unsupported call end type");
		return TEL_RETURN_FAILURE;
	}

	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_end");
}

/*
 * Operation - send dtmf.
 *
 * Request -
 * 1. AT-Command: AT+VTS=<DTMF>,{<DTMF>,<duration>}.
 * where
 * <DTMF>:
 * is a single ASCII character in the set 0-9, #, *, A-D. Even it will support string DTMF.
 * <duration>:
 * integer in range 0-255, meaning 1/10(10 millisec) seconds multiples. The string parameter
 * of the command consists of combinations of the following separated by commas:
 * NOTE : There is a limit of 50 dtmf tones can be requested through a single VTS command.
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_send_dtmf(CoreObject *co, const char *dtmf_str,
	TcoreObjectResponseCallback cb,  void *cb_data)
{
	gchar *at_cmd;
	char *tmp_dtmf = NULL, *dtmf;
	unsigned int count;

	dbg("entry");

	//(void) _set_dtmf_tone_duration(o, dup);
	tmp_dtmf = tcore_malloc0((strlen(dtmf_str) * 2) + 1); // DTMF digits + comma for each dtmf digit.
	tcore_check_return_value_assert(tmp_dtmf != NULL, TEL_RETURN_FAILURE);
	/* Save initial pointer */
	dtmf = tmp_dtmf;

	for (count = 0; count < strlen(dtmf_str); count++) {
		*tmp_dtmf = dtmf_str[count];
		tmp_dtmf++;

		*tmp_dtmf = COMMA;
		tmp_dtmf++;
	}

	// last digit is having COMMA , overwrite it with '\0' .
	*(--tmp_dtmf) = '\0';

	// AT+VTS = <d1>,<d2>,<d3>,<d4>,<d5>,<d6>, ..... <d32>
	at_cmd = g_strdup_printf("AT+VTS=%s", dtmf);
	dbg("at command : %s", at_cmd);

	tcore_free(dtmf);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_send_dtmf");
}

/*
 * Operation - call hold.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2 - place all active calls (if exist) on hold and accepts the other call (held or waiting/incoming).
 * If only one call exists which is active, place it on hold and if only held call exists
 * make it active call
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_hold(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)

{
	gchar *at_cmd;
	dbg("entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_hold");
}

/*
 * Operation - call active.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2 - place all active calls (if exist) on hold and accepts the other call (held or waiting/incoming).
 * If only one call exists which is active, place it on hold and if only held call exists
 * make it active call
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_active(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_active");
}

/*
 * Operation - call swap.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2 - place all active calls (if exist) on hold and accepts the other call (held or waiting/incoming).
 * If only one call exists which is active, place it on hold and if only held call exists
 * make it active call
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_swap(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=2");
	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_swap");
}

/*
 * Operation - call join.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 3 - adds a held call to the conversation
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_join(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=3");
	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_join");
}

/*
 * Operation - call split.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 2x - place all active calls on hold except call x with which communication is supported
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_split(CoreObject *co, unsigned int call_id,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	at_cmd = g_strdup_printf("%s%d", "AT+CHLD=2", call_id);
	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_split");
}

/*
 * Operation - call transfer.
 *
 * Request -
 * 1. AT-Command: AT+CHLD=[<n>]
 * Where
 * <n>
 * 4 connects the two calls and disconnects the subscriber from both calls (Explicit Call Transfer)
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_transfer(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	at_cmd = g_strdup_printf("%s", "AT+CHLD=4");
	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_transfer");
}

/*
 * Operation - call transfer.
 *
 * Request -
 * 1. AT-Command: AT+CTFR= <number>[,<type>]
 * Where
 * number>
 * string type phone number
 * <type>
 * type of address octet in integer format. It is optional parameter.
 *
 * Response -
 * Success:
 * OK
 * Failure:
 * +CME ERROR: <error>
 */
static TelReturn imc_call_deflect(CoreObject *co, const char *deflect_to,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	dbg("entry");

	at_cmd = g_strdup_printf("AT+CTFR=%s", deflect_to);
	dbg("at command : %s", at_cmd);

	return __send_call_request(co, cb, cb_data, at_cmd, "imc_call_deflect");
}

static TelReturn imc_call_set_active_line(CoreObject *co, TelCallActiveLine active_line,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	dbg("entry");

	dbg("exit");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

static TelReturn imc_call_get_active_line(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	dbg("entry");

	dbg("exit");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

/*
 * Operation - Set voule info.
 *
 * Request -
 * AT-Command: AT+XDRV=<group_id>,<function_id>[,<param_n>]
 * The first command parameter defines the involved driver group.
 * The second command parameter defines a certain function in the selected driver group.
 * Other parameters are dependent on the first two parameters.
 * Nearly all parameters are integer values, also if they are represented by literals.
 * Only very few are strings or
 * hex data strings.
 *
 * Response -
 * +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>]
 * The first response parameter defines the involved driver group.
 * The second response parameter defines the current function in the selected driver group.
 * The third response parameter defines the xdrv_result of the operation.
 * Additional response parameters dependent on the first two parameters.
 */
static TelReturn imc_call_set_volume_info(CoreObject *co, const TelCallVolumeInfo *volume_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data = NULL;
	gchar *at_cmd;
	TelReturn ret;
	struct imc_set_volume_info cb_volume_info;

	dbg("entry");

	cb_volume_info.next_index = 1;
	cb_volume_info.volume = volume_info->volume;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				&cb_volume_info, sizeof(struct imc_set_volume_info));

	at_cmd = g_strdup_printf("%s", xdrv_set_volume[0]);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+XDRV",
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			NULL,
			on_response_imc_call_set_volume_info, resp_cb_data,
			on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_call_set_volume_info");

	g_free(at_cmd);
	return ret;
}


static TelReturn imc_call_get_volume_info(CoreObject *co, TelCallSoundDevice sound_device,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	dbg("Entry");

	dbg("Exit");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

/*
 * Operation - Set sound path.
 *
 * Request -
 * AT-Command: AT+XDRV=<group_id>,<function_id>[,<param_n>]
 * The first command parameter defines the involved driver group.
 * The second command parameter defines a certain function in the selected driver group.
 * Other parameters are dependent on the first two parameters.
 * Nearly all parameters are integer values, also if they are represented by literals.
 * Only very few are strings or
 * hex data strings.
 *
 * Response -
 * +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>]
 * The first response parameter defines the involved driver group.
 * The second response parameter defines the current function in the selected driver group.
 * The third response parameter defines the xdrv_result of the operation.
 * Additional response parameters dependent on the first two parameters.
 */

static TelReturn imc_call_set_sound_path(CoreObject *co, const TelCallSoundPathInfo *sound_path_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data = NULL;
	TelReturn ret;
	gchar *at_cmd;
	gint device_type = -1;
	TcorePlugin *plugin = tcore_object_ref_plugin(co);
	const char *cp_name = tcore_server_get_cp_name_by_plugin(plugin);

	dbg("audio device type - 0x%x", sound_path_info->path);

	switch (sound_path_info->path) {
		case TEL_SOUND_PATH_HANDSET:
			device_type = 1;
			break;
		case TEL_SOUND_PATH_HEADSET:
			device_type = 2;
			break;
		case TEL_SOUND_PATH_HEADSET_3_5PI:
			device_type = 3;
			break;
		case TEL_SOUND_PATH_SPK_PHONE:
			device_type = 4;
			break;
		case TEL_SOUND_PATH_HANDSFREE:
			device_type = 5;
			break;
		case TEL_SOUND_PATH_HEADSET_HAC:
			device_type = 6;
			break;
		case TEL_SOUND_PATH_BLUETOOTH:
		case TEL_SOUND_PATH_STEREO_BLUETOOTH:
			device_type = 7;
			break;
		case TEL_SOUND_PATH_BT_NSEC_OFF:
		case TEL_SOUND_PATH_MIC1:
		case TEL_SOUND_PATH_MIC2:
		default:
			dbg("unsupported device type");
			return TEL_RETURN_INVALID_PARAMETER;
	}

	if (g_str_has_prefix(cp_name, "imcmodem")) {
		/* Response callback data */
		resp_cb_data = imc_create_resp_cb_data(cb, cb_data, &device_type, sizeof(gint));

		at_cmd = g_strdup_printf("AT+XDRV=40,4,3,0,0,0,0,0,1,0,1,0,%d", device_type);

		ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+XDRV",
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			NULL,
			on_response_imc_call_set_sound_path, resp_cb_data,
			on_send_imc_request, NULL);
		IMC_CHECK_REQUEST_RET(ret, NULL, "imc_call_set_sound_path");
		g_free(at_cmd);
	} else {
		/* Response callback data */
		resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

		/* Configure modem I2S1 to 8khz, mono, PCM if routing to bluetooth */
		if (sound_path_info->path == TEL_SOUND_PATH_BLUETOOTH ||
				sound_path_info->path == TEL_SOUND_PATH_STEREO_BLUETOOTH) {
			tcore_at_prepare_and_send_request(co,
					"AT+XDRV=40,4,3,0,1,0,0,0,0,0,0,0,21",
					NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
					NULL, NULL, NULL, NULL, NULL);

			tcore_at_prepare_and_send_request(co,
					"AT+XDRV=40,5,2,0,1,0,0,0,0,0,0,0,22",
					NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
					NULL, NULL, NULL, NULL, NULL);
		} else {
			tcore_at_prepare_and_send_request(co,
					"AT+XDRV=40,4,3,0,1,0,8,0,1,0,2,0,21",
					NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
					NULL, NULL, NULL, NULL, NULL);

			tcore_at_prepare_and_send_request(co,
					"AT+XDRV=40,5,2,0,1,0,8,0,1,0,2,0,22",
					NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
					NULL, NULL, NULL, NULL, NULL);
		}

		/* Configure modem I2S2 and do the modem routing */
		tcore_at_prepare_and_send_request(co,
				"AT+XDRV=40,4,4,0,0,0,8,0,1,0,2,0,21",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		tcore_at_prepare_and_send_request(co,
				"AT+XDRV=40,5,3,0,0,0,8,0,1,0,2,0,22",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		tcore_at_prepare_and_send_request(co, "AT+XDRV=40,6,0,4",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		tcore_at_prepare_and_send_request(co, "AT+XDRV=40,6,3,0",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		tcore_at_prepare_and_send_request(co, "AT+XDRV=40,6,4,2",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		tcore_at_prepare_and_send_request(co, "AT+XDRV=40,6,5,2",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		/* amc enable */
		tcore_at_prepare_and_send_request(co, "AT+XDRV=40,2,4",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		tcore_at_prepare_and_send_request(co, "AT+XDRV=40,2,3",
				NULL, TCORE_AT_COMMAND_TYPE_NO_RESULT,
				NULL, NULL, NULL, NULL, NULL);

		/* amc route: AMC_RADIO_RX => AMC_I2S1_TX */
		ret = tcore_at_prepare_and_send_request(co, "AT+XDRV=40,6,0,2",
				"+XDRV", TCORE_AT_COMMAND_TYPE_SINGLELINE, NULL,
				on_response_set_sound_path, resp_cb_data, NULL, NULL);

		IMC_CHECK_REQUEST_RET(ret, NULL, "imc_call_set_sound_path");
	}

	return ret;
}

/*
 * Operation - Set/Unset mute status.
 *
 * Request -
 * AT-Command: AT+XDRV=<group_id>,<function_id>[,<param_n>]
 * The first command parameter defines the involved driver group.
 * The second command parameter defines a certain function in the selected driver group.
 * Other parameters are dependent on the first two parameters.
 * Nearly all parameters are integer values, also if they are represented by literals.
 * Only very few are strings or
 * hex data strings.
 *
 * Response -
 * +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>]
 * The first response parameter defines the involved driver group.
 * The second response parameter defines the current function in the selected driver group.
 * The third response parameter defines the xdrv_result of the operation.
 * Additional response parameters dependent on the first two parameters.
 */
static TelReturn imc_call_set_mute(CoreObject *co, gboolean mute, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	ImcRespCbData *resp_cb_data = NULL;
	gchar *at_cmd;
	TelReturn ret;

	dbg("entry");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* AT - Command */
	if (mute)
		at_cmd = g_strdup_printf("%s", "AT+XDRV=40,8,0,0,0");  /*MUTE*/
	else
		at_cmd = g_strdup_printf("%s", "AT+XDRV=40,8,0,0,88"); /*UNMUTE*/

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+XDRV",
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			NULL,
			on_response_imc_call_set_mute, resp_cb_data,
			on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "imc_call_set_mute");

	g_free(at_cmd);

	return ret;
}

static TelReturn imc_call_get_mute_status(CoreObject *co, TcoreObjectResponseCallback cb,
	void *cb_data)
{
	dbg("entry");

	dbg("exit");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}


static TelReturn imc_call_set_sound_recording(CoreObject *co, TelCallSoundRecording sound_rec,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	dbg("entry");

	dbg("exit");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

static TelReturn imc_call_set_sound_equalization(CoreObject *co, const TelCallSoundEqualization *sound_eq,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	dbg("entry");

	dbg("exit");
	return TEL_RETURN_OPERATION_NOT_SUPPORTED;
}

/* Call Operations */
static TcoreCallOps imc_call_ops = {
	.dial = imc_call_dial,
	.answer = imc_call_answer,
	.end = imc_call_end,
	.send_dtmf = imc_call_send_dtmf,
	.hold = imc_call_hold,
	.active = imc_call_active,
	.swap = imc_call_swap,
	.join = imc_call_join,
	.split = imc_call_split,
	.transfer = imc_call_transfer,
	.deflect = imc_call_deflect,
	.set_active_line = imc_call_set_active_line,
	.get_active_line = imc_call_get_active_line,
	.set_volume_info = imc_call_set_volume_info,
	.get_volume_info = imc_call_get_volume_info,
	.set_sound_path = imc_call_set_sound_path,
	.set_mute = imc_call_set_mute,
	.get_mute_status = imc_call_get_mute_status,
	.set_sound_recording = imc_call_set_sound_recording,
	.set_sound_equalization = imc_call_set_sound_equalization,
};

gboolean imc_call_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Entry");

	/* Set operations */
	tcore_call_set_ops(co, &imc_call_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co, "+XCALLSTAT", on_notification_imc_call_status, NULL);
	tcore_object_add_callback(co, "+CLIP", on_notification_imc_call_clip_info, NULL);
	tcore_object_add_callback(co, "+CSSU", on_notification_imc_call_ss_cssu_info, NULL);
	tcore_object_add_callback(co, "+CSSI", on_notification_imc_call_ss_cssi_info, NULL);

	return TRUE;
}

void imc_call_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
