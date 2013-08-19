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
#include <storage.h>
#include <co_call.h>
#include <user_request.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_call.h"


#define STATUS_INCOMING    4
#define STATUS_WAITING     5
#define STATUS_CONNECTED   7
#define COMMA              0X2c

static gboolean setsoundpath = FALSE;
static gboolean soundvolume = FALSE;

// End Cause field  - Call state end cause

typedef enum {
	CALL_END_NO_CAUSE,

	// These definitions are taken from GSM 04.08 Table 10.86

	CC_CAUSE_UNASSIGNED_NUMBER,
	CC_CAUSE_NO_ROUTE_TO_DEST,
	CC_CAUSE_CHANNEL_UNACCEPTABLE,
	CC_CAUSE_OPERATOR_DETERMINED_BARRING,
	CC_CAUSE_NORMAL_CALL_CLEARING,
	CC_CAUSE_USER_BUSY,
	CC_CAUSE_NO_USER_RESPONDING,
	CC_CAUSE_USER_ALERTING_NO_ANSWER,
	CC_CAUSE_CALL_REJECTED,
	CC_CAUSE_NUMBER_CHANGED,
	CC_CAUSE_NON_SELECTED_USER_CLEARING,
	CC_CAUSE_DESTINATION_OUT_OF_ORDER,
	CC_CAUSE_INVALID_NUMBER_FORMAT,
	CC_CAUSE_FACILITY_REJECTED,
	CC_CAUSE_RESPONSE_TO_STATUS_ENQUIRY,
	CC_CAUSE_NORMAL_UNSPECIFIED,
	CC_CAUSE_NO_CIRCUIT_CHANNEL_AVAILABLE,
	CC_CAUSE_NETWORK_OUT_OF_ORDER,
	CC_CAUSE_TEMPORARY_FAILURE,
	CC_CAUSE_SWITCHING_EQUIPMENT_CONGESTION,
	CC_CAUSE_ACCESS_INFORMATION_DISCARDED,
	CC_CAUSE_REQUESTED_CIRCUIT_CHANNEL_NOT_AVAILABLE,
	CC_CAUSE_RESOURCES_UNAVAILABLE_UNSPECIFIED,
	CC_CAUSE_QUALITY_OF_SERVICE_UNAVAILABLE,
	CC_CAUSE_REQUESTED_FACILITY_NOT_SUBSCRIBED,
	CC_CAUSE_INCOMING_CALL_BARRED_WITHIN_CUG,
	CC_CAUSE_BEARER_CAPABILITY_NOT_AUTHORISED,
	CC_CAUSE_BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE,
	CC_CAUSE_SERVICE_OR_OPTION_NOT_AVAILABLE,
	CC_CAUSE_BEARER_SERVICE_NOT_IMPLEMENTED,
	CC_CAUSE_ACM_GEQ_ACMMAX,
	CC_CAUSE_REQUESTED_FACILITY_NOT_IMPLEMENTED,
	CC_CAUSE_ONLY_RESTRICTED_DIGITAL_INFO_BC_AVAILABLE,
	CC_CAUSE_SERVICE_OR_OPTION_NOT_IMPLEMENTED,
	CC_CAUSE_INVALID_TRANSACTION_ID_VALUE,
	CC_CAUSE_USER_NOT_MEMBER_OF_CUG,
	CC_CAUSE_INCOMPATIBLE_DESTINATION,
	CC_CAUSE_INVALID_TRANSIT_NETWORK_SELECTION,
	CC_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE,
	CC_CAUSE_INVALID_MANDATORY_INFORMATION,
	CC_CAUSE_MESSAGE_TYPE_NON_EXISTENT,
	CC_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROT_STATE,
	CC_CAUSE_IE_NON_EXISTENT_OR_NOT_IMPLEMENTED,
	CC_CAUSE_CONDITIONAL_IE_ERROR,
	CC_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE,
	CC_CAUSE_RECOVERY_ON_TIMER_EXPIRY,
	CC_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
	CC_CAUSE_INTERWORKING_UNSPECIFIED,
	CC_CAUSE_END = 128,

	// Reject causes
	REJECT_CAUSE_IMSI_UNKNOWN_IN_HLR,
	REJECT_CAUSE_ILLEGAL_MS,
	REJECT_CAUSE_IMSI_UNKNOWN_IN_VLR,
	REJECT_CAUSE_IMEI_NOT_ACCEPTED,
	REJECT_CAUSE_ILLEGAL_ME,
	REJECT_CAUSE_GPRS_SERVICES_NOT_ALLOWED,
	REJECT_CAUSE_GPRS_SERVICES_AND_NON_GPRS_SERVICES_NOT_ALLOWED,
	REJECT_CAUSE_MS_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK,
	REJECT_CAUSE_IMPLICITLY_DETACHED,
	REJECT_CAUSE_PLMN_NOT_ALLOWED,
	REJECT_CAUSE_LA_NOT_ALLOWED,
	REJECT_CAUSE_NATIONAL_ROAMING_NOT_ALLOWED,
	REJECT_CAUSE_GPRS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN,
	REJECT_CAUSE_NO_SUITABLE_CELLS_IN_LA,
	REJECT_CAUSE_MSC_TEMPORARILY_NOT_REACHABLE,
	REJECT_CAUSE_NETWORK_FAILURE,
	REJECT_CAUSE_MAC_FAILURE,
	REJECT_CAUSE_SYNCH_FAILURE,
	REJECT_CAUSE_CONGESTTION,
	REJECT_CAUSE_GSM_AUTH_UNACCEPTED,
	REJECT_CAUSE_SERVICE_OPTION_NOT_SUPPORTED,
	REJECT_CAUSE_REQ_SERV_OPT_NOT_SUBSCRIBED,
	REJECT_CAUSE_SERVICE_OPT__OUT_OF_ORDER,
	REJECT_CAUSE_CALL_CANNOT_BE_IDENTIFIED,
	REJECT_CAUSE_NO_PDP_CONTEXT_ACTIVATED,
	REJECT_CAUSE_RETRY_UPON_ENTRY_INTO_A_NEW_CELL_MIN_VALUE,
	REJECT_CAUSE_RETRY_UPON_ENTRY_INTO_A_NEW_CELL_MAX_VALUE,
	REJECT_CAUSE_SEMANTICALLY_INCORRECT_MSG,
	REJECT_CAUSE_INVALID_MANDATORY_INFO,
	REJECT_CAUSE_MESSAGE_TYPE_NON_EXISTANT,
	REJECT_CAUSE_MESSAGE_TYPE_NOT_COMP_PRT_ST,
	REJECT_CAUSE_IE_NON_EXISTANT,
	REJECT_CAUSE_MSG_NOT_COMPATIBLE_PROTOCOL_STATE,


	// Connection Management establishment rejection cause
	REJECT_CAUSE_REJ_UNSPECIFIED,

	// AS reject causes
	REJECT_CAUSE_AS_REJ_RR_REL_IND,
	REJECT_CAUSE_AS_REJ_RR_RANDOM_ACCESS_FAILURE,
	REJECT_CAUSE_AS_REJ_RRC_REL_IND,
	REJECT_CAUSE_AS_REJ_RRC_CLOSE_SESSION_IND,
	REJECT_CAUSE_AS_REJ_RRC_OPEN_SESSION_FAILURE,
	REJECT_CAUSE_AS_REJ_LOW_LEVEL_FAIL,
	REJECT_CAUSE_AS_REJ_LOW_LEVEL_FAIL_REDIAL_NOT_ALLOWED,
	REJECT_CAUSE_AS_REJ_LOW_LEVEL_IMMED_RETRY,

	// MM reject causes
	REJECT_CAUSE_MM_REJ_INVALID_SIM,
	REJECT_CAUSE_MM_REJ_NO_SERVICE,
	REJECT_CAUSE_MM_REJ_TIMER_T3230_EXP,
	REJECT_CAUSE_MM_REJ_NO_CELL_AVAILABLE,
	REJECT_CAUSE_MM_REJ_WRONG_STATE,
	REJECT_CAUSE_MM_REJ_ACCESS_CLASS_BLOCKED,
	// Definitions for release ind causes between MM  and CNM
	REJECT_CAUSE_ABORT_MSG_RECEIVED,
	REJECT_CAUSE_OTHER_CAUSE,

	// CNM reject causes
	REJECT_CAUSE_CNM_REJ_TIMER_T303_EXP,
	REJECT_CAUSE_CNM_REJ_NO_RESOURCES,
	REJECT_CAUSE_CNM_MM_REL_PENDING,
	REJECT_CAUSE_CNM_INVALID_USER_DATA,
	CALL_END_CAUSE_MAX = 255
} call_end_cause_e_type;


struct clcc_call_t {
	struct call_CLCC_info {
		int id;
		enum tcore_call_direction direction;
		enum tcore_call_status status;
		enum tcore_call_type type;
		int mpty;
		int num_len;
		int num_type;
	}
	info;
	char number[90];
};

typedef struct {
	int network_cause;
	int tapi_cause;
} call_end_cause_info;

/**************************************************************************
  *							Local Function Prototypes
  **************************************************************************/
/*************************		REQUESTS		***************************/
static void _call_status_idle(TcorePlugin *p, CallObject *co);
static void _call_status_active(TcorePlugin *p, CallObject *co);
static void _call_status_dialing(TcorePlugin *p, CallObject *co);
static void _call_status_alert(TcorePlugin *p, CallObject *co);
static void _call_status_incoming(TcorePlugin *p, CallObject *co);
static void _call_status_waiting(TcorePlugin *p, CallObject *co);
static TReturn _call_list_get(CoreObject *o, gboolean *event_flag);
static TReturn _set_dtmf_tone_duration(CoreObject *o, UserRequest *ur);

/*************************		CONFIRMATION		***************************/
static void on_confirmation_call_message_send(TcorePending *p, gboolean result, void *user_data);     // from Kernel
static void on_confirmation_call_hold(TcorePending *p, int data_len, const void *data, void *user_data);
static void on_confirmation_call_swap(TcorePending *p, int data_len, const void *data, void *user_data);
static void on_confirmation_call_split(TcorePending *p, int data_len, const void *data, void *user_data);
static void on_confirmation_call_hold_and_accept(TcorePending *p, int data_len, const void *data, void *user_data);

static void _on_confirmation_call_release(TcorePending *p, int data_len, const void *data, void *user_data, int type);
static void _on_confirmation_call(TcorePending *p, int data_len, const void *data, void *user_data, int type);
static void _on_confirmation_dtmf_tone_duration(TcorePending *p, int data_len, const void *data, void *user_data);
static void _on_confirmation_call_end_cause(TcorePending *p, int data_len, const void *data, void *user_data);

/*************************		RESPONSES		***************************/
static void on_response_call_list_get(TcorePending *p, int data_len, const void *data, void *user_data);

/*************************		NOTIIFICATIONS		***************************/
static void on_notification_call_waiting(CoreObject *o, const void *data, void *user_data);
static void on_notification_call_incoming(CoreObject *o, const void *data, void *user_data);
static void on_notification_call_status(CoreObject *o, const void *data, void *user_data);
static gboolean on_notification_call_info(CoreObject *o, const void *data, void *user_data);
static gboolean on_notification_call_clip_info(CoreObject *o, const void *data, void *user_data);


/**************************************************************************
  *							Local Utility Function Prototypes
  **************************************************************************/
static gboolean _call_request_message(TcorePending *pending, CoreObject *o, UserRequest *ur, void *on_resp, void *user_data);
static void _call_branch_by_status(TcorePlugin *p, CallObject *co, unsigned int status);
static int _callFromCLCCLine(char *line, struct clcc_call_t *p_call);

/**************************************************************************
  *							Local Function Definitions
  **************************************************************************/

const call_end_cause_info call_end_cause_table[] =   // call end cause table to convert Netwotk cause to TAPI cause
{
	{ 1, CC_CAUSE_UNASSIGNED_NUMBER}, { 3, CC_CAUSE_NO_ROUTE_TO_DEST},
	{ 6, CC_CAUSE_CHANNEL_UNACCEPTABLE}, { 8, CC_CAUSE_OPERATOR_DETERMINED_BARRING},
	{ 16, CC_CAUSE_NORMAL_CALL_CLEARING}, { 17, CC_CAUSE_USER_BUSY},
	{ 18, CC_CAUSE_NO_USER_RESPONDING}, { 19, CC_CAUSE_USER_ALERTING_NO_ANSWER},
	{ 21, CC_CAUSE_CALL_REJECTED}, { 22, CC_CAUSE_NUMBER_CHANGED},
	{ 26, CC_CAUSE_NON_SELECTED_USER_CLEARING}, { 27, CC_CAUSE_DESTINATION_OUT_OF_ORDER},
	{ 28, CC_CAUSE_INVALID_NUMBER_FORMAT}, { 29, CC_CAUSE_FACILITY_REJECTED},
	{ 30, CC_CAUSE_RESPONSE_TO_STATUS_ENQUIRY}, { 31, CC_CAUSE_NORMAL_UNSPECIFIED},
	{ 34, CC_CAUSE_NO_CIRCUIT_CHANNEL_AVAILABLE}, { 38, CC_CAUSE_NETWORK_OUT_OF_ORDER},
	{ 41, CC_CAUSE_TEMPORARY_FAILURE}, { 42, CC_CAUSE_SWITCHING_EQUIPMENT_CONGESTION},
	{ 43, CC_CAUSE_ACCESS_INFORMATION_DISCARDED}, { 44, CC_CAUSE_REQUESTED_CIRCUIT_CHANNEL_NOT_AVAILABLE},
	{ 47, CC_CAUSE_RESOURCES_UNAVAILABLE_UNSPECIFIED}, { 49, CC_CAUSE_QUALITY_OF_SERVICE_UNAVAILABLE},
	{ 50, CC_CAUSE_REQUESTED_FACILITY_NOT_SUBSCRIBED}, { 55, CC_CAUSE_INCOMING_CALL_BARRED_WITHIN_CUG},
	{ 57, CC_CAUSE_BEARER_CAPABILITY_NOT_AUTHORISED}, { 58, CC_CAUSE_BEARER_CAPABILITY_NOT_PRESENTLY_AVAILABLE},
	{ 63, CC_CAUSE_SERVICE_OR_OPTION_NOT_AVAILABLE}, { 65, CC_CAUSE_BEARER_SERVICE_NOT_IMPLEMENTED},
	{ 68, CC_CAUSE_ACM_GEQ_ACMMAX}, { 69, CC_CAUSE_REQUESTED_FACILITY_NOT_IMPLEMENTED},
	{ 70, CC_CAUSE_ONLY_RESTRICTED_DIGITAL_INFO_BC_AVAILABLE}, { 79, CC_CAUSE_SERVICE_OR_OPTION_NOT_IMPLEMENTED},
	{ 81, CC_CAUSE_INVALID_TRANSACTION_ID_VALUE}, { 87, CC_CAUSE_USER_NOT_MEMBER_OF_CUG},
	{ 88, CC_CAUSE_INCOMPATIBLE_DESTINATION}, { 91, CC_CAUSE_INVALID_TRANSIT_NETWORK_SELECTION},
	{ 95, CC_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE}, { 96, CC_CAUSE_INVALID_MANDATORY_INFORMATION},
	{ 97, CC_CAUSE_MESSAGE_TYPE_NON_EXISTENT}, { 98, CC_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROT_STATE},
	{ 99, CC_CAUSE_IE_NON_EXISTENT_OR_NOT_IMPLEMENTED}, { 100, CC_CAUSE_CONDITIONAL_IE_ERROR},
	{ 101, CC_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE}, { 102, CC_CAUSE_RECOVERY_ON_TIMER_EXPIRY},
	{ 111, CC_CAUSE_PROTOCOL_ERROR_UNSPECIFIED}, {127, CC_CAUSE_INTERWORKING_UNSPECIFIED},
};

static enum tcore_call_cli_mode _get_clir_status(char *num)
{
	enum tcore_call_cli_mode clir = TCORE_CALL_CLI_MODE_DEFAULT;

	dbg("Entry");

	if (!strncmp(num, "*31#", 4)) {
		dbg("CLI mode restricted");
		return TCORE_CALL_CLI_MODE_RESTRICT;
	}

	if (!strncmp(num, "#31#", 4)) {
		dbg("CLI mode allowed");
		return TCORE_CALL_CLI_MODE_PRESENT;
	}

	dbg("CLI mode default");

	dbg("Exit");

	return clir;
}

static enum tcore_call_status _call_status(unsigned int status)
{
	dbg("Entry");

	switch (status) {
	case 0:
		return TCORE_CALL_STATUS_ACTIVE;

	case 1:
		return TCORE_CALL_STATUS_HELD;

	case 2:
		return TCORE_CALL_STATUS_DIALING;

	case 3:
		return TCORE_CALL_STATUS_ALERT;

	case 4:
		return TCORE_CALL_STATUS_INCOMING;

	case 5:
		return TCORE_CALL_STATUS_WAITING;

	case 6:         // DISCONNECTED state  // FALL THROUGH
	default:
		return TCORE_CALL_STATUS_IDLE;
	}
}

static gboolean _call_is_in_mpty(int mpty)
{
	dbg("Entry");

	switch (mpty) {
	case 0:
		return FALSE;

	case 1:
		return TRUE;

	default:
		break;
	}

	return FALSE;
}

static enum tcore_call_type call_type(int type)
{
	dbg("Entry");

	switch (type) {
	case 0:
		return TCORE_CALL_TYPE_VOICE;

	case 1:
		return TCORE_CALL_TYPE_VIDEO;

	default:
		break;
	}

	return TCORE_CALL_TYPE_VOICE;
}

static int _compare_call_end_cause(int networkcause)
{
	unsigned int count;

	for (count = 0; count < sizeof(call_end_cause_table) / sizeof(call_end_cause_info); count++) {
		if (call_end_cause_table[count].network_cause == networkcause)
			return (call_end_cause_table[count].tapi_cause);
	}
	return CC_CAUSE_NORMAL_CALL_CLEARING;
	dbg("Exit");
}

static gboolean on_notification_call_clip_info(CoreObject *o, const void *data, void *user_data)
{
	dbg("Entry");

	// TODO

	return TRUE;
}

static gboolean on_notification_call_info(CoreObject *o, const void *data, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	const char *line = NULL;
	char *stat;
	int status;

	dbg("Entry");

	lines = (GSList *) data;
	if (1 != g_slist_length(lines)) {
		err("Unsolicited message, BUT multiple lines present");
		goto OUT;
	}

	line = (char *) (lines->data);
	tokens = tcore_at_tok_new(line);

	stat = g_slist_nth_data(tokens, 1);
	if (!stat) {
		dbg("Stat is missing from %XCALLSTAT indiaction");
	} else {
		status = atoi(stat);

		switch (status) {
		case STATUS_INCOMING:
			dbg("calling on_notification_call_incoming");
			on_notification_call_incoming(o, line, user_data);
			break;

		case STATUS_WAITING:
			dbg("calling on_notification_call_waiting");
			on_notification_call_waiting(o, line, user_data);
			break;

		case STATUS_CONNECTED:     /*igonre Connected state. */
			dbg("Connected state");
			break;

		default:
			dbg("calling on_notification_call_status");
			on_notification_call_status(o, line, user_data);
			break;
		}
	}

	// Free tokens
	tcore_at_tok_free(tokens);

OUT:
	dbg("Exit");
	return TRUE;
}

static gboolean _call_request_message(TcorePending *pending,
									  CoreObject *o,
									  UserRequest *ur,
									  void *on_resp,
									  void *user_data)
{
	TcoreHal *hal = NULL;
	TReturn ret;

	dbg("Entry");

	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);

	if (on_resp) {
		tcore_pending_set_response_callback(pending, on_resp, user_data);
	}
	tcore_pending_set_send_callback(pending, on_confirmation_call_message_send, NULL);

	if (ur) {
		tcore_pending_link_user_request(pending, ur);
	} else {
		err("User Request is NULL, is this internal request??");
	}

	// HAL
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

static void _call_status_idle(TcorePlugin *p, CallObject *co)
{
	CoreObject *core_obj = NULL;
	char *cmd_str = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req = NULL;
	gboolean ret = FALSE;
	UserRequest *ur;

	dbg("Entry");
	core_obj = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL);
	dbg("Call ID [%d], Call Status [%d]", tcore_call_object_get_id(co), tcore_call_object_get_status(co));

	if (tcore_call_object_get_status(co) != TCORE_CALL_STATUS_IDLE) {
		// get call end cause.
		cmd_str = g_strdup_printf("%s", "AT+XCEER");
		dbg("Request command string: %s", cmd_str);

		// Create new Pending request
		pending = tcore_pending_new(core_obj, 0);

		// Create new AT-Command request
		req = tcore_at_request_new(cmd_str, "+XCEER", TCORE_AT_SINGLELINE);
		dbg("Command: %s, prefix(if any): %s, Command length: %d", req->cmd, req->prefix, strlen(req->cmd));
		// Free command string
		g_free(cmd_str);

		// Set request data (AT command) to Pending request
		tcore_pending_set_request_data(pending, 0, req);

		ur = tcore_user_request_new(NULL, NULL);
		// Send request
		ret = _call_request_message(pending, core_obj, ur, _on_confirmation_call_end_cause, co);

		if (!ret) {
			err("Failed to send AT-Command request");
			// free only UserRequest.
			if (ur) {
				tcore_user_request_free(ur);
				ur = NULL;
			}
			return;
		}
	} else {
		err("Call object was not free");
		tcore_call_object_free(core_obj, co);
	}
	dbg("Exit");
	return;
}

static void _call_status_dialing(TcorePlugin *p, CallObject *co)
{
	struct tnoti_call_status_dialing data;

	dbg("Entry");

	if (tcore_call_object_get_status(co) != TCORE_CALL_STATUS_DIALING) {
		data.type = tcore_call_object_get_type(co);
		dbg("data.type : [%d]", data.type);

		data.id = tcore_call_object_get_id(co);
		dbg("data.id : [%d]", data.id);

		// Set Status
		tcore_call_object_set_status(co, TCORE_CALL_STATUS_DIALING);

		// Send notification to TAPI
		tcore_server_send_notification(tcore_plugin_ref_server(p),
									   tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL),
									   TNOTI_CALL_STATUS_DIALING,
									   sizeof(struct tnoti_call_status_dialing),
									   (void *) &data);
	}

	dbg("Exit");
	return;
}

static void _call_status_alert(TcorePlugin *p, CallObject *co)
{
	struct tnoti_call_status_alert data;

	dbg("Entry");

	// Alerting has just 1 data 'CALL ID'
	if (tcore_call_object_get_status(co) != TCORE_CALL_STATUS_ALERT) {
		data.type = tcore_call_object_get_type(co);
		dbg("data.type : [%d]", data.type);

		data.id = tcore_call_object_get_id(co);
		dbg("data.id : [%d]", data.id);

		// Set Status
		tcore_call_object_set_status(co, TCORE_CALL_STATUS_ALERT);

		// Send notification to TAPI
		tcore_server_send_notification(tcore_plugin_ref_server(p),
									   tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL),
									   TNOTI_CALL_STATUS_ALERT,
									   sizeof(struct tnoti_call_status_alert),
									   (void *) &data);
	}

	dbg("Exit");
	return;
}

static void _call_status_active(TcorePlugin *p, CallObject *co)
{
	struct tnoti_call_status_active data;

	dbg("Entry");

	if (tcore_call_object_get_status(co) != TCORE_CALL_STATUS_ACTIVE) {
		data.type = tcore_call_object_get_type(co);
		dbg("data.type : [%d]", data.type);

		data.id = tcore_call_object_get_id(co);
		dbg("data.id : [%d]", data.id);

		// Set Status
		tcore_call_object_set_status(co, TCORE_CALL_STATUS_ACTIVE);

		// Send notification to TAPI
		tcore_server_send_notification(tcore_plugin_ref_server(p),
									   tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL),
									   TNOTI_CALL_STATUS_ACTIVE,
									   sizeof(struct tnoti_call_status_active),
									   (void *) &data);
	}

	dbg("Exit");
	return;
}

static void _call_status_held(TcorePlugin *p, CallObject *co)
{
	struct tnoti_call_status_held data;

	dbg("Entry");

	if (tcore_call_object_get_status(co) != TCORE_CALL_STATUS_HELD) {
		data.type = tcore_call_object_get_type(co);
		dbg("data.type : [%d]", data.type);

		data.id = tcore_call_object_get_id(co);
		dbg("data.id : [%d]", data.id);

		// Set Status
		tcore_call_object_set_status(co, TCORE_CALL_STATUS_HELD);

		// Send notification to TAPI
		tcore_server_send_notification(tcore_plugin_ref_server(p),
									   tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL),
									   TNOTI_CALL_STATUS_HELD,
									   sizeof(struct tnoti_call_status_held),
									   (void *) &data);
	}

	dbg("Exit");
	return;
}

static void _call_status_incoming(TcorePlugin *p, CallObject *co)
{
	struct tnoti_call_status_incoming data;

	dbg("Entry");

	if (tcore_call_object_get_status(co) != TCORE_CALL_STATUS_INCOMING) {
		tcore_call_object_set_status(co, TCORE_CALL_STATUS_INCOMING);

		data.type = tcore_call_object_get_type(co);
		dbg("data.type : [%d]", data.type);

		data.id = tcore_call_object_get_id(co);
		dbg("data.id : [%d]", data.id);

		data.cli.mode = tcore_call_object_get_cli_mode(co);
		dbg("data.cli.mode : [%d]", data.cli.mode);

		tcore_call_object_get_number(co, data.cli.number);
		dbg("data.cli.number : [%s]", data.cli.number);

		data.cna.mode = tcore_call_object_get_cna_mode(co);
		dbg("data.cna.mode : [%d]", data.cna.mode);

		tcore_call_object_get_name(co, data.cna.name);
		dbg("data.cna.name : [%s]", data.cna.name);

		data.forward = FALSE; // this is tmp code

		data.active_line = tcore_call_object_get_active_line(co);
		dbg("data.active_line : [%d]", data.active_line);

		// Send notification to TAPI
		tcore_server_send_notification(tcore_plugin_ref_server(p),
									   tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_CALL),
									   TNOTI_CALL_STATUS_INCOMING,
									   sizeof(struct tnoti_call_status_incoming),
									   (void *) &data);
	}

	dbg("Exit");
	return;
}

static void _call_status_waiting(TcorePlugin *p, CallObject *co)
{
	dbg("Entry");
	_call_status_incoming(p, co);

	dbg("Exit");
	return;
}

static void _call_branch_by_status(TcorePlugin *p, CallObject *co, unsigned int status)
{
	dbg("Entry");

	dbg("Call Status is %d", status);
	switch (status) {
	case TCORE_CALL_STATUS_IDLE:
		_call_status_idle(p, co);
		break;

	case TCORE_CALL_STATUS_ACTIVE:
		_call_status_active(p, co);
		break;

	case TCORE_CALL_STATUS_HELD:
		_call_status_held(p, co);
		break;

	case TCORE_CALL_STATUS_DIALING:
		_call_status_dialing(p, co);
		break;

	case TCORE_CALL_STATUS_ALERT:
		_call_status_alert(p, co);
		break;

	case TCORE_CALL_STATUS_INCOMING:
		_call_status_incoming(p, co);
		break;

	case TCORE_CALL_STATUS_WAITING:
		_call_status_waiting(p, co);
		break;
	}

	dbg("Exit");
	return;
}

static TReturn _call_list_get(CoreObject *o, gboolean *event_flag)
{
	UserRequest *ur = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	TcoreATRequest *req = NULL;
	gboolean ret = FALSE;

	dbg("Entry");
	if (!o) {
		err("Core Object is NULL");
		return TCORE_RETURN_FAILURE;
	}

	// Create new User Request
	ur = tcore_user_request_new(NULL, NULL);

	// Command string
	cmd_str = g_strdup("AT+CLCC");

	// Create new Pending Request
	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, "+CLCC", TCORE_AT_MULTILINE);

	g_free(cmd_str);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);

	ret = _call_request_message(pending, o, ur, on_response_call_list_get, event_flag);
	if (!ret) {
		err("AT request (%s) sending failed", req->cmd);
		// free only UserRequest.
		if (ur) {
			tcore_user_request_free(ur);
			ur = NULL;
		}
		return TCORE_RETURN_FAILURE;
	}

	dbg("AT request sent success");
	return TCORE_RETURN_SUCCESS;
}

// CONFIRMATION
static void on_confirmation_call_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("Entry");

	if (result == FALSE) {  // Fail
		dbg("SEND FAIL");
	} else {
		dbg("SEND OK");
	}

	dbg("Exit");
	return;
}

static void call_prepare_and_send_pending_request(CoreObject *co, const char *at_cmd, const char *prefix, enum tcore_at_command_type at_cmd_type, TcorePendingResponseCallback callback)
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
	tcore_pending_set_send_callback(pending, on_confirmation_call_message_send, NULL);
	ret = tcore_hal_send_request(hal, pending);
}

static void on_confirmation_call_outgoing(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	struct tresp_call_dial resp;
	enum telephony_call_error error;
	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			resp.err = CALL_ERROR_NONE;
		} else {
			dbg("RESPONSE NOT OK");

			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("Unspecified error cause OR string corrupted");
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));

				// TODO: CMEE error mapping is required.
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			}

			// Free tokens
			tcore_at_tok_free(tokens);
		}

		// Send Response to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_DIAL, sizeof(struct tresp_call_dial), &resp);
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void on_confirmation_call_accept(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	struct tresp_call_answer resp;
	enum telephony_call_error error;
	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			resp.err = CALL_ERROR_NONE;
		} else {
			dbg("RESPONSE NOT OK");

			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("Unspecified error cause OR string corrupted");
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));

				// TODO: CMEE error mapping is required.
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			}

			// Free tokens
			tcore_at_tok_free(tokens);
		}

		resp.id = tcore_call_object_get_id((CallObject *) user_data);

		// Send Response to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_ANSWER, sizeof(struct tresp_call_answer), &resp);
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}


static void on_confirmation_call_reject(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	struct tresp_call_answer resp;
	enum telephony_call_error error;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			resp.err = CALL_ERROR_NONE;
		} else {
			dbg("RESPONSE NOT OK");
			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("Unspecified error cause OR string corrupted");
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));
				// TODO: CMEE error mapping is required.
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			}

			// Free tokens
			tcore_at_tok_free(tokens);
		}

		resp.id = tcore_call_object_get_id((CallObject *) user_data);

		// Send Response to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_ANSWER, sizeof(struct tresp_call_answer), &resp);
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void on_confirmation_call_replace(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	struct tresp_call_answer resp;
	enum telephony_call_error error;

	dbg("Entry");
	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			resp.err = CALL_ERROR_NONE;
		} else {
			dbg("RESPONSE NOT OK");
			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("Unspecified error cause OR string corrupted");
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));
				// TODO: CMEE error mapping is required.
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			}

			// Free tokens
			tcore_at_tok_free(tokens);
		}
		resp.id = tcore_call_object_get_id((CallObject *) user_data);

		// Send Response to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_ANSWER, sizeof(struct tresp_call_answer), &resp);
	} else {
		dbg("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void on_confirmation_call_hold_and_accept(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *o = NULL;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	struct tresp_call_answer resp;
	enum telephony_call_error error;

	dbg("Entry");

	o = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	resp.id = tcore_call_object_get_id((CallObject *) user_data);

	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("RESPONSE NOT OK");
			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("Unspecified error cause OR string corrupted");
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));

				// TODO: CMEE error mapping is required.
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			}

			// Free tokens
			tcore_at_tok_free(tokens);
		}

		// Send response to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_ANSWER, sizeof(struct tresp_call_answer), &resp);
		if (!resp.err) {
			GSList *list = 0;
			CallObject *co = NULL;

			// Active Call
			list = tcore_call_object_find_by_status(o, TCORE_CALL_STATUS_ACTIVE);
			if (!list) {
				err("Can't find active Call");
				return;
			}

			co = (CallObject *) list->data;
			if (!co) {
				err("Can't get active Call object");
				return;
			}

			// Set Call Status
			tcore_call_object_set_status(co, TCORE_CALL_STATUS_HELD);
			dbg("Call status is set to HELD");
		}
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void _on_confirmation_call_release(TcorePending *p, int data_len, const void *data, void *user_data, int type)
{
	UserRequest *ur = NULL;
	struct tresp_call_end resp;
	GSList *tokens = NULL;
	const char *line = NULL;
	enum telephony_call_error error;
	const TcoreATResponse *response = data;

	dbg("Entry");
	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("RESPONSE NOT OK");

			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("Unspecified error cause OR string corrupted");
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));

				// TODO: CMEE error mapping is required.
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			}
			tcore_at_tok_free(tokens);
		}

		resp.type = type;
		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("resp.type = %d  resp.id= %d", resp.type, resp.id);

		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_END, sizeof(struct tresp_call_end), &resp);
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

// RESPONSE
static void on_confirmation_call_endall(TcorePending *p, int data_len, const void *data, void *user_data)
{
	// skip response handling - actual result will be handled in on_confirmation_call_release_all
	const TcoreATResponse *response = data;

	dbg("Entry");

	if (response->success > 0) {
		dbg("RESPONSE OK");
	} else {
		err("RESPONSE NOT OK");
	}

	dbg("Exit");
	return;
}


static void on_confirmation_call_release_all(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call_release(p, data_len, data, user_data, CALL_END_TYPE_ALL);

	return;
}


static void on_confirmation_call_release_specific(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call_release(p, data_len, data, user_data, CALL_END_TYPE_DEFAULT);

	return;
}

static void on_confirmation_call_release_all_active(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call_release(p, data_len, data, user_data, CALL_END_TYPE_ACTIVE_ALL);

	return;
}

static void on_confirmation_call_release_all_held(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call_release(p, data_len, data, user_data, CALL_END_TYPE_HOLD_ALL);

	return;
}

static void _on_confirmation_call(TcorePending *p, int data_len, const void *data, void *user_data, int type)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = NULL;
	enum telephony_call_error error;

	dbg("Entry");
	ur = tcore_pending_ref_user_request(p);
	response = (TcoreATResponse *) data;
	if (response->success > 0) {
		dbg("RESPONSE OK");
		error = CALL_ERROR_NONE;
	} else {
		err("RESPONSE NOT OK");

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			err("Unspecified error cause OR string corrupted");
			error = CALL_ERROR_SERVICE_UNAVAIL;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));

			// TODO: CMEE error mapping is required.
			error = CALL_ERROR_SERVICE_UNAVAIL;
		}

		// Free tokens
		tcore_at_tok_free(tokens);
	}

	dbg("Response Call type -%d", type);
	switch (type) {
	case TRESP_CALL_HOLD:
	{
		struct tresp_call_hold resp;

		resp.err = error;
		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("call hold response");
		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_HOLD, sizeof(struct tresp_call_hold), &resp);
	}
	break;

	case TRESP_CALL_ACTIVE:
	{
		struct tresp_call_active resp;

		resp.err = error;
		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("call active response");
		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_ACTIVE, sizeof(struct tresp_call_active), &resp);
	}
	break;

	case TRESP_CALL_JOIN:
	{
		struct tresp_call_join resp;

		resp.err = error;
		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("call join response");

		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_JOIN, sizeof(struct tresp_call_join), &resp);
	}
	break;

	case TRESP_CALL_SPLIT:
	{
		struct tresp_call_split resp;

		resp.err = error;
		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("call split response");
		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_SPLIT, sizeof(struct tresp_call_split), &resp);
	}
	break;

	case TRESP_CALL_DEFLECT:
	{
		struct tresp_call_deflect resp;

		resp.err = error;
		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("call deflect response");
		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_DEFLECT, sizeof(struct tresp_call_deflect), &resp);
	}

	break;

	case TRESP_CALL_TRANSFER:
	{
		struct tresp_call_transfer resp;

		resp.err = error;
		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("call transfer response");
		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_TRANSFER, sizeof(struct tresp_call_transfer), &resp);
	}
	break;

	case TRESP_CALL_SEND_DTMF:
	{
		struct tresp_call_dtmf resp;

		resp.err = error;
		dbg("call dtmf response");
		// Send reponse to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_SEND_DTMF, sizeof(struct tresp_call_dtmf), &resp);
	}
	break;

	default:
	{
		dbg("type not supported");
		return;
	}
	}

	if ((type == TRESP_CALL_HOLD) || (type == TRESP_CALL_ACTIVE) || (type == TRESP_CALL_JOIN)
		|| (type == TRESP_CALL_SPLIT)) {
		if (!error) {
			CoreObject *core_obj = NULL;
			gboolean *eflag = g_new0(gboolean, 1);

			core_obj = tcore_pending_ref_core_object(p);
			*eflag = FALSE;

			dbg("Calling _call_list_get");
			_call_list_get(core_obj, eflag);
		}
	}

	dbg("Exit");
	return;
}

static void on_confirmation_call_hold(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call(p, data_len, data, user_data, TRESP_CALL_HOLD);

	return;
}

static void on_confirmation_call_active(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call(p, data_len, data, user_data, TRESP_CALL_ACTIVE);

	return;
}

static void on_confirmation_call_join(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call(p, data_len, data, user_data, TRESP_CALL_JOIN);

	return;
}

static void on_confirmation_call_split(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call(p, data_len, data, user_data, TRESP_CALL_SPLIT);

	return;
}

static void on_confirmation_call_deflect(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call(p, data_len, data, user_data, TRESP_CALL_DEFLECT);

	return;
}

static void on_confirmation_call_transfer(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call(p, data_len, data, user_data, TRESP_CALL_TRANSFER);

	return;
}

static void on_confirmation_call_dtmf(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	_on_confirmation_call(p, data_len, data, user_data, TRESP_CALL_SEND_DTMF);

	return;
}

static void _on_confirmation_dtmf_tone_duration(TcorePending *p, int data_len, const void *data, void *user_data)
{
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	enum telephony_call_error error;

	dbg("Entry");

	if (response->success > 0) {
		dbg("RESPONSE OK");
		error = CALL_ERROR_NONE;
	} else {
		err("RESPONSE NOT OK");
		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("err cause not specified or string corrupted");
			error = CALL_ERROR_SERVICE_UNAVAIL;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));
			// TODO: CMEE error mapping is required.
		}

		// Free tokens
		tcore_at_tok_free(tokens);
	}

	dbg("Set dtmf tone duration response - %d", error);
	return;
}

static void on_confirmation_call_swap(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *core_obj = NULL;
	UserRequest *ur = NULL;
	const TcoreATResponse *response = data;
	struct tresp_call_swap resp;
	GSList *tokens = NULL;
	const char *line = NULL;

	dbg("Entry");
	core_obj = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			resp.err = CALL_ERROR_NONE;
		} else {
			err("RESPONSE NOT OK");
			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				err("err cause not specified or string corrupted");
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			} else {
				resp.err = atoi(g_slist_nth_data(tokens, 0));

				// TODO: CMEE error mapping is required.
				resp.err = CALL_ERROR_SERVICE_UNAVAIL;
			}

			// Free tokens
			tcore_at_tok_free(tokens);
		}

		resp.id = tcore_call_object_get_id((CallObject *) user_data);
		dbg("resp.id = %d", resp.id);

		// Send response to TAPI
		tcore_user_request_send_response(ur, TRESP_CALL_SWAP, sizeof(struct tresp_call_swap), &resp);

		if (!resp.err) {
			GSList *active = NULL;
			GSList *held = NULL;
			CallObject *co = NULL;
			gboolean *eflag = NULL;

			held = tcore_call_object_find_by_status(core_obj, TCORE_CALL_STATUS_HELD);
			if (!held) {
				err("Can't find held Call");
				return;
			}

			active = tcore_call_object_find_by_status(core_obj, TCORE_CALL_STATUS_ACTIVE);
			if (!active) {
				dbg("Can't find active Call");
				return;
			}

			while (held) {
				co = (CallObject *) held->data;
				if (!co) {
					err("Can't get held Call object");
					return;
				}

				resp.id = tcore_call_object_get_id(co);

				// Send response to TAPI
				tcore_user_request_send_response(ur, TRESP_CALL_ACTIVE, sizeof(struct tresp_call_active), &resp);

				held = g_slist_next(held);
			}

			while (active) {
				co = (CallObject *) active->data;
				if (!co) {
					err("[ error ] can't get active call object");
					return;
				}

				resp.id = tcore_call_object_get_id(co);

				// Send response to TAPI
				tcore_user_request_send_response(ur, TRESP_CALL_HOLD, sizeof(struct tresp_call_hold), &resp);
				active = g_slist_next(active);
			}

			eflag = g_new0(gboolean, 1);
			*eflag = FALSE;

			dbg("calling _call_list_get");
			_call_list_get(core_obj, eflag);
		}
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void on_confirmation_set_sound_path(TcorePending *p, int data_len,
						const void *data,
						void *user_data)
{
	const TcoreATResponse *resp = data;
	struct tnoti_call_sound_path *snd_path = user_data;
	struct tresp_call_sound_set_path resp_set_sound_path;
	UserRequest *ur = tcore_pending_ref_user_request(p);
	TcorePlugin *plugin = tcore_pending_ref_plugin(p);
	CoreObject *co_call;

	if (ur == NULL) {
		err("User Request is NULL");
		g_free(user_data);
		return;
	}

	if (resp->success <= 0) {

		dbg("RESPONSE NOT OK");
		resp_set_sound_path.err = TRUE;

		goto out;
	}

	dbg("RESPONSE OK");
	resp_set_sound_path.err = FALSE;

	co_call = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);

	/* Notify control plugin about sound path */
	tcore_server_send_notification(tcore_plugin_ref_server(plugin),
					co_call, TNOTI_CALL_SOUND_PATH,
					sizeof(struct tnoti_call_sound_path),
					snd_path);

out:
	/* Answer TAPI request */
	tcore_user_request_send_response(ur, TRESP_CALL_SET_SOUND_PATH,
				sizeof(resp_set_sound_path),
				&resp_set_sound_path);

	g_free(user_data);
}

static void on_confirmation_call_set_source_sound_path(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	char *resp_str = NULL;
	struct tresp_call_sound_set_path resp;
	gboolean error;

	dbg("Entry");
	ur = tcore_pending_ref_user_request(p);

	// +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>]
	if (!response) {
		err("Input data is NULL");
		return;
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");

		line = (const char *) (((GSList *) response->lines)->data);
		tokens = tcore_at_tok_new(line);

		resp_str = g_slist_nth_data(tokens, 0);
		if (!g_slist_nth_data(tokens, 0)) {
			err("group_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		if (!g_slist_nth_data(tokens, 1)) {
			err(" function_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		resp_str = g_slist_nth_data(tokens, 2);

		if (resp_str) {
			error = atoi(resp_str);
			if (0 == error) {
				dbg("Response is Success");
				resp.err = FALSE;
			} else {
				resp.err = TRUE;
			}
		}
OUT:
		// Free tokens
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOT OK");

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			err("err cause not specified or string corrupted");
			resp.err = TRUE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));

			// TODO: CMEE error mapping is required.
			resp.err = TRUE;
		}

		// Free tokens
		tcore_at_tok_free(tokens);
	}

	if (ur) {
		if ( resp.err ) {  // Send only failed notification . success notification send when destination device is set.
			// Send notification to TAPI
			tcore_user_request_send_response(ur, TRESP_CALL_SET_SOUND_PATH, sizeof(struct tresp_call_sound_set_path), &resp);
			setsoundpath = TRUE;
		}
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void on_confirmation_call_set_destination_sound_path(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	char *resp_str = NULL;
	struct tresp_call_sound_set_path resp;
	const TcoreATResponse *response = data;
	gboolean error;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	// +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>]

	if (!response) {
		err("Input data is NULL");
		return;
	}

	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");

			line = (const char *) (((GSList *) response->lines)->data);
			tokens = tcore_at_tok_new(line);

			resp_str = g_slist_nth_data(tokens, 0);
			if (!g_slist_nth_data(tokens, 0)) {
				dbg("group_id is missing");
				resp.err = TRUE;
				goto OUT;
			}

			if (!g_slist_nth_data(tokens, 1)) {
				dbg("function_id is missing");
				resp.err = TRUE;
				goto OUT;
			}

			resp_str = g_slist_nth_data(tokens, 2);
			if (resp_str) {
				error = atoi(resp_str);
				if (0 == error) {
					dbg("Response is Success");
					resp.err = FALSE;
				} else {
					resp.err = TRUE;
				}
			}

OUT:
			// Free tokens
			tcore_at_tok_free(tokens);
		} else {
			dbg("RESPONSE NOT OK");

			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("err cause not specified or string corrupted");
				resp.err = TRUE;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));
				// TODO: CMEE error mapping is required.
				resp.err = TRUE;
			}

			// Free tokens
			tcore_at_tok_free(tokens);
		}

		if (setsoundpath == TRUE) {
			setsoundpath = FALSE;
		} else {
			// Send response to TAPI
			tcore_user_request_send_response(ur, TRESP_CALL_SET_SOUND_PATH, sizeof(struct tresp_call_sound_set_path), &resp);
		}
	} else {
		dbg("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void on_confirmation_call_set_source_sound_volume_level(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	const TcoreATResponse *response = data;
	char *resp_str = NULL;
	struct tresp_call_sound_set_volume_level resp;
	gboolean error;

	ur = tcore_pending_ref_user_request(p);
	dbg("Entry");
	// +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>]
	if (!response) {
		err("Input data is NULL");
		return;
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");

		line = (const char *) (((GSList *) response->lines)->data);
		tokens = tcore_at_tok_new(line);

		resp_str = g_slist_nth_data(tokens, 0);
		if (!g_slist_nth_data(tokens, 0)) {
			err("group_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		if (!g_slist_nth_data(tokens, 1)) {
			err("function_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		resp_str = g_slist_nth_data(tokens, 2);
		if (resp_str) {
			error = atoi(resp_str);

			if (0 == error) {
				dbg("Response is Success ");
				resp.err = FALSE;
			} else {
				resp.err = TRUE;
			}
		}

OUT:
		// Free tokens
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOT OK");

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			err("err cause not specified or string corrupted");
			resp.err = TRUE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));

			// TODO: CMEE error mapping is required.
			resp.err = TRUE;
		}

		// Free tokens
		tcore_at_tok_free(tokens);
	}

	if (ur) {
		if (resp.err && soundvolume == FALSE) {  // Send only failed notification . success notification send when destination device is set.
			// Send reposne to TAPI
			tcore_user_request_send_response(ur, TRESP_CALL_SET_SOUND_VOLUME_LEVEL, sizeof(struct tresp_call_sound_set_volume_level), &resp);
			soundvolume = TRUE;
		}
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}


static void on_confirmation_call_set_destination_sound_volume_level(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	char *resp_str = NULL;
	const TcoreATResponse *response = data;
	struct tresp_call_sound_set_volume_level resp;
	gboolean error;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);

	// +XDRV: <group_id>,<function_id>,<xdrv_result>[,<response_n>]
	if (!response) {
		err("Input data is NULL");
		return;
	}

	if (ur) {
		if (response->success > 0) {
			dbg("RESPONSE OK");
			line = (const char *) (((GSList *) response->lines)->data);
			tokens = tcore_at_tok_new(line);
			resp_str = g_slist_nth_data(tokens, 0);

			if (!g_slist_nth_data(tokens, 0)) {
				err("group_id is missing");
				resp.err = TRUE;
				goto OUT;
			}

			if (!g_slist_nth_data(tokens, 1)) {
				err("function_id is missing");
				resp.err = TRUE;
				goto OUT;
			}

			resp_str = g_slist_nth_data(tokens, 2);

			if (resp_str) {
				error = atoi(resp_str);

				if (0 == error) {
					dbg("Response is Success");
					resp.err = FALSE;
				} else {
					resp.err = TRUE;
				}
			}

OUT:
			// Free tokens
			tcore_at_tok_free(tokens);
		} else {
			dbg("RESPONSE NOT OK");

			line = (const char *) response->final_response;
			tokens = tcore_at_tok_new(line);

			if (g_slist_length(tokens) < 1) {
				err("err cause not specified or string corrupted");
				resp.err = TRUE;
			} else {
				error = atoi(g_slist_nth_data(tokens, 0));

				// TODO: CMEE error mapping is required.
				resp.err = TRUE;
			}

			tcore_at_tok_free(tokens);
		}

		if (soundvolume == TRUE) {
			soundvolume = FALSE;
		} else {
			// Send reposne to TAPI
			tcore_user_request_send_response(ur, TRESP_CALL_SET_SOUND_VOLUME_LEVEL, sizeof(struct tresp_call_sound_set_volume_level), &resp);
		}
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}


static void on_confirmation_call_mute(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	char *resp_str = NULL;
	struct tresp_call_mute resp;
	const TcoreATResponse *response = data;
	gboolean error;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);

	if (!response) {
		err("Input data is NULL");
		return;
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");

		line = (const char *) (((GSList *) response->lines)->data);
		tokens = tcore_at_tok_new(line);
		resp_str = g_slist_nth_data(tokens, 0);

		if (!g_slist_nth_data(tokens, 0)) {
			err("group_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		if (!g_slist_nth_data(tokens, 1)) {
			err(" function_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		resp_str = g_slist_nth_data(tokens, 2);

		if (resp_str) {
			error = atoi(resp_str);
			if (0 == error) {
				dbg("Response is Success");
				resp.err = FALSE;
			} else {
				resp.err = TRUE;
			}
		}
OUT:
		// Free tokens
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOT OK");

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			err("err cause not specified or string corrupted");
			resp.err = TRUE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));

			// TODO: CMEE error mapping is required.
			resp.err = TRUE;
		}

		// Free tokens
		tcore_at_tok_free(tokens);
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_CALL_MUTE, sizeof(struct tresp_call_mute), &resp);
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

static void on_confirmation_call_unmute(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *response = NULL;
	struct tresp_call_unmute resp;
	GSList *tokens = NULL;
	const char *line = NULL;
	UserRequest *ur = NULL;
	char *resp_str = NULL;
	gboolean error;

	dbg("Entry");

	response = (TcoreATResponse *) data;
	ur = tcore_pending_ref_user_request(p);

	if (!response) {
		err("Input data is NULL");
		return;
	}

	if (response->success > 0) {
		dbg("RESPONSE OK");

		line = (const char *) (((GSList *) response->lines)->data);
		tokens = tcore_at_tok_new(line);
		resp_str = g_slist_nth_data(tokens, 0);

		if (!g_slist_nth_data(tokens, 0)) {
			err("group_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		if (!g_slist_nth_data(tokens, 1)) {
			err(" function_id is missing");
			resp.err = TRUE;
			goto OUT;
		}

		resp_str = g_slist_nth_data(tokens, 2);

		if (resp_str) {
			error = atoi(resp_str);
			if (0 == error) {
				dbg("Response is Success");
				resp.err = FALSE;
			} else {
				resp.err = TRUE;
			}
		}
OUT:
		// Free tokens
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOT OK");

		line = (const char *) response->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			err("err cause not specified or string corrupted");
			resp.err = TRUE;
		} else {
			error = atoi(g_slist_nth_data(tokens, 0));

			// TODO: CMEE error mapping is required.
			resp.err = TRUE;
		}

		// Free tokens
		tcore_at_tok_free(tokens);
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_CALL_UNMUTE, sizeof(struct tresp_call_unmute), &resp);
	} else {
		err("User Request is NULL");
	}

	dbg("Exit");
	return;
}

// RESPONSE
static void on_response_call_list_get(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin *plugin = NULL;
	CoreObject *core_obj = NULL;
	CallObject *co = NULL;
	struct clcc_call_t *call_list = NULL;
	gboolean *event_flag = (gboolean *) user_data;
	const TcoreATResponse *response = data;
	GSList *resp_data = NULL;
	char *line = NULL;

	int cllc_info = 0, countCalls = 0, countValidCalls = 0;
	int error = 0;

	dbg("Entry");

	plugin = tcore_pending_ref_plugin(p);
	core_obj = tcore_pending_ref_core_object(p);

	if (response->success > 0) {
		dbg("RESPONCE OK");
		if (response->lines) {
			resp_data = (GSList *) response->lines;
			countCalls = g_slist_length(resp_data);
			dbg("Total records : %d", countCalls);
		}

		if (0 == countCalls) {
			err("Call count is zero");
			if (event_flag) {
				g_free(event_flag);
				event_flag = NULL;
			}
			return;
		}

		call_list = g_new0(struct clcc_call_t, countCalls);

		for (countValidCalls = 0; resp_data != NULL; resp_data = resp_data->next, countValidCalls++, cllc_info++) {
			line = (char *) (resp_data->data);

			error = _callFromCLCCLine(line, call_list + countValidCalls);
			if (0 != error) {
				continue;
			}

			co = tcore_call_object_find_by_id(core_obj, call_list[cllc_info].info.id);
			if (!co) {
				co = tcore_call_object_new(core_obj, call_list[cllc_info].info.id);
				if (!co) {
					err("error : tcore_call_object_new [ id : %d ]", call_list[cllc_info].info.id);
					continue;
				}
			}

			// Call set parameters
			tcore_call_object_set_type(co, call_type(call_list[cllc_info].info.type));
			tcore_call_object_set_direction(co, call_list[cllc_info].info.direction);
			tcore_call_object_set_multiparty_state(co, _call_is_in_mpty(call_list[cllc_info].info.mpty));
			tcore_call_object_set_cli_info(co, CALL_CLI_MODE_DEFAULT, call_list[cllc_info].number);
			tcore_call_object_set_active_line(co, 0);

			if (*event_flag) {
				dbg("Call status before calling _call_branch_by_status() : (%d)", call_list[cllc_info].info.status);
				_call_branch_by_status(plugin, co, call_list[cllc_info].info.status);
			} else {
				// Set Status
				tcore_call_object_set_status(co, call_list[cllc_info].info.status);

				dbg("Call id : (%d)", call_list[cllc_info].info.id);
				dbg("Call direction : (%d)", call_list[cllc_info].info.direction);
				dbg("Call type : (%d)", call_list[cllc_info].info.type);
				dbg("Call mpty : (%d)", call_list[cllc_info].info.mpty);
				dbg("Call number : (%s)", call_list[cllc_info].number);
				dbg("Call status : (%d)", call_list[cllc_info].info.status);
			}
		}

		// Free Call list
		g_free(call_list);
	}

	// Free User data
	if (event_flag) {
	g_free(event_flag);
		event_flag = NULL;
	}

	dbg("Exit");
	return;
}

static void _on_confirmation_call_end_cause(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin *plugin = NULL;
	CoreObject *core_obj = NULL;
	CallObject *co = (CallObject *) user_data;
	const TcoreATResponse *response = data;
	const char *line = NULL;
	struct tnoti_call_status_idle call_status;
	GSList *tokens = NULL;
	char *resp_str;
	int error;

	dbg("Entry");
	plugin = tcore_pending_ref_plugin(p);
	core_obj = tcore_pending_ref_core_object(p);

	if (response->success > 0) {
		dbg("RESPONSE OK");
		line = (const char *) (((GSList *) response->lines)->data);
		tokens = tcore_at_tok_new(line);
		resp_str = g_slist_nth_data(tokens, 0);
		if (!resp_str) {
			err("call end cause - report value missing");
		} else {
			resp_str = g_slist_nth_data(tokens, 1);
			if (!resp_str) {
				err("call end cause value missing");
			}
			error = atoi(resp_str);
			dbg("call end cause - %d", error);
			call_status.cause = _compare_call_end_cause(error);
			dbg("TAPI call end cause - %d", call_status.cause);
		}

		// Free tokens
		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOT OK");
		line = (char *) response->final_response;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			err("err cause not specified or string corrupted");
		} else {
			err(" err cause  value: %d", atoi(g_slist_nth_data(tokens, 0)));
		}
		call_status.cause = CC_CAUSE_NORMAL_CALL_CLEARING;
		// Free tokens
		tcore_at_tok_free(tokens);
	}

	call_status.type = tcore_call_object_get_type(co);
	dbg("data.type : [%d]", call_status.type);

	call_status.id = tcore_call_object_get_id(co);
	dbg("data.id : [%d]", call_status.id);

	// Set Status
	tcore_call_object_set_status(co, TCORE_CALL_STATUS_IDLE);

	// Send Notification to TAPI
	tcore_server_send_notification(tcore_plugin_ref_server(plugin),
								   core_obj,
								   TNOTI_CALL_STATUS_IDLE,
								   sizeof(struct tnoti_call_status_idle),
								   (void *) &call_status);

	// Free Call object
	tcore_call_object_free(core_obj, co);
}

static int _callFromCLCCLine(char *line, struct clcc_call_t *p_call)
{
	// +CLCC: 1,0,2,0,0,"18005551212",145
	// [+CLCC: <id1>, <dir>, <stat>, <mode>,<mpty>[,<number>,<type>[,<alpha>[,<priority>]]]
	int state;
	int mode;
	int isMT;
	char *num = NULL;
	unsigned int num_type;
	GSList *tokens = NULL;
	char *resp = NULL;

	dbg("Entry");

	tokens = tcore_at_tok_new(line);
	// parse <id>
	resp = g_slist_nth_data(tokens, 0);
	if (!resp) {
		err("InValid ID");
		goto ERROR;
	}
	p_call->info.id = atoi(resp);
	dbg("id : [%d]\n", p_call->info.id);

	// parse <dir>
	resp = g_slist_nth_data(tokens, 1);
	if (!resp) {
		err("InValid Dir");
		goto ERROR;
	}
	isMT = atoi(resp);
	if (0 == isMT) {
		p_call->info.direction = TCORE_CALL_DIRECTION_OUTGOING;
	} else {
		p_call->info.direction = TCORE_CALL_DIRECTION_INCOMING;
	}
	dbg("Direction : [ %d ]\n", p_call->info.direction);

	// parse <stat>
	resp = g_slist_nth_data(tokens, 2);
	if (!resp) {
		err("InValid Stat");
		goto ERROR;
	}
	state = atoi(resp);
	dbg("Call state : %d", state);
	switch (state) {
	case 0:     // active
		p_call->info.status = TCORE_CALL_STATUS_ACTIVE;
		break;

	case 1:
		p_call->info.status = TCORE_CALL_STATUS_HELD;
		break;

	case 2:
		p_call->info.status = TCORE_CALL_STATUS_DIALING;
		break;

	case 3:
		p_call->info.status = TCORE_CALL_STATUS_ALERT;
		break;

	case 4:
		p_call->info.status = TCORE_CALL_STATUS_INCOMING;
		break;

	case 5:
		p_call->info.status = TCORE_CALL_STATUS_WAITING;
		break;
	}
	dbg("Status : [%d]\n", p_call->info.status);

	// parse <mode>
	resp = g_slist_nth_data(tokens, 3);
	if (!resp) {
		err("InValid Mode");
		goto ERROR;
	}
	mode = atoi(resp);
	switch (mode) {
	case 0:
		p_call->info.type = TCORE_CALL_TYPE_VOICE;
		break;

	case 1:
		p_call->info.type = TCORE_CALL_TYPE_VIDEO;
		break;

	default:        // only Voice/VT call is supported in CS. treat other unknown calls as error
		dbg("invalid type : [%d]\n", mode);
		goto ERROR;
	}
	dbg("Call type : [%d]\n", p_call->info.type);

	// parse <mpty>
	resp = g_slist_nth_data(tokens, 4);
	if (!resp) {
		err("InValid Mpty");
		goto ERROR;
	}

	p_call->info.mpty = atoi(resp);
	dbg("Mpty : [ %d ]\n", p_call->info.mpty);

	// parse <num>
	resp = g_slist_nth_data(tokens, 5);
	dbg("Incoming number - %s and its len  - %d", resp, strlen(resp));

	// tolerate null here
	if (!resp) {
		err("Number is NULL");
		goto ERROR;
	}
	// Strike off double quotes
	num = util_removeQuotes(resp);
	dbg("num  after removing quotes - %s", num);

	p_call->info.num_len = strlen(resp);
	dbg("num_len : [0x%x]\n", p_call->info.num_len);

	// parse <num type>
	resp = g_slist_nth_data(tokens, 6);
	if (!resp) {
		dbg("InValid Num type");
		goto ERROR;
	}
	p_call->info.num_type = atoi(resp);
	dbg("BCD num type: [0x%x]\n", p_call->info.num_type);

	// check number is international or national.
	num_type = ((p_call->info.num_type) >> 4) & 0x07;
	dbg("called party's type of number : [0x%x]\n", num_type);

	if (num_type == 1 && num[0] != '+') {
		// international number
		p_call->number[0] = '+';
		memcpy(&(p_call->number[1]), num, strlen(num));
	} else {
		memcpy(&(p_call->number), num, strlen(num));
	}
	dbg("incoming number - %s", p_call->number);

	g_free(num);
	num = NULL;
	// Free tokens
	tcore_at_tok_free(tokens);

	dbg("Exit");
	return 0;

ERROR:
	err("Invalid CLCC line");

	g_free(num);

	// Free tokens
	tcore_at_tok_free(tokens);
	err("Exit");
	return -1;
}

// NOTIFICATION
static void on_notification_call_waiting(CoreObject *o, const void *data, void *user_data)
{
	GSList *tokens = NULL;
	const char *line = NULL;
	char *pId;
	int call_id;
	gboolean *eflag;
	GSList *pList = NULL;
	CallObject *co = NULL, *dupco = NULL;

	dbg("function entrance");
	// check call with waiting status already exist
	pList = tcore_call_object_find_by_status(o, TCORE_CALL_STATUS_WAITING);

	if (pList != NULL) {
		dbg("[error]Waiting call already exist. skip");
		return;
	}
	// check call with incoming status already exist
	pList = tcore_call_object_find_by_status(o, TCORE_CALL_STATUS_INCOMING);

	if (pList != NULL) {
		dbg("[error]incoming call already exist. skip");
		return;
	}
	line = (char *) data;
	tokens = tcore_at_tok_new(line);

	pId = g_slist_nth_data(tokens, 0);
	if (!pId) {
		dbg("[error]:Call id is missing from +XCALLSTAT indication");
		tcore_at_tok_free(tokens);
		return;
	}

	call_id = atoi(pId);
	dupco = tcore_call_object_find_by_id(o, call_id);
	if (dupco != NULL) {
		dbg("co with same id already exist. skip");
		tcore_at_tok_free(tokens);
		return;
	}
	co = tcore_call_object_new(o, call_id);
	if (!co) {
		dbg("[ error ] co is NULL");
		tcore_at_tok_free(tokens);
		return;
	}

	tcore_at_tok_free(tokens);

	eflag = g_new0(gboolean, 1);
	*eflag = TRUE;
	dbg("calling _call_list_get");
	_call_list_get(o, eflag);
}

static void on_notification_call_incoming(CoreObject *o, const void *data, void *user_data)
{
	GSList *tokens = NULL;
	const char *line = NULL;
	char *pId;
	int call_id;
	gboolean *eflag;
	GSList *pList = NULL;
	CallObject *co = NULL, *dupco = NULL;

	dbg("function entrance");
	// check call with incoming status already exist
	pList = tcore_call_object_find_by_status(o, TCORE_CALL_STATUS_INCOMING);

	if (pList != NULL) {
		dbg("incoming call already exist. skip");
		return;
	}

	line = (char *) data;
	tokens = tcore_at_tok_new(line);

	pId = g_slist_nth_data(tokens, 0);
	if (!pId) {
		dbg("Error:Call id is missing from %XCALLSTAT indication");
		tcore_at_tok_free(tokens);
		return;
	}

	call_id = atoi(pId);

	dupco = tcore_call_object_find_by_id(o, call_id);
	if (dupco != NULL) {
		dbg("co with same id already exist. skip");
		tcore_at_tok_free(tokens);
		return;
	}

	co = tcore_call_object_new(o, call_id);
	if (!co) {
		dbg("[ error ] co is NULL");
		tcore_at_tok_free(tokens);
		return;
	}

	dbg("freeing  at token");
	tcore_at_tok_free(tokens);

	eflag = g_new0(gboolean, 1);
	*eflag = TRUE;

	dbg("calling  _call_list_get");
	_call_list_get(o, eflag);
}

static void on_notification_call_status(CoreObject *o, const void *data, void *user_data)
{
	char *cmd = NULL;
	TcorePlugin *plugin = NULL;
	CallObject *co = NULL;
	int id = -1;
	int status = 0;
	int type = 0;
	char *stat = NULL;
	char *pCallId = NULL;
	GSList *tokens = NULL;
	gboolean *eflag = NULL;
	enum tcore_call_status co_status;

	dbg("function entrance");
	plugin = tcore_object_ref_plugin(o);
	cmd = (char *) data;
	tokens = tcore_at_tok_new(cmd);

	// parse <Call Id>
	pCallId = g_slist_nth_data(tokens, 0);
	if (!pCallId) {
		dbg("CallId is missing from %XCALLSTAT indication");
		tcore_at_tok_free(tokens);
		return;
	} else {
		id = atoi(pCallId);
		dbg("call id = %d", id);
		// parse <Stat>
		if ((stat = g_slist_nth_data(tokens, 1))) {
			status = atoi(stat);
		}
		dbg("call status = %d", status);
	}

	tcore_at_tok_free(tokens);
	co_status = _call_status(status);

	dbg("co_status = %d", co_status);
	switch (co_status) {
	case CALL_STATUS_ACTIVE:
	{
		dbg("call(%d) status : [ ACTIVE ]", id);
		co = tcore_call_object_find_by_id(o, id);
		if (!co) {
			dbg("co is NULL");
			return;
		}
		_call_status_active(plugin, co);
	}
	break;

	case CALL_STATUS_HELD:
		dbg("call(%d) status : [ held ]", id);
		break;

	case CALL_STATUS_DIALING:
	{
		dbg("call(%d) status : [ dialing ]", id);
		co = tcore_call_object_find_by_id(o, id);
		if (!co) {
			co = tcore_call_object_new(o, id);
			if (!co) {
				dbg("error : tcore_call_object_new [ id : %d ]", id);
				return;
			}
		}

		tcore_call_object_set_type(co, call_type(type));
		tcore_call_object_set_direction(co, TCORE_CALL_DIRECTION_OUTGOING);
		_call_status_dialing(plugin, co);
	}
	break;

	case CALL_STATUS_ALERT:
	{
		dbg("call(%d) status : [ alert ]", id);
		co = tcore_call_object_find_by_id(o, id);
		if (!co) {
			dbg("co is NULL");
			return;
		}
		// Store dialed number information into Call object.
		eflag = g_new0(gboolean, 1);
		*eflag = TRUE;
		dbg("calling _call_list_get");
		_call_list_get(o, eflag);
	}
	break;

	case CALL_STATUS_INCOMING:
	case CALL_STATUS_WAITING:
		dbg("call(%d) status : [ incoming ]", id);
		break;

	case CALL_STATUS_IDLE:
	{
		dbg("call(%d) status : [ release ]", id);

		co = tcore_call_object_find_by_id(o, id);
		if (!co) {
			dbg("co is NULL");
			return;
		}

		plugin = tcore_object_ref_plugin(o);
		if (!plugin) {
			dbg("plugin is NULL");
			return;
		}
		_call_status_idle(plugin, co);
	}
	break;

	default:
		dbg("invalid call status", id);
		break;
	}
}

static TReturn s_call_outgoing(CoreObject *o, UserRequest *ur)
{
	struct treq_call_dial *data = 0;
	char *cmd_str;
	const char *cclir, *num;
	enum tcore_call_cli_mode clir = CALL_CLI_MODE_DEFAULT;
	TcorePending *pending;
	TcoreATRequest *req;
	gboolean ret;

	dbg("Entry");

	data = (struct treq_call_dial *) tcore_user_request_ref_data(ur, 0);
	if (data->type == CALL_TYPE_VIDEO) {
		dbg("invalid call type");
		return TCORE_RETURN_FAILURE;
	}

	clir = _get_clir_status(data->number);

	if (clir == TCORE_CALL_CLI_MODE_DEFAULT) {
		TcorePlugin *plugin = tcore_object_ref_plugin(o);
		Server *server = tcore_plugin_ref_server(plugin);
		Storage *strg;

		dbg("Reading VCONF key");

		strg = tcore_server_find_storage(server, "vconf");
		clir = tcore_storage_get_int(strg,
				STORAGE_KEY_CISSAPPL_SHOW_MY_NUMBER_INT);

		num = data->number;
	} else
		/* Need to remove CLIR code from dialing number */
		num = data->number + 4;

	/* Compose ATD Cmd string */
	switch (clir) {
	case TCORE_CALL_CLI_MODE_PRESENT:
		dbg("CALL_CLI_MODE_PRESENT");
		cclir = "i";
		break;

	case TCORE_CALL_CLI_MODE_RESTRICT:
		dbg("CALL_CLI_MODE_RESTRICT");
		cclir = "I";
		break;

	case TCORE_CALL_CLI_MODE_DEFAULT:
	default:
		cclir = "";
		dbg("CALL_CLI_MODE_DEFAULT");
		break;
	}

	dbg("data->number = %s", data->number);

	cmd_str = g_strdup_printf("ATD%s%s;", num, cclir);

	dbg("request command : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	ret = _call_request_message(pending, o, ur, on_confirmation_call_outgoing, NULL);

	g_free(cmd_str);

	if (ret == FALSE) {
		dbg("AT request(%s) sent failed", req->cmd);
		return TCORE_RETURN_FAILURE;
	}

	dbg("AT request(%s) sent success", req->cmd);

	dbg("Exit");

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_answer(CoreObject *o, UserRequest *ur)
{
	char *cmd_str = NULL;
	CallObject *co = NULL;
	struct treq_call_answer *data = 0;
	TcorePending *pending = NULL;
	TcoreATRequest *req;
	gboolean ret = FALSE;

	dbg("function entrance");

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	data = (struct treq_call_answer *) tcore_user_request_ref_data(ur, 0);
	co = tcore_call_object_find_by_id(o, data->id);
	if (data->type == CALL_ANSWER_TYPE_ACCEPT) {
		dbg(" request type CALL_ANSWER_TYPE_ACCEPT");

		cmd_str = g_strdup_printf("%s", "ATA");
		pending = tcore_pending_new(o, 0);
		req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
		dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

		tcore_pending_set_request_data(pending, 0, req);
		ret = _call_request_message(pending, o, ur, on_confirmation_call_accept, co);
		g_free(cmd_str);

		if (!ret) {
			dbg("AT request(%s) sent failed", req->cmd);
			return TCORE_RETURN_FAILURE;
		}
	} else {
		switch (data->type) {
		case CALL_ANSWER_TYPE_REJECT:
		{
			dbg("call answer reject");
			tcore_call_control_answer_reject(o, ur, on_confirmation_call_reject, co);
		}
		break;

		case CALL_ANSWER_TYPE_REPLACE:
		{
			dbg("call answer replace");
			tcore_call_control_answer_replace(o, ur, on_confirmation_call_replace, co);
		}
		break;

		case CALL_ANSWER_TYPE_HOLD_ACCEPT:
		{
			dbg("call answer hold and accept");
			tcore_call_control_answer_hold_and_accept(o, ur, on_confirmation_call_hold_and_accept, co);
		}
		break;

		default:
			dbg("[ error ] wrong answer type [ %d ]", data->type);
			return TCORE_RETURN_FAILURE;
		}
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_release(CoreObject *o, UserRequest *ur)
{
	CallObject *co = NULL;
	struct treq_call_end *data = 0;
	UserRequest *ur_dup = NULL;
	char *chld0_cmd = NULL;
	char *chld1_cmd = NULL;
	TcorePending *pending = NULL, *pending1 = NULL;
	TcoreATRequest *req, *req1;
	gboolean ret = FALSE;

	dbg("function entrance");
	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	data = (struct treq_call_end *) tcore_user_request_ref_data(ur, 0);
	co = tcore_call_object_find_by_id(o, data->id);

	dbg("type of release call = %d", data->type);

	if (data->type == CALL_END_TYPE_ALL) {
		// releaseAll do not exist on legacy request. send CHLD=0, CHLD=1 in sequence
		chld0_cmd = g_strdup("AT+CHLD=0");
		chld1_cmd = g_strdup("AT+CHLD=1");

		pending = tcore_pending_new(o, 0);
		req = tcore_at_request_new(chld0_cmd, NULL, TCORE_AT_NO_RESULT);

		dbg("input command is %s", chld0_cmd);
		dbg("req-cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

		tcore_pending_set_request_data(pending, 0, req);
		ur_dup = tcore_user_request_new(NULL, NULL);
		ret = _call_request_message(pending, o, ur_dup, on_confirmation_call_endall, NULL);
		g_free(chld0_cmd);

		if (!ret) {
			dbg("AT request %s has failed ", req->cmd);
			if (ur_dup) {
				tcore_user_request_free(ur_dup);
				ur_dup = NULL;
			}
			g_free(chld1_cmd);
			return TCORE_RETURN_FAILURE;
		}

		pending1 = tcore_pending_new(o, 0);
		req1 = tcore_at_request_new(chld1_cmd, NULL, TCORE_AT_NO_RESULT);

		dbg("input command is %s", chld1_cmd);
		dbg("req-cmd : %s, prefix(if any) :%s, cmd_len : %d", req1->cmd, req1->prefix, strlen(req1->cmd));

		tcore_pending_set_request_data(pending1, 0, req1);
		ret = _call_request_message(pending1, o, ur, on_confirmation_call_release_all, co);
		g_free(chld1_cmd);

		if (!ret) {
			dbg("AT request %s has failed ", req->cmd);
			return TCORE_RETURN_FAILURE;
		}
	} else {
		switch (data->type) {
		case CALL_END_TYPE_DEFAULT:
		{
			int id = 0;
			id = tcore_call_object_get_id(co);

			dbg("call end call id [%d]", id);
			tcore_call_control_end_specific(o, ur, id, on_confirmation_call_release_specific, co);
		}
		break;

		case CALL_END_TYPE_ACTIVE_ALL:
		{
			dbg("call end all active");
			tcore_call_control_end_all_active(o, ur, on_confirmation_call_release_all_active, co);
		}
		break;

		case CALL_END_TYPE_HOLD_ALL:
		{
			dbg("call end all held");
			tcore_call_control_end_all_held(o, ur, on_confirmation_call_release_all_held, co);
		}
		break;

		default:
			dbg("[ error ] wrong end type [ %d ]", data->type);
			return TCORE_RETURN_FAILURE;
		}
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_hold(CoreObject *o, UserRequest *ur)
{
	struct treq_call_hold *hold = 0;
	CallObject *co = NULL;

	dbg("function entrance");

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	hold = (struct treq_call_hold *) tcore_user_request_ref_data(ur, 0);
	dbg("call id : [ %d ]", hold->id);

	co = tcore_call_object_find_by_id(o, hold->id);
	tcore_call_control_hold(o, ur, on_confirmation_call_hold, co);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_active(CoreObject *o, UserRequest *ur)
{
	struct treq_call_active *active = 0;
	CallObject *co = NULL;

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	active = (struct treq_call_active *) tcore_user_request_ref_data(ur, 0);
	dbg("call id : [ %d ]", active->id);

	co = tcore_call_object_find_by_id(o, active->id);
	tcore_call_control_active(o, ur, on_confirmation_call_active, co);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_swap(CoreObject *o, UserRequest *ur)
{
	struct treq_call_swap *swap = NULL;
	CallObject *co = NULL;

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	swap = (struct treq_call_swap *) tcore_user_request_ref_data(ur, 0);
	dbg("call id : [ %d ]", swap->id);

	co = tcore_call_object_find_by_id(o, swap->id);
	tcore_call_control_swap(o, ur, on_confirmation_call_swap, co);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_join(CoreObject *o, UserRequest *ur)
{
	struct treq_call_join *join = 0;
	CallObject *co = NULL;

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	join = (struct treq_call_join *) tcore_user_request_ref_data(ur, 0);
	dbg("call id : [ %d ]", join->id);

	co = tcore_call_object_find_by_id(o, join->id);
	tcore_call_control_join(o, ur, on_confirmation_call_join, co);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_split(CoreObject *o, UserRequest *ur)
{
	struct treq_call_split *split = 0;
	CallObject *co = NULL;

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	split = (struct treq_call_split *) tcore_user_request_ref_data(ur, 0);
	co = tcore_call_object_find_by_id(o, split->id);
	dbg("call id : [ %d ]", split->id);

	tcore_call_control_split(o, ur, split->id, on_confirmation_call_split, co);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_deflect(CoreObject *o, UserRequest *ur)
{
	struct treq_call_deflect *deflect = 0;
	CallObject *co = NULL;

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	deflect = (struct treq_call_deflect *) tcore_user_request_ref_data(ur, 0);
	co = tcore_call_object_find_by_number(o, deflect->number);
	dbg("deflect number: [ %s ]", deflect->number);

	tcore_call_control_deflect(o, ur, deflect->number, on_confirmation_call_deflect, co);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_transfer(CoreObject *o, UserRequest *ur)
{
	struct treq_call_transfer *transfer = 0;
	CallObject *co = NULL;

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	transfer = (struct treq_call_transfer *) tcore_user_request_ref_data(ur, 0);
	dbg("call id : [ %d ]", transfer->id);

	co = tcore_call_object_find_by_id(o, transfer->id);
	tcore_call_control_transfer(o, ur, on_confirmation_call_transfer, co);

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_send_dtmf(CoreObject *o, UserRequest *ur)
{
	char *cmd_str = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req;
	UserRequest *dup;
	gboolean ret = FALSE;
	struct treq_call_dtmf *dtmf = 0;
	char *dtmfstr = NULL, *tmp_dtmf = NULL;
	unsigned int dtmf_count;

	dbg("Function enter");

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dup = tcore_user_request_new(NULL, NULL);
	(void) _set_dtmf_tone_duration(o, dup);

	dtmf = (struct treq_call_dtmf *) tcore_user_request_ref_data(ur, 0);
	dtmfstr = g_malloc0((MAX_CALL_DTMF_DIGITS_LEN * 2) + 1);    // DTMF digits + comma for each dtmf digit.

	if (dtmfstr == NULL) {
		dbg("Memory allocation failed");
		return TCORE_RETURN_FAILURE;
	}

	tmp_dtmf = dtmfstr;

	for (dtmf_count = 0; dtmf_count < strlen(dtmf->digits); dtmf_count++) {
		*tmp_dtmf = dtmf->digits[dtmf_count];
		tmp_dtmf++;

		*tmp_dtmf = COMMA;
		tmp_dtmf++;
	}

	// last digit is having COMMA , overwrite it with '\0' .
	*(--tmp_dtmf) = '\0';
	dbg("Input DTMF string(%s)", dtmfstr);

	// AT+VTS = <d1>,<d2>,<d3>,<d4>,<d5>,<d6>, ..... <d32>
	cmd_str = g_strdup_printf("AT+VTS=%s", dtmfstr);
	dbg("request command : %s", cmd_str);

	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	ret = _call_request_message(pending, o, ur, on_confirmation_call_dtmf, NULL);
	g_free(dtmfstr);
	g_free(cmd_str);

	if (!ret) {
		dbg("AT request sent failed");
		return TCORE_RETURN_FAILURE;
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_set_sound_path(CoreObject *o, UserRequest *ur)
{
	UserRequest *ur_dup = NULL;
	TcorePending *pending = NULL, *pending1 = NULL;
	TcoreATRequest *req, *req1;
	char *cmd_str = NULL, *cmd_str1 = NULL;
	int device_type = -1;
	struct treq_call_sound_set_path *sound_path = 0;
	gboolean ret = FALSE;
	TcorePlugin *plugin = tcore_object_ref_plugin(o);
	const char *cp_name = tcore_server_get_cp_name_by_plugin(plugin);

	dbg("function entrance");

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	sound_path = (struct treq_call_sound_set_path *) tcore_user_request_ref_data(ur, 0);
	if (sound_path == NULL) {
		dbg("invaling user request");
		return TCORE_RETURN_FAILURE;
	}
	dbg("audio device type - 0x%x", sound_path->path);
	switch (sound_path->path) {
	case CALL_SOUND_PATH_HANDSET:
		device_type = 1;
		break;

	case CALL_SOUND_PATH_HEADSET:
		device_type = 2;
		break;

	case CALL_SOUND_PATH_HEADSET_3_5PI:
		device_type = 3;
		break;

	case CALL_SOUND_PATH_SPEAKER:
		device_type = 4;
		break;

	case CALL_SOUND_PATH_HANDFREE:
		device_type = 5;
		break;

	case CALL_SOUND_PATH_HEADSET_HAC:
		device_type = 6;
		break;

	case CALL_SOUND_PATH_BLUETOOTH:
	case CALL_SOUND_PATH_STEREO_BLUETOOTH:
		device_type = 7;
		break;

	case CALL_SOUND_PATH_BT_NSEC_OFF:
	case CALL_SOUND_PATH_MIC1:
	case CALL_SOUND_PATH_MIC2:
	default:
		dbg("unsupported device type");
		return TCORE_RETURN_FAILURE;
	}

	if (g_str_has_prefix(cp_name, "mfld_blackbay") == TRUE) {
		struct tnoti_call_sound_path *tnoti_snd_path;

		tnoti_snd_path = g_try_new0(struct tnoti_call_sound_path, 1);
		if (!tnoti_snd_path)
			return TCORE_RETURN_ENOMEM;

		tnoti_snd_path->path = sound_path->path;

		/* Configure modem I2S1 to 8khz, mono, PCM if routing to bluetooth */
		if (sound_path->path == CALL_SOUND_PATH_BLUETOOTH || sound_path->path == CALL_SOUND_PATH_STEREO_BLUETOOTH) {
			call_prepare_and_send_pending_request(o, "AT+XDRV=40,4,3,0,1,0,0,0,0,0,0,0,21", NULL, TCORE_AT_NO_RESULT, NULL);
			call_prepare_and_send_pending_request(o, "AT+XDRV=40,5,2,0,1,0,0,0,0,0,0,0,22", NULL, TCORE_AT_NO_RESULT, NULL);
		}
		else {
			call_prepare_and_send_pending_request(o, "AT+XDRV=40,4,3,0,1,0,8,0,1,0,2,0,21", NULL, TCORE_AT_NO_RESULT, NULL);
			call_prepare_and_send_pending_request(o, "AT+XDRV=40,5,2,0,1,0,8,0,1,0,2,0,22", NULL, TCORE_AT_NO_RESULT, NULL);
		}

		/* Configure modem I2S2 and do the modem routing */
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,4,4,0,0,0,8,0,1,0,2,0,21", NULL, TCORE_AT_NO_RESULT, NULL);
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,5,3,0,0,0,8,0,1,0,2,0,22", NULL, TCORE_AT_NO_RESULT, NULL);
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,6,0,4", NULL, TCORE_AT_NO_RESULT, NULL);
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,6,3,0", NULL, TCORE_AT_NO_RESULT, NULL);
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,6,4,2", NULL, TCORE_AT_NO_RESULT, NULL);
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,6,5,2", NULL, TCORE_AT_NO_RESULT, NULL);

		/* amc enable */
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,2,4", NULL, TCORE_AT_NO_RESULT, NULL); //AMC_I2S2_RX
		call_prepare_and_send_pending_request(o, "AT+XDRV=40,2,3", NULL, TCORE_AT_NO_RESULT, NULL); //AMC_I2S1_RX
		/* amc route: AMC_RADIO_RX => AMC_I2S1_TX */

		pending = tcore_pending_new(o, 0);
		req = tcore_at_request_new("AT+XDRV=40,6,0,2", "+XDRV", TCORE_AT_SINGLELINE);
		dbg("XDRV req-cmd for source type  : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));
		tcore_pending_set_request_data(pending, 0, req);
		ur_dup = tcore_user_request_ref(ur);
		ret = _call_request_message(pending, o, ur_dup, on_confirmation_set_sound_path, tnoti_snd_path);

	} else {

		cmd_str = g_strdup_printf("AT+XDRV=40,4,3,0,0,0,0,0,1,0,1,0,%d",device_type); // source type.
		pending = tcore_pending_new(o, 0);
		req = tcore_at_request_new(cmd_str, "+XDRV", TCORE_AT_SINGLELINE);
		dbg("XDRV req-cmd for source type  : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));
		tcore_pending_set_request_data(pending, 0, req);
		ur_dup = tcore_user_request_ref(ur);
		ret = _call_request_message(pending, o, ur_dup, on_confirmation_call_set_source_sound_path, NULL);
		g_free(cmd_str);

		if (!ret) {
			dbg("At request(%s) sent failed", req->cmd);
			return TCORE_RETURN_FAILURE;
		}

		cmd_str1 = g_strdup_printf("AT+XDRV=40,5,2,0,0,0,0,0,1,0,1,0,%d",device_type); // destination type
		pending1 = tcore_pending_new(o, 0);
		req1 = tcore_at_request_new(cmd_str1, "+XDRV", TCORE_AT_SINGLELINE);
		dbg("XDRV req-cmd for destination type : %s, prefix(if any) :%s, cmd_len : %d", req1->cmd, req1->prefix, strlen(req1->cmd));
		tcore_pending_set_request_data(pending1, 0, req1);
		ret = _call_request_message(pending1, o, ur, on_confirmation_call_set_destination_sound_path, NULL);
		g_free(cmd_str1);

		if (!ret) {
			dbg("AT request %s has failed ", req1->cmd);
			return TCORE_RETURN_FAILURE;
		}
	}

	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_set_sound_volume_level(CoreObject *o, UserRequest *ur)
{
	UserRequest *src_ur = NULL;
	UserRequest *dest_ur = NULL;
	TcorePending *src_pending = NULL;
	TcorePending *dest_pending = NULL;
	TcoreATRequest *src_req = NULL;
	TcoreATRequest *dest_req = NULL;
	char *cmd_str = NULL, *volume_level = NULL;
	gboolean ret = FALSE;
	struct treq_call_sound_set_volume_level *data = NULL;

	dbg("Entry");

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	data = (struct treq_call_sound_set_volume_level *) tcore_user_request_ref_data(ur, 0);

	// Hard-coded values for MIC & Speakers
	// Source volume
	dbg("Set Source volume");

	cmd_str = g_strdup_printf("%s", "AT+XDRV=40,7,3,88");   // Source type
	dbg("Request command string: %s", cmd_str);

	// Create new Pending request
	src_pending = tcore_pending_new(o, 0);

	// Create new AT-Command request
	src_req = tcore_at_request_new(cmd_str, "+XDRV", TCORE_AT_SINGLELINE);
	dbg("Command: %s, prefix(if any): %s, Command length: %d", src_req->cmd, src_req->prefix, strlen(src_req->cmd));

	// Free Command string
	g_free(cmd_str);

	tcore_pending_set_request_data(src_pending, 0, src_req);
	src_ur = tcore_user_request_ref(ur);

	// Send request
	ret = _call_request_message(src_pending, o, src_ur, on_confirmation_call_set_source_sound_volume_level, NULL);
	if (!ret) {
		err("Failed to send AT-Command request");
		return TCORE_RETURN_FAILURE;
	}

	cmd_str = g_strdup_printf("%s", "AT+XDRV=40,7,0,88");   // Destination type
	dbg("Request command string: %s", cmd_str);

	// Create new Pending request
	src_pending = tcore_pending_new(o, 0);

	// Create new AT-Command request
	src_req = tcore_at_request_new(cmd_str, "+XDRV", TCORE_AT_SINGLELINE);
	dbg("Command: %s, prefix(if any): %s, Command length: %d", src_req->cmd, src_req->prefix, strlen(src_req->cmd));

	// Free Command string
	g_free(cmd_str);

	tcore_pending_set_request_data(src_pending, 0, src_req);

	src_ur = tcore_user_request_ref(ur);

	// Send request
	ret = _call_request_message(src_pending, o, src_ur, on_confirmation_call_set_source_sound_volume_level, NULL);
	if (!ret) {
		err("Failed to send AT-Command request");
		return TCORE_RETURN_FAILURE;
	}

	// Destination volume
	dbg("Set Source volume");

	cmd_str = g_strdup_printf("%s", "AT+XDRV=40,8,0,88");   // Source type
	dbg("Request command string: %s", cmd_str);

	// Create new Pending request
	dest_pending = tcore_pending_new(o, 0);

	// Create new AT-Command request
	dest_req = tcore_at_request_new(cmd_str, "+XDRV", TCORE_AT_SINGLELINE);
	dbg("Command: %s, prefix(if any): %s, Command length: %d", dest_req->cmd, dest_req->prefix, strlen(dest_req->cmd));

	// Free Command string
	g_free(cmd_str);

	tcore_pending_set_request_data(dest_pending, 0, dest_req);
	dest_ur = tcore_user_request_ref(ur);

	// Send request
	ret = _call_request_message(dest_pending, o, dest_ur, on_confirmation_call_set_source_sound_volume_level, NULL);
	if (!ret) {
		err("Failed to send AT-Command request");
		return TCORE_RETURN_FAILURE;
	}

	dbg("Input volume level - %d", data->volume);
	switch (data->volume) {
	case CALL_SOUND_MUTE:
		volume_level = "0";
		break;

	case CALL_SOUND_VOLUME_LEVEL_1:
		volume_level = "40";
		break;

	case CALL_SOUND_VOLUME_LEVEL_2:
		volume_level = "46";
		break;

	case CALL_SOUND_VOLUME_LEVEL_3:
		volume_level = "52";
		break;

	case CALL_SOUND_VOLUME_LEVEL_4:
		volume_level = "58";
		break;

	case CALL_SOUND_VOLUME_LEVEL_5:
		volume_level = "64";
		break;

	case CALL_SOUND_VOLUME_LEVEL_6:
		volume_level = "70";
		break;

	case CALL_SOUND_VOLUME_LEVEL_7:
		volume_level = "76";
		break;

	case CALL_SOUND_VOLUME_LEVEL_8:
		volume_level = "82";
		break;

	case CALL_SOUND_VOLUME_LEVEL_9:
	default:
		volume_level = "88";
		break;
	}
	cmd_str = g_strdup_printf("%s%s", "AT+XDRV=40,8,2,", volume_level);   // Destination type
	dbg("Request command string: %s", cmd_str);

	// Create new Pending request
	dest_pending = tcore_pending_new(o, 0);

	// Create new AT-Command request
	dest_req = tcore_at_request_new(cmd_str, "+XDRV", TCORE_AT_SINGLELINE);
	dbg("Command: %s, prefix(if any): %s, Command length: %d", dest_req->cmd, dest_req->prefix, strlen(dest_req->cmd));

	// Free Command string
	g_free(cmd_str);

	tcore_pending_set_request_data(dest_pending, 0, dest_req);

	// Send request
	ret = _call_request_message(dest_pending, o, ur, on_confirmation_call_set_destination_sound_volume_level, NULL);
	if (!ret) {
		err("Failed to send AT-Command request");
		return TCORE_RETURN_FAILURE;
	}

	return TCORE_RETURN_SUCCESS;
}


static TReturn s_call_get_sound_volume_level(CoreObject *o, UserRequest *ur)
{
	dbg("Entry");

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_mute(CoreObject *o, UserRequest *ur)
{
	char *cmd_str = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req = NULL;
	gboolean ret = FALSE;

	dbg("Entry");

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	cmd_str = g_strdup_printf("%s", "AT+XDRV=40,8,0,0,0");

	dbg("Request command string: %s", cmd_str);

	// Create new Pending request
	pending = tcore_pending_new(o, 0);

	// Create new AT-Command request
	req = tcore_at_request_new(cmd_str, "+XDRV", TCORE_AT_SINGLELINE);
	dbg("Command: %s, prefix(if any): %s, Command length: %d", req->cmd, req->prefix, strlen(req->cmd));

	// Free command string
	g_free(cmd_str);

	// Set request data (AT command) to Pending request
	tcore_pending_set_request_data(pending, 0, req);

	// Send request
	ret = _call_request_message(pending, o, ur, on_confirmation_call_mute, NULL);
	if (!ret) {
		err("Failed to send AT-Command request");
		return TCORE_RETURN_FAILURE;
	}

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_call_unmute(CoreObject *o, UserRequest *ur)
{
	char *cmd_str = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req = NULL;
	gboolean ret = FALSE;

	dbg("Entry");

	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	cmd_str = g_strdup_printf("%s", "AT+XDRV=40,8,0,0,88");
	dbg("Request command string: %s", cmd_str);

	// Create new Pending request
	pending = tcore_pending_new(o, 0);

	// Create new AT-Command request
	req = tcore_at_request_new(cmd_str, "+XDRV", TCORE_AT_SINGLELINE);
	dbg("Command: %s, prefix(if any): %s, Command length: %d", req->cmd, req->prefix, strlen(req->cmd));

	// Free command string
	g_free(cmd_str);

	// Set request data (AT command) to Pending request
	tcore_pending_set_request_data(pending, 0, req);

	// Send request
	ret = _call_request_message(pending, o, ur, on_confirmation_call_unmute, NULL);
	if (!ret) {
		err("Failed to send AT-Command request");
		return TCORE_RETURN_FAILURE;
	}

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}


static TReturn s_call_get_mute_status(CoreObject *o, UserRequest *ur)
{
	dbg("Entry");

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn _set_dtmf_tone_duration(CoreObject *o, UserRequest *ur)
{
	char *cmd_str = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req = NULL;
	gboolean ret = FALSE;

	dbg("Entry");

	cmd_str = g_strdup_printf("%s", "AT+VTD=3"); // ~300 mili secs. +VTD= n, where  n = (0 - 255) * 1/10 secs.
	dbg("Request command string: %s", cmd_str);

	// Create new Pending request
	pending = tcore_pending_new(o, 0);

	// Create new AT-Command request
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("Command: %s, prefix(if any): %s, Command length: %d", req->cmd, req->prefix, strlen(req->cmd));

	// Free command string */
	g_free(cmd_str);

	// Set request data (AT command) to Pending request
	tcore_pending_set_request_data(pending, 0, req);

	// Send request
	ret = _call_request_message(pending, o, ur, _on_confirmation_dtmf_tone_duration, NULL);
	if (!ret) {
		err("Failed to send AT-Command request");
		if (ur) {
			tcore_user_request_free(ur);
			ur = NULL;
		}
		return TCORE_RETURN_FAILURE;
	}

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

// Call Operations
static struct tcore_call_operations call_ops = {
	.dial = s_call_outgoing,
	.answer = s_call_answer,
	.end = s_call_release,
	.hold = s_call_hold,
	.active = s_call_active,
	.swap = s_call_swap,
	.join = s_call_join,
	.split = s_call_split,
	.deflect = s_call_deflect,
	.transfer = s_call_transfer,
	.send_dtmf = s_call_send_dtmf,
	.set_sound_path = s_call_set_sound_path,
	.set_sound_volume_level = s_call_set_sound_volume_level,
	.get_sound_volume_level = s_call_get_sound_volume_level,
	.mute = s_call_mute,
	.unmute = s_call_unmute,
	.get_mute_status = s_call_get_mute_status,
	.set_sound_recording = NULL,
	.set_sound_equalization = NULL,
	.set_sound_noise_reduction = NULL,
};

gboolean s_call_init(TcorePlugin *cp, CoreObject *co_call)
{
	dbg("Entry");

	tcore_call_override_ops(co_call, &call_ops, NULL);

	/* Add Callbacks */
	tcore_object_override_callback(co_call, "+XCALLSTAT", on_notification_call_info, NULL);
	tcore_object_override_callback(co_call, "+CLIP", on_notification_call_clip_info, NULL);

	dbg("Exit");

	return TRUE;
}

void s_call_exit(TcorePlugin *cp, CoreObject *co_call)
{
	dbg("Exit");
}
