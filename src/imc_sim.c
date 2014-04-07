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

#include <co_sim.h>
#include <co_sms.h>

#include "imc_sim.h"
#include "imc_common.h"

#define ENABLE_FLAG 1
#define DISABLE_FLAG 2

#define IMC_SIM_ACCESS_READ_BINARY		176
#define IMC_SIM_ACCESS_READ_RECORD		178
#define IMC_SIM_ACCESS_GET_RESPONSE		192
#define IMC_SIM_ACCESS_UPDATE_BINARY		214
#define IMC_SIM_ACCESS_UPDATE_RECORD		220

#define IMC_SIM_READ_FILE(co, cb, cb_data, fileId, ret) \
{ \
	ImcSimMetaInfo file_meta = {0, }; \
	ImcRespCbData *resp_cb_data = NULL; \
	\
	file_meta.file_id = fileId; \
	file_meta.file_result = TEL_SIM_RESULT_FAILURE; \
	\
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, &file_meta, sizeof(ImcSimMetaInfo)); \
	\
	ret =  __imc_sim_get_response(co, resp_cb_data); \
	dbg("Request reading '%s' - [%s]", #fileId, (ret == TEL_RETURN_SUCCESS ? "SUCCESS" : "FAILURE")); \
}

typedef enum {
	IMC_SIM_FILE_TYPE_DEDICATED = 0x00,	/**< Dedicated */
	IMC_SIM_FILE_TYPE_TRANSPARENT = 0x01,	/**< Transparent -binary type*/
	IMC_SIM_FILE_TYPE_LINEAR_FIXED = 0x02,	/**< Linear fixed - record type*/
	IMC_SIM_FILE_TYPE_CYCLIC = 0x04,	/**< Cyclic - record type*/
	IMC_SIM_FILE_TYPE_INVALID_TYPE = 0xFF	/**< Invalid type */
} ImcSimFileType;

typedef enum {
	IMC_SIM_CURR_SEC_OP_PIN1_VERIFY,
	IMC_SIM_CURR_SEC_OP_PIN2_VERIFY,
	IMC_SIM_CURR_SEC_OP_PUK1_VERIFY,
	IMC_SIM_CURR_SEC_OP_PUK2_VERIFY,
	IMC_SIM_CURR_SEC_OP_SIM_VERIFY,
	IMC_SIM_CURR_SEC_OP_ADM_VERIFY,
	IMC_SIM_CURR_SEC_OP_PIN1_CHANGE,
	IMC_SIM_CURR_SEC_OP_PIN2_CHANGE,
	IMC_SIM_CURR_SEC_OP_PIN1_ENABLE,
	IMC_SIM_CURR_SEC_OP_PIN1_DISABLE,
	IMC_SIM_CURR_SEC_OP_PIN2_ENABLE,
	IMC_SIM_CURR_SEC_OP_PIN2_DISABLE, // 10
	IMC_SIM_CURR_SEC_OP_SIM_ENABLE,
	IMC_SIM_CURR_SEC_OP_SIM_DISABLE,
	IMC_SIM_CURR_SEC_OP_NET_ENABLE,
	IMC_SIM_CURR_SEC_OP_NET_DISABLE,
	IMC_SIM_CURR_SEC_OP_NS_ENABLE,
	IMC_SIM_CURR_SEC_OP_NS_DISABLE,
	IMC_SIM_CURR_SEC_OP_SP_ENABLE,
	IMC_SIM_CURR_SEC_OP_SP_DISABLE,
	IMC_SIM_CURR_SEC_OP_CP_ENABLE,
	IMC_SIM_CURR_SEC_OP_CP_DISABLE, // 20
	IMC_SIM_CURR_SEC_OP_FDN_ENABLE,
	IMC_SIM_CURR_SEC_OP_FDN_DISABLE,
	IMC_SIM_CURR_SEC_OP_PIN1_STATUS,
	IMC_SIM_CURR_SEC_OP_PIN2_STATUS,
	IMC_SIM_CURR_SEC_OP_FDN_STATUS,
	IMC_SIM_CURR_SEC_OP_NET_STATUS,
	IMC_SIM_CURR_SEC_OP_NS_STATUS,
	IMC_SIM_CURR_SEC_OP_SP_STATUS,
	IMC_SIM_CURR_SEC_OP_CP_STATUS,
	IMC_SIM_CURR_SEC_OP_SIM_STATUS,
	IMC_SIM_CURR_SEC_OP_SIM_UNKNOWN = 0xff
} ImcSimCurrSecOp;

typedef struct {
	guint smsp_count;					/**< SMSP record count */
	guint smsp_rec_len;					/**< SMSP record length */
} ImcSimPrivateInfo;

typedef struct {
	gboolean b_valid;					/**< Valid or not */
	guint rec_length;					/**< Length of one record in file */
	guint rec_count;					/**< Number of records in file */
	guint data_size;					/**< File size */
	guint current_index;					/**< Current index to read */
	ImcSimFileType file_type;				/**< File type and structure */
	ImcSimCurrSecOp sec_op;					/**< Current index to read */
	TelSimMailboxList mbi_list;				/**< Mailbox List */
	TelSimMailBoxNumber mb_list[TEL_SIM_MSP_CNT_MAX*5];	/**< Mailbox number */
	TelSimFileId file_id;					/**< Current file id */
	TelSimResult file_result;				/**< File access result */
	TelSimFileResult files;					/**< File read data */
	TcoreCommand req_command;				/**< Request command Id */
	TelSimImsiInfo imsi;					/**< Stored locally as of now,
								          Need to store in secure storage*/
} ImcSimMetaInfo;

/* Utility Function Declaration */
static TelSimResult __imc_sim_decode_status_word(unsigned short status_word1, unsigned short status_word2);
static void __imc_sim_update_sim_status(CoreObject *co, TelSimCardStatus sim_status);
static void __imc_sim_notify_sms_state(CoreObject *co, gboolean sms_ready);
static TelReturn __imc_sim_start_to_cache(CoreObject *co);
static gboolean __imc_sim_get_sim_type(CoreObject *co, TcoreObjectResponseCallback cb, void *cb_data);
static void __imc_sim_next_from_read_binary(CoreObject *co, ImcRespCbData *resp_cb_data, TelSimResult sim_result, gboolean decode_ret);
static void __imc_sim_next_from_get_response(CoreObject *co, ImcRespCbData *resp_cb_data, TelSimResult sim_result);
static TelReturn __imc_sim_update_file(CoreObject *co, ImcRespCbData *resp_cb_data, int cmd, TelSimFileId ef,
						int p1, int p2, int p3, char *encoded_data);
static void __imc_sim_read_record(CoreObject *co, ImcRespCbData *resp_cb_data);
static void __imc_sim_read_binary(CoreObject *co, ImcRespCbData *resp_cb_data);
static TelReturn __imc_sim_get_response (CoreObject *co, ImcRespCbData *resp_cb_data);
static TelReturn __imc_sim_get_retry_count(CoreObject *co, ImcRespCbData *resp_cb_data);
static TelSimLockType __imc_sim_lock_type(int lock_type);
static char *__imc_sim_get_fac_from_lock_type(TelSimLockType lock_type, ImcSimCurrSecOp *sec_op, int flag);
static int __imc_sim_get_lock_type(ImcSimCurrSecOp sec_op);

/* Internal Response Functions*/
static void __on_response_imc_sim_get_sim_type_internal(CoreObject *co, gint result, const void *response, void *user_data);
static void __on_response_imc_sim_get_sim_type(TcorePending *p, guint data_len, const void *data, void *user_data);
static void __on_response_imc_sim_read_data(TcorePending *p, guint data_len, const void *data, void *user_data);
static void __on_response_imc_sim_get_response(TcorePending *p, guint data_len, const void *data, void *user_data);
static void __on_response_imc_sim_get_retry_count(TcorePending *p, guint data_len, const void *data, void *user_data);
static void __on_response_imc_sim_update_file(TcorePending *p, guint data_len, const void *data, void *user_data);

/* GET SMSP info for SMS module */
gboolean imc_sim_get_smsp_info(TcorePlugin *plugin, int *rec_count, int *rec_len)
{
	CoreObject *co = NULL;
	ImcSimPrivateInfo *priv_info = NULL;

	dbg("Entry");

	co = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);
	priv_info = tcore_sim_ref_userdata(co);
	if(!priv_info)
		return FALSE;

	*rec_count = priv_info->smsp_count;
	*rec_len = priv_info->smsp_rec_len;

	dbg("smsp_count:[%d], smsp_rec_len:[%d]", priv_info->smsp_count, priv_info->smsp_rec_len);
	return TRUE;
}

static void __imc_sim_set_identity(CoreObject *co, TelSimImsiInfo *imsi)
{
	gchar new_imsi[15 + 1] = {0, };
	gchar *old_imsi;

	memcpy(&new_imsi, imsi->mcc, strlen(imsi->mcc));
	memcpy(&new_imsi[strlen(imsi->mcc)], imsi->mnc, strlen(imsi->mnc));
	memcpy(&new_imsi[strlen(imsi->mcc) + strlen(imsi->mnc)], imsi->msin, strlen(imsi->msin));

	/* TODO: This is temporary code, we should use secure storage instead of vconf */
	old_imsi = vconf_get_str("db/telephony/imsi");
	if (old_imsi) {
		if (g_strcmp0(old_imsi, new_imsi) != 0) {
			dbg("New SIM");
			vconf_set_str("db/telephony/imsi", new_imsi);
			tcore_sim_set_identification(co, TRUE);
		} else {
			dbg("Same SIM");
			tcore_sim_set_identification(co, FALSE);
		}
	} else {
		dbg("Old IMSI value is NULL, set IMSI");
		vconf_set_str("db/telephony/imsi", new_imsi);
		tcore_sim_set_identification(co, TRUE);
	}
}

/* Utility Functions */
static TelSimResult __imc_sim_decode_status_word(unsigned short status_word1, unsigned short status_word2)
{
	TelSimResult rst = TEL_SIM_RESULT_FAILURE;

	if (status_word1 == 0x93 && status_word2 == 0x00) {
		/*Failed SIM request command*/
		dbg("error - SIM application toolkit busy [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x00) {
		/*Failed SIM request command*/
		dbg("error - No EF Selected [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x02) {
		/*Failed SIM request command*/
		dbg("error - Out of Range - Invalid address or record number[%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x04) {
		/*Failed SIM request command*/
		dbg("error - File ID not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x08) {
		/*Failed SIM request command*/
		dbg("error - File is inconsistent with command - Modem not support or USE IPC [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x02) {
		/*Failed SIM request command*/
		dbg("error - CHV not initialized [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x04) {
		/*Failed SIM request command*/
		dbg("error - Access condition not fullfilled [%x][%x]", status_word1, status_word2);
		dbg("error -Unsuccessful CHV verification - at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Unsuccessful Unblock CHV - at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Authentication failure [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x08) {
		/*Failed SIM request command*/
		dbg("error - Contradiction with CHV status [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x10) {
		/*Failed SIM request command*/
		dbg("error - Contradiction with invalidation status [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x40) {
		/*Failed SIM request command*/
		dbg("error -Unsuccessful CHV verification - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Unsuccessful Unblock CHV - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - CHV blocked [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x67 && status_word2 == 0x00) {
		dbg("error -Incorrect Parameter 3 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6B && status_word2 == 0x00) {
		dbg("error -Incorrect Parameter 1 or 2 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6D && status_word2 == 0x00) {
		dbg("error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6E && status_word2 == 0x00) {
		dbg("error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x69 && status_word2 == 0x82) {
		dbg("error -Access denied [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x87) {
		dbg("error -Incorrect parameters [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x82) {
		dbg("error -File Not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x83) {
		dbg("error -Record Not found [%x][%x]", status_word1, status_word2);
	} else {
		rst = TEL_SIM_RESULT_CARD_ERROR;
		dbg("error -Unknown state [%x][%x]", status_word1, status_word2);
	}
	return rst;
}

static void __imc_sim_update_sim_status(CoreObject *co, TelSimCardStatus sim_status)
{
	TelSimCardStatus curr_sim_status;

	/*
	 * Send SIM Init status, if not sent already
	 */
	(void)tcore_sim_get_status(co, &curr_sim_status);
	if (sim_status != curr_sim_status) {
		TelSimCardStatusInfo sim_status_noti = {0, };

		dbg("Change in SIM State - Old State: [0x%02x] --> New State: [0x%02x]",
				curr_sim_status, sim_status);

		/* Update SIM Status */
		tcore_sim_set_status(co, sim_status);
		sim_status_noti.status = sim_status;
		tcore_sim_get_identification(co, &sim_status_noti.change_status);

		/* Send notification: SIM Status */
		tcore_object_send_notification(co,
			TCORE_NOTIFICATION_SIM_STATUS,
			sizeof(sim_status_noti), &sim_status_noti);
	}
}

static void __imc_sim_notify_sms_state(CoreObject *co,
						gboolean sms_ready)
{
	TcorePlugin *plugin;
	CoreObject *co_sms;
	gboolean sms_status = FALSE;

	dbg("Entry");

	plugin = tcore_object_ref_plugin(co);
	co_sms = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SMS);
	tcore_check_return_assert(co_sms != NULL);

	(void)tcore_sms_get_ready_status(co_sms, &sms_status);
	if (sms_status == sms_ready) {
		dbg("No change in SMS Status: [%s]",
			(sms_status ? "INITIALIZED" : "UNINITIALIZED"));
	} else {
		TelSimCardStatus sim_status;

		/* Update SMS State */
		tcore_sms_set_ready_status(co_sms, sms_ready);

		dbg("SMS Status - Changed [%s] --> [%s]",
			(sms_status ? "INITIALIZED" : "UNINITIALIZED"),
			(sms_ready ? "INITIALIZED" : "UNINITIALIZED"));

		/*
		 * Send SMS device ready notification, if SIM is initialiazed.
		 */
		(void)tcore_sim_get_status(co, &sim_status);
		if (sim_status == TEL_SIM_STATUS_SIM_INIT_COMPLETED) {
			/* Send notification: SMS Device ready */
			tcore_object_send_notification(co_sms,
				TCORE_NOTIFICATION_SMS_DEVICE_READY,
				sizeof(sms_ready), &sms_ready);
		}
	}
}

TelReturn __imc_sim_start_to_cache(CoreObject *co)
{
	TelReturn ret;
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_IMSI, ret);
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_CPHS_CPHS_INFO, ret);
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_ICCID, ret);
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_SPN, ret);
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_SST, ret);
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_ECC, ret);
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_MSISDN, ret);
	IMC_SIM_READ_FILE(co, NULL, NULL, TEL_SIM_EF_SMSP, ret);

	return ret;
}

static void __on_response_imc_sim_get_sim_type_internal(CoreObject *co,
	gint result, const void *response, void *user_data)
{
	dbg("SIM Response - SIM Type (internal): [+XUICC]");

	if (result == TEL_SIM_RESULT_SUCCESS) {
		TelSimCardType *sim_type = (TelSimCardType *)response;
		dbg("SIM Type: [%d]", *sim_type);

		/* Update SIM type */
		tcore_sim_set_type(co, *sim_type);
		if (*sim_type != TEL_SIM_CARD_TYPE_UNKNOWN) {
			TelReturn ret;

			/* Start Caching SIM files */
			ret = __imc_sim_start_to_cache(co);

			/* Send SIM Type notification */
			tcore_object_send_notification(co,
				TCORE_NOTIFICATION_SIM_TYPE,
				sizeof(TelSimCardType), sim_type);
		}
	}
}

static void __on_response_imc_sim_get_sim_type(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSimCardType sim_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	TelSimResult result = TEL_SIM_RESULT_FAILURE;

	dbg("SIM Response - SIM Type: [+XUICC]");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		if (at_resp->lines) {
			const gchar *line;
			GSList *tokens;

			line = (const gchar *)at_resp->lines->data;

			/*
			 * Tokenize
			 *
			 *	+XUICC: <state>
			 */
			tokens = tcore_at_tok_new(line);

			/* <state> */
			if (g_slist_length(tokens) == 1) {
				guint state = atoi(g_slist_nth_data(tokens, 0));

				if (state == 0)	/* 0 - 2G SIM */
					sim_type = TEL_SIM_CARD_TYPE_GSM;
				else if (state == 1)	/* 1 - 3G SIM */
					sim_type = TEL_SIM_CARD_TYPE_USIM;

				result = TEL_SIM_RESULT_SUCCESS;
			}
			else {
				err("Invalid message");
			}

			tcore_at_tok_free(tokens);
		}
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &sim_type, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

/*
 * Operation - get_sim_type
 *
 * Request -
 * AT-Command: AT+XUICC?
 *
 * Response - sim_type (TelSimCardType)
 * Success: (Single line) -
 *	+ XUICC: <state>
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
gboolean __imc_sim_get_sim_type(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XUICC?", "+XUICC:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		__on_response_imc_sim_get_sim_type, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SIM Type");

	return ret;
}

static void __imc_sim_process_sim_status(CoreObject *co, guint sim_state)
{
	TelSimCardStatus sim_card_status;

	switch (sim_state) {
	case 0:
		sim_card_status = TEL_SIM_STATUS_CARD_NOT_PRESENT;
		dbg("NO SIM");
	break;

	case 1:
		sim_card_status = TEL_SIM_STATUS_SIM_PIN_REQUIRED;
		dbg("PIN REQUIRED");
	break;

	case 2:
		sim_card_status = TEL_SIM_STATUS_SIM_INITIALIZING;
		dbg("PIN DISABLED AT BOOT UP");
	break;

	case 3:
		sim_card_status = TEL_SIM_STATUS_SIM_INITIALIZING;
		dbg("PIN VERIFIED");
	break;

	case 4:
		sim_card_status = TEL_SIM_STATUS_SIM_PUK_REQUIRED;
		dbg("PUK REQUIRED");
	break;

	case 5:
		sim_card_status = TEL_SIM_STATUS_SIM_PUK_REQUIRED;
		dbg("CARD PERMANENTLY BLOCKED");
	break;

	case 6:
		sim_card_status = TEL_SIM_STATUS_CARD_ERROR;
		dbg("SIM CARD ERROR");
	break;

	case 7:
		sim_card_status = TEL_SIM_STATUS_SIM_INIT_COMPLETED;
		dbg("SIM INIT COMPLETED");
	break;

	case 8:
		sim_card_status = TEL_SIM_STATUS_CARD_ERROR;
		dbg("SIM CARD ERROR");
	break;

	case 9:
		sim_card_status = TEL_SIM_STATUS_CARD_REMOVED;
		dbg("SIM REMOVED");
	break;

	case 12:
		dbg("SIM SMS Ready");

		/* Notify SMS status */
		return __imc_sim_notify_sms_state(co, TRUE);

	case 99:
		sim_card_status = TEL_SIM_STATUS_UNKNOWN;
		dbg("SIM STATE UNKNOWN");
	break;

	default:
		err("Unknown/Unsupported SIM state: [%d]", sim_state);
		return;
	}

	switch (sim_card_status) {
	case TEL_SIM_STATUS_SIM_INIT_COMPLETED: {
		TelSimCardType sim_type;

		dbg("SIM INIT COMPLETED");

		(void)tcore_sim_get_type(co, &sim_type);
		if (sim_type == TEL_SIM_CARD_TYPE_UNKNOWN) {
			/*
			 * SIM is initialized for first time, need to
			 * fetch SIM type
			 */
			(void)__imc_sim_get_sim_type(co,
				__on_response_imc_sim_get_sim_type_internal, NULL);

			return;
		}
	}
	break;

	case TEL_SIM_STATUS_CARD_REMOVED:
		dbg("SIM CARD REMOVED");
		tcore_sim_set_type(co, TEL_SIM_CARD_TYPE_UNKNOWN);
	break;

	case TEL_SIM_STATUS_CARD_NOT_PRESENT:
		dbg("SIM CARD NOT PRESENT");
		tcore_sim_set_type(co, TEL_SIM_CARD_TYPE_UNKNOWN);
	break;

	case TEL_SIM_STATUS_CARD_ERROR:
		dbg("SIM CARD ERROR");
		tcore_sim_set_type(co, TEL_SIM_CARD_TYPE_UNKNOWN);
	break;

	default:
		err("SIM Status: [0x%02x]", sim_card_status);
	break;
	}

	/* Update SIM Status */
	return __imc_sim_update_sim_status(co, sim_card_status);
}

static void __on_response_imc_sim_get_sim_status(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = (ImcRespCbData *)user_data;
	dbg("Enter");

	dbg("SIM Response - SIM status: [+XSIMSTATE]");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		if (at_resp->lines) {
			const gchar *line = NULL;

			/* Process +XSIMSTATE response */
			line = (const gchar *) (at_resp->lines->data);
			if (line != NULL) {
				GSList *tokens;
				guint sim_state, sms_state;

				/*
				 * Tokenize
				 *
				 * +XSIMSTATE: <mode>,<SIM state>,<PB Ready>,<SMS Ready>
				 */
				tokens = tcore_at_tok_new(line);

				if (g_slist_length(tokens) == 4) {
					/* <SIM state> */
					sim_state = atoi(g_slist_nth_data(tokens, 1));

					/* Process SIM Status */
					__imc_sim_process_sim_status(co, sim_state);

					/* <SMS Ready> */
					sms_state = atoi(g_slist_nth_data(tokens, 3));

					/* Notify SMS status */
					__imc_sim_notify_sms_state(co, (sms_state > 0));

				} else {
					err("Invalid message");
				}

				tcore_at_tok_free(tokens);
			}
		}
	}

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

/*
 * Operation - get_sim_status
 *
 * Request -
 * AT-Command: AT+XSIMSTATE?
 *
 * Response - sim_status
 * Success: (Single line) -
 *	+XSIMSTATE: <mode>,<SIM state>,<PB Ready>,<SMS Ready>
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static gboolean __imc_sim_get_sim_status(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		"AT+XSIMSTATE?", "+XSIMSTATE:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		__on_response_imc_sim_get_sim_status, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SIM Status");

	return TRUE;
}

static void __imc_sim_next_from_read_binary(CoreObject *co, ImcRespCbData *resp_cb_data, TelSimResult sim_result, gboolean decode_ret)
{
	ImcSimMetaInfo *file_meta = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	dbg("Entry");

	dbg("[SIM]EF[0x%x] read sim_result[%d] Decode rt[%d]", file_meta->file_id, sim_result, decode_ret);
	switch (file_meta->file_id) {
	case TEL_SIM_EF_ELP:
	case TEL_SIM_EF_USIM_PL:
	case TEL_SIM_EF_LP:
	case TEL_SIM_EF_USIM_LI:
		if (decode_ret == TRUE) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
		} else {
			tcore_sim_get_type(co, &card_type);
			/* 2G */
			/* The ME requests the Extended Language Preference. The ME only requests the Language Preference (EFLP) if at least one of the following conditions holds:
			 -	EFELP is not available;
			 -	EFELP does not contain an entry corresponding to a language specified in ISO 639[30];
			 -	the ME does not support any of the languages in EFELP.
			 */
			/* 3G */
			/* The ME only requests the Language Preference (EFPL) if at least one of the following conditions holds:
			 -	if the EFLI has the value 'FFFF' in its highest priority position
			 -	if the ME does not support any of the language codes indicated in EFLI , or if EFLI is not present
			 */
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				if (file_meta->file_id == TEL_SIM_EF_LP) {
					if (resp_cb_data->cb)
						resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
				} else {
					file_meta->file_id = TEL_SIM_EF_LP;
					__imc_sim_get_response(co, resp_cb_data);
				}
			} else if (TEL_SIM_CARD_TYPE_USIM) {
				if (file_meta->file_id == TEL_SIM_EF_LP || file_meta->file_id == TEL_SIM_EF_USIM_LI) {
					file_meta->file_id = TEL_SIM_EF_ELP;
					__imc_sim_get_response(co, resp_cb_data);
				} else {
					if (resp_cb_data->cb)
						resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
				}
			}
		}
	break;

	case TEL_SIM_EF_ECC:
		tcore_sim_get_type(co, &card_type);
		if (TEL_SIM_CARD_TYPE_USIM == card_type) {
			if (file_meta->current_index == file_meta->rec_count) {
				if (resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
			} else {
				file_meta->current_index++;
				__imc_sim_read_record(co, resp_cb_data);
			}
		} else if (TEL_SIM_CARD_TYPE_GSM == card_type) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
		} else {
			dbg("[SIM DATA]Invalid CardType[%d] Unable to handle", card_type);
		}
	break;

	case TEL_SIM_EF_IMSI:
		if (resp_cb_data->cb) {
			resp_cb_data->cb(co, (gint)sim_result, &file_meta->imsi, resp_cb_data->cb_data);
		} else {
			file_meta->file_id = TEL_SIM_EF_CPHS_CPHS_INFO;
			file_meta->file_result = TEL_SIM_RESULT_FAILURE;
			__imc_sim_get_response(co, resp_cb_data);
		}
		/* Update SIM INIT status - INIT COMPLETE */
		__imc_sim_update_sim_status(co, TEL_SIM_STATUS_SIM_INIT_COMPLETED);
	break;

	case TEL_SIM_EF_MSISDN:
		if (file_meta->current_index == file_meta->rec_count) {
			guint i;
			dbg("rec_count [%d], msisdn_count[%d]", file_meta->rec_count,
				file_meta->files.data.msisdn_list.count);
			if (resp_cb_data->cb) {
				resp_cb_data->cb(co, (gint)sim_result,
					&file_meta->files.data.msisdn_list, resp_cb_data->cb_data);
			}

			/* Free resources */
			for (i = 0; i < file_meta->files.data.msisdn_list.count; i++) {
				tcore_free(file_meta->files.data.msisdn_list.list[i].alpha_id);
				tcore_free(file_meta->files.data.msisdn_list.list[i].num);
			}
			tcore_free(file_meta->files.data.msisdn_list.list);
		} else {
			file_meta->current_index++;
			__imc_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_OPL:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);

		} else {
			file_meta->current_index++;
			__imc_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_PNN:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__imc_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_USIM_CFIS:
	case TEL_SIM_EF_USIM_MWIS:
	case TEL_SIM_EF_USIM_MBI:
	case TEL_SIM_EF_MBDN:
	case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:
	case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
		if (file_meta->current_index == file_meta->rec_count) {
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
		} else {
			file_meta->current_index++;
			__imc_sim_read_record(co, resp_cb_data);
		}
	break;

	case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
	{
		ImcSimMetaInfo *file_meta_new = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

		file_meta->files.result = sim_result;
		if (decode_ret == TRUE && sim_result == TEL_SIM_RESULT_SUCCESS) {
			file_meta_new->files.data.cphs_net.full_name = file_meta->files.data.cphs_net.full_name;
			dbg("file_meta_new->files.data.cphs_net.full_name[%s]", file_meta_new->files.data.cphs_net.full_name);
		}

		file_meta_new->file_id = TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING;
		file_meta_new->file_result = TEL_SIM_RESULT_FAILURE;

		__imc_sim_get_response(co, resp_cb_data);
	}
	break;

	case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data.cphs_net, resp_cb_data->cb_data);

		tcore_free(file_meta->files.data.cphs_net.full_name);
		tcore_free(file_meta->files.data.cphs_net.short_name);
		file_meta->files.data.cphs_net.full_name = NULL;
		file_meta->files.data.cphs_net.short_name = NULL;
	break;

	case TEL_SIM_EF_ICCID:
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data.iccid, resp_cb_data->cb_data);
	break;

	case TEL_SIM_EF_SST:
	case TEL_SIM_EF_SPN:
	case TEL_SIM_EF_SPDI:
	case TEL_SIM_EF_OPLMN_ACT:
	case TEL_SIM_EF_CPHS_CPHS_INFO:
	case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:
	case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
	case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
	break;

	default:
		err("File id not handled [0x%x]", file_meta->file_id);
	break;
	}
}

static void __imc_sim_next_from_get_response(CoreObject *co, ImcRespCbData *resp_cb_data, TelSimResult sim_result)
{
	ImcSimMetaInfo *file_meta = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

	dbg("EF[0x%x] access Result[%d]", file_meta->file_id, sim_result);

	file_meta->files.result = sim_result;
	if (file_meta->file_id != TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING)
		memset(&file_meta->files.data, 0x00, sizeof(file_meta->files.data));

	if ((file_meta->file_id != TEL_SIM_EF_ELP && file_meta->file_id != TEL_SIM_EF_LP &&
		file_meta->file_id != TEL_SIM_EF_USIM_PL && file_meta->file_id != TEL_SIM_EF_CPHS_CPHS_INFO)
		&& (sim_result != TEL_SIM_RESULT_SUCCESS)) {
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
		return;
	}

	switch (file_meta->file_id) {
	case TEL_SIM_EF_ELP:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			__imc_sim_read_binary(co, resp_cb_data);
		} else {
			tcore_sim_get_type(co, &card_type);
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				ImcSimMetaInfo file_meta_new = {0,};

				dbg("[SIM DATA]SIM_EF_ELP(2F05) access fail. Request SIM_EF_LP(0x6F05) info");
				/* The ME requests the Language Preference (EFLP) if EFELP is not available */
				file_meta_new.file_id = TEL_SIM_EF_LP;
				file_meta_new.file_result = TEL_SIM_RESULT_FAILURE;
				file_meta_new.req_command = TCORE_COMMAND_SIM_GET_LANGUAGE;

				memcpy(resp_cb_data->data, &file_meta_new, sizeof(ImcSimMetaInfo));

				__imc_sim_get_response(co, resp_cb_data);
			} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				dbg(" [SIM DATA]fail to get Language information in USIM(EF-LI(6F05),EF-PL(2F05))");
				if (resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
				return;
			}
		}
		break;

	case TEL_SIM_EF_LP:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFLP/LI(0x6F05)");
			__imc_sim_read_binary(co, resp_cb_data);
		} else {
			tcore_sim_get_type(co, &card_type);
			dbg("[SIM DATA]SIM_EF_LP/LI(6F05) access fail. Current CardType[%d]", card_type);
			if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				if (resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
				return;
			}
			/* if EFLI is not present, then the language selection shall be as defined in EFPL at the MF level	*/
			else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				ImcSimMetaInfo file_meta_new = {0,};

				dbg("[SIM DATA] try USIM EFPL(0x2F05)");
				file_meta_new.file_id = TEL_SIM_EF_ELP;
				file_meta_new.file_result = TEL_SIM_RESULT_FAILURE;
				file_meta_new.req_command = TCORE_COMMAND_SIM_GET_LANGUAGE;

				memcpy(resp_cb_data->data, &file_meta_new, sizeof(ImcSimMetaInfo));

				__imc_sim_get_response(co, resp_cb_data);
			}
		}
		break;

	case TEL_SIM_EF_USIM_PL:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			__imc_sim_read_binary(co, resp_cb_data);
		} else {
			/* EFELIand EFPL not present, so set language count as zero and select ECC */
			dbg(
				" [SIM DATA]SIM_EF_USIM_PL(2A05) access fail. Request SIM_EF_ECC(0x6FB7) info");
			if (resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
			return;
		}
		break;

	case TEL_SIM_EF_ECC:
		tcore_sim_get_type(co, &card_type);
		if (TEL_SIM_CARD_TYPE_GSM == card_type) {
			__imc_sim_read_binary(co, resp_cb_data);
		} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
			if (file_meta->rec_count > TEL_SIM_ECC_LIST_MAX) {
				file_meta->rec_count = TEL_SIM_ECC_LIST_MAX;
			}
			file_meta->current_index++;
			__imc_sim_read_record(co, resp_cb_data);
		}
		break;

	case TEL_SIM_EF_ICCID:
	case TEL_SIM_EF_IMSI:
	case TEL_SIM_EF_SST:
	case TEL_SIM_EF_SPN:
	case TEL_SIM_EF_SPDI:
	case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:
	case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
	case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
	case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
	case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		__imc_sim_read_binary(co, resp_cb_data);
		break;

	case TEL_SIM_EF_CPHS_CPHS_INFO:
		if (sim_result == TEL_SIM_RESULT_SUCCESS) {
			tcore_sim_set_cphs_status(co, TRUE);
			__imc_sim_read_binary(co, resp_cb_data);
		} else {
			tcore_sim_set_cphs_status(co, FALSE);
			if (resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)sim_result, &file_meta->files.data, resp_cb_data->cb_data);
		}
		break;


	case TEL_SIM_EF_USIM_CFIS:
		if (file_meta->rec_count > TEL_SIM_CALL_FORWARDING_TYPE_MAX) {
			file_meta->rec_count = TEL_SIM_CALL_FORWARDING_TYPE_MAX;
		}
		file_meta->current_index++;
		__imc_sim_read_record(co, resp_cb_data);
		break;

	case TEL_SIM_EF_MSISDN:
		file_meta->files.data.msisdn_list.list =
			tcore_malloc0(sizeof(TelSimSubscriberInfo) * file_meta->rec_count);

	case TEL_SIM_EF_OPL:
	case TEL_SIM_EF_PNN:
	case TEL_SIM_EF_USIM_MWIS:
	case TEL_SIM_EF_USIM_MBI:
	case TEL_SIM_EF_MBDN:
	case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:
	case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
		file_meta->current_index++;
		__imc_sim_read_record(co, resp_cb_data);
		break;

	case TEL_SIM_EF_SMSP:
	{
		ImcSimPrivateInfo *priv_info = NULL;

		priv_info = tcore_sim_ref_userdata(co);

		dbg("SMSP info set to tcore : count:[%d], rec_len:[%d]",file_meta->rec_count, file_meta->rec_length);
		priv_info->smsp_count = file_meta->rec_count;
		priv_info->smsp_rec_len = file_meta->rec_length;
		break;
	}

	default:
		dbg("error - File id for get file info [0x%x]", file_meta->file_id);
		break;
	}
	return;
}

static void __on_response_imc_sim_update_file(TcorePending *p, guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co_sim = NULL;
	GSList *tokens = NULL;
	TelSimResult sim_result = TEL_SIM_RESULT_CARD_ERROR;
	const char *line;
	ImcRespCbData *resp_cb_data = (ImcRespCbData *) user_data;
	ImcSimMetaInfo *file_meta = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);

	dbg("file_id:[0x%x]", file_meta->file_id);

	if (resp->success > 0) {
		int sw1 = 0;
		int sw2 = 0;
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 2) {
				err("Invalid message");
				goto OUT;
			}
			sw1 = atoi(g_slist_nth_data(tokens, 0));
			sw2 = atoi(g_slist_nth_data(tokens, 1));
		}

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			sim_result = TEL_SIM_RESULT_SUCCESS;
		} else {
			sim_result = __imc_sim_decode_status_word(sw1, sw2);
		}
	} else {
		err("RESPONSE NOK");
		sim_result = TEL_SIM_RESULT_FAILURE;
	}
OUT:
	/* Send Response */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co_sim, (gint)sim_result, NULL, resp_cb_data->cb_data);

	tcore_at_tok_free(tokens);
	dbg("Exit");
}

static void __on_response_imc_sim_read_data(TcorePending *p, guint data_len,
							const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co = NULL;
	GSList *tokens = NULL;
	TelSimResult sim_result;
	gboolean dr = FALSE;
	const char *line = NULL;
	char *res = NULL;
	char *tmp = NULL;
	int res_len;
	int sw1 = 0;
	int sw2 = 0;
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;
	ImcRespCbData *resp_cb_data = (ImcRespCbData *) user_data;
	ImcSimMetaInfo *file_meta = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry");

	co = tcore_pending_ref_core_object(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 3) {
				err("Invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));
		res = g_slist_nth_data(tokens, 2);

		tmp = tcore_at_tok_extract(res);
		tcore_util_hexstring_to_bytes(tmp, &res, (guint *)&res_len);
		dbg("Response: [%s] Response length: [%d]", res, res_len);

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			sim_result = TEL_SIM_RESULT_SUCCESS;
			file_meta->files.result = sim_result;

			dbg("File ID: [0x%x]", file_meta->file_id);
			switch (file_meta->file_id) {
			case TEL_SIM_EF_IMSI: {
				dbg("Data: [%s]", res);
				dr = tcore_sim_decode_imsi((unsigned char *)res, res_len, &file_meta->imsi);
				if (dr == FALSE) {
					err("IMSI decoding failed");
				} else {
					__imc_sim_set_identity(co, &file_meta->imsi);

					/* Update IMSI */
					tcore_sim_set_imsi(co, &file_meta->imsi);
				}
			}
			break;

			case TEL_SIM_EF_ICCID: {
				dr = tcore_sim_decode_iccid((unsigned char *)res, res_len,
						file_meta->files.data.iccid);
			}
			break;

			case TEL_SIM_EF_ELP:		/* 2G EF - 2 bytes decoding */
			case TEL_SIM_EF_USIM_LI:		/* 3G EF - 2 bytes decoding */
			case TEL_SIM_EF_USIM_PL:		/* 3G EF - same as EFELP, so 2 byte decoding */
			case TEL_SIM_EF_LP: 		/* 1 byte encoding */
			{
				tcore_sim_get_type(co, &card_type);
				if ((TEL_SIM_CARD_TYPE_GSM == card_type)
						&& (file_meta->file_id == TEL_SIM_EF_LP)) {
					/*
					 * 2G LP(0x6F05) has 1 byte for each language
					 */
					dr = tcore_sim_decode_lp((unsigned char *)res, res_len, &file_meta->files.data.language);
				} else {
					/*
					 * 3G LI(0x6F05)/PL(0x2F05),
					 * 2G ELP(0x2F05) has 2 bytes for each language
					 */
					dr = tcore_sim_decode_li((unsigned char *)res, res_len,
						file_meta->file_id, &file_meta->files.data.language);
				}
			}
			break;

			case TEL_SIM_EF_SPN:
				dr = tcore_sim_decode_spn((unsigned char *)res, res_len, &file_meta->files.data.spn);
			break;

			case TEL_SIM_EF_SPDI:
				dr = tcore_sim_decode_spdi((unsigned char *)res, res_len, &file_meta->files.data.spdi);
			break;

			case TEL_SIM_EF_SST:
			{
				TelSimServiceTable *svct = NULL;

				svct = g_try_new0(TelSimServiceTable, 1);
				tcore_sim_get_type(co, &card_type);
				svct->sim_type = card_type;
				if (TEL_SIM_CARD_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_sst((unsigned char *)res, res_len, svct->table.sst_service);
				} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
					dr = tcore_sim_decode_ust((unsigned char *)res, res_len, svct->table.ust_service);
				} else {
					err("Not handled card_type[%d]", card_type);
				}

				if (dr == FALSE) {
					err("SST/UST decoding failed");
				} else {
					tcore_sim_set_service_table(co, svct);
				}

				/* Free memory */
				g_free(svct);
			}
			break;

			case TEL_SIM_EF_ECC:
			{
				tcore_sim_get_type(co, &card_type);
				if (TEL_SIM_CARD_TYPE_GSM == card_type) {
					dr = tcore_sim_decode_ecc((unsigned char *)res, res_len, &file_meta->files.data.ecc);
				} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
					TelSimEcc *ecc = NULL;

					ecc = g_try_new0(TelSimEcc, 1);
					dbg("Index [%d]", file_meta->current_index);

					dr = tcore_sim_decode_uecc((unsigned char *)res, res_len, ecc);
					if (dr == TRUE) {
						memcpy(&file_meta->files.data.ecc.list[file_meta->files.data.ecc.count], ecc, sizeof(TelSimEcc));
						file_meta->files.data.ecc.count++;
					}

					/* Free memory */
					g_free(ecc);
				} else {
					dbg("Unknown/Unsupported SIM card Type: [%d]", card_type);
				}
			}
			break;

			case TEL_SIM_EF_MSISDN:
			{
				TelSimSubscriberInfo *msisdn = NULL;

				dbg("Index [%d]", file_meta->current_index);
				msisdn = tcore_malloc0(sizeof(TelSimSubscriberInfo));
				dr = tcore_sim_decode_msisdn((unsigned char *)res, res_len, msisdn);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.msisdn_list.list[file_meta->files.data.msisdn_list.count],
								msisdn, sizeof(TelSimSubscriberInfo));

					file_meta->files.data.msisdn_list.count++;
				}

				/* Free memory */
				dbg("Freeing resources");
				tcore_free(msisdn);
			}
			break;

			case TEL_SIM_EF_OPL:
			{
				TelSimOpl *opl = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				opl = g_try_new0(TelSimOpl, 1);

				dr = tcore_sim_decode_opl((unsigned char *)res, res_len, opl);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.opl.list[file_meta->files.data.opl.opl_count],
							opl, sizeof(TelSimOpl));

					file_meta->files.data.opl.opl_count++;
				}

				/* Free memory */
				g_free(opl);
			}
			break;

			case TEL_SIM_EF_PNN:
			{
				TelSimPnn *pnn = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				pnn = g_try_new0(TelSimPnn, 1);

				dr = tcore_sim_decode_pnn((unsigned char *)res, res_len, pnn);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.pnn.list[file_meta->files.data.pnn.pnn_count],
								pnn, sizeof(TelSimPnn));

					file_meta->files.data.pnn.pnn_count++;
				}

				/* Free memory */
				g_free(pnn);
			}
			break;

			case TEL_SIM_EF_OPLMN_ACT:
				/*dr = tcore_sim_decode_oplmnwact(&file_meta->files.data.opwa,
						(unsigned char *)res, res_len);*/
			break;

			case TEL_SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
				/*dr = tcore_sim_decode_csp(&po->p_cphs->csp,
					p_data->response, p_data->response_len);*/
			break;

			case TEL_SIM_EF_USIM_MBI:			/* linear type */
			{
				TelSimMbi *mbi = NULL;

				mbi = g_try_new0(TelSimMbi, 1);
				dr = tcore_sim_decode_mbi((unsigned char *)res, res_len, mbi);
				if (dr == TRUE) {
					memcpy(&file_meta->mbi_list.list[file_meta->mbi_list.count],
										mbi, sizeof(TelSimMbi));
					file_meta->mbi_list.count++;

					dbg("mbi count[%d]", file_meta->mbi_list.count);
				}

				/* Free memory */
				g_free(mbi);
			}
			break;

			case TEL_SIM_EF_CPHS_MAILBOX_NUMBERS:		/* linear type */
			case TEL_SIM_EF_MBDN:				/* linear type */
				dr = tcore_sim_decode_xdn((unsigned char *)res, res_len,
										file_meta->mb_list[file_meta->current_index-1].alpha_id,
										file_meta->mb_list[file_meta->current_index-1].number);
				file_meta->mb_list[file_meta->current_index-1].alpha_id_len = strlen(file_meta->mb_list[file_meta->current_index-1].alpha_id);
				file_meta->mb_list[file_meta->current_index-1].profile_id = file_meta->current_index;
			break;

			case TEL_SIM_EF_CPHS_VOICE_MSG_WAITING:		/* transparent type */
				dr = tcore_sim_decode_vmwf((unsigned char *)res, res_len, file_meta->files.data.mw.mw);
			break;

			case TEL_SIM_EF_USIM_MWIS: {			/* linear type */
				TelSimMwis *mw = NULL;

				mw = g_try_new0(TelSimMwis, 1);

				dr = tcore_sim_decode_mwis((unsigned char *)res, res_len, mw);
				if (dr == TRUE) {
					guint count = file_meta->files.data.mw.profile_count;

					memcpy(&file_meta->files.data.mw.mw[count], mw, sizeof(TelSimMwis));

					/**
					 * The Profile Identity shall be between 1 and 4 as defined
					 * in TS 23.097 for MSP
					 */
					file_meta->files.data.mw.mw[count].profile_id = count+1;

					file_meta->files.data.mw.profile_count++;
				}

				/* Free memory */
				g_free(mw);
			}
			break;

			case TEL_SIM_EF_CPHS_CALL_FORWARD_FLAGS:	/* transparent type */
				dr = tcore_sim_decode_cff((unsigned char *)res, res_len, file_meta->files.data.mw.mw);
			break;

			case TEL_SIM_EF_USIM_CFIS:			/* linear type */
			{
				TelSimCfis *cf = NULL;

				cf = g_try_new0(TelSimCfis, 1);
				dr = tcore_sim_decode_cfis((unsigned char *)res, res_len, cf);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.cf.cf[file_meta->files.data.cf.profile_count],
									cf, sizeof(TelSimCfis));
					file_meta->files.data.cf.profile_count++;
				}

				/* Free memory */
				g_free(cf);
			}
			break;

			case TEL_SIM_EF_CPHS_SERVICE_STRING_TABLE:
				dbg("not handled - TEL_SIM_EF_CPHS_SERVICE_STRING_TABLE ");
			break;

			case TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING:
				file_meta->files.data.cphs_net.full_name = tcore_malloc0(TEL_SIM_CPHS_OPERATOR_NAME_LEN_MAX+1);
				dr = tcore_sim_decode_ons((unsigned char *)res, res_len,
										(unsigned char*)file_meta->files.data.cphs_net.full_name);
				dbg("file_meta->files.result[%d],file_meta->files.data.cphs_net.full_name[%s]",
						file_meta->files.result, file_meta->files.data.cphs_net.full_name);
			break;

			case TEL_SIM_EF_CPHS_DYNAMICFLAGS:
				/*dr = tcore_sim_decode_dynamic_flag(&po->p_cphs->dflagsinfo,
							p_data->response, p_data->response_len);*/
			break;

			case TEL_SIM_EF_CPHS_DYNAMIC2FLAG:
				/*dr = tcore_sim_decode_dynamic2_flag(&po->p_cphs->d2flagsinfo, p_data->response,
							p_data->response_len);*/
			break;

			case TEL_SIM_EF_CPHS_CPHS_INFO:
				/*dr = tcore_sim_decode_cphs_info(&file_meta->files.data.cphs,
							(unsigned char *)res, res_len);*/
			break;

			case TEL_SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
				file_meta->files.data.cphs_net.short_name = tcore_malloc0(TEL_SIM_CPHS_OPERATOR_NAME_SHORT_FORM_LEN_MAX+1);
				dr = tcore_sim_decode_short_ons((unsigned char *)res, res_len,
										(unsigned char*)file_meta->files.data.cphs_net.short_name);
				dbg("file_meta->files.result[%d],file_meta->files.data.cphs_net.short_name[%s]",
						file_meta->files.result, file_meta->files.data.cphs_net.short_name);
			break;

			case TEL_SIM_EF_CPHS_INFORMATION_NUMBERS:
				/*dr = tcore_sim_decode_information_number(&po->p_cphs->infn, p_data->response, p_data->response_len);*/
			break;

			default:
				dbg("File Decoding Failed - not handled File[0x%x]", file_meta->file_id);
				dr = 0;
			break;
			}
		} else {
			sim_result = __imc_sim_decode_status_word(sw1, sw2);
			file_meta->files.result = sim_result;
		}

		/* Free memory */
		g_free(tmp);
		g_free(res);

		/* Free tokens */
		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");
		dbg("Error - File ID: [0x%x]", file_meta->file_id);
		sim_result = TEL_SIM_RESULT_FAILURE;
	}

	/* Get File data */
	__imc_sim_next_from_read_binary(tcore_pending_ref_core_object(p), resp_cb_data, sim_result, dr);

	dbg("Exit");
}

static void __on_response_imc_sim_get_response(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co = NULL;
	TelSimResult sim_result;
	GSList *tokens = NULL;
	const char *line = NULL;
	int sw1 = 0;
	int sw2 = 0;
	ImcRespCbData *resp_cb_data = (ImcRespCbData *)user_data;
	ImcSimMetaInfo *file_meta =
		(ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("SIM Response - SIM File info: [+CRSM]");

	co = tcore_pending_ref_core_object(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 2) {
				err("Invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));

		/*1. SIM access success case*/
		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			unsigned char tag_len = 0;
			unsigned short record_len = 0;
			char num_of_records = 0;
			unsigned char file_id_len = 0;
			unsigned short file_id = 0;
			unsigned short file_size = 0;
			unsigned short file_type = 0;
			unsigned short arr_file_id = 0;
			int arr_file_id_rec_num = 0;
			TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;

			/* handling only last 3 bits */
			unsigned char file_type_tag = 0x07;
			unsigned char *ptr_data;

			char *hexData;
			char *tmp;
			char *record_data = NULL;
			guint record_data_len;
			hexData = g_slist_nth_data(tokens, 2);
			dbg("hexData: %s", hexData);
			dbg("hexData: %s", hexData + 1);

			tmp = tcore_at_tok_extract(hexData);
			tcore_util_hexstring_to_bytes(tmp, &record_data, &record_data_len);
			tcore_util_hex_dump("   ", record_data_len, record_data);
			g_free(tmp);

			ptr_data = (unsigned char *)record_data;
			tcore_sim_get_type(co, &card_type);
			if (TEL_SIM_CARD_TYPE_USIM == card_type) {
				/*
				 ETSI TS 102 221 v7.9.0
				 - Response Data
				 '62'	FCP template tag
				 - Response for an EF
				 '82'	M	File Descriptor
				 '83'	M	File Identifier
				 'A5'	O	Proprietary information
				 '8A'	M	Life Cycle Status Integer
				 '8B', '8C' or 'AB' C1	Security attributes
				 '80'	M	File size
				 '81'	O	Total file size
				 '88'	O	Short File Identifier (SFI)
				 */

				/* rsim.res_len has complete data length received */

				/* FCP template tag - File Control Parameters tag*/
				if (*ptr_data == 0x62) {
					/* parse complete FCP tag*/
					/* increment to next byte */
					ptr_data++;
					tag_len = *ptr_data++;
					dbg("tag_len: %02x", tag_len);
					/* FCP file descriptor - file type, accessibility, DF, ADF etc*/
					if (*ptr_data == 0x82) {
						/* increment to next byte */
						ptr_data++;
						/* 2 or 5 value*/
						ptr_data++;
						/* consider only last 3 bits*/
						dbg("file_type_tag: %02x", file_type_tag);
						file_type_tag = file_type_tag & (*ptr_data);
						dbg("file_type_tag: %02x", file_type_tag);

						switch (file_type_tag) {
						/* increment to next byte */
						// ptr_data++;
						case 0x1:
							dbg("Getting FileType: [Transparent file type]");
							file_type = IMC_SIM_FILE_TYPE_TRANSPARENT;

							/* increment to next byte */
							ptr_data++;
							/* increment to next byte */
							ptr_data++;
							break;

						case 0x2:
							dbg("Getting FileType: [Linear fixed file type]");
							/* increment to next byte */
							ptr_data++;
							/* data coding byte - value 21 */
							ptr_data++;
							/* 2bytes */
							memcpy(&record_len, ptr_data, 2);
							/* swap bytes */
							IMC_SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							/* Data lossy conversation from enum (int) to unsigned char */
							file_type = IMC_SIM_FILE_TYPE_LINEAR_FIXED;
							break;

						case 0x6:
							dbg("Cyclic fixed file type");
							/* increment to next byte */
							ptr_data++;
							/* data coding byte - value 21 */
							ptr_data++;
							/* 2bytes */
							memcpy(&record_len, ptr_data, 2);
							/* swap bytes */
							IMC_SWAP_BYTES_16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							file_type = IMC_SIM_FILE_TYPE_CYCLIC;
							break;

						default:
							dbg("not handled file type [0x%x]", *ptr_data);
							break;
						}
					} else {
						dbg("INVALID FCP received - DEbug!");
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					/*File identifier - 0x84,0x85,0x86 etc are currently ignored and not handled */
					if (*ptr_data == 0x83) {
						/* increment to next byte */
						ptr_data++;
						file_id_len = *ptr_data++;
						dbg("file_id_len: %02x", file_id_len);

						memcpy(&file_id, ptr_data, file_id_len);
						dbg("file_id: %x", file_id);

						/* swap bytes	 */
						IMC_SWAP_BYTES_16(file_id);
						dbg("file_id: %x", file_id);

						ptr_data = ptr_data + 2;
						dbg("Getting FileID=[0x%x]", file_id);
					} else {
						dbg("INVALID FCP received - DEbug!");
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					/* proprietary information */
					if (*ptr_data == 0xA5) {
						unsigned short prop_len;
						/* increment to next byte */
						ptr_data++;

						/* length */
						prop_len = *ptr_data;
						dbg("prop_len: %02x", prop_len);

						/* skip data */
						ptr_data = ptr_data + prop_len + 1;
					} else {
						dbg("INVALID FCP received - DEbug!");
					}

					/* life cycle status integer [8A][length:0x01][status]*/
					/*
					 status info b8~b1
					 00000000 : No information given
					 00000001 : creation state
					 00000011 : initialization state
					 000001-1 : operation state -activated
					 000001-0 : operation state -deactivated
					 000011-- : Termination state
					 b8~b5 !=0, b4~b1=X : Proprietary
					 Any other value : RFU
					 */
					if (*ptr_data == 0x8A) {
						/* increment to next byte */
						ptr_data++;
						/* length - value 1 */
						ptr_data++;

						switch (*ptr_data) {
						case 0x04:
						case 0x06:
							dbg("<RX> operation state -deactivated");
							ptr_data++;
							break;

						case 0x05:
						case 0x07:
							dbg("<RX> operation state -activated");
							ptr_data++;
							break;

						default:
							dbg("<RX> DEBUG! LIFE CYCLE STATUS =[0x%x]", *ptr_data);
							ptr_data++;
							break;
						}
					}

					/* related to security attributes : currently not handled*/
					if (*ptr_data == 0x86 || *ptr_data == 0x8B || *ptr_data == 0x8C || *ptr_data == 0xAB) {
						/* increment to next byte */
						ptr_data++;
						/* if tag length is 3 */
						if (*ptr_data == 0x03) {
							/* increment to next byte */
							ptr_data++;
							/* EFARR file id */
							memcpy(&arr_file_id, ptr_data, 2);
							/* swap byes */
							IMC_SWAP_BYTES_16(arr_file_id);
							ptr_data = ptr_data + 2;
							arr_file_id_rec_num = *ptr_data++;
							dbg("arr_file_id_rec_num:[%d]", arr_file_id_rec_num);
						} else {
							/* if tag length is not 3 */
							/* ignoring bytes	*/
							// ptr_data = ptr_data + 4;
							dbg("Useless security attributes, so jump to next tag");
							ptr_data = ptr_data + (*ptr_data + 1);
						}
					} else {
						dbg("INVALID FCP received[0x%x] - DEbug!", *ptr_data);
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					dbg("Current ptr_data value is [%x]", *ptr_data);

					/* file size excluding structural info*/
					if (*ptr_data == 0x80) {
						/* for EF file size is body of file and for Linear or cyclic it is
						 * number of recXsizeof(one record)
						 */
						/* increment to next byte */
						ptr_data++;
						/* length is 1 byte - value is 2 bytes or more */
						ptr_data++;
						memcpy(&file_size, ptr_data, 2);
						/* swap bytes */
						IMC_SWAP_BYTES_16(file_size);
						ptr_data = ptr_data + 2;
					} else {
						dbg("INVALID FCP received - DEbug!");
						tcore_at_tok_free(tokens);
						g_free(record_data);
						return;
					}

					/* total file size including structural info*/
					if (*ptr_data == 0x81) {
						int len;
						/* increment to next byte */
						ptr_data++;
						/* length */
						len = *ptr_data;
						dbg("len:[%d]", len);
						/* ignored bytes */
						ptr_data = ptr_data + 3;
					} else {
						dbg("INVALID FCP received - DEbug!");
						/* 0x81 is optional tag?? check out! so do not return -1 from here! */
					}
					/*short file identifier ignored*/
					if (*ptr_data == 0x88) {
						dbg("0x88: Do Nothing");
						/*DO NOTHING*/
					}
				} else {
					dbg("INVALID FCP received - DEbug!");
					tcore_at_tok_free(tokens);
					g_free(record_data);
					return;
				}
			} else if (TEL_SIM_CARD_TYPE_GSM == card_type) {
				unsigned char gsm_specific_file_data_len = 0;
				/* ignore RFU byte1 and byte2 */
				ptr_data++;
				ptr_data++;
				/* file size */
				// file_size = p_info->response_len;
				memcpy(&file_size, ptr_data, 2);
				/* swap bytes */
				IMC_SWAP_BYTES_16(file_size);
				/* parsed file size */
				ptr_data = ptr_data + 2;
				/* file id */
				memcpy(&file_id, ptr_data, 2);
				IMC_SWAP_BYTES_16(file_id);
				dbg("FILE id --> [%x]", file_id);
				ptr_data = ptr_data + 2;
				/* save file type - transparent, linear fixed or cyclic */
				file_type_tag = (*(ptr_data + 7));

				switch (*ptr_data) {
				case 0x0:
					/* RFU file type */
					dbg("RFU file type- not handled - Debug!");
					break;

				case 0x1:
					/* MF file type */
					dbg("MF file type - not handled - Debug!");
					break;

				case 0x2:
					/* DF file type */
					dbg("DF file type - not handled - Debug!");
					break;

				case 0x4:
					/* EF file type */
					dbg("EF file type [%d] ", file_type_tag);
					/*	increment to next byte */
					ptr_data++;

					if (file_type_tag == 0x00 || file_type_tag == 0x01) {
						/* increament to next byte as this byte is RFU */
						ptr_data++;
						file_type =
							(file_type_tag == 0x00) ? IMC_SIM_FILE_TYPE_TRANSPARENT : IMC_SIM_FILE_TYPE_LINEAR_FIXED;
					} else {
						/* increment to next byte */
						ptr_data++;
						/* For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
						/* the INCREASE command is allowed on the selected cyclic file. */
						file_type = IMC_SIM_FILE_TYPE_CYCLIC;
					}
					/* bytes 9 to 11 give SIM file access conditions */
					ptr_data++;
					/* byte 10 has one nibble that is RF U and another for INCREASE which is not used currently */
					ptr_data++;
					/* byte 11 is invalidate and rehabilate nibbles */
					ptr_data++;
					/* byte 12 - file status */
					ptr_data++;
					/* byte 13 - GSM specific data */
					gsm_specific_file_data_len = *ptr_data;
					dbg("gsm_specific_file_data_len:[%d]", gsm_specific_file_data_len);
					ptr_data++;
					/* byte 14 - structure of EF - transparent or linear or cyclic , already saved above */
					ptr_data++;
					/* byte 15 - length of record for linear and cyclic , for transparent it is set to 0x00. */
					record_len = *ptr_data;
					dbg("record length[%d], file size[%d]", record_len, file_size);
					if (record_len != 0)
						num_of_records = (file_size / record_len);

					dbg("Number of records [%d]", num_of_records);
					break;

				default:
					dbg("not handled file type");
					break;
				}
			} else {
				err("Unknown Card Type - [%d]", card_type);
			}

			dbg("req ef[0x%x] resp ef[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]",
				file_meta->file_id, file_id, file_size, file_type, num_of_records, record_len);

			file_meta->file_type = file_type;
			file_meta->data_size = file_size;
			file_meta->rec_length = record_len;
			file_meta->rec_count = num_of_records;
			file_meta->current_index = 0;		/* reset for new record type EF */
			sim_result = TEL_SIM_RESULT_SUCCESS;
			g_free(record_data);
		} else {
			/*2. SIM access fail case*/
			err("Failed to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
			sim_result = __imc_sim_decode_status_word(sw1, sw2);
		}

		tcore_at_tok_free(tokens);
	} else {
		err("RESPONSE NOK");
		err("Failed to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
		sim_result = TEL_SIM_RESULT_FAILURE;
	}

	dbg("Calling __imc_sim_next_from_get_response");
	__imc_sim_next_from_get_response(co, resp_cb_data, sim_result);
	dbg("Exit");
}

static TelReturn __imc_sim_update_file(CoreObject *co, ImcRespCbData *resp_cb_data, int cmd, TelSimFileId ef,
					int p1, int p2, int p3, char *encoded_data)
{
	char *cmd_str = NULL;
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcSimMetaInfo *file_meta = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	cmd_str = g_strdup_printf("AT+CRSM=%d,%d,%d,%d,%d,\"%s\"", cmd, ef, p1, p2, p3, encoded_data);

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+CRSM:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT, NULL,
						__on_response_imc_sim_update_file, resp_cb_data,
						on_send_imc_request, NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Update SIM File");

	tcore_free(encoded_data);
	g_free(cmd_str);

	dbg("Exit");
	return ret;
}
static void __imc_sim_read_record(CoreObject *co, ImcRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	ImcSimMetaInfo *file_meta = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	/* According to TS 102 221, values of p1, p2, p3 can be as below:
	 * 11.1.5 READ RECORD
	 * P1: Record number
	 * P2: Mode, see table 11.11
	 * Lc: Not present
	 * Data: Not present
	 * Le: Number of bytes to be read (P3)
	 */

	p1 = (unsigned char) file_meta->current_index;
	p2 = (unsigned char) 0x04;			/* 0x4 for absolute mode */
	p3 = (unsigned char) file_meta->rec_length;

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d, %d, %d, %d",
				IMC_SIM_ACCESS_READ_RECORD, file_meta->file_id, p1, p2, p3);

	ret = tcore_at_prepare_and_send_request(co, at_cmd, "+CRSM:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT, NULL,
						__on_response_imc_sim_read_data, resp_cb_data,
						on_send_imc_request, NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Record");

	dbg("ret:[%d]", ret);
	g_free(at_cmd);

	dbg("Exit");
}

static void __imc_sim_read_binary(CoreObject *co, ImcRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	int offset = 0;
	ImcSimMetaInfo *file_meta = (ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	/* According to TS 102 221, values of P1, P2, P3 can be as below:
	 * 11.1.3 READ BINARY
	 * P1: See table 11.10
	 * P2: Offset low
	 * Lc: Not present
	 * Data: Not present
	 * Le: Number of bytes to be read (P3)
	 */

	p1 = (unsigned char) (offset & 0xFF00) >> 8;
	p2 = (unsigned char) offset & 0x00FF;			/* offset low */
	p3 = (unsigned char) file_meta->data_size;

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d, %d, %d, %d",
				IMC_SIM_ACCESS_READ_BINARY, file_meta->file_id, p1, p2, p3);

	ret = tcore_at_prepare_and_send_request(co, at_cmd, "+CRSM:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT, NULL,
						__on_response_imc_sim_read_data, resp_cb_data,
						on_send_imc_request, NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Data");

	dbg("ret:[%d]", ret);
	g_free(at_cmd);

	dbg("Exit");
}

static TelReturn __imc_sim_get_response(CoreObject *co, ImcRespCbData *resp_cb_data)
{
	gchar *at_cmd = NULL;
	ImcSimMetaInfo *file_meta =
		(ImcSimMetaInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry File-id:[0x%02x]", file_meta->file_id);

	at_cmd = g_strdup_printf("AT+CRSM=%d, %d",
		IMC_SIM_ACCESS_GET_RESPONSE, file_meta->file_id);

	ret = tcore_at_prepare_and_send_request(co,
				at_cmd, "+CRSM:",
				TCORE_AT_COMMAND_TYPE_SINGLELINE,
				TCORE_PENDING_PRIORITY_DEFAULT, NULL,
				__on_response_imc_sim_get_response, resp_cb_data,
				on_send_imc_request, NULL,
				0, NULL, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get File Info");

	g_free(at_cmd);
	dbg("Exit");
	return ret;
}

static void __on_response_imc_sim_get_retry_count(TcorePending *p, guint data_len,
			const void *data, void *user_data)
{
	TelSimResult result = TEL_SIM_RESULT_INCORRECT_PASSWORD;
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcSimCurrSecOp *sec_op = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	int lock_type = 0;
	int attempts_left = 0;
	int time_penalty = 0;

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		dbg("Sim Get Retry Count [OK]");

		if (at_resp->lines) {
			line = (const char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 3) {
				err("Invalid message");
				goto Failure;
			}
		}
		lock_type = atoi(g_slist_nth_data(tokens, 0));
		attempts_left = atoi(g_slist_nth_data(tokens, 1));
		time_penalty = atoi(g_slist_nth_data(tokens, 2));

		dbg("lock_type = %d, attempts_left = %d, time_penalty = %d",
			lock_type, attempts_left, time_penalty);

		switch (*sec_op) {
			case IMC_SIM_CURR_SEC_OP_PIN1_VERIFY:
			case IMC_SIM_CURR_SEC_OP_PIN2_VERIFY:
			{
				TelSimSecPinResult verify_pin = {0, };

				if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN1_VERIFY)
					verify_pin.pin_type = TEL_SIM_PIN_TYPE_PIN1;
				else if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN2_VERIFY)
					verify_pin.pin_type = TEL_SIM_PIN_TYPE_PIN2;

				verify_pin.retry_count = attempts_left;

				if(resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)result,
						&verify_pin, resp_cb_data->cb_data);
				break;
			}
			case IMC_SIM_CURR_SEC_OP_PUK1_VERIFY:
			case IMC_SIM_CURR_SEC_OP_PUK2_VERIFY:
			{
				TelSimSecPukResult verify_puk = {0, };

				if (*sec_op == IMC_SIM_CURR_SEC_OP_PUK1_VERIFY)
					verify_puk.puk_type = TEL_SIM_PUK_TYPE_PUK1;
				else if (*sec_op == IMC_SIM_CURR_SEC_OP_PUK2_VERIFY)
					verify_puk.puk_type = TEL_SIM_PUK_TYPE_PUK2;

				verify_puk.retry_count = attempts_left;

				if(resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)result,
						&verify_puk, resp_cb_data->cb_data);
				break;
			}
			case IMC_SIM_CURR_SEC_OP_PIN1_CHANGE:
			case IMC_SIM_CURR_SEC_OP_PIN2_CHANGE:
			{
				TelSimSecPinResult change_pin = {0, };

				if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN1_CHANGE)
					change_pin.pin_type = TEL_SIM_PIN_TYPE_PIN1;
				else if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN2_CHANGE)
					change_pin.pin_type = TEL_SIM_PIN_TYPE_PIN2;

				change_pin.retry_count = attempts_left;

				if(resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)result,
						&change_pin, resp_cb_data->cb_data);
				break;
			}
			case IMC_SIM_CURR_SEC_OP_PIN1_DISABLE:
			case IMC_SIM_CURR_SEC_OP_PIN2_DISABLE:
			case IMC_SIM_CURR_SEC_OP_FDN_DISABLE:
			case IMC_SIM_CURR_SEC_OP_SIM_DISABLE:
			case IMC_SIM_CURR_SEC_OP_NET_DISABLE:
			case IMC_SIM_CURR_SEC_OP_NS_DISABLE:
			case IMC_SIM_CURR_SEC_OP_SP_DISABLE:
			case IMC_SIM_CURR_SEC_OP_CP_DISABLE:
			{
				TelSimFacilityResult disable_facility = {0, };
				int lock_type;

				lock_type = __imc_sim_get_lock_type(*sec_op);
				if (lock_type == -1)
					goto Failure;

				disable_facility.type = lock_type;
				disable_facility.retry_count = attempts_left;

				if(resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)result,
						&disable_facility, resp_cb_data->cb_data);
				break;
			}
			case IMC_SIM_CURR_SEC_OP_PIN1_ENABLE:
			case IMC_SIM_CURR_SEC_OP_PIN2_ENABLE:
			case IMC_SIM_CURR_SEC_OP_FDN_ENABLE:
			case IMC_SIM_CURR_SEC_OP_SIM_ENABLE:
			case IMC_SIM_CURR_SEC_OP_NET_ENABLE:
			case IMC_SIM_CURR_SEC_OP_NS_ENABLE:
			case IMC_SIM_CURR_SEC_OP_SP_ENABLE:
			case IMC_SIM_CURR_SEC_OP_CP_ENABLE:
			{
				TelSimFacilityResult enable_facility = {0, };
				int lock_type;

				lock_type = __imc_sim_get_lock_type(*sec_op);
				if (lock_type == -1)
					goto Failure;

				enable_facility.type = lock_type;
				enable_facility.retry_count = attempts_left;

				if(resp_cb_data->cb)
					resp_cb_data->cb(co, (gint)result,
						&enable_facility, resp_cb_data->cb_data);
				break;
			}
			default:
				err("Unhandled sec op [%d]", *sec_op);
			break;
		}

		tcore_at_tok_free(tokens);
		imc_destroy_resp_cb_data(resp_cb_data);
		return;
	}
	err("Sim Get Retry Count [NOK]");
Failure :
	/*TODO - send response for verify pin, puk etc.,
	* when get_retry_count fails
	*/
	tcore_at_tok_free(tokens);
	imc_destroy_resp_cb_data(resp_cb_data);
}

static TelReturn __imc_sim_get_retry_count(CoreObject *co,
			ImcRespCbData *resp_cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcSimCurrSecOp *sec_op = (
		ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	int lock_type = 0;
	gchar *cmd_str = NULL;

	dbg("Entry");

	switch (*sec_op) {
		case IMC_SIM_CURR_SEC_OP_PIN1_VERIFY:
		case IMC_SIM_CURR_SEC_OP_PIN1_CHANGE:
		case IMC_SIM_CURR_SEC_OP_PIN1_ENABLE:
		case IMC_SIM_CURR_SEC_OP_PIN1_DISABLE:
			lock_type = 1;
			break;
		case IMC_SIM_CURR_SEC_OP_PIN2_VERIFY:
		case IMC_SIM_CURR_SEC_OP_PIN2_CHANGE:
		case IMC_SIM_CURR_SEC_OP_PIN2_ENABLE:
		case IMC_SIM_CURR_SEC_OP_PIN2_DISABLE:
		case IMC_SIM_CURR_SEC_OP_FDN_ENABLE:
		case IMC_SIM_CURR_SEC_OP_FDN_DISABLE:
			lock_type = 2;
			break;
		case IMC_SIM_CURR_SEC_OP_PUK1_VERIFY:
			lock_type = 3;
			break;
		case IMC_SIM_CURR_SEC_OP_PUK2_VERIFY:
			lock_type = 4;
			break;
		case IMC_SIM_CURR_SEC_OP_NET_ENABLE:
		case IMC_SIM_CURR_SEC_OP_NET_DISABLE:
			lock_type = 5;
			break;
		case IMC_SIM_CURR_SEC_OP_NS_ENABLE:
		case IMC_SIM_CURR_SEC_OP_NS_DISABLE:
			lock_type = 6;
			break;
		case IMC_SIM_CURR_SEC_OP_SP_ENABLE:
		case IMC_SIM_CURR_SEC_OP_SP_DISABLE:
			lock_type = 7;
			break;
		case IMC_SIM_CURR_SEC_OP_CP_ENABLE:
		case IMC_SIM_CURR_SEC_OP_CP_DISABLE:
			lock_type = 8;
			break;
		case IMC_SIM_CURR_SEC_OP_ADM_VERIFY:
			lock_type = 9;
			break;
		default:
			break;
		}
	cmd_str = g_strdup_printf("AT+XPINCNT=%d", lock_type);

	ret = tcore_at_prepare_and_send_request(co, cmd_str, NULL,
					TCORE_AT_COMMAND_TYPE_SINGLELINE,
					TCORE_PENDING_PRIORITY_DEFAULT,
					NULL,
					__on_response_imc_sim_get_retry_count,
					resp_cb_data,
					on_send_imc_request,
					NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Retry Count");
	g_free(cmd_str);
	return ret;
}

static TelSimLockType __imc_sim_lock_type(int lock_type)
{
	switch(lock_type) {
		case 1 :
			return TEL_SIM_LOCK_SC;
		case 2 :
			return TEL_SIM_LOCK_FD;
		case 5 :
			return TEL_SIM_LOCK_PN;
		case 6 :
			return TEL_SIM_LOCK_PU;
		case 7 :
			return TEL_SIM_LOCK_PP;
		case 8 :
			return TEL_SIM_LOCK_PC ;
		case 9 :
			return TEL_SIM_LOCK_PS ;
		default :
			err("Invalid lock_type [%d]", lock_type);
			return -1;
	}
}

static char *__imc_sim_get_fac_from_lock_type(TelSimLockType lock_type,
		ImcSimCurrSecOp *sec_op, int flag)
{
	char *fac = NULL;
	switch(lock_type) {
		case TEL_SIM_LOCK_PS :
			fac = "PS";
			if (flag == ENABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_SIM_ENABLE;
			else if (flag == DISABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_SIM_DISABLE;
			else
				*sec_op = IMC_SIM_CURR_SEC_OP_SIM_STATUS;
			break;
		case TEL_SIM_LOCK_SC :
			fac = "SC";
			if (flag == ENABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_PIN1_ENABLE;
			else if (flag == DISABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_PIN1_DISABLE;
			else
				*sec_op = IMC_SIM_CURR_SEC_OP_PIN1_STATUS;
			break;
		case TEL_SIM_LOCK_FD :
			fac = "FD";
			if (flag == ENABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_FDN_ENABLE;
			else if (flag == DISABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_FDN_DISABLE;
			else
				*sec_op = IMC_SIM_CURR_SEC_OP_FDN_STATUS;
			break;
		case TEL_SIM_LOCK_PN :
			fac = "PN";
			if (flag == ENABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_NET_ENABLE;
			else if (flag == DISABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_NET_DISABLE;
			else
				*sec_op = IMC_SIM_CURR_SEC_OP_NET_STATUS;
			break;
		case TEL_SIM_LOCK_PU :
			fac = "PU";
			if (flag == ENABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_NS_ENABLE;
			else if (flag == DISABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_NS_DISABLE;
			else
				*sec_op = IMC_SIM_CURR_SEC_OP_NS_STATUS;
			break;
		case TEL_SIM_LOCK_PP :
			fac = "PP";
			if (flag == ENABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_SP_ENABLE;
			else if (flag == DISABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_SP_DISABLE;
			else
				*sec_op = IMC_SIM_CURR_SEC_OP_SP_STATUS;
			break;
		case TEL_SIM_LOCK_PC :
			fac = "PC";
			if (flag == ENABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_CP_ENABLE;
			else if (flag == DISABLE_FLAG)
				*sec_op = IMC_SIM_CURR_SEC_OP_CP_DISABLE;
			else
				*sec_op = IMC_SIM_CURR_SEC_OP_CP_STATUS;
			break;
		default :
			err("Unhandled sim lock type [%d]", lock_type);
	}
	return fac;
}

static int __imc_sim_get_lock_type(ImcSimCurrSecOp sec_op)
{
	switch(sec_op) {
		case IMC_SIM_CURR_SEC_OP_SIM_DISABLE :
		case IMC_SIM_CURR_SEC_OP_SIM_ENABLE :
		case IMC_SIM_CURR_SEC_OP_SIM_STATUS :
			return TEL_SIM_LOCK_PS;
		case IMC_SIM_CURR_SEC_OP_PIN1_DISABLE :
		case IMC_SIM_CURR_SEC_OP_PIN1_ENABLE :
		case IMC_SIM_CURR_SEC_OP_PIN1_STATUS :
			return TEL_SIM_LOCK_SC;
		case IMC_SIM_CURR_SEC_OP_FDN_DISABLE :
		case IMC_SIM_CURR_SEC_OP_FDN_ENABLE :
		case IMC_SIM_CURR_SEC_OP_FDN_STATUS :
			return TEL_SIM_LOCK_FD;
		case IMC_SIM_CURR_SEC_OP_NET_DISABLE :
		case IMC_SIM_CURR_SEC_OP_NET_ENABLE :
		case IMC_SIM_CURR_SEC_OP_NET_STATUS :
			return TEL_SIM_LOCK_PN;
		case IMC_SIM_CURR_SEC_OP_NS_DISABLE :
		case IMC_SIM_CURR_SEC_OP_NS_ENABLE :
		case IMC_SIM_CURR_SEC_OP_NS_STATUS :
			return TEL_SIM_LOCK_PU;
		case IMC_SIM_CURR_SEC_OP_SP_DISABLE :
		case IMC_SIM_CURR_SEC_OP_SP_ENABLE :
		case IMC_SIM_CURR_SEC_OP_SP_STATUS :
			return TEL_SIM_LOCK_PP;
		case IMC_SIM_CURR_SEC_OP_CP_DISABLE :
		case IMC_SIM_CURR_SEC_OP_CP_ENABLE :
		case IMC_SIM_CURR_SEC_OP_CP_STATUS :
			return TEL_SIM_LOCK_PC ;
		default :
			err("Invalid sec op [%d]", sec_op);
			return -1;
	}
}

/* Notifications */
/*
 * Notification: +XSIM: <SIM state>
 *
 * Possible values of <SIM state> can be
 * 0	SIM not present
 * 1	PIN verification needed
 * 2	PIN verification not needed - Ready
 * 3	PIN verified - Ready
 * 4	PUK verification needed
 * 5	SIM permanently blocked
 * 6	SIM Error
 * 7	ready for attach (+COPS)
 * 8	SIM Technical Problem
 * 9	SIM Removed
 * 10	SIM Reactivating
 * 11	SIM Reactivated
 * 12	SIM SMS Caching Completed. (Sent only when SMS caching enabled)
 * 99	SIM State Unknown
 */
static gboolean on_notification_imc_sim_status(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *lines = (GSList *)event_info;
	const gchar *line;

	dbg("SIM notification - SIM status: [+XSIM]");

	if (g_slist_length(lines) != 1) {
		err("+XSIM unsolicited message expected to be "
			"Single line but received multiple lines");
		return TRUE;
	}

	line = (const gchar *) (lines->data);
	if (line != NULL) {
		GSList *tokens;
		guint sim_state;

		/*
		 * Tokenize
		 *
		 * +XSIM: <SIM state>
		 */
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) == 1) {
			/* <SIM state> */
			sim_state = atoi(g_slist_nth_data(tokens, 0));

			/* Process SIM Status */
			__imc_sim_process_sim_status(co, sim_state);
		} else {
			err("Invalid message");
		}

		tcore_at_tok_free(tokens);
	}

	return TRUE;
}

/* Hooks */
static TcoreHookReturn on_hook_imc_modem_power(TcorePlugin *source,
	TcoreNotification command, guint data_len, void *data, void *user_data)
{
	CoreObject *co = (CoreObject *)user_data;

	tcore_check_return_value(co != NULL, TCORE_HOOK_RETURN_CONTINUE);

	dbg("Get SIM status");
	(void)__imc_sim_get_sim_status(co, NULL, NULL);

	return TCORE_HOOK_RETURN_CONTINUE;
}

/* Response Functions */
static void on_response_imc_sim_req_authentication(TcorePending *p, guint data_len,
			const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	GSList *tokens = NULL;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimAuthenticationResponse auth_resp = {0, };
	TelSimResult sim_result = TEL_SIM_RESULT_FAILURE;
	ImcRespCbData *resp_cb_data = user_data;
	TelSimAuthenticationType *auth_type = (TelSimAuthenticationType *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	dbg("Entry");

	if (NULL == at_resp) {
		err("at_resp is NULL");
		auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
		goto out;
	}

	auth_resp.auth_type = *auth_type;

	if (at_resp->success == TRUE) {
		const char *line;
		int status;

		dbg("RESPONSE OK");
		if (at_resp->lines != NULL) {
			line = at_resp->lines->data;
			dbg("Received data: [%s]", line);
		} else {
			err("at_resp->lines is NULL");
			auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
			goto out;
		}

		tokens = tcore_at_tok_new(line);
		if (tokens == NULL) {
			err("tokens is NULL");
			auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
			goto out;
		}

		status = atoi(g_slist_nth_data(tokens, 0));
		switch (status) {
		case 0:
			dbg("Authentications successful");
			auth_resp.detailed_result = TEL_SIM_AUTH_NO_ERROR;
			break;
		case 1:
			err("Synchronize fail");
			auth_resp.detailed_result = TEL_SIM_AUTH_SYNCH_FAILURE;
			goto out;
		case 2:
			err("MAC wrong");
			auth_resp.detailed_result = TEL_SIM_AUTH_MAK_CODE_FAILURE;
			goto out;
		case 3:
			err("Does not support security context");
			auth_resp.detailed_result = TEL_SIM_AUTH_UNSUPPORTED_CONTEXT;
			goto out;
		default:
			err("Other failure");
			auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
			goto out;
		}

		if (auth_resp.auth_type == TEL_SIM_AUTH_GSM) {
			char *kc, *sres;
			char *convert_kc, *convert_sres;

			kc = g_slist_nth_data(tokens, 1);
			if (kc != NULL) {
				guint convert_kc_len = 0;
				kc = tcore_at_tok_extract(kc);
				dbg("Kc: [%s]", kc);

				tcore_util_hexstring_to_bytes(kc, &convert_kc, &convert_kc_len);
				if (convert_kc_len && convert_kc_len <= TEL_SIM_AUTH_MAX_RESP_DATA_LEN) {
					auth_resp.authentication_key_length = convert_kc_len;
					memcpy(&auth_resp.authentication_key, convert_kc, convert_kc_len);
				} else {
					err("Invalid Kc");
					auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				}
				g_free(kc);
				g_free(convert_kc);
			} else {
				err("Invalid Kc");
				auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				goto out;
			}

			sres = g_slist_nth_data(tokens, 2);
			if (sres != NULL) {
				guint convert_sres_len = 0;
				sres = tcore_at_tok_extract(sres);
				dbg("SRES: [%s]", sres);

				tcore_util_hexstring_to_bytes(sres, &convert_sres, &convert_sres_len);
				if (convert_sres_len && convert_sres_len <= TEL_SIM_AUTH_MAX_RESP_DATA_LEN) {
					auth_resp.resp_length = convert_sres_len;
					memcpy(&auth_resp.resp_data, convert_sres, convert_sres_len);
				} else {
					err("Invalid SRES");
					auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				}
				g_free(sres);
				g_free(convert_sres);
			} else {
				err("Invalid SRES");
				auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				goto out;
			}
		} else if (auth_resp.auth_type == TEL_SIM_AUTH_3G_CTX) {
			char *res, *ck, *ik, *kc;
			char *convert_res, *convert_ck;
			char *convert_ik, *convert_kc;

			res = g_slist_nth_data(tokens, 1);
			if (res != NULL) {
				guint convert_res_len = 0;
				res = tcore_at_tok_extract(res);
				dbg("RES/AUTS: [%s]", res);

				tcore_util_hexstring_to_bytes(res, &convert_res, &convert_res_len);
				if (convert_res_len && convert_res_len <= TEL_SIM_AUTH_MAX_RESP_DATA_LEN) {
					auth_resp.resp_length = convert_res_len;
					memcpy(auth_resp.resp_data, convert_res, convert_res_len);
				} else {
					err("Invalid RES/AUTS");
					auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				}
				g_free(res);
				g_free(convert_res);
			} else {
				err("Invalid RES/AUTS");
				auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				goto out;
			}

			ck = g_slist_nth_data(tokens, 2);
			if (ck != NULL) {
				guint convert_ck_len = 0;
				ck = tcore_at_tok_extract(ck);
				dbg("CK: [%s]", ck);

				tcore_util_hexstring_to_bytes(ck, &convert_ck, &convert_ck_len);
				if (convert_ck_len && convert_ck_len <= TEL_SIM_AUTH_MAX_RESP_DATA_LEN) {
					auth_resp.cipher_length = convert_ck_len;
					memcpy(&auth_resp.cipher_data, convert_ck, convert_ck_len);
				} else {
					err("Invalid CK");
					auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				}
				g_free(ck);
				g_free(convert_ck);
			} else {
				err("Invalid CK");
				auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				goto out;
			}

			ik = g_slist_nth_data(tokens, 3);
			if (ik != NULL) {
				guint convert_ik_len = 0;
				ik = tcore_at_tok_extract(ik);
				dbg("IK: [%s]", ik);

				tcore_util_hexstring_to_bytes(ik, &convert_ik, &convert_ik_len);
				if (convert_ik_len && convert_ik_len <= TEL_SIM_AUTH_MAX_RESP_DATA_LEN) {
					auth_resp.integrity_length = convert_ik_len;
					memcpy(&auth_resp.integrity_data, convert_ik, convert_ik_len);
				} else {
					err("Invalid IK");
					auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				}
				g_free(ik);
				g_free(convert_ik);
			} else {
				err("Invalid IK");
				auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				goto out;
			}

			kc = g_slist_nth_data(tokens, 4);
			if (kc != NULL) {
				guint convert_kc_len = 0;
				kc = tcore_at_tok_extract(kc);
				dbg("Kc: [%s]", kc);

				tcore_util_hexstring_to_bytes(kc, &convert_kc, &convert_kc_len);
				if (convert_kc_len && convert_kc_len <= TEL_SIM_AUTH_MAX_RESP_DATA_LEN) {
					auth_resp.authentication_key_length = convert_kc_len;
					memcpy(&auth_resp.authentication_key, convert_kc, convert_kc_len);
				} else {
					err("Invalid Kc");
					auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				}
				g_free(kc);
				g_free(convert_kc);
			} else {
				err("Invalid Kc");
				auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
				goto out;
			}
		} else {
			err("Not supported");
			auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
			goto out;
		}
		sim_result = TEL_SIM_RESULT_SUCCESS;
	} else {
		err("RESPONSE NOK");
		auth_resp.detailed_result = TEL_SIM_AUTH_CANNOT_PERFORM;
	}

out:
	if(resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)sim_result, &auth_resp, resp_cb_data->cb_data);

	tcore_at_tok_free(tokens);
}

static void on_response_imc_sim_verify_pins(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	ImcSimCurrSecOp *sec_op = NULL;
	TelSimSecPinResult verify_pin_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		dbg("Sim Verify Pin Response- [OK]");

		result = TEL_SIM_RESULT_SUCCESS;

		if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN1_VERIFY) {
			TelSimCardStatus status;

			verify_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN1;

			tcore_sim_get_status(co, &status);
			if (status != TEL_SIM_STATUS_SIM_INIT_COMPLETED) {
				/*Update sim status*/
				__imc_sim_update_sim_status(co,
					TEL_SIM_STATUS_SIM_INITIALIZING);
			}
		} else if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN2_VERIFY) {
			verify_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN2;
		}

		/*Invoke callback*/
		if(resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)result,
					&verify_pin_resp,
					resp_cb_data->cb_data);
		imc_destroy_resp_cb_data(resp_cb_data);
	} else {
		err("Sim Verify Pin Response- [NOK]");
		/* Get retry count */
		__imc_sim_get_retry_count(co, resp_cb_data);
	}
}

static void on_response_imc_sim_verify_puks(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	ImcSimCurrSecOp *sec_op = NULL;
	TelSimSecPukResult verify_puk_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		dbg("Sim Verify Puk Response- [OK]");

		result = TEL_SIM_RESULT_SUCCESS;

		if (*sec_op == IMC_SIM_CURR_SEC_OP_PUK1_VERIFY) {
			verify_puk_resp.puk_type = TEL_SIM_PUK_TYPE_PUK1;
		} else if (*sec_op == IMC_SIM_CURR_SEC_OP_PUK2_VERIFY) {
			verify_puk_resp.puk_type = TEL_SIM_PUK_TYPE_PUK2;
		}
		/*Invoke callback*/
		if(resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)result,
					&verify_puk_resp,
					resp_cb_data->cb_data);
		imc_destroy_resp_cb_data(resp_cb_data);
	} else {
		err("Sim Verify Puk Response- [NOK]");
		/* Get retry count */
		__imc_sim_get_retry_count(co, resp_cb_data);
	}
}

static void on_response_imc_sim_change_pins(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	ImcSimCurrSecOp *sec_op = NULL;
	TelSimSecPinResult change_pin_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		dbg("Sim Change Pin Response- [OK]");

		result = TEL_SIM_RESULT_SUCCESS;

		if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN1_CHANGE) {
			change_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN1;
		} else if (*sec_op == IMC_SIM_CURR_SEC_OP_PIN2_CHANGE) {
			change_pin_resp.pin_type = TEL_SIM_PIN_TYPE_PIN2;
		}
		/*Invoke callback*/
		if(resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)result,
					&change_pin_resp,
					resp_cb_data->cb_data);
		imc_destroy_resp_cb_data(resp_cb_data);
	} else {
		err("Sim Change Pin Response- [NOK]");
		/* Get retry count */
		__imc_sim_get_retry_count(co, resp_cb_data);
	}
}

static void on_response_imc_sim_disable_facility(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	ImcSimCurrSecOp *sec_op = NULL;
	TelSimFacilityResult disable_facility_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		int lock_type;
		dbg("Sim Disable Facility Response- [OK]");

		lock_type = __imc_sim_get_lock_type(*sec_op);
		if (lock_type == -1) {
			result = TEL_SIM_RESULT_INVALID_PARAMETER;

			/*Invoke callback*/
			if(resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)result,
						NULL,
						resp_cb_data->cb_data);
			imc_destroy_resp_cb_data(resp_cb_data);
			return;
		}

		disable_facility_resp.type = lock_type;
		result = TEL_SIM_RESULT_SUCCESS;

		/*Invoke callback*/
		if(resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)result,
					&disable_facility_resp,
					resp_cb_data->cb_data);
		imc_destroy_resp_cb_data(resp_cb_data);
	} else {
		err("Sim Disable Facility Response- [NOK]");
		/* Get retry count */
		__imc_sim_get_retry_count(co, resp_cb_data);
	}
}

static void on_response_imc_sim_enable_facility(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	ImcSimCurrSecOp *sec_op = NULL;
	TelSimFacilityResult enable_facility_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		int lock_type;
		dbg("Sim Enable Facility Response- [OK]");

		lock_type = __imc_sim_get_lock_type(*sec_op);
		if (lock_type == -1) {
			result = TEL_SIM_RESULT_INVALID_PARAMETER;

			/*Invoke callback*/
			if(resp_cb_data->cb)
				resp_cb_data->cb(co, (gint)result,
						NULL,
						resp_cb_data->cb_data);
			imc_destroy_resp_cb_data(resp_cb_data);
			return;
		}

		enable_facility_resp.type = lock_type;
		result = TEL_SIM_RESULT_SUCCESS;

		/*Invoke callback*/
		if(resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)result,
					&enable_facility_resp,
					resp_cb_data->cb_data);
		imc_destroy_resp_cb_data(resp_cb_data);
	} else {
		err("Sim Enable Facility Response- [NOK]");
		/* Get retry count */
		__imc_sim_get_retry_count(co, resp_cb_data);
	}
}

static void on_response_imc_sim_get_facility(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	ImcSimCurrSecOp *sec_op = NULL;
	TelSimFacilityInfo get_facility_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	sec_op = (ImcSimCurrSecOp *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		GSList *tokens = NULL;
		const char *line;
		int lock_type;

		dbg("Sim Get Facility Response- [OK]");

		lock_type = __imc_sim_get_lock_type(*sec_op);
		if (lock_type == -1) {
			result = TEL_SIM_RESULT_INVALID_PARAMETER;
			goto EXIT;
		}
		if (at_resp->lines) {
			line = (const char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				err("Invalid message");
				tcore_at_tok_free(tokens);
				goto EXIT;
			}
			get_facility_resp.f_status = atoi(g_slist_nth_data(tokens, 0));
			get_facility_resp.type = lock_type;
			result = TEL_SIM_RESULT_SUCCESS;
		}

		tcore_at_tok_free(tokens);
	} else {
		err("Sim Get Facility Response- [NOK]");
	}
EXIT:
	/* Invoke callback */
	if(resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &get_facility_resp, resp_cb_data->cb_data);
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sim_get_lock_info(TcorePending *p, guint data_len,
		const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	ImcRespCbData *resp_cb_data = user_data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	TelSimResult result = TEL_SIM_RESULT_FAILURE;
	TelSimLockInfo get_lock_info_resp = {0, };

	dbg("Entry");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if(at_resp && at_resp->success) {
		GSList *tokens = NULL;
		const char *line;
		int lock_type = 0;
		int attempts_left = 0;
		int time_penalty = 0;

		dbg("Sim Get Lock Info Response- [OK]");

		if (at_resp->lines) {
			line = (const char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 3) {
				err("Invalid message");
				tcore_at_tok_free(tokens);
				goto EXIT;
			}

			lock_type = atoi(g_slist_nth_data(tokens, 0));
			attempts_left = atoi(g_slist_nth_data(tokens, 1));
			time_penalty = atoi(g_slist_nth_data(tokens, 2));

			dbg("lock_type = %d, attempts_left = %d, time_penalty = %d",
				lock_type, attempts_left, time_penalty);

			get_lock_info_resp.lock_type = __imc_sim_lock_type(lock_type);
			get_lock_info_resp.retry_count = attempts_left;
			result = TEL_SIM_RESULT_SUCCESS;
		}
		tcore_at_tok_free(tokens);
	} else {
		err("Sim Get Lock Info Response- [NOK]");
	}
EXIT:
	/* Invoke callback */
	if(resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &get_lock_info_resp, resp_cb_data->cb_data);
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sim_req_apdu (TcorePending *p, guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co = NULL;
	TelSimApduResp apdu_resp = {0,};
	TelSimResult sim_result = TEL_SIM_RESULT_FAILURE;
	GSList *tokens = NULL;
	const char *line;
	ImcRespCbData *resp_cb_data = (ImcRespCbData *) user_data;

	dbg("Entry");

	co = tcore_pending_ref_core_object(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			char *tmp = NULL;
			char *decoded_data = NULL;
			guint decoded_data_len = 0;
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 2) {
				err("Invalid message");
				goto OUT;
			}

			tmp = tcore_at_tok_extract(g_slist_nth_data(tokens, 1));
			tcore_util_hexstring_to_bytes(tmp, &decoded_data, &decoded_data_len);

			apdu_resp.apdu_resp_len = decoded_data_len;
			memcpy((char *)apdu_resp.apdu_resp, decoded_data, decoded_data_len);
			g_free(tmp);
			g_free(decoded_data);
			sim_result = TEL_SIM_RESULT_SUCCESS;
		}
	} else {
		err("RESPONSE NOK");
	}

OUT:
	/* Send Response */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)sim_result, &apdu_resp, resp_cb_data->cb_data);
	tcore_at_tok_free(tokens);
	dbg("Exit");
}

static void on_response_imc_sim_req_atr(TcorePending *p, guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *resp = data;
	CoreObject *co = NULL;
	TelSimAtr atr_res = {0,};
	TelSimResult sim_result = TEL_SIM_RESULT_FAILURE;
	GSList *tokens = NULL;
	const char *line;
	ImcRespCbData *resp_cb_data = (ImcRespCbData *) user_data;

	dbg("Entry");

	co = tcore_pending_ref_core_object(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			char *tmp = NULL;
			char *decoded_data = NULL;
			guint decoded_data_len = 0;
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				err("Invalid message");
				goto OUT;
			}

			tmp = tcore_at_tok_extract(g_slist_nth_data(tokens, 0));
			tcore_util_hexstring_to_bytes(tmp, &decoded_data, &decoded_data_len);

			atr_res.atr_len = decoded_data_len;
			memcpy((char *)atr_res.atr, decoded_data, decoded_data_len);
			g_free(tmp);
			g_free(decoded_data);
			sim_result = TEL_SIM_RESULT_SUCCESS;
		}
	} else {
		err("RESPONSE NOK");
	}

OUT:
	/* Send Response */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)sim_result, &atr_res, resp_cb_data->cb_data);
	tcore_at_tok_free(tokens);
	dbg("Exit");
}

/* SIM Operations */
/*
 * Operation - get_imsi
 *
 * Request -
 * AT-Command: AT+CRSM= <command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]
 * where,
 * <command>
 * 176 READ BINARY
 * 178 READ RECORD
 * 192 GET RESPONSE
 * 214 UPDATE BINARY
 * 220 UPDATE RECORD
 * 242 STATUS
 *
 * <fileid>
 * 28423 meaning IMSI file (6F07)
 * 28473 meaning ACM file (6F39)
 * 28481 meaning PUKT file (6F41)
 * 28482 meaning SMS file (6F42)
 *
 * <P1>, <P2>, <P3>
 * Integer type defining the request.
 * These parameters are mandatory for every command, except GET RESPONSE and STATUS.
 *
 * <data>
 * Information which shall be written to the SIM
 *
 * <pathid>
 * String type, contains the path of an elementary file on the SIM/USIM in hexadecimal format
 *
 * <status>
 * 0 not active
 * 1 active
 *
 * Success:
 * 	OK
 * 	+CRSM: <sw1>,<sw2>[,<response>]
 *
 * <sw1>, <sw2>
 * Integer type containing the SIM information
 *
 * <response>
 * Response of successful completion of the command previously issued
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_sim_get_imsi (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_IMSI, ret);

	return ret;
}

static TelReturn imc_sim_get_ecc (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_ECC, ret);

	return ret;
}

static TelReturn imc_sim_get_iccid (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_ICCID, ret);

	return ret;
}

static TelReturn imc_sim_get_language (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_LP, ret);

	return ret;
}

static TelReturn imc_sim_set_language (CoreObject *co,
	TelSimLanguagePreferenceCode language,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcSimMetaInfo file_meta = {0, };
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;
	ImcRespCbData *resp_cb_data = NULL;
	char *tmp = NULL;
	int tmp_len = 0;
	char *encoded_data = NULL;
	int encoded_data_len = 0;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;

	dbg("Entry");

	file_meta.file_id = TEL_SIM_EF_LP;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;

	tcore_sim_get_type(co, &card_type);

	dbg("language[%d], card_type[%d]", language, card_type);

	if (TEL_SIM_CARD_TYPE_GSM == card_type) {
		dbg("2G");
		tcore_sim_encode_lp(language, &tmp, &tmp_len);
	} else if (TEL_SIM_CARD_TYPE_USIM == card_type) {
		dbg("3G");
		tcore_sim_encode_li(language, &tmp, &tmp_len);
	} else {
		err("Invalid card_type:[%d]", card_type);
		return TEL_RETURN_OPERATION_NOT_SUPPORTED;
	}
	if (!tmp_len) {
		err("Failed to encode Language [%d]", language);
		return TEL_RETURN_FAILURE;
	}
	dbg("Encoded Language [%s]", tmp);

	encoded_data_len = 2 * tmp_len;
	encoded_data = (char *)tcore_malloc0(encoded_data_len + 1);
	tcore_util_byte_to_hex(tmp, encoded_data, tmp_len);
	tcore_free(tmp);

	p1 = 0;
	p2 = 0;
	p3 = encoded_data_len;
	dbg("encoded_data - [%s], encoded_data_len - %d", encoded_data, encoded_data_len);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, &file_meta, sizeof(ImcSimMetaInfo));

	return __imc_sim_update_file(co, resp_cb_data, IMC_SIM_ACCESS_UPDATE_BINARY,
					TEL_SIM_EF_LP, p1, p2, p3, encoded_data);
}

static TelReturn imc_sim_get_callforwarding_info (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_USIM_CFIS, ret);

	return ret;
}

static TelReturn imc_sim_get_messagewaiting_info (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_USIM_MWIS, ret);

	return ret;
}

static TelReturn imc_sim_set_messagewaiting_info (CoreObject *co,
	const TelSimMwis *request, TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcSimMetaInfo file_meta = {0, };
	ImcRespCbData *resp_cb_data = NULL;
	gchar *encoded_mwis;
	guint encoded_mwis_len = 0;
	gchar *encoded_data = NULL;
	guint encoded_data_len = 0;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;

	dbg("Entry");

	/*
	 * Videomail is not supported.
	 */
	if (!tcore_sim_encode_mwis(request, TEL_SIM_MAILBOX_TYPE_MAX,
			&encoded_mwis, &encoded_mwis_len)) {
		err("Failed to encode mwis");
		return TEL_RETURN_FAILURE;
	}

	encoded_data_len = 2 * encoded_mwis_len;
	encoded_data = (char *)tcore_malloc0(encoded_data_len + 1);
	tcore_util_byte_to_hex(encoded_mwis, encoded_data, encoded_mwis_len);
	tcore_free(encoded_mwis);
	dbg("Encoded data: [%s] Encoded data length: [%d]", encoded_data, encoded_data_len);

	p1 = 1;
	p2 = 0x04;
	p3 = TEL_SIM_MAILBOX_TYPE_MAX;	/* Indicator Status | Voicemail | Fax | Electronic Mail | Others */
	dbg("p1: [%d] p2: [%d] p3: [%d]", p1, p2, p3);

	file_meta.file_id = TEL_SIM_EF_USIM_MWIS;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, &file_meta, sizeof(ImcSimMetaInfo));

	return __imc_sim_update_file(co, resp_cb_data, IMC_SIM_ACCESS_UPDATE_RECORD,
					TEL_SIM_EF_USIM_MWIS, p1, p2, p3, encoded_data);
}

static TelReturn imc_sim_get_mailbox_info (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_USIM_MBI, ret);

	return ret;
}

static TelReturn imc_sim_set_mailbox_info (CoreObject *co,
	const TelSimMailBoxNumber *request, TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcSimMetaInfo file_meta = {0, };
	ImcRespCbData *resp_cb_data = NULL;
	char *tmp = NULL;
	int tmp_len = 0;
	char *encoded_data = NULL;
	int encoded_data_len = 0;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;

	dbg("Entry");

	file_meta.file_id = TEL_SIM_EF_USIM_MBI;
	file_meta.file_result = TEL_SIM_RESULT_FAILURE;

	/* TBD - Do Encoding.
	if (!tcore_sim_encode_mbi(request, sizeof(request), tmp, &tmp_len)) {
		err("Failed to encode mwis");
		return TEL_RETURN_FAILURE;
	} */

	encoded_data_len = tmp_len * 2;
	encoded_data = (char *)tcore_malloc0(encoded_data_len + 1);
	tcore_util_byte_to_hex(tmp, encoded_data, tmp_len);
	if (!encoded_data) {
		err("Failed to convert byte to hex");
		tcore_free(encoded_data);
		return TEL_RETURN_FAILURE;
	}

	p1 = 1;
	p2 = 0x04;
	p3 = encoded_data_len;
	dbg("encoded_data - [%s], encoded_data_len - %d", encoded_data, encoded_data_len);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, &file_meta, sizeof(ImcSimMetaInfo));

	return __imc_sim_update_file(co, resp_cb_data, IMC_SIM_ACCESS_UPDATE_RECORD,
					TEL_SIM_EF_USIM_MBI, p1, p2, p3, encoded_data);
}

static TelReturn imc_sim_get_msisdn (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_MSISDN, ret);

	return ret;
}

static TelReturn imc_sim_get_spn (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_SPN, ret);

	return ret;
}

static TelReturn imc_sim_get_cphs_netname (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_CPHS_OPERATOR_NAME_STRING, ret);

	return ret;
}

static TelReturn imc_sim_get_sp_display_info (CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret;
	dbg("Entry");

	IMC_SIM_READ_FILE(co, cb, cb_data, TEL_SIM_EF_SPDI, ret);

	return ret;
}

static TelReturn imc_sim_req_authentication (CoreObject *co,
	const TelSimAuthenticationData *request,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *cmd_str = NULL;
	ImcRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_FAILURE;
	TelSimCardType card_type = TEL_SIM_CARD_TYPE_UNKNOWN;
	char *convert_rand = NULL;
	char *convert_autn = NULL;
	int session_id;
	int context_type;

	dbg("Entry");

	tcore_sim_get_type(co, &card_type);
	if (TEL_SIM_CARD_TYPE_GSM == card_type || TEL_SIM_CARD_TYPE_USIM == card_type) {
		session_id = 0;
	} else {
		err("Not Supported SIM type:[%d]", card_type);
		return TEL_SIM_RESULT_OPERATION_NOT_SUPPORTED;
	}

	if (request->rand_data != NULL) {
		convert_rand = tcore_malloc0(request->rand_length*2 + 1);
		tcore_util_byte_to_hex(request->rand_data, convert_rand, request->rand_length);
		dbg("Convert RAND hex to string: [%s]", convert_rand);
	} else {
		err("rand_data is NULL");
		goto EXIT;
	}

	switch (request->auth_type) {
	case TEL_SIM_AUTH_GSM:
		context_type = 2;
		cmd_str = g_strdup_printf("AT+XAUTH=%d,%d,\"%s\"",
			session_id, context_type, convert_rand);
	break;
	case TEL_SIM_AUTH_3G_CTX:
		context_type = 1;
		if (request->autn_data != NULL) {
			convert_autn = tcore_malloc0(request->autn_length*2 + 1);
			tcore_util_byte_to_hex(request->autn_data, convert_autn, request->autn_length);
			dbg("Convert AUTN hex to string: [%s]", convert_autn);
		} else {
			err("autn_data is NULL");
			goto EXIT;
		}
		cmd_str = g_strdup_printf("AT+XAUTH=%d,%d,\"%s\",\"%s\"",
			session_id, context_type, convert_rand, convert_autn);
	break;
	default:
		err("Not supported Authentication type:[%d]", request->auth_type);
		ret = TEL_SIM_RESULT_OPERATION_NOT_SUPPORTED;
		goto EXIT;
	}

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, (void *)&request->auth_type, sizeof(TelSimAuthenticationType));

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+XAUTH:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT, NULL,
						on_response_imc_sim_req_authentication, resp_cb_data,
						on_send_imc_request, NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim request authentication");
EXIT:
	g_free(cmd_str);
	tcore_free(convert_rand);
	tcore_free(convert_autn);
	dbg("Exit");
	return ret;
}

/*
 * Operation - verify_pins/verify_puks
 *
 * Request -
 * For SIM PIN
 * AT-Command: AT+CPIN= <pin> [, <newpin>]
 * where,
 * <pin>, <newpin>
 * String type values
 *
 * For SIM PIN2
 * AT-Command: AT+CPIN2= <puk2/oldpin2> [, <newpin2>]andAT+CPIN2=<oldpin2>
 * where,
 * <puk2/pin2>, <newpin2>
 * String type values
 *
 * Success:
 * 	OK
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_sim_verify_pins(CoreObject *co, const TelSimSecPinPw *request,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcRespCbData *resp_cb_data = NULL;
	ImcSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;

	dbg("Entry");

	if (request->pin_type == TEL_SIM_PIN_TYPE_PIN1) {
		sec_op = IMC_SIM_CURR_SEC_OP_PIN1_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN=\"%s\"", request->pw);
	} else if (request->pin_type == TEL_SIM_PIN_TYPE_PIN2) {
		sec_op = IMC_SIM_CURR_SEC_OP_PIN2_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN2=\"%s\"", request->pw);
	} else {
		err("Invalid pin type [%d]", request->pin_type);
		return TEL_RETURN_INVALID_PARAMETER;
	}

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co, cmd_str, NULL,
						TCORE_AT_COMMAND_TYPE_NO_RESULT,
						TCORE_PENDING_PRIORITY_DEFAULT,
						NULL,
						on_response_imc_sim_verify_pins,
						resp_cb_data,
						on_send_imc_request,
						NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Verify Pins");
	g_free(cmd_str);
	return ret;
}

static TelReturn imc_sim_verify_puks(CoreObject *co, const TelSimSecPukPw *request,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcRespCbData *resp_cb_data = NULL;
	ImcSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;

	dbg("Entry");

	if (request->puk_type == TEL_SIM_PUK_TYPE_PUK1) {
		sec_op = IMC_SIM_CURR_SEC_OP_PUK1_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"",
				request->puk_pw, request->new_pin_pw);
	} else if (request->puk_type == TEL_SIM_PUK_TYPE_PUK2) {
		sec_op = IMC_SIM_CURR_SEC_OP_PUK2_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN2=\"%s\", \"%s\"",
				request->puk_pw, request->new_pin_pw);
	} else {
		err("Invalid puk type [%d]", request->puk_type);
		return TEL_RETURN_INVALID_PARAMETER;
	}

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co, cmd_str, NULL,
						TCORE_AT_COMMAND_TYPE_NO_RESULT,
						TCORE_PENDING_PRIORITY_DEFAULT,
						NULL,
						on_response_imc_sim_verify_puks,
						resp_cb_data,
						on_send_imc_request,
						NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Verify Puks");
	g_free(cmd_str);
	return ret;
}

/*
 * Operation - change_pins
 *
 * Request -
 * AT-Command: AT+CPWD= <fac>,<oldpwd>,<newpwd>
 * where,
 * <fac>
 * SIM facility
 *
 * <oldpwd>
 * Old Password
 *
 * <newpwd>
 * New Password
 *
 * Success:
 * 	OK
 *
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_sim_change_pins(CoreObject *co, const TelSimSecChangePinPw *request,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcRespCbData *resp_cb_data = NULL;
	ImcSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;
	char *pin1_fac = "SC";
	char *pin2_fac = "P2";

	dbg("Entry");

	if (request->pin_type == TEL_SIM_PIN_TYPE_PIN1) {
		sec_op = IMC_SIM_CURR_SEC_OP_PIN1_CHANGE;
		cmd_str = g_strdup_printf("AT+CPWD=\"%s\",\"%s\",\"%s\"",
				pin1_fac, request->old_pw, request->new_pw);
	} else if (request->pin_type == TEL_SIM_PIN_TYPE_PIN2) {
		sec_op = IMC_SIM_CURR_SEC_OP_PIN2_CHANGE;
		cmd_str = g_strdup_printf("AT+CPWD=\"%s\",\"%s\",\"%s\"",
				pin2_fac, request->old_pw, request->new_pw);
	} else {
		err("Invalid pin type [%d]", request->pin_type);
		return TEL_RETURN_INVALID_PARAMETER;
	}

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co, cmd_str, NULL,
						TCORE_AT_COMMAND_TYPE_NO_RESULT,
						TCORE_PENDING_PRIORITY_DEFAULT,
						NULL,
						on_response_imc_sim_change_pins,
						resp_cb_data,
						on_send_imc_request,
						NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Change Pins");
	g_free(cmd_str);
	return ret;
}

/*
 * Operation - disable_facility/enable_facility/get_facility
 *
 * Request -
 * AT-Command: AT+CLCK = <fac>, <mode> [, <passwd> [, <class>]]
 * where,
 * <fac>
 * SIM facility
 *
 * <mode>
 * 0 unlock
 * 1 lock
 * 2 query status
 *
 * <passwd>
 * Password string
 *
 * <status>
 * 0 not active
 * 1 active
 *
 * Success: when <mode>=2:
 * 	OK
 * 	+CLCK: <status>[,<class1> [<CR><LF>
 * 	+CLCK: <status>,<class2> [...]]
 *
 * Failure:
 */
static TelReturn imc_sim_disable_facility(CoreObject *co, const TelSimFacilityPw *request,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcRespCbData *resp_cb_data = NULL;
	ImcSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;
	char *fac = "SC";
	int mode = 0; /*mode = 0 for disable lock*/

	dbg("Entry");

	fac = __imc_sim_get_fac_from_lock_type(request->lock_type,
			&sec_op, DISABLE_FLAG);
	if (!fac)
		return TEL_RETURN_INVALID_PARAMETER;

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"",
			fac, mode, request->pw);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+CLCK:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT,
						NULL,
						on_response_imc_sim_disable_facility,
						resp_cb_data,
						on_send_imc_request,
						NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Disable Facility");
	g_free(cmd_str);
	return ret;
}

static TelReturn imc_sim_enable_facility(CoreObject *co, const TelSimFacilityPw *request,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcRespCbData *resp_cb_data = NULL;
	ImcSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;
	char *fac = "SC";
	int mode = 1; /*mode = 1 for enable lock*/

	dbg("Entry");

	fac = __imc_sim_get_fac_from_lock_type(request->lock_type,
			&sec_op, ENABLE_FLAG);
	if (!fac)
		return TEL_RETURN_INVALID_PARAMETER;

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"",
			fac, mode, request->pw);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
			&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+CLCK:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT,
						NULL,
						on_response_imc_sim_enable_facility,
						resp_cb_data,
						on_send_imc_request,
						NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Disable Facility");
	g_free(cmd_str);
	return ret;
}

static TelReturn imc_sim_get_facility(CoreObject *co, TelSimLockType lock_type,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcRespCbData *resp_cb_data = NULL;
	ImcSimCurrSecOp sec_op;
	gchar *cmd_str = NULL;
	char *fac = "SC";
	int mode = 2; /*mode = 2 for Get Facility*/

	dbg("Entry");

	fac = __imc_sim_get_fac_from_lock_type(lock_type,
			&sec_op, 0);
	if (!fac)
		return TEL_RETURN_INVALID_PARAMETER;

	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d", fac, mode);

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
				&sec_op, sizeof(sec_op));

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+CLCK:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT,
						NULL,
						on_response_imc_sim_get_facility,
						resp_cb_data,
						on_send_imc_request,
						NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Get Facility");
	g_free(cmd_str);
	return ret;
}

static TelReturn imc_sim_get_lock_info(CoreObject *co, TelSimLockType lock_type,
		TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	ImcRespCbData *resp_cb_data = NULL;
	gchar *cmd_str = NULL;
	int lockType = 0;

	dbg("Entry");

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	switch (lock_type) {
	case TEL_SIM_LOCK_PS:
		lockType = 9;
		break;

	case TEL_SIM_LOCK_SC:
		lockType = 1;
		break;

	case TEL_SIM_LOCK_FD:
		lockType = 2;
		break;

	case TEL_SIM_LOCK_PN:
		lockType = 5;
		break;

	case TEL_SIM_LOCK_PU:
		lockType = 6;
		break;

	case TEL_SIM_LOCK_PP:
		lockType = 7;
		break;

	case TEL_SIM_LOCK_PC:
		lockType = 8;
		break;

	default:
		break;
	}

	cmd_str = g_strdup_printf("AT+XPINCNT=%d", lockType);

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+XPINCNT:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT,
						NULL,
						on_response_imc_sim_get_lock_info,
						resp_cb_data,
						on_send_imc_request,
						NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Get Lock Info");
	g_free(cmd_str);
	return ret;
}

static TelReturn imc_sim_req_apdu (CoreObject *co, const TelSimApdu *request, TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *cmd_str = NULL;
	char *apdu = NULL;
	ImcRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry");

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	apdu = (char *)tcore_malloc0((2 * request->apdu_len) + 1);
	tcore_util_byte_to_hex((char *)request->apdu, apdu, request->apdu_len);

	cmd_str = g_strdup_printf("AT+CSIM=%d,\"%s\"", strlen((const char *)apdu), apdu);

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+CSIM:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT, NULL,
						on_response_imc_sim_req_apdu, resp_cb_data,
						on_send_imc_request, NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Request APDU");

	g_free(cmd_str);
	g_free(apdu);

	dbg("Exit");
	return ret;
}

static TelReturn imc_sim_req_atr (CoreObject *co, TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *cmd_str = NULL;
	ImcRespCbData *resp_cb_data = NULL;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("Entry");

	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	cmd_str = g_strdup_printf("AT+XGATR");

	ret = tcore_at_prepare_and_send_request(co, cmd_str, "+XGATR:",
						TCORE_AT_COMMAND_TYPE_SINGLELINE,
						TCORE_PENDING_PRIORITY_DEFAULT, NULL,
						on_response_imc_sim_req_atr, resp_cb_data,
						on_send_imc_request, NULL, 0, NULL, NULL);

	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Sim Request ATR");

	g_free(cmd_str);

	dbg("Exit");
	return ret;
}

/* SIM Operations */
static TcoreSimOps imc_sim_ops = {
	.get_imsi = imc_sim_get_imsi,
	.get_ecc = imc_sim_get_ecc,
	.get_iccid = imc_sim_get_iccid,
	.get_language = imc_sim_get_language,
	.set_language = imc_sim_set_language,
	.get_callforwarding_info = imc_sim_get_callforwarding_info,
	.get_messagewaiting_info = imc_sim_get_messagewaiting_info,
	.set_messagewaiting_info = imc_sim_set_messagewaiting_info,
	.get_mailbox_info = imc_sim_get_mailbox_info,
	.set_mailbox_info = imc_sim_set_mailbox_info,
	.get_msisdn = imc_sim_get_msisdn,
	.get_spn = imc_sim_get_spn,
	.get_cphs_netname = imc_sim_get_cphs_netname,
	.get_sp_display_info = imc_sim_get_sp_display_info,
	.req_authentication = imc_sim_req_authentication,
	.verify_pins = imc_sim_verify_pins,
	.verify_puks = imc_sim_verify_puks,
	.change_pins = imc_sim_change_pins,
	.disable_facility = imc_sim_disable_facility,
	.enable_facility = imc_sim_enable_facility,
	.get_facility = imc_sim_get_facility,
	.get_lock_info = imc_sim_get_lock_info,
	.req_apdu = imc_sim_req_apdu,
	.req_atr = imc_sim_req_atr
};

gboolean imc_sim_init(TcorePlugin *p, CoreObject *co)
{
	ImcSimPrivateInfo *priv_info = NULL;

	dbg("Entry");

	priv_info = g_try_new0(ImcSimPrivateInfo, 1);
	if (priv_info == NULL)
		return FALSE;

	tcore_sim_link_userdata(co, priv_info);

	/* Set operations */
	tcore_sim_set_ops(co, &imc_sim_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co, "+XSIM:",
		on_notification_imc_sim_status, NULL);

	/* Hooks */
	tcore_plugin_add_notification_hook(p,
		TCORE_NOTIFICATION_MODEM_POWER,
		on_hook_imc_modem_power, co);

	dbg("Exit");
	return TRUE;
}

void imc_sim_exit(TcorePlugin *plugin, CoreObject *co)
{
	ImcSimPrivateInfo *priv_info = NULL;

	dbg("Entry");

	priv_info = tcore_sim_ref_userdata(co);
	g_free(priv_info);

	dbg("Exit");
}
