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

#include <co_sms.h>

#include "imc_sms.h"
#include "imc_sim.h"
#include "imc_common.h"

#define CR  '\r'
#define CTRL_Z   '\x1A'

#define AT_MT_UNREAD		0	/* Received and Unread */
#define AT_MT_READ		1	/* Received and Read */
#define AT_MO_UNSENT		2	/* Unsent */
#define AT_MO_SENT		3	/* Sent */
#define AT_ALL			4	/* Unknown */

#define IMC_NUM_PLAN_ID(sca)    (gchar)(sca & 0x0F)
#define IMC_TYPE_OF_NUM(sca)    (gchar)((sca & 0x70) >> 4)

/* SCA 12 bytes long and TDPU is 164 bytes long */
#define PDU_LEN_MAX		176
#define HEX_PDU_LEN_MAX		((PDU_LEN_MAX * 2) + 1)

#define IMC_SIM_TON_INTERNATIONAL	1
#define IMC_SIM_TON_NATIONAL		2

#define IMC_AT_EF_SMS_RECORD_LEN	176

typedef struct {
	guint total_param_count;
	guint count;
	guint index;
	TelSmsParamsInfo *params;
} ImcSmsParamsCbData;

/*
 * Notification - SMS-DELIVER
 * +CMT = [<alpha>],<length><CR><LF><pdu> (PDU mode enabled)
 *
 * where,
 * <alpha> alpha_id
 * <length> length of the PDU
 * <pdu> Incomming SMS PDU
 *
 * Notification - SMS-STATUS-REPORT
 * +CDS: <length><CR><LF><pdu> (PDU mode enabled)
 *
 * where,
 * <length> length of the PDU
 * <pdu> Incomming SMS PDU
 *
 */
static gboolean on_notification_imc_sms_incoming_msg(CoreObject *co,
	const void *event_info, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = NULL;
	char *line = NULL;
	int pdu_len = 0, no_of_tokens = 0;

	TelSmsDatapackageInfo incoming_msg = {{0}, };
	int sca_length = 0;
	gchar *byte_pdu;
	guint byte_pdu_len;
	dbg("Enter");

	lines = (GSList *)event_info;
	if (2 != g_slist_length(lines)) {
		err("Invalid number of lines for +CMT. Must be 2");
		return TRUE;
	}

	line = (char *)g_slist_nth_data(lines, 0); /* Fetch Line 1 */
	if (!line) {
		err("Line 1 is invalid");
		return TRUE;
	}
	dbg("Line 1: [%s]", line);

	/* Split Line 1 into tokens */
	tokens = tcore_at_tok_new(line);
	no_of_tokens = g_slist_length(tokens);

	/*
	 * Incoming SMS: +CMT
	 *		Number of tokens: 2
	 *
	 * Incoming SMS-STATUS-REPORT: +CDS
	 *		Number of tokens: 1
	 */
	if (2 == no_of_tokens) {
		/* Token 0: Alpha ID */
		dbg("Alpha ID: [0x%x]", g_slist_nth_data(tokens, 0));

		/* Token 1: PDU Length */
		pdu_len = atoi((char *)g_slist_nth_data(tokens, 1));
		dbg("pdu_len: [%d]", pdu_len);
	} else if (1 == no_of_tokens) {
		/* Token 0: PDU Length */
		pdu_len = atoi((char *)g_slist_nth_data(tokens, 0));
		dbg("pdu_len: [%d]", pdu_len);
	}
	tcore_at_tok_free(tokens);

	/* Fetch Line 2 */
	line = (char *)g_slist_nth_data(lines, 1);
	if (!line) {
		err("Line 2 is invalid");
		return TRUE;
	}
	dbg("Line 2: [%s]", line);

	/* Convert to Bytes */
	tcore_util_hexstring_to_bytes(line, &byte_pdu, &byte_pdu_len);

	sca_length = byte_pdu[0];
	dbg("SCA length = %d", sca_length);
	if (sca_length) {
		gchar *decoded_sca;
		guint encoded_sca_len;
		/*
		 * byte_pdu[1] - sca_address_type
		 *	Excluding sca_address_type and copy SCA
		 */
		encoded_sca_len = sca_length - 1;
		decoded_sca =
			tcore_util_convert_bcd_to_ascii(&byte_pdu[2], encoded_sca_len, encoded_sca_len*2);
		dbg("Decoded SCA: [%s]", decoded_sca);
		g_strlcpy(incoming_msg.sca.number, decoded_sca, strlen(decoded_sca)+1);
		tcore_free(decoded_sca);

		/*SCA Conversion for Address type*/
		incoming_msg.sca.ton = IMC_TYPE_OF_NUM(byte_pdu[1]);
		incoming_msg.sca.npi = IMC_NUM_PLAN_ID(byte_pdu[1]);
		dbg("TON: [%d] NPI: [%d] SCA: [%s]",
			incoming_msg.sca.ton, incoming_msg.sca.npi,
			incoming_msg.sca.number);
	}
	else {
		dbg("NO SCA Present");
	}

	/* TPDU */
	incoming_msg.tpdu_length = pdu_len;
	memcpy(incoming_msg.tpdu,
		&byte_pdu[sca_length+1], incoming_msg.tpdu_length);

	tcore_util_hex_dump("    ",incoming_msg.tpdu_length, &byte_pdu[sca_length+1]);

	/* Send notification */
	tcore_object_send_notification(co,
		TCORE_NOTIFICATION_SMS_INCOM_MSG,
		sizeof(TelSmsDatapackageInfo), &incoming_msg);

	g_free(byte_pdu);
	return TRUE;
}

/*
 * Notification
 * +CBM: <length><CR><LF><pdu> (PDU mode enabled);
 *
 * where,
 * <length> length of the PDU
 * <pdu> Incomming SMS CB PDU
 *
 */
static gboolean on_notification_imc_sms_cb_incom_msg(CoreObject *co,
	const void *event_info, void *user_data)
{
	char * line = NULL, *pdu = NULL, *line_token = NULL;
	GSList *tokens = NULL;
	unsigned char *byte_pdu = NULL;
	guint byte_pdu_len = 0;
	GSList *lines = NULL;

	TelSmsCbMsgInfo cb_noti = { 0, };
	dbg("Enter");

	lines = (GSList *)event_info;

	line = (char *)(lines->data);/*Fetch Line 1*/
	if (line != NULL) {
		tokens = tcore_at_tok_new(line); /* Split Line 1 into tokens */
		line_token = g_slist_nth_data(tokens, 0);
		if (line_token) {
			cb_noti.length = atoi(line_token);
		} else {
			dbg("token 0 is NULL");
			tcore_at_tok_free(tokens);
			return TRUE;
		}
		pdu = g_slist_nth_data(lines, 1);
		if (pdu != NULL) {
			cb_noti.cb_type = TEL_SMS_CB_MSG_GSM;

			dbg("CB Msg LENGTH [%d]", cb_noti.length);

			if ((cb_noti.length > 0) && (TEL_SMS_CB_DATA_SIZE_MAX >= cb_noti.length)) {
				tcore_util_hexstring_to_bytes(pdu, (gchar **)&byte_pdu, &byte_pdu_len);

				memcpy(cb_noti.cb_data, (char*)byte_pdu, cb_noti.length);
			} else {
				err("Invalid Message Length");
				tcore_at_tok_free(tokens);
				return TRUE;
			}
		} else {
			err("NULL PDU Recieved ");
			tcore_at_tok_free(tokens);
			return TRUE;
		}
		tcore_object_send_notification(co,
				TCORE_NOTIFICATION_SMS_CB_INCOM_MSG, sizeof(TelSmsCbMsgInfo), &cb_noti);
		g_free(byte_pdu);
	} else {
		err("Response NOK");
	}

	tcore_at_tok_free(tokens);
	return TRUE;
}

/*
 * Notification
 * TODO - AT Command Description Not available
 *
 */
static gboolean on_notification_imc_sms_memory_status(CoreObject *co,
	const void *event_info, void *user_data)
{
	gboolean memory_status = TRUE;

	GSList *tokens = NULL;
	GSList *lines = NULL;
	char *line = NULL , *line_token = NULL;
	dbg(" Enter");

	lines = (GSList *)event_info;
	if (1 != g_slist_length(lines)) {
		dbg("Unsolicited msg but multiple line");
		return TRUE;
	}

	line = (char*)(lines->data);
	if (line) {
		tokens = tcore_at_tok_new(line);
		line_token = g_slist_nth_data(tokens, 0);
		if (line_token) {
			/* SIM Full condition */
			if (0 == atoi(line_token))
				memory_status = FALSE;

		/* Send notification */
		tcore_object_send_notification(co,
				TCORE_NOTIFICATION_SMS_MEMORY_STATUS,
				sizeof(gboolean), &memory_status);
		}
		tcore_at_tok_free(tokens);
	} else {
		err("Response NOK");
	}

	return TRUE;
}

static void on_response_imc_class2_sms_incom_msg(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);

	TelSmsDatapackageInfo incoming_msg = { { 0 }, };

	GSList *tokens=NULL;
	char *gslist_line = NULL, *line_token = NULL, *byte_pdu = NULL, *hex_pdu = NULL;
	gint sca_length = 0;
	guint byte_pdu_len = 0;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			/*
			 * TCORE_AT_PDU:
			 *	Multi-line output
			 *
			 * Fetching First Line
			 */
			gslist_line = (char *)at_resp->lines->data;
			dbg("gslist_line: [%s]", gslist_line);

			/*Tokenize*/
			tokens = tcore_at_tok_new(gslist_line);
			dbg("Number of tokens: [%d]", g_slist_length(tokens));

			/* First Token : status
			 * Second Token: Alpha ID - not needed
			 */
			line_token = g_slist_nth_data(tokens, 2); /* Third Token: PDU Length */
			if (line_token != NULL) {
				incoming_msg.tpdu_length = atoi(line_token);
				dbg("Length: [%d]", incoming_msg.tpdu_length);
			}
			else {
				err("Line Token for PDU Length is NULL");
				return;
			}

			/* Fetching line: Second line is PDU */
			hex_pdu = (char *) at_resp->lines->next->data;
			dbg("EF-SMS PDU: [%s]", hex_pdu);

			tcore_at_tok_free(tokens);	/* free the consumed token */
			if (NULL != hex_pdu) {
				tcore_util_hexstring_to_bytes(hex_pdu, &byte_pdu, &byte_pdu_len);

				sca_length = (int)byte_pdu[0];

				dbg("SCA Length [%d], msgLength: [%d]", sca_length, incoming_msg.tpdu_length);

				if (ZERO == sca_length) {
					memcpy(incoming_msg.tpdu, &byte_pdu[1], incoming_msg.tpdu_length);
				}
				else {
					char sca_toa;

					/*
					 * byte_pdu[1] - sca_address_type
					 * Excluding sca_address_type and copy SCA
					 */
					memcpy(incoming_msg.sca.number, &byte_pdu[2], (sca_length-1));

					/*
					 * SCA Conversion: Address Type
					 * 3GPP TS 23.040 V6.5.0 Section: 9.1.2.5
					 */
					sca_toa = byte_pdu[1];
					incoming_msg.sca.npi = IMC_NUM_PLAN_ID(sca_toa);
					incoming_msg.sca.ton = IMC_TYPE_OF_NUM(sca_toa);

					memcpy(incoming_msg.tpdu,
						&byte_pdu[sca_length+1],
						incoming_msg.tpdu_length);
				}
			}

			tcore_object_send_notification(co,
					TCORE_NOTIFICATION_SMS_INCOM_MSG,
					sizeof(TelSmsDatapackageInfo), &incoming_msg);
			tcore_at_tok_free(tokens);
			g_free(byte_pdu);
		}
		else {
			err("Invalid Response Received");
		}
	}
	else {
		err("RESPONSE NOK");
	}
}

/*
 * Notification
 * +CMTI: <mem>,<index>
 *
 * where,
 * <mem> memory location
 * <index> index where msg is stored
 */
static gboolean on_notification_imc_sms_class2_incoming_msg(CoreObject *co, const void *event_info, void *user_data)
{
	gchar *at_cmd;
	TelReturn ret;

	GSList *tokens = NULL , *lines = NULL;
	char *line = NULL;
	gint index, mem_type = 0;
	dbg("Enter");

	lines = (GSList *)event_info;
	line = (char *)g_slist_nth_data(lines, 0); /* Fetch Line 1 */
	if (!line) {
		err("Line 1 is invalid");
		return TRUE;
	}
	dbg("Line 1: [%s]", line);

	tokens = tcore_at_tok_new(line); /* Split Line 1 into tokens */
	mem_type = atoi(g_slist_nth_data(tokens, 0));/* Type of Memory stored */
	dbg("mem_type=[%d]", mem_type);
	index = atoi((char *) g_slist_nth_data(tokens, 1));
	dbg("index: [%d]", index);

	/*
	 * Operation - read_sms_in_sim
	 *
	 * Request -
	 * AT-Command: At+CMGR=<index>
	 *  where
	 * <index> index of the message to be read.
	 *
	 * Response -
	 * Success: (PDU: Multi-line output)
	 * +CMGR: <stat>,[<alpha>],<length><CR><LF><pdu>
	 *
	 * Failure:
	 *	+CMS ERROR: <error>
	 */
	/*AT Command*/
	at_cmd = g_strdup_printf("AT+CMGR=%d", index);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CMGR:",
		TCORE_AT_COMMAND_TYPE_PDU,
		NULL,
		on_response_imc_class2_sms_incom_msg, NULL,
		on_send_imc_request, NULL);
	if (ret != TEL_RETURN_SUCCESS) {
		err("Failed to Read Class2 Incomming Message");
	}
	g_free(at_cmd);
	return TRUE;
}

static void on_response_imc_sms_send_more_msg(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;

	dbg("Enter");

	if (at_resp && at_resp->success)
		dbg("Response OK for AT+CMMS: More msgs to send!!");
	else
		err("Response NOK for AT+CMMS: More msgs to send");

	/* Need not send any response */
}

static void on_response_imc_sms_send_sms(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;/*TODO: CMS error mapping required */
	dbg("Enter");

	tcore_check_return_assert(co != NULL);
	tcore_check_return_assert(resp_cb_data != NULL);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			const gchar *line;
			gchar* line_token;
			GSList *tokens = NULL;
			gint msg_ref = 0;

			line = (const gchar *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL) {
				/*Response from MODEM for send SMS: +CMGS: <mr>[,<ackpdu>]*/
				/*Message Reference is not used by MSG_SERVER and application.So Filling only result*/
				msg_ref = atoi(line_token);

				dbg("Message Reference: [%d]", msg_ref);

				result = TEL_SMS_RESULT_SUCCESS;
			}
			else {
				dbg("No Message Reference received");
			}
			tcore_at_tok_free(tokens);
		}
	}
	else {
		err("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_write_sms_in_sim(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;

	GSList *tokens = NULL;
	char *line = NULL, *line_token = NULL;
	guint index = -1;

	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
		line = (char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token) {
		 		index = (atoi(line_token));
				dbg("SMS written to '%d' index", index);
				result = TEL_SMS_RESULT_SUCCESS;
			}
			else {
				dbg("No Tokens");
				result = TEL_SMS_RESULT_FAILURE;
			}
		}
		else {
			err("Lines NOT present");
		}
	}
	else {
		dbg("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &index, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_read_sms_in_sim(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	TelSmsSimDataInfo read_resp;
	GSList *tokens = NULL;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;/* CMS error mapping required */
	dbg("Enter");

	memset(&read_resp, 0x0, sizeof(TelSmsSimDataInfo));

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			char *gslist_line = NULL,*line_token = NULL,*byte_pdu = NULL,*hex_pdu = NULL;
			gint msg_status = 0, pdu_len = 0, alpha_id = 0;

			/*
			 * TCORE_AT_PDU:
			 *	Multi-line output
			 *
			 * Fetching First Line
			 */
			gslist_line = (char *)at_resp->lines->data;
			dbg("gslist_line: [%s]", gslist_line);

			/*Tokenize*/
			tokens = tcore_at_tok_new(gslist_line);
			dbg("Number of tokens: [%d]", g_slist_length(tokens));

			/*+CMGR: <stat>,[<alpha>],<length><CR><LF><pdu>*/
			line_token = g_slist_nth_data(tokens, 0);	/*First Token: Message status*/
			if (line_token == NULL) {
				err("Invalid stat");
				goto OUT;
			}

			msg_status = atoi(line_token);
			dbg("msg_status is %d",msg_status);

			switch (msg_status) {
			case AT_MT_UNREAD:
				read_resp.status = TEL_SMS_STATUS_MT_UNREAD;
			break;
			case AT_MT_READ:
				read_resp.status = TEL_SMS_STATUS_MT_READ;
			break;
			case AT_MO_UNSENT:
				read_resp.status = TEL_SMS_STATUS_MO_NOT_SENT;
			break;
			case AT_MO_SENT:
				read_resp.status = TEL_SMS_STATUS_MO_SENT;
			break;
			case AT_ALL:
			default:
				read_resp.status = TEL_SMS_STATUS_REPLACED;
			break;
			}

			 /*Second Token: Alpha ID*/
			line_token = g_slist_nth_data(tokens, 1);
			if (line_token != NULL) {
				alpha_id = atoi(line_token);
				dbg("alpha_id: [%d]", alpha_id);
			}

			/*Third Token: Length*/
			line_token = g_slist_nth_data(tokens, 2);
			if (line_token == NULL) {
				err("Invalid PDU length");
				goto OUT;
			}
			pdu_len = atoi(line_token);
			dbg("PDU length: [%d]", pdu_len);

			/*Fetching line: Second line is PDU*/
			hex_pdu = (char *) at_resp->lines->next->data;
			dbg("EF-SMS PDU: [%s]", hex_pdu);

			if (NULL != hex_pdu) {
				gint sca_length = 0;
				guint byte_pdu_len = 0;

				tcore_util_hex_dump("    ", sizeof(hex_pdu), (void *)hex_pdu);

				tcore_util_hexstring_to_bytes(hex_pdu, &byte_pdu, &byte_pdu_len);

				sca_length = byte_pdu[0];
				dbg("SCA length = %d", sca_length);
				if (sca_length) {
					gchar *decoded_sca;
					guint encoded_sca_len;

					/*
					 * byte_pdu[1] - sca_address_type
					 *	Excluding sca_address_type and copy SCA
					 */
					encoded_sca_len = sca_length - 1;
					decoded_sca =
						tcore_util_convert_bcd_to_ascii(&byte_pdu[2],
							encoded_sca_len, encoded_sca_len*2);

					dbg("Decoded SCA: [%s]", decoded_sca);
					memcpy(read_resp.data.sca.number, decoded_sca, TEL_SMS_SCA_LEN_MAX);
					tcore_free(decoded_sca);

					/*SCA Conversion for Address type*/
					read_resp.data.sca.ton = IMC_TYPE_OF_NUM(byte_pdu[1]);
					read_resp.data.sca.npi = IMC_NUM_PLAN_ID(byte_pdu[1]);
					dbg("TON: [%d] NPI: [%d] SCA: [%s]",
						read_resp.data.sca.ton, read_resp.data.sca.npi,
						read_resp.data.sca.number);
				} else {
					err("NO SCA Present");
				}

				/* TPDU */
				read_resp.data.tpdu_length  = pdu_len;
				if ((read_resp.data.tpdu_length > 0)
					&& (read_resp.data.tpdu_length <= TEL_SMS_SMDATA_SIZE_MAX)) {
						memcpy(read_resp.data.tpdu, &byte_pdu[sca_length+1],
							read_resp.data.tpdu_length);
				} else {
					warn("Invalid TPDU length: [%d]", read_resp.data.tpdu_length);
				}

				result = TEL_SMS_RESULT_SUCCESS;
				g_free(byte_pdu);
			}
		} else {
			err("Invalid Response Received");
		}
	}
	else {
		err("RESPONSE NOK");
	}
OUT:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &read_resp, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);

	/*free the consumed token*/
	tcore_at_tok_free(tokens);
}

static void on_response_imc_sms_delete_sms_in_sim(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	tcore_check_return_assert(co != NULL);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		result = TEL_SMS_RESULT_SUCCESS;
	}
	else {
		dbg("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_get_msg_indices(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	TelSmsStoredMsgCountInfo *count_info;/*Response from get_count Request*/
	TelSmsResult result = TEL_SMS_RESULT_FAILURE;/*TODO: CMS error mapping required */

	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	dbg("Enter");

	count_info = (TelSmsStoredMsgCountInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			char *gslist_line = NULL;
			gint gslist_line_count = 0, ctr_loop = 0;

			gslist_line_count = g_slist_length(at_resp->lines);

			if (gslist_line_count > TEL_SMS_GSM_MSG_NUM_MAX)
				gslist_line_count = TEL_SMS_GSM_MSG_NUM_MAX;
			dbg("Number of lines: [%d]", gslist_line_count);

			for (ctr_loop = 0; ctr_loop < gslist_line_count; ctr_loop++) {
				/* Fetch Line 'ctr_loop' */
				gslist_line = (char *)g_slist_nth_data(at_resp->lines, ctr_loop);
				dbg("gslist_line [%d] is [%s]", ctr_loop, gslist_line);

				if (NULL != gslist_line) {
					GSList *tokens = NULL;
					char *line_token = NULL;

					tokens = tcore_at_tok_new(gslist_line);

					line_token = g_slist_nth_data(tokens, 0);
					if (NULL != line_token) {
					        count_info->index_list[ctr_loop] = atoi(line_token);
					}
					else {
					        dbg("line_token of gslist_line [%d] is NULL", ctr_loop);
					}

					tcore_at_tok_free(tokens);
				}
				else {
					err("gslist_line is NULL");
					goto ERROR;
				}
			}

			result = TEL_SMS_RESULT_SUCCESS;
		}
		else {
			err("Invalid Response received. No Lines present in Response");

			/* Check if used count is zero*/
			if (count_info->used_count == 0)
			        result = TEL_SMS_RESULT_SUCCESS;
		}
	}
	else {
		err("RESPONSE NOK");
	}

ERROR:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, count_info, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_get_sms_count(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	gchar *at_cmd;
	TelReturn ret;

	TelSmsStoredMsgCountInfo count_info = {0, };
	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	int used_count = 0, total_count = 0;

	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	ImcRespCbData *getcnt_resp_cb_data;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			GSList *tokens = NULL;
			char *line = NULL, *line_token = NULL;

			line = (char *)at_resp->lines->data;
			dbg("line: [%s]",line);

			/*
			 * Tokenize
			 *
			 * +CPMS: <used1>, <total1>, <used2>, <total2>, <used3>, <total3>
			 */
			tokens = tcore_at_tok_new(line);

			/* <used1> */
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token) {
				used_count =atoi(line_token);
				dbg("used cnt is %d",used_count);
			}
			else {
				err("Line Token for used count is NULL");
				tcore_at_tok_free(tokens);
				goto ERROR;
			}

			/* <total1> */
			line_token = g_slist_nth_data(tokens, 1);
			if (line_token) {
				total_count = atoi(line_token);

				count_info.total_count = total_count;
				count_info.used_count = used_count;
				dbg("Count - used: [%d] total: [%d]", used_count, total_count);

				/*
				* Operation - get_msg_indices_in_sim
				*
				* Request -
				* AT-Command: AT+CMGL
				*      +CPMS=<mem1>[, <mem2>[,<mem3>]]
				*  where
				* <mem1> memory storage to read.
				*
				* Response -
				* Success: (Multi-line output)
				* +CMGL=<stat>]
				*
				* <stat> status of the message.
				* Failure:
				*      +CMS ERROR: <error>
				*/

				/* Sending the Second AT Request to fetch msg indices */
				at_cmd = g_strdup_printf("AT+CMGL=4");

				/* Response callback data */
				getcnt_resp_cb_data = imc_create_resp_cb_data(resp_cb_data->cb,
						resp_cb_data->cb_data,
						&count_info, sizeof(TelSmsStoredMsgCountInfo));

				/* Free previous request callback data */
				imc_destroy_resp_cb_data(resp_cb_data);

				/* Send Request to modem */
				ret = tcore_at_prepare_and_send_request(co,
					at_cmd, "+CMGL",
					TCORE_AT_COMMAND_TYPE_MULTILINE,
					NULL,
					on_response_imc_sms_get_msg_indices, getcnt_resp_cb_data,
					on_send_imc_request, NULL);

				/* free the consumed token */
				tcore_at_tok_free(tokens);
				g_free(at_cmd);

				IMC_CHECK_REQUEST_RET(ret, getcnt_resp_cb_data, "Get Indices in SIM");
				if (ret != TEL_RETURN_SUCCESS) {
					err("Failed to Process Get Msg Indices Request");
					goto ERROR;
				}

				dbg("Exit");
				return;
			}
			else {
				err("Line Token for Total count is NULL");

				/* free the consumed token */
				tcore_at_tok_free(tokens);
				goto ERROR;
			}
		}
		else {
			err("Invalid Response Received: NO Lines Present");
		}
	}
	else {
		err("RESPONSE NOK");
	}

ERROR:
	/* Invoke callback in case of error*/
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_set_sca(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		result = TEL_SMS_RESULT_SUCCESS;
	}
	else {
		err("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_get_sca(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsSca sca_resp = { 0, };
	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			GSList *tokens = NULL;
			const char *sca_tok_addr;
			gchar *line = NULL, *sca_addr = NULL, *sca_toa = NULL;

			line = (char *)at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			sca_tok_addr = g_slist_nth_data(tokens, 0);
			sca_toa = g_slist_nth_data(tokens, 1);

			sca_addr = tcore_at_tok_extract(sca_tok_addr);
			dbg("SCA: [%s] SCA-TOA: [%s]", sca_addr, sca_toa);
			if ((NULL != sca_addr) && (NULL != sca_toa)) {
				memcpy(sca_resp.number, sca_addr, strlen(sca_addr));

				/* Type-of-Address */
				if (145 == atoi(sca_toa)) {
					sca_resp.ton = IMC_SIM_TON_INTERNATIONAL;
				}
				else {
					sca_resp.ton = IMC_SIM_TON_NATIONAL;
				}
				sca_resp.npi = 0;/* TODO */
				result = TEL_SMS_RESULT_SUCCESS;
			}
			else {
				err("SCA is NULL");
			}
			tcore_at_tok_free(tokens);
			g_free(sca_addr);
		}
		else {
			err("Invalid Response.No Lines Received");
		}
	}
	else {
		err("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &sca_resp, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_set_cb_config(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;/*TODO: CME error mapping required */
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		result = TEL_SMS_RESULT_SUCCESS;
	}
	else {
		err("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_get_cb_config(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	GSList *cb_tokens = NULL;
	char *cb_str_token = NULL;
	int num_cb_tokens = 0;
	char *mid_tok = NULL;
	char *first_tok = NULL, *second_tok = NULL;
	gint i = 0, mode = 0;
	char delim[] = "-";

	TelSmsCbConfigInfo get_cb_conf = {0, };
	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			GSList *tokens = NULL;
			char *line_token = NULL, *line = NULL;
			line = (char*)at_resp->lines->data;
			if (line != NULL) {
				tokens = tcore_at_tok_new(line);
				/*
				 * Response -
				 *	+CSCB: <mode>,<mids>,<dcss>
				 */
				 line_token = g_slist_nth_data(tokens, 0);
				if (line_token) {
					mode = atoi(line_token);
					dbg("mode:[%d]", mode);
					get_cb_conf.cb_enabled = mode;
				}
				else {
					err("Line Token for Mode is NULL");
					tcore_at_tok_free(tokens);
					goto OUT;
				}
				line_token = g_slist_nth_data(tokens, 1);
				if (line_token) {
					cb_str_token = tcore_at_tok_extract(line_token);
					cb_tokens = tcore_at_tok_new((const char *)cb_str_token);

					num_cb_tokens = g_slist_length(cb_tokens);
					dbg("num_cb_tokens = %d", num_cb_tokens);
					if (num_cb_tokens == 0) {
						if (mode == 1) {	/* All CBS Enabled */
							get_cb_conf.msg_id_range_cnt = 1;
							get_cb_conf.msg_ids[0].from_msg_id = 0x0000;
							get_cb_conf.msg_ids[0].to_msg_id = TEL_SMS_GSM_CBMI_LIST_SIZE_MAX + 1;
							get_cb_conf.msg_ids[0].selected = TRUE;
						}
						else {	/* All CBS Disabled */
							get_cb_conf.msg_id_range_cnt = 0;
							get_cb_conf.msg_ids[0].selected = FALSE;
						}
					}

					for(i = 0; i < num_cb_tokens; i++) {
						get_cb_conf.msg_ids[i].selected = TRUE;
						dbg("msgIdRangeCount:[%d]", get_cb_conf.msg_id_range_cnt);
						get_cb_conf.msg_id_range_cnt++;
						dbg("Incremented msgIdRangeCount:[%d]", get_cb_conf.msg_id_range_cnt);

						mid_tok = tcore_at_tok_nth(cb_tokens, i);
						first_tok = strtok(mid_tok, delim);
						second_tok = strtok(NULL, delim);

						if ((first_tok != NULL) && (second_tok != NULL)) {/* mids in range (320-478) */
							get_cb_conf.msg_ids[i].from_msg_id = atoi(first_tok);
							get_cb_conf.msg_ids[i].to_msg_id = atoi(second_tok);
						}
						else {/* single mid value (0,1,5, 922)*/
							get_cb_conf.msg_ids[i].from_msg_id = atoi(mid_tok);
							get_cb_conf.msg_ids[i].to_msg_id = atoi(mid_tok);
						}
					}
				}
				else {
					err("Line Token for MID is NULL");
					tcore_at_tok_free(tokens);
					goto OUT;
				}
			}
			else {
				err("Line is NULL");
			}
			result = TEL_SMS_RESULT_SUCCESS;
			tcore_at_tok_free(tokens);
			tcore_at_tok_free(cb_tokens);
			g_free(cb_str_token);
		}
		else {
			err("Invalid Response.No Lines Received");
		}
	}
	else {
		err("Response NOK");
	}

OUT:
	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, &get_cb_conf, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_set_memory_status(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		result = TEL_SMS_RESULT_SUCCESS;
	}
	else {
		err("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_set_message_status(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	int response = 0, sw1 = 0, sw2 = 0;
	const char *line = NULL;
	char *line_token = NULL;
	GSList *tokens = NULL;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);
			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL) {
				sw1 = atoi(line_token);
			}
			else {
				dbg("sw1 is NULL");
			}
			line_token = g_slist_nth_data(tokens, 1);
			if (line_token != NULL) {
				sw2 = atoi(line_token);
				if ((sw1 == 0x90) && (sw2 == 0)) {
					result = TEL_SMS_RESULT_SUCCESS;
				}
			}
			else {
				dbg("sw2 is NULL");
			}
			line_token = g_slist_nth_data(tokens, 3);

			if (line_token != NULL) {
				response = atoi(line_token);
				dbg("response is %s", response);
			}
			tcore_at_tok_free(tokens);
		}
		else {
			dbg("No lines");
		}
	}
	else {
			err("RESPONSE NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void _response_get_efsms_data(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	gchar *at_cmd;
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsStatusInfo *status_info;
	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	TelReturn ret;

	char *encoded_data = NULL;
	int encoded_len = 0;
	char msg_status = 0;
	char *line_token = NULL;
	GSList *tokens=NULL;
	const char *line = NULL;
	int sw1 = 0;
	int sw2 = 0;
	dbg("Enter");

	status_info = (TelSmsStatusInfo *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);
	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			dbg("Entry:lines Ok");
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);

			sw1 = atoi(g_slist_nth_data(tokens, 0));
			sw2 = atoi(g_slist_nth_data(tokens, 1));
			line_token = g_slist_nth_data(tokens, 2);

			dbg("line_token:[%s], Length of line token:[%d]", line_token, strlen(line_token));

			if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
				switch (status_info->status) {
				case TEL_SMS_STATUS_MT_READ:
					msg_status = 0x01;
				break;

				case TEL_SMS_STATUS_MT_UNREAD:
					msg_status = 0x03;
				break;

				case TEL_SMS_STATUS_MO_NOT_SENT:
					msg_status = 0x07;
				break;

				case TEL_SMS_STATUS_MO_SENT:
					msg_status = 0x05;
				break;

				case TEL_SMS_STATUS_MO_DELIVERED:
					msg_status = 0x1D;
				break;

				case TEL_SMS_STATUS_MO_DELIVERY_NOT_CONFIRMED:
					msg_status = 0xD;
				break;

				case TEL_SMS_STATUS_REPLACED:/*Fall Through*/
				default:
					msg_status = 0x03;
				break;
				}
			}
			encoded_len = strlen(line_token);
			dbg("Encoded data length:[%d]", encoded_len);

			encoded_data = tcore_malloc0(2*encoded_len + 1);

			memcpy(encoded_data, line_token, encoded_len);
			dbg("encoded_data: [%s]", encoded_data);

			/* overwrite Status byte information */
			tcore_util_byte_to_hex((const char *)&msg_status, encoded_data, 1);

			/*
			 * Updating EF-SMS File with status byte
			 * Rest 175 bytes are same as received in Read Record
			 *
			 */
			at_cmd = g_strdup_printf("AT+CRSM=220,28476,%d, 4, %d, \"%s\"",
				(status_info->index), IMC_AT_EF_SMS_RECORD_LEN, encoded_data);

			/* Send Request to modem */
			ret = tcore_at_prepare_and_send_request(co,
				at_cmd, "+CRSM:",
				TCORE_AT_COMMAND_TYPE_SINGLELINE,
				NULL,
				on_response_imc_sms_set_message_status, resp_cb_data,
				on_send_imc_request, NULL);
			IMC_CHECK_REQUEST_RET(ret, resp_cb_data,
				"Set Message Status-Updating status in Record");

			g_free(encoded_data);
			g_free(status_info);
			tcore_at_tok_free(tokens);
			return;
		}
		else {
			err("Invalid Response Received");
		}
	}
	else {
		err("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_get_sms_params(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;
	ImcSmsParamsCbData *params_req_data;
	gint sw1 = 0, sw2 = 0, decoding_length = 0;
	const char *line = NULL;
	char *hex_data = NULL, *record_data = NULL;
	GSList *tokens = NULL;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	dbg("Enter");

	params_req_data = (ImcSmsParamsCbData *)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data);

	if (at_resp && at_resp->success) {
		dbg("RESPONSE OK");
		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);

			sw1 = atoi(g_slist_nth_data(tokens, 0));
			sw2 = atoi(g_slist_nth_data(tokens, 1));
			dbg("sw1 [0x%x], sw2[0x%x]", sw1, sw2);

			if (!(sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
				err("invalid response received");
				goto OUT;
			}

			hex_data = g_slist_nth_data(tokens, 2);
			if (hex_data == NULL) {
				err("invalid response received");
				goto OUT;
			}

			tcore_util_hexstring_to_bytes(hex_data, &record_data, (guint*)&decoding_length);
			/*
			* Decrementing the Record Count and Filling the ParamsInfo List
			* Final Response will be posted when Record count is ZERO
			*/
			params_req_data->params[params_req_data->index].index = params_req_data->index;

			tcore_util_decode_sms_parameters((unsigned char *)record_data,
				decoding_length,
				&params_req_data->params[params_req_data->index]);

			params_req_data->total_param_count -= 1;

			if (params_req_data->total_param_count == 0) {
				dbg("Reading all Records - Complete");
				result = TEL_SMS_RESULT_SUCCESS;
				goto OUT;
			} else {
				dbg("Reading all records incomplete [%d - Pending]",
					params_req_data->total_param_count);
				tcore_at_tok_free(tokens);
				return;
			}
		} else {
			err("Invalid Response Received");
		}
	} else {
		err("RESPONSE NOK");
	}

OUT:
	{
		TelSmsParamsInfoList param_info_list = {0, };

		if (result == TEL_SMS_RESULT_SUCCESS) {
			param_info_list.params = params_req_data->params;
			param_info_list.count = params_req_data->count;
		}

		/* Invoke callback */
		if (resp_cb_data->cb)
			resp_cb_data->cb(co, (gint)result, (void *)&param_info_list, resp_cb_data->cb_data);
	}

	/* Free resource */
	tcore_at_tok_free(tokens);

	tcore_free(params_req_data->params);
	g_free(record_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static void on_response_imc_sms_set_sms_params(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co = tcore_pending_ref_core_object(p);
	ImcRespCbData *resp_cb_data = user_data;

	TelSmsResult result = TEL_SMS_RESULT_FAILURE;
	gint sw1 = 0 , sw2 = 0;
	const char *line = NULL;
	GSList *tokens=NULL;
	dbg("Enter");

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			line = (const char *) at_resp->lines->data;
			tokens = tcore_at_tok_new(line);

			sw1 = atoi(g_slist_nth_data(tokens, 0));
			sw2 = atoi(g_slist_nth_data(tokens, 1));

			if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
				result = TEL_SMS_RESULT_SUCCESS;
			}
			else {
				result = TEL_SMS_RESULT_FAILURE;
			}
		}
		tcore_at_tok_free(tokens);
	} else {
		err("Response NOK");
	}

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);
}

static gboolean async_callback(gpointer data)
{
	ImcRespCbData *resp_cb_data = data;
	CoreObject **co;
	TelSmsResult result = TEL_SMS_RESULT_SUCCESS;

	co = ((CoreObject **)IMC_GET_DATA_FROM_RESP_CB_DATA(resp_cb_data));

	/* Invoke callback */
	if (resp_cb_data->cb)
		resp_cb_data->cb(*co, (gint)result, NULL, resp_cb_data->cb_data);

	/* Free callback data */
	imc_destroy_resp_cb_data(resp_cb_data);

	return FALSE;
}

/* SMS Operations */
/*
 * Operation - send_sms
 *
 * Request -
 * AT-Command: AT+CMGS
 * 	For PDU mode (+CMGF=0):
 * 	+CMGS=<length><CR>
 * 	PDU is given<ctrl-Z/ESC>
 * where,
 * <length> Length of the pdu.
 * <PDU>    PDU to send.
 *
 * Response -
 *+CMGS: <mr>[,<ackpdu>]
 *	OK
 * Failure:
 *	+CMS ERROR: <error>
 */
static TelReturn imc_sms_send_sms(CoreObject *co,
	const TelSmsSendInfo *send_info, TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	const unsigned char *tpdu_byte_data;
	gint tpdu_byte_len, pdu_byte_len;
	char buf[HEX_PDU_LEN_MAX];
	char pdu[PDU_LEN_MAX];
	dbg("Enter");

	tpdu_byte_data = send_info->send_data.tpdu;

	/* TPDU length is in byte */
	tpdu_byte_len = send_info->send_data.tpdu_length;

	/* Use same Radio Resource Channel :More Messages to send*/
	dbg("More messages: [%d]", send_info->more_msgs);

	/* Prepare PDU for hex encoding */
	pdu_byte_len = tcore_util_encode_pdu(&(send_info->send_data.sca),
				tpdu_byte_data, tpdu_byte_len, pdu);
	tcore_util_hex_dump("    ", pdu_byte_len, pdu);

	tcore_util_encode_hex((unsigned char *)pdu, pdu_byte_len, buf);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	if (send_info->more_msgs == TRUE) {
		/* AT Command: More Msgs to Send */
		ret = tcore_at_prepare_and_send_request(co,
			"AT+CMMS=1", "+CMMS:",
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			NULL,
			on_response_imc_sms_send_more_msg, NULL,
			on_send_imc_request, NULL);
		IMC_CHECK_REQUEST_RET(ret, NULL, "More Msgs to Send");
	}

	/* AT-Command : Send SMS*/
	at_cmd = g_strdup_printf("AT+CMGS=%d\r%s\x1A", tpdu_byte_len, buf);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CMGS:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sms_send_sms, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Send SMS");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - write_sms_in_sim
 *
 * Request -
 * AT-Command: AT+CMGW
 * 	AT+CMGW = <length>[,<stat>]<CR>PDU is given<ctrl-Z/ESC>
 * where
 *	<length> 	length of the tpdu
 * 	<stat>	status of the message
 *	<PDU>	PDu of the message
 *
 * Response -
 *	+CMGW: <index>
 * Success: (Single line)
 *	OK
 * Failure:
 *	+CMS ERROR: <error>
 */
static TelReturn imc_sms_write_sms_in_sim(CoreObject *co,
	const TelSmsSimDataInfo *wdata, TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	const unsigned char *tpdu_byte_data;
	int tpdu_byte_len, pdu_byte_len;
	char buf[HEX_PDU_LEN_MAX];
	char hex_pdu[PDU_LEN_MAX];
	gint status = 0;
	dbg("Enter");

	switch (wdata->status) {
	case TEL_SMS_STATUS_MT_UNREAD:
		status = AT_MT_UNREAD;
	break;

	case TEL_SMS_STATUS_MT_READ:
		status = AT_MT_READ;
	break;

	case TEL_SMS_STATUS_MO_NOT_SENT:
		status = AT_MO_UNSENT;
	break;

	case TEL_SMS_STATUS_MO_SENT:
		status = AT_MO_SENT;
	break;

	default:
		err("Invalid Message Status");
		return TEL_RETURN_INVALID_PARAMETER;
	}
	tpdu_byte_data = wdata->data.tpdu;

	tpdu_byte_len = wdata->data.tpdu_length;
	dbg("TDPU length: [%d]", tpdu_byte_len);

	/* Prepare PDU for hex encoding */
	pdu_byte_len = tcore_util_encode_pdu(&(wdata->data.sca),
				tpdu_byte_data, tpdu_byte_len, hex_pdu);
	tcore_util_hex_dump("    ", pdu_byte_len, hex_pdu);

	tcore_util_encode_hex((unsigned char *)hex_pdu, pdu_byte_len, buf);

	/*AT Command*/
	at_cmd = g_strdup_printf("AT+CMGW=%d,%d%c%s%c",
			tpdu_byte_len, status, CR, buf, CTRL_Z);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CMGW:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sms_write_sms_in_sim, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Write SMS in SIM");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - read_sms_in_sim
 *
 * Request -
 * AT-Command: At+CMGR=<index>
 *  where
 * <index> index of the message to be read.
 *
 * Response -
 * Success: (PDU: Multi-line output)
 * +CMGR: <stat>,[<alpha>],<length><CR><LF><pdu>
 *
 * Failure:
 *	+CMS ERROR: <error>
 */
static TelReturn imc_sms_read_sms_in_sim(CoreObject *co,
	unsigned int index, TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/* AT+Command */
	at_cmd = g_strdup_printf("AT+CMGR=%d", index);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, ZERO);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CMGR:",
		TCORE_AT_COMMAND_TYPE_PDU,
		NULL,
		on_response_imc_sms_read_sms_in_sim, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Read SMS in SIM");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - delete_sms_in_sim
 *
 * Request -
 * AT-Command: AT+CGMD
 * 	+CMGD=<index>[,<delflag>]
 *
 * Response -
 * Success: (NO RESULT) -
 *	OK
 * Failure:
 *	+CMS ERROR: <error>
 */
static TelReturn imc_sms_delete_sms_in_sim(CoreObject *co,
	unsigned int index,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);
	/*
	 * TODO: Delete All Messages
	 *
	 * at_cmd = g_strdup_printf("AT+CMGD=0,4");
	 * Need to convey MSG_SERVICE to pass an index of
	 * guint value to delete all Messages.probably as 0.
	 */

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CMGD=%d,0", index); /*Delete specified index*/

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CMGD:",
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_sms_delete_sms_in_sim, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Delete SMS in SIM");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get_sms_count_in_sim
 *
 * Request -
 * AT-Command: AT+CPMS
 *      +CPMS=<mem1>[, <mem2>[,<mem3>]]
 *  where
 * <mem1> memory storage to read.
 *
 * Response -
 * Success: (Single-line output)
 * +CPMS: <mem1>,<used1>,<total1>,<mem2>,<used2>,<total2>,
 * <mem3>,<used3>,<total3>
 * OK
 *
 * Failure:
 *      +CMS ERROR: <error>
 */
static TelReturn imc_sms_get_msg_count_in_sim(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/*AT Command*/
	at_cmd = g_strdup_printf("AT+CPMS=\"SM\"");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CPMS",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sms_get_sms_count, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SMS Count");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - set SCA
 *
 * Request -
 * AT-Command: AT+CSCA
 * 	AT+CSCA=<sca>[,<tosca>]
 * where
 * <sca> Service center number
 * <tosca> address type of SCA
 *
 * Response -
 * Success: No result
 * 	OK
 *
 * Failure:
 *      +CMS ERROR: <error>
 */
 static TelReturn imc_sms_set_sca(CoreObject *co,
	const TelSmsSca *sca, TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	gint address_type;

	address_type = ((sca->ton << 4) | sca->npi ) | 0x80;

	/* AT Command */
	at_cmd = g_strdup_printf("AT+CSCA=\"%s\",%d", sca->number, address_type);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_sms_set_sca, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set SCA");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get SCA
 *
 * Request -
 * AT-Command: AT+CSCA?
 *
 * Response -
 * 	Success: Single-Line
 * 	+CSCA: <sca>,<tosca>
 * 	OK
 * where
 * <sca> Service center number
 * <tosca> address type of SCA
 *
 */
 static TelReturn imc_sms_get_sca(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/* AT Command */
	at_cmd = g_strdup_printf("AT+CSCA?");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CSCA",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sms_get_sca, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SCA");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - set_cb_config
 *
 * Request -
 * AT-Command: AT+CSCB
 *      +CSCB=[<mode>[,<mids>[,<dcss>]]]
 *
 * Response -
 * Success
 * OK
 *
 * Failure:
 *      +CME ERROR: <error>
 */
static TelReturn imc_sms_set_cb_config(CoreObject *co,
	const TelSmsCbConfigInfo *cb_conf,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	unsigned short ctr1 = 0, ctr2 = 0, msg_id_range = 0;
	unsigned short append_msg_id = 0;
	dbg("Enter");

	if (cb_conf->msg_id_range_cnt != 0) {	/* Enable Specific Msgid's */
		gchar *mids_str = NULL;
		GString *mid_string = NULL;
		at_cmd = NULL;

		mid_string = g_string_new("AT+CSCB=0,\"");
		for(ctr1 = 0; ctr1 < cb_conf->msg_id_range_cnt; ctr1++) {
			if (cb_conf->msg_ids[ctr1].selected == FALSE)
				continue;
			msg_id_range = ((cb_conf->msg_ids[ctr1].to_msg_id) - (cb_conf->msg_ids[ctr1].from_msg_id));

			if (TEL_SMS_GSM_CBMI_LIST_SIZE_MAX <= msg_id_range) {
				mid_string = g_string_new("AT+CSCB=1");	/* Enable All CBS */
				break;
			}
			append_msg_id = cb_conf->msg_ids[ctr1].from_msg_id;
			dbg( "%x", append_msg_id);

			for(ctr2 = 0; ctr2 <= msg_id_range; ctr2++) {
				mid_string = g_string_append(mid_string, g_strdup_printf("%d", append_msg_id));
				if (ctr2 == msg_id_range) {
					mid_string = g_string_append(mid_string, "\"");	/*Mids string termination*/
				}
				else {
					mid_string = g_string_append(mid_string, ",");
				}
				append_msg_id++;
			}
		}
		mids_str = g_string_free(mid_string, FALSE);
		at_cmd = g_strdup_printf("%s", mids_str);
		g_free(mids_str);
	}
	else {
		at_cmd = g_strdup_printf("AT+CSCB=%d", cb_conf->cb_enabled);	/* Enable or Disable MsgId's */
	}

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_sms_set_cb_config, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Cb Config");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get_cb_config
 *
 * Request -
 * AT-Command: AT+CSCB
 *      +CSCB?
 *
 * Response -
 * Success - (Single line)
 * 	+CSCB : <mode>,<mids>,<dcss>
 * OK
 *
 */
 static TelReturn imc_sms_get_cb_config(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;
	dbg("Enter");

	/* AT Command */
	at_cmd = g_strdup_printf("AT+CSCB?");

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sms_get_cb_config, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get Cb Config");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - send_deliver_report
 *
 * Request -
 *	Modem Takes care of sending the ACK to the network
 *
 * Response -
 * Success: Default response always SUCCESS posted
 *
 */
static TelReturn imc_sms_send_deliver_report(CoreObject *co,
	const TelSmsDeliverReportInfo *dr_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	ImcRespCbData *resp_cb_data;
	TelReturn ret = TEL_RETURN_FAILURE;

	dbg("CP takes care of sending SMS ack to network for all "
		"classes of SMS. Sending default success.!!!");
	ret =  TEL_RETURN_SUCCESS;

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		(void *)&co, sizeof(CoreObject*));

	g_idle_add(async_callback, (gpointer)resp_cb_data);

	return ret;
}


/* Operation - set memory status
 *
 * Request -
 * AT-Command: AT+XTESM=<mem_capacity>
 * 	<mem_capacity> status of the external SMS storage which may be:
 * 0: memory capacity free
 * 1: memory capacity full
 *
 * Response -No Result
 * 	Success
 *	 OK
 *
 * Failure:
 *      +CME ERROR: <error>
 */
static TelReturn imc_sms_set_memory_status(CoreObject *co,
	gboolean available, TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/*AT+Command*/
	at_cmd = g_strdup_printf("AT+XTESM=%d", available? 0: 1);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, 0);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_sms_set_memory_status, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Memory Status");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/* Operation - set Message status
 *
 * Request -
 * AT-Command: AT+CRSM= command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]
 *	p1 Index
 *	p3 SMSP record length
 *
 *
 * Response -Single Line
 * 	Success
 *	 OK
 *
 * Failure:
 *      +CME ERROR: <error>
 */
static TelReturn imc_sms_set_message_status(CoreObject *co,
	const TelSmsStatusInfo *status_info,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;

	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	/*AT+Command*/
	at_cmd = g_strdup_printf("AT+CRSM=178,28476,%d,4,%d",
		(status_info->index), IMC_AT_EF_SMS_RECORD_LEN);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
		(void *)status_info, sizeof(TelSmsStatusInfo));

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CRSM:",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		_response_get_efsms_data, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set Message Status");

	/* Free resources */
	g_free(at_cmd);

	return ret;
}

/*
 * Operation - get_sms_parameters
 *
 * Request -
 * AT-Command: AT+CRSM
 * 	AT+CRSM= command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]
 *
 * Response -
 * Success: (Single-line output)
 * 	+CRSM:
 * 	<sw1>,<sw2>[,<response>]
 * 	OK
 *
 * Failure:
 *      +CME ERROR: <error>
 */
static TelReturn imc_sms_get_sms_params(CoreObject *co,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	TcorePlugin *plugin;
	ImcRespCbData *resp_cb_data;
	ImcSmsParamsCbData params_req_data = {0, };
	gint loop_count, record_count = 0, smsp_record_len = 0;
	TelReturn ret = TEL_RETURN_INVALID_PARAMETER;

	dbg("Enter");

	plugin = tcore_object_ref_plugin(co);

	/* Get Record count and SMSP record length*/
	if (FALSE == (imc_sim_get_smsp_info(plugin, &record_count,
				&smsp_record_len))) {
		err("Failed to get SMSP record Count and Record length");
		return ret;
	}

	dbg("Record Count: [%d] SMSP Record Length: [%d]",
		record_count, smsp_record_len);

	/* Allocate Memory for params list data */
	params_req_data.params = tcore_malloc0(sizeof(TelSmsParamsInfo) * record_count);
	/* Counter */
	params_req_data.total_param_count = record_count;
	/* Saving actual count to be returned */
	params_req_data.count = record_count;
	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data,
					(void *)&params_req_data,
					sizeof(ImcSmsParamsCbData));

	for (loop_count = 1; loop_count <= record_count; loop_count++) {
		gchar *at_cmd;

		/* Updating the Index */
		params_req_data.index = loop_count;
		/* AT-Command */
		at_cmd = g_strdup_printf("AT+CRSM=178,28482,%d,4,%d",
					params_req_data.index, smsp_record_len);

		/* Send Request to modem */
		ret = tcore_at_prepare_and_send_request(co,
			at_cmd, "+CRSM",
			TCORE_AT_COMMAND_TYPE_SINGLELINE,
			NULL,
			on_response_imc_sms_get_sms_params, resp_cb_data,
			on_send_imc_request, NULL);
		IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Get SMS Parameters");

		/* Free resources */
		if (ret != TEL_RETURN_SUCCESS)
			tcore_free(params_req_data.params);
		g_free(at_cmd);
	}

	return ret;
}

/*
 * Operation - set_sms_params
 *
 * Request -
 * AT-Command: AT+CRSM
 * 	AT+CRSM= command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]
 *
 * Response -
 * Success: (Single-line output)
 * 	+CRSM:
 * 	<sw1>,<sw2>[,<response>]
 * 	OK
 *
 * Failure:
 *      +CME ERROR: <error>
 */
static TelReturn imc_sms_set_sms_params(CoreObject *co,
	const TelSmsParamsInfo *params,
	TcoreObjectResponseCallback cb, void *cb_data)
{
	gchar *at_cmd;
	ImcRespCbData *resp_cb_data;
	TelReturn ret;

	TcorePlugin *plugin;
	gint smsp_record_len = 0;
	gchar *set_params_data = NULL;
	gchar *encoded_data = NULL;
	gint record_count;
	dbg("Enter");

	plugin = tcore_object_ref_plugin(co);

	if (FALSE  == imc_sim_get_smsp_info(plugin, &record_count, &smsp_record_len)) {
		err("Failed to get SMSP record Count and Record length");
		return TEL_RETURN_INVALID_PARAMETER;
	}

	dbg("SMSP Record Length: [%d]", smsp_record_len);

	/* Allocate memory for set_params_data */
	set_params_data = tcore_malloc0(sizeof(smsp_record_len));

	/* Allocate memory for encoded data*/
	encoded_data = tcore_malloc0((2 * sizeof(smsp_record_len)+1));

	tcore_util_encode_sms_parameters((TelSmsParamsInfo *)params,
		set_params_data, smsp_record_len);

	tcore_util_byte_to_hex((const char *)set_params_data,
		(char *)encoded_data, smsp_record_len);

	/* Response callback data */
	resp_cb_data = imc_create_resp_cb_data(cb, cb_data, NULL, sizeof(gint));

	/* AT+ Command*/
	at_cmd = g_strdup_printf("AT+CRSM=220,28482,%d,4,%d,\"%s\"",
		params->index, smsp_record_len, encoded_data);
	dbg("at_cmd  - %s", at_cmd);
	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co,
		at_cmd, "+CRSM",
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		on_response_imc_sms_set_sms_params, resp_cb_data,
		on_send_imc_request, NULL);
	IMC_CHECK_REQUEST_RET(ret, resp_cb_data, "Set SMS Parameters");

	/* Free resources */
	g_free(at_cmd);
	g_free(set_params_data);
	g_free(encoded_data);

	return ret;
}

/* SMS Operations */
static TcoreSmsOps imc_sms_ops = {
	.send_sms = imc_sms_send_sms,
	.read_in_sim = imc_sms_read_sms_in_sim,
	.write_in_sim = imc_sms_write_sms_in_sim,
	.delete_in_sim = imc_sms_delete_sms_in_sim,
	.get_count = imc_sms_get_msg_count_in_sim,
	.set_cb_config = imc_sms_set_cb_config,
	.get_cb_config = imc_sms_get_cb_config,
	.get_parameters = imc_sms_get_sms_params,
	.set_parameters = imc_sms_set_sms_params,
	.send_deliver_report = imc_sms_send_deliver_report,
	.set_sca = imc_sms_set_sca,
	.get_sca = imc_sms_get_sca,
	.set_memory_status = imc_sms_set_memory_status,
	.set_message_status = imc_sms_set_message_status
};

gboolean imc_sms_init(TcorePlugin *p, CoreObject *co)
{
	dbg("Entry");

	/* Set operations */
	tcore_sms_set_ops(co, &imc_sms_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co, "\e+CMT:",
		on_notification_imc_sms_incoming_msg, NULL);
	tcore_object_add_callback(co, "\e+CDS",
		on_notification_imc_sms_incoming_msg, NULL);

	tcore_object_add_callback(co, "\e+CBM",
		on_notification_imc_sms_cb_incom_msg, NULL);
	tcore_object_add_callback(co, "+CMTI",
		on_notification_imc_sms_class2_incoming_msg, NULL);

	/*
	 * Notification
	 * TODO - AT Command Description Not available
	 */
	tcore_object_add_callback(co, "+XSMSMMSTAT",
		on_notification_imc_sms_memory_status, NULL);

	dbg("Exit");
	return TRUE;
}

void imc_sms_exit(TcorePlugin *p, CoreObject *co)
{
	dbg("Exit");
}
