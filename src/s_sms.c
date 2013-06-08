/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Madhavi Akella <madhavi.a@samsung.com>
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
#include <stdint.h>

#include <glib.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_sms.h>
#include <co_sim.h>
#include <user_request.h>
#include <storage.h>
#include <server.h>
#include <at.h>
#include <plugin.h>

#include <util.h>

#include "common/TelErr.h"
#include "s_common.h"
#include "s_sms.h"

/*=============================================================
							GSM-SMS Size
==============================================================*/
#define MAX_GSM_SMS_TPDU_SIZE						244
#define MAX_GSM_SMS_MSG_NUM							255
#define MAX_GSM_SMS_SERVICE_CENTER_ADDR				12		/* Maximum number of bytes of service center address */
#define MAX_GSM_SMS_CBMI_LIST_SIZE					100		/* Maximum number of CBMI list size for CBS 30*2=60  */
#define MAX_GSM_SMS_PARAM_RECORD_SIZE				156		/* Maximum number of bytes SMSP Record size (Y + 28), y : 0 ~ 128 */
#define MAX_GSM_SMS_STATUS_FILE_SIZE					2		/* Last Used TP-MR + SMS "Memory Cap. Exceeded" Noti Flag */
#define TAPI_SIM_SMSP_ADDRESS_LEN					20

/*=============================================================
							Device Ready
==============================================================*/
#define SMS_DEVICE_READY				1		/* Telephony device ready */
#define SMS_DEVICE_NOT_READY			0		/* Telephony device not ready */

/*=============================================================
							CBMI Selection
==============================================================*/
#define SMS_CBMI_SELECTED_SOME		0x02	/* Some CBMIs are selected */
#define SMS_CBMI_SELECTED_ALL 			0x01	/* All CBMIs are selected */

/*=============================================================
							Message Status
==============================================================*/
#define AT_REC_UNREAD 					0		/* Received and Unread */
#define AT_REC_READ 					1		/* Received and Read */
#define AT_STO_UNSENT 					2		/* Unsent */
#define AT_STO_SENT 					3		/* Sent */
#define AT_ALL 							4		/* Unknown */

/*=============================================================
							Memory Status
==============================================================*/
#define AT_MEMORY_AVAILABLE 			0		/* Memory Available */
#define AT_MEMORY_FULL 				1		/* Memory Full */

/*=============================================================
		SIM CRSM SW1 and Sw2 Error definitions */

#define AT_SW1_SUCCESS 0x90
#define AT_SW2_SUCCESS 0
#define AT_SW1_LEN_RESP 0x9F

#define AT_MAX_RECORD_LEN 256
 /* SCA 12 bytes long and TDPU is 164 bytes long */
#define PDU_LEN_MAX 176
#define HEX_PDU_LEN_MAX			((PDU_LEN_MAX * 2) + 1)

/*=============================================================
							String Preprocessor
==============================================================*/
#define CR		'\r'		/* Carriage Return */

/*=============================================================
							Developer
==============================================================*/
#define SMS_SWAPBYTES16(x) (((x) & 0xffff0000) | (((x) & 0x0000ff00) >> 8) | (((x) & 0x000000ff) << 8))

void print_glib_list_elem(gpointer data, gpointer user_data);

static void on_response_class2_read_msg(TcorePending *pending, int data_len, const void *data, void *user_data);


gboolean util_byte_to_hex(const char *byte_pdu, char *hex_pdu, int num_bytes);

void print_glib_list_elem(gpointer data, gpointer user_data)
{
	char *item = (char *)data;

	dbg("item: [%s]", item);
}

/*=============================================================
							Send Callback
==============================================================*/
static void on_confirmation_sms_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("Entered Function. Request message out from queue");

	dbg("TcorePending: [%p]", p);
	dbg("result: [%02x]", result);
	dbg("user_data: [%p]", user_data);

	if (result == TRUE) {
		dbg("SEND OK");
	} else { /* Failed */
		dbg("SEND NOK");
	}

	dbg("Exiting Function. Nothing to return");
}

/*=============================================================
							Utilities
==============================================================*/
static void util_sms_free_memory(void *sms_ptr)
{
	dbg("Entry");

	if (NULL != sms_ptr) {
		dbg("Freeing memory location: [%p]", sms_ptr);
		free(sms_ptr);
		sms_ptr = NULL;
	} else {
		err("Invalid memory location. Nothing to do.");
	}

	dbg("Exit");
}


static int util_sms_decode_smsParameters(unsigned char *incoming, unsigned int length, struct telephony_sms_Params *params)
{
	int alpha_id_len = 0;
	int i = 0;
	int nOffset = 0;

	dbg(" RecordLen = %d", length);

	if(incoming == NULL || params == NULL)
		return FALSE;

	alpha_id_len = length -SMS_SMSP_PARAMS_MAX_LEN;

	if (alpha_id_len > 0) {
		if (alpha_id_len > SMS_SMSP_ALPHA_ID_LEN_MAX) {
			alpha_id_len = SMS_SMSP_ALPHA_ID_LEN_MAX;
		}

		for (i = 0; i < alpha_id_len; i++) {
			if (0xff == incoming[i]) {
				dbg(" found");
				break;
			}
		}

		memcpy(params->szAlphaId, incoming, i);

		params->alphaIdLen = i;

		dbg(" Alpha id length = %d", i);
	} else {
		params->alphaIdLen = 0;
		dbg(" Alpha id length is zero");
	}

	params->paramIndicator = incoming[alpha_id_len];

	dbg(" Param Indicator = %02x", params->paramIndicator);

	if ((params->paramIndicator & SMSPValidDestAddr) == 0) {
		nOffset = nDestAddrOffset;

		if (0x00 == incoming[alpha_id_len + nOffset] || 0xff == incoming[alpha_id_len + nOffset]) {
			params->tpDestAddr.dialNumLen = 0;

			dbg("DestAddr Length is 0");
		} else {
			if (0 < (int) incoming[alpha_id_len + nOffset]) {
				params->tpDestAddr.dialNumLen = (int) (incoming[alpha_id_len + nOffset] - 1);

				if (params->tpDestAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
					params->tpDestAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;
			} else {
				params->tpDestAddr.dialNumLen = 0;
			}

			params->tpDestAddr.numPlanId = incoming[alpha_id_len + (++nOffset)] & 0x0f;
			params->tpDestAddr.typeOfNum = (incoming[alpha_id_len + nOffset] & 0x70) >> 4;

			memcpy(params->tpDestAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpDestAddr.dialNumLen));

			dbg("Dest TON is %d", params->tpDestAddr.typeOfNum);
			dbg("Dest NPI is %d", params->tpDestAddr.numPlanId);
			dbg("Dest Length = %d", params->tpDestAddr.dialNumLen);
			dbg("Dest Addr = %s", params->tpDestAddr.diallingNum);
		}
	} else {
		params->tpDestAddr.dialNumLen = 0;
	}

	if ((params->paramIndicator & SMSPValidSvcAddr) == 0) {
		nOffset = nSCAAddrOffset;

		if (0x00 == (int) incoming[alpha_id_len + nOffset] || 0xff == (int) incoming[alpha_id_len + nOffset]) {
			params->tpSvcCntrAddr.dialNumLen = 0;

			dbg(" SCAddr Length is 0");
		} else {
			if (0 < (int) incoming[alpha_id_len + nOffset]) {
				params->tpSvcCntrAddr.dialNumLen = (int) (incoming[alpha_id_len + nOffset] - 1);

				if (params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
					params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId = incoming[alpha_id_len + (++nOffset)] & 0x0f;
				params->tpSvcCntrAddr.typeOfNum = (incoming[alpha_id_len + nOffset] & 0x70) >> 4;

				memcpy(params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpSvcCntrAddr.dialNumLen));

				dbg("SCAddr Length = %d ", params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d", params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d", params->tpSvcCntrAddr.numPlanId);

				for (i = 0; i < (int) params->tpSvcCntrAddr.dialNumLen; i++)
					dbg("SCAddr = %d [%02x]", i, params->tpSvcCntrAddr.diallingNum[i]);
			} else {
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}
	} else if ((0x00 < (int) incoming[alpha_id_len + nSCAAddrOffset] && (int) incoming[alpha_id_len + nSCAAddrOffset] <= 12)
			   || 0xff != (int) incoming[alpha_id_len + nSCAAddrOffset]) {
		nOffset = nSCAAddrOffset;

		if (0x00 == (int) incoming[alpha_id_len + nOffset] || 0xff == (int) incoming[alpha_id_len + nOffset]) {
			params->tpSvcCntrAddr.dialNumLen = 0;
			dbg("SCAddr Length is 0");
		} else {
			if (0 < (int) incoming[alpha_id_len + nOffset]) {
				params->tpSvcCntrAddr.dialNumLen = (int) (incoming[alpha_id_len + nOffset] - 1);

				params->tpSvcCntrAddr.dialNumLen = incoming[alpha_id_len + nOffset] - 1;

				if (params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
					params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId = incoming[alpha_id_len + (++nOffset)] & 0x0f;
				params->tpSvcCntrAddr.typeOfNum = (incoming[alpha_id_len + nOffset] & 0x70) >> 4;

				memcpy(params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)],
					   (params->tpSvcCntrAddr.dialNumLen));

				dbg("SCAddr Length = %d ", params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d", params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d", params->tpSvcCntrAddr.numPlanId);

				for (i = 0; i < (int) params->tpSvcCntrAddr.dialNumLen; i++)
					dbg("SCAddr = %d [%02x]", i, params->tpSvcCntrAddr.diallingNum[i]);
			} else {
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}
	} else {
			params->tpSvcCntrAddr.dialNumLen = 0;
	}

	if ((params->paramIndicator & SMSPValidPID) == 0 && (alpha_id_len + nPIDOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE) {
		params->tpProtocolId = incoming[alpha_id_len + nPIDOffset];
	}
	if ((params->paramIndicator & SMSPValidDCS) == 0 && (alpha_id_len + nDCSOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE) {
		params->tpDataCodingScheme = incoming[alpha_id_len + nDCSOffset];
	}
	if ((params->paramIndicator & SMSPValidVP) == 0 && (alpha_id_len + nVPOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE) {
		params->tpValidityPeriod = incoming[alpha_id_len + nVPOffset];
	}

	dbg(" Alpha Id(Len) = %d", (int) params->alphaIdLen);

	for (i = 0; i < (int) params->alphaIdLen; i++) {
		dbg(" Alpha Id = [%d] [%c]", i, params->szAlphaId[i]);
	}
	dbg(" PID = %d",params->tpProtocolId);
	dbg(" DCS = %d",params->tpDataCodingScheme);
	dbg(" VP = %d",params->tpValidityPeriod);

	return TRUE;
}

/*=============================================================
							Notifications
==============================================================*/
static gboolean on_event_class2_sms_incom_msg(CoreObject *obj,
									const void *event_info, void *user_data)
{
	//+CMTI: <mem>,<index>

	GSList *tokens = NULL , *lines = NULL;
	char *line = NULL, *cmd_str = NULL;
	int index = 0, mem_type = 0;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;

	dbg("Entered Function");

	lines = (GSList *)event_info;
	line = (char *)g_slist_nth_data(lines, 0); /* Fetch Line 1 */

	dbg("Line 1: [%s]", line);

	if (!line) {
		err("Line 1 is invalid");
		return FALSE;
	}

	tokens = tcore_at_tok_new(line); /* Split Line 1 into tokens */
	mem_type = atoi(g_slist_nth_data(tokens, 0));       // Type of Memory stored
	index = atoi((char *) g_slist_nth_data(tokens, 1));

	hal = tcore_object_get_hal(obj);
	if (NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("readMsg: hal: [%p]", hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}

	dbg("index: [%d]", index);

	cmd_str = g_strdup_printf("AT+CMGR=%d", index);
	atreq     = tcore_at_request_new((const char *)cmd_str, "+CMGR", TCORE_AT_PDU);
	pending = tcore_pending_new(obj, 0);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_class2_read_msg, (void *)(uintptr_t)index); //storing index as user data for response
	tcore_pending_link_user_request(pending, NULL);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);
	g_free(cmd_str);

	if(tokens)
		tcore_at_tok_free(tokens);

	return TRUE;
}

static gboolean on_event_sms_incom_msg(CoreObject *o, const void *event_info, void *user_data)
{
	//+CMT: [<alpha>],<length><CR><LF><pdu> (PDU mode enabled);

	int rtn = -1;
	GSList *tokens = NULL;
	GSList *lines = NULL;
	char *line = NULL;
	int pdu_len = 0, no_of_tokens = 0;
	unsigned char *bytePDU = NULL;
	struct tnoti_sms_umts_msg gsmMsgInfo;
	int sca_length = 0;

	dbg("Entered Function");

	lines = (GSList *)event_info;
	memset(&gsmMsgInfo, 0x00, sizeof(struct tnoti_sms_umts_msg));

	if (2 != g_slist_length(lines)) {
		err("Invalid number of lines for +CMT. Must be 2");
		return FALSE;
	}

	line = (char *)g_slist_nth_data(lines, 0); /* Fetch Line 1 */

	dbg("Line 1: [%s]", line);

	if (!line) {
		err("Line 1 is invalid");
		return FALSE;
	}

	tokens = tcore_at_tok_new(line); /* Split Line 1 into tokens */

	no_of_tokens = g_slist_length(tokens);

	if (no_of_tokens == 2) { // in case of incoming SMS +CMT
		dbg("Alpha ID: [%02x]", g_slist_nth_data(tokens, 0)); /* 0: Alpha ID */
		pdu_len = atoi((char *)g_slist_nth_data(tokens, 1));
		dbg("pdu_len: [%d]", pdu_len);	/* 1: PDU Length */
	} else if (no_of_tokens == 1) { // in case of incoming status report +CDS
		pdu_len = atoi((char *)g_slist_nth_data(tokens, 0));
		dbg("pdu_len: [%d]", pdu_len);	/* 1: PDU Length */
	}

	line = (char *)g_slist_nth_data(lines, 1); /* Fetch Line 2 */

	dbg("Line 2: [%s]", line);

	if (!line) {
		err("Line 2 is invalid");
		return FALSE;
	}

	/* Convert to Bytes */
	bytePDU = (unsigned char *)util_hexStringToBytes(line);

	sca_length = bytePDU[0];

	dbg("SCA length = %d", sca_length);

	gsmMsgInfo.msgInfo.msgLength = pdu_len;

	if (sca_length == 0) {
		memcpy(gsmMsgInfo.msgInfo.tpduData, &bytePDU[1], gsmMsgInfo.msgInfo.msgLength);
	} else {
		memcpy(gsmMsgInfo.msgInfo.sca, &bytePDU[1], sca_length);
		memcpy(gsmMsgInfo.msgInfo.tpduData, &bytePDU[sca_length+1], gsmMsgInfo.msgInfo.msgLength);
	}

	util_hex_dump("      ", strlen(line)/2, bytePDU);
	util_hex_dump("      ", sca_length, gsmMsgInfo.msgInfo.sca);
	util_hex_dump("      ", gsmMsgInfo.msgInfo.msgLength,gsmMsgInfo.msgInfo.tpduData);

	rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_INCOM_MSG, sizeof(struct tnoti_sms_umts_msg), &gsmMsgInfo);

	if(tokens)
		tcore_at_tok_free(tokens);

	g_free(bytePDU);

	return TRUE;
}



static gboolean on_event_sms_memory_status(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_sms_memory_status memStatusInfo = {0,};

	int rtn = -1 ,memoryStatus = -1;
	GSList *tokens=NULL;
	GSList *lines=NULL;
	char *line = NULL , *pResp = NULL;

	dbg(" Entry");

	lines = (GSList *)event_info;
	if (1 != g_slist_length(lines)) {
                dbg("unsolicited msg but multiple line");
        }

	line = (char*)(lines->data);

	if (line) {
		dbg("Response OK");
		tokens = tcore_at_tok_new(line);
		pResp = g_slist_nth_data(tokens, 0);

		if (pResp) {
			memoryStatus = atoi(pResp);
			dbg("memoryStatus is %d",memoryStatus);
			if (memoryStatus == 0) {//SIM Full condition
				memStatusInfo.status = SMS_PHONE_MEMORY_STATUS_FULL;
			}
			rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_MEMORY_STATUS, sizeof(struct tnoti_sms_memory_status), &memStatusInfo);
		}
		tcore_at_tok_free(tokens);
	}else {
		dbg("Response NOK");
	}

	dbg(" Exit ");
	return TRUE;
}

static gboolean on_event_sms_cb_incom_msg(CoreObject *o, const void *event_info, void *user_data)
{
	//+CBM: <length><CR><LF><pdu>

	struct tnoti_sms_cellBroadcast_msg cbMsgInfo;

	int rtn = -1 , length = 0;
	char * line = NULL, *pdu = NULL, *pResp = NULL;
	GSList *tokens = NULL;
	GSList *lines = NULL;

	dbg(" Func Entrance");

	lines = (GSList *)event_info;

	memset(&cbMsgInfo, 0, sizeof(struct tnoti_sms_cellBroadcast_msg));

	line = (char *)(lines->data);

	if (line != NULL) {
		dbg("Response OK");
		dbg("Noti line is %s",line);
		tokens = tcore_at_tok_new(line); /* Split Line 1 into tokens */

		pResp = g_slist_nth_data(tokens, 0);
		if (pResp) {
			length = atoi(pResp);
		} else {
			dbg("token 0 is null");
		}

		pdu = g_slist_nth_data(lines, 1);
		if (pdu != NULL) {
			cbMsgInfo.cbMsg.length = length;
			cbMsgInfo.cbMsg.cbMsgType = SMS_CB_MSG_GSM;

			dbg("CB Msg LENGTH [%2x]", length);

			if ((cbMsgInfo.cbMsg.length >0) && (SMS_CB_SIZE_MAX >= cbMsgInfo.cbMsg.length)) {
				unsigned char *byte_pdu = NULL;

				byte_pdu = (unsigned char *)util_hexStringToBytes(pdu);

				memcpy(cbMsgInfo.cbMsg.msgData, (char*)byte_pdu, cbMsgInfo.cbMsg.length);
				rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_CB_INCOM_MSG, sizeof(struct tnoti_sms_cellBroadcast_msg), &cbMsgInfo);
				g_free(byte_pdu);
			} else {
				dbg("Invalid Message Length");
			}
		} else {
			dbg("Recieved NULL pdu");
		}
	} else {
		dbg("Response NOK");
	}

	dbg(" Return value [%d]",rtn);

	if(tokens)
		tcore_at_tok_free(tokens);

	return TRUE;
}


/*=============================================================
							Responses
==============================================================*/
static void on_response_sms_delete_msg(TcorePending *p, int data_len, const void *data, void *user_data)
{
	struct tresp_sms_delete_msg delMsgInfo = {0,};
	UserRequest *ur = NULL;
	const TcoreATResponse *atResp = data;

	int rtn = -1;
	int index = (int) user_data;

	dbg(" Func Entrance");

	ur = tcore_pending_ref_user_request(p);
	if (atResp->success) {
		dbg("Response OK");
		delMsgInfo.index = index;
		delMsgInfo.result = SMS_SENDSMS_SUCCESS;
	} else {
		dbg("Response NOK");
		delMsgInfo.index = index;
		delMsgInfo.result = SMS_DEVICE_FAILURE;
	}

	rtn = tcore_user_request_send_response(ur, TRESP_SMS_DELETE_MSG, sizeof(struct tresp_sms_delete_msg), &delMsgInfo);

	return;
}

static void on_response_sms_save_msg(TcorePending *p, int data_len, const void *data, void *user_data)
{
	struct tresp_sms_save_msg saveMsgInfo = {0,};
	UserRequest *ur = NULL;
	const TcoreATResponse *atResp = data;
	GSList *tokens = NULL;
	char *line = NULL;
	char *pResp = NULL;
	int rtn = -1;

	ur = tcore_pending_ref_user_request(p);
	if (atResp->success) {
		dbg("Response OK");
		if (atResp->lines) {
			line = (char *)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp) {
				dbg("0: %s", pResp);
		 		saveMsgInfo.index = (atoi(pResp) - 1); /* IMC index starts from 1 */
				saveMsgInfo.result = SMS_SENDSMS_SUCCESS;
			} else {
				dbg("No Tokens");
				saveMsgInfo.index = -1;
				saveMsgInfo.result = SMS_DEVICE_FAILURE;
			}
			tcore_at_tok_free(tokens);
		}
	} else {
		dbg("Response NOK");
		saveMsgInfo.index = -1;
		saveMsgInfo.result = SMS_DEVICE_FAILURE;
	}

	rtn = tcore_user_request_send_response(ur, TRESP_SMS_SAVE_MSG, sizeof(struct tresp_sms_save_msg), &saveMsgInfo);
	dbg("Return value [%d]", rtn);
	return;
}

static void on_response_send_umts_msg(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_response = data;
	struct tresp_sms_send_umts_msg resp_umts;
	UserRequest *user_req = NULL;

	int msg_ref = 0;
	GSList *tokens = NULL;
	char *gslist_line = NULL, *line_token = NULL;

	dbg("Entry");

	user_req = tcore_pending_ref_user_request(pending);

	if (NULL == user_req) {
		err("No user request");

		dbg("Exit");
		return;
	}

	memset(&resp_umts, 0x00, sizeof(resp_umts));
	resp_umts.result = SMS_DEVICE_FAILURE;

	if (at_response->success > 0) { /* SUCCESS */
		dbg("Response OK");
		if (at_response->lines) { // lines present in at_response
			gslist_line = (char *)at_response->lines->data;
			dbg("gslist_line: [%s]", gslist_line);

			tokens = tcore_at_tok_new(gslist_line); //extract tokens

			line_token = g_slist_nth_data(tokens, 0);
			if (line_token != NULL) {
				msg_ref = atoi(line_token);
				dbg("Message Reference: [%d]", msg_ref);

				resp_umts.result = SMS_SENDSMS_SUCCESS;
			} else {
				dbg("No Message Reference received");
			}
			tcore_at_tok_free(tokens);
		} else { // no lines in at_response
			dbg("No lines");
		}
	} else { // failure
		dbg("Response NOK");
	}

	tcore_user_request_send_response(user_req, TRESP_SMS_SEND_UMTS_MSG, sizeof(resp_umts), &resp_umts);

	dbg("Exit");
	return;
}

static void on_response_class2_read_msg(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_response = data;
	GSList *tokens=NULL;
	char *gslist_line = NULL, *line_token = NULL, *hex_pdu = NULL;
	int  pdu_len = 0, rtn = 0;
	unsigned char *bytePDU = NULL;
	struct tnoti_sms_umts_msg gsmMsgInfo;
	int sca_length= 0;

	dbg("Entry");
	dbg("lines: [%p]", at_response->lines);
	g_slist_foreach(at_response->lines, print_glib_list_elem, NULL); //for debug log

	if (at_response->success > 0) {
		dbg("Response OK");
		if (at_response->lines) {
			//fetch first line
			gslist_line = (char *)at_response->lines->data;

			dbg("gslist_line: [%s]", gslist_line);

			tokens = tcore_at_tok_new(gslist_line);
			dbg("Number of tokens: [%d]", g_slist_length(tokens));
			g_slist_foreach(tokens, print_glib_list_elem, NULL); //for debug log

			line_token = g_slist_nth_data(tokens, 2); //Third Token: Length
			if (line_token != NULL) {
				pdu_len = atoi(line_token);
				dbg("Length: [%d]", pdu_len);
			}

			//fetch second line
			gslist_line = (char *)at_response->lines->next->data;

			dbg("gslist_line: [%s]", gslist_line);

			//free the consumed token
			tcore_at_tok_free(tokens);

			tokens = tcore_at_tok_new(gslist_line);
			dbg("Number of tokens: [%d]", g_slist_length(tokens));
			g_slist_foreach(tokens, print_glib_list_elem, NULL); //for debug log

			hex_pdu = g_slist_nth_data(tokens, 0); //Fetch SMS PDU

			//free the consumed token
			tcore_at_tok_free(tokens);
		} else {
			dbg("No lines");
		}
	} else {
		err("Response NOK");
	}

	/* Convert to Bytes */
	bytePDU = (unsigned char *)util_hexStringToBytes(hex_pdu);

	sca_length = bytePDU[0];

	dbg("SCA length = %d", sca_length);

	gsmMsgInfo.msgInfo.msgLength = pdu_len;

	if (sca_length == 0) {
		memcpy(gsmMsgInfo.msgInfo.tpduData, &bytePDU[1], gsmMsgInfo.msgInfo.msgLength);
	} else {
		memcpy(gsmMsgInfo.msgInfo.sca, bytePDU, sca_length);
		memcpy(gsmMsgInfo.msgInfo.tpduData, &bytePDU[sca_length+1], gsmMsgInfo.msgInfo.msgLength);
	}

	util_hex_dump("      ", strlen(hex_pdu)/2, bytePDU);
	util_hex_dump("      ", sca_length, gsmMsgInfo.msgInfo.sca);
	util_hex_dump("      ", gsmMsgInfo.msgInfo.msgLength,gsmMsgInfo.msgInfo.tpduData);

	rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(tcore_pending_ref_core_object(pending))), tcore_pending_ref_core_object(pending), TNOTI_SMS_INCOM_MSG, sizeof(struct tnoti_sms_umts_msg), &gsmMsgInfo);

	g_free(bytePDU);

	dbg("Exit");
	return;
}

static void on_response_read_msg(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_response = data;
	struct tresp_sms_read_msg resp_read_msg;
	UserRequest *user_req = NULL;

	GSList *tokens=NULL;
	char *gslist_line = NULL, *line_token = NULL, *byte_pdu = NULL, *hex_pdu = NULL;
	int sca_length = 0;
	int msg_status = 0, alpha_id = 0, pdu_len = 0;
	int index = (int)(uintptr_t)user_data;

	dbg("Entry");
	dbg("index: [%d]", index);
	g_slist_foreach(at_response->lines, print_glib_list_elem, NULL); //for debug log

	user_req = tcore_pending_ref_user_request(pending);
	if (NULL == user_req) {
		err("No user request");

		dbg("Exit");
		return;
	}

	memset(&resp_read_msg, 0x00, sizeof(resp_read_msg));
	resp_read_msg.result = SMS_PHONE_FAILURE;

	if (at_response->success > 0) {
		dbg("Response OK");
		if (at_response->lines) {
			//fetch first line
			gslist_line = (char *)at_response->lines->data;

			dbg("gslist_line: [%s]", gslist_line);

			tokens = tcore_at_tok_new(gslist_line);
			dbg("Number of tokens: [%d]", g_slist_length(tokens));
			g_slist_foreach(tokens, print_glib_list_elem, NULL); //for debug log

			line_token = g_slist_nth_data(tokens, 0); //First Token: Message Status
			if (line_token != NULL) {
				msg_status = atoi(line_token);
				dbg("msg_status is %d",msg_status);
				switch (msg_status) {
					case AT_REC_UNREAD:
						resp_read_msg.dataInfo.msgStatus = SMS_STATUS_UNREAD;
						break;

					case AT_REC_READ:
						resp_read_msg.dataInfo.msgStatus = SMS_STATUS_READ;
						break;

					case AT_STO_UNSENT:
						resp_read_msg.dataInfo.msgStatus = SMS_STATUS_UNSENT;
						break;

					case AT_STO_SENT:
						resp_read_msg.dataInfo.msgStatus = SMS_STATUS_SENT;
						break;

					case AT_ALL: //Fall Through
					default: //Fall Through
						resp_read_msg.dataInfo.msgStatus = SMS_STATUS_RESERVED;
						break;
				}
			}

			line_token = g_slist_nth_data(tokens, 1); //Second Token: AlphaID
			if (line_token != NULL) {
				alpha_id = atoi(line_token);
				dbg("AlphaID: [%d]", alpha_id);
			}

			line_token = g_slist_nth_data(tokens, 2); //Third Token: Length
			if (line_token != NULL) {
				pdu_len = atoi(line_token);
				dbg("Length: [%d]", pdu_len);
			}

			//fetch second line
			hex_pdu = (char *) at_response->lines->next->data;

			dbg("EF-SMS PDU: [%s]", hex_pdu);

			//free the consumed token
			tcore_at_tok_free(tokens);

			if (NULL != hex_pdu) {
				util_hex_dump("    ", sizeof(hex_pdu), (void *)hex_pdu);

				byte_pdu = util_hexStringToBytes(hex_pdu);

				sca_length = (int)byte_pdu[0];

				resp_read_msg.dataInfo.simIndex = index; //Retrieving index stored as user_data

				dbg("SCA Length : %d", sca_length);

				resp_read_msg.dataInfo.smsData.msgLength = pdu_len;
				dbg("msgLength: [%d]", resp_read_msg.dataInfo.smsData.msgLength);

				if(0 == sca_length) {
					if ((resp_read_msg.dataInfo.smsData.msgLength > 0)
						&& (resp_read_msg.dataInfo.smsData.msgLength <= SMS_SMDATA_SIZE_MAX)) 	{
						memset(resp_read_msg.dataInfo.smsData.sca, 0, TAPI_SIM_SMSP_ADDRESS_LEN);
						memcpy(resp_read_msg.dataInfo.smsData.tpduData, &byte_pdu[1], resp_read_msg.dataInfo.smsData.msgLength);

						resp_read_msg.result = SMS_SUCCESS;
					} else {
						dbg("Invalid Message Length");
						resp_read_msg.result = SMS_INVALID_PARAMETER_FORMAT;
					}
				} else {
					if ((resp_read_msg.dataInfo.smsData.msgLength > 0)
						&& (resp_read_msg.dataInfo.smsData.msgLength <= SMS_SMDATA_SIZE_MAX)) {
						memcpy(resp_read_msg.dataInfo.smsData.sca, (char *)byte_pdu, (sca_length+1));
						memcpy(resp_read_msg.dataInfo.smsData.tpduData, &byte_pdu[sca_length+1], resp_read_msg.dataInfo.smsData.msgLength);

						util_hex_dump("    ", SMS_SMSP_ADDRESS_LEN, (void *)resp_read_msg.dataInfo.smsData.sca);
						util_hex_dump("    ", (SMS_SMDATA_SIZE_MAX + 1), (void *)resp_read_msg.dataInfo.smsData.tpduData);
						util_hex_dump("    ", sizeof(byte_pdu), (void *)byte_pdu);

						resp_read_msg.result = SMS_SUCCESS;
					} else {
						dbg("Invalid Message Length");
						resp_read_msg.result = SMS_INVALID_PARAMETER_FORMAT;
					}
				}
				g_free(byte_pdu);
			}else {
				dbg("NULL PDU");
			}
		}else {
			dbg("No lines");
		}
	} else {
		err("Response NOK");
	}

	tcore_user_request_send_response(user_req, TRESP_SMS_READ_MSG, sizeof(resp_read_msg), &resp_read_msg);

	dbg("Exit");
	return;
}

static void on_response_get_msg_indices(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_response = data;
	struct tresp_sms_get_storedMsgCnt resp_stored_msg_cnt;
	UserRequest *user_req = NULL;
	struct tresp_sms_get_storedMsgCnt *resp_stored_msg_cnt_prev = NULL;

	GSList *tokens = NULL;
	char *gslist_line = NULL, *line_token = NULL;
	int gslist_line_count = 0, ctr_loop = 0;

	dbg("Entry");

	resp_stored_msg_cnt_prev = (struct tresp_sms_get_storedMsgCnt *)user_data;
	user_req = tcore_pending_ref_user_request(pending);

	memset(&resp_stored_msg_cnt, 0x00, sizeof(resp_stored_msg_cnt));
	resp_stored_msg_cnt.result = SMS_DEVICE_FAILURE;

	if (at_response->success) {
		dbg("Response OK");
		if (at_response->lines) {
			gslist_line_count = g_slist_length(at_response->lines);

			if (gslist_line_count > SMS_GSM_SMS_MSG_NUM_MAX)
				gslist_line_count = SMS_GSM_SMS_MSG_NUM_MAX;

			dbg("Number of lines: [%d]", gslist_line_count);
			g_slist_foreach(at_response->lines, print_glib_list_elem, NULL); //for debug log

			for (ctr_loop = 0; ctr_loop < gslist_line_count; ctr_loop++) {
				gslist_line = (char *)g_slist_nth_data(at_response->lines, ctr_loop); /* Fetch Line i */

				dbg("gslist_line [%d] is [%s]", ctr_loop, gslist_line);

				if (NULL != gslist_line) {
					tokens = tcore_at_tok_new(gslist_line);

					g_slist_foreach(tokens, print_glib_list_elem, NULL); //for debug log

					line_token = g_slist_nth_data(tokens, 0);
					if (NULL != line_token) {
						resp_stored_msg_cnt.storedMsgCnt.indexList[ctr_loop] = atoi(line_token);
						resp_stored_msg_cnt.result = SMS_SENDSMS_SUCCESS;
					} else {
						dbg("line_token of gslist_line [%d] is NULL", ctr_loop);
						continue;
					}
					tcore_at_tok_free(tokens);
				} else {
					dbg("gslist_line [%d] is NULL", ctr_loop);
					continue;
				}
     			}
		} else {
			dbg("No lines.");
			if (resp_stored_msg_cnt_prev->storedMsgCnt.usedCount == 0) { // Check if used count is zero
				resp_stored_msg_cnt.result = SMS_SENDSMS_SUCCESS;
			}
		}
	} else {
		dbg("Respnose NOK");
	}

	resp_stored_msg_cnt.storedMsgCnt.totalCount = resp_stored_msg_cnt_prev->storedMsgCnt.totalCount;
	resp_stored_msg_cnt.storedMsgCnt.usedCount = resp_stored_msg_cnt_prev->storedMsgCnt.usedCount;

	util_sms_free_memory(resp_stored_msg_cnt_prev);

	dbg("total: [%d], used: [%d], result: [%d]", resp_stored_msg_cnt.storedMsgCnt.totalCount, resp_stored_msg_cnt.storedMsgCnt.usedCount, resp_stored_msg_cnt.result);
	for (ctr_loop = 0; ctr_loop < gslist_line_count; ctr_loop++) {
		dbg("index: [%d]", resp_stored_msg_cnt.storedMsgCnt.indexList[ctr_loop]);
	}

	tcore_user_request_send_response(user_req, TRESP_SMS_GET_STORED_MSG_COUNT, sizeof(resp_stored_msg_cnt), &resp_stored_msg_cnt);

	dbg("Exit");
	return;
}

static void on_response_get_stored_msg_cnt(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL, *ur_dup = NULL;
	struct tresp_sms_get_storedMsgCnt *respStoredMsgCnt = NULL;
	const TcoreATResponse *atResp = data;
	GSList *tokens=NULL;
	char *line = NULL , *pResp = NULL , *cmd_str = NULL;
	TcoreATRequest *atReq = NULL;
	int usedCnt = 0, totalCnt = 0, result = 0;

	TcorePending *pending_new = NULL;
	CoreObject *o = NULL;

	dbg("Entered");

	respStoredMsgCnt = malloc(sizeof(struct tresp_sms_get_storedMsgCnt));
	result = SMS_DEVICE_FAILURE;

	ur = tcore_pending_ref_user_request(pending);
	ur_dup = tcore_user_request_ref(ur);
	o = tcore_pending_ref_core_object(pending);

	if (atResp->success > 0) {
		dbg("Response OK");
		if (NULL != atResp->lines) {
			line = (char *)atResp->lines->data;
			dbg("line is %s",line);

			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);

			if (pResp) {
		 		usedCnt =atoi(pResp);
				dbg("used cnt is %d",usedCnt);
			}

			pResp = g_slist_nth_data(tokens, 1);
			if (pResp) {
		 		totalCnt =atoi(pResp);
				result = SMS_SENDSMS_SUCCESS;

				respStoredMsgCnt->storedMsgCnt.usedCount = usedCnt;
				respStoredMsgCnt->storedMsgCnt.totalCount = totalCnt;
				respStoredMsgCnt->result = result;

				dbg("used %d, total %d, result %d",usedCnt, totalCnt,result);

				pending_new = tcore_pending_new(o, 0);
				//Get all messages information
				cmd_str = g_strdup_printf("AT+CMGL=4");
				atReq = tcore_at_request_new((const char *)cmd_str, "+CMGL", TCORE_AT_MULTILINE);

				dbg("cmd str is %s",cmd_str);

				tcore_pending_set_request_data(pending_new, 0,atReq);
				tcore_pending_set_response_callback(pending_new, on_response_get_msg_indices, (void *)respStoredMsgCnt);
				tcore_pending_link_user_request(pending_new, ur_dup);
				tcore_pending_set_send_callback(pending_new, on_confirmation_sms_message_send, NULL);
				tcore_hal_send_request(tcore_object_get_hal(o), pending_new);

				//free the consumed token
				tcore_at_tok_free(tokens);

				g_free(cmd_str);

				dbg("Exit");
				return;
			}
			//free the consumed token
			if (tokens)
			tcore_at_tok_free(tokens);
		} else {
			dbg("No data");
		}
	} else {
		err("Response NOK");
	}
	respStoredMsgCnt->result = result;
	tcore_user_request_send_response(ur, TRESP_SMS_GET_STORED_MSG_COUNT, sizeof(struct tresp_sms_get_storedMsgCnt), &respStoredMsgCnt);


	dbg("Exit");
	return;
}

static void on_response_get_sca(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *at_response = data;
	struct tresp_sms_get_sca respGetSca;
	UserRequest *user_req = NULL;

	GSList *tokens = NULL;
	const char *sca_tok_addr;
	char *gslist_line = NULL, *sca_addr = NULL, *sca_toa = NULL;

	dbg("Entry");

	memset(&respGetSca, 0, sizeof(respGetSca));
	respGetSca.result = SMS_DEVICE_FAILURE;

	user_req = tcore_pending_ref_user_request(pending);

	if (at_response->success) {
		dbg("Response OK");
		if (at_response->lines) {
			gslist_line = (char *)at_response->lines->data;

			tokens = tcore_at_tok_new(gslist_line);
			sca_tok_addr = g_slist_nth_data(tokens, 0);
			sca_toa = g_slist_nth_data(tokens, 1);

			sca_addr = tcore_at_tok_extract(sca_tok_addr);
			if ((NULL != sca_addr)
				&& (NULL != sca_toa)) {
				dbg("sca_addr: [%s]. sca_toa: [%s]", sca_addr, sca_toa);

				respGetSca.scaAddress.dialNumLen = strlen(sca_addr);

				if (145 == atoi(sca_toa)) {
					respGetSca.scaAddress.typeOfNum = SIM_TON_INTERNATIONAL;
				} else {
					respGetSca.scaAddress.typeOfNum = SIM_TON_NATIONAL;
				}

				respGetSca.scaAddress.numPlanId = 0;

				memcpy(respGetSca.scaAddress.diallingNum, sca_addr, strlen(sca_addr));

				dbg("len [%d], sca_addr [%s], TON [%d], NPI [%d]", respGetSca.scaAddress.dialNumLen, respGetSca.scaAddress.diallingNum, respGetSca.scaAddress.typeOfNum, respGetSca.scaAddress.numPlanId);

				respGetSca.result = SMS_SENDSMS_SUCCESS;
			} else {
				err("sca_addr OR sca_toa NULL");
			}
		} else {
			dbg("NO Lines");
		}
	} else {
		dbg("Response NOK");
	}

	tcore_user_request_send_response(user_req, TRESP_SMS_GET_SCA, sizeof(respGetSca), &respGetSca);

	tcore_at_tok_free(tokens);
	g_free(sca_addr);

	dbg("Exit");
	return;
}

static void on_response_set_sca(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	/*
	Response is expected in this format
	OK
	or
	+CMS ERROR: <err>
	*/
	UserRequest *ur;
	//copies the AT response data to resp
	const TcoreATResponse *atResp = data;
	struct tresp_sms_set_sca respSetSca;

	memset(&respSetSca, 0, sizeof(struct tresp_sms_set_sca));

	ur = tcore_pending_ref_user_request(pending);
	if (!ur) {
		dbg("no user_request");
		return;
	}

	if (atResp->success > 0) {
		dbg("RESPONSE OK");
		respSetSca.result = SMS_SUCCESS;
	} else {
		dbg("RESPONSE NOK");
		respSetSca.result = SMS_DEVICE_FAILURE;
	}

	tcore_user_request_send_response(ur, TRESP_SMS_SET_SCA, sizeof(struct tresp_sms_set_sca), &respSetSca);

	return;
}

static void on_response_get_cb_config(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_cb_config respGetCbConfig;
	const TcoreATResponse *atResp = data;
	GSList *tokens=NULL;
	int i = 0, mode =0;
	char *pResp = NULL, *line = NULL;
	char delim[] = "-";

	memset(&respGetCbConfig, 0, sizeof(struct tresp_sms_get_cb_config));
	respGetCbConfig.result = SMS_DEVICE_FAILURE;

	ur = tcore_pending_ref_user_request(p);
	if (!ur) {
		dbg("no user_request");
		return;
	}

	respGetCbConfig.cbConfig.net3gppType = SMS_NETTYPE_3GPP;

	if (atResp->success) {
		dbg("Response OK");
		if (atResp->lines) {
			line = (char*)atResp->lines->data;
			if (line != NULL) {
				dbg("line is %s",line);
				tokens = tcore_at_tok_new(line);
				pResp = g_slist_nth_data(tokens, 0);
				if (pResp) {
					mode = atoi(pResp);
					respGetCbConfig.cbConfig.cbEnabled = mode;

					pResp = g_slist_nth_data(tokens, 1);
					if (pResp) {
						GSList *cb_tokens = NULL;
						char *cb_mid_str = NULL;
						int num_cb_tokens = 0;
						char *mid_tok = NULL;
						char *first_tok = NULL, *second_tok = NULL;

						// 0,1,5,320-478,922
						cb_mid_str = util_removeQuotes(pResp);
						cb_tokens = tcore_at_tok_new((const char *) cb_mid_str);

						g_free(cb_mid_str);

						num_cb_tokens = g_slist_length(cb_tokens);
						dbg("num_cb_tokens = %d", num_cb_tokens);

						if (num_cb_tokens == 0) {
							if (mode == 1) { // Enable all CBs
								respGetCbConfig.cbConfig.msgIdRangeCount = 1;
								respGetCbConfig.cbConfig.msgIDs[0].net3gpp.fromMsgId = 0x0000;
								respGetCbConfig.cbConfig.msgIDs[0].net3gpp.toMsgId = SMS_GSM_SMS_CBMI_LIST_SIZE_MAX + 1;
								respGetCbConfig.cbConfig.msgIDs[0].net3gpp.selected = TRUE;
									respGetCbConfig.result = SMS_SENDSMS_SUCCESS;
							} else { // all CBs disabled
								respGetCbConfig.cbConfig.msgIdRangeCount = 0;
								respGetCbConfig.cbConfig.msgIDs[0].net3gpp.selected = FALSE;
								respGetCbConfig.result = SMS_SENDSMS_SUCCESS;
							}
						} else {
							respGetCbConfig.cbConfig.msgIdRangeCount = 0;
							respGetCbConfig.cbConfig.msgIDs[0].net3gpp.selected = FALSE;
							respGetCbConfig.result = SMS_SENDSMS_SUCCESS;
						}

						for (i = 0; i < num_cb_tokens; i++) {
							respGetCbConfig.cbConfig.msgIDs[i].net3gpp.selected = TRUE;
							respGetCbConfig.cbConfig.msgIdRangeCount++;

							mid_tok = tcore_at_tok_nth(cb_tokens, i);
							first_tok = strtok(mid_tok, delim);
							second_tok = strtok(NULL, delim);

							if ((first_tok != NULL) && (second_tok != NULL)) { // mids in range (320-478)
								dbg("inside if mid_range");
								respGetCbConfig.cbConfig.msgIDs[i].net3gpp.fromMsgId = atoi(first_tok);
								respGetCbConfig.cbConfig.msgIDs[i].net3gpp.toMsgId = atoi(second_tok);
							} // single mid value (0,1,5, 922)
							else {
								respGetCbConfig.cbConfig.msgIDs[i].net3gpp.fromMsgId = atoi(mid_tok);
								respGetCbConfig.cbConfig.msgIDs[i].net3gpp.toMsgId = atoi(mid_tok);
							}
						}
					}
					}else {
						if (mode == 1) {
						respGetCbConfig.cbConfig.msgIdRangeCount = 1;
						respGetCbConfig.cbConfig.msgIDs[0].net3gpp.fromMsgId = 0x0000;
						respGetCbConfig.cbConfig.msgIDs[0].net3gpp.toMsgId = SMS_GSM_SMS_CBMI_LIST_SIZE_MAX + 1;
						respGetCbConfig.cbConfig.msgIDs[0].net3gpp.selected = TRUE;
						respGetCbConfig.result = SMS_SENDSMS_SUCCESS;
                    } else {
						respGetCbConfig.cbConfig.msgIdRangeCount = 0;
						respGetCbConfig.cbConfig.msgIDs[0].net3gpp.selected = FALSE;
						respGetCbConfig.result = SMS_SENDSMS_SUCCESS;
					}
				}
			} else {
					dbg("line is NULL");
			}
		} else {
			dbg("atresp->lines is NULL");
		}
	} else {
		dbg("RESPONSE NOK");
	}

	tcore_user_request_send_response(ur, TRESP_SMS_GET_CB_CONFIG, sizeof(struct tresp_sms_get_cb_config), &respGetCbConfig);

	if(tokens)
		tcore_at_tok_free(tokens);

	return;
}

static void on_response_set_cb_config(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	/*
	Response is expected in this format
	OK
	or
	+CMS ERROR: <err>
	*/

	UserRequest *ur;
	const TcoreATResponse *resp = data;
	int response = 0;
	const char *line = NULL;
	GSList *tokens=NULL;

	struct tresp_sms_set_cb_config respSetCbConfig = {0,};

	memset(&respSetCbConfig, 0, sizeof(struct tresp_sms_set_cb_config));

	ur = tcore_pending_ref_user_request(pending);
	respSetCbConfig.result = SMS_SENDSMS_SUCCESS;

	if (resp->success > 0) {
		dbg("RESPONSE OK");
	} else {
		dbg("RESPONSE NOK");
		line = (const char*)resp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
		  	dbg("err cause not specified or string corrupted");
		    	respSetCbConfig.result = SMS_DEVICE_FAILURE;
		} else {
			response = atoi(g_slist_nth_data(tokens, 0));
			/* TODO: CMEE error mapping is required. */
    			respSetCbConfig.result = SMS_DEVICE_FAILURE;
		}
	}
	if (!ur) {
		dbg("no user_request");
		return;
	}

	tcore_user_request_send_response(ur, TRESP_SMS_SET_CB_CONFIG, sizeof(struct tresp_sms_set_cb_config), &respSetCbConfig);

	if(tokens)
		tcore_at_tok_free(tokens);

	return;
}

static void on_response_set_mem_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_mem_status respSetMemStatus = {0,};
	const TcoreATResponse *resp = data;

	memset(&respSetMemStatus, 0, sizeof(struct tresp_sms_set_mem_status));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		respSetMemStatus.result = SMS_SENDSMS_SUCCESS;
	} else {
		dbg("RESPONSE NOK");
		respSetMemStatus.result = SMS_DEVICE_FAILURE;
	}

	ur = tcore_pending_ref_user_request(p);
	if (!ur) {
		dbg("no user_request");
		return;
	}

	tcore_user_request_send_response(ur, TRESP_SMS_SET_MEM_STATUS, sizeof(struct tresp_sms_set_mem_status), &respSetMemStatus);

	return;
}

static void on_response_set_msg_status(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_msg_status respMsgStatus = {0, };
	const TcoreATResponse *atResp = data;
	int response = 0, sw1 = 0, sw2 = 0;
	const char *line = NULL;
	char *pResp = NULL;
	GSList *tokens = NULL;

	dbg("Entry");

	memset(&respMsgStatus, 0, sizeof(struct tresp_sms_set_msg_status));
	respMsgStatus.result = SMS_DEVICE_FAILURE;

	ur = tcore_pending_ref_user_request(pending);

	if (atResp->success > 0) {
		dbg("RESPONSE OK");

		if (atResp->lines) {
			line = (const char *) atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL) {
				sw1 = atoi(pResp);
			} else {
				dbg("sw1 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL) {
				sw2 = atoi(pResp);
				if ((sw1 == AT_SW1_SUCCESS) && (sw2 == 0)) {
					respMsgStatus.result = SMS_SENDSMS_SUCCESS;
				}
			} else {
				dbg("sw2 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 3);

			if (pResp != NULL) {
				response = atoi(pResp);
				dbg("response is %s", response);
			}
		} else {
			dbg("No lines");
		}
	} else {
		dbg("RESPONSE NOK");
	}

        tcore_user_request_send_response(ur, TRESP_SMS_SET_MSG_STATUS , sizeof(struct tresp_sms_set_msg_status), &respMsgStatus);

	if(tokens)
		tcore_at_tok_free(tokens);

	dbg("Exit");
	return;
}

static void on_response_get_sms_params(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_get_params respGetParams ;
	const TcoreATResponse *atResp = data;
	int sw1 = 0, sw2 = 0;
	const char *line = NULL;
	char *pResp = NULL;
	GSList *tokens=NULL;
   	char *hexData = NULL;
    char *recordData = NULL;
    int i = 0;

	memset(&respGetParams, 0, sizeof(struct tresp_sms_get_params));
	respGetParams.result = SMS_DEVICE_FAILURE;

	ur = tcore_pending_ref_user_request(pending);

	if (atResp->success > 0) {
		dbg("RESPONSE OK");

		if (atResp->lines) {
			line = (const char *) atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL) {
				sw1 = atoi(pResp);
				dbg("sw1 is %d", sw1);
			} else {
				dbg("sw1 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL) {
				sw2 = atoi(pResp);
				dbg("sw2 is %d", sw2);
				if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
					respGetParams.result = SMS_SENDSMS_SUCCESS;
				}
			} else {
				dbg("sw2 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 2);
			if (pResp != NULL) {
				hexData = util_removeQuotes(pResp);

				recordData = util_hexStringToBytes(hexData);
				util_hex_dump("    ", strlen(hexData) / 2, recordData);

				respGetParams.paramsInfo.recordLen = strlen(hexData) / 2;

				util_sms_decode_smsParameters((unsigned char *) recordData, strlen(hexData) / 2, &(respGetParams.paramsInfo));
				respGetParams.result = SMS_SENDSMS_SUCCESS;

				for (i = 0; i < (int) respGetParams.paramsInfo.tpSvcCntrAddr.dialNumLen; i++)
					dbg("SCAddr = %d [%02x]", i, respGetParams.paramsInfo.tpSvcCntrAddr.diallingNum[i]);

				g_free(recordData);
				g_free(hexData);
			} else {
				dbg("No response");
			}
			tcore_at_tok_free(tokens);
		}
	} else {
		dbg("RESPONSE NOK");
	}

	tcore_user_request_send_response(ur, TRESP_SMS_GET_PARAMS, sizeof(struct tresp_sms_get_params), &respGetParams);

	dbg("Exit");
	return;
}

static void on_response_set_sms_params(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_params respSetParams = {0, };
	const TcoreATResponse *atResp = data;
	int sw1 =0 , sw2 = 0;
	const char *line = NULL;
	char *pResp = NULL;
	GSList *tokens=NULL;


	memset(&respSetParams, 0, sizeof(struct tresp_sms_set_params));
	ur = tcore_pending_ref_user_request(pending);

	respSetParams.result = SMS_DEVICE_FAILURE;

	if (atResp->success > 0) {
		dbg("RESPONSE OK");

		if (atResp->lines) {
			line = (const char *) atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL) {
				sw1 = atoi(pResp);
			} else {
				dbg("sw1 is NULL");
			}

			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL) {
				sw2 = atoi(pResp);
				if (((sw1 == AT_SW1_SUCCESS) && (sw2 == AT_SW2_SUCCESS)) || (sw1 == 0x91)) {
					respSetParams.result = SMS_SENDSMS_SUCCESS;
				}
			} else {
				dbg("sw2 is NULL");
			}
		} else {
			dbg("No lines");
		}
	} else {
		dbg("RESPONSE NOK");
	}

	tcore_user_request_send_response(ur, TRESP_SMS_SET_PARAMS , sizeof(struct tresp_sms_set_params), &respSetParams);

	if(tokens)
		tcore_at_tok_free(tokens);

	dbg("Exit");
	return;
}

static void on_response_get_paramcnt(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	struct tresp_sms_get_paramcnt respGetParamCnt = {0, };
	const TcoreATResponse *atResp = data;
	char *line = NULL , *pResp = NULL;
	int sw1 = 0 , sw2 = 0, *smsp_record_len = NULL;
	int sim_type = 0;
	GSList *tokens=NULL;
	CoreObject *co_sim = NULL;  //need this to get the sim type GSM/USIM
	TcorePlugin *plugin = NULL;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);
	respGetParamCnt.result = SMS_DEVICE_FAILURE;

	if (atResp->success > 0) {
		dbg("RESPONSE OK");

		if (atResp->lines) {
			line = (char *) atResp->lines->data;

			dbg("line is %s", line);

			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL) {
				sw1 = atoi(pResp);
			} else {
				dbg("sw1 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL) {
				sw2 = atoi(pResp);
				if ((sw1 == 144) && (sw2 == 0)) {
					respGetParamCnt.result = SMS_SENDSMS_SUCCESS;
				}
			} else {
				dbg("sw2 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 2);
			if (pResp != NULL) {
				char *hexData = NULL;
				char *recordData = NULL;
				hexData = util_removeQuotes(pResp);

				/*1. SIM access success case*/
				if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
					unsigned char tag_len = 0; /*	1 or 2 bytes ??? */
					int record_len = 0;
					char num_of_records = 0;
					unsigned char file_id_len = 0;
					unsigned short file_id = 0;
					unsigned short file_size = 0;
					unsigned short file_type = 0;
					unsigned short arr_file_id = 0;
					int arr_file_id_rec_num = 0;

					/*	handling only last 3 bits */
					unsigned char file_type_tag = 0x07;
					unsigned char *ptr_data;

					recordData = util_hexStringToBytes(hexData);
					util_hex_dump("    ", strlen(hexData)/2, recordData);

					ptr_data = (unsigned char *)recordData;

					co_sim = tcore_plugin_ref_core_object(tcore_pending_ref_plugin(p), CORE_OBJECT_TYPE_SIM);
					sim_type = tcore_sim_get_type(co_sim);
					dbg("sim type is %d",sim_type);

					if (sim_type ==  SIM_TYPE_USIM) {
						/*
						 ETSI TS 102 221 v7.9.0
				 			- Response Data
							 '62'	FCP template tag
							 - Response for an EF
							 '82'	M	File Descriptor
							 '83'	M	File Identifier
				 			'A5'	O	Proprietary information
							 '8A'	M	Life Cycle Status Integer
							 '8B', '8C' or 'AB'	C1	Security attributes
				 			'80'	M	File size
							 '81'	O	Total file size
				 			 '88'	O	Short File Identifier (SFI)
				 		*/

						/* rsim.res_len  has complete data length received  */

						/* FCP template tag - File Control Parameters tag*/
						if (*ptr_data == 0x62) {
							/* parse complete FCP tag*/
							/* increment to next byte */
							ptr_data++;
							tag_len = *ptr_data++;
							/* FCP file descriptor - file type, accessibility, DF, ADF etc*/
							if (*ptr_data == 0x82) {
									/* increment to next byte */
									ptr_data++;
									/*2 or 5 value*/
									ptr_data++;
							/*	unsigned char file_desc_len = *ptr_data++;*/
							/*	dbg("file descriptor length: [%d]", file_desc_len);*/
							/* TBD:  currently capture only file type : ignore sharable, non sharable, working, internal etc*/
							/* consider only last 3 bits*/
							file_type_tag = file_type_tag & (*ptr_data);

							switch (file_type_tag) {
								/* increment to next byte */
								ptr_data++;

								case 0x1:
									dbg("Getting FileType: [Transparent file type]");
									/* increment to next byte */
									ptr_data++;
									file_type = 0x01; 	//SIM_FTYPE_TRANSPARENT
									/*	data coding byte - value 21 */
									ptr_data++;
									break;

								case 0x2:
									dbg("Getting FileType: [Linear fixed file type]");
									/* increment to next byte */
									ptr_data++;
									/*	data coding byte - value 21 */
									ptr_data++;
									/*	2bytes */
									memcpy(&record_len, ptr_data, 2);
									/* swap bytes */
									record_len = SMS_SWAPBYTES16(record_len);
									ptr_data = ptr_data + 2;
									num_of_records = *ptr_data++;
									/* Data lossy conversation from enum (int) to unsigned char */
									file_type = 0x02;	// SIM_FTYPE_LINEAR_FIXED
									break;

								case 0x6:
									dbg(" Cyclic fixed file type");
									/* increment to next byte */
									ptr_data++;
									/*	data coding byte - value 21 */
									ptr_data++;
									/*	2bytes */
									memcpy(&record_len, ptr_data, 2);
									/* swap bytes  */
									record_len = SMS_SWAPBYTES16(record_len);
									ptr_data = ptr_data + 2;
									num_of_records = *ptr_data++;
									file_type = 0x04;	//SIM_FTYPE_CYCLIC
									break;

								default:
									dbg("not handled file type [0x%x]", *ptr_data);
									break;
								}
							} else {
								dbg("INVALID FCP received - DEbug!");
								g_free(hexData);
								g_free(recordData);
								tcore_at_tok_free(tokens);
								return;
							}

							/*File identifier - file id?? */ // 0x84,0x85,0x86 etc are currently ignored and not handled
							if (*ptr_data == 0x83) {
								/* increment to next byte */
								ptr_data++;
								file_id_len = *ptr_data++;
								memcpy(&file_id, ptr_data, file_id_len);
								/* swap bytes	 */
								file_id = SMS_SWAPBYTES16(file_id);
								ptr_data = ptr_data + 2;
								dbg("Getting FileID=[0x%x]", file_id);
							} else {
								dbg("INVALID FCP received - DEbug!");
								g_free(hexData);
								g_free(recordData);
								tcore_at_tok_free(tokens);
								return;
							}

							/*	proprietary information  */
							if (*ptr_data == 0xA5) {
								unsigned short prop_len;
								/* increment to next byte */
								ptr_data++;
								/* length */
								prop_len = *ptr_data;
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
										dbg("[RX] Operation State: DEACTIVATED");
										ptr_data++;
										break;

									case 0x05:
									case 0x07:
										dbg("[RX] Operation State: ACTIVATED");
										ptr_data++;
										break;

									default:
										dbg("[RX] DEBUG! LIFE CYCLE STATUS: [0x%x]",*ptr_data);
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
									arr_file_id = SMS_SWAPBYTES16(arr_file_id);
									ptr_data = ptr_data + 2;
									arr_file_id_rec_num = *ptr_data++;
								} else {
									/* if tag length is not 3 */
									/* ignoring bytes	*/
									//	ptr_data = ptr_data + 4;
									dbg("Useless security attributes, so jump to next tag");
									ptr_data = ptr_data + (*ptr_data + 1);
								}
							} else {
								dbg("INVALID FCP received[0x%x] - DEbug!", *ptr_data);
								g_free(hexData);
								g_free(recordData);
								tcore_at_tok_free(tokens);
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
								file_size = SMS_SWAPBYTES16(file_size);
								ptr_data = ptr_data + 2;
							} else {
								dbg("INVALID FCP received - DEbug!");
								g_free(hexData);
								g_free(recordData);
								tcore_at_tok_free(tokens);
								return;
							}

							/* total file size including structural info*/
							if (*ptr_data == 0x81) {
								int len;
								/* increment to next byte */
								ptr_data++;
								/* length */
								len = *ptr_data;
								/* ignored bytes */
								ptr_data = ptr_data + 3;
							} else {
								dbg("INVALID FCP received - DEbug!");
								/* 0x81 is optional tag?? check out! so do not return -1 from here! */
								/* return -1; */
							}
							/*short file identifier ignored*/
							if (*ptr_data == 0x88) {
								dbg("0x88: Do Nothing");
								/*DO NOTHING*/
							}
						} else {
							dbg("INVALID FCP received - DEbug!");
							g_free(hexData);
							g_free(recordData);
							tcore_at_tok_free(tokens);
							return;
						}
					} else if (sim_type == SIM_TYPE_GSM) {
						unsigned char gsm_specific_file_data_len = 0;
						/*	ignore RFU byte1 and byte2 */
						ptr_data++;
						ptr_data++;
						/*	file size */
						//file_size = p_info->response_len;
						memcpy(&file_size, ptr_data, 2);
						/* swap bytes */
						file_size = SMS_SWAPBYTES16(file_size);
						/*	parsed file size */
						ptr_data = ptr_data + 2;
						/*  file id  */
						memcpy(&file_id, ptr_data, 2);
						file_id = SMS_SWAPBYTES16(file_id);
						dbg(" FILE id --> [%x]", file_id);
						ptr_data = ptr_data + 2;
						/* save file type - transparent, linear fixed or cyclic */
						file_type_tag = (*(ptr_data + 7));

						switch (*ptr_data) {
							case 0x0:
								/* RFU file type */
								dbg(" RFU file type- not handled - Debug!");
								break;

							case 0x1:
								/* MF file type */
								dbg(" MF file type - not handled - Debug!");
								break;

							case 0x2:
								/* DF file type */
								dbg(" DF file type - not handled - Debug!");
								break;

							case 0x4:
								/* EF file type */
								dbg(" EF file type [%d] ", file_type_tag);
								/*	increment to next byte */
								ptr_data++;

								if (file_type_tag == 0x00 || file_type_tag == 0x01) {
									/* increament to next byte as this byte is RFU */
									ptr_data++;
									file_type =
											(file_type_tag == 0x00) ? 0x01 : 0x02; // SIM_FTYPE_TRANSPARENT:SIM_FTYPE_LINEAR_FIXED;
								} else {
									/* increment to next byte */
									ptr_data++;
									/*	For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
									/* the INCREASE command is allowed on the selected cyclic file. */
									file_type = 0x04;	// SIM_FTYPE_CYCLIC;
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
								ptr_data++;
								/*	byte 14 - structure of EF - transparent or linear or cyclic , already saved above */
								ptr_data++;
								/* byte 15 - length of record for linear and cyclic , for transparent it is set to 0x00. */
								record_len = *ptr_data;
								dbg("record length[%d], file size[%d]", record_len, file_size);

								if (record_len != 0)
									num_of_records = (file_size / record_len);

								dbg("Number of records [%d]", num_of_records);
								break;

							default:
								dbg(" not handled file type");
								break;
						}
					} else {
						dbg(" Card Type - UNKNOWN  [%d]", sim_type);
					}

					dbg("EF[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]", file_id, file_size, file_type, num_of_records, record_len);

					respGetParamCnt.recordCount = num_of_records;
					respGetParamCnt.result = SMS_SUCCESS;

					//TO Store smsp record length in the property
					plugin = tcore_pending_ref_plugin(p);
					smsp_record_len = tcore_plugin_ref_property(plugin, "SMSPRECORDLEN");
					memcpy(smsp_record_len, &record_len, sizeof(int));

					g_free(recordData);
					g_free(hexData);
				} else {
					/*2. SIM access fail case*/
					dbg("SIM access fail");
					respGetParamCnt.result = SMS_UNKNOWN;
				}
			} else {
				dbg("presp is NULL");
			}
		} else {
			dbg("line is blank");
		}
	} else {
		dbg("RESPONSE NOK");
	}

	tcore_user_request_send_response(ur, TRESP_SMS_GET_PARAMCNT, sizeof(struct tresp_sms_get_paramcnt), &respGetParamCnt);

	if(tokens)
		tcore_at_tok_free(tokens);

	dbg("Exit");
	return;
}

static void _response_get_efsms_data(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	UserRequest *dup_ur = NULL;
	struct tresp_sms_set_msg_status resp_msg_status = {0,};
	const struct treq_sms_set_msg_status *req_msg_status = NULL ;

	const TcoreATResponse *resp = data;
	char *encoded_data = NULL;
	char msg_status = 0;
        char *pResp = NULL;
        GSList *tokens=NULL;
	const char *line = NULL;
	int sw1 = 0;
	int sw2 = 0;

	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	gchar *cmd_str = NULL;

	ur = tcore_pending_ref_user_request(p);

	req_msg_status = tcore_user_request_ref_data(ur, NULL);

	resp_msg_status.result = SMS_DEVICE_FAILURE;

	hal = tcore_object_get_hal(tcore_pending_ref_core_object(pending));
	dbg("msgStatus: [%x], index [%x]", req_msg_status->msgStatus, req_msg_status->index);

	if (resp->success <= 0) {
		goto OUT;
	}

	{
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 3) {
				msg("invalid message");
				goto OUT;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));
		pResp = g_slist_nth_data(tokens, 2);

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			switch (req_msg_status->msgStatus) {
				case SMS_STATUS_READ:
					msg_status = 0x01;
					break;

				case SMS_STATUS_UNREAD:
					msg_status = 0x03;
					break;

				case SMS_STATUS_UNSENT:
					msg_status = 0x07;
					break;

				case SMS_STATUS_SENT:
					msg_status = 0x05;
					break;

				case SMS_STATUS_DELIVERED:
					msg_status = 0x1D;
					break;

				case SMS_STATUS_DELIVERY_UNCONFIRMED:
					msg_status = 0xD;
					break;

				case SMS_STATUS_MESSAGE_REPLACED:
				case SMS_STATUS_RESERVED:
				default:
					msg_status = 0x03;
					break;
			}

			encoded_data = util_removeQuotes(pResp);

			//overwrite Status byte information
			util_byte_to_hex((const char *)&msg_status, (char *)encoded_data, 1);

			//Update EF-SMS with just status byte overwritten, rest 175 bytes are same as received in read information
			cmd_str = g_strdup_printf("AT+CRSM=220,28476,%d, 4, %d, \"%s\"", (req_msg_status->index+1), PDU_LEN_MAX, encoded_data);
			atreq = tcore_at_request_new((const char *)cmd_str, "+CRSM", TCORE_AT_SINGLELINE);
			pending = tcore_pending_new(tcore_pending_ref_core_object(pending), 0);
			if (NULL == cmd_str || NULL == atreq || NULL == pending) {
				err("Out of memory. Unable to proceed");
				dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

				//free memory we own
				g_free(cmd_str);
				g_free(encoded_data);
				util_sms_free_memory(atreq);
				util_sms_free_memory(pending);

				goto OUT;
			}

			util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

			dup_ur = tcore_user_request_ref(ur);

			tcore_pending_set_request_data(pending, 0, atreq);
			tcore_pending_set_response_callback(pending, on_response_set_msg_status, NULL);
			tcore_pending_link_user_request(pending, dup_ur);
			tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
			tcore_hal_send_request(hal, pending);

			g_free(cmd_str);
			g_free(encoded_data);
		}
	}

OUT:
	if(tokens)
		tcore_at_tok_free(tokens);

	tcore_user_request_send_response(ur, TRESP_SMS_SET_MSG_STATUS , sizeof(struct tresp_sms_set_msg_status), &msg_status);

	dbg("Exit");

	return;
}

/*=============================================================
							Requests
==============================================================*/
static TReturn send_umts_msg(CoreObject *co_sms, UserRequest *ur)
{
	const struct treq_sms_send_umts_msg *send_msg;
	const unsigned char *tpdu_byte_data, *sca_byte_data;
	int tpdu_byte_len, pdu_byte_len;
	char buf[HEX_PDU_LEN_MAX];
	char pdu[PDU_LEN_MAX];
	char *cmd_str;
	int pdu_hex_len, mms;
	TReturn ret;

	dbg("Enter");

	send_msg = tcore_user_request_ref_data(ur, NULL);

	tpdu_byte_data = send_msg->msgDataPackage.tpduData;
	sca_byte_data = send_msg->msgDataPackage.sca;


	/* TPDU length is in byte */
	tpdu_byte_len = send_msg->msgDataPackage.msgLength;

	/* Use same Radio Resource Channel */
	mms = send_msg->more;

	dbg("TDPU length: [%d]", tpdu_byte_len);
	dbg("SCA semi-octet length: [%d]", sca_byte_data[0]);

	/* Prepare PDU for hex encoding */
	pdu_byte_len = tcore_util_pdu_encode(sca_byte_data, tpdu_byte_data,
						tpdu_byte_len, pdu);

	pdu_hex_len = (int) tcore_util_encode_hex((unsigned char *) pdu,
						pdu_byte_len, buf);

	dbg("PDU hexadecimal length: [%d]", pdu_hex_len);

	if (mms > 0) {
		cmd_str = g_strdup_printf("AT+CMMS=%d", mms);

		ret = tcore_prepare_and_send_at_request(co_sms, cmd_str, NULL,
					TCORE_AT_NO_RESULT, NULL, NULL, NULL,
					on_confirmation_sms_message_send,
					NULL);
		if (ret != TCORE_RETURN_SUCCESS) {
			err("Failed to prepare and send AT request");
			goto error;
		}

		g_free(cmd_str);
	}

	cmd_str = g_strdup_printf("AT+CMGS=%d\r%s\x1A", tpdu_byte_len, buf);

	ret = tcore_prepare_and_send_at_request(co_sms, cmd_str, "+CMGS:",
				TCORE_AT_SINGLELINE, ur,
				on_response_send_umts_msg, NULL,
				on_confirmation_sms_message_send, NULL);
	if (ret != TCORE_RETURN_SUCCESS)
		err("Failed to prepare and send AT request");

error:
	g_free(cmd_str);

	dbg("Exit");

	return ret;
}

static TReturn read_msg(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_read_msg *readMsg = NULL;

	dbg("Entry");

	readMsg = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == readMsg || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("readMsg: [%p], hal: [%p]", readMsg, hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}

	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	dbg("index: [%d]", readMsg->index);

	cmd_str = g_strdup_printf("AT+CMGR=%d", (readMsg->index + 1)); //IMC index is one ahead of TAPI
	atreq = tcore_at_request_new((const char *)cmd_str, "+CMGR", TCORE_AT_PDU);
	pending = tcore_pending_new(obj, 0);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_read_msg, (void *)(uintptr_t)(readMsg->index)); //storing index as user data for response
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn save_msg(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_save_msg *saveMsg = NULL;
	int ScLength = 0, pdu_len = 0, stat = 0;
	char buf[2*(SMS_SMSP_ADDRESS_LEN+SMS_SMDATA_SIZE_MAX)+1] = {0};
	char *hex_pdu = NULL;

	dbg("Entry");

	saveMsg = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == saveMsg || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("saveMsg: [%p], hal: [%p]", saveMsg, hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("msgStatus: %x, msgLength: [%d]", saveMsg->msgStatus, saveMsg->msgDataPackage.msgLength);
	util_hex_dump("    ", (SMS_SMDATA_SIZE_MAX+1), (void *)saveMsg->msgDataPackage.tpduData);
	util_hex_dump("    ", SMS_SMSP_ADDRESS_LEN, (void *)saveMsg->msgDataPackage.sca);

	switch (saveMsg->msgStatus) {
		case SMS_STATUS_READ:
			stat = AT_REC_READ;
			break;

		case SMS_STATUS_UNREAD:
			stat = AT_REC_UNREAD;
			break;

		case SMS_STATUS_SENT:
			stat = AT_STO_SENT;
			break;

		case SMS_STATUS_UNSENT:
			stat = AT_STO_UNSENT;
			break;

		default:
			err("Invalid msgStatus");
			dbg("Exit");
			return TCORE_RETURN_EINVAL;
	}

	if ((saveMsg->msgDataPackage.msgLength > 0)
		&& (saveMsg->msgDataPackage.msgLength <= SMS_SMDATA_SIZE_MAX)) {
		ScLength = (int)saveMsg->msgDataPackage.sca[0];

		buf[0] = ScLength;
		dbg("ScLength = %d", ScLength);

		if(ScLength == 0) {
			buf[0] = 0;
		} else {
			memcpy(&buf[1],  saveMsg->msgDataPackage.sca, ScLength);
		}

		memcpy(&buf[ScLength+1],  saveMsg->msgDataPackage.tpduData, saveMsg->msgDataPackage.msgLength);

		pdu_len= saveMsg->msgDataPackage.msgLength + ScLength + 1;
		dbg("pdu_len: [%d]", pdu_len);

		hex_pdu = malloc(pdu_len * 2 + 1);
		util_hex_dump("    ", sizeof(buf), (void *)buf);

		memset (hex_pdu, 0x00, pdu_len * 2 + 1);

		util_byte_to_hex((const char *)buf, (char *)hex_pdu, pdu_len);

		//AT+CMGW=<length>[,<stat>]<CR>PDU is given<ctrl-Z/ESC>
		cmd_str = g_strdup_printf("AT+CMGW=%d,%d%s%s\x1A", saveMsg->msgDataPackage.msgLength, stat, "\r", hex_pdu);
		pending = tcore_pending_new(obj, 0);
		atreq = tcore_at_request_new((const char *)cmd_str, "+CMGW", TCORE_AT_SINGLELINE);

		if(NULL == cmd_str || NULL == atreq || NULL == pending) {
			err("Out of memory. Unable to proceed");
			dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

			//free memory we own
			g_free(cmd_str);
			util_sms_free_memory(atreq);
			util_sms_free_memory(pending);
			util_sms_free_memory(hex_pdu);

			dbg("Exit");
			return TCORE_RETURN_ENOMEM;
		}

		util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

		tcore_pending_set_request_data(pending, 0, atreq);
		tcore_pending_set_response_callback(pending, on_response_sms_save_msg, NULL);
		tcore_pending_link_user_request(pending, ur);
		tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
		tcore_hal_send_request(hal, pending);

		g_free(cmd_str);
		free(hex_pdu);

		dbg("Exit");
		return TCORE_RETURN_SUCCESS;
	}

	err("Invalid Data len");
	dbg("Exit");
	return TCORE_RETURN_SMS_INVALID_DATA_LEN;
}

static TReturn delete_msg(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_delete_msg *delete_msg = NULL;

	dbg("Entry");

	delete_msg = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == delete_msg || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("deleteMsg: [%p], hal: [%p]", delete_msg, hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}

	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("index: %d", delete_msg->index);

	if (delete_msg->index == -1) {
		cmd_str = g_strdup_printf("AT+CMGD=0,4"); // Delete All Messages
	} else {
		cmd_str = g_strdup_printf("AT+CMGD=%d,0", delete_msg->index + 1); // Delete specified index
	}

	pending = tcore_pending_new(obj, 0);
	atreq = tcore_at_request_new((const char *)cmd_str, NULL, TCORE_AT_NO_RESULT);
	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_sms_delete_msg, (void *) (uintptr_t) (delete_msg->index)); // storing index as user data for response
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_stored_msg_cnt(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;

	dbg("Entry");

	hal = tcore_object_get_hal(obj);
	if (NULL == hal) {
		err("NULL HAL. Unable to proceed");

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}

	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	cmd_str = g_strdup_printf("AT+CPMS=\"SM\"");
	pending = tcore_pending_new(obj, 0);
	atreq = tcore_at_request_new((const char *)cmd_str, "+CPMS", TCORE_AT_SINGLELINE);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_stored_msg_cnt, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_sca(CoreObject *obj, UserRequest *ur)
{
	gchar * cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;

	dbg("Entry");

	hal = tcore_object_get_hal(obj);
	if (NULL == hal) {
		err("HAL NULL. Unable to proceed");

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	cmd_str = g_strdup_printf("AT+CSCA?");
	pending = tcore_pending_new(obj, 0);
	atreq = tcore_at_request_new((const char *)cmd_str, "+CSCA", TCORE_AT_SINGLELINE);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_sca, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_sca(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_sca *setSca = NULL;
	int addrType = 0;

	dbg("Entry");

	setSca = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == setSca || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("setSca: [%p], hal: [%p]", setSca, hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("dialNumLen: %u, typeOfNum: %d, numPlanId: %d, ", setSca->scaInfo.dialNumLen, setSca->scaInfo.typeOfNum, setSca->scaInfo.numPlanId);

	util_hex_dump("    ", (SMS_SMSP_ADDRESS_LEN+1), (void *)setSca->scaInfo.diallingNum);

	addrType = ((setSca->scaInfo.typeOfNum << 4) | setSca->scaInfo.numPlanId) | 0x80;

	cmd_str = g_strdup_printf("AT+CSCA=\"%s\",%d", setSca->scaInfo.diallingNum, addrType);
	pending = tcore_pending_new(obj, 0);
	atreq = tcore_at_request_new((const char *)cmd_str, NULL, TCORE_AT_NO_RESULT);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_set_sca, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_cb_config(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;

	dbg("Entry");

	hal = tcore_object_get_hal(obj);
	if (NULL == hal) {
		err("NULL HAL. Unable to proceed");

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	cmd_str = g_strdup_printf("AT+CSCB?");
	pending = tcore_pending_new(obj, 0);
	atreq = tcore_at_request_new((const char *)cmd_str, "+CSCB", TCORE_AT_SINGLELINE);
	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_cb_config, NULL);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_cb_config(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	gchar *mids_str = NULL;
	GString *mids_GString = NULL;

	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_cb_config *setCbConfig = NULL;
	int ctr1= 0, ctr2 =0;
	unsigned short appendMsgId = 0;

	dbg("Entry");

	setCbConfig = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == setCbConfig || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("setCbConfig: [%p], hal: [%p]", setCbConfig, hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("bCBEnabled: %d,  msgIdCount: %d", setCbConfig->cbEnabled, setCbConfig->msgIdRangeCount);

	if (setCbConfig->cbEnabled == 2) { //Enable all CBS
		cmd_str = g_strdup_printf("AT+CSCB=1");
	} else if ((setCbConfig->cbEnabled == 1) && (setCbConfig->msgIdRangeCount == 0)) { // Special case: Enable all CBS
		cmd_str = g_strdup_printf("AT+CSCB=1");
	} else if (setCbConfig->cbEnabled == 0) {//AT+CSCB=0: Disable CBS
		cmd_str = g_strdup_printf("AT+CSCB=0");
	} else {
		mids_GString = g_string_new("AT+CSCB=0,\"");

		for(ctr1 = 0; ctr1 < setCbConfig->msgIdRangeCount; ctr1++ ) {
			if( setCbConfig->msgIDs[ctr1].net3gpp.selected == FALSE )
				continue;

			if( SMS_GSM_SMS_CBMI_LIST_SIZE_MAX <= (setCbConfig->msgIDs[ctr1].net3gpp.toMsgId - setCbConfig->msgIDs[ctr1].net3gpp.fromMsgId) ) {
				mids_GString = g_string_new("AT+CSCB=1");
				break;
			}

			appendMsgId = setCbConfig->msgIDs[ctr1].net3gpp.fromMsgId;

			for( ctr2 = 0; (ctr2 <= ((setCbConfig->msgIDs[ctr1].net3gpp.toMsgId) - (setCbConfig->msgIDs[ctr1].net3gpp.fromMsgId))); ctr2++ ) {
				dbg( "%x", appendMsgId);
				mids_GString = g_string_append(mids_GString, g_strdup_printf("%d", appendMsgId));

				if (ctr2 == ((setCbConfig->msgIDs[ctr1].net3gpp.toMsgId) - (setCbConfig->msgIDs[ctr1].net3gpp.fromMsgId))) {
					mids_GString = g_string_append(mids_GString, "\""); //Mids string termination
				} else {
					mids_GString = g_string_append(mids_GString, ",");
				}

				appendMsgId++;
			}
 		}
		mids_str = g_string_free(mids_GString, FALSE);
	 	cmd_str = g_strdup_printf("%s", mids_str);
		g_free(mids_str);
	}

	pending = tcore_pending_new(obj, 0);
	atreq = tcore_at_request_new((const char *)cmd_str, NULL, TCORE_AT_NO_RESULT);
	if(NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_set_cb_config, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_mem_status(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_mem_status *setMemStatus = NULL;
	int memoryStatus = 0;

	dbg("Entry");

	setMemStatus = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == setMemStatus || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("setMemStatus: [%p], hal: [%p]", setMemStatus, hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("memory_status: %d", setMemStatus->memory_status);

	if(setMemStatus->memory_status < SMS_PDA_MEMORY_STATUS_AVAILABLE
		|| setMemStatus->memory_status > SMS_PDA_MEMORY_STATUS_FULL) {
		err("Invalid memory_status");

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}

	switch (setMemStatus->memory_status) {
		case SMS_PDA_MEMORY_STATUS_AVAILABLE:
			memoryStatus = AT_MEMORY_AVAILABLE;
			break;

		case SMS_PDA_MEMORY_STATUS_FULL:
			memoryStatus = AT_MEMORY_FULL;
			break;

		default:
			err("Invalid memory_status");
			dbg("Exit");
			return TCORE_RETURN_EINVAL;
	}

	cmd_str = g_strdup_printf("AT+XTESM=%d", memoryStatus);
	pending = tcore_pending_new(obj, 0);
	atreq = tcore_at_request_new((const char *)cmd_str, NULL, TCORE_AT_NO_RESULT);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_set_mem_status, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_delivery_report(CoreObject *obj, UserRequest *ur)
{
	struct tresp_sms_set_delivery_report respSetDeliveryReport = {0,};

	respSetDeliveryReport.result = SMS_SUCCESS;

	dbg("Entry");
	if(FALSE == tcore_hal_get_power_state(tcore_object_get_hal(obj))){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	dbg("CP takes care of sending SMS ack to network for all classes of SMS. Sending default success.");

	tcore_user_request_send_response(ur, TRESP_SMS_SET_DELIVERY_REPORT, sizeof(struct tresp_sms_set_delivery_report), &respSetDeliveryReport);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_msg_status(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_msg_status *msg_status = NULL;

	dbg("Entry");
	hal = tcore_object_get_hal(obj);
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}
	msg_status = tcore_user_request_ref_data(ur, NULL);

	cmd_str = g_strdup_printf("AT+CRSM=178,28476,%d,4,%d", (msg_status->index+1), PDU_LEN_MAX);
	atreq = tcore_at_request_new((const char *)cmd_str, "+CRSM", TCORE_AT_SINGLELINE);
	pending = tcore_pending_new(obj, 0);
	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, _response_get_efsms_data, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_sms_params(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_get_params *getSmsParams = NULL;
	int record_len = 0 , *smsp_record_len = NULL;

	dbg("Entry");

	getSmsParams = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == getSmsParams || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("getSmsParams: [%p], hal: [%p]", getSmsParams, hal);

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	smsp_record_len = tcore_plugin_ref_property(tcore_object_ref_plugin(obj), "SMSPRECORDLEN");
	record_len = *smsp_record_len;
	dbg("record len from property %d", record_len);

	//AT+CRSM=command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]
	cmd_str = g_strdup_printf("AT+CRSM=178,28482,%d,4,%d", (getSmsParams->index + 1), record_len);

	dbg("cmd_str is %s",cmd_str);

	atreq = tcore_at_request_new((const char *)cmd_str, "+CRSM", TCORE_AT_SINGLELINE);
	pending = tcore_pending_new(obj, 0);
	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_sms_params, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_sms_params(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	char *encoded_data = NULL;
	unsigned char *temp_data = NULL;
	int SMSPRecordLen = 0;

	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_params *setSmsParams = NULL;
	int encoded_data_len = 0;

	dbg("Entry");

	setSmsParams = tcore_user_request_ref_data(ur, NULL);
	hal = tcore_object_get_hal(obj);
	if (NULL == setSmsParams || NULL == hal) {
		err("NULL input. Unable to proceed");
		dbg("setSmsParams: [%p], hal: [%p]", setSmsParams, hal);
		return FALSE;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	//EFsmsp file size is 28 +Y bytes (Y is alpha id size)
	SMSPRecordLen = 28 + setSmsParams->params.alphaIdLen;
	temp_data = calloc(SMSPRecordLen,1);
	encoded_data = calloc(SMSPRecordLen*2 + 1,1);

	_tcore_util_sms_encode_smsParameters(&(setSmsParams->params), temp_data, SMSPRecordLen);

	util_byte_to_hex((const char *)temp_data, (char *)encoded_data,SMSPRecordLen);

	encoded_data_len = ((SMSPRecordLen) * 2);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

        dbg("alpha id len %d encoded data %s. Encoded data len %d",setSmsParams->params.alphaIdLen,encoded_data, encoded_data_len);
        cmd_str = g_strdup_printf("AT+CRSM=220,28482,%d,4,%d,\"%s\"",(setSmsParams->params.recordIndex+1),SMSPRecordLen,encoded_data);

        dbg("cmd str is %s",cmd_str);
        atreq = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("Out of memory. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		util_sms_free_memory(temp_data);
		util_sms_free_memory(encoded_data);

		dbg("Exit");
		return TCORE_RETURN_ENOMEM;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0,atreq);
	tcore_pending_set_response_callback(pending, on_response_set_sms_params, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);
	util_sms_free_memory(temp_data);
	util_sms_free_memory(encoded_data);

	return TCORE_RETURN_SUCCESS;
}

static TReturn get_paramcnt(CoreObject *obj, UserRequest *ur)
{
	gchar *cmd_str = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;

	dbg("Entry");

	hal = tcore_object_get_hal(obj);
	if (NULL == hal) {
		err("NULL HAL. Unable to proceed");

		dbg("Exit");
		return TCORE_RETURN_EINVAL;
	}
	if(FALSE == tcore_hal_get_power_state(hal)){
		dbg("cp not ready/n");
		return TCORE_RETURN_ENOSYS;
	}

	//AT+CRSM=command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]
	cmd_str = g_strdup_printf("AT+CRSM=192,28482");
	atreq = tcore_at_request_new((const char *)cmd_str, "+CRSM", TCORE_AT_SINGLELINE);
	pending = tcore_pending_new(obj, 0);

	if (NULL == cmd_str || NULL == atreq || NULL == pending) {
		err("NULL pointer. Unable to proceed");
		dbg("cmd_str: [%p], atreq: [%p], pending: [%p]", cmd_str, atreq, pending);

		//free memory we own
		g_free(cmd_str);
		util_sms_free_memory(atreq);
		util_sms_free_memory(pending);

		dbg("Exit");
		return TCORE_RETURN_FAILURE;
	}

	util_hex_dump("    ", strlen(cmd_str), (void *)cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_paramcnt, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	g_free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_sms_operations sms_ops = {
	.send_umts_msg = send_umts_msg,
	.read_msg = read_msg,
	.save_msg = save_msg,
	.delete_msg = delete_msg,
	.get_stored_msg_cnt = get_stored_msg_cnt,
	.get_sca = get_sca,
	.set_sca = set_sca,
	.get_cb_config = get_cb_config,
	.set_cb_config = set_cb_config,
	.set_mem_status = set_mem_status,
	.get_pref_brearer = NULL,
	.set_pref_brearer = NULL,
	.set_delivery_report = set_delivery_report,
	.set_msg_status = set_msg_status,
	.get_sms_params = get_sms_params,
	.set_sms_params = set_sms_params,
	.get_paramcnt = get_paramcnt,
};

gboolean s_sms_init(TcorePlugin *cp, CoreObject *co_sms)
{
	int *smsp_record_len;
	dbg("Entry");

	/* Override SMS Operations */
	tcore_sms_override_ops(co_sms, &sms_ops);

	/* Registering for SMS notifications */
	tcore_object_override_callback(co_sms, "+CMTI:", on_event_class2_sms_incom_msg, NULL);
	tcore_object_override_callback(co_sms, "\e+CMT:", on_event_sms_incom_msg, NULL);

	tcore_object_override_callback(co_sms, "\e+CDS", on_event_sms_incom_msg, NULL);
	tcore_object_override_callback(co_sms, "+XSMSMMSTAT", on_event_sms_memory_status, NULL);
	tcore_object_override_callback(co_sms, "+CMS", on_event_sms_memory_status, NULL);

	tcore_object_override_callback(co_sms, "+CBMI:", on_event_sms_cb_incom_msg, NULL);
	tcore_object_override_callback(co_sms, "\e+CBM:", on_event_sms_cb_incom_msg, NULL);

	/* Storing SMSP record length */
	smsp_record_len = g_new0(int, 1);
	tcore_plugin_link_property(cp, "SMSPRECORDLEN", smsp_record_len);

	dbg("Exit");
	return TRUE;
}

void s_sms_exit(TcorePlugin *cp, CoreObject *co_sms)
{
	int *smsp_record_len;

	smsp_record_len = tcore_plugin_ref_property(cp, "SMSPRECORDLEN");
	g_free(smsp_record_len);

	dbg("Exit");
}
