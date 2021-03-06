/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Ankit Jogi <ankit.jogi@samsung.com>
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
#include <co_sim.h>
#include <storage.h>
#include <user_request.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_sim.h"

#define ID_RESERVED_AT 0x0229

#define SWAPBYTES16(x) \
	{ \
		unsigned short int data = *(unsigned short int *) &(x);	\
		data = ((data & 0xff00) >> 8) |	   \
			   ((data & 0x00ff) << 8);	   \
		*(unsigned short int *) &(x) = data;	  \
	}

enum s_sim_file_type_e {
	SIM_FTYPE_DEDICATED = 0x00, /**< Dedicated */
	SIM_FTYPE_TRANSPARENT = 0x01, /**< Transparent -binary type*/
	SIM_FTYPE_LINEAR_FIXED = 0x02, /**< Linear fixed - record type*/
	SIM_FTYPE_CYCLIC = 0x04, /**< Cyclic - record type*/
	SIM_FTYPE_INVALID_TYPE = 0xFF /**< Invalid type */
};

enum s_sim_sec_op_e {
	SEC_PIN1_VERIFY,
	SEC_PIN2_VERIFY,
	SEC_PUK1_VERIFY,
	SEC_PUK2_VERIFY,
	SEC_SIM_VERIFY,
	SEC_ADM_VERIFY,
	SEC_PIN1_CHANGE,
	SEC_PIN2_CHANGE,
	SEC_PIN1_ENABLE,
	SEC_PIN1_DISABLE,
	SEC_PIN2_ENABLE,
	SEC_PIN2_DISABLE, // 10
	SEC_SIM_ENABLE,
	SEC_SIM_DISABLE,
	SEC_NET_ENABLE,
	SEC_NET_DISABLE,
	SEC_NS_ENABLE,
	SEC_NS_DISABLE,
	SEC_SP_ENABLE,
	SEC_SP_DISABLE,
	SEC_CP_ENABLE,
	SEC_CP_DISABLE, // 20
	SEC_FDN_ENABLE,
	SEC_FDN_DISABLE,
	SEC_PIN1_STATUS,
	SEC_PIN2_STATUS,
	SEC_FDN_STATUS,
	SEC_NET_STATUS,
	SEC_NS_STATUS,
	SEC_SP_STATUS,
	SEC_CP_STATUS,
	SEC_SIM_STATUS,
	SEC_SIM_UNKNOWN = 0xff
};

struct s_sim_property {
	gboolean b_valid; /**< Valid or not */
	enum tel_sim_file_id file_id; /**< File identifier */
	enum s_sim_file_type_e file_type; /**< File type and structure */
	int rec_length; /**< Length of one record in file */
	int rec_count; /**< Number of records in file */
	int data_size; /**< File size */
	int current_index; /**< current index to read */
	enum tel_sim_status first_recv_status;
	enum s_sim_sec_op_e current_sec_op; /**< current index to read */
	struct tresp_sim_read files;
};

static void _next_from_get_file_info(CoreObject *o, UserRequest *ur, enum tel_sim_file_id ef, enum tel_sim_access_result rt);
static void _next_from_get_file_data(CoreObject *o, UserRequest *ur, enum tel_sim_access_result rt, int decode_ret);
static gboolean _get_sim_type(CoreObject *o);
static TReturn _get_file_info(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef);
static gboolean _get_file_data(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int offset, const int length);
static gboolean _get_file_record(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int index, const int length);
static void _sim_status_update(CoreObject *o, enum tel_sim_status sim_status);
static void on_confirmation_sim_message_send(TcorePending *p, gboolean result, void *user_data);  // from Kernel
extern gboolean util_byte_to_hex(const char *byte_pdu, char *hex_pdu, int num_bytes);

static void on_confirmation_sim_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("on_confirmation_sim_message_send - msg out from queue.\n");

	if (result == FALSE) {
		/* Fail */
		dbg("SEND FAIL");
	} else {
		dbg("SEND OK");
	}
}

static enum tcore_response_command _find_resp_command(UserRequest *ur)
{
	enum tcore_request_command command;

	command = tcore_user_request_get_command(ur);
	switch (command) {
	case TREQ_SIM_VERIFY_PINS:
		return TRESP_SIM_VERIFY_PINS;
		break;

	case TREQ_SIM_VERIFY_PUKS:
		return TRESP_SIM_VERIFY_PUKS;
		break;

	case TREQ_SIM_CHANGE_PINS:
		return TRESP_SIM_CHANGE_PINS;
		break;

	case TREQ_SIM_GET_FACILITY_STATUS:
		return TRESP_SIM_GET_FACILITY_STATUS;
		break;

	case TREQ_SIM_DISABLE_FACILITY:
		return TRESP_SIM_DISABLE_FACILITY;
		break;

	case TREQ_SIM_ENABLE_FACILITY:
		return TRESP_SIM_ENABLE_FACILITY;
		break;

	case TREQ_SIM_GET_LOCK_INFO:
		return TRESP_SIM_GET_LOCK_INFO;
		break;

	case TREQ_SIM_TRANSMIT_APDU:
		return TRESP_SIM_TRANSMIT_APDU;
		break;

	case TREQ_SIM_GET_ATR:
		return TRESP_SIM_GET_ATR;
		break;

	case TREQ_SIM_GET_ECC:
		return TRESP_SIM_GET_ECC;
		break;

	case TREQ_SIM_GET_LANGUAGE:
		return TRESP_SIM_GET_LANGUAGE;
		break;

	case TREQ_SIM_SET_LANGUAGE:
		return TRESP_SIM_SET_LANGUAGE;
		break;

	case TREQ_SIM_GET_ICCID:
		return TRESP_SIM_GET_ICCID;
		break;

	case TREQ_SIM_GET_MAILBOX:
		return TRESP_SIM_GET_MAILBOX;
		break;

	case TREQ_SIM_GET_CALLFORWARDING:
		return TRESP_SIM_GET_CALLFORWARDING;
		break;

	case TREQ_SIM_SET_CALLFORWARDING:
		return TRESP_SIM_SET_CALLFORWARDING;
		break;

	case TREQ_SIM_GET_MESSAGEWAITING:
		return TRESP_SIM_GET_MESSAGEWAITING;
		break;

	case TREQ_SIM_GET_CPHS_INFO:
		return TRESP_SIM_GET_CPHS_INFO;
		break;

	case TREQ_SIM_GET_MSISDN:
		return TRESP_SIM_GET_MSISDN;
		break;

	case TREQ_SIM_GET_SPN:
		return TRESP_SIM_GET_SPN;
		break;

	case TREQ_SIM_GET_SPDI:
		return TRESP_SIM_GET_SPDI;
		break;

	case TREQ_SIM_GET_OPL:
		return TRESP_SIM_GET_OPL;
		break;

	case TREQ_SIM_GET_PNN:
		return TRESP_SIM_GET_PNN;
		break;

	case TREQ_SIM_GET_CPHS_NETNAME:
		return TRESP_SIM_GET_CPHS_NETNAME;
		break;

	case TREQ_SIM_GET_OPLMNWACT:
		return TRESP_SIM_GET_OPLMNWACT;
		break;

	case TREQ_SIM_REQ_AUTHENTICATION:
		return TRESP_SIM_REQ_AUTHENTICATION;
		break;

	default:
		break;
	}
	return TRESP_UNKNOWN;
}

static int _sim_get_current_pin_facility(enum s_sim_sec_op_e op)
{
	int ret_type = 0;

	dbg("current sec_op[%d]", op);
	
	switch (op) {
	case SEC_PIN1_VERIFY:
	case SEC_PIN1_CHANGE:
		ret_type = SIM_PTYPE_PIN1;
		break;

	case SEC_PIN2_VERIFY:
	case SEC_PIN2_CHANGE:
		ret_type = SIM_PTYPE_PIN2;
		break;

	case SEC_PUK1_VERIFY:
		ret_type = SIM_PTYPE_PUK1;
		break;

	case SEC_PUK2_VERIFY:
		ret_type = SIM_PTYPE_PUK2;
		break;

	case SEC_SIM_VERIFY:
		ret_type = SIM_PTYPE_SIM;
		break;

	case SEC_ADM_VERIFY:
		ret_type = SIM_PTYPE_ADM;
		break;

	case SEC_PIN1_ENABLE:
	case SEC_PIN1_DISABLE:
	case SEC_PIN1_STATUS:
		ret_type = SIM_FACILITY_SC;
		break;

	case SEC_SIM_ENABLE:
	case SEC_SIM_DISABLE:
	case SEC_SIM_STATUS:
		ret_type = SIM_FACILITY_PS;
		break;

	case SEC_NET_ENABLE:
	case SEC_NET_DISABLE:
	case SEC_NET_STATUS:
		ret_type = SIM_FACILITY_PN;
		break;

	case SEC_NS_ENABLE:
	case SEC_NS_DISABLE:
	case SEC_NS_STATUS:
		ret_type = SIM_FACILITY_PU;
		break;

	case SEC_SP_ENABLE:
	case SEC_SP_DISABLE:
	case SEC_SP_STATUS:
		ret_type = SIM_FACILITY_PP;
		break;

	case SEC_CP_ENABLE:
	case SEC_CP_DISABLE:
	case SEC_CP_STATUS:
		ret_type = SIM_FACILITY_PC;
		break;

	case SEC_FDN_ENABLE:
	case SEC_FDN_DISABLE:
	case SEC_FDN_STATUS:
		ret_type = SIM_FACILITY_FD;
		break;

	default:
		dbg("not handled current sec op[%d]", op)
		break;
	}
	return ret_type;
}

static enum tel_sim_access_result _decode_status_word(unsigned short status_word1, unsigned short status_word2)
{
	enum tel_sim_access_result rst = SIM_ACCESS_FAILED;

	if (status_word1 == 0x93 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg(" error - SIM application toolkit busy [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg(" error - No EF Selected [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x02) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg("error - Out of Range - Invalid address or record number[%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x04) {
		rst = SIM_ACCESS_FILE_NOT_FOUND;
		/*Failed SIM request command*/
		dbg(" error - File ID not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x08) {
		rst = SIM_ACCESS_FAILED; /* MOdem not support */
		/*Failed SIM request command*/
		dbg(" error - File is inconsistent with command - Modem not support or USE IPC [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x02) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - CHV not initialized [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x04) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - Access condition not fullfilled [%x][%x]", status_word1, status_word2);
		dbg(" error -Unsuccessful CHV verification - at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg(" error - Unsuccessful Unblock CHV - at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg(" error - Authentication failure [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x08) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - Contradiction with CHV status [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x10) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error - Contradiction with invalidation  status [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x40) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg(" error -Unsuccessful CHV verification - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg(" error - Unsuccessful Unblock CHV - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg(" error - CHV blocked [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x67 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg(" error -Incorrect Parameter 3 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6B && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg(" error -Incorrect Parameter 1 or 2 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6D && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg(" error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6E && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg(" error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x69 && status_word2 == 0x82) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg(" error -Access denied [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x87) {
		rst = SIM_ACCESS_FAILED;
		dbg(" error -Incorrect parameters [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x82) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg(" error -File Not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x83) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg(" error -Record Not found [%x][%x]", status_word1, status_word2);
	} else {
		rst = SIM_ACCESS_CARD_ERROR;
		dbg(" error -Unknown state [%x][%x]", status_word1, status_word2);
	}
	return rst;
}

static gboolean _sim_check_identity(CoreObject *o, struct tel_sim_imsi *imsi)
{
	Server *s = NULL;
	Storage *strg = NULL;
	char *old_imsi = NULL;
	char new_imsi[15 + 1] = {0, };

	s = tcore_plugin_ref_server(tcore_object_ref_plugin(o));
	if (!s) {
		dbg("there is no valid server at this point");
		return FALSE;
	}
	strg = (Storage *) tcore_server_find_storage(s, "vconf");
	if (!strg) {
		dbg("there is no valid storage plugin");
		return FALSE;
	}
	memcpy(&new_imsi, imsi->plmn, strlen(imsi->plmn));
	memcpy(&new_imsi[strlen(imsi->plmn)], imsi->msin, strlen(imsi->msin));
	new_imsi[strlen(imsi->plmn) + strlen(imsi->msin)] = '\0';

	old_imsi = tcore_storage_get_string(strg, STORAGE_KEY_TELEPHONY_IMSI);
	dbg("old_imsi[%s],newImsi[%s]", old_imsi, new_imsi);

	if (old_imsi != NULL) {
		if (strncmp(old_imsi, new_imsi, 15) != 0) {
			dbg("NEW SIM");
			if (tcore_storage_set_string(strg, STORAGE_KEY_TELEPHONY_IMSI, (const char *) &new_imsi) == FALSE) {
				dbg("[FAIL] UPDATE STORAGE_KEY_TELEPHONY_IMSI");
			}
			tcore_sim_set_identification(o, TRUE);
		} else {
			dbg("SAME SIM");
			tcore_sim_set_identification(o, FALSE);
		}
	} else {
		dbg("OLD SIM VALUE IS NULL. NEW SIM");
		if (tcore_storage_set_string(strg, STORAGE_KEY_TELEPHONY_IMSI, (const char *) &new_imsi) == FALSE) {
			dbg("[FAIL] UPDATE STORAGE_KEY_TELEPHONY_IMSI");
		}
		tcore_sim_set_identification(o, TRUE);
	}
	return 1;
}

static void _next_from_get_file_info(CoreObject *o, UserRequest *ur, enum tel_sim_file_id ef, enum tel_sim_access_result rt)
{
	struct tresp_sim_read resp = {0, };
	struct s_sim_property *file_meta = NULL;

	dbg("EF[0x%x] access Result[%d]", ef, rt);

	resp.result = rt;
	memset(&resp.data, 0x00, sizeof(resp.data));
	file_meta = (struct s_sim_property *) tcore_user_request_ref_metainfo(ur, NULL);

	if ((ef != SIM_EF_ELP && ef != SIM_EF_LP && ef != SIM_EF_USIM_PL && ef != SIM_EF_CPHS_CPHS_INFO)
		&& (rt != SIM_ACCESS_SUCCESS)) {
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &resp);
		return;
	}

	switch (ef) {
	case SIM_EF_ELP:
		if (rt == SIM_ACCESS_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			/*				if (po->language_file == 0x00)
			 po->language_file = SIM_EF_ELP;*/
			_get_file_data(o, ur, ef, 0, file_meta->data_size);
		} else {
			if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
				dbg(" [SIM DATA]SIM_EF_ELP(2F05) access fail. Request SIM_EF_LP(0x6F05) info");
				/* The ME requests the Language Preference (EFLP) if EFELP is not available  */
				_get_file_info(o, ur, SIM_EF_LP);
			} else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
				dbg(
					" [SIM DATA]fail to get Language information in USIM(EF-LI(6F05),EF-PL(2F05)). Request SIM_EF_ECC(0x6FB7) info");
				/* EFELPand EFLI not present at this point. */
				/*					po->language.lang_cnt = 0;*/
				tcore_user_request_send_response(ur, _find_resp_command(ur),
												 sizeof(struct tresp_sim_read), &resp);
				return;
			}
		}
		break;

	case SIM_EF_LP:     // same with SIM_EF_USIM_LI
		if (rt == SIM_ACCESS_SUCCESS) {
			dbg("[SIM DATA] exist EFLP/LI(0x6F05)");
			_get_file_data(o, ur, ef, 0, file_meta->data_size);
		} else {
			dbg("[SIM DATA]SIM_EF_LP/LI(6F05) access fail. Current CardType[%d]",
				tcore_sim_get_type(o));
			if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
				tcore_user_request_send_response(ur, _find_resp_command(ur),
												 sizeof(struct tresp_sim_read), &resp);
				return;
			}
			/*  if EFLI is not present, then the language selection shall be as defined in EFPL at the MF level	*/
			else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
				dbg("[SIM DATA] try USIM EFPL(0x2F05)");
				_get_file_info(o, ur, SIM_EF_ELP);
			}
		}
		break;

	case SIM_EF_USIM_PL:
		if (rt == SIM_ACCESS_SUCCESS) {
			dbg("[SIM DATA] exist EFELP/PL(0x2F05)");
			_get_file_data(o, ur, SIM_EF_ELP, 0, file_meta->data_size);
		} else {
			/* EFELIand EFPL not present, so set language count as zero and select ECC */
			dbg(
				" [SIM DATA]SIM_EF_USIM_PL(2A05) access fail. Request SIM_EF_ECC(0x6FB7) info");
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_read), &resp);
			return;
		}
		break;

	case SIM_EF_ECC:
		if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
			_get_file_data(o, ur, ef, 0, file_meta->data_size);
		} else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
			if (file_meta->rec_count > SIM_ECC_RECORD_CNT_MAX) {
				file_meta->rec_count = SIM_ECC_RECORD_CNT_MAX;
			}

			file_meta->current_index++;
			_get_file_record(o, ur, ef, file_meta->current_index, file_meta->rec_length);
		}
		break;

	case SIM_EF_ICCID:
	case SIM_EF_IMSI:
	case SIM_EF_SST:
	case SIM_EF_SPN:
	case SIM_EF_SPDI:
	case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case SIM_EF_CPHS_VOICE_MSG_WAITING:
	case SIM_EF_CPHS_OPERATOR_NAME_STRING:
	case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
	case SIM_EF_CPHS_DYNAMICFLAGS:
	case SIM_EF_CPHS_DYNAMIC2FLAG:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		_get_file_data(o, ur, ef, 0, file_meta->data_size);
		break;

	case SIM_EF_CPHS_CPHS_INFO:
		if (rt == SIM_ACCESS_SUCCESS) {
			tcore_sim_set_cphs_status(o, TRUE);
			if (!tcore_user_request_ref_communicator(ur)) {
				dbg("internal CPHS INFO request before sim status update");
				_sim_status_update(o, SIM_STATUS_INIT_COMPLETED);
			} else {
				dbg("external CPHS INFO request");
				_get_file_data(o, ur, ef, 0, file_meta->data_size);
			}
		} else {
			tcore_sim_set_cphs_status(o, FALSE);
			if (!tcore_user_request_ref_communicator(ur)) {
				dbg("internal CPHS INFO request before sim status update");
				_sim_status_update(o, SIM_STATUS_INIT_COMPLETED);
			} else {
				dbg("external CPHS INFO request");
				tcore_user_request_send_response(ur, _find_resp_command(ur),
												 sizeof(struct tresp_sim_read), &resp);
			}
		}
		break;


	case SIM_EF_USIM_CFIS:
		if (file_meta->rec_count > SIM_CF_RECORD_CNT_MAX) {
			file_meta->rec_count = SIM_CF_RECORD_CNT_MAX;
		}
		file_meta->current_index++;
		_get_file_record(o, ur, ef, file_meta->current_index, file_meta->rec_length);
		break;

	case SIM_EF_OPL:
	case SIM_EF_PNN:
	case SIM_EF_USIM_MWIS:
	case SIM_EF_USIM_MBI:
	case SIM_EF_MBDN:
	case SIM_EF_CPHS_MAILBOX_NUMBERS:
	case SIM_EF_CPHS_INFORMATION_NUMBERS:
		file_meta->current_index++;
		_get_file_record(o, ur, ef, file_meta->current_index, file_meta->rec_length);
		break;

	default:
		dbg("error - File id for get file info [0x%x]", ef);
		break;
	}
	return;
}

static void _next_from_get_file_data(CoreObject *o, UserRequest *ur, enum tel_sim_access_result rt, int decode_ret)
{
	struct s_sim_property *file_meta = NULL;

	dbg("Entry");

	file_meta = (struct s_sim_property *) tcore_user_request_ref_metainfo(ur, NULL);
	dbg("[SIM]EF[0x%x] read rt[%d] Decode rt[%d]", file_meta->file_id, rt, decode_ret);
	switch (file_meta->file_id) {
	case SIM_EF_ELP:
	case SIM_EF_USIM_PL:
	case SIM_EF_LP:
	case SIM_EF_USIM_LI:
		if (decode_ret == TRUE) {
			if (file_meta->file_id == SIM_EF_LP || file_meta->file_id == SIM_EF_USIM_LI) {
/*					po->language_file = SIM_EF_LP;*/
			} else if (file_meta->file_id == SIM_EF_ELP || file_meta->file_id == SIM_EF_USIM_PL) {
/*					po->language_file = SIM_EF_ELP;*/
			}
			tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		} else {
			/* 2G */
			/*  The ME requests the Extended Language Preference. The ME only requests the Language Preference (EFLP) if at least one of the following conditions holds:
			 -	EFELP is not available;
			 -	EFELP does not contain an entry corresponding to a language specified in ISO 639[30];
			 -	the ME does not support any of the languages in EFELP.
			 */
			/* 3G */
			/*  The ME only requests the Language Preference (EFPL) if at least one of the following conditions holds:
			 -	if the EFLI has the value 'FFFF' in its highest priority position
			 -	if the ME does not support any of the language codes indicated in EFLI , or if EFLI is not present
			 */
			if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
				if (file_meta->file_id == SIM_EF_LP) {
					tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
				} else {
					_get_file_info(o, ur, SIM_EF_LP);
				}
			} else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
				if (file_meta->file_id == SIM_EF_LP || file_meta->file_id == SIM_EF_USIM_LI) {
					_get_file_info(o, ur, SIM_EF_ELP);
				} else {
					tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
				}
			}
		}
		break;

	case SIM_EF_ECC:
		if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
			if (file_meta->current_index == file_meta->rec_count) {
				tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
			} else {
				file_meta->current_index++;
				_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length);
			}
		} else if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
			tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		} else {
			dbg("[SIM DATA]Invalid CardType[%d] Unable to handle", tcore_sim_get_type(o));
		}
		break;

	case SIM_EF_IMSI:
		ur = tcore_user_request_new(NULL, NULL);     // this is for using ur metainfo set/ref functionality.
		_get_file_info(o, ur, SIM_EF_CPHS_CPHS_INFO);
		break;

	case SIM_EF_MSISDN:
		if (file_meta->current_index == file_meta->rec_count) {
			tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		} else {
			file_meta->current_index++;
			_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length);
		}
		break;

	case SIM_EF_OPL:
		if (file_meta->current_index == file_meta->rec_count) {
			tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		} else {
			file_meta->current_index++;
			_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length);
		}
		break;

	case SIM_EF_PNN:
		if (file_meta->current_index == file_meta->rec_count) {
			tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		} else {
			file_meta->current_index++;
			_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length);
		}
		break;

	case SIM_EF_USIM_CFIS:
	case SIM_EF_USIM_MWIS:
	case SIM_EF_USIM_MBI:
	case SIM_EF_MBDN:
	case SIM_EF_CPHS_MAILBOX_NUMBERS:
	case SIM_EF_CPHS_INFORMATION_NUMBERS:
		if (file_meta->current_index == file_meta->rec_count) {
			tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		} else {
			file_meta->current_index++;
			_get_file_record(o, ur, file_meta->file_id, file_meta->current_index, file_meta->rec_length);
		}
		break;

	case SIM_EF_CPHS_OPERATOR_NAME_STRING:
		file_meta->files.result = rt;
		if (decode_ret == TRUE && rt == SIM_ACCESS_SUCCESS) {
			memcpy(file_meta->files.data.cphs_net.full_name, file_meta->files.data.cphs_net.full_name, strlen((char *) file_meta->files.data.cphs_net.full_name));
		}
		_get_file_info(o, ur, SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING);
		break;

	case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
		if (file_meta->files.result == SIM_ACCESS_SUCCESS || file_meta->files.result == SIM_ACCESS_SUCCESS) {
			file_meta->files.result = SIM_ACCESS_SUCCESS;
		}
		if (strlen((char *) file_meta->files.data.cphs_net.full_name)) {
			memcpy(&file_meta->files.data.cphs_net.full_name, &file_meta->files.data.cphs_net.full_name, strlen((char *) file_meta->files.data.cphs_net.full_name));
		}
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		break;

	case SIM_EF_ICCID:
	case SIM_EF_SST:
	case SIM_EF_SPN:
	case SIM_EF_SPDI:
	case SIM_EF_OPLMN_ACT:
	case SIM_EF_CPHS_CPHS_INFO:
	case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case SIM_EF_CPHS_VOICE_MSG_WAITING:
	case SIM_EF_CPHS_DYNAMICFLAGS:
	case SIM_EF_CPHS_DYNAMIC2FLAG:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
	case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE_LINE2:
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_read), &file_meta->files);
		break;

	default:
		dbg("File id not handled [0x%x]", file_meta->file_id);
		break;
	}
}

static void _sim_status_update(CoreObject *o, enum tel_sim_status sim_status)
{
	struct tnoti_sim_status noti_data = {0, };

	dbg("tcore_sim_set_status and send noti w/ [%d]", sim_status);
	tcore_sim_set_status(o, sim_status);
	noti_data.sim_status = sim_status;
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SIM_STATUS,
								   sizeof(struct tnoti_sim_status), &noti_data);
}

static void _response_get_sim_type(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	enum tel_sim_type sim_type = SIM_TYPE_UNKNOWN;
	const char *line;
	int state;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		state = atoi(g_slist_nth_data(tokens, 0));
		dbg("SIM Type is %d", state);

		if (state == 0) {
			sim_type = SIM_TYPE_GSM;
		} else if (state == 1) {
			sim_type = SIM_TYPE_USIM;
		} else {
			sim_type = SIM_TYPE_UNKNOWN;
		}
	} else {
		dbg("RESPONSE NOK");
		sim_type = SIM_TYPE_UNKNOWN;
	}

	tcore_sim_set_type(co_sim, sim_type);
	_sim_status_update(co_sim, sp->first_recv_status);
	tcore_at_tok_free(tokens);
	dbg(" Function exit");
}

static void _response_get_file_info(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *file_meta = NULL;
	GSList *tokens = NULL;
	enum tel_sim_access_result rt;
	const char *line = NULL;
	int sw1 = 0;
	int sw2 = 0;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	file_meta = (struct s_sim_property *) tcore_user_request_ref_metainfo(ur, NULL);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 2) {
				err("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));

		/*1. SIM access success case*/
		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			unsigned char tag_len = 0; /*	1 or 2 bytes ??? */
			unsigned short record_len = 0;
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

			char *hexData;
			char *tmp;
			char *recordData = NULL;
			hexData = g_slist_nth_data(tokens, 2);
			dbg("hexData: %s", hexData);
			dbg("hexData: %s", hexData + 1);

			tmp = util_removeQuotes(hexData);
			recordData = util_hexStringToBytes(tmp);
			util_hex_dump("    ", strlen(hexData) / 2, recordData);
			free(tmp);

			ptr_data = (unsigned char *) recordData;
			if (tcore_sim_get_type(co_sim) == SIM_TYPE_USIM) {
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
					dbg("tag_len: %02x", tag_len);
					/* FCP file descriptor - file type, accessibility, DF, ADF etc*/
					if (*ptr_data == 0x82) {
						/* increment to next byte */
						ptr_data++;
						/* 2 or 5 value*/
						ptr_data++;
						/*	unsigned char file_desc_len = *ptr_data++;*/
						/*	dbg("file descriptor length: [%d]", file_desc_len);*/
						/* TBD:  currently capture only file type : ignore sharable, non sharable, working, internal etc*/
						/* consider only last 3 bits*/
						dbg("file_type_tag: %02x", file_type_tag);
						file_type_tag = file_type_tag & (*ptr_data);
						dbg("file_type_tag: %02x", file_type_tag);

						switch (file_type_tag) {
						/* increment to next byte */
						// ptr_data++;
						case 0x1:
							dbg("Getting FileType: [Transparent file type]");
							file_type = SIM_FTYPE_TRANSPARENT;

							/* increment to next byte */
							ptr_data++;
							/* increment to next byte */
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
							SWAPBYTES16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							/* Data lossy conversation from enum (int) to unsigned char */
							file_type = SIM_FTYPE_LINEAR_FIXED;
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
							SWAPBYTES16(record_len);
							ptr_data = ptr_data + 2;
							num_of_records = *ptr_data++;
							file_type = SIM_FTYPE_CYCLIC;
							break;

						default:
							dbg("not handled file type [0x%x]", *ptr_data);
							break;
						}
					} else {
						dbg("INVALID FCP received - DEbug!");
						return;
					}

					/*File identifier - file id?? */ // 0x84,0x85,0x86 etc are currently ignored and not handled
					if (*ptr_data == 0x83) {
						/* increment to next byte */
						ptr_data++;
						file_id_len = *ptr_data++;
						dbg("file_id_len: %02x", file_id_len);

						memcpy(&file_id, ptr_data, file_id_len);
						dbg("file_id: %x", file_id);

						/* swap bytes	 */
						SWAPBYTES16(file_id);
						dbg("file_id: %x", file_id);

						ptr_data = ptr_data + 2;
						dbg("Getting FileID=[0x%x]", file_id);
					} else {
						dbg("INVALID FCP received - DEbug!");
						free(recordData);
						return;
					}

					/*	proprietary information  */
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
							SWAPBYTES16(arr_file_id);
							ptr_data = ptr_data + 2;
							arr_file_id_rec_num = *ptr_data++;
						} else {
							/* if tag length is not 3 */
							/* ignoring bytes	*/
							// ptr_data = ptr_data + 4;
							dbg("Useless security attributes, so jump to next tag");
							ptr_data = ptr_data + (*ptr_data + 1);
						}
					} else {
						dbg("INVALID FCP received[0x%x] - DEbug!", *ptr_data);
						free(recordData);
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
						SWAPBYTES16(file_size);
						ptr_data = ptr_data + 2;
					} else {
						dbg("INVALID FCP received - DEbug!");
						free(recordData);
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
					free(recordData);
					return;
				}
			} else if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM) {
				unsigned char gsm_specific_file_data_len = 0;
				/*	ignore RFU byte1 and byte2 */
				ptr_data++;
				ptr_data++;
				/*	file size */
				// file_size = p_info->response_len;
				memcpy(&file_size, ptr_data, 2);
				/* swap bytes */
				SWAPBYTES16(file_size);
				/*	parsed file size */
				ptr_data = ptr_data + 2;
				/*  file id  */
				memcpy(&file_id, ptr_data, 2);
				SWAPBYTES16(file_id);
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
							(file_type_tag == 0x00) ? SIM_FTYPE_TRANSPARENT : SIM_FTYPE_LINEAR_FIXED;
					} else {
						/* increment to next byte */
						ptr_data++;
						/*	For a cyclic EF all bits except bit 7 are RFU; b7=1 indicates that */
						/* the INCREASE command is allowed on the selected cyclic file. */
						file_type = SIM_FTYPE_CYCLIC;
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
				dbg(" Card Type - UNKNOWN  [%d]", tcore_sim_get_type(co_sim));
			}

			dbg("req ef[0x%x] resp ef[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]",
				file_meta->file_id, file_id, file_size, file_type, num_of_records, record_len);

			file_meta->file_type = file_type;
			file_meta->data_size = file_size;
			file_meta->rec_length = record_len;
			file_meta->rec_count = num_of_records;
			file_meta->current_index = 0; // reset for new record type EF
			rt = SIM_ACCESS_SUCCESS;
			free(recordData);
		} else {
			/*2. SIM access fail case*/
			dbg("error to get ef[0x%x]", file_meta->file_id);
			dbg("error to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
			rt = _decode_status_word(sw1, sw2);
		}
		ur = tcore_user_request_ref(ur);

		dbg("Calling _next_from_get_file_info");
		_next_from_get_file_info(co_sim, ur, file_meta->file_id, rt);
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		dbg("error to get ef[0x%x]", file_meta->file_id);
		dbg("error to get ef[0x%x] (file_meta->file_id) ", file_meta->file_id);
		rt = SIM_ACCESS_FAILED;

		ur = tcore_user_request_ref(ur);
		_next_from_get_file_info(co_sim, ur, file_meta->file_id, rt);
	}
	dbg(" Function exit");
}

static void _response_get_file_data(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *file_meta = NULL;
	GSList *tokens = NULL;
	enum tel_sim_access_result rt;
	struct tel_sim_imsi imsi;
	struct tel_sim_ecc ecc;
	struct tel_sim_msisdn msisdn;
	struct tel_sim_opl opl;
	struct tel_sim_pnn pnn;
	gboolean dr = FALSE;
	const char *line = NULL;
	char *res = NULL;
	char *tmp = NULL;
	int res_len;
	int sw1 = 0;
	int sw2 = 0;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	file_meta = (struct s_sim_property *) tcore_user_request_ref_metainfo(ur, NULL);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 3) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));
		res = g_slist_nth_data(tokens, 2);

		tmp = util_removeQuotes(res);
		res = util_hexStringToBytes(tmp);
		res_len = strlen((const char *) res);
		dbg("res: %s res_len: %d", res, res_len);

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			rt = SIM_ACCESS_SUCCESS;
			file_meta->files.result = rt;
			dbg("file_meta->file_id : %x", file_meta->file_id);

			switch (file_meta->file_id) {
			case SIM_EF_IMSI:
			{
				dbg("res: %s", res);
				dr = tcore_sim_decode_imsi(&imsi, (unsigned char *) res, res_len);
				if (dr == FALSE) {
					dbg("imsi decoding failed");
				} else {
					_sim_check_identity(co_sim, &imsi);
					tcore_sim_set_imsi(co_sim, &imsi);
				}
				break;
			}

			case SIM_EF_ICCID:
				dr = tcore_sim_decode_iccid(&file_meta->files.data.iccid, (unsigned char *) res, res_len);
				break;

			case SIM_EF_ELP:    /*  2G EF -  2 bytes decoding*/
			case SIM_EF_USIM_LI:     /* 3G EF - 2 bytes decoding*/
			case SIM_EF_USIM_PL:    /*  3G EF - same as EFELP, so 2  byte decoding*/
			case SIM_EF_LP:    /*  1 byte encoding*/
				if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM && file_meta->file_id == SIM_EF_LP) {
					/*2G LP(0x6F05) has 1 byte for each language*/
					dr = tcore_sim_decode_lp(&file_meta->files.data.language, (unsigned char *) res, res_len);
				} else {
					/*3G LI(0x6F05)/PL(0x2F05), 2G ELP(0x2F05) has 2 bytes for each language*/
					dr = tcore_sim_decode_li(file_meta->file_id, &file_meta->files.data.language, (unsigned char *) res, res_len);
				}
				break;

			case SIM_EF_SPN:
				dr = tcore_sim_decode_spn(&file_meta->files.data.spn, (unsigned char *) res, res_len);
				break;

			case SIM_EF_SPDI:
				dr = tcore_sim_decode_spdi(&file_meta->files.data.spdi, (unsigned char *) res, res_len);
				break;

			case SIM_EF_ECC:
				if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM) {
					dr = tcore_sim_decode_ecc(&file_meta->files.data.ecc, (unsigned char *) res, res_len);
				} else if (tcore_sim_get_type(co_sim) == SIM_TYPE_USIM) {
					dbg("decode w/ index [%d]", file_meta->current_index);
					memset(&ecc, 0x00, sizeof(struct tel_sim_ecc));
					dr = tcore_sim_decode_uecc(&ecc, (unsigned char *) res, res_len);
					if (dr == TRUE) {
						memcpy(&file_meta->files.data.ecc.ecc[file_meta->files.data.ecc.ecc_count], &ecc, sizeof(struct tel_sim_ecc));
						file_meta->files.data.ecc.ecc_count++;
					}
				} else {
					dbg("err not handled tcore_sim_get_type(o)[%d] in here", tcore_sim_get_type(co_sim));
				}
				break;

			case SIM_EF_MSISDN:
				dbg("decode w/ index [%d]", file_meta->current_index);
				memset(&msisdn, 0x00, sizeof(struct tel_sim_msisdn));
				dr = tcore_sim_decode_msisdn(&msisdn, (unsigned char *) res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.msisdn_list.msisdn[file_meta->files.data.msisdn_list.count], &msisdn, sizeof(struct tel_sim_msisdn));
					file_meta->files.data.msisdn_list.count++;
				}
				break;

			case SIM_EF_OPL:
				dbg("decode w/ index [%d]", file_meta->current_index);
				memset(&opl, 0x00, sizeof(struct tel_sim_opl));
				dr = tcore_sim_decode_opl(&opl, (unsigned char *) res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.opl.opl[file_meta->files.data.opl.opl_count], &opl, sizeof(struct tel_sim_opl));
					file_meta->files.data.opl.opl_count++;
				}
				break;

			case SIM_EF_PNN:
				dbg("decode w/ index [%d]", file_meta->current_index);
				memset(&pnn, 0x00, sizeof(struct tel_sim_pnn));
				dr = tcore_sim_decode_pnn(&pnn, (unsigned char *) res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.pnn.pnn[file_meta->files.data.pnn.pnn_count], &opl, sizeof(struct tel_sim_pnn));
					file_meta->files.data.pnn.pnn_count++;
				}
				break;

			case SIM_EF_OPLMN_ACT:
				dr = tcore_sim_decode_oplmnwact(&file_meta->files.data.opwa, (unsigned char *) res, res_len);
				break;

			case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
				dr = tcore_sim_decode_cff(&file_meta->files.data.cf, (unsigned char *) res, res_len);
				break;

			case SIM_EF_CPHS_VOICE_MSG_WAITING:
				dr = tcore_sim_decode_vmwf(&file_meta->files.data.mw.mw_data_u.cphs_mw, (unsigned char *) res, res_len);
				break;

			case SIM_EF_USIM_MWIS:
				dr = tcore_sim_decode_mwis(&file_meta->files.data.mw.mw_data_u.mw, (unsigned char *) res, res_len);
				break;

			case SIM_EF_USIM_CFIS:
				dr = tcore_sim_decode_cfis(&file_meta->files.data.cf, (unsigned char *) res, res_len);
				break;

			case SIM_EF_CPHS_SERVICE_STRING_TABLE:
				dbg(" not handled -SIM_EF_CPHS_SERVICE_STRING_TABLE ");
				break;

			case SIM_EF_CPHS_OPERATOR_NAME_STRING:
				dr = tcore_sim_decode_ons((unsigned char *) &file_meta->files.data.cphs_net.full_name, (unsigned char *) res, res_len);
				dbg(" file_meta->files.result[%d],file_meta->files.data.cphs_net.full_name[%s]", file_meta->files.result, file_meta->files.data.cphs_net.full_name);
				break;

			case SIM_EF_CPHS_CPHS_INFO:
				dr = tcore_sim_decode_cphs_info(&file_meta->files.data.cphs, (unsigned char *) res, res_len);
				break;

			case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
				dr = tcore_sim_decode_short_ons((unsigned char *) &file_meta->files.data.cphs_net.short_name, (unsigned char *) res, res_len);
				break;

			default:
				dbg("File Decoding Failed - not handled File[0x%x]", file_meta->file_id);
				dr = 0;
				break;
			}
		} else {
			rt = _decode_status_word(sw1, sw2);
			file_meta->files.result = rt;
		}
		free(tmp);
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		dbg("error to get ef[0x%x]", file_meta->file_id);
		rt = SIM_ACCESS_FAILED;
	}
	ur = tcore_user_request_ref(ur);

	dbg("Calling _next_from_get_file_data");
	_next_from_get_file_data(tcore_pending_ref_core_object(p), ur, rt, dr);
	dbg(" Function exit");
}

static void _on_response_get_retry_count(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	struct tresp_sim_verify_pins v_pin = {0, };
	struct tresp_sim_verify_puks v_puk = {0, };
	struct tresp_sim_change_pins change_pin = {0, };
	struct tresp_sim_disable_facility dis_facility = {0, };
	struct tresp_sim_enable_facility en_facility = {0, };
	int lock_type = 0;
	int attempts_left = 0;
	int time_penalty = 0;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 3) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		lock_type = atoi(g_slist_nth_data(tokens, 0));
		attempts_left = atoi(g_slist_nth_data(tokens, 1));
		time_penalty = atoi(g_slist_nth_data(tokens, 2));

		dbg("lock_type = %d, attempts_left = %d, time_penalty = %d",
			lock_type, attempts_left, time_penalty);

		switch (sp->current_sec_op) {
		case SEC_PIN1_VERIFY:
		case SEC_PIN2_VERIFY:
		case SEC_SIM_VERIFY:
		case SEC_ADM_VERIFY:
			v_pin.result = SIM_INCORRECT_PASSWORD;
			v_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_pin.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_verify_pins), &v_pin);
			break;

		case SEC_PUK1_VERIFY:
		case SEC_PUK2_VERIFY:
			v_puk.result = SIM_INCORRECT_PASSWORD;
			v_puk.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_puk.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_verify_puks), &v_puk);
			break;

		case SEC_PIN1_CHANGE:
		case SEC_PIN2_CHANGE:
			change_pin.result = SIM_INCORRECT_PASSWORD;
			change_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			change_pin.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_change_pins), &change_pin);
			break;

		case SEC_PIN1_DISABLE:
		case SEC_PIN2_DISABLE:
		case SEC_FDN_DISABLE:
		case SEC_SIM_DISABLE:
		case SEC_NET_DISABLE:
		case SEC_NS_DISABLE:
		case SEC_SP_DISABLE:
		case SEC_CP_DISABLE:
			dis_facility.result = SIM_INCORRECT_PASSWORD;
			dis_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			dis_facility.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_disable_facility), &dis_facility);
			break;

		case SEC_PIN1_ENABLE:
		case SEC_PIN2_ENABLE:
		case SEC_FDN_ENABLE:
		case SEC_SIM_ENABLE:
		case SEC_NET_ENABLE:
		case SEC_NS_ENABLE:
		case SEC_SP_ENABLE:
		case SEC_CP_ENABLE:
			en_facility.result = SIM_INCORRECT_PASSWORD;
			en_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			en_facility.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_enable_facility), &en_facility);
			break;

		default:
			dbg("not handled sec op[%d]", sp->current_sec_op);
			break;
		}
		tcore_at_tok_free(tokens);
	}
	dbg(" Function exit");
}

static gboolean _get_sim_type(CoreObject *o)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	UserRequest *ur = NULL;
	char *cmd_str = NULL;

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	cmd_str = g_strdup_printf("AT+XUICC?");
	req = tcore_at_request_new(cmd_str, "+XUICC:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _response_get_sim_type, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TRUE;
}

static TReturn _get_file_info(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	struct s_sim_property file_meta = {0, };
	char *cmd_str = NULL;
	int trt = 0;

	dbg(" Function entry ");

	file_meta.file_id = ef;
	dbg("file_meta.file_id: %d", file_meta.file_id);
	hal = tcore_object_get_hal(o);
	dbg("hal: %x", hal);
	pending = tcore_pending_new(o, 0);

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &file_meta);
	dbg("trt[%d]", trt);
	cmd_str = g_strdup_printf("AT+CRSM=192, %d", ef);           /*command - 192 : GET RESPONSE*/
	dbg("cmd_str: %x", cmd_str);

	pending = tcore_at_pending_new(o, cmd_str, "+CRSM:", TCORE_AT_SINGLELINE, _response_get_file_info, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static gboolean _get_file_data(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int offset, const int length)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;

	dbg(" Function entry ");
	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	dbg("file_id: %x", ef);

	p1 = (unsigned char) (offset & 0xFF00) >> 8;
	p2 = (unsigned char) offset & 0x00FF; // offset low
	p3 = (unsigned char) length;

	cmd_str = g_strdup_printf("AT+CRSM=176, %d, %d, %d, %d", ef, p1, p2, p3);          /*command - 176 : READ BINARY*/

	req = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _response_get_file_data, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TRUE;
}

static gboolean _get_file_record(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int index, const int length)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	p1 = (unsigned char) index;
	p2 = (unsigned char) 0x04;       /* 0x4 for absolute mode  */
	p3 = (unsigned char) length;

	cmd_str = g_strdup_printf("AT+CRSM=178, %d, %d, %d, %d", ef, p1, p2, p3);          /*command - 178 : READ RECORD*/

	req = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _response_get_file_data, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TRUE;
}

static TReturn _get_retry_count(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	int lock_type = 0;
	struct s_sim_property *sp = NULL;
	const struct treq_sim_get_lock_info *req_data = NULL;

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);
	sp = tcore_sim_ref_userdata(o);

	switch (sp->current_sec_op) {
	case SEC_PIN1_VERIFY:
	case SEC_PIN1_CHANGE:
	case SEC_PIN1_ENABLE:
	case SEC_PIN1_DISABLE:
		lock_type = 1;
		break;

	case SEC_PIN2_VERIFY:
	case SEC_PIN2_CHANGE:
	case SEC_PIN2_ENABLE:
	case SEC_PIN2_DISABLE:
	case SEC_FDN_ENABLE:
	case SEC_FDN_DISABLE:
		lock_type = 2;
		break;

	case SEC_PUK1_VERIFY:
		lock_type = 3;
		break;

	case SEC_PUK2_VERIFY:
		lock_type = 4;
		break;

	case SEC_NET_ENABLE:
	case SEC_NET_DISABLE:
		lock_type = 5;
		break;

	case SEC_NS_ENABLE:
	case SEC_NS_DISABLE:
		lock_type = 6;
		break;

	case SEC_SP_ENABLE:
	case SEC_SP_DISABLE:
		lock_type = 7;
		break;

	case SEC_CP_ENABLE:
	case SEC_CP_DISABLE:
		lock_type = 8;
		break;

	case SEC_ADM_VERIFY:
		lock_type = 9;
		break;

	default:
		break;
	}

	cmd_str = g_strdup_printf("AT+XPINCNT=%d", lock_type);
	req = tcore_at_request_new(cmd_str, "+XPINCNT:", TCORE_AT_SINGLELINE);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _on_response_get_retry_count, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}


static gboolean on_event_facility_lock_status(CoreObject *o, const void *event_info, void *user_data)
{
	struct s_sim_property *sp = NULL;
	char *line = NULL;
	GSList *tokens = NULL;
	GSList *lines = NULL;

	dbg("Function entry");
	return TRUE;

	sp = tcore_sim_ref_userdata(o);
	lines = (GSList *) event_info;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}
	line = (char *) (lines->data);
	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) != 1) {
		msg("invalid message");
		tcore_at_tok_free(tokens);
		return TRUE;
	}

OUT:
	dbg(" Function exit");
	if (NULL != tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}


static gboolean on_event_pin_status(CoreObject *o, const void *event_info, void *user_data)
{
	UserRequest *ur = NULL;
	struct s_sim_property *sp = NULL;
	enum tel_sim_status sim_status = SIM_STATUS_INITIALIZING;
	GSList *tokens = NULL;
	GSList *lines = NULL;
	const char *line = NULL;
	int sim_state = 0;

	dbg(" Function entry ");

	sp = tcore_sim_ref_userdata(o);

	lines = (GSList *) event_info;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}
	line = (char *) (lines->data);

	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) != 1) {
		msg("invalid message");
		tcore_at_tok_free(tokens);
		return TRUE;
	}
	sim_state = atoi(g_slist_nth_data(tokens, 0));

	switch (sim_state) {
	case 0:                                                         // sim state = SIM not present
		sim_status = SIM_STATUS_CARD_NOT_PRESENT;
		dbg("NO SIM");
		break;

	case 1:                                                         // sim state = PIN verification needed
		sim_status = SIM_STATUS_PIN_REQUIRED;
		dbg(" PIN required");
		break;

	case 2:                                                         // sim state = PIN verification not needed \96 Ready
	case 3:                                                         // sim state = PIN verified \96 Ready
		sim_status = SIM_STATUS_INITIALIZING;
		dbg(" Inside PIN disabled at BOOT UP");
		break;

	case 4:                                                         // sim state = PUK verification needed
		sim_status = SIM_STATUS_PUK_REQUIRED;
		dbg(" PUK required");
		break;

	case 5:                                                         // sim state = SIM permanently blocked
		sim_status = SIM_STATUS_CARD_BLOCKED;
		dbg(" Card permanently blocked");
		break;

	case 6:                                                         // sim state = SIM error
		sim_status = SIM_STATUS_CARD_ERROR;
		dbg("SIM card error ");
		break;

	case 7:                                                         // sim state = ready for attach (+COPS)
		sim_status = SIM_STATUS_INIT_COMPLETED;
		dbg("Modem init completed");
		break;

	case 8:                                                         // sim state = SIM Technical Problem
		sim_status = SIM_STATUS_CARD_ERROR;
		dbg("SIM unavailable");
		break;

	case 9:                                                         // sim state = SIM removed
		sim_status = SIM_STATUS_CARD_REMOVED;
		dbg("SIM removed");
		break;

	case 99:                                                            // sim state = SIM State Unknown
		sim_status = SIM_STATUS_UNKNOWN;
		dbg("SIM State Unknown");
		break;

	case 12:
		dbg("SIM Status : %d", sim_status);
		goto OUT;

	default:
		dbg(" not handled SEC lock type ");
		break;
	}

	switch (sim_status) {
	case SIM_STATUS_INIT_COMPLETED:
		ur = tcore_user_request_new(NULL, NULL);     // this is for using ur metainfo set/ref functionality.
		_get_file_info(o, ur, SIM_EF_IMSI);
		break;

	case SIM_STATUS_INITIALIZING:
	case SIM_STATUS_PIN_REQUIRED:
	case SIM_STATUS_PUK_REQUIRED:
	case SIM_STATUS_CARD_BLOCKED:
	case SIM_STATUS_NCK_REQUIRED:
	case SIM_STATUS_NSCK_REQUIRED:
	case SIM_STATUS_SPCK_REQUIRED:
	case SIM_STATUS_CCK_REQUIRED:
	case SIM_STATUS_LOCK_REQUIRED:
		if (sp->first_recv_status == SIM_STATUS_UNKNOWN) {
			dbg("first received sim status[%d]", sim_status);
			sp->first_recv_status = sim_status;
			_get_sim_type(o);
		} else {
			dbg("second or later received lock status[%d]", sim_status);
			if (tcore_sim_get_status(o) != SIM_STATUS_INIT_COMPLETED) {
				dbg("sim is not init complete in telephony side yet");
				_sim_status_update(o, sim_status);
			}
		}
		break;

	case SIM_STATUS_CARD_REMOVED:
	case SIM_STATUS_CARD_NOT_PRESENT:
	case SIM_STATUS_CARD_ERROR:
		if (sim_status == SIM_STATUS_CARD_NOT_PRESENT && tcore_sim_get_status(o) != SIM_STATUS_UNKNOWN) {
			dbg("[SIM]SIM CARD REMOVED!!");
			sim_status = SIM_STATUS_CARD_REMOVED;
		}
		_sim_status_update(o, sim_status);
		break;

	default:
		dbg("not handled status[%d]", sim_status);

		break;
	}
OUT:
	dbg(" Function exit");
	if (NULL != tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}



static void on_response_verify_pins(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_verify_pins res;
	GQueue *queue = NULL;
	const char *line;
	int err;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_verify_pins));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		res.result = SIM_PIN_OPERATION_SUCCESS;
		res.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
		if (res.pin_type == SIM_PTYPE_PIN1 || res.pin_type == SIM_PTYPE_SIM) {
			if (tcore_sim_get_status(co_sim) != SIM_STATUS_INIT_COMPLETED)
				_sim_status_update(co_sim, SIM_STATUS_INITIALIZING);
		}
		tcore_user_request_send_response(ur, TRESP_SIM_VERIFY_PINS, sizeof(struct tresp_sim_verify_pins), &res);
	} else {
		dbg("RESPONSE NOK");
		line = (const char *) resp->final_response;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			err = atoi(g_slist_nth_data(tokens, 0));
			dbg("on_response_verify_pins: err = %d", err);
			queue = tcore_object_ref_user_data(co_sim);
			ur = tcore_user_request_ref(ur);
			_get_retry_count(co_sim, ur);
		}
		tcore_at_tok_free(tokens);
	}
	dbg(" Function exit");
}

static void on_response_verify_puks(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_verify_puks res;
	GQueue *queue = NULL;
	const char *line;
	int err;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_verify_pins));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		res.result = SIM_PIN_OPERATION_SUCCESS;
		res.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
		tcore_user_request_send_response(ur, TRESP_SIM_VERIFY_PUKS, sizeof(struct tresp_sim_verify_pins), &res);
	} else {
		dbg("RESPONSE NOK");
		line = (const char *) resp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			err = atoi(g_slist_nth_data(tokens, 0));
			queue = tcore_object_ref_user_data(co_sim);
			ur = tcore_user_request_ref(ur);
			_get_retry_count(co_sim, ur);
		}
		tcore_at_tok_free(tokens);
	}
	dbg(" Function exit");
}

static void on_response_change_pins(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_change_pins res;
	GQueue *queue;
	const char *line;
	int err;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_change_pins));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		res.result = SIM_PIN_OPERATION_SUCCESS;
		res.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
		tcore_user_request_send_response(ur, TRESP_SIM_CHANGE_PINS, sizeof(struct tresp_sim_change_pins), &res);
	} else {
		dbg("RESPONSE NOK");
		line = (const char *) resp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("err cause not specified or string corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;
		} else {
			err = atoi(g_slist_nth_data(tokens, 0));
			queue = tcore_object_ref_user_data(co_sim);
			ur = tcore_user_request_ref(ur);
			_get_retry_count(co_sim, ur);
		}
		tcore_at_tok_free(tokens);
	}
	dbg(" Function exit");
}

static void on_response_get_facility_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_get_facility_status res;
	const char *line;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_get_facility_status));

	res.result = SIM_PIN_OPERATION_SUCCESS;
	res.type = _sim_get_current_pin_facility(sp->current_sec_op);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res.b_enable = atoi(g_slist_nth_data(tokens, 0));
	} else {
		dbg("RESPONSE NOK");
		res.result = SIM_INCOMPATIBLE_PIN_OPERATION;
	}

	if (ur) {
		tcore_user_request_send_response(ur, TRESP_SIM_GET_FACILITY_STATUS,
										 sizeof(struct tresp_sim_get_facility_status), &res);
	}
	tcore_at_tok_free(tokens);
	dbg(" Function exit");
}

static void on_response_enable_facility(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_enable_facility res;
	GQueue *queue;
	const char *line;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_enable_facility));

	res.result = SIM_PIN_OPERATION_SUCCESS;
	res.type = _sim_get_current_pin_facility(sp->current_sec_op);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res.result = SIM_PIN_OPERATION_SUCCESS;
		if (ur) {
			tcore_user_request_send_response(ur, TRESP_SIM_ENABLE_FACILITY,
											 sizeof(struct tresp_sim_enable_facility), &res);
		}
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		queue = tcore_object_ref_user_data(co_sim);
		ur = tcore_user_request_ref(ur);
		_get_retry_count(co_sim, ur);
	}
	dbg(" Function exit");
}

static void on_response_disable_facility(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_disable_facility res;
	GQueue *queue;
	const char *line;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_disable_facility));

	res.result = SIM_PIN_OPERATION_SUCCESS;
	res.type = _sim_get_current_pin_facility(sp->current_sec_op);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res.result = SIM_PIN_OPERATION_SUCCESS;
		if (ur) {
			tcore_user_request_send_response(ur, TRESP_SIM_DISABLE_FACILITY,
											 sizeof(struct tresp_sim_disable_facility), &res);
		}
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		queue = tcore_object_ref_user_data(co_sim);
		ur = tcore_user_request_ref(ur);
		_get_retry_count(co_sim, ur);
	}
	dbg(" Function exit");
}

static void on_response_get_lock_info(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	const char *line;
	struct tresp_sim_verify_pins v_pin = {0, };
	struct tresp_sim_verify_puks v_puk = {0, };
	struct tresp_sim_change_pins change_pin = {0, };
	struct tresp_sim_disable_facility dis_facility = {0, };
	struct tresp_sim_enable_facility en_facility = {0, };
	int lock_type;
	int attempts_left = 0;
	int time_penalty = 0;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 3) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		lock_type = atoi(g_slist_nth_data(tokens, 0));
		attempts_left = atoi(g_slist_nth_data(tokens, 1));
		time_penalty = atoi(g_slist_nth_data(tokens, 2));

		switch (sp->current_sec_op) {
		case SEC_PIN1_VERIFY:
		case SEC_PIN2_VERIFY:
		case SEC_SIM_VERIFY:
		case SEC_ADM_VERIFY:
			v_pin.result = SIM_INCORRECT_PASSWORD;
			v_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_pin.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_verify_pins), &v_pin);
			break;

		case SEC_PUK1_VERIFY:
		case SEC_PUK2_VERIFY:
			v_puk.result = SIM_INCORRECT_PASSWORD;
			v_puk.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_puk.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_verify_puks), &v_puk);
			break;

		case SEC_PIN1_CHANGE:
		case SEC_PIN2_CHANGE:
			change_pin.result = SIM_INCORRECT_PASSWORD;
			change_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			change_pin.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_change_pins), &change_pin);
			break;

		case SEC_PIN1_DISABLE:
		case SEC_PIN2_DISABLE:
		case SEC_FDN_DISABLE:
		case SEC_SIM_DISABLE:
		case SEC_NET_DISABLE:
		case SEC_NS_DISABLE:
		case SEC_SP_DISABLE:
		case SEC_CP_DISABLE:
			dis_facility.result = SIM_INCORRECT_PASSWORD;
			dis_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			dis_facility.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_disable_facility), &dis_facility);
			break;

		case SEC_PIN1_ENABLE:
		case SEC_PIN2_ENABLE:
		case SEC_FDN_ENABLE:
		case SEC_SIM_ENABLE:
		case SEC_NET_ENABLE:
		case SEC_NS_ENABLE:
		case SEC_SP_ENABLE:
		case SEC_CP_ENABLE:
			en_facility.result = SIM_INCORRECT_PASSWORD;
			en_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			en_facility.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_enable_facility), &en_facility);
			break;

		default:
			dbg("not handled sec op[%d]", sp->current_sec_op);
			break;
		}
		tcore_at_tok_free(tokens);
	}
	dbg(" Function exit");
}

static void on_response_update_file(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct tresp_sim_set_callforwarding resp_cf = {0, };
	struct tresp_sim_set_language resp_language = {0, };
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	enum tel_sim_access_result result;
	const char *line;
	int sw1 = 0;
	int sw2 = 0;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	sp = (struct s_sim_property *) tcore_user_request_ref_metainfo(ur, NULL);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 2) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			result = SIM_ACCESS_SUCCESS;
		} else {
			result = _decode_status_word(sw1, sw2);
		}
	} else {
		dbg("RESPONSE NOK");
		result = SIM_ACCESS_FAILED;
	}

	switch (sp->file_id) {
	case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case SIM_EF_USIM_CFIS:
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_set_callforwarding), &resp_cf);
		break;

	case SIM_EF_ELP:
	case SIM_EF_LP:
	case SIM_EF_USIM_LI:
	case SIM_EF_USIM_PL:
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_set_language), &resp_language);
		break;

	default:
		dbg("Invalid File ID - %d", sp->file_id)
		break;
	}
	tcore_at_tok_free(tokens);
	dbg(" Function exit");
}

static void on_response_transmit_apdu(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_transmit_apdu res;
	const char *line;

	dbg(" Function entry ");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_transmit_apdu));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		res.result = SIM_ACCESS_SUCCESS;
		if (resp->lines) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 2) {
				msg("invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res.apdu_resp_length = atoi(g_slist_nth_data(tokens, 0));
		strncpy((char *) res.apdu_resp, (const char *) g_slist_nth_data(tokens, 1), res.apdu_resp_length);
	} else {
		dbg("RESPONSE NOK");
		res.result = SIM_ACCESS_FAILED;
	}
	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur, _find_resp_command(ur), sizeof(struct tresp_sim_transmit_apdu), &res);
	}
	tcore_at_tok_free(tokens);
	dbg(" Function exit");
}

static TReturn s_verify_pins(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_verify_pins *req_data = NULL;
	struct s_sim_property *sp = NULL;

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	if (req_data->pin_type == SIM_PTYPE_PIN1) {
		sp->current_sec_op = SEC_PIN1_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN=\"%s\"", req_data->pin);
	} else if (req_data->pin_type == SIM_PTYPE_PIN2) {
		sp->current_sec_op = SEC_PIN2_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN2=\"%s\"", req_data->pin);
	} else if (req_data->pin_type == SIM_PTYPE_SIM) {
		sp->current_sec_op = SEC_SIM_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN=\"%s\"", req_data->pin);
	} else if (req_data->pin_type == SIM_PTYPE_ADM) {
		sp->current_sec_op = SEC_ADM_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN=\"%s\"", req_data->pin);
	} else {
		return TCORE_RETURN_EINVAL;
	}

	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_verify_pins, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_verify_puks(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_verify_puks *req_data;
	struct s_sim_property *sp = NULL;

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	if (req_data->puk_type == SIM_PTYPE_PUK1) {
		sp->current_sec_op = SEC_PUK1_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN=\"%s\", \"%s\"", req_data->puk, req_data->pin);
	} else if (req_data->puk_type == SIM_PTYPE_PUK2) {
		sp->current_sec_op = SEC_PUK2_VERIFY;
		cmd_str = g_strdup_printf("AT+CPIN2=\"%s\", \"%s\"", req_data->puk, req_data->pin);
	} else {
		return TCORE_RETURN_EINVAL;
	}
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_verify_puks, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_change_pins(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_change_pins *req_data;
	struct s_sim_property *sp = NULL;
	char *pin1 = "SC";
	char *pin2 = "P2";

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	if (req_data->type == SIM_PTYPE_PIN1) {
		sp->current_sec_op = SEC_PIN1_CHANGE;
		cmd_str = g_strdup_printf("AT+CPWD=\"%s\",\"%s\",\"%s\"", pin1, req_data->old_pin, req_data->new_pin);
	} else if (req_data->type == SIM_PTYPE_PIN2) {
		sp->current_sec_op = SEC_PIN2_CHANGE;
		cmd_str = g_strdup_printf("AT+CPWD=\"%s\",\"%s\",\"%s\"", pin2, req_data->old_pin, req_data->new_pin);
	} else {
		return TCORE_RETURN_EINVAL;
	}
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_change_pins, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_get_facility_status(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_get_facility_status *req_data;
	struct s_sim_property *sp = NULL;
	char *fac = "SC";
	int mode = 2;       /* 0:unlock, 1:lock, 2:query*/

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	if (req_data->type == SIM_FACILITY_PS) {
		fac = "PS";                             /*PH-SIM, Lock PHone to SIM/UICC card*/
	} else if (req_data->type == SIM_FACILITY_SC) {
		fac = "SC";                             /*Lock SIM/UICC card, simply PIN1*/
	} else if (req_data->type == SIM_FACILITY_FD) {
		fac = "FD";                             /*Fixed Dialing Number feature, need PIN2*/
	} else if (req_data->type == SIM_FACILITY_PN) {
		fac = "PN";                             /*Network Personalization*/
	} else if (req_data->type == SIM_FACILITY_PU) {
		fac = "PU";                             /*network sUbset Personalization*/
	} else if (req_data->type == SIM_FACILITY_PP) {
		fac = "PP";                             /*service Provider Personalization*/
	} else if (req_data->type == SIM_FACILITY_PC) {
		fac = "PC";                             /*Corporate Personalization*/
	} else {
		return TCORE_RETURN_EINVAL;
	}
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d", fac, mode);
	req = tcore_at_request_new(cmd_str, "+CLCK:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_get_facility_status, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_enable_facility(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_enable_facility *req_data;
	struct s_sim_property *sp = NULL;
	char *fac = "SC";
	int mode = 1;       /* 0:unlock, 1:lock, 2:query*/

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	if (req_data->type == SIM_FACILITY_PS) {
		fac = "PS";                             /*PH-SIM, Lock PHone to SIM/UICC card*/
		sp->current_sec_op = SEC_SIM_ENABLE;
	} else if (req_data->type == SIM_FACILITY_SC) {
		fac = "SC";                             /*Lock SIM/UICC card, simply PIN1*/
		sp->current_sec_op = SEC_PIN1_ENABLE;
	} else if (req_data->type == SIM_FACILITY_FD) {
		fac = "FD";                             /*Fixed Dialing Number feature, need PIN2*/
		sp->current_sec_op = SEC_FDN_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PN) {
		fac = "PN";                             /*Network Personalization*/
		sp->current_sec_op = SEC_NET_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PU) {
		fac = "PU";                             /*network sUbset Personalization*/
		sp->current_sec_op = SEC_NS_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PP) {
		fac = "PP";                             /*service Provider Personalization*/
		sp->current_sec_op = SEC_SP_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PC) {
		fac = "PC";                             /*Corporate Personalization*/
		sp->current_sec_op = SEC_CP_ENABLE;
	} else {
		return TCORE_RETURN_EINVAL;
	}
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"", fac, mode, req_data->password);
	req = tcore_at_request_new(cmd_str, "+CLCK:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_enable_facility, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_disable_facility(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_enable_facility *req_data;
	struct s_sim_property *sp = NULL;
	char *fac = "SC";
	int mode = 0;       /* 0:unlock, 1:lock, 2:query*/

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	if (req_data->type == SIM_FACILITY_PS) {
		fac = "PS";                             /*PH-SIM, Lock PHone to SIM/UICC card*/
		sp->current_sec_op = SEC_SIM_DISABLE;
	} else if (req_data->type == SIM_FACILITY_SC) {
		fac = "SC";                             /*Lock SIM/UICC card, simply PIN1*/
		sp->current_sec_op = SEC_PIN1_DISABLE;
	} else if (req_data->type == SIM_FACILITY_FD) {
		fac = "FD";                             /*Fixed Dialing Number feature, need PIN2*/
		sp->current_sec_op = SEC_FDN_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PN) {
		fac = "PN";                             /*Network Personalization*/
		sp->current_sec_op = SEC_NET_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PU) {
		fac = "PU";                             /*network sUbset Personalization*/
		sp->current_sec_op = SEC_NS_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PP) {
		fac = "PP";                             /*service Provider Personalization*/
		sp->current_sec_op = SEC_SP_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PC) {
		fac = "PC";                             /*Corporate Personalization*/
		sp->current_sec_op = SEC_CP_DISABLE;
	} else {
		return TCORE_RETURN_EINVAL;
	}
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"", fac, mode, req_data->password);
	req = tcore_at_request_new(cmd_str, "+CLCK:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_disable_facility, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_get_lock_info(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	char *lock_type = NULL;
	const struct treq_sim_get_lock_info *req_data;
	struct s_sim_property *sp = NULL;

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	switch (req_data->type) {
	case SIM_FACILITY_PS:
		lock_type = "PS";
		break;

	case SIM_FACILITY_SC:
		lock_type = "SC";
		break;

	case SIM_FACILITY_FD:
		lock_type = "FD";
		break;

	case SIM_FACILITY_PN:
		lock_type = "PN";
		break;

	case SIM_FACILITY_PU:
		lock_type = "PU";
		break;

	case SIM_FACILITY_PP:
		lock_type = "PP";
		break;

	case SIM_FACILITY_PC:
		lock_type = "PC";
		break;

	default:
		break;
	}
	cmd_str = g_strdup_printf("AT+XPINCNT =\"%s\"", lock_type);
	req = tcore_at_request_new(cmd_str, "+XPINCNT:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_get_lock_info, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_read_file(CoreObject *o, UserRequest *ur)
{
	TReturn api_ret = TCORE_RETURN_SUCCESS;
	enum tcore_request_command command;

	command = tcore_user_request_get_command(ur);

	dbg(" Function entry ");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	switch (command) {
	case TREQ_SIM_GET_ECC:
		api_ret = _get_file_info(o, ur, SIM_EF_ECC);
		break;

	case TREQ_SIM_GET_LANGUAGE:
		if (tcore_sim_get_type(o) == SIM_TYPE_GSM)
			api_ret = _get_file_info(o, ur, SIM_EF_ELP);
		else if (tcore_sim_get_type(o) == SIM_TYPE_USIM)
			api_ret = _get_file_info(o, ur, SIM_EF_LP);
		else
			api_ret = TCORE_RETURN_ENOSYS;
		break;

	case TREQ_SIM_GET_ICCID:
		api_ret = _get_file_info(o, ur, SIM_EF_ICCID);
		break;

	case TREQ_SIM_GET_MAILBOX:
		if (tcore_sim_get_cphs_status(o))
			api_ret = _get_file_info(o, ur, SIM_EF_CPHS_MAILBOX_NUMBERS);
		else
			api_ret = _get_file_info(o, ur, SIM_EF_MBDN);
		break;

	case TREQ_SIM_GET_CALLFORWARDING:
		if (tcore_sim_get_cphs_status(o))
			api_ret = _get_file_info(o, ur, SIM_EF_CPHS_CALL_FORWARD_FLAGS);
		else
			api_ret = _get_file_info(o, ur, SIM_EF_USIM_CFIS);
		break;

	case TREQ_SIM_GET_MESSAGEWAITING:
		if (tcore_sim_get_cphs_status(o))
			api_ret = _get_file_info(o, ur, SIM_EF_CPHS_VOICE_MSG_WAITING);
		else
			api_ret = _get_file_info(o, ur, SIM_EF_USIM_MWIS);
		break;

	case TREQ_SIM_GET_CPHS_INFO:
		api_ret = _get_file_info(o, ur, SIM_EF_CPHS_CPHS_INFO);
		break;

	case TREQ_SIM_GET_MSISDN:
		api_ret = _get_file_info(o, ur, SIM_EF_MSISDN);
		break;

	case TREQ_SIM_GET_SPN:
		dbg("enter case SPN");
		api_ret = _get_file_info(o, ur, SIM_EF_SPN);
		break;

	case TREQ_SIM_GET_SPDI:
		api_ret = _get_file_info(o, ur, SIM_EF_SPDI);
		break;

	case TREQ_SIM_GET_OPL:
		api_ret = _get_file_info(o, ur, SIM_EF_OPL);
		break;

	case TREQ_SIM_GET_PNN:
		api_ret = _get_file_info(o, ur, SIM_EF_PNN);
		break;

	case TREQ_SIM_GET_CPHS_NETNAME:
		api_ret = _get_file_info(o, ur, SIM_EF_CPHS_OPERATOR_NAME_STRING);
		break;

	case TREQ_SIM_GET_OPLMNWACT:
		api_ret = _get_file_info(o, ur, SIM_EF_OPLMN_ACT);
		break;

	default:
		dbg("error - not handled read treq command[%d]", command);
		api_ret = TCORE_RETURN_EINVAL;
		break;
	}
	dbg(" Function exit");
	return api_ret;
}

static TReturn s_update_file(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	TcoreATRequest *req;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	TReturn api_ret = TCORE_RETURN_SUCCESS;
	char *encoded_data = NULL;
	int encoded_len = 0;
	enum tcore_request_command command;
	enum tel_sim_file_id ef = SIM_EF_INVALID;
	const struct treq_sim_set_callforwarding *cf;
	const struct treq_sim_set_language *cl;
	struct s_sim_property file_meta = {0, };
	int p1 = 0;
	int p2 = 0;
	int p3 = 0;
	int cmd = 0;
	int out_length = 0;
	int trt = 0;
	struct tel_sim_language sim_language;
	char *tmp = NULL;
	gboolean result;

	command = tcore_user_request_get_command(ur);

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	if (!o || !ur) {
		return TCORE_RETURN_EINVAL;
	}

	switch (command) {
	case TREQ_SIM_SET_LANGUAGE:
		cl = tcore_user_request_ref_data(ur, NULL);
		memset(&sim_language, 0x00, sizeof(struct tel_sim_language));
		cmd = 214;

		sim_language.language_count = 1;
		sim_language.language[0] = cl->language;
		dbg("language %d", cl->language);

		if (tcore_sim_get_type(o) == SIM_TYPE_GSM) {
			dbg("2G");
			ef = SIM_EF_LP;
			tmp = tcore_sim_encode_lp(&out_length, &sim_language);

			encoded_data = (char *) malloc(2 * (sim_language.language_count) + 1);
			memset(encoded_data, 0x00, (2 * sim_language.language_count) + 1);
			result = util_byte_to_hex(tmp, encoded_data, out_length);

			p1 = 0;
			p2 = 0;
			p3 = out_length;
			dbg("encoded_data - %s ---", encoded_data);
			dbg("out_length - %d ---", out_length);
		} else if (tcore_sim_get_type(o) == SIM_TYPE_USIM) {
			dbg("3G");
			ef = SIM_EF_LP;
			tmp = tcore_sim_encode_li(&out_length, &sim_language);

			encoded_data = (char *) malloc(2 * (out_length) + 1);
			memset(encoded_data, 0x00, (2 * out_length) + 1);
			result = util_byte_to_hex(tmp, encoded_data, out_length);

			p1 = 0;
			p2 = 0;
			p3 = out_length;
			dbg("encoded_data - %s ---", encoded_data);
			dbg("out_length - %d ---", out_length);
		} else {
			api_ret = TCORE_RETURN_ENOSYS;
		}
		break;

	case TREQ_SIM_SET_CALLFORWARDING:
		cf = tcore_user_request_ref_data(ur, NULL);
		if (tcore_sim_get_cphs_status(o)) {
			tmp = tcore_sim_encode_cff((const struct tel_sim_callforwarding *) cf);
			ef = SIM_EF_CPHS_CALL_FORWARD_FLAGS;
			p1 = 0;
			p2 = 0;
			p3 = strlen(tmp);
			encoded_data = (char *) malloc(2 * (p3) + 1);
			memset(encoded_data, 0x00, (2 *p3) + 1);
			result = util_byte_to_hex(tmp, encoded_data, p3);
			cmd = 214;                  /*command - 214 : UPDATE BINARY*/
		} else {
			tmp = tcore_sim_encode_cfis(&encoded_len, (const struct tel_sim_callforwarding *) cf);
			ef = SIM_EF_USIM_CFIS;
			p1 = 1;
			p2 = 0x04;
			p3 = encoded_len;
			encoded_data = (char *) malloc(2 * (encoded_len) + 1);
			memset(encoded_data, 0x00, (2 * encoded_len) + 1);
			result = util_byte_to_hex(tmp, encoded_data, encoded_len);
			cmd = 220;                  /*command - 220 : UPDATE RECORD*/
		}
		break;

	default:
		dbg("error - not handled update treq command[%d]", command);
		api_ret = TCORE_RETURN_EINVAL;
		break;
	}
	file_meta.file_id = ef;
	dbg("file_meta.file_id: %d", file_meta.file_id);

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &file_meta);
	dbg("trt[%d]", trt);

	cmd_str = g_strdup_printf("AT+CRSM=%d,%d,%d,%d,%d,\"%s\"", cmd, ef, p1, p2, p3, encoded_data);
	req = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_update_file, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);

	tcore_hal_send_request(hal, pending);
	if (NULL != encoded_data) {
		g_free(encoded_data);
	}
	free(cmd_str);

	if (tmp) {
		free(tmp);
	}

	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_transmit_apdu(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	char *apdu = NULL;
	int result = 0;
	const struct treq_sim_transmit_apdu *req_data;

	dbg(" Function entry ");

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	apdu = (char *) malloc((2 * req_data->apdu_length) + 1);
	memset(apdu, 0x00, (2 * req_data->apdu_length) + 1);
	result = util_byte_to_hex((const char *) req_data->apdu, apdu, req_data->apdu_length);

	cmd_str = g_strdup_printf("AT+CSIM=%d,\"%s\"", req_data->apdu_length * 2, apdu);

	req = tcore_at_request_new(cmd_str, "+CSIM:", TCORE_AT_SINGLELINE);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_transmit_apdu, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sim_message_send, NULL);
	tcore_hal_send_request(hal, pending);

	free(cmd_str);
	free(apdu);
	dbg(" Function exit");
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_sim_operations sim_ops = {
	.verify_pins = s_verify_pins,
	.verify_puks = s_verify_puks,
	.change_pins = s_change_pins,
	.get_facility_status = s_get_facility_status,
	.enable_facility = s_enable_facility,
	.disable_facility = s_disable_facility,
	.get_lock_info = s_get_lock_info,
	.read_file = s_read_file,
	.update_file = s_update_file,
	.transmit_apdu = s_transmit_apdu,
	/*ToDo - Need to be implemented in Phase-2*/
	/*.get_atr = s_get_atr,
	.req_authentication = s_req_authentication*/
};

gboolean s_sim_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *o;
	struct s_sim_property *file_meta = NULL;
	GQueue *work_queue;

	dbg("entry");

	o = tcore_sim_new(p, "sim", &sim_ops, h);

	if (!o)
		return FALSE;

	file_meta = calloc(sizeof(struct s_sim_property), 1);
	if (!file_meta)
		return FALSE;

	work_queue = g_queue_new();
	tcore_object_link_user_data(o, work_queue);

	file_meta->first_recv_status = SIM_STATUS_UNKNOWN;
	tcore_sim_link_userdata(o, file_meta);

	tcore_object_add_callback(o, "+XLOCK", on_event_facility_lock_status, NULL);
	tcore_object_add_callback(o, "+XSIM", on_event_pin_status, NULL);

	dbg("exit");
	return TRUE;
}

void s_sim_exit(TcorePlugin *p)
{
	CoreObject *o;

	o = tcore_plugin_ref_core_object(p, "sim");
	if (!o)
		return;
	tcore_sim_free(o);
}
