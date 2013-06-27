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
#include <co_sms.h>
#include <storage.h>
#include <user_request.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
#include "s_sms.h"
#include "s_sim.h"

#define ID_RESERVED_AT 0x0229

#define SWAPBYTES16(x) \
	{ \
		unsigned short int data = *(unsigned short int *)&(x);	\
		data = ((data & 0xff00) >> 8) |	  \
			   ((data & 0x00ff) << 8);	  \
		*(unsigned short int *)&(x) = data;	 \
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
	enum s_sim_sec_op_e current_sec_op; /**< current index to read */
	struct tel_sim_mbi_list mbi_list;
	struct tel_sim_mb_number mb_list[SIM_MSP_CNT_MAX*5];
	struct tresp_sim_read files;
};

static void _next_from_get_file_info(CoreObject *o, UserRequest *ur, enum tel_sim_file_id ef, enum tel_sim_access_result rt);
static void _next_from_get_file_data(CoreObject *o, UserRequest *ur, enum tel_sim_access_result rt, int decode_ret);
static gboolean _get_sim_type(CoreObject *o);
static TReturn _get_file_info(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef);
static gboolean _get_file_data(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int offset, const int length);
static gboolean _get_file_record(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef, const int index, const int length);
static void _sim_status_update(CoreObject *o, enum tel_sim_status sim_status);
extern gboolean util_byte_to_hex(const char *byte_pdu, char *hex_pdu, int num_bytes);

static void sim_prepare_and_send_pending_request(CoreObject *co, const char *at_cmd, const char *prefix, enum tcore_at_command_type at_cmd_type, TcorePendingResponseCallback callback)
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
	tcore_pending_link_user_request(pending, NULL); // set user request to NULL - this is internal request
	ret = tcore_hal_send_request(hal, pending);
	return;
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
		dbg("not handled current sec op[%d]", op);
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
		dbg("error - SIM application toolkit busy [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg("error - No EF Selected [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x02) {
		rst = SIM_ACCESS_FAILED;
		/*Failed SIM request command*/
		dbg("error - Out of Range - Invalid address or record number[%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x04) {
		rst = SIM_ACCESS_FILE_NOT_FOUND;
		/*Failed SIM request command*/
		dbg("error - File ID not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x94 && status_word2 == 0x08) {
		rst = SIM_ACCESS_FAILED; /* MOdem not support */
		/*Failed SIM request command*/
		dbg("error - File is inconsistent with command - Modem not support or USE IPC [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x02) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - CHV not initialized [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x04) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - Access condition not fullfilled [%x][%x]", status_word1, status_word2);
		dbg("error -Unsuccessful CHV verification - at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Unsuccessful Unblock CHV - at least one attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Authentication failure [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x08) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - Contradiction with CHV status [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x10) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error - Contradiction with invalidation status [%x][%x]",
			status_word1, status_word2);
	} else if (status_word1 == 0x98 && status_word2 == 0x40) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		/*Failed SIM request command*/
		dbg("error -Unsuccessful CHV verification - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - Unsuccessful Unblock CHV - no attempt left [%x][%x]",
			status_word1, status_word2);
		dbg("error - CHV blocked [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x67 && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg("error -Incorrect Parameter 3 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6B && status_word2 == 0x00) {
		rst = SIM_ACCESS_FAILED;
		dbg("error -Incorrect Parameter 1 or 2 [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6D && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg("error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6E && status_word2 == 0x00) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg("error -Unknown instruction given as command [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x69 && status_word2 == 0x82) {
		rst = SIM_ACCESS_CONDITION_NOT_SATISFIED;
		dbg("error -Access denied [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x87) {
		rst = SIM_ACCESS_FAILED;
		dbg("error -Incorrect parameters [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x82) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg("error -File Not found [%x][%x]", status_word1, status_word2);
	} else if (status_word1 == 0x6A && status_word2 == 0x83) {
		rst = SIM_ACCESS_FILE_NOT_FOUND; // not sure of the SW1 and SW2 meaning here
		dbg("error -Record Not found [%x][%x]", status_word1, status_word2);
	} else {
		rst = SIM_ACCESS_CARD_ERROR;
		dbg("error -Unknown state [%x][%x]", status_word1, status_word2);
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
	strg = (Storage *)tcore_server_find_storage(s, "vconf");
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
			if (tcore_storage_set_string(strg, STORAGE_KEY_TELEPHONY_IMSI, (const char *)&new_imsi) == FALSE) {
				dbg("[FAIL] UPDATE STORAGE_KEY_TELEPHONY_IMSI");
			}
			tcore_sim_set_identification(o, TRUE);
		} else {
			dbg("SAME SIM");
			tcore_sim_set_identification(o, FALSE);
		}
	} else {
		dbg("OLD SIM VALUE IS NULL. NEW SIM");
		if (tcore_storage_set_string(strg, STORAGE_KEY_TELEPHONY_IMSI, (const char *)&new_imsi) == FALSE) {
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
	file_meta = (struct s_sim_property *)tcore_user_request_ref_metainfo(ur, NULL);

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
				dbg("[SIM DATA]SIM_EF_ELP(2F05) access fail. Request SIM_EF_LP(0x6F05) info");
				/* The ME requests the Language Preference (EFLP) if EFELP is not available */
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

	case SIM_EF_LP:   // same with SIM_EF_USIM_LI
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
			/* if EFLI is not present, then the language selection shall be as defined in EFPL at the MF level	*/
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
	case SIM_EF_MSISDN:
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

	file_meta = (struct s_sim_property *)tcore_user_request_ref_metainfo(ur, NULL);
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
		ur = tcore_user_request_new(NULL, NULL);   // this is for using ur metainfo set/ref functionality.
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
			memcpy(file_meta->files.data.cphs_net.full_name, file_meta->files.data.cphs_net.full_name, strlen((char *)file_meta->files.data.cphs_net.full_name));
		}
		_get_file_info(o, ur, SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING);
		break;

	case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
		if (file_meta->files.result == SIM_ACCESS_SUCCESS || file_meta->files.result == SIM_ACCESS_SUCCESS) {
			file_meta->files.result = SIM_ACCESS_SUCCESS;
		}
		if (strlen((char *)file_meta->files.data.cphs_net.full_name)) {
			memcpy(&file_meta->files.data.cphs_net.full_name, &file_meta->files.data.cphs_net.full_name, strlen((char *)file_meta->files.data.cphs_net.full_name));
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

	if (sim_status != tcore_sim_get_status(o)) {
		dbg("Change in SIM State - Old State: [0x%02x] New State: [0x%02x]",
				tcore_sim_get_status(o), sim_status);

		/* Update SIM Status */
		tcore_sim_set_status(o, sim_status);
		noti_data.sim_status = sim_status;

		/* Send notification */
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)),
				o, TNOTI_SIM_STATUS, sizeof(noti_data), &noti_data);
	}
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

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("Invalid message");
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

	if (sim_type != SIM_TYPE_UNKNOWN) {
		/* set user request for using ur metainfo set/ref functionality */
		ur = tcore_user_request_new(NULL, NULL);
		_get_file_info(co_sim, ur, SIM_EF_IMSI);
	}

	tcore_at_tok_free(tokens);
	dbg("Exit");
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

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	file_meta = (struct s_sim_property *)tcore_user_request_ref_metainfo(ur, NULL);

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
			util_hex_dump("   ", strlen(hexData) / 2, recordData);
			g_free(tmp);

			ptr_data = (unsigned char *)recordData;
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
						/*	unsigned char file_desc_len = *ptr_data++;*/
						/*	dbg("file descriptor length: [%d]", file_desc_len);*/
						/* TBD: currently capture only file type : ignore sharable, non sharable, working, internal etc*/
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
							dbg("Cyclic fixed file type");
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
							file_type = SIM_FTYPE_CYCLIC;
							break;

						default:
							dbg("not handled file type [0x%x]", *ptr_data);
							break;
						}
					} else {
						dbg("INVALID FCP received - DEbug!");
						tcore_at_tok_free(tokens);
						g_free(recordData);
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
						tcore_at_tok_free(tokens);
						g_free(recordData);
						return;
					}

					/*	proprietary information */
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
						tcore_at_tok_free(tokens);
						g_free(recordData);
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
						tcore_at_tok_free(tokens);
						g_free(recordData);
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
					tcore_at_tok_free(tokens);
					g_free(recordData);
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
				/* file id */
				memcpy(&file_id, ptr_data, 2);
				SWAPBYTES16(file_id);
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
					dbg("not handled file type");
					break;
				}
			} else {
				dbg("Card Type - UNKNOWN [%d]", tcore_sim_get_type(co_sim));
			}

			dbg("req ef[0x%x] resp ef[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]",
				file_meta->file_id, file_id, file_size, file_type, num_of_records, record_len);

			file_meta->file_type = file_type;
			file_meta->data_size = file_size;
			file_meta->rec_length = record_len;
			file_meta->rec_count = num_of_records;
			file_meta->current_index = 0; // reset for new record type EF
			rt = SIM_ACCESS_SUCCESS;
			g_free(recordData);
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
	dbg("Exit");
}

static void _response_get_file_data(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *file_meta = NULL;
	GSList *tokens = NULL;
	enum tel_sim_access_result rt;
	gboolean dr = FALSE;
	const char *line = NULL;
	char *res = NULL;
	char *tmp = NULL;
	int res_len;
	int sw1 = 0;
	int sw2 = 0;

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	file_meta = (struct s_sim_property *)tcore_user_request_ref_metainfo(ur, NULL);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 3) {
				msg("Invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		sw1 = atoi(g_slist_nth_data(tokens, 0));
		sw2 = atoi(g_slist_nth_data(tokens, 1));
		res = g_slist_nth_data(tokens, 2);

		tmp = util_removeQuotes(res);
		res = util_hexStringToBytes(tmp);
		res_len = strlen(tmp) / 2;
		dbg("Response: [%s] Response length: [%d]", res, res_len);

		if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) {
			rt = SIM_ACCESS_SUCCESS;
			file_meta->files.result = rt;

			dbg("File ID: [0x%x]", file_meta->file_id);
			switch (file_meta->file_id) {
			case SIM_EF_IMSI:
			{
				struct tel_sim_imsi *imsi = NULL;

				dbg("Data: [%s]", res);
				imsi = g_try_new0(struct tel_sim_imsi, 1);
				dr = tcore_sim_decode_imsi(imsi, (unsigned char *)res, res_len);
				if (dr == FALSE) {
					err("IMSI decoding failed");
				} else {
					_sim_check_identity(co_sim, imsi);
					tcore_sim_set_imsi(co_sim, imsi);
				}

				/* Free memory */
				g_free(imsi);
			}
			break;

			case SIM_EF_ICCID:
				dr = tcore_sim_decode_iccid(&file_meta->files.data.iccid, (unsigned char *)res, res_len);
			break;

			case SIM_EF_ELP:			/* 2G EF - 2 bytes decoding */
			case SIM_EF_USIM_LI:		/* 3G EF - 2 bytes decoding */
			case SIM_EF_USIM_PL:		/* 3G EF - same as EFELP, so 2 byte decoding */
			case SIM_EF_LP:				/* 1 byte encoding */
				if ((tcore_sim_get_type(co_sim) == SIM_TYPE_GSM)
						&& (file_meta->file_id == SIM_EF_LP)) {
					/*
					 * 2G LP(0x6F05) has 1 byte for each language
					 */
					dr = tcore_sim_decode_lp(&file_meta->files.data.language,
								(unsigned char *)res, res_len);
				} else {
					/*
					 * 3G LI(0x6F05)/PL(0x2F05),
					 * 2G ELP(0x2F05) has 2 bytes for each language
					 */
					dr = tcore_sim_decode_li(file_meta->file_id,
								&file_meta->files.data.language,
								(unsigned char *)res, res_len);
				}
			break;

			case SIM_EF_SPN:
				dr = tcore_sim_decode_spn(&file_meta->files.data.spn,
								(unsigned char *)res, res_len);
			break;

			case SIM_EF_SPDI:
				dr = tcore_sim_decode_spdi(&file_meta->files.data.spdi,
								(unsigned char *)res, res_len);
			break;

			case SIM_EF_SST: //EF UST has same address
			{
				struct tel_sim_service_table *svct = NULL;

				svct = g_try_new0(struct tel_sim_service_table, 1);
				if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM) {
					dr = tcore_sim_decode_sst(&svct->sst , (unsigned char *)res, res_len);
				} else if (tcore_sim_get_type(co_sim) == SIM_TYPE_USIM) {
					dr = tcore_sim_decode_ust(&svct->ust , (unsigned char *)res, res_len);
				} else {
					dbg("err not handled tcore_sim_get_type(o)[%d] in here",tcore_sim_get_type(co_sim));
				}

				if (dr == FALSE) {
					dbg("SST/UST decoding failed");
				} else {
					tcore_sim_set_service_table(co_sim, svct);
				}

				/* Free memory */
				g_free(svct);
			}
			break;

			case SIM_EF_ECC:
			{
				if (tcore_sim_get_type(co_sim) == SIM_TYPE_GSM) {
					dr = tcore_sim_decode_ecc(&file_meta->files.data.ecc, (unsigned char *)res, res_len);
				} else if (tcore_sim_get_type(co_sim) == SIM_TYPE_USIM) {
					struct tel_sim_ecc *ecc = NULL;

					ecc = g_try_new0(struct tel_sim_ecc, 1);
					dbg("Index [%d]", file_meta->current_index);

					dr = tcore_sim_decode_uecc(ecc, (unsigned char *)res, res_len);
					if (dr == TRUE) {
						memcpy(&file_meta->files.data.ecc.ecc[file_meta->files.data.ecc.ecc_count], ecc, sizeof(struct tel_sim_ecc));
						file_meta->files.data.ecc.ecc_count++;
					}

					/* Free memory */
					g_free(ecc);
				} else {
					dbg("Unknown/Unsupported SIM Type: [%d]", tcore_sim_get_type(co_sim));
				}
			}
			break;

			case SIM_EF_MSISDN:
			{
				struct tel_sim_msisdn *msisdn = NULL;

				dbg("Index [%d]", file_meta->current_index);
				msisdn = g_try_new0(struct tel_sim_msisdn, 1);
				dr = tcore_sim_decode_msisdn(msisdn, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.msisdn_list.msisdn[file_meta->files.data.msisdn_list.count],
								msisdn, sizeof(struct tel_sim_msisdn));

					file_meta->files.data.msisdn_list.count++;
				}

				/* Free memory */
				g_free(msisdn);
			}
			break;

			case SIM_EF_OPL:
			{
				struct tel_sim_opl *opl = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				opl = g_try_new0(struct tel_sim_opl, 1);

				dr = tcore_sim_decode_opl(opl, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.opl.opl[file_meta->files.data.opl.opl_count],
							opl, sizeof(struct tel_sim_opl));

					file_meta->files.data.opl.opl_count++;
				}

				/* Free memory */
				g_free(opl);
			}
			break;

			case SIM_EF_PNN:
			{
				struct tel_sim_pnn *pnn = NULL;

				dbg("decode w/ index [%d]", file_meta->current_index);
				pnn = g_try_new0(struct tel_sim_pnn, 1);

				dr = tcore_sim_decode_pnn(pnn, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.pnn.pnn[file_meta->files.data.pnn.pnn_count],
								pnn, sizeof(struct tel_sim_pnn));

					file_meta->files.data.pnn.pnn_count++;
				}

				/* Free memory */
				g_free(pnn);
			}
			break;

			case SIM_EF_OPLMN_ACT:
				dr = tcore_sim_decode_oplmnwact(&file_meta->files.data.opwa,
										(unsigned char *)res, res_len);
			break;

			case SIM_EF_CPHS_CUSTOMER_SERVICE_PROFILE:
				/*dr = tcore_sim_decode_csp(&po->p_cphs->csp,
										p_data->response, p_data->response_len);*/
			break;

			case SIM_EF_USIM_MBI: //linear type
			{
				struct tel_sim_mbi *mbi = NULL;

				mbi = g_try_new0(struct tel_sim_mbi, 1);
				dr = tcore_sim_decode_mbi(mbi, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->mbi_list.mbi[file_meta->mbi_list.profile_count],
										mbi, sizeof(struct tel_sim_mbi));
					file_meta->mbi_list.profile_count++;

					dbg("mbi count[%d]", file_meta->mbi_list.profile_count);
					dbg("voice_index[%d]", file_meta->mbi_list.mbi[file_meta->mbi_list.profile_count -1].voice_index);
					dbg("fax_index[%d]", file_meta->mbi_list.mbi[file_meta->mbi_list.profile_count -1].fax_index);
					dbg("email_index[%d]", file_meta->mbi_list.mbi[file_meta->mbi_list.profile_count -1].email_index);
					dbg("other_index[%d]", file_meta->mbi_list.mbi[file_meta->mbi_list.profile_count -1].other_index);
					dbg("video_index[%d]", file_meta->mbi_list.mbi[file_meta->mbi_list.profile_count -1].video_index);
				}

				/* Free memory */
				g_free(mbi);
			}
			break;

			case SIM_EF_CPHS_MAILBOX_NUMBERS: // linear type
			case SIM_EF_MBDN: //linear type
				dr = tcore_sim_decode_xdn(&file_meta->mb_list[file_meta->current_index-1].number_info,
									(unsigned char *)res, res_len);
				file_meta->mb_list[file_meta->current_index-1].rec_index = file_meta->current_index;
			break;

			case SIM_EF_CPHS_VOICE_MSG_WAITING: // transparent type
				dr = tcore_sim_decode_vmwf(&file_meta->files.data.mw.cphs_mw,
									(unsigned char *)res, res_len);
			break;

			case SIM_EF_USIM_MWIS: //linear type
			{
				struct tel_sim_mw *mw = NULL;

				mw = g_try_new0(struct tel_sim_mw, 1);

				dr = tcore_sim_decode_mwis(mw, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.mw.mw_list.mw[file_meta->files.data.mw.mw_list.profile_count], mw, sizeof(struct tel_sim_mw));
					file_meta->files.data.mw.mw_list.mw[file_meta->files.data.mw.mw_list.profile_count].rec_index = file_meta->current_index;
					file_meta->files.data.mw.mw_list.profile_count++;
				}

				/* Free memory */
				g_free(mw);
			}
			break;

			case SIM_EF_CPHS_CALL_FORWARD_FLAGS: //transparent type
				dr = tcore_sim_decode_cff(&file_meta->files.data.cf.cphs_cf,
									(unsigned char *)res, res_len);
			break;

			case SIM_EF_USIM_CFIS: //linear type
			{
				struct tel_sim_cfis *cf = NULL;

				cf = g_try_new0(struct tel_sim_cfis, 1);
				dr = tcore_sim_decode_cfis(cf, (unsigned char *)res, res_len);
				if (dr == TRUE) {
					memcpy(&file_meta->files.data.cf.cf_list.cf[file_meta->files.data.cf.cf_list.profile_count],
									cf, sizeof(struct tel_sim_cfis));

					file_meta->files.data.cf.cf_list.cf[file_meta->files.data.cf.cf_list.profile_count].rec_index = file_meta->current_index;
					file_meta->files.data.cf.cf_list.profile_count++;
				}

				/* Free memory */
				g_free(cf);
			}
			break;

			case SIM_EF_CPHS_SERVICE_STRING_TABLE:
				dbg("not handled -SIM_EF_CPHS_SERVICE_STRING_TABLE ");
			break;

			case SIM_EF_CPHS_OPERATOR_NAME_STRING:
				dr = tcore_sim_decode_ons((unsigned char*)&file_meta->files.data.cphs_net.full_name,
									(unsigned char *)res, res_len);
				dbg("file_meta->files.result[%d],file_meta->files.data.cphs_net.full_name[%s]",
						file_meta->files.result, file_meta->files.data.cphs_net.full_name);
			break;

			case SIM_EF_CPHS_DYNAMICFLAGS:
				/*dr = tcore_sim_decode_dynamic_flag(&po->p_cphs->dflagsinfo,
										p_data->response, p_data->response_len);*/
			break;

			case SIM_EF_CPHS_DYNAMIC2FLAG:
				/*dr = tcore_sim_decode_dynamic2_flag(&po->p_cphs->d2flagsinfo, p_data->response,
										p_data->response_len);*/
			break;

			case SIM_EF_CPHS_CPHS_INFO:
				dr = tcore_sim_decode_cphs_info(&file_meta->files.data.cphs,
										(unsigned char *)res, res_len);
			break;

			case SIM_EF_CPHS_OPERATOR_NAME_SHORT_FORM_STRING:
				dr = tcore_sim_decode_short_ons((unsigned char*)&file_meta->files.data.cphs_net.short_name,
										(unsigned char *)res, res_len);
			break;

			case SIM_EF_CPHS_INFORMATION_NUMBERS:
				/*dr = tcore_sim_decode_information_number(&po->p_cphs->infn, p_data->response, p_data->response_len);*/
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

		/* Free memory */
		g_free(tmp);
		g_free(res);

		/* Free tokens */
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		dbg("Error - File ID: [0x%x]", file_meta->file_id);
		rt = SIM_ACCESS_FAILED;
	}

	/* Reference User Request */
	ur = tcore_user_request_ref(ur);

	/* Get File data */
	_next_from_get_file_data(tcore_pending_ref_core_object(p), ur, rt, dr);

	dbg("Exit");
}

static void _on_response_get_retry_count(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	const char *line = NULL;
	int lock_type = 0;
	int attempts_left = 0;
	int time_penalty = 0;

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 3) {
				msg("Invalid message");
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
		{
			struct tresp_sim_verify_pins v_pin = {0, };

			v_pin.result = SIM_INCORRECT_PASSWORD;
			v_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_pin.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_verify_pins), &v_pin);
		}
		break;

		case SEC_PUK1_VERIFY:
		case SEC_PUK2_VERIFY:
		{
			struct tresp_sim_verify_puks v_puk = {0, };

			v_puk.result = SIM_INCORRECT_PASSWORD;
			v_puk.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_puk.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_verify_puks), &v_puk);
		}
		break;

		case SEC_PIN1_CHANGE:
		case SEC_PIN2_CHANGE:
		{
			struct tresp_sim_change_pins change_pin = {0, };

			change_pin.result = SIM_INCORRECT_PASSWORD;
			change_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			change_pin.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_change_pins), &change_pin);
		}
		break;

		case SEC_PIN1_DISABLE:
		case SEC_PIN2_DISABLE:
		case SEC_FDN_DISABLE:
		case SEC_SIM_DISABLE:
		case SEC_NET_DISABLE:
		case SEC_NS_DISABLE:
		case SEC_SP_DISABLE:
		case SEC_CP_DISABLE:
		{
			struct tresp_sim_disable_facility dis_facility = {0, };

			dis_facility.result = SIM_INCORRECT_PASSWORD;
			dis_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			dis_facility.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_disable_facility), &dis_facility);
		}
		break;

		case SEC_PIN1_ENABLE:
		case SEC_PIN2_ENABLE:
		case SEC_FDN_ENABLE:
		case SEC_SIM_ENABLE:
		case SEC_NET_ENABLE:
		case SEC_NS_ENABLE:
		case SEC_SP_ENABLE:
		case SEC_CP_ENABLE:
		{
			struct tresp_sim_enable_facility en_facility = {0, };

			en_facility.result = SIM_INCORRECT_PASSWORD;
			en_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			en_facility.retry_count = attempts_left;
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											 sizeof(struct tresp_sim_enable_facility), &en_facility);
		}
		break;

		default:
			dbg("not handled sec op[%d]", sp->current_sec_op);
		break;
		}

		/* Free tokens */
		tcore_at_tok_free(tokens);
	}

	dbg("Exit");
}

static gboolean _get_sim_type(CoreObject *o)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	UserRequest *ur = NULL;
	char *cmd_str = NULL;

	dbg("Entry");

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	cmd_str = g_strdup_printf("AT+XUICC?");
	req = tcore_at_request_new(cmd_str, "+XUICC:", TCORE_AT_SINGLELINE);
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s] Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _response_get_sim_type, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return TRUE;
}

static TReturn _get_file_info(CoreObject *o, UserRequest *ur, const enum tel_sim_file_id ef)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	struct s_sim_property file_meta = {0, };
	char *cmd_str = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;
	int trt = 0;

	dbg("Entry");

	file_meta.file_id = ef;
	dbg("file_meta.file_id: [0x%02x]", file_meta.file_id);
	hal = tcore_object_get_hal(o);
	dbg("hal: %x", hal);

	trt = tcore_user_request_set_metainfo(ur, sizeof(struct s_sim_property), &file_meta);
	dbg("trt[%d]", trt);
	cmd_str = g_strdup_printf("AT+CRSM=192, %d", ef);      /*command - 192 : GET RESPONSE*/
	dbg("Command: [%s] Command length: [%d]", cmd_str, strlen(cmd_str));

	pending = tcore_at_pending_new(o, cmd_str, "+CRSM:", TCORE_AT_SINGLELINE, _response_get_file_info, NULL);
	tcore_pending_link_user_request(pending, ur);
	ret = tcore_hal_send_request(hal, pending);
	if (TCORE_RETURN_SUCCESS != ret) {
		tcore_user_request_free(ur);
	}

	g_free(cmd_str);
	dbg("Exit");
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

	dbg("Entry");
	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	dbg("file_id: %x", ef);

	p1 = (unsigned char) (offset & 0xFF00) >> 8;
	p2 = (unsigned char) offset & 0x00FF; // offset low
	p3 = (unsigned char) length;

	cmd_str = g_strdup_printf("AT+CRSM=176, %d, %d, %d, %d", ef, p1, p2, p3);     /*command - 176 : READ BINARY*/

	req = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _response_get_file_data, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_hal_send_request(hal, pending);

	dbg("Exit");
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

	dbg("Entry");

	hal = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	p1 = (unsigned char) index;
	p2 = (unsigned char) 0x04;    /* 0x4 for absolute mode */
	p3 = (unsigned char) length;

	cmd_str = g_strdup_printf("AT+CRSM=178, %d, %d, %d, %d", ef, p1, p2, p3);     /*command - 178 : READ RECORD*/

	req = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _response_get_file_data, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_hal_send_request(hal, pending);

	dbg("Exit");
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

	dbg("Entry");

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
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, _on_response_get_retry_count, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_hal_send_request(hal, pending);

	dbg("Exit");
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
	lines = (GSList *)event_info;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}
	line = (char *)(lines->data);
	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) != 1) {
		msg("Invalid message");
		tcore_at_tok_free(tokens);
		return TRUE;
	}

OUT:
	dbg("Exit");
	if (NULL != tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}

static void notify_sms_state(TcorePlugin *plugin, CoreObject *co_sim,
				gboolean sms_ready)
{
	Server *server = tcore_plugin_ref_server(plugin);
	struct tnoti_sms_ready_status sms_ready_noti;
	CoreObject *co_sms;

	dbg("Entry");

	co_sms = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SMS);
	if (co_sms == NULL) {
		err("Can't find SMS core object");
		return;
	}

	if (tcore_sms_get_ready_status(co_sms) == sms_ready)
		return;

	tcore_sms_set_ready_status(co_sms, sms_ready);

	if (tcore_sim_get_status(co_sim) == SIM_STATUS_INIT_COMPLETED) {
		sms_ready_noti.status = sms_ready;
		tcore_server_send_notification(server, co_sms,
						TNOTI_SMS_DEVICE_READY,
						sizeof(sms_ready_noti),
						&sms_ready_noti);
	}

	dbg("Exit");
}

static gboolean on_event_pin_status(CoreObject *o, const void *event_info, void *user_data)
{
	TcorePlugin *plugin = tcore_object_ref_plugin(o);
	enum tel_sim_status sim_status = SIM_STATUS_INITIALIZING;
	GSList *tokens = NULL;
	GSList *lines;
	const char *line;
	int sim_state = 0;
	int sms_state = 0;

	dbg("Entry");

	lines = (GSList *)event_info;
	if (g_slist_length(lines) != 1) {
		err("Unsolicited message BUT multiple lines");
		goto out;
	}

	line = lines->data;

	/* Create 'tokens' */
	tokens = tcore_at_tok_new(line);

	/* SIM State */
	if (g_slist_length(tokens) == 4) {
		sim_state = atoi(g_slist_nth_data(tokens, 1));
		sms_state = atoi(g_slist_nth_data(tokens, 3));
		notify_sms_state(plugin, o, (sms_state > 0));
	} else if (g_slist_length(tokens) == 1) {
		sim_state = atoi(g_slist_nth_data(tokens, 0));
	} else {
		err("Invalid message");
		goto out;
	}

	switch (sim_state) {
	case 0:
		sim_status = SIM_STATUS_CARD_NOT_PRESENT;
		dbg("NO SIM");
		break;

	case 1:
		sim_status = SIM_STATUS_PIN_REQUIRED;
		dbg("PIN REQUIRED");
		break;

	case 2:
		sim_status = SIM_STATUS_INITIALIZING;
		dbg("PIN DISABLED AT BOOT UP");
		break;

	case 3:
		sim_status = SIM_STATUS_INITIALIZING;
		dbg("PIN VERIFIED");
		break;

	case 4:
		sim_status = SIM_STATUS_PUK_REQUIRED;
		dbg("PUK REQUIRED");
		break;

	case 5:
		sim_status = SIM_STATUS_CARD_BLOCKED;
		dbg("CARD PERMANENTLY BLOCKED");
		break;

	case 6:
		sim_status = SIM_STATUS_CARD_ERROR;
		dbg("SIM CARD ERROR");
		break;

	case 7:
		sim_status = SIM_STATUS_INIT_COMPLETED;
		dbg("SIM INIT COMPLETED");
		break;

	case 8:
		sim_status = SIM_STATUS_CARD_ERROR;
		dbg("SIM CARD ERROR");
		break;

	case 9:
		sim_status = SIM_STATUS_CARD_REMOVED;
		dbg("SIM REMOVED");
		break;

	case 12:
		dbg("SIM SMS Ready");
		notify_sms_state(plugin, o, TRUE);
		goto out;

	case 99:
		sim_status = SIM_STATUS_UNKNOWN;
		dbg("SIM STATE UNKNOWN");
		break;

	default:
		err("Unknown/Unsupported SIM state: [%d]", sim_state);
		goto out;
	}

	switch (sim_status) {
	case SIM_STATUS_INIT_COMPLETED:
		dbg("[SIM] SIM INIT COMPLETED");
		if (tcore_sim_get_type(o) == SIM_TYPE_UNKNOWN) {
			_get_sim_type(o);
			goto out;
		}

		break;

	case SIM_STATUS_CARD_REMOVED:
		dbg("[SIM] SIM CARD REMOVED");
		tcore_sim_set_type(o, SIM_TYPE_UNKNOWN);
		break;

	case SIM_STATUS_CARD_NOT_PRESENT:
		dbg("[SIM] SIM CARD NOT PRESENT");
		tcore_sim_set_type(o, SIM_TYPE_UNKNOWN);
		break;

	case SIM_STATUS_CARD_ERROR:
		dbg("[SIM] SIM CARD ERROR");
		tcore_sim_set_type(o, SIM_TYPE_UNKNOWN);
		break;

	default:
		dbg("SIM Status: [0x%02x]", sim_status);
		break;
	}

	_sim_status_update(o, sim_status);

out:
	tcore_at_tok_free(tokens);

	dbg("Exit");
	return TRUE;
}

static void on_response_get_sim_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_sim = NULL;

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines)
			on_event_pin_status(co_sim, resp->lines, NULL);
	} else {
		dbg("RESPONSE NOK");
	}

	dbg("Exit");
}

static enum tcore_hook_return on_hook_modem_power(Server *s, CoreObject *source, enum tcore_notification_command command,
											  unsigned int data_len, void *data, void *user_data)
{
	TcorePlugin *plugin = tcore_object_ref_plugin(source);
	CoreObject *co_sim = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);

	if (co_sim == NULL)
		return TCORE_HOOK_RETURN_CONTINUE;

	dbg("Get SIM status");

	sim_prepare_and_send_pending_request(co_sim, "AT+XSIMSTATE?", "+XSIMSTATE:", TCORE_AT_SINGLELINE, on_response_get_sim_status);

	return TCORE_HOOK_RETURN_CONTINUE;
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

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_verify_pins));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		res.result = SIM_PIN_OPERATION_SUCCESS;

		/* Get PIN facility */
		res.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
		if ((res.pin_type == SIM_PTYPE_PIN1)
				|| (res.pin_type == SIM_PTYPE_SIM)) {
			if (tcore_sim_get_status(co_sim) != SIM_STATUS_INIT_COMPLETED) {
				/* Update SIM Status */
				_sim_status_update(co_sim, SIM_STATUS_INITIALIZING);
			}
		}

		/* Send Response */
		tcore_user_request_send_response(ur, _find_resp_command(ur),
					sizeof(struct tresp_sim_verify_pins), &res);
	} else {
		dbg("RESPONSE NOK");
		line = (const char *)resp->final_response;
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) < 1) {
			dbg("Unkown Error OR String corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
								sizeof(struct tresp_sim_verify_pins), &res);
		} else {
			err = atoi(g_slist_nth_data(tokens, 0));
			dbg("Error: [%d]", err);

			queue = tcore_object_ref_user_data(co_sim);
			ur = tcore_user_request_ref(ur);

			/* Get retry count */
			_get_retry_count(co_sim, ur);
		}

		/* Free tokens */
		tcore_at_tok_free(tokens);
	}

	dbg("Exit");
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

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_verify_pins));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		res.result = SIM_PIN_OPERATION_SUCCESS;
		res.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);

		/* Send Response */
		tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_verify_pins), &res);
	} else {
		dbg("RESPONSE NOK");
		line = (const char *)resp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("Unkown Error OR String corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_verify_pins), &res);
		} else {
			err = atoi(g_slist_nth_data(tokens, 0));
			queue = tcore_object_ref_user_data(co_sim);
			ur = tcore_user_request_ref(ur);
			_get_retry_count(co_sim, ur);
		}
		tcore_at_tok_free(tokens);
	}
	dbg("Exit");
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

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_change_pins));

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		res.result = SIM_PIN_OPERATION_SUCCESS;
		res.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);

		/* Send Response */
		tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_change_pins), &res);
	} else {
		dbg("RESPONSE NOK");
		line = (const char *)resp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
			dbg("Unkown Error OR String corrupted");
			res.result = TCORE_RETURN_3GPP_ERROR;

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_change_pins), &res);
		} else {
			err = atoi(g_slist_nth_data(tokens, 0));
			queue = tcore_object_ref_user_data(co_sim);
			ur = tcore_user_request_ref(ur);
			_get_retry_count(co_sim, ur);
		}

		/* Free tokens */
		tcore_at_tok_free(tokens);
	}
	dbg("Exit");
}

static void on_response_get_facility_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_get_facility_status *res = user_data;
	const char *line;

	dbg("Entry");

	ur = tcore_pending_ref_user_request(p);

	res->result = SIM_PIN_OPERATION_SUCCESS;

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("Invalid message");
				tcore_at_tok_free(tokens);
				return;
			}
		}
		res->b_enable = atoi(g_slist_nth_data(tokens, 0));
	} else {
		dbg("RESPONSE NOK");
		res->result = SIM_INCOMPATIBLE_PIN_OPERATION;
	}

	/* Send Response */
	if (ur) {
		tcore_user_request_send_response(ur, _find_resp_command(ur),
						sizeof(struct tresp_sim_get_facility_status), res);
	}
	tcore_at_tok_free(tokens);
	g_free(res);
	dbg("Exit");
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

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_enable_facility));

	res.result = SIM_CARD_ERROR;
	res.type = _sim_get_current_pin_facility(sp->current_sec_op);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("Invalid message");

				/* Send Response */
				tcore_user_request_send_response(ur, _find_resp_command(ur),
									 sizeof(struct tresp_sim_enable_facility), &res);
				tcore_at_tok_free(tokens);
				return;
			}
		}

		res.result = SIM_PIN_OPERATION_SUCCESS;

		/* Send Response */
		if (ur) {
			tcore_user_request_send_response(ur, _find_resp_command(ur),
								 sizeof(struct tresp_sim_enable_facility), &res);
		}

		/* Free tokens */
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		queue = tcore_object_ref_user_data(co_sim);
		ur = tcore_user_request_ref(ur);
		_get_retry_count(co_sim, ur);
	}
	dbg("Exit");
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

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_disable_facility));

	res.result = SIM_CARD_ERROR;
	res.type = _sim_get_current_pin_facility(sp->current_sec_op);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 1) {
				msg("Invalid message");

				/* Send Response */
				tcore_user_request_send_response(ur, _find_resp_command(ur),
										sizeof(struct tresp_sim_disable_facility), &res);
				tcore_at_tok_free(tokens);
				return;
			}
		}

		res.result = SIM_PIN_OPERATION_SUCCESS;
		/* Send Response */
		if (ur) {
			tcore_user_request_send_response(ur, _find_resp_command(ur),
									sizeof(struct tresp_sim_disable_facility), &res);
		}

		/* Free tokens */
		tcore_at_tok_free(tokens);
	} else {
		dbg("RESPONSE NOK");
		queue = tcore_object_ref_user_data(co_sim);
		ur = tcore_user_request_ref(ur);
		_get_retry_count(co_sim, ur);
	}
	dbg("Exit");
}

static void on_response_get_lock_info(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	const char *line;
	int lock_type;
	int attempts_left = 0;
	int time_penalty = 0;

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	sp = tcore_sim_ref_userdata(co_sim);
	ur = tcore_pending_ref_user_request(p);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			dbg("Line: [%s]", line);
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 3) {
				msg("Invalid message");
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
		{
			struct tresp_sim_verify_pins v_pin = {0, };

			v_pin.result = SIM_INCORRECT_PASSWORD;
			v_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_pin.retry_count = attempts_left;
			dbg("PIN Type: [0x%02x] Attempts left: [%d]",
							v_pin.pin_type, v_pin.retry_count);

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											sizeof(v_pin), &v_pin);
		}
		break;

		case SEC_PUK1_VERIFY:
		case SEC_PUK2_VERIFY:
		{
			struct tresp_sim_verify_puks v_puk = {0, };

			v_puk.result = SIM_INCORRECT_PASSWORD;
			v_puk.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			v_puk.retry_count = attempts_left;
			dbg("PUK Type: [0x%02x] Attempts left: [%d]",
							v_puk.pin_type, v_puk.retry_count);

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											sizeof(v_puk), &v_puk);
		}
		break;

		case SEC_PIN1_CHANGE:
		case SEC_PIN2_CHANGE:
		{
			struct tresp_sim_change_pins change_pin = {0, };

			change_pin.result = SIM_INCORRECT_PASSWORD;
			change_pin.pin_type = _sim_get_current_pin_facility(sp->current_sec_op);
			change_pin.retry_count = attempts_left;
			dbg("PIN Type: [0x%02x] Attempts left: [%d]",
							change_pin.pin_type, change_pin.retry_count);

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											sizeof(change_pin), &change_pin);
		}
		break;

		case SEC_PIN1_DISABLE:
		case SEC_PIN2_DISABLE:
		case SEC_FDN_DISABLE:
		case SEC_SIM_DISABLE:
		case SEC_NET_DISABLE:
		case SEC_NS_DISABLE:
		case SEC_SP_DISABLE:
		case SEC_CP_DISABLE:
		{
			struct tresp_sim_disable_facility dis_facility = {0, };

			dis_facility.result = SIM_INCORRECT_PASSWORD;
			dis_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			dis_facility.retry_count = attempts_left;
			dbg("Facility Type: [0x%02x] Attempts left: [%d]",
							dis_facility.type, dis_facility.retry_count);

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											sizeof(dis_facility), &dis_facility);
		}
		break;

		case SEC_PIN1_ENABLE:
		case SEC_PIN2_ENABLE:
		case SEC_FDN_ENABLE:
		case SEC_SIM_ENABLE:
		case SEC_NET_ENABLE:
		case SEC_NS_ENABLE:
		case SEC_SP_ENABLE:
		case SEC_CP_ENABLE:
		{
			struct tresp_sim_enable_facility en_facility = {0, };

			en_facility.result = SIM_INCORRECT_PASSWORD;
			en_facility.type = _sim_get_current_pin_facility(sp->current_sec_op);
			en_facility.retry_count = attempts_left;
			dbg("Facility Type: [0x%02x] Attempts left: [%d]",
							en_facility.type, en_facility.retry_count);

			/* Send Response */
			tcore_user_request_send_response(ur, _find_resp_command(ur),
											sizeof(en_facility), &en_facility);
		}
		break;

		default:
			dbg("not handled sec op[%d]", sp->current_sec_op);
			break;
		}

		/* Free tokens */
		tcore_at_tok_free(tokens);
	}
	dbg("Exit");
}

static void on_response_update_file(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	struct tresp_sim_set_data resp_cf = {0, };
	struct tresp_sim_set_data resp_language = {0, };
	struct s_sim_property *sp = NULL;
	GSList *tokens = NULL;
	enum tel_sim_access_result result = SIM_CARD_ERROR;
	const char *line;
	int sw1 = 0;
	int sw2 = 0;

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);
	sp = (struct s_sim_property *)tcore_user_request_ref_metainfo(ur, NULL);

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 2) {
				msg("Invalid message");
				goto OUT;
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
OUT:
	switch (sp->file_id) {
	case SIM_EF_CPHS_CALL_FORWARD_FLAGS:
	case SIM_EF_USIM_CFIS:
		resp_cf.result = result;

		/* Send Response */
		tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_set_data), &resp_cf);
		break;

	case SIM_EF_ELP:
	case SIM_EF_LP:
	case SIM_EF_USIM_LI:
	case SIM_EF_USIM_PL:
		resp_language.result = result;

		/* Send Response */
		tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_set_data), &resp_language);
		break;

	default:
		dbg("Invalid File ID - %d", sp->file_id);
		break;
	}
	tcore_at_tok_free(tokens);
	dbg("Exit");
}

static void on_response_transmit_apdu(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	CoreObject *co_sim = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_transmit_apdu res;
	const char *line;

	dbg("Entry");

	co_sim = tcore_pending_ref_core_object(p);
	ur = tcore_pending_ref_user_request(p);

	memset(&res, 0, sizeof(struct tresp_sim_transmit_apdu));
	res.result = SIM_ACCESS_FAILED;

	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			char *tmp = NULL;
			char *decoded_data = NULL;
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) != 2) {
				msg("Invalid message");
				goto OUT;
			}
			res.apdu_resp_length = atoi(g_slist_nth_data(tokens, 0)) / 2;

			tmp = util_removeQuotes(g_slist_nth_data(tokens, 1));
			decoded_data = util_hexStringToBytes(tmp);

			memcpy((char *)res.apdu_resp, decoded_data, res.apdu_resp_length);
			g_free(tmp);
			g_free(decoded_data);
			res.result = SIM_ACCESS_SUCCESS;
		}
	} else {
		dbg("RESPONSE NOK");
	}

OUT:
	/* Send Response */
	if (ur) {
		tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_transmit_apdu), &res);
	}
	tcore_at_tok_free(tokens);
	dbg("Exit");
}

static void on_response_get_atr(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur = NULL;
	GSList *tokens = NULL;
	struct tresp_sim_get_atr res;
	const char *line;

	dbg("Entry");

	memset(&res, 0, sizeof(struct tresp_sim_get_atr));
	ur = tcore_pending_ref_user_request(p);

	res.result = SIM_ACCESS_FAILED;
	if (resp->success > 0) {
		dbg("RESPONSE OK");
		if (resp->lines) {
			char *tmp = NULL;
			char *decoded_data = NULL;
			line = (const char *)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 1) {
				msg("Invalid message");
				goto OUT;
			}

			tmp = util_removeQuotes(g_slist_nth_data(tokens, 0));
			decoded_data = util_hexStringToBytes(tmp);

			res.atr_length = strlen(tmp) / 2;
			memcpy((char *)res.atr, decoded_data, res.atr_length);
			g_free(tmp);
			g_free(decoded_data);
			res.result = SIM_ACCESS_SUCCESS;
		}
	} else {
		dbg("RESPONSE NOK");
	}

OUT:
	/* Send Response */
	if (ur) {
		tcore_user_request_send_response(ur, _find_resp_command(ur),
							sizeof(struct tresp_sim_get_atr), &res);
	}
	tcore_at_tok_free(tokens);
	dbg("Exit");
}

static TReturn s_verify_pins(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_verify_pins *req_data = NULL;
	struct s_sim_property *sp = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

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
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_verify_pins, hal);
	tcore_pending_link_user_request(pending, ur);
	ret = tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return ret;
}

static TReturn s_verify_puks(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_verify_puks *req_data;
	struct s_sim_property *sp = NULL;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

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
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_verify_puks, hal);
	tcore_pending_link_user_request(pending, ur);
	ret = tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return ret;
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
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

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
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_change_pins, hal);
	tcore_pending_link_user_request(pending, ur);
	ret = tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return ret;
}

static TReturn s_get_facility_status(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	const struct treq_sim_get_facility_status *req_data;
	struct tresp_sim_get_facility_status *res;
	char *fac = "SC";
	int mode = 2;    /* 0:unlock, 1:lock, 2:query*/
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	res = g_try_new0(struct tresp_sim_get_facility_status, 1);
	if (!res)
		return TCORE_RETURN_ENOMEM;

	res->type = req_data->type;

	if (req_data->type == SIM_FACILITY_PS) {
		fac = "PS";               /*PH-SIM, Lock PHone to SIM/UICC card*/
	} else if (req_data->type == SIM_FACILITY_SC) {
		fac = "SC";               /*Lock SIM/UICC card, simply PIN1*/
	} else if (req_data->type == SIM_FACILITY_FD) {
		fac = "FD";               /*Fixed Dialing Number feature, need PIN2*/
	} else if (req_data->type == SIM_FACILITY_PN) {
		fac = "PN";               /*Network Personalization*/
	} else if (req_data->type == SIM_FACILITY_PU) {
		fac = "PU";               /*network sUbset Personalization*/
	} else if (req_data->type == SIM_FACILITY_PP) {
		fac = "PP";               /*service Provider Personalization*/
	} else if (req_data->type == SIM_FACILITY_PC) {
		fac = "PC";               /*Corporate Personalization*/
	} else {
		return TCORE_RETURN_EINVAL;
	}
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d", fac, mode);
	req = tcore_at_request_new(cmd_str, "+CLCK:", TCORE_AT_SINGLELINE);
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_get_facility_status, res);
	tcore_pending_link_user_request(pending, ur);
	ret = tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return ret;
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
	int mode = 1;    /* 0:unlock, 1:lock, 2:query*/
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (req_data->type == SIM_FACILITY_PS) {
		fac = "PS";               /*PH-SIM, Lock PHone to SIM/UICC card*/
		sp->current_sec_op = SEC_SIM_ENABLE;
	} else if (req_data->type == SIM_FACILITY_SC) {
		fac = "SC";               /*Lock SIM/UICC card, simply PIN1*/
		sp->current_sec_op = SEC_PIN1_ENABLE;
	} else if (req_data->type == SIM_FACILITY_FD) {
		fac = "FD";               /*Fixed Dialing Number feature, need PIN2*/
		sp->current_sec_op = SEC_FDN_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PN) {
		fac = "PN";               /*Network Personalization*/
		sp->current_sec_op = SEC_NET_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PU) {
		fac = "PU";               /*network sUbset Personalization*/
		sp->current_sec_op = SEC_NS_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PP) {
		fac = "PP";               /*service Provider Personalization*/
		sp->current_sec_op = SEC_SP_ENABLE;
	} else if (req_data->type == SIM_FACILITY_PC) {
		fac = "PC";               /*Corporate Personalization*/
		sp->current_sec_op = SEC_CP_ENABLE;
	} else {
		return TCORE_RETURN_EINVAL;
	}
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"", fac, mode, req_data->password);
	req = tcore_at_request_new(cmd_str, "+CLCK:", TCORE_AT_SINGLELINE);
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_enable_facility, hal);
	tcore_pending_link_user_request(pending, ur);
	ret = tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return ret;
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
	int mode = 0;    /* 0:unlock, 1:lock, 2:query*/
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if (req_data->type == SIM_FACILITY_PS) {
		fac = "PS";               /*PH-SIM, Lock PHone to SIM/UICC card*/
		sp->current_sec_op = SEC_SIM_DISABLE;
	} else if (req_data->type == SIM_FACILITY_SC) {
		fac = "SC";               /*Lock SIM/UICC card, simply PIN1*/
		sp->current_sec_op = SEC_PIN1_DISABLE;
	} else if (req_data->type == SIM_FACILITY_FD) {
		fac = "FD";               /*Fixed Dialing Number feature, need PIN2*/
		sp->current_sec_op = SEC_FDN_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PN) {
		fac = "PN";               /*Network Personalization*/
		sp->current_sec_op = SEC_NET_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PU) {
		fac = "PU";               /*network sUbset Personalization*/
		sp->current_sec_op = SEC_NS_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PP) {
		fac = "PP";               /*service Provider Personalization*/
		sp->current_sec_op = SEC_SP_DISABLE;
	} else if (req_data->type == SIM_FACILITY_PC) {
		fac = "PC";               /*Corporate Personalization*/
		sp->current_sec_op = SEC_CP_DISABLE;
	} else {
		return TCORE_RETURN_EINVAL;
	}
	cmd_str = g_strdup_printf("AT+CLCK=\"%s\", %d, \"%s\"", fac, mode, req_data->password);
	req = tcore_at_request_new(cmd_str, "+CLCK:", TCORE_AT_SINGLELINE);
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_disable_facility, hal);
	tcore_pending_link_user_request(pending, ur);
	ret = tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return ret;
}

static TReturn s_get_lock_info(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;
	TcoreATRequest *req = NULL;
	TcorePending *pending = NULL;
	char *cmd_str = NULL;
	int lock_type = 0;
	const struct treq_sim_get_lock_info *req_data;
	struct s_sim_property *sp = NULL;

	dbg("Entry");

	hal = tcore_object_get_hal(o);

	sp = tcore_sim_ref_userdata(o);
	pending = tcore_pending_new(o, 0);
	req_data = tcore_user_request_ref_data(ur, NULL);

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	switch (req_data->type) {
	case SIM_FACILITY_PS:
		lock_type = 9; // IMSI lock
		break;

	case SIM_FACILITY_SC:
		lock_type = 1;
		break;

	case SIM_FACILITY_FD:
		lock_type = 2;
		break;

	case SIM_FACILITY_PN:
		lock_type = 5;
		break;

	case SIM_FACILITY_PU:
		lock_type = 6;
		break;

	case SIM_FACILITY_PP:
		lock_type = 7;
		break;

	case SIM_FACILITY_PC:
		lock_type = 8;
		break;

	default:
		break;
	}
	cmd_str = g_strdup_printf("AT+XPINCNT=%d", lock_type);
	req = tcore_at_request_new(cmd_str, "+XPINCNT:", TCORE_AT_SINGLELINE);
	g_free(cmd_str);

	dbg("Command: [%s] Prefix(if any): [%s], Command length: [%d]",
				req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, on_response_get_lock_info, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_hal_send_request(hal, pending);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn s_read_file(CoreObject *o, UserRequest *ur)
{
	TReturn api_ret = TCORE_RETURN_SUCCESS;
	enum tcore_request_command command;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	command = tcore_user_request_get_command(ur);
	if (FALSE == tcore_hal_get_power_state(tcore_object_get_hal(o))) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

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
	dbg("Exit");
	return api_ret;
}

static TReturn s_update_file(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal;
	char *cmd_str = NULL;
	TReturn ret = TCORE_RETURN_SUCCESS;
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

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL)) {
		return TCORE_RETURN_EINVAL;
	}

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
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

			encoded_data = (char *)malloc(2 * (sim_language.language_count) + 1);
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

			encoded_data = (char *)malloc(2 * (out_length) + 1);
			memset(encoded_data, 0x00, (2 * out_length) + 1);
			result = util_byte_to_hex(tmp, encoded_data, out_length);

			p1 = 0;
			p2 = 0;
			p3 = out_length;
			dbg("encoded_data - %s ---", encoded_data);
			dbg("out_length - %d ---", out_length);
		} else {
			ret = TCORE_RETURN_ENOSYS;
		}
		break;

	case TREQ_SIM_SET_CALLFORWARDING:
		cf = tcore_user_request_ref_data(ur, NULL);
		if (tcore_sim_get_cphs_status(o)) {
			tmp = tcore_sim_encode_cff((const struct tel_sim_cphs_cf*)&cf->cphs_cf);
			ef = SIM_EF_CPHS_CALL_FORWARD_FLAGS;
			p1 = 0;
			p2 = 0;
			p3 = strlen(tmp);
			encoded_data = (char *)g_try_malloc0(2 * (p3) + 1);
			result = util_byte_to_hex(tmp, encoded_data, p3);
			cmd = 214;         /*command - 214 : UPDATE BINARY*/
		} else {
			tmp = tcore_sim_encode_cfis(&encoded_len, (const struct tel_sim_cfis*)&cf->cf);
			ef = SIM_EF_USIM_CFIS;
			p1 = 1;
			p2 = 0x04;
			p3 = encoded_len;
			encoded_data = (char *)g_try_malloc0(2 * (encoded_len) + 1);
			result = util_byte_to_hex(tmp, encoded_data, encoded_len);
			cmd = 220;         /*command - 220 : UPDATE RECORD*/
		}
		break;

	default:
		dbg("error - not handled update treq command[%d]", command);
		ret = TCORE_RETURN_EINVAL;
		break;
	}

	file_meta.file_id = ef;
	dbg("File ID: [0x%x]", file_meta.file_id);

	trt = tcore_user_request_set_metainfo(ur,
						sizeof(struct s_sim_property), &file_meta);
	dbg("trt[%d]", trt);

	cmd_str = g_strdup_printf("AT+CRSM=%d,%d,%d,%d,%d,\"%s\"", cmd, ef, p1, p2, p3, encoded_data);

	ret = tcore_prepare_and_send_at_request(o, cmd_str, "+CRSM:",
								TCORE_AT_SINGLELINE, ur,
								on_response_update_file, hal,
								NULL, NULL);

	g_free(cmd_str);
	g_free(encoded_data);
	if (tmp) {
		free(tmp);
	}

	dbg("Exit");
	return ret;
}

static TReturn s_transmit_apdu(CoreObject *o, UserRequest *ur)
{
	const struct treq_sim_transmit_apdu *req_data;
	TcoreHal *hal = NULL;
	char *cmd_str = NULL;
	char *apdu = NULL;
	int result = 0;
	TReturn ret = TCORE_RETURN_FAILURE;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL))
		return TCORE_RETURN_EINVAL;

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	req_data = tcore_user_request_ref_data(ur, NULL);

	apdu = (char *)g_try_malloc0((2 * req_data->apdu_length) + 1);
	result = util_byte_to_hex((const char *)req_data->apdu, apdu, req_data->apdu_length);
	cmd_str = g_strdup_printf("AT+CSIM=%d,\"%s\"", strlen(apdu), apdu);

	ret = tcore_prepare_and_send_at_request(o, cmd_str, "+CSIM:",
								TCORE_AT_SINGLELINE, ur,
								on_response_transmit_apdu, hal,
								NULL, NULL);
	g_free(cmd_str);
	g_free(apdu);

	dbg("Exit");
	return ret;
}

static TReturn s_get_atr(CoreObject *o, UserRequest *ur)
{
	TcoreHal *hal = NULL;

	dbg("Entry");

	if ((o == NULL )|| (ur == NULL)) {
		err("Invalid parameters");
		return TCORE_RETURN_EINVAL;
	}

	hal = tcore_object_get_hal(o);
	if (FALSE == tcore_hal_get_power_state(hal)) {
		err("CP NOT READY");
		return TCORE_RETURN_ENOSYS;
	}

	return tcore_prepare_and_send_at_request(o, "AT+XGATR", "+XGATR:",
								TCORE_AT_SINGLELINE, ur,
								on_response_get_atr, hal,
								NULL, NULL);
}

/* SIM Operations */
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
	.get_atr = s_get_atr,
	.req_authentication = NULL,
};

gboolean s_sim_init(TcorePlugin *cp, CoreObject *co_sim)
{
	struct s_sim_property *file_meta;

	dbg("Entry");

	tcore_sim_override_ops(co_sim, &sim_ops);

	file_meta = g_try_new0(struct s_sim_property, 1);
	if (file_meta == NULL)
		return FALSE;

	tcore_sim_link_userdata(co_sim, file_meta);

	tcore_object_override_callback(co_sim, "+XLOCK:",
							on_event_facility_lock_status, NULL);
	tcore_object_override_callback(co_sim, "+XSIM:",
							on_event_pin_status, NULL);

	tcore_server_add_notification_hook(tcore_plugin_ref_server(cp),
							TNOTI_MODEM_POWER, on_hook_modem_power, co_sim);

	dbg("Exit");

	return TRUE;
}

void s_sim_exit(TcorePlugin *cp, CoreObject *co_sim)
{
	struct s_sim_property *file_meta;

	file_meta = tcore_sim_ref_userdata(co_sim);
	g_free(file_meta);

	dbg("Exit");
}
