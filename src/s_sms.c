/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hayoon Ko <hayoon.ko@samsung.com>
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
#include <co_sms.h>
#include <user_request.h>
#include <storage.h>
#include <server.h>
#include <at.h>

#include "common/TelErr.h"
#include "s_common.h"
#include "s_sms.h"

/*=============================================================
							SMS PARAMETER_ID
==============================================================*/
#define TIZEN_SMSPARAMID_TELESERVICE_ID					0x01	/* Teleservice Identifier */
#define TIZEN_SMSPARAMID_SERVICE_CATEGORY				0x02	/* Broadcast Service Category */
#define TIZEN_SMSPARAMID_ADDRESS							0x03	/* Address */
#define TIZEN_SMSPARAMID_SUBADDRESS						0x04	/* Subaddress */
#define TIZEN_SMSPARAMID_BEARER_REPLY					0x05	/* Bearer Reply Option */
#define TIZEN_SMSPARAMID_CAUSE_CODES					0x06	/* Cause Codes */
#define TIZEN_SMSPARAMID_MESSAGE_ID						0x07	/* Message Identifier */
#define TIZEN_SMSPARAMID_USER_DATA						0x08	/* User Data */
#define TIZEN_SMSPARAMID_USER_RESPONSE_CODE			0x09	/* User Response Code */
#define TIZEN_SMSPARAMID_MC_TIME_STAMP					0x0A	/* Message Center Time Stamp */
#define TIZEN_SMSPARAMID_VALIDITY_PERIOD_ABS			0x0B	/* Validity Period - Absolute */
#define TIZEN_SMSPARAMID_VALIDITY_PERIOD_REL			0x0C	/* Validiry Period - Relative */
#define TIZEN_SMSPARAMID_DEFERRED_DELIVERY_ABS			0x0D	/* Deferred Delivery Time - Absolute */
#define TIZEN_SMSPARAMID_DEFERRED_DELIVERY_REL			0x0E	/* Deferred Delivery Time - Relative */
#define TIZEN_SMSPARAMID_PRIORITY							0x0F	/* Priority Indicator */
#define TIZEN_SMSPARAMID_PRIVACY							0x10	/* Privacy Indicator */
#define TIZEN_SMSPARAMID_REPLY_OPTION					0x11	/* Reply Option */
#define TIZEN_SMSPARAMID_NUMBER_OF_MESSAGE				0x12	/* Number of Messages : Voice Mail Count */
#define TIZEN_SMSPARAMID_ALERT_ON_DELIVERY				0x13	/* Alert on Message Delivery */
#define TIZEN_SMSPARAMID_LANGUAGE						0x14	/* Langauge Indicator */
#define TIZEN_SMSPARAMID_CALLBACK						0x15	/* Call Back Number */
#define TIZEN_SMSPARAMID_DISPLAY_MODE					0x16	/* Display Mode */
#define TIZEN_SMSPARAMID_MULTI_ENCODING_USER_DATA		0x17	/* Multiply Encoding User Data */
#define TIZEN_SMSPARAMID_MEMORY_INDEX					0x18	/* Memory address stored in Phone Memory */
#define TIZEN_SMSPARAMID_BEARER_DATA					0x19	/* Bearer data - raw data  */
#define TIZEN_SMSPARAMID_SCPT_DATA                               		0x1A	/* Service Category Program Data */
#define TIZEN_SMSPARAMID_SCPT_RESURLT                        		0x1B	/* Service Category Program Result */

/*=============================================================
						TIZEN_SMSPARAMID_MESSAGE_ID Types
==============================================================*/
#define TIZEN_MESSAGETYPE_DELIVER						0x01
#define TIZEN_MESSAGETYPE_SUBMIT						0x02
#define TIZEN_MESSAGETYPE_CANCEL						0x03
#define TIZEN_MESSAGETYPE_DELIVERY_ACK				0x04
#define TIZEN_MESSAGETYPE_USER_ACK					0x05

/*=============================================================
						TIZEN_SMSPARAMID_LANGUAGE Types
==============================================================*/
#define TIZEN_LANGUAGE_UNKNOWN					0x00
#define TIZEN_LANGUAGE_ENGLISH					0x01
#define TIZEN_LANGUAGE_FRENCH						0x02
#define TIZEN_LANGUAGE_SPANISH					0x03
#define TIZEN_LANGUAGE_JAPANESE					0x04
#define TIZEN_LANGUAGE_KOREAN						0x05
#define TIZEN_LANGUAGE_CHINESE					0x06
#define TIZEN_LANGUAGE_HEBREW					0x07
#define TIZEN_LANGUAGE_KOREAN1					0x40	/* Used in Korean 3 PCS's and STI */
#define TIZEN_LANGUAGE_KOREAN_SKT				0xFE	/* Used in only SKT */

/*=============================================================
							CDMA-SMS Size
==============================================================*/
#define MAX_CDMA_SMS_DATA_SIZE				512		/* Maximum number of bytes SMSP Record size (Y + 28), y : 0 ~ 128 */
#define MAX_CDMA_SMS_ADDRESS_SIZE			32		/* MAX sms destination(or origination ) address /call back number */

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
#define AT_SMS_DEVICE_READY			12		/* AT device ready */
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
							Security
==============================================================*/
#define MAX_SEC_PIN_LEN							8
#define MAX_SEC_PUK_LEN							8
#define MAX_SEC_PHONE_LOCK_PW_LEN				39		/* Maximum Phone Locking Password Length */
#define MAX_SEC_SIM_DATA_STRING					256		/* Maximum Length of the DATA or RESPONSE. Restricted SIM Access, Generic SIM Access Message */
#define MAX_SEC_NUM_LOCK_TYPE						8		/* Maximum number of Lock Type used in Lock Information Message */                                                                                        
#define MAX_SEC_IMS_AUTH_LEN						512		/* Maximum Length of IMS Authentication Message */

/*=============================================================
							String Preprocessor
==============================================================*/
#define CR		'\r'		/* Carriage Return */

/*=============================================================
							Developer
==============================================================*/
#define TAPI_CODE_SUBJECT_TO_CHANGE				/* For folding future features */

#define SMS_SWAPBYTES16(x) \
{ \
    unsigned short int data = *(unsigned short int*)&(x); \
    data = ((data & 0xff00) >> 8) |    \
           ((data & 0x00ff) << 8);     \
    *(unsigned short int*)&(x) = data ;      \
}


static TReturn Send_SmsSubmitTpdu(CoreObject *o, UserRequest *ur);

/********************************************************************************
Send Callback: Invoked when request is out from queue
********************************************************************************/
static void on_confirmation_sms_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("Entered Function. Request message out from queue");

	dbg("TcorePending: [%p]", p);
	dbg("result: [%02x]", result);
	dbg("user_data: [%p]", user_data);

	if(result == TRUE)
	{
		dbg("SEND OK");
	}
	else /* Failed */
	{
		dbg("SEND NOK");
	}

	dbg("Exiting Function. Nothing to return");
}

/************************************************************/
/*********************  Utility for SMS  *************************/
/************************************************************/
static void util_sms_get_length_of_sca(int* nScLength) {
	if (*nScLength % 2) {
		*nScLength = (*nScLength / 2) + 1;
	} else {
		*nScLength = *nScLength / 2;
	}

	return;
}

static TReturn util_sms_encode_submit_message(const struct telephony_sms_CdmaMsgInfo *pMsgInfo, unsigned char *output, unsigned int *pos)
{
	TReturn api_err = TCORE_RETURN_SUCCESS;

	struct telephony_sms_Is637OutSubmit *pSubmit = NULL;
	unsigned int index = 0;
	int i = 0;

	// 1. check null pointer
	if(pMsgInfo == NULL || output == NULL || pos == NULL)
		return TCORE_RETURN_EINVAL;

	// 2. check manatory parameter in the TelSmsMsgInfo_t
	if(!((pMsgInfo->ParamMask & SMS_PARAM_TELESERVICE_MASK) &&
		(pMsgInfo->ParamMask & SMS_PARAM_ADDRESS_MASK) &&
		(pMsgInfo->ParamMask & SMS_PARAM_MESSAGE_ID_MASK)))
				return TCORE_RETURN_EINVAL;

	pSubmit = (struct telephony_sms_Is637OutSubmit *)&(pMsgInfo->MsgData.outSubmit);

	printf("TIZEN_SMSPARAMID_TELESERVICE_ID\n");
	printf("teleservice msg=%x\n", pSubmit->TeleService);
	// 3. teleservice
	output[index++] = TIZEN_SMSPARAMID_TELESERVICE_ID;
	output[index++] = 2;
	memcpy(output+index, &(pSubmit->TeleService), sizeof(unsigned short));
	index += sizeof(unsigned short);

	printf("TIZEN_SMSPARAMID_ADDRESS\n");
	// 4. Destination address
	output[index++] = TIZEN_SMSPARAMID_ADDRESS;
	output[index++] = pSubmit->DstAddr.szAddrLength + 5;
	output[index++] = (unsigned char)pSubmit->DstAddr.Digit;
	output[index++] = (unsigned char)pSubmit->DstAddr.NumberMode;
	output[index++] = (unsigned char)pSubmit->DstAddr.NumberType;
	output[index++] = (unsigned char)pSubmit->DstAddr.NumberPlan;
	output[index++] = (unsigned char)pSubmit->DstAddr.szAddrLength;
	if(pSubmit->DstAddr.szAddrLength > SMS_MAXLENGTH_SMS_ADDRESS)
		api_err = TCORE_RETURN_EINVAL;
	else{
		memcpy(output+ index, pSubmit->DstAddr.szAddress, pSubmit->DstAddr.szAddrLength);
		index += pSubmit->DstAddr.szAddrLength;
	}

	printf("TIZEN_SMSPARAMID_SUBADDRESS\n");
	// 5. Subaddress (optional)
	if((api_err == TCORE_RETURN_SUCCESS)  && (pMsgInfo->ParamMask & SMS_PARAM_SUBADDRESS_MASK)){
		output[index++] = TIZEN_SMSPARAMID_SUBADDRESS;
		output[index++] = pSubmit->DstSubAddr.szAddrLength + 3;
		output[index++] = pSubmit->DstSubAddr.SubType;
		output[index++] = pSubmit->DstSubAddr.Odd;
		output[index++] = pSubmit->DstSubAddr.szAddrLength;
		if(pSubmit->DstSubAddr.szAddrLength > SMS_MAXLENGTH_SMS_ADDRESS)
			api_err = TCORE_RETURN_EINVAL;
		else{
			memcpy(output+ index, pSubmit->DstSubAddr.szAddress, pSubmit->DstSubAddr.szAddrLength);
			index += pSubmit->DstSubAddr.szAddrLength;
		}
	}

	printf("TIZEN_SMSPARAMID_BEARER_REPLY\n");
	// 6. Bearer Reply Option
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_BEARER_REPLY_MASK)){
		output[index++] = TIZEN_SMSPARAMID_BEARER_REPLY;
		output[index++] = 1;
		if(pSubmit->ReplySeqNumber >= 64)
			api_err = TCORE_RETURN_EINVAL;
		else output[index++] = pSubmit->ReplySeqNumber;
	}

	printf("TIZEN_SMSPARAMID_MESSAGE_ID\n");
	printf("Message ID msg=%x\n",pSubmit->MsgId);
	// 7. Message Id
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_MESSAGE_ID_MASK)){
		output[index++] = TIZEN_SMSPARAMID_MESSAGE_ID;
		output[index++] = 3;
		output[index++] = TIZEN_MESSAGETYPE_SUBMIT;
		memcpy(output+ index, &(pSubmit->MsgId), sizeof(unsigned short));
		index += sizeof(unsigned short);
	}

	printf("TIZEN_SMSPARAMID_USER_DATA\n");
	// 8. User Data
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_USER_DATA_MASK)){
		output[index++] = TIZEN_SMSPARAMID_USER_DATA;
		output[index++] = 2 + pSubmit->MsgLength;
		output[index++] = pSubmit->MsgEncoding;
		output[index++] = pSubmit->MsgLength;
		if(pSubmit->MsgLength > SMS_MAXLENGTH_SMS_MO_USER_DATA)
			api_err = TCORE_RETURN_EINVAL;
		else{
			memcpy(output+ index, pSubmit->szData, pSubmit->MsgLength);
			index += pSubmit->MsgLength;
		}
	}

	// 9. Deferred DeliveryTime Absolute
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_DEFERRED_DELIVERY_ABS_MASK)){
		output[index++] = TIZEN_SMSPARAMID_DEFERRED_DELIVERY_ABS;
		output[index++] = 6;
		output[index++] = (unsigned char)pSubmit->DeferredDelTimeAbs.year;
		output[index++] = (unsigned char)pSubmit->DeferredDelTimeAbs.month;
		output[index++] = (unsigned char)pSubmit->DeferredDelTimeAbs.day;
		output[index++] = (unsigned char)pSubmit->DeferredDelTimeAbs.hours;
		output[index++] = (unsigned char)pSubmit->DeferredDelTimeAbs.minutes;
		output[index++] = (unsigned char)pSubmit->DeferredDelTimeAbs.seconds;
	}

	// 10. Deferred DeliveryTime Relative
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_DEFERRED_DELIVERY_REL_MASK)){
		output[index++] = TIZEN_SMSPARAMID_DEFERRED_DELIVERY_REL;
		output[index++] = 1;
		output[index++] = (unsigned char)pSubmit->DeferredDelTimeRel;
	}

	// 11. Priority Indicator
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_PRIORITY_MASK)){
		output[index++] = TIZEN_SMSPARAMID_PRIORITY;
		output[index++] = 1;
		if((int)pSubmit->Privacy < SMS_PRIVACY_NOT_RESTRICTED || pSubmit->Privacy > SMS_PRIVACY_SECRET)
			api_err = TCORE_RETURN_EINVAL;
		else output[index++] = pSubmit->Priority;
	}

	// 12. Privacy Indicator
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_PRIVACY_MASK)){
		output[index++] = TIZEN_SMSPARAMID_PRIVACY;
		output[index++] = 1;
		if((int)pSubmit->Priority < SMS_PRIORITY_NORMAL || pSubmit->Priority > SMS_PRIORITY_EMERGENCY)
			api_err = TCORE_RETURN_EINVAL;
		else output[index++] = pSubmit->Privacy;
	}

	// 13. Reply Option
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_REPLY_OPTION_MASK)){
		output[index++] = TIZEN_SMSPARAMID_REPLY_OPTION;
		output[index++] = 2;
		if(pSubmit->bUserAckRequest == 0 &&  pSubmit->bDeliveryAckRequest == 0)
			api_err = TCORE_RETURN_EINVAL;
		else {
			output[index++] = (unsigned char)(pSubmit->bUserAckRequest);
			output[index++] = (unsigned char)(pSubmit->bDeliveryAckRequest);
		}
	}

	// 14. Alert on Message Delivery
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_ALERT_ON_DELIVERY_MASK)){
		output[index++] = TIZEN_SMSPARAMID_ALERT_ON_DELIVERY;
		output[index++] = 1;
		if((int)pSubmit->AlertPriority< SMS_ALERT_PRIORITY_DEFAULT || pSubmit->AlertPriority > SMS_ALERT_PRIORITY_HIGH)
			api_err = TCORE_RETURN_EINVAL;
		else output[index++] = pSubmit->AlertPriority;
	}

	// 15. Language Indicator
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_LANGUAGE_MASK)){
		output[index++] = TIZEN_SMSPARAMID_LANGUAGE;
		output[index++] = 1;
		if((int)pSubmit->MsgLang< TIZEN_LANGUAGE_UNKNOWN || pSubmit->MsgLang > TIZEN_LANGUAGE_KOREAN_SKT)
			api_err = TCORE_RETURN_EINVAL;
		else output[index++] = pSubmit->MsgLang;
	}

	printf("TIZEN_SMSPARAMID_CALLBACK\n");
	// 16. Callback Number
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_CALLBACK_MASK)){
		output[index++] = TIZEN_SMSPARAMID_CALLBACK;
		output[index++] = 4 + pSubmit->CallBackNumber.szAddrLength;
		output[index++] = pSubmit->CallBackNumber.Digit;
		output[index++] = pSubmit->CallBackNumber.NumberType;
		output[index++] = pSubmit->CallBackNumber.NumberPlan;
		output[index++] = (unsigned char)pSubmit->CallBackNumber.szAddrLength;
		printf("index before =%d, value=%x", (int)index, output[index-1]);
		if(pSubmit->CallBackNumber.szAddrLength > SMS_MAXLENGTH_SMS_ADDRESS)
			api_err = TCORE_RETURN_EINVAL;
		else{
			memcpy(output+ index, pSubmit->CallBackNumber.szAddress, pSubmit->CallBackNumber.szAddrLength);

			printf("index after =%d, value=%x\n", (int)index, output[index]);

			for (i=0;i<11;i++)
				printf("szAddr[%d]=%x\n", i, output[index+i]);
			index += pSubmit->CallBackNumber.szAddrLength;
		}
	}

	printf("output index: (0)=%x, (-1)=%x, (+1)=%x\n", output[index], output[index-1],output[index+1]);

	*pos = index;

	return api_err;
}

static TReturn util_sms_encode_cancel_message(const struct telephony_sms_CdmaMsgInfo *pMsgInfo, unsigned char *output, unsigned int *pos)
{
	TReturn api_err = TCORE_RETURN_SUCCESS;
	struct telephony_sms_Is637OutCancel *pCancel = NULL;
	unsigned int index = 0;

	// 1. check null pointer
	if(pMsgInfo == NULL || output == NULL || pos == NULL)
		return TCORE_RETURN_EINVAL;

	// 2. check manatory parameter in the TelSmsMsgInfo_t
	if(!((pMsgInfo->ParamMask & SMS_PARAM_TELESERVICE_MASK) &&
		(pMsgInfo->ParamMask & SMS_PARAM_ADDRESS_MASK) &&
		(pMsgInfo->ParamMask & SMS_PARAM_MESSAGE_ID_MASK)))
		return TCORE_RETURN_EINVAL;

	pCancel = (struct telephony_sms_Is637OutCancel *)&(pMsgInfo->MsgData.outCancel);

	// 3. teleservice
	output[index++] = TIZEN_SMSPARAMID_TELESERVICE_ID;
	output[index++] = 2;
	memcpy(output+index, &pCancel->TeleService, sizeof(unsigned short));
	index += sizeof(unsigned short);


	// 4. Destination address
	output[index++] = TIZEN_SMSPARAMID_ADDRESS;
	output[index++] = pCancel->DstAddr.szAddrLength + 5;
	output[index++] = (unsigned char)pCancel->DstAddr.Digit;
	output[index++] = (unsigned char)pCancel->DstAddr.NumberMode;
	output[index++] = (unsigned char)pCancel->DstAddr.NumberType;
	output[index++] = (unsigned char)pCancel->DstAddr.NumberPlan;
	output[index++] = (unsigned char)pCancel->DstAddr.szAddrLength;
	if(pCancel->DstAddr.szAddrLength > SMS_MAXLENGTH_SMS_ADDRESS)
		api_err = TCORE_RETURN_EINVAL;
	else{
		memcpy(output+ index, pCancel->DstAddr.szAddress, pCancel->DstAddr.szAddrLength);
		index += pCancel->DstAddr.szAddrLength;
	}

	// 5. Subaddress (optional)
	if((api_err == TCORE_RETURN_SUCCESS)  && (pMsgInfo->ParamMask & SMS_PARAM_SUBADDRESS_MASK)){
		output[index++] = TIZEN_SMSPARAMID_SUBADDRESS;
		output[index++] = pCancel->DstSubAddr.szAddrLength + 3;
		output[index++] = pCancel->DstSubAddr.SubType;
		output[index++] = pCancel->DstSubAddr.Odd;
		output[index++] = pCancel->DstSubAddr.szAddrLength;
		if(pCancel->DstSubAddr.szAddrLength > SMS_MAXLENGTH_SMS_ADDRESS)
			api_err = TCORE_RETURN_EINVAL;
		else{
			memcpy(output+ index, pCancel->DstSubAddr.szAddress, pCancel->DstSubAddr.szAddrLength);
			index += pCancel->DstSubAddr.szAddrLength;
		}
	}

	// 6. Bearer Reply Option
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_BEARER_REPLY_MASK)){
		output[index++] = TIZEN_SMSPARAMID_BEARER_REPLY;
		output[index++] = 1;
		if(pCancel->ReplySeqNumber >= 64)
			api_err = TCORE_RETURN_EINVAL;
		else output[index++] = pCancel->ReplySeqNumber;
	}

	// 7. Message Id
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_MESSAGE_ID_MASK)){
		output[index++] = TIZEN_SMSPARAMID_MESSAGE_ID;
		output[index++] = 3;
		output[index++] = TIZEN_MESSAGETYPE_CANCEL;
		memcpy(output+ index, &pCancel->MsgId, sizeof(unsigned short));
		index += sizeof(unsigned short);
	}

	*pos = index;

	return api_err;
}

static TReturn util_sms_encode_user_ack_message(const struct telephony_sms_CdmaMsgInfo *pMsgInfo, unsigned char *output, unsigned int *pos)
{
	TReturn api_err = TCORE_RETURN_SUCCESS;
	struct telephony_sms_Is637OutAck *pUserAck = NULL;
	unsigned int index = 0;

	// 1. check null pointer
	if(pMsgInfo == NULL || output == NULL || pos == NULL)
		return TCORE_RETURN_EINVAL;

	if(!((pMsgInfo->ParamMask & SMS_PARAM_TELESERVICE_MASK) &&
		(pMsgInfo->ParamMask & SMS_PARAM_ADDRESS_MASK) &&
		(pMsgInfo->ParamMask & SMS_PARAM_MESSAGE_ID_MASK)))
				return TCORE_RETURN_EINVAL;

	pUserAck = (struct telephony_sms_Is637OutAck *)&(pMsgInfo->MsgData.outAck);

	// 3. teleservice
	output[index++] = TIZEN_SMSPARAMID_TELESERVICE_ID;
	output[index++] = 2;
	memcpy(output+index, &pUserAck->TeleService, sizeof(unsigned short));
	index += sizeof(unsigned short);


	// 4. Destination address
	output[index++] = TIZEN_SMSPARAMID_ADDRESS;
	output[index++] = pUserAck->DstAddr.szAddrLength + 5;
	output[index++] = (unsigned char)pUserAck->DstAddr.Digit;
	output[index++] = (unsigned char)pUserAck->DstAddr.NumberMode;
	output[index++] = (unsigned char)pUserAck->DstAddr.NumberType;
	output[index++] = (unsigned char)pUserAck->DstAddr.NumberPlan;
	output[index++] = (unsigned char)pUserAck->DstAddr.szAddrLength;
	if(pUserAck->DstAddr.szAddrLength > SMS_MAXLENGTH_SMS_ADDRESS)
		api_err = TCORE_RETURN_EINVAL;
	else{
		memcpy(output+ index, pUserAck->DstAddr.szAddress, pUserAck->DstAddr.szAddrLength);
		index += pUserAck->DstAddr.szAddrLength;
	}

	// 5. Subaddress (optional)
	if((api_err == TCORE_RETURN_SUCCESS)  && (pMsgInfo->ParamMask & SMS_PARAM_SUBADDRESS_MASK)){
		output[index++] = TIZEN_SMSPARAMID_SUBADDRESS;
		output[index++] = pUserAck->DstSubAddr.szAddrLength + 3;
		output[index++] = pUserAck->DstSubAddr.SubType;
		output[index++] = pUserAck->DstSubAddr.Odd;
		output[index++] = pUserAck->DstSubAddr.szAddrLength;
		if(pUserAck->DstSubAddr.szAddrLength > SMS_MAXLENGTH_SMS_ADDRESS)
			api_err = TCORE_RETURN_EINVAL;
		else{
			memcpy(output+ index, pUserAck->DstSubAddr.szAddress, pUserAck->DstSubAddr.szAddrLength);
			index += pUserAck->DstSubAddr.szAddrLength;
		}
	}

	// 6. Bearer Reply Option
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_BEARER_REPLY_MASK)){
		output[index++] = TIZEN_SMSPARAMID_BEARER_REPLY;
		output[index++] = 1;
		if(pUserAck->ReplySeqNumber >= 64)
			api_err = TCORE_RETURN_EINVAL;
		else output[index++] = pUserAck->ReplySeqNumber;
	}

	// 7. Message Id
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_MESSAGE_ID_MASK)){
		output[index++] = TIZEN_SMSPARAMID_MESSAGE_ID;
		output[index++] = 3;
		output[index++] = TIZEN_MESSAGETYPE_USER_ACK;
		memcpy(output+ index, &pUserAck->MsgId, sizeof(unsigned short));
		index += sizeof(unsigned short);
	}

	// 8. User Data
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_USER_DATA_MASK)){
		output[index++] = TIZEN_SMSPARAMID_USER_DATA;
		output[index++] = 2 + pUserAck->MsgEncoding;
		output[index++] = pUserAck->MsgLength;
		if(pUserAck->MsgLength > SMS_MAXLENGTH_SMS_MO_USER_DATA)
			api_err = TCORE_RETURN_EINVAL;
		else{
			memcpy(output+ index, pUserAck->szData, pUserAck->MsgLength);
			index += pUserAck->MsgLength;
		}
	}

	// 9. User Response Code
	if((api_err == TCORE_RETURN_SUCCESS) && (pMsgInfo->ParamMask & SMS_PARAM_USER_RESPONSE_CODE_MASK)){
		output[index++] = TIZEN_SMSPARAMID_USER_RESPONSE_CODE;
		output[index++] = 1;
		output[index++] = pUserAck->UserResponseCode;
	}

	*pos = index;

	return api_err;
}

static int util_sms_decode_inDeliver_message(unsigned char *incoming, unsigned int length, struct telephony_sms_CdmaMsgInfo *pMsgInfo)
{
	int rtn = TRUE;
	unsigned int	index = 0;
	unsigned int	ParamLen = 0;
	struct telephony_sms_Is637InDeliver *InDeliver = NULL;

	dbg("Parsing Bearer Data below, Total length[0x%x]", (unsigned int)length);

	if(incoming == NULL || pMsgInfo == NULL)
		return FALSE;

	InDeliver = &(pMsgInfo->MsgData.inDeliver);

	do{
		if(incoming[index] == TIZEN_SMSPARAMID_USER_DATA){
			int i=0;
			dbg("ParamID[TIZEN_SMSPARAMID_USER_DATA=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->MsgEncoding = incoming[++index];
			InDeliver->MsgLength = incoming[++index];
			memcpy(InDeliver->szData, incoming+ ++index, InDeliver->MsgLength);
			index += InDeliver->MsgLength;
			pMsgInfo->ParamMask |= SMS_PARAM_USER_DATA_MASK;
			dbg("MsgEnconding[0x%x], MsgLength[%d]",
				InDeliver->MsgEncoding, InDeliver->MsgLength);

			for(i = 0 ; i < InDeliver->MsgLength ; i++)
			{
				dbg("Index[%d] Char[0x%x]", i, InDeliver->szData[i]);
			}
			dbg("Final Index[0x%x]", (unsigned int)index);


		}
		else if(incoming[index] == TIZEN_SMSPARAMID_VALIDITY_PERIOD_ABS){
			dbg("ParamID[TIZEN_SMSPARAMID_VALIDITY_PERIOD_ABS=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->ValidityPeriodAbs.year = incoming[++index];
			InDeliver->ValidityPeriodAbs.month = incoming[++index];
			InDeliver->ValidityPeriodAbs.day = incoming[++index];
			InDeliver->ValidityPeriodAbs.hours = incoming[++index];
			InDeliver->ValidityPeriodAbs.minutes = incoming[++index];
			InDeliver->ValidityPeriodAbs.seconds = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_VALIDITY_PERIOD_ABS_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_VALIDITY_PERIOD_REL){
			dbg("ParamID[TIZEN_SMSPARAMID_VALIDITY_PERIOD_REL=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->ValidityPeriodRel = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_VALIDITY_PERIOD_REL_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_MC_TIME_STAMP){
			dbg("ParamID[TIZEN_SMSPARAMID_MC_TIME_STAMP=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->MessageCenterTimeStamp.year = incoming[++index];
			InDeliver->MessageCenterTimeStamp.month = incoming[++index];
			InDeliver->MessageCenterTimeStamp.day = incoming[++index];
			InDeliver->MessageCenterTimeStamp.hours = incoming[++index];
			InDeliver->MessageCenterTimeStamp.minutes = incoming[++index];
			InDeliver->MessageCenterTimeStamp.seconds = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_MC_TIME_STAMP_MASK;
		}

		else if(incoming[index] == TIZEN_SMSPARAMID_PRIORITY){
			dbg("ParamID[TIZEN_SMSPARAMID_PRIORITY=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->Priority = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_PRIORITY_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_PRIVACY){
			dbg("ParamID[TIZEN_SMSPARAMID_PRIVACY=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->Privacy = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_PRIVACY_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_NUMBER_OF_MESSAGE){
			dbg("ParamID[TIZEN_SMSPARAMID_NUMBER_OF_MESSAGE=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->NumMsg = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_NUMBER_OF_MESSAGE_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_ALERT_ON_DELIVERY){
			dbg("ParamID[TIZEN_SMSPARAMID_ALERT_ON_DELIVERY=0x%x], ParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->AlertPriority = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_ALERT_ON_DELIVERY_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_LANGUAGE){
			dbg("ParamID[TIZEN_SMSPARAMID_LANGUAGE=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->MsgLang = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_LANGUAGE_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_REPLY_OPTION){
			dbg("ParamID[TIZEN_SMSPARAMID_REPLY_OPTION=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->bUserAckRequest = (int)incoming[++index];
			InDeliver->bDeliveryAckRequest = (int)incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_REPLY_OPTION_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_CALLBACK){
			dbg("ParamID[TIZEN_SMSPARAMID_CALLBACK=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->CallBackNumer.Digit = incoming[++index];
			InDeliver->CallBackNumer.NumberType= incoming[++index];
			InDeliver->CallBackNumer.NumberPlan = incoming[++index];
			InDeliver->CallBackNumer.szAddrLength = incoming[++index];
			memcpy(InDeliver->CallBackNumer.szAddress, incoming+ ++index, InDeliver->CallBackNumer.szAddrLength);
			index+= InDeliver->CallBackNumer.szAddrLength;
			pMsgInfo->ParamMask |= TIZEN_SMSPARAMID_CALLBACK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_DISPLAY_MODE){
			dbg("ParamID[TIZEN_SMSPARAMID_DISPLAY_MODE=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			InDeliver->Display= incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_DISPLAY_MODE_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_MEMORY_INDEX){
			dbg("ParamID[TIZEN_SMSPARAMID_MEMORY_INDEX=0x%x]\tindex + 4", incoming[index]);
			index += 4;
		}

		else
		{
			dbg("Undefined SMS Parameter ID [0x%x] in the Bearer Data", incoming[index]);
			rtn = FALSE;
			break;
		}
	}while(!(index == length));

	return rtn;
}

static int util_sms_decode_inAck_message(unsigned char *incoming, unsigned int length, struct telephony_sms_CdmaMsgInfo *pMsgInfo)
{
	int rtn = TRUE;
	struct telephony_sms_Is637InAck *InAck = NULL;
	unsigned int	index = 0;
	unsigned int	ParamLen = 0;

	if(incoming == NULL || pMsgInfo == NULL)
		return FALSE;

	InAck = &(pMsgInfo->MsgData.inAck);
	do{
		if(incoming[index] == TIZEN_SMSPARAMID_USER_DATA){
			ParamLen = incoming[++index];	 //parameter length
			InAck->MsgEncoding = incoming[++index];
			InAck->MsgLength = incoming[++index];
			memcpy(InAck->szData, incoming+ ++index, InAck->MsgLength);
			index += InAck->MsgLength;
			pMsgInfo->ParamMask |= SMS_PARAM_USER_DATA_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_USER_RESPONSE_CODE){
			ParamLen = incoming[++index];	 //parameter length
			InAck->MsgEncoding = incoming[++index];
			InAck->UserResponseCode = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_USER_RESPONSE_CODE_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_MC_TIME_STAMP){
			ParamLen = incoming[++index];	 //parameter length
			InAck->MessageCenterTimeStamp.year = incoming[++index];
			InAck->MessageCenterTimeStamp.month = incoming[++index];
			InAck->MessageCenterTimeStamp.day = incoming[++index];
			InAck->MessageCenterTimeStamp.hours = incoming[++index];
			InAck->MessageCenterTimeStamp.minutes = incoming[++index];
			InAck->MessageCenterTimeStamp.seconds = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_MC_TIME_STAMP_MASK;
		}
		else{
			rtn = FALSE;
			break;
		}
	}while(!(index == length));

	return rtn;
}

static int util_sms_decode_inDeliverAck_message(unsigned char *incoming, unsigned int length, struct telephony_sms_CdmaMsgInfo *pMsgInfo)
{
	int rtn = TRUE;
	struct telephony_sms_Is637InDeliverAck *InDelAck = NULL;
	unsigned int	index = 0;
	unsigned int	ParamLen = 0;

	if(incoming == NULL || pMsgInfo == NULL)
		return FALSE;

	InDelAck = &(pMsgInfo->MsgData.inDeliverAck);
	do{
		if(incoming[index] == TIZEN_SMSPARAMID_USER_DATA){
			ParamLen = incoming[++index];	 //parameter length
			InDelAck->MsgEncoding = incoming[++index];
			InDelAck->MsgLength = incoming[++index];
			memcpy(InDelAck->szData, incoming+ ++index, InDelAck->MsgLength);
			index += InDelAck->MsgLength;
			pMsgInfo->ParamMask |= SMS_PARAM_USER_DATA_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_MC_TIME_STAMP){
			ParamLen = incoming[++index];	 //parameter length
			InDelAck->MessageCenterTimeStamp.year = incoming[++index];
			InDelAck->MessageCenterTimeStamp.month = incoming[++index];
			InDelAck->MessageCenterTimeStamp.day = incoming[++index];
			InDelAck->MessageCenterTimeStamp.hours = incoming[++index];
			InDelAck->MessageCenterTimeStamp.minutes = incoming[++index];
			InDelAck->MessageCenterTimeStamp.seconds = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_MC_TIME_STAMP_MASK;
		}
		else{
			rtn = FALSE;
			break;
		}
	}while(!(index == length));

	return rtn;
}

static int util_sms_decode_ptp_message(unsigned char *incoming, unsigned int length, struct telephony_sms_CdmaMsgInfo *pMsgInfo)
{
	int rtn = TRUE;
	unsigned int	index = 0;
	unsigned int	ParamLen = 0;
	struct telephony_sms_Is637InDeliver *pCommon = NULL;
	enum telephony_sms_CdmaMsgType type;

	if(incoming == NULL || pMsgInfo == NULL)
		return FALSE;

	pCommon = &(pMsgInfo->MsgData.inDeliver);

	do{
		if(incoming[index] == TIZEN_SMSPARAMID_TELESERVICE_ID)
		{
			dbg("ParamID[TIZEN_SMSPARAMID_TELESERVICE_ID=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			memcpy(&pCommon->TeleService, incoming+ ++index, ParamLen);
			index += ParamLen;
			pMsgInfo->ParamMask |= SMS_PARAM_TELESERVICE_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_ADDRESS)
		{
			dbg("ParamID[TIZEN_SMSPARAMID_ADDRESS=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			pCommon->OrigAddr.Digit = incoming[++index];
			pCommon->OrigAddr.NumberMode = incoming[++index];
			pCommon->OrigAddr.NumberType = incoming[++index];
			pCommon->OrigAddr.NumberPlan = incoming[++index];
			pCommon->OrigAddr.szAddrLength = incoming[++index];
			memcpy(pCommon->OrigAddr.szAddress, incoming+ ++index, pCommon->OrigAddr.szAddrLength);
			index += pCommon->OrigAddr.szAddrLength;
			pMsgInfo->ParamMask |= SMS_PARAM_ADDRESS_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_SUBADDRESS)
		{
			dbg("ParamID[TIZEN_SMSPARAMID_SUBADDRESS=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			pCommon->OrigSubAddr.SubType =  incoming[++index];
			pCommon->OrigSubAddr.Odd =  incoming[++index];
			pCommon->OrigSubAddr.szAddrLength = incoming[++index];
			memcpy(pCommon->OrigSubAddr.szAddress, incoming+ ++index, pCommon->OrigSubAddr.szAddrLength);
			index += pCommon->OrigSubAddr.szAddrLength;
			pMsgInfo->ParamMask |= SMS_PARAM_SUBADDRESS_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_BEARER_REPLY)
		{
			dbg("ParamID[TIZEN_SMSPARAMID_BEARER_REPLY=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			pCommon->bBearerReplySeqRequest = (int)TRUE;
			pCommon->ReplySeqNumber = incoming[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_BEARER_REPLY_MASK;
		}
		else if(incoming[index] == TIZEN_SMSPARAMID_MESSAGE_ID)
		{
			dbg("ParamID[TIZEN_SMSPARAMID_MESSAGE_ID=0x%x]\tParamLen[%d]", incoming[index], incoming[index+1]);
			ParamLen = incoming[++index];	 //parameter length
			type = incoming[++index];
			pMsgInfo->MsgType = type;
			memcpy(&pCommon->MsgId, incoming+ ++index, sizeof(unsigned short));
			index += sizeof(unsigned short);
			pMsgInfo->ParamMask |= SMS_PARAM_MESSAGE_ID_MASK;
			switch(type)
			{
				case SMS_MESSAGETYPE_DELIVER:
					dbg("SubParamID[SMS_MESSAGETYPE_DELIVER=0x%x]", type);
					dbg("Current Index[0x%x], Parsing Length[0x%x], ParamLen[0x%x]", (unsigned int)index, (unsigned int)length, (unsigned int)ParamLen);

					rtn = util_sms_decode_inDeliver_message(incoming+index, length - index, pMsgInfo);

					break;
				case SMS_MESSAGETYPE_DELIVERY_ACK:
					dbg("SubParamID[SMS_MESSAGETYPE_DELIVERY_ACK=0x%x]", type);

					rtn = util_sms_decode_inAck_message(incoming+index, length - index, pMsgInfo);

					break;
				case SMS_MESSAGETYPE_USER_ACK:
					dbg("SubParamID[SMS_MESSAGETYPE_USER_ACK=0x%x]", type);

					rtn = util_sms_decode_inDeliverAck_message(incoming+index, length - index, pMsgInfo);

					break;
				default:
					dbg("Unknown Incoming Message Type = %d", type);
					rtn = FALSE;
					break;
			}
			index = length;
		}
		else
		{
			dbg("ParamID[Undefined]");
			//rtn = FALSE;
			break;
		}

	}while(!(index == length));

	return rtn;
}

static int util_sms_decode_broadcast_message(unsigned char *bcmsg, unsigned int length, struct telephony_sms_CdmaMsgInfo *pMsgInfo)
{
	int rtn = TRUE;
	unsigned int	index = 0;
	unsigned int	ParamLen = 0;
	struct telephony_sms_Is637InBroadCast *pOutput = NULL;

	if(bcmsg == NULL || pMsgInfo == NULL)
		return FALSE;

	pOutput = &(pMsgInfo->MsgData.inBc);

	do{
		if(bcmsg[index] == TIZEN_SMSPARAMID_SERVICE_CATEGORY){
			ParamLen = bcmsg[++index];	 //parameter length
			memcpy(&pOutput->ServiceCategory, bcmsg+ ++index, ParamLen);
			index += ParamLen;
			pMsgInfo->ParamMask |= SMS_PARAM_SERVICE_CATEGORY_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_BEARER_REPLY){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->bBearerReplySeqRequest = (int)TRUE;
			pOutput->ReplySeqNumber = bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_BEARER_REPLY_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_MESSAGE_ID){
			ParamLen = bcmsg[++index];	 //parameter length
			memcpy(&pOutput->MsgId, bcmsg+ ++index, ParamLen);
			index += ParamLen;
			pMsgInfo->ParamMask |= SMS_PARAM_MESSAGE_ID_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_VALIDITY_PERIOD_ABS){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->ValidityPeriodAbs.year = bcmsg[++index];
			pOutput->ValidityPeriodAbs.month = bcmsg[++index];
			pOutput->ValidityPeriodAbs.day = bcmsg[++index];
			pOutput->ValidityPeriodAbs.hours = bcmsg[++index];
			pOutput->ValidityPeriodAbs.minutes = bcmsg[++index];
			pOutput->ValidityPeriodAbs.seconds = bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_VALIDITY_PERIOD_ABS_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_VALIDITY_PERIOD_REL){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->ValidityPeriodRel = bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_VALIDITY_PERIOD_REL_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_MC_TIME_STAMP){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->MessageCenterTimeStamp.year = bcmsg[++index];
			pOutput->MessageCenterTimeStamp.month = bcmsg[++index];
			pOutput->MessageCenterTimeStamp.day = bcmsg[++index];
			pOutput->MessageCenterTimeStamp.hours = bcmsg[++index];
			pOutput->MessageCenterTimeStamp.minutes = bcmsg[++index];
			pOutput->MessageCenterTimeStamp.seconds = bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_MC_TIME_STAMP_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_PRIORITY){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->Priority= bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_PRIORITY_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_ALERT_ON_DELIVERY){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->AlertPriority = bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_ALERT_ON_DELIVERY_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_LANGUAGE){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->MsgLang = bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_LANGUAGE_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_DISPLAY_MODE){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->Display = bcmsg[++index];
			index++;
			pMsgInfo->ParamMask |= SMS_PARAM_DISPLAY_MODE_MASK;
		}
		else if(bcmsg[index] == TIZEN_SMSPARAMID_USER_DATA){
			ParamLen = bcmsg[++index];	 //parameter length
			pOutput->MsgEncoding = bcmsg[++index];
			pOutput->MsgLength = bcmsg[++index];
			memcpy(pOutput->szData, bcmsg+ ++index, pOutput->MsgLength);
			index += pOutput->MsgLength;
			pMsgInfo->ParamMask |= SMS_PARAM_USER_DATA_MASK;
		}
		else{
			rtn = FALSE;
			break;
		}

	}while(!(index == length));

	return rtn;
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

	if (alpha_id_len > 0)
	{
		if(alpha_id_len > SMS_SMSP_ALPHA_ID_LEN_MAX)
		{
			alpha_id_len = SMS_SMSP_ALPHA_ID_LEN_MAX;
		}

		for(i=0 ; i < alpha_id_len ; i++)
		{
			if(0xff == incoming[i])
			{
				dbg(" found");
				break;
			}
		}

		memcpy(params->szAlphaId, incoming, i);

		params->alphaIdLen = i;

		dbg(" Alpha id length = %d", i);

	}
	else
	{
		params->alphaIdLen = 0;
		dbg(" Alpha id length is zero");
	}

	//dongil01.park - start parse from here.
	params->paramIndicator = incoming[alpha_id_len];

	dbg(" Param Indicator = %02x", params->paramIndicator);

	//dongil01.park(2008/12/26) - DestAddr
	if((params->paramIndicator & SMSPValidDestAddr) == 0)
	{
		nOffset = nDestAddrOffset;

		if(0x00 == incoming[alpha_id_len + nOffset] || 0xff == incoming[alpha_id_len + nOffset])
		{
			params->tpDestAddr.dialNumLen = 0;

			dbg("DestAddr Length is 0");
		}
		else
		{
			if (0 < (int)incoming[alpha_id_len + nOffset])
			{
				params->tpDestAddr.dialNumLen = (int)(incoming[alpha_id_len + nOffset] - 1);

			        if(params->tpDestAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
				        params->tpDestAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;
			}
			else
			{
				params->tpDestAddr.dialNumLen = 0;
			}

			params->tpDestAddr.numPlanId= incoming[alpha_id_len + (++nOffset)] & 0x0f ;
			params->tpDestAddr.typeOfNum= (incoming[alpha_id_len + nOffset] & 0x70)>>4 ;

			memcpy(params->tpDestAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpDestAddr.dialNumLen)) ;

			dbg("Dest TON is %d",params->tpDestAddr.typeOfNum);
			dbg("Dest NPI is %d",params->tpDestAddr.numPlanId);
			dbg("Dest Length = %d",params->tpDestAddr.dialNumLen);
			dbg("Dest Addr = %s",params->tpDestAddr.diallingNum);

		}
	}

	//dongil01.park(2008/12/26) - SvcAddr
	if((params->paramIndicator & SMSPValidSvcAddr) == 0)
	{
		nOffset = nSCAAddrOffset;

		if(0x00 == (int)incoming[alpha_id_len + nOffset] || 0xff == (int)incoming[alpha_id_len + nOffset])
		{
			params->tpSvcCntrAddr.dialNumLen = 0;

			dbg(" SCAddr Length is 0");
		}
		else
		{
			if (0 < (int)incoming[alpha_id_len + nOffset] )
			{
				params->tpSvcCntrAddr.dialNumLen = (int)(incoming[alpha_id_len + nOffset] - 1);

			        if(params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
				        params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId= incoming[alpha_id_len + (++nOffset)] & 0x0f ;
				params->tpSvcCntrAddr.typeOfNum= (incoming[alpha_id_len + nOffset] & 0x70) >>4 ;

				memcpy(params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)], (params->tpSvcCntrAddr.dialNumLen));

				dbg("SCAddr Length = %d ",params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d",params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d",params->tpSvcCntrAddr.numPlanId);

				for(i = 0 ; i < (int)params->tpSvcCntrAddr.dialNumLen ; i ++)
					dbg("SCAddr = %d [%02x]",i,params->tpSvcCntrAddr.diallingNum[i]);
			}
			else
			{
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}
	}
	else if ((0x00 < (int)incoming[alpha_id_len +nSCAAddrOffset] && (int)incoming[alpha_id_len +nSCAAddrOffset] <= 12)
			|| 0xff != (int)incoming[alpha_id_len +nSCAAddrOffset])
	{
		nOffset = nSCAAddrOffset;

		if(0x00 == (int)incoming[alpha_id_len + nOffset] || 0xff == (int)incoming[alpha_id_len + nOffset])
		{
			params->tpSvcCntrAddr.dialNumLen = 0;
			dbg("SCAddr Length is 0");
		}
		else
		{

			if (0 < (int)incoming[alpha_id_len + nOffset] )
			{
				params->tpSvcCntrAddr.dialNumLen = (int)(incoming[alpha_id_len + nOffset] - 1);

				params->tpSvcCntrAddr.dialNumLen = incoming[alpha_id_len + nOffset] -1;

			        if(params->tpSvcCntrAddr.dialNumLen > SMS_SMSP_ADDRESS_LEN)
				        params->tpSvcCntrAddr.dialNumLen = SMS_SMSP_ADDRESS_LEN;

				params->tpSvcCntrAddr.numPlanId= incoming[alpha_id_len + (++nOffset)] & 0x0f ;
				params->tpSvcCntrAddr.typeOfNum= (incoming[alpha_id_len + nOffset] & 0x70) >>4 ;

				memcpy(params->tpSvcCntrAddr.diallingNum, &incoming[alpha_id_len + (++nOffset)],
						(params->tpSvcCntrAddr.dialNumLen)) ;

				dbg("SCAddr Length = %d ",params->tpSvcCntrAddr.dialNumLen);
				dbg("SCAddr TON is %d",params->tpSvcCntrAddr.typeOfNum);
				dbg("SCAddr NPI is %d",params->tpSvcCntrAddr.numPlanId);

				for(i = 0 ; i < (int)params->tpSvcCntrAddr.dialNumLen ; i ++)
					dbg("SCAddr = %d [%02x]",i,params->tpSvcCntrAddr.diallingNum[i]);
			}
			else
			{
				params->tpSvcCntrAddr.dialNumLen = 0;
			}
		}

	}

	if((params->paramIndicator & SMSPValidPID) == 0 &&	(alpha_id_len + nPIDOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
	{
		params->tpProtocolId = incoming[alpha_id_len + nPIDOffset];
	}
	if((params->paramIndicator & SMSPValidDCS) == 0 && (alpha_id_len + nDCSOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
	{
		params->tpDataCodingScheme = incoming[alpha_id_len + nDCSOffset];
	}
	if((params->paramIndicator & SMSPValidVP) == 0 && (alpha_id_len + nVPOffset) < MAX_GSM_SMS_PARAM_RECORD_SIZE)
	{
		params->tpValidityPeriod = incoming[alpha_id_len + nVPOffset];
	}

	dbg(" Alpha Id(Len) = %d",(int)params->alphaIdLen);

	for (i=0; i< (int)params->alphaIdLen ; i++)
	{
		dbg(" Alpha Id = [%d] [%c]",i,params->szAlphaId[i]);
	}
	dbg(" PID = %d",params->tpProtocolId);
	dbg(" DCS = %d",params->tpDataCodingScheme);
	dbg(" VP = %d",params->tpValidityPeriod);

	return TRUE;
}

/************************************************************/
/************************  Events Cb  *************************/
/************************************************************/

static gboolean on_event_sms_ready_status(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_sms_ready_status readyStatusInfo = {0,};
	char *line = NULL;
	GSList* tokens = NULL;
	GSList* lines = NULL;
	char *pResp = NULL;
	//CoreObject *o = NULL;
	
	int rtn = -1 , status = 0;

	dbg(" Func Entrance");

	lines = (GSList *)event_info;
	if (1 != g_slist_length(lines))
	{
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}
	line = (char *)(lines->data);

	dbg(" Func Entrance");

	if(line!=NULL)
	{
		dbg("Response OK");
			dbg("noti line is %s", line);
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp !=NULL)
				status = atoi(pResp);

	}
	else
	{
		dbg("Response NOK");
	}		

	if (status == AT_SMS_DEVICE_READY)
	{
		readyStatusInfo.status = SMS_DEVICE_READY;
		tcore_sms_set_ready_status(o, readyStatusInfo.status);
		dbg("SMS Ready status = [%s]", readyStatusInfo.status ? "TRUE" : "FALSE");
		rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_DEVICE_READY, sizeof(struct tnoti_sms_ready_status), &readyStatusInfo);
		dbg(" Return value [%d]",rtn);
	}
	else
	{
		readyStatusInfo.status = SMS_DEVICE_NOT_READY;
	}

OUT:
	if(NULL!=tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}



static gboolean on_event_sms_incom_msg(CoreObject *o, const void *event_info, void *user_data)
{
	struct property_sms_info *property;
	

	int rtn = -1, ScLength = 0, i = 0 , alpha = 0;
	unsigned char format = 0;
	unsigned char LastSemiOctect;

	char * line1 = NULL, *line2 = NULL, *pResp = NULL;
	GSList *tokens = NULL;

	GSList *lines = NULL;
	char *line = NULL;
	int length = 0;
	unsigned char *bytePDU = NULL;
	struct tnoti_sms_umts_msg gsmMsgInfo;

	dbg("Entered Function");

	lines = (GSList *)event_info;
	memset(&gsmMsgInfo, 0x00, sizeof(struct tnoti_sms_umts_msg));

	if(2 != g_slist_length(lines))
	{
		err("Invalid number of lines for +CMT. Must be 2");
		return FALSE;
	}
	
	line = (char *)g_slist_nth_data(lines, 0); /* Fetch Line 1 */

	dbg("Line 1: [%s]", line);
	
	if (!line)
	{
		err("Line 1 is invalid");
		return FALSE;
	}

	tokens = tcore_at_tok_new(line); /* Split Line 1 into tokens */

	dbg("Alpha ID: [%02x]", g_slist_nth_data(tokens, 0)); /* 0: Alpha ID */

	length = atoi((char *)g_slist_nth_data(tokens, 1));

	dbg("Length: [%d]", length);	/* 1: PDU Length */

	gsmMsgInfo.msgInfo.msgLength = length;

	line = (char *)g_slist_nth_data(lines, 1); /* Fetch Line 2 */

	dbg("Line 2: [%s]", line);
	
	if (!line)
	{
		err("Line 2 is invalid");
		return FALSE;
	}

	/* Convert to Bytes */
	bytePDU = (unsigned char *)util_hexStringToBytes(line);

	if(NULL == bytePDU)
	{
		err("bytePDU is NULL");
		return FALSE;
	}

	memcpy(gsmMsgInfo.msgInfo.sca, bytePDU, (strlen(line)/2 - length));
	memcpy(gsmMsgInfo.msgInfo.tpduData, &bytePDU[(strlen(line)/2 - length)], length);

	util_hex_dump("      ", strlen(line)/2, bytePDU);
	util_hex_dump("      ", (strlen(line)/2 - length), gsmMsgInfo.msgInfo.sca);
	util_hex_dump("      ", length, gsmMsgInfo.msgInfo.tpduData);

	rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_INCOM_MSG, sizeof(struct tnoti_sms_umts_msg), &gsmMsgInfo);
	
	return TRUE;
}



static void on_event_sms_send_ack(TcorePending *p, int data_len, const void *data, void *user_data)
{
    GSList *lines = NULL;
	
    lines = (GSList*)data;
    return TRUE;
}

static gboolean on_event_sms_memory_status(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_sms_memory_status memStatusInfo = {0,};

	int rtn = -1 ,memoryStatus = 0;
	const TcoreATResponse *atResp = event_info;
	GSList *tokens=NULL;
	GSList *lines=NULL;
	char *line = NULL , pResp = NULL;

	lines = (GSList *)event_info;
        if (1 != g_slist_length(lines))
        {
                dbg("unsolicited msg but multiple line");
		return;
        }

	line = (char*)(lines->data);


	dbg(" Func Entrance");

	if (atResp->success)
	{
		dbg("Response OK");
		line = (const char*)lines->data;
		tokens = tcore_at_tok_new(line);
		pResp = g_slist_nth_data(tokens, 0);

		if(pResp)
		{
			memoryStatus = atoi(pResp);	
		}
		
	}
	switch(memoryStatus)
	{
		case AT_MEMORY_AVAILABLE:
			{
				memStatusInfo.status = SMS_PHONE_MEMORY_STATUS_AVAILABLE;
				break;
			}
			
		case AT_MEMORY_FULL:
			{
				memStatusInfo.status = SMS_PHONE_MEMORY_STATUS_FULL;
				break;
			}
		default:
			{
				memStatusInfo.status = -1;
				break;
			}
	}

	dbg("memory status - %d",memStatusInfo.status);

	rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_MEMORY_STATUS, sizeof(struct tnoti_sms_memory_status), &memStatusInfo);
	dbg(" Return value [%d]",rtn);

	return TRUE;

}

static gboolean on_event_sms_cb_incom_msg(CoreObject *o, const void *event_info, void *user_data)
{
	//+CBM: <length><CR><LF><pdu>

	struct tnoti_sms_cellBroadcast_msg cbMsgInfo;

	int rtn = -1 , length = 0;
	char * line = NULL, *pdu = NULL, pResp = NULL;
	GSList *tokens = NULL;
	GSList *lines = NULL;

	dbg(" Func Entrance");

	lines = (GSList *)event_info;

	memset(&cbMsgInfo, 0, sizeof(struct tnoti_sms_cellBroadcast_msg));

	if (1 != g_slist_length(lines))
	{
		dbg("unsolicited msg but multiple lines");
		goto OUT;
	}
	line = (char *)(lines->data);

	if (line != NULL)
	{
			dbg("Response OK");
			dbg("Noti line is %s",line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp)
			{
				length = atoi(pResp);
			}else
			{
				dbg("token 0 is null");
			}
			pdu = g_slist_nth_data(tokens, 3);
			if (pdu != NULL)
			{
				cbMsgInfo.cbMsg.length = length;
				cbMsgInfo.cbMsg.cbMsgType = SMS_CB_MSG_CBS ; //TODO - Need to check for other CB types

				dbg("CB Msg LENGTH [%2x](((( %d ))))", length, cbMsgInfo.cbMsg.length);

				if ( (cbMsgInfo.cbMsg.length >0) && ((SMS_CB_PAGE_SIZE_MAX +1)  > cbMsgInfo.cbMsg.length))
				{
					memcpy(cbMsgInfo.cbMsg.msgData, (char*)pdu, cbMsgInfo.cbMsg.length);
					rtn = tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_SMS_CB_INCOM_MSG, sizeof(struct tnoti_sms_cellBroadcast_msg), &cbMsgInfo);
				}
				else
				{
					dbg("Invalid Message Length");
				}

			}
			else
			{
				dbg("Recieved NULL pdu");
			}
	}
	else
	{
			dbg("Response NOK");
	}
	
	
	dbg(" Return value [%d]",rtn);

OUT:

	return;

}

static void on_response_sms_delete_msg_cnf(TcorePending *p, int data_len, const void *data, void *user_data)
{
	struct tresp_sms_delete_msg delMsgInfo = {0,};
	UserRequest *ur = NULL;
	const TcoreATResponse *atResp = data;
	GSList *tokens=NULL;
	char *line = NULL , pResp = NULL;

	int rtn = -1 , RequestId = -1;
	int index = (int *)user_data;

	dbg(" Func Entrance");

	ur = tcore_pending_ref_user_request(p);
	if (atResp->success)
	{
		dbg("Response OK");
		delMsgInfo.index = index;
		delMsgInfo.result = SMS_SENDSMS_SUCCESS;
		
	}
	else
	{
		dbg("Response NOK");	
		delMsgInfo.index = index;
		delMsgInfo.result = SMS_DEVICE_FAILURE;

	}

	rtn = tcore_user_request_send_response(ur, TRESP_SMS_DELETE_MSG, sizeof(struct tresp_sms_delete_msg), &delMsgInfo);

	return;
}

static void on_response_sms_save_msg_cnf(TcorePending *p, int data_len, const void *data, void *user_data)
{
	struct tresp_sms_save_msg saveMsgInfo = {0,};
	UserRequest *ur = NULL;
	const TcoreATResponse *atResp = data;
	GSList *tokens = NULL;
	char *line = NULL;
	char *pResp = NULL;
	int rtn = -1, index = -1;

	ur = tcore_pending_ref_user_request(p);
	if (atResp->success)
	{
		dbg("Response OK");
		if(atResp->lines)
		{
			line = (const char *)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp)
			{
				dbg("0: %s", pResp);
		 		saveMsgInfo.index = (atoi(pResp) - 1); /* IMC index starts from 1 */
				saveMsgInfo.result = SMS_SENDSMS_SUCCESS;
		 	}
			else
			{
				dbg("No Tokens");	
				saveMsgInfo.index = -1;
				saveMsgInfo.result = SMS_DEVICE_FAILURE;
			}
			 
		}
	}
	else
	{
		dbg("Response NOK");	
		saveMsgInfo.index = -1;
		saveMsgInfo.result = SMS_DEVICE_FAILURE;
	}

	rtn = tcore_user_request_send_response(ur, TRESP_SMS_SAVE_MSG, sizeof(struct tresp_sms_save_msg), &saveMsgInfo);
	dbg("Return value [%d]", rtn);
	return;
}

static void on_response_sms_deliver_rpt_cnf(TcorePending *p, int data_len, const void *data, void *user_data)
{

	struct tresp_sms_set_delivery_report deliverReportInfo = {0,};
	UserRequest *ur = NULL;
	const TcoreATResponse *atResp = data;
	GSList *tokens=NULL;
	char *line = NULL , pResp = NULL;
	int rtn = -1;

	dbg(" Func Entrance");


	if (atResp->success)
	{
		dbg("Response OK");
		if(atResp->lines) 
		{
			line = (const char*)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			 pResp = g_slist_nth_data(tokens, 0);
			 if (pResp)
		 	{
	 			deliverReportInfo.result = SMS_SENDSMS_SUCCESS;
		 	}
			else
			{
				dbg("No tokens");	
				deliverReportInfo.result = SMS_DEVICE_FAILURE;
			}
		}else
		{
			dbg("No lines");
			deliverReportInfo.result = SMS_DEVICE_FAILURE;
		}
	}else
	{
		dbg("Response NOK");
	}


	rtn = tcore_user_request_send_response(ur, TRESP_SMS_SET_DELIVERY_REPORT, sizeof(struct tresp_sms_set_delivery_report), &deliverReportInfo);

	dbg(" Return value [%d]",rtn);

	return;

}



/*************************************************************/
/***********************  Responses Cb  ************************/
/************************************************************/
static void on_response_send_umts_msg(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	UserRequest *ur;
	struct tresp_sms_send_umts_msg respSendMsg;

	GSList *tokens=NULL;
	int error;
	char *line = NULL;
	int ret;
	int err;

	ur = tcore_pending_ref_user_request(p);

	if (resp->success)
		{
			dbg("RESPONSE OK");
			ret = Send_SmsSubmitTpdu(tcore_pending_ref_core_object(p), ur);

			if(ret != (int)TCORE_RETURN_SUCCESS)
			{
				respSendMsg.result = SMS_INVALID_PARAMETER;
				tcore_user_request_send_response(ur, TRESP_SMS_SEND_UMTS_MSG, sizeof(struct tresp_sms_send_umts_msg), &respSendMsg);
			}	
			
		}
	else
		{
			dbg("RESPONSE N OK");	
			memset(&respSendMsg, 0, sizeof(struct tresp_sms_send_umts_msg));
	
			//failure case - consider this later
			line = resp->final_response;
	
			respSendMsg.result = SMS_DEVICE_FAILURE;

			tcore_user_request_send_response(ur, TRESP_SMS_SEND_UMTS_MSG, sizeof(struct tresp_sms_send_umts_msg), &respSendMsg);
			
		}
}

static void on_response_send_smsSubmitTpdu(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entered");

	UserRequest *ur = NULL;
	ur = tcore_pending_ref_user_request(p);
	struct tresp_sms_send_umts_msg respUmtsInfo;
	const TcoreATResponse *resp = data;
	char *line = NULL , *pResp = NULL;
	int ret =0, result = 0;
	int mr = 0;
	int error = 0;
	GSList* tokens = NULL;

	//currently IMC provides only index and msgref
	 memset(&respUmtsInfo, 0 , sizeof(struct tresp_sms_send_umts_msg));
	
	if(resp->success > 0)
	{
		dbg("Response OK");
		if(resp->lines) {
			line = (const char *)resp->lines->data;
			dbg("line is %s",line);
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL)	
			{
				mr = atoi(pResp);
				result = SMS_SENDSMS_SUCCESS;
			}else
			{
				dbg("no MsgRef recieved");
				result = SMS_DEVICE_FAILURE;
			}
		}else
		{
			dbg("No lines");	
			result = SMS_DEVICE_FAILURE;
		}
	}else
	{
		//failure case - consider this later
		dbg("Sent Status Response NOK");
		result = SMS_DEVICE_FAILURE;
	}
		
	ur = tcore_pending_ref_user_request(p);
	if(ur)
	{


		dbg(" MR : %d", mr);
		respUmtsInfo.result = result;
		tcore_user_request_send_response(ur, TRESP_SMS_SEND_UMTS_MSG, sizeof(struct tresp_sms_send_umts_msg), &respUmtsInfo);

	}
	else
	{
		dbg("no user_request");
	}
	

	dbg("Exit");
	
}

static void on_response_read_msg(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_read_msg respReadMsg;
	const TcoreATResponse *atResp = data;

	GSList *tokens=NULL;
	char * line = NULL, *pResp = NULL , *pdu = NULL;
	int ScLength = 0;
	unsigned char LastSemiOctect;
	int rtn =0 , i =0;
	int stat =0 , alpha =0 , length =0;
	int index = (int *)user_data;

	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	if (atResp->success)
	{
		if (atResp->lines)
		{
			line = (char*)atResp->lines->data;

			dbg("response Ok line is %s",line);

			tokens = tcore_at_tok_new(line);
			dbg(" length of tokens is %d\n", g_slist_length(atResp->lines));
		
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL)
			{
				//ToDO msg status mapping needs to be done
				stat = atoi(pResp);
				dbg("stat is %d",stat);
				switch (stat)
				{
					case AT_REC_UNREAD:
						respReadMsg.dataInfo.msgStatus = SMS_STATUS_UNREAD;
						break;
					case AT_REC_READ:
						respReadMsg.dataInfo.msgStatus = SMS_STATUS_READ;
						break;
					case AT_STO_UNSENT:
						respReadMsg.dataInfo.msgStatus = SMS_STATUS_UNSENT;
						break;
					case AT_STO_SENT:
						respReadMsg.dataInfo.msgStatus = SMS_STATUS_SENT;
						break;
					case AT_ALL://TODO Need to verify the mapping
						respReadMsg.dataInfo.msgStatus = SMS_STATUS_RESERVED;
						break;
					default://TODO Need to verify the mapping
						respReadMsg.dataInfo.msgStatus = SMS_STATUS_RESERVED;
						break;
				}
			}
		
			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL)
			{
				alpha = atoi(pResp);
				dbg("alpha is %d",alpha);
			}
		
			pResp = g_slist_nth_data(tokens, 2);
			if (pResp != NULL)
			{
				length = atoi(pResp);
				dbg("length is %d",length);
			}

			pdu = g_slist_nth_data(tokens, 3);
			if (pdu != NULL)
			{
				dbg("pdu is %s",pdu);
				ScLength = (int)pdu[0];

				respReadMsg.dataInfo.simIndex = index; //Retrieving index stored as part of req userdata 


			if(0 == ScLength)
			{

				respReadMsg.dataInfo.smsData.msgLength =  length  - (ScLength+1) ;

				if ((respReadMsg.dataInfo.smsData.msgLength >0) && (0xff >= respReadMsg.dataInfo.smsData.msgLength))
				{
					dbg("SCA Length is 0");

					memset(respReadMsg.dataInfo.smsData.sca, 0, TAPI_SIM_SMSP_ADDRESS_LEN);

					//if(read_data.SmsData.MsgLength > SMS_SMDATA_SIZE_MAX)
					//{
						respReadMsg.dataInfo.smsData.msgLength = SMS_SMDATA_SIZE_MAX;
					//}

					memcpy(respReadMsg.dataInfo.smsData.tpduData, &pdu[2], respReadMsg.dataInfo.smsData.msgLength);
					respReadMsg.result = SMS_SUCCESS;

					rtn = tcore_user_request_send_response(ur, TRESP_SMS_READ_MSG, sizeof(struct tresp_sms_read_msg), &respReadMsg);
				}
				else
				{
					dbg("Invalid Message Length");
					respReadMsg.result = SMS_INVALID_PARAMETER_FORMAT;
					rtn = tcore_user_request_send_response(ur, TRESP_SMS_READ_MSG, sizeof(struct tresp_sms_read_msg), &respReadMsg);
				}

			}
			else		//SCLength is Not 0
			{
				respReadMsg.dataInfo.smsData.msgLength =  (length - (ScLength+1));

				if ((respReadMsg.dataInfo.smsData.msgLength >0) && (0xff >= respReadMsg.dataInfo.smsData.msgLength))
				{
					memcpy(respReadMsg.dataInfo.smsData.sca, (char*)pdu,(ScLength+1));

					LastSemiOctect = pdu[ScLength + 1] & 0xf0;
					if(LastSemiOctect == 0xf0)
					{
						respReadMsg.dataInfo.smsData.sca[0] = (ScLength-1)*2 - 1;
					}
					else
					{
						respReadMsg.dataInfo.smsData.sca[0] = (ScLength-1)*2;
					}

					//if(read_data.SmsData.MsgLength > SMS_SMDATA_SIZE_MAX)
					//{
						respReadMsg.dataInfo.smsData.msgLength = SMS_SMDATA_SIZE_MAX;
					//}

					for(i=0;i<(ScLength+1);i++)
					{
						dbg("SCA is [%2x] ", respReadMsg.dataInfo.smsData.sca[i]);
					}

					memcpy(respReadMsg.dataInfo.smsData.tpduData, &pdu[ScLength+1], respReadMsg.dataInfo.smsData.msgLength);
					respReadMsg.result = SMS_SUCCESS;

					rtn = tcore_user_request_send_response(ur, TRESP_SMS_READ_MSG, sizeof(struct tresp_sms_read_msg), &respReadMsg);
				}
				else
				{
					dbg("Invalid Message Length");
					respReadMsg.result = SMS_INVALID_PARAMETER_FORMAT;
					rtn = tcore_user_request_send_response(ur, TRESP_SMS_READ_MSG, sizeof(struct tresp_sms_read_msg), &respReadMsg);
				}

			}
		}
		else
		{
			dbg("Read PDU Is NULL");
		}
		}
		else
		{
			dbg("No lines in AT response");
		}
	}
	else
	{
		dbg("Response NOK");
	}
	return;

}


static void on_response_get_msg_indices(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL;
	struct tresp_sms_get_storedMsgCnt * respStoredMsgCnt = NULL;
	int ctr = 0;
	const TcoreATResponse *atResp = data;
	GSList *tokens = NULL;
	GSList *lines = NULL;
	char *line = NULL , *pResp = NULL;
	int usedCnt = 0, totalCnt = 0, result = 0, noOfLines = 0 , i = 0;

	//memset(&respStoredMsgCnt, 0, sizeof(struct tresp_sms_get_storedMsgCnt));

	respStoredMsgCnt = (struct tresp_sms_get_storedMsgCnt *)user_data;
	ur = tcore_pending_ref_user_request(p);


	if (atResp->success)
        {
                dbg("Response OK");
                if(atResp->lines)
                {
			noOfLines = g_slist_length(atResp->lines);

			if (noOfLines > SMS_GSM_SMS_MSG_NUM_MAX)
				noOfLines = SMS_GSM_SMS_MSG_NUM_MAX;

                        line = (const char*)atResp->lines->data;
                        dbg("line and no of lines is %s %d",line, noOfLines);
                        tokens = tcore_at_tok_new(line);
             
	
     			for (i = 0; i < noOfLines ; i++)
     			{
				line = (char *)(lines->data);
				if (line != NULL)
				{
					tokens = tcore_at_tok_new(line);
					pResp = g_slist_nth_data(tokens, 0);
					if (pResp != NULL)
					{
						respStoredMsgCnt->storedMsgCnt.indexList[i] = atoi(pResp);
						lines = lines->next;
					}
					else
					{
						respStoredMsgCnt->result = SMS_DEVICE_FAILURE;
						dbg("pResp is NULL");
				
					}
				}
				else
				{
					respStoredMsgCnt->result = SMS_DEVICE_FAILURE;
					dbg("line is NULL");
				}
     			}
		}
		else
		{
			dbg("No lines");
		}
	}
	else
	{
		dbg("Respnose NOK");
	}
	
	
	tcore_user_request_send_response(ur, TRESP_SMS_GET_STORED_MSG_COUNT, sizeof(struct tresp_sms_get_storedMsgCnt), respStoredMsgCnt);


}

static void on_response_get_storedMsgCnt(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur = NULL, *ur_dup = NULL;
	struct tresp_sms_get_storedMsgCnt respStoredMsgCnt;
	int ctr = 0;
	const TcoreATResponse *atResp = data;
	GSList *tokens=NULL;
	char *line = NULL , *pResp = NULL , *cmd_str = NULL, *atReq = NULL;
	int usedCnt = 0, totalCnt = 0, result = 0;

	TcorePending *pending_new = NULL;
	CoreObject *o = NULL;

	memset(&respStoredMsgCnt, 0, sizeof(struct tresp_sms_get_storedMsgCnt));

	ur = tcore_pending_ref_user_request(p);
	ur_dup = tcore_user_request_ref(ur);
	o = tcore_pending_ref_core_object(p);

	if (atResp->success)
	{
		dbg("Response OK");
		if(atResp->lines) 
		{
			line = (const char*)atResp->lines->data;
			dbg("line is %s",line);
			tokens = tcore_at_tok_new(line);
			 pResp = g_slist_nth_data(tokens, 0);
			 if (pResp)
		 	{
		 			usedCnt =atoi(pResp);
					dbg("used cnt is %d",usedCnt);
					
			}
			 pResp = g_slist_nth_data(tokens, 1);
			 if (pResp)
		 	{
		 			totalCnt =atoi(pResp);
					result = SMS_SENDSMS_SUCCESS;
					
					respStoredMsgCnt.storedMsgCnt.usedCount = usedCnt;
					respStoredMsgCnt.storedMsgCnt.totalCount = totalCnt;
					respStoredMsgCnt.result = result;
					dbg("used %d, total %d, result %d",usedCnt, totalCnt,result);


					// This is required  because CPMS does not give index list. So need to store the above in user req and again issue CMGL
// commented to avoid parser malfunction hyKo 120819

					pending_new = tcore_pending_new(o,0);
					cmd_str = g_strdup_printf("AT+CMGL\r");;
					dbg("cmd str is %s",cmd_str);
					atReq = tcore_at_request_new((const char*)cmd_str, "+CMGL:", TCORE_AT_MULTILINE);
					tcore_pending_set_request_data(pending_new, 0,atReq);
					// Setting user data so as to send consolidated response to GetStoredMsgCnt notification
					tcore_pending_set_response_callback(pending_new, on_response_get_msg_indices, (void *)&respStoredMsgCnt);
					tcore_pending_link_user_request(pending_new, ur_dup);
					tcore_pending_set_send_callback(pending_new, on_confirmation_sms_message_send, NULL);
					tcore_hal_send_request(tcore_object_get_hal(o), pending_new);

					return;

			}
		}else
		{
				dbg("No data");
				result = SMS_DEVICE_FAILURE;
		}
	}
	else
	{
		dbg("Response NOK");
	}

	respStoredMsgCnt.storedMsgCnt.usedCount = usedCnt;
	respStoredMsgCnt.storedMsgCnt.totalCount = totalCnt;
	respStoredMsgCnt.result = result;
	//TODO - index list needs to be populated
//	tcore_user_request_send_response(ur, TRESP_SMS_GET_STORED_MSG_COUNT, sizeof(struct tresp_sms_get_storedMsgCnt), &respStoredMsgCnt);

	return;
}

static void on_response_get_sca(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	//Response is expected in this format +CSCA: <sca>,<tosca>

	TcorePlugin *plugin;
	UserRequest *ur;
	struct tresp_sms_get_sca respGetSca;
	GSList *tokens=NULL;

	//copies the AT response data to resp
	const TcoreATResponse *atResp = data;
	char *line = NULL, *sca = NULL, *typeOfAddress = NULL;

	int err = 0;
	int response = 0;

	// +CSCA: <sca number>,<sca type>

	memset(&respGetSca, 0, sizeof(struct tresp_sms_get_sca));

	ur = tcore_pending_ref_user_request(pending);
	if (atResp->success)
	{
		dbg("Response OK");
		if(atResp->lines) 
		{
			line = (const char*)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			sca = g_slist_nth_data(tokens, 0);
			typeOfAddress = g_slist_nth_data(tokens, 1);
			if ((sca) && (typeOfAddress))
			{
					dbg("sca and address type are %s %s", sca, typeOfAddress);
					respGetSca.scaAddress.dialNumLen = strlen(sca);
					if(atoi(typeOfAddress) == 145)
						{
							respGetSca.scaAddress.typeOfNum = SIM_TON_INTERNATIONAL;
						}
					else	
						{
							respGetSca.scaAddress.typeOfNum = SIM_TON_NATIONAL;
						}
					respGetSca.scaAddress.numPlanId = 0;
		
					memcpy(respGetSca.scaAddress.diallingNum, sca, strlen(sca));

					dbg("len %d, sca %s, TON %d, NPI %d",respGetSca.scaAddress.dialNumLen,respGetSca.scaAddress.diallingNum,respGetSca.scaAddress.typeOfNum,respGetSca.scaAddress.numPlanId); 
					respGetSca.result = SMS_SENDSMS_SUCCESS;
			}
		}
	}
	else
	{
		dbg("Response NOK");
		respGetSca.result = SMS_DEVICE_FAILURE;
	}
	
	tcore_user_request_send_response(ur, TRESP_SMS_GET_SCA, sizeof(struct tresp_sms_get_sca), &respGetSca);
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
	
	//CoreObject *obj = user_data;
	UserRequest *ur;
	//copies the AT response data to resp
	const TcoreATResponse *atResp = data;
	char * line = NULL;
	struct tresp_sms_set_sca respSetSca;
	int err = 0, response = 0;

	memset(&respSetSca, 0, sizeof(struct tresp_sms_set_sca));

	ur = tcore_pending_ref_user_request(pending);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}
	
	if (atResp->success >0)
	{
		dbg("RESPONSE OK");
		respSetSca.result = SMS_SUCCESS;
	}
	else
	{
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

	int msgid_length = 0 , msgCount = 0;
	int i = 0, mode =0 , result = 0;
	char *mid = NULL, *dcs = NULL, *pResp = NULL, *line = NULL, *res = NULL;
	char delim[] = ",";

	memset(&respGetCbConfig, 0, sizeof(struct tresp_sms_get_cb_config));

	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	if (atResp->success)
	{
		dbg("Response OK");
		if(atResp->lines) 
		{
			line = (const char*)atResp->lines->data;
			if (line != NULL)
			{
				dbg("line is %s",line);	
				tokens = tcore_at_tok_new(line);
				pResp = g_slist_nth_data(tokens, 0);
				if (pResp)
				{
					mode = atoi(pResp);
					respGetCbConfig.cbConfig.bCBEnabled = mode;
					pResp = g_slist_nth_data(tokens, 1);
					if (pResp)
					{
						mid = strtok(pResp, delim); i = 0;
							while( res != NULL ) 
							{
						    		res = strtok( NULL, delim );
    						  		dbg("mid is %s%s\n", mid,res);
								if (result!= NULL)
								{
									if (strlen(res) >0)
										{
						    					respGetCbConfig.cbConfig.msgIDs[i] = atoi(res);
						    					i++;
										}
								}
							}
					}
					else
					{
							result = SMS_DEVICE_FAILURE;
					}
					respGetCbConfig.cbConfig.msgIdCount = i;

				}
				else
				{
						result = SMS_DEVICE_FAILURE;
				}
				//dcs = g_slist_nth_data(tokens, 2); DCS not needed by telephony
			}
			else
			{
				dbg("line is NULL");
				result = SMS_DEVICE_FAILURE;
			}
			
			
		}
		else
		{
				result = SMS_DEVICE_FAILURE;
				dbg("atresp->lines is NULL");
		}
	}
	else
	{
			result = SMS_DEVICE_FAILURE;
			dbg("RESPONSE NOK");
	}

	// Todo max list count and selectedid

	tcore_user_request_send_response(ur, TRESP_SMS_GET_CB_CONFIG, sizeof(struct tresp_sms_get_cb_config), &respGetCbConfig);

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

	CoreObject *obj = user_data;
	UserRequest *ur;
	const TcoreATResponse *resp = data;
	
	GQueue *queue;
	int err;
	int response;
	const char *line = NULL;
	GSList *tokens=NULL;
	
	struct tresp_sms_set_cb_config respSetCbConfig = {0,};

	memset(&respSetCbConfig, 0, sizeof(struct tresp_sms_set_cb_config));

	ur = tcore_pending_ref_user_request(pending);

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");
		
	}
	else
	{
		dbg("RESPONSE NOK");
		line = (const char*)resp->final_response;
		tokens = tcore_at_tok_new(line);

		if (g_slist_length(tokens) < 1) {
		  	dbg("err cause not specified or string corrupted");
		    	respSetCbConfig.result = TCORE_RETURN_3GPP_ERROR;
		}
		else
		{
			response = atoi(g_slist_nth_data(tokens, 0));
			/* TODO: CMEE error mapping is required. */
    			respSetCbConfig.result = TCORE_RETURN_3GPP_ERROR;
		}
	}
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	tcore_user_request_send_response(ur, TRESP_SMS_SET_CB_CONFIG, sizeof(struct tresp_sms_set_cb_config), &respSetCbConfig);

	return;
}

static void on_response_set_mem_status(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_mem_status respSetMemStatus = {0,};
	const TcoreATResponse *resp = data;
	int err = 0, response = 0;
	const char *line = NULL;
	GSList *tokens=NULL;
	
	struct tresp_sms_set_cb_config respSetCbConfig = {0,};

	memset(&respSetMemStatus, 0, sizeof(struct tresp_sms_set_mem_status));

	if(resp->success > 0)
	{
		dbg("RESPONSE OK");
		respSetMemStatus.result = SMS_SENDSMS_SUCCESS;
		
	}
	else
	{
		dbg("RESPONSE NOK");
		respSetMemStatus.result = SMS_DEVICE_FAILURE;
	}	

	ur = tcore_pending_ref_user_request(p);
	if (!ur)
	{
		dbg("no user_request");
		return;
	}

	tcore_user_request_send_response(ur, TRESP_SMS_SET_MEM_STATUS, sizeof(struct tresp_sms_set_mem_status), &respSetMemStatus);

	return;
}


static void on_response_set_msg_status(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_sms_set_msg_status respMsgStatus = {0,};
	const TcoreATResponse *atResp = data;
        int err = 0, response = 0, sw1 =0 , sw2 = 0;
        const char *line = NULL;
        char *pResp = NULL;
        GSList *tokens=NULL;

	dbg("Entry");

	memset(&respMsgStatus, 0, sizeof(struct tresp_sms_set_msg_status));
        ur = tcore_pending_ref_user_request(pending);

        if(atResp->success > 0)
        {
                dbg("RESPONSE OK");

		if(atResp->lines)
                {
                        line = (const char*)atResp->lines->data;
                        tokens = tcore_at_tok_new(line);
                        pResp = g_slist_nth_data(tokens, 0);
                        if (pResp != NULL)
                        {
                                sw1 = atoi(pResp);
                        }
                        else
                        {
                                respMsgStatus.result = SMS_DEVICE_FAILURE;
                                dbg("sw1 is NULL");
                        }
                        pResp = g_slist_nth_data(tokens, 1);
                        if (pResp != NULL)
                        {
                                sw2 = atoi(pResp);
                                if ((sw1 == 144) && (sw2 == 0))
                                {
                                        respMsgStatus.result = SMS_SENDSMS_SUCCESS;
                                }
                                else
                                {
                                        //TODO Error Mapping
                                        respMsgStatus.result = SMS_DEVICE_FAILURE;
                                }
                        }
                        else
                        {
                                dbg("sw2 is NULL");
                                respMsgStatus.result = SMS_DEVICE_FAILURE;

       			}
                        pResp = g_slist_nth_data(tokens, 3);

        		if (pResp != NULL)
                        {
                                response = pResp;
                                dbg("response is %s", response);
                        }

                }
		else
		{
			dbg("No lines");
		}

        }
        else
        {
                dbg("RESPONSE NOK");
                respMsgStatus.result = SMS_DEVICE_FAILURE;
        }

        tcore_user_request_send_response(ur, TRESP_SMS_SET_MSG_STATUS , sizeof(struct tresp_sms_set_msg_status), &respMsgStatus);



	dbg("Exit");
	return;
}

static void on_response_get_sms_params(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	UserRequest *ur;
	struct tresp_sms_get_params respGetParams = {0,};
	const TcoreATResponse *atResp = data;
	int err = 0, response = 0, sw1 =0 , sw2 = 0;
	const char *line = NULL;
	char *pResp = NULL;
	GSList *tokens=NULL;
	
	memset(&respGetParams, 0, sizeof(struct tresp_sms_set_params));
	ur = tcore_pending_ref_user_request(pending);
		
	if(atResp->success > 0)
	{
		dbg("RESPONSE OK");

		if(atResp->lines) 
		{
			line = (const char*)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL)
			{
				sw1 = atoi(pResp);
			}
			else
			{
				respGetParams.result = SMS_DEVICE_FAILURE;
				dbg("sw1 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL)
			{
				sw2 = atoi(pResp);
				if ((sw1 == 144) && (sw2 == 0))
				{
					respGetParams.result = SMS_SENDSMS_SUCCESS;
				}
				else
				{
					//TODO Error Mapping
					respGetParams.result = SMS_DEVICE_FAILURE;
				}
			}
			else
			{
				dbg("sw2 is NULL");
				respGetParams.result = SMS_DEVICE_FAILURE;
				
			}
			pResp = g_slist_nth_data(tokens, 3);
			if (pResp != NULL)
			{
				response = pResp;
				dbg("response is %s", response);
			}
			
		}
	}
	else
	{
		dbg("RESPONSE NOK");
		respGetParams.result = SMS_DEVICE_FAILURE;
	}

	dbg("Exit");
	return;
}

static void on_response_set_sms_params(TcorePending *pending, int data_len, const void *data, void *user_data)
{
	dbg("Entry");
	
	UserRequest *ur;
	struct tresp_sms_set_params respSetParams = {0,};
	const TcoreATResponse *atResp = data;
	int err = 0, response = 0, sw1 =0 , sw2 = 0;
	const char *line = NULL;
	char *pResp = NULL;
	GSList *tokens=NULL;
	

	memset(&respSetParams, 0, sizeof(struct tresp_sms_set_params));
	ur = tcore_pending_ref_user_request(pending);
		
	if(atResp->success > 0)
	{
		dbg("RESPONSE OK");

		if(atResp->lines) 
		{
			line = (const char*)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL)
			{
				sw1 = atoi(pResp);
			}
			else
			{
				respSetParams.result = SMS_DEVICE_FAILURE;
				dbg("sw1 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL)
			{
				sw2 = atoi(pResp);
				if ((sw1 == 144) && (sw2 == 0))
				{
					respSetParams.result = SMS_SENDSMS_SUCCESS;
				}
				else
				{
					//TODO Error Mapping
					respSetParams.result = SMS_DEVICE_FAILURE;
				}
			}
			else
			{
				dbg("sw2 is NULL");
				respSetParams.result = SMS_DEVICE_FAILURE;
				
			}
			pResp = g_slist_nth_data(tokens, 3);
			if (pResp != NULL)
			{
				response = pResp;
				dbg("response is %s", response);
			}
			
		}
	}
	else
	{
		dbg("RESPONSE NOK");
		respSetParams.result = SMS_DEVICE_FAILURE;
	}	

	tcore_user_request_send_response(ur, TRESP_SMS_SET_PARAMS , sizeof(struct tresp_sms_set_params), &respSetParams);

	dbg("Exit");
	return;
}

static void on_response_get_paramcnt(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	UserRequest *ur = NULL;
	struct tresp_sms_get_paramcnt respGetParamCnt = {0,};
	const TcoreATResponse *atResp = data;
	dbg("Entry");
	char *line = NULL , *pResp = NULL;
	int ret = 0;
	int sw1 = 0 , sw2 = 0;
	int sim_type = SIM_TYPE_USIM; //TODO need to check how to handle this
	GSList *tokens=NULL;

	ur = tcore_pending_ref_user_request(p);

	if(atResp->success > 0)
	{
		dbg("RESPONSE OK");

		if(atResp->lines) 
		{
			line = (const char*)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			pResp = g_slist_nth_data(tokens, 0);
			if (pResp != NULL)
			{
				sw1 = atoi(pResp);
			}
			else
			{
				respGetParamCnt.result = SMS_DEVICE_FAILURE;
				dbg("sw1 is NULL");
			}
			pResp = g_slist_nth_data(tokens, 1);
			if (pResp != NULL)
			{
				sw2 = atoi(pResp);
				if ((sw1 == 144) && (sw2 == 0))
				{
					respGetParamCnt.result = SMS_SENDSMS_SUCCESS;
				}
				else
				{
					//TODO Error Mapping
					respGetParamCnt.result = SMS_DEVICE_FAILURE;
				}
			}
			else
			{
				dbg("sw2 is NULL");
				respGetParamCnt.result = SMS_DEVICE_FAILURE;
				
			}
			pResp = g_slist_nth_data(tokens, 3);
			if (pResp != NULL)
			{
				char *hexData;	
				char *recordData;
				
				hexData  = pResp;
				if (pResp)
				dbg("response is %s", pResp);
				
				/*1. SIM access success case*/
				if ((sw1 == 0x90 && sw2 == 0x00) || sw1 == 0x91) 
				{
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

					recordData = util_hexStringToBytes(hexData);
					util_hex_dump("    ", strlen(hexData)/2, recordData);
		
					ptr_data = (unsigned char *)recordData;

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
								SMS_SWAPBYTES16(record_len);
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
								SMS_SWAPBYTES16(record_len);
								ptr_data = ptr_data + 2;
								num_of_records = *ptr_data++;
								file_type = 0x04;	//SIM_FTYPE_CYCLIC
								break;

						default:
							dbg("not handled file type [0x%x]", *ptr_data);
							break;
						}
					}
					else 
					{
						dbg("INVALID FCP received - DEbug!");
						return;
					}

					/*File identifier - file id?? */ // 0x84,0x85,0x86 etc are currently ignored and not handled
					if (*ptr_data == 0x83) {
						/* increment to next byte */
						ptr_data++;
						file_id_len = *ptr_data++;
						memcpy(&file_id, ptr_data, file_id_len);
						/* swap bytes	 */
						SMS_SWAPBYTES16(file_id);
						ptr_data = ptr_data + 2;
						dbg("Getting FileID=[0x%x]", file_id);
					} else {
						dbg("INVALID FCP received - DEbug!");
						free(recordData);
						//ReleaseResponse();						
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
								dbg("<IPC_RX> operation state -deactivated");
								ptr_data++;
								break;
							case 0x05:
							case 0x07:
								dbg("<IPC_RX> operation state -activated");
								ptr_data++;
								break;
							default:
								dbg("<IPC_RX> DEBUG! LIFE CYCLE STATUS =[0x%x]",*ptr_data);
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
							SMS_SWAPBYTES16(arr_file_id);
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
						SMS_SWAPBYTES16(file_size);
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
			}
			else if (sim_type == SIM_TYPE_GSM) 
			{
				unsigned char gsm_specific_file_data_len = 0;
				/*	ignore RFU byte1 and byte2 */
				ptr_data++;
				ptr_data++;
				/*	file size */
				//file_size = p_info->response_len;
				memcpy(&file_size, ptr_data, 2);
				/* swap bytes */
				SMS_SWAPBYTES16(file_size);
				/*	parsed file size */
				ptr_data = ptr_data + 2;
				/*  file id  */
				memcpy(&file_id, ptr_data, 2);
				SMS_SWAPBYTES16(file_id);
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
			} 
			else 
			{
				dbg(" Card Type - UNKNOWN  [%d]", sim_type);
			}

			dbg("EF[0x%x] size[%ld] Type[0x%x] NumOfRecords[%ld] RecordLen[%ld]", file_id, file_size, file_type, num_of_records, record_len);

			respGetParamCnt.recordCount = num_of_records;
			respGetParamCnt.result = SMS_SUCCESS;
			
			free(recordData);
		}
		else 
		{
			/*2. SIM access fail case*/
			dbg("SIM access fail");
			respGetParamCnt.result = SMS_UNKNOWN;
		}
		}
			
		}
	}
	else
	{
		dbg("RESPONSE NOK");
		respGetParamCnt.result = SMS_DEVICE_FAILURE;
	}

	
	tcore_user_request_send_response(ur, TRESP_SMS_GET_PARAMCNT, sizeof(struct tresp_sms_get_paramcnt), &respGetParamCnt);

	dbg("Exit");
	return;
}
/********************************************************/
/******************** Str Utility Functions *******************/






/********************************************************/
/***********************  Requests ************************/
/********************************************************/
static TReturn send_umts_msg(CoreObject *obj, UserRequest *ur)
{
	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	char *cmd_str = NULL;
	
	TcorePending *pending = NULL;
	const struct treq_sms_send_umts_msg *sendUmtsMsg = NULL;
	GQueue *queue = NULL;

	Storage *strg = NULL;
	int mode = 0x00;
	Server *s = NULL;

	unsigned char optMask = 0;
	TReturn api_err = TCORE_RETURN_SUCCESS;

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	dbg("new pending(TIZEN_SMS_SEND_MSG)");
	sendUmtsMsg = tcore_user_request_ref_data(ur, NULL);
	
	// AT command to select MoreMessagesToSend. In the response, actual send AT cmd will be sent
	cmd_str = g_strdup_printf("AT+CMMS=%d\r", sendUmtsMsg->more);
	atreq = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);

	tcore_pending_set_request_data(pending,0,atreq);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_send_umts_msg, hal);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);


	tcore_hal_send_request(hal, pending);
	return TCORE_RETURN_SUCCESS;
}


static TReturn Send_SmsSubmitTpdu(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_send_umts_msg *sendUmtsMsg = NULL;
	
	char *cmd_str = NULL;
	char tpdu[2*MAX_GSM_SMS_TPDU_SIZE];
	int ScLength = 0;
	int tpduDataLen = 0;
	int i = 0;

	TcoreATRequest *atreq = NULL;
	TReturn api_err = TCORE_RETURN_SUCCESS;

	sendUmtsMsg = tcore_user_request_ref_data(ur, NULL);

  	h = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	if (!sendUmtsMsg || !h)
		return TCORE_RETURN_ENOSYS;

	/* Populate data */
	dbg("[tcore_SMS] MoreToSend[0x%x](1:Persist, 2:NotPersist) MsgLen[%d]",sendUmtsMsg->more, sendUmtsMsg->msgDataPackage.msgLength);
	for(i=0; i<sendUmtsMsg->msgDataPackage.msgLength; i++)
		dbg("[%02x]", sendUmtsMsg->msgDataPackage.tpduData[i]);

	ScLength = sendUmtsMsg->msgDataPackage.sca[0];

	if ((sendUmtsMsg->msgDataPackage.msgLength > 0)
		&& (SMS_SMDATA_SIZE_MAX > sendUmtsMsg->msgDataPackage.msgLength)
		&& (ScLength <= SMS_MAX_SMS_SERVICE_CENTER_ADDR))
	{
			memset(tpdu, 0, sizeof(2*MAX_GSM_SMS_TPDU_SIZE));
		
			if(ScLength == 0) /* ScAddress not specified */
			{
				tpduDataLen = 2;
				tpdu[0] = '0';
				tpdu[1] = '0';
			}
			else
			{
			#ifndef TAPI_CODE_SUBJECT_TO_CHANGE
				dbg("SC length in Tx is %d - before", ScLength);

				util_sms_get_length_of_sca(&ScLength);

				dbg(" SC length in Tx is %d - after", ScLength);

				tpdu[0] = ScLength + 1;
				memcpy(&(tpdu[1]), &(sendUmtsMsg->msgDataPackage.sca[1]), (ScLength + 1));

				tpduDataLen = 2 + ScLength;
			#else
				dbg("Specifying SCA in TPDU is currently not supported");

				tpduDataLen = 2;
				tpdu[0] = '0';
				tpdu[1] = '0';
			#endif
			}

			for(i=0; i<(sendUmtsMsg->msgDataPackage.msgLength*2); i+=2) 
			{
				char value = 0;

				value = (sendUmtsMsg->msgDataPackage.tpduData[i/2] & 0xf0 ) >> 4;
				if(value < 0xA)
					tpdu[i+tpduDataLen] = ((sendUmtsMsg->msgDataPackage.tpduData[i/2] & 0xf0 ) >> 4) + '0';
				else tpdu[i+tpduDataLen] = ((sendUmtsMsg->msgDataPackage.tpduData[i/2] & 0xf0 ) >> 4) + 'A' -10;

				value = sendUmtsMsg->msgDataPackage.tpduData[i/2] & 0x0f;
				if(value < 0xA)
					tpdu[i+1+tpduDataLen] = (sendUmtsMsg->msgDataPackage.tpduData[i/2] & 0x0f ) + '0';
				else tpdu[i+1+tpduDataLen] = (sendUmtsMsg->msgDataPackage.tpduData[i/2] & 0x0f ) + 'A' -10;

			}

			tpduDataLen = tpduDataLen + 2*sendUmtsMsg->msgDataPackage.msgLength;
			
			/* AT+CMGS=<length><CR>PDU is given<ctrl-Z/ESC> */
			cmd_str = g_strdup_printf("AT+CMGS=%d%s%s\x1A%s", sendUmtsMsg->msgDataPackage.msgLength, "\r", tpdu, "\r");
			dbg("cmd_str is %p", cmd_str);
			dbg("tpdu %s", tpdu);
			for(i=0; i<strlen(cmd_str); i++)
				dbg("cmd_str data: [%x]", cmd_str[i]);

			dbg("TPDU data_len: %d", tpduDataLen);
			
			for(i=0; i<tpduDataLen; i++)
				dbg("[%02x]", tpdu[i]);
			
			atreq = tcore_at_request_new(cmd_str, "+CMGS:", TCORE_AT_SINGLELINE);

			tcore_pending_set_request_data(pending, 0, atreq);
			tcore_pending_set_response_callback(pending, on_response_send_smsSubmitTpdu, NULL);
			tcore_pending_link_user_request(pending, ur);

			tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
			
			api_err = tcore_hal_send_request(h, pending);	
			
	}
	else
	{
		dbg("[tcore_SMS] Invalid Data Length");
		api_err = TCORE_RETURN_SMS_INVALID_DATA_LEN;
	}
	
	return api_err;

}

static TReturn read_msg(CoreObject *obj, UserRequest *ur)
{
	TcorePlugin *plugin = NULL;
	TcoreATRequest *atreq = NULL;
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_read_msg *readMsg = NULL;
	const char * cmd_str = NULL;

	dbg("new pending(TIZEN_SMS_READ_MSG)");

	readMsg = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!readMsg || !hal)
		return TCORE_RETURN_ENOSYS;

	cmd_str = g_strdup_printf("AT+CMGR=%d\r", (readMsg->index + 1)); /* IMC index is one ahead of Samsung */
		
	dbg("cmd str is %s",cmd_str);

	atreq = tcore_at_request_new((const char *)cmd_str, "\e+CMGR:", TCORE_AT_SINGLELINE);

	g_free(cmd_str);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_read_msg, &(readMsg->index)); //storing index as user data
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	return tcore_hal_send_request(hal, pending);

}

static TReturn save_msg(CoreObject *obj, UserRequest *ur)
{	

	TcorePlugin *plugin = NULL;
	TcoreATRequest *atreq = NULL;
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_save_msg *saveMsg = NULL;
	const char *cmd_str = NULL;
	char pdu[MAX_GSM_SMS_TPDU_SIZE]; /* SCA + PDU */

	TReturn api_err = TCORE_RETURN_SUCCESS;
	int ScLength = 0, pduLength = 0, stat = 0;

	dbg("new pending(TIZEN_SMS_SAVE_MSG)");

	saveMsg = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!saveMsg ||  !hal)
		return TCORE_RETURN_ENOSYS;

	dbg("Index value %x is not ensured. CP will allocate index automatically", saveMsg->simIndex);
	dbg("msgStatus: %x", saveMsg->msgStatus);

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
			api_err = TCORE_RETURN_EINVAL;
			
			dbg("Exiting with api_err: %x", api_err);
			return api_err;
	}

	if ((saveMsg->msgDataPackage.msgLength > 0) && (SMS_SMDATA_SIZE_MAX > saveMsg->msgDataPackage.msgLength)) {

		/* Initialize PDU */
		memset(pdu, 0x00, MAX_GSM_SMS_TPDU_SIZE);
		
		ScLength = saveMsg->msgDataPackage.sca[0];

		if(ScLength == 0) {
			dbg("ScLength is zero");
			pduLength = 1;
		}
		else {
			dbg("ScLength (Useful semi-octets) %d", ScLength);

			util_sms_get_length_of_sca(&ScLength); /* Convert useful semi-octets to useful octets */

			dbg("ScLength (Useful octets) %d", ScLength);

			pdu[0] = ScLength + 1; /* ScLength */
			memcpy(&(pdu[1]), &(saveMsg->msgDataPackage.sca[1]), ScLength+1); /* ScType + ScAddress */

			pduLength = 2 + ScLength;
		}

		/* SMS PDU */
		memcpy(&(pdu[pduLength]), saveMsg->msgDataPackage.tpduData, saveMsg->msgDataPackage.msgLength);

		pduLength = pduLength + saveMsg->msgDataPackage.msgLength;

		dbg("pduLength: %d", pduLength);

		{
			int i;
			for(i=0; i<pduLength; i++)
				dbg("SMS-PDU: [%x]", pdu[i]);
		}

		/* +CMGW=<length>[,<stat>]<CR>PDU is given<ctrl-Z/ESC> */
		cmd_str = g_strdup_printf("AT+CMGW=%d,%d%s%s%x%s", pduLength, stat, "\r", pdu, 0x1A, "\r");

		g_printf("cmd_str: %s", cmd_str);
		
		atreq = tcore_at_request_new((const char *)cmd_str, "+CMGW", TCORE_AT_SINGLELINE);

		g_free(cmd_str);
	
		tcore_pending_set_request_data(pending, 0, atreq);
		tcore_pending_set_response_callback(pending, on_response_sms_save_msg_cnf, NULL);
		tcore_pending_link_user_request(pending, ur);
		tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

		api_err = tcore_hal_send_request(hal, pending);
	}
	else {
		dbg("Invalid Data Length for SaveMessage");
		api_err = TCORE_RETURN_SMS_INVALID_DATA_LEN;
	}

	dbg("Exiting with api_err: %x", api_err);
	return api_err;

}

static TReturn delete_msg(CoreObject *obj, UserRequest *ur)
{

	TcorePlugin *plugin= NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_delete_msg *deleteMsg = NULL;
	GQueue *queue = NULL;
	const char * cmd_str = NULL;
	int index = 0;

	dbg("new pending(TIZEN_SMS_DEL_MSG)");

	deleteMsg = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!deleteMsg || !hal)
		return TCORE_RETURN_ENOSYS;

	index = deleteMsg->index;
	
	cmd_str =g_strdup_printf("AT+CMGD=%d,0\r",deleteMsg->index);
	atreq = tcore_at_request_new((const char*)cmd_str, NULL, TCORE_AT_NO_RESULT);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_sms_delete_msg_cnf, (void *)&index);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);

	return tcore_hal_send_request(hal, pending);



}

static TReturn get_storedMsgCnt(CoreObject *obj, UserRequest *ur)
{
	TReturn ret_code = TCORE_RETURN_UNKNOWN;

	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *atreq = NULL;
	
	const struct treq_sms_get_msg_count *getStoredMsgCnt = NULL;
	const char *cmd_str = NULL;

	dbg("new pending(TIZEN_SMS_GET_STORED_MSG_COUNT)");

	getStoredMsgCnt = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	cmd_str = g_strdup_printf("AT+CPMS=\"SM\",\"SM\",\"SM\"%c", CR);
	atreq = tcore_at_request_new((const char *)cmd_str, "+CPMS", TCORE_AT_SINGLELINE);

	/* NULL checkpoint */
	if (!hal || !pending || !cmd_str || !atreq)
	{
		err("Pointer is NULL. hal:[%p], pending:[%p], cmd_str:[%p], atreq:[%p]", hal, pending, cmd_str, atreq);

		if(pending)
		{
			dbg("Freeing pending");
			free(pending);
		}
		if(cmd_str)
		{
			dbg("Freeing cmd_str");
			g_free(cmd_str);
		}
		if(atreq)
		{
			dbg("Freeing atreq");
			free(atreq);
		}

		ret_code = TCORE_RETURN_FAILURE;
		dbg("Exiting Function with ret_code: [%x]", ret_code);
		return ret_code;
	}

	if(cmd_str) /* Already copied in AT-Request */
	{
		dbg("Freeing cmd_str");
		g_free(cmd_str);
	}
	
	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_storedMsgCnt, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	ret_code = tcore_hal_send_request(hal, pending);
	
	dbg("Exiting Function with ret_code: [%x]", ret_code);
	return ret_code;
}

static TReturn get_sca(CoreObject *obj, UserRequest *ur)
{

	//TODO - Need to make this a blocking call??
	
	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *atreq = NULL;
	struct tresp_sms_get_sca *respGetSca;
	const char * cmd_str = NULL;

	dbg("new pending(TIZEN_SMS_GET_SCA)");

	//index is not supported as input param for GetSCA AT command.Hence ignoring
	respGetSca = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!respGetSca || !hal)
		return TCORE_RETURN_ENOSYS;

	cmd_str = g_strdup_printf("AT+CSCA?\r");;
	atreq = tcore_at_request_new((const char*)cmd_str, "+CSCA", TCORE_AT_SINGLELINE);

	tcore_pending_set_request_data(pending, 0,atreq);
	tcore_pending_set_response_callback(pending, on_response_get_sca, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);


	return tcore_hal_send_request(hal, pending);

}

static TReturn set_sca(CoreObject *object, UserRequest *ur)
{

	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *atreq = NULL;

	const struct treq_sms_set_sca *setSca = NULL;
	char* cmd_str = NULL;
	int addrType = 0;
	

	dbg("new pending(TIZEN_SMS_SET_SCA)");

	setSca = tcore_user_request_ref_data(ur, NULL);

	if(setSca->index != 0){
		dbg("Index except 0 is supported");
		return TCORE_RETURN_EINVAL;	// TAPI_API_NOT_SUPPORTED;
	}

	hal = tcore_object_get_hal(object);
	pending = tcore_pending_new(object, 0);
	
	if (!setSca || !hal)
		return TCORE_RETURN_ENOSYS;

	addrType = ((setSca->scaInfo.typeOfNum << 4) | setSca->scaInfo.numPlanId) | 0x80;

	//TODO Need to clarify about dialing NumLen
	cmd_str = g_strdup_printf("AT+CSCA=%s,%d", setSca->scaInfo.diallingNum, addrType);
	atreq = tcore_at_request_new((const char*)cmd_str, NULL, TCORE_AT_NO_RESULT);
	
	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_set_sca, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);


	return tcore_hal_send_request(hal, pending);


}

static TReturn get_cb_config(CoreObject *obj, UserRequest *ur)
{
	//Format of AT command is 	AT+CSCB?
	//Possible response is +CSCB : <mode>,<mids>,<dcss>
	//OK

	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	
	TcoreATRequest *atreq;
	TcorePending *pending = NULL;
	
	const struct treq_sms_get_cb_config *getCbConfig = NULL;

	dbg("new pending(TIZEN_SMS_GET_CBS_CFG)");

	getCbConfig = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!hal) // request data is NULL, so do not NULL check for getCbConfig
	{
		dbg("[ERR]  pointer is NULL, getCbConfig=0x%x, h=0x%x", getCbConfig, hal);
		return TCORE_RETURN_ENOSYS;
	}

	atreq = tcore_at_request_new("AT+CSCB?", "+CSCB", TCORE_AT_SINGLELINE);
	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_cb_config, NULL);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	tcore_pending_link_user_request(pending, ur);

	return tcore_hal_send_request(hal, pending);

}

static TReturn set_cb_config(CoreObject *obj, UserRequest *ur)
{
	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;

	const struct treq_sms_set_cb_config *setCbConfig = NULL;
	char *cmd_str = NULL;
	gchar *mids_str = NULL;
	GString *mids_GString = NULL;
	int err = 0, response = 0, ctr = 0;

	dbg("new pending(TIZEN_SMS_SET_CBS_CFG)");

	setCbConfig = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	
	if (!setCbConfig || !hal)
		return TCORE_RETURN_ENOSYS;

	if (setCbConfig->bCBEnabled == FALSE) /* AT+CSCB=0: Disable CBS */
	{
		cmd_str = g_strdup_printf("AT+CSCB=0\r");
	}
	else
	{
		if(setCbConfig->selectedId == SMS_CBMI_SELECTED_SOME) /* AT+CSCB=0,<mids>,<dcss>: Enable CBS for specified <mids> and <dcss> */
		{
			dbg("Enabling specified CBMIs");
			mids_GString = g_string_new(g_strdup_printf("%d", setCbConfig->msgIDs[0]));
			
			for(ctr=1; ctr <setCbConfig->msgIdCount; ctr++)
			{
				mids_GString = g_string_append(mids_GString, ",");
				mids_GString = g_string_append(mids_GString, g_strdup_printf("%d", setCbConfig->msgIDs[ctr]));
			}

			mids_str = g_string_free(mids_GString, FALSE);
			//cmd_str = g_strdup_printf("AT+CSCB=0,\"%s\"\r", mids_str);

			//Temporary work around to test from UI. Enabling all - To be removed later
			cmd_str = g_strdup_printf("AT+CSCB=1\r");
			g_free(mids_str);
		}
		else if (setCbConfig->selectedId == SMS_CBMI_SELECTED_ALL) /* AT+CSCB=1: Enable CBS for all <mids> and <dcss> */
		{
			dbg("Enabling all CBMIs");
			cmd_str = g_strdup_printf("AT+CSCB=1\r");
		}
	}
	
	dbg("cmd_str: %s", cmd_str);
	
	atreq = tcore_at_request_new((const char *)cmd_str, NULL, TCORE_AT_NO_RESULT);

	g_free(cmd_str);
	
	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_set_cb_config, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	
	tcore_hal_send_request(hal, pending);

	return TCORE_RETURN_SUCCESS;
	
}

static TReturn set_mem_status(CoreObject *obj, UserRequest *ur)
{

	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq;
	TcorePending *pending = NULL;

	const struct treq_sms_set_mem_status *setMemStatus = NULL;
	char* cmd_str = NULL;
	int memoryStatus = 0;

	dbg("new pending(TIZEN_SMS_SET_MEM_STATUS)");

	setMemStatus = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);


	if (!setMemStatus || !hal)
		return TCORE_RETURN_ENOSYS;

	if(setMemStatus->memory_status < SMS_PDA_MEMORY_STATUS_AVAILABLE ||
		setMemStatus->memory_status > SMS_PDA_MEMORY_STATUS_FULL)
		return TCORE_RETURN_EINVAL;

	switch (setMemStatus->memory_status)
	{
		case SMS_PDA_MEMORY_STATUS_AVAILABLE:
			memoryStatus = AT_MEMORY_AVAILABLE;
			break;
		case SMS_PDA_MEMORY_STATUS_FULL:
			memoryStatus = AT_MEMORY_FULL;
			break;
		default:
			memoryStatus = -1;
			break;
	}


	cmd_str = g_strdup_printf("AT+XTESM=%d",memoryStatus);
	atreq = tcore_at_request_new((const char *)cmd_str, NULL, TCORE_AT_NO_RESULT);

	dbg("cmd str is %s",cmd_str);
		

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_set_mem_status, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);


	return tcore_hal_send_request(hal, pending);
	
}

static TReturn get_pref_brearer(CoreObject *obj, UserRequest *ur)
{
	dbg("Entry");

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_pref_brearer(CoreObject *obj, UserRequest *ur)
{
	dbg("Entry");

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_delivery_report(CoreObject *obj, UserRequest *ur)
{
	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq;
	TcorePending *pending = NULL;
	const struct treq_sms_set_delivery_report *deliveryReport = NULL;
	struct property_sms_info *property = NULL;
	GQueue *queue = NULL;
	char pdu[MAX_GSM_SMS_TPDU_SIZE];

	TReturn api_err = TCORE_RETURN_SUCCESS;
	int scaLen = 0 , length = 0;
	unsigned short nRpCause = 0;
	char *cmd_str = NULL ;

       //Format  -	+CNMA[=<n>[,<length>[<CR>PDU is given<ctrl-Z/ESC>]]]
	dbg("new pending(IPC_SMS_SET_DELIVER_REPORT)");

	deliveryReport = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!deliveryReport || !hal)
		return TCORE_RETURN_ENOSYS;

	//pdu = (treq_sms_set_delivery_report *) calloc (1,sizeof(treq_sms_set_delivery_report));

	if ((deliveryReport->dataInfo.msgLength > 0) && (MAX_GSM_SMS_TPDU_SIZE > deliveryReport->dataInfo.msgLength)) 
	{
			//pending = tcore_pending_new(obj, 0);
			//atreq = tcore_at_request_new("AT+CNMA", NULL, TCORE_AT_NO_RESULT);

		scaLen = deliveryReport->dataInfo.sca[0];
		if(scaLen == 0){
			memcpy(pdu, deliveryReport->dataInfo.sca, scaLen+2);
		}
		else{
			scaLen = deliveryReport->dataInfo.sca[0];

			dbg(" SC length in tx is %d - before", scaLen);

			util_sms_get_length_of_sca(&scaLen);

			dbg(" SC length in tx is %d - after", scaLen);

			//1Copy SCA to the pdu stream first
			pdu[0] = scaLen + 1;
			memcpy(&(pdu[1]), &(deliveryReport->dataInfo.sca[1]), scaLen+1);
		}

		length = (deliveryReport->dataInfo.msgLength) + (scaLen + 2);

		nRpCause = (unsigned short) deliveryReport->rspType;

		dbg(" data len is %d",length);

		if ((deliveryReport->dataInfo.msgLength < SMS_SMDATA_SIZE_MAX)) {
			//2Copy rest of the SMS-DELIVER TPDU
			memcpy(&(pdu[scaLen + 2]), deliveryReport->dataInfo.tpduData,	deliveryReport->dataInfo.msgLength);
		} else {
			dbg(" SCA len is %d", scaLen);
			api_err = TCORE_RETURN_SMS_INVALID_DATA_LEN;
			return api_err;
		}


			if(deliveryReport->rspType == SMS_SENDSMS_SUCCESS)
			{
				//cmd_str = g_strdup_printf("AT+CNMA=1,%d\r%s\x1A\r", length,pdu);
				cmd_str = g_strdup_printf("AT+CNMA=1\r");
			}
			else
			{
				cmd_str = g_strdup_printf("AT+CNMA=2\r");
			}
	
			atreq = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);

			tcore_pending_set_request_data(pending, 0, atreq);
			tcore_pending_set_timeout(pending, 0);
			tcore_pending_set_response_callback(pending, on_response_sms_deliver_rpt_cnf, NULL);
			tcore_pending_link_user_request(pending, ur);

			return tcore_hal_send_request(hal, pending);

		}
	else {
		dbg(" Invalid Data Length for DeliverReportSet");
		api_err = TCORE_RETURN_SMS_INVALID_DATA_LEN;
	}

	return api_err;
}

static TReturn set_msg_status(CoreObject *obj, UserRequest *ur)
{
	dbg("Entry");

	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq;
	TcorePending *pending = NULL;
	const struct treq_sms_set_msg_status *msg_status = NULL;
	char *cmd_str = NULL, *encoded_data = NULL;	

	encoded_data = calloc(176,1);


	msg_status = tcore_user_request_ref_data(ur, NULL);

	dbg("msg status %d and index %d",msg_status->msgStatus, msg_status->index);

	switch (msg_status->msgStatus)
	{
		case SMS_STATUS_READ:
			encoded_data[0] = encoded_data[0] | 0x01;
			break;
		
		case SMS_STATUS_UNREAD:
			encoded_data[0] = encoded_data[0] | 0x03;
			break;

		case SMS_STATUS_UNSENT:
			encoded_data[0] = encoded_data[0] | 0x07;
			break;
	
		case SMS_STATUS_SENT:
			encoded_data[0] = encoded_data[0] | 0x05;
			break;

		case SMS_STATUS_DELIVERED:
			encoded_data[0] = encoded_data[0] | 0x1D;
			break;
		case SMS_STATUS_DELIVERY_UNCONFIRMED:
			encoded_data[0] = encoded_data[0] | 0xD;
			break;
		case SMS_STATUS_MESSAGE_REPLACED:
		case SMS_STATUS_RESERVED:
			encoded_data[0] = encoded_data[0] | 0x03;
			break;		
	}

	memset(&encoded_data[1] , 0xff, 175);
	

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!hal)
	{
		dbg("[ERR]  pointer is NULL, h=0x%x", hal);
		return TCORE_RETURN_ENOSYS;
	}

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3> TODO
	cmd_str = g_strdup_printf("AT+CRSM=220,0x6F3C,%d, 4, 176 %s\r", msg_status->index, encoded_data);
	dbg("cmd str is %s",cmd_str);

	atreq = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);
	
	tcore_pending_set_request_data(pending, 0,atreq);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_set_msg_status, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	
	tcore_hal_send_request(hal, pending);
	free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_sms_params(CoreObject *obj, UserRequest *ur)
{
	dbg("Entry");

	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_get_params *getSmsParams = NULL;
	char *cmd_str = NULL;
	
	getSmsParams = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!getSmsParams || !hal)
	{
		dbg("[ERR]  pointer is NULL, getSmsParams=0x%x, h=0x%x", getSmsParams, hal);
		return TCORE_RETURN_ENOSYS;
	}

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3> 
	
	//cmd_str = g_strdup_printf("AT+CRSM=%d,%x,%d,4 40%s", 178, 0x6F42, getSmsParams->index + 1, "\r");
	
	cmd_str = g_strdup_printf("AT+CRSM=178,0x6F42,%d,4,0\r",getSmsParams->index);

	
	atreq = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);
	dbg("cmd str is %s",cmd_str);
	
	tcore_pending_set_request_data(pending, 0,atreq);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_get_sms_params, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	 
	tcore_hal_send_request(hal, pending);
	free(cmd_str);
	

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn set_sms_params(CoreObject *obj, UserRequest *ur)
{
	dbg("Entry");
	
	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_set_params *setSmsParams = NULL;
	char *cmd_str = NULL, *encoded_data = NULL ,*temp_data = NULL;
	int len = 0, i = 0, iSize = sizeof(struct treq_sms_set_params);


	setSmsParams = tcore_user_request_ref_data(ur, NULL);
	
	temp_data = calloc(iSize,1);

	
	memcpy(temp_data,(void *)(setSmsParams+6), (iSize-6));	
	len = strlen(temp_data);

	//EFsmsp file size is 28 +Y bytes (Y is alpha id size)
        encoded_data = calloc((setSmsParams->params.alphaIdLen+28),1);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!setSmsParams || !hal)
	{
		dbg("[ERR]  pointer is NULL, setSmsParams=0x%x, h=0x%x", setSmsParams, hal);
		return TCORE_RETURN_ENOSYS;
	}

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3> 

	for(i=0; i<(len*2); i+=2)
        {
         	char value = 0;

                value = (temp_data[i/2] & 0xf0 ) >> 4;
                                if(value < 0xA)
                                        encoded_data[i+len] = ((temp_data[i/2] & 0xf0 ) >> 4) + '0';
                                else encoded_data[i+len] = ((temp_data[i/2] & 0xf0 ) >> 4) + 'A' -10;

                                value = temp_data[i/2] & 0x0f;
                                if(value < 0xA)
                                        encoded_data[i+1+len] = (temp_data[i/2] & 0x0f ) + '0';
                                else encoded_data[i+1+len] = (temp_data[i/2] & 0x0f ) + 'A' -10;

         }




	cmd_str = g_strdup_printf("AT+CRSM=220,0x6F42,%x,4,0,%x%x%x%x%x%x%x", 220, 0x6F42, setSmsParams->params.recordIndex, setSmsParams->params.szAlphaId,setSmsParams->params.paramIndicator,setSmsParams->params.tpDestAddr,setSmsParams->params.tpSvcCntrAddr,setSmsParams->params.tpProtocolId,setSmsParams->params.tpDataCodingScheme,setSmsParams->params.tpValidityPeriod, "\r"); 

	dbg("cmd str is %s",cmd_str);
	atreq = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);
	
	tcore_pending_set_request_data(pending, 0,atreq);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_set_sms_params, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	
	tcore_hal_send_request(hal, pending);
	free(cmd_str);

	

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}
static TReturn get_paramcnt(CoreObject *obj, UserRequest *ur)
{
	dbg("Entry");

	TcorePlugin *plugin = NULL;
	TcoreHal *hal = NULL;
	TcoreATRequest *atreq = NULL;
	TcorePending *pending = NULL;
	const struct treq_sms_get_paramcnt *getParamCnt = NULL;
	char *cmd_str = NULL;
	
	getParamCnt = tcore_user_request_ref_data(ur, NULL);

	hal = tcore_object_get_hal(obj);
	pending = tcore_pending_new(obj, 0);

	if (!hal)
	{
		dbg("[ERR]  pointer is NULL, h=0x%x", hal);
		return TCORE_RETURN_ENOSYS;
	}

	// AT+CRSM=<command>,<fildid>,<p1>,<p2+C29,<p3>, EFsmsp: 0x6F42 
	cmd_str = g_strdup_printf("AT+CRSM=192, %d%s", 0x6F42, "\r");

	atreq = tcore_at_request_new(cmd_str, "+CRSM:", TCORE_AT_SINGLELINE);
	dbg("cmd str is %s",cmd_str);

	
	tcore_pending_set_request_data(pending, 0,atreq);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_response_callback(pending, on_response_get_paramcnt, NULL);
	tcore_pending_link_user_request(pending, ur);

	tcore_pending_set_send_callback(pending, on_confirmation_sms_message_send, NULL);
	
	tcore_hal_send_request(hal, pending);
	free(cmd_str);

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_sms_operations sms_ops =
{
	//.send_umts_msg = send_umts_msg,	
	.send_umts_msg = Send_SmsSubmitTpdu,
	.read_msg = read_msg,
	.save_msg = save_msg,
	.delete_msg = delete_msg,
	.get_storedMsgCnt = get_storedMsgCnt,
	.get_sca = get_sca,
	.set_sca = set_sca,
	.get_cb_config = get_cb_config,
	.set_cb_config = set_cb_config,
	.set_mem_status = set_mem_status,
	.get_pref_brearer = get_pref_brearer,
	.set_pref_brearer = set_pref_brearer,
	.set_delivery_report = set_delivery_report,
	.set_msg_status = set_msg_status,
	.get_sms_params = get_sms_params,
	.set_sms_params = set_sms_params,
	.get_paramcnt = get_paramcnt,
	//.send_cdma_msg = send_cdma_msg,
};

gboolean s_sms_init(TcorePlugin *plugin,  TcoreHal *hal)
{
	CoreObject *obj = NULL;
	struct property_sms_info *data = NULL;
	GQueue *work_queue = NULL;
	dbg("Entry");
	
	obj = tcore_sms_new(plugin, "umts_sms", &sms_ops, hal);
	if (!obj) {
		return FALSE;
	}

	work_queue = g_queue_new();
	tcore_object_link_user_data(obj, work_queue);

	tcore_object_add_callback(obj, "\e+CMTI" , on_event_sms_incom_msg, NULL);
	tcore_object_add_callback(obj, "\e+CMT" , on_event_sms_incom_msg, NULL);

	tcore_object_add_callback(obj, "\e+CDS" , on_event_sms_incom_msg, NULL);
	tcore_object_add_callback(obj, "\e+CDSI" , on_event_sms_incom_msg, NULL);

	tcore_object_add_callback(obj, "+XTESM",  on_event_sms_memory_status, NULL);

	tcore_object_add_callback(obj, "\e+CBMI" , on_event_sms_cb_incom_msg, NULL); 	
	tcore_object_add_callback(obj, "\e+CBM" , on_event_sms_cb_incom_msg, NULL);
	tcore_object_add_callback(obj, "+XSIM", on_event_sms_ready_status, NULL);

	//tcore_at_add_notification(&coreAt, "+XSIMSTATE", 0 , on_event_sms_incom_msg, NULL);

	data = calloc(sizeof(struct property_sms_info), 1);
	tcore_plugin_link_property(plugin, "SMS", data);

	/* Make registration settings via AT commands necessary to recieve unsolicited noti */

	dbg("Exit");
	return TRUE;
}


void s_sms_exit(TcorePlugin *p)
{
	CoreObject *o;
	struct property_sms_info *data;
	dbg("Entry");

	o = tcore_plugin_ref_core_object(p, "umts_sms");
	if (!o) {
		return;
	}
	tcore_sms_free(o);

	data = tcore_plugin_ref_property(p, "SMS");
	if (data) {
		free(data);
	}

	dbg("Exit");
	return;
}

