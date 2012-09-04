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

/**
 * @open
 * @ingroup			TelephonyAPI
 * @addtogroup		COMMON_TAPI	COMMON
 * @{
 *	These error codes are used by Applications.
 */


#ifndef _TEL_ERR_H_
#define _TEL_ERR_H_
/*==================================================================================================
                                         INCLUDE FILES
==================================================================================================*/

#ifdef __cplusplus
extern "C"
{
#endif

/*==================================================================================================
                                           CONSTANTS
==================================================================================================*/


/*==================================================================================================
                                            MACROS
==================================================================================================*/


/*==================================================================================================
                                             ENUMS
==================================================================================================*/

/************************************************************
**    Errors defined in  "+CME ERROR" ,
**    - see 3GPP TS 27.007
**    - ranges are 0x00 ~ 0x7FFF
************************************************************/
/**
    Error codes sent by the modem in response to the above operations.
*/
typedef enum {
	/* GENERAL ERRORS */
	TAPI_OP_GEN_ERR_PHONE_FAILURE = 0,                      /* 0 */
	TAPI_OP_GEN_ERR_NO_CONNECTION_TO_PHONE,                 /* 1 */
	TAPI_OP_GEN_ERR_PHONE_ADAPTOR_LINK_RESERVED,            /* 2 */
	TAPI_OP_GEN_ERR_OPER_NOT_ALLOWED,                       /* 3 */
	TAPI_OP_GEN_ERR_OPER_NOT_SUPPORTED,                     /* 4 */
	TAPI_OP_GEN_ERR_PH_SIM_PIN_REQU,                        /* 5 */
	TAPI_OP_GEN_ERR_PH_FSIM_PIN_REQU,                       /* 6 */
	TAPI_OP_GEN_ERR_PH_FSIM_PUK_REQU,                       /* 7 */
	TAPI_OP_GEN_ERR_SIM_NOT_INSERTED = 10,                  /* 10 */
	TAPI_OP_GEN_ERR_SIM_PIN_REQU,                           /* 11 */
	TAPI_OP_GEN_ERR_SIM_PUK_REQU,                           /* 12 */
	TAPI_OP_GEN_ERR_SIM_FAILURE,                            /* 13 */
	TAPI_OP_GEN_ERR_SIM_BUSY,                               /* 14 */
	TAPI_OP_GEN_ERR_SIM_WRONG,                              /* 15 */
	TAPI_OP_GEN_ERR_INCORRECT_PW,                           /* 16 */
	TAPI_OP_GEN_ERR_SIM_PIN2_REQU,                          /* 17 */
	TAPI_OP_GEN_ERR_SIM_PUK2_REQU,                          /* 18 */
	TAPI_OP_GEN_ERR_MEM_FULL = 20,                          /* 20 */
	TAPI_OP_GEN_ERR_INVALID_INDEX,                          /* 21 */
	TAPI_OP_GEN_ERR_NOT_FOUND,                              /* 22 */
	TAPI_OP_GEN_ERR_MEM_FAILURE,                            /* 23 */
	TAPI_OP_GEN_ERR_TEXT_STR_TOO_LONG,                      /* 24 */
	TAPI_OP_GEN_ERR_INVALID_CHARACTERS_IN_TEXT_STR,         /* 25 */
	TAPI_OP_GEN_ERR_DIAL_STR_TOO_LONG,                      /* 26 */
	TAPI_OP_GEN_ERR_INVALID_CHARACTERS_IN_DIAL_STR,         /* 27 */
	TAPI_OP_GEN_ERR_NO_NET_SVC = 30,                        /* 30 */
	TAPI_OP_GEN_ERR_NET_TIMEOUT,                            /* 31 */
	TAPI_OP_GEN_ERR_NET_NOT_ALLOWED_EMERGENCY_CALLS_ONLY,   /* 32 */
	TAPI_OP_GEN_ERR_NET_PERS_PIN_REQU = 40,                 /* 40 */
	TAPI_OP_GEN_ERR_NET_PERS_PUK_REQU,                      /* 41 */
	TAPI_OP_GEN_ERR_NET_SUBSET_PERS_PIN_REQU,               /* 42 */
	TAPI_OP_GEN_ERR_NET_SUBSET_PERS_PUK_REQU,               /* 43 */
	TAPI_OP_GEN_ERR_SVC_PROVIDER_PERS_PIN_REQU,             /* 44 */
	TAPI_OP_GEN_ERR_SVC_PROVIDER_PERS_PUK_REQU,             /* 45 */
	TAPI_OP_GEN_ERR_CORPORATE_PERS_PIN_REQU,                /* 46 */
	TAPI_OP_GEN_ERR_CORPORATE_PERS_PUK_REQU,                /* 47 */
	TAPI_OP_GEN_ERR_HIDDEN_KEY_REQU,                        /* 48 */
	TAPI_OP_GEN_ERR_UNKNOWN = 100,                          /* 100 */

	/* Errors related to a failure to perform an Attach */
	TAPI_OP_GEN_ERR_ILLEGAL_MS = 103,                       /* 103 */
	TAPI_OP_GEN_ERR_ILLEGAL_ME = 106,                       /* 106 */
	TAPI_OP_GEN_ERR_GPRS_SVC_NOT_ALLOWED,                   /* 107 */
	TAPI_OP_GEN_ERR_PLMN_NOT_ALLOWED = 111,                 /* 111 */
	TAPI_OP_GEN_ERR_LOCATION_AREA_NOT_ALLOWED,              /* 112 */
	TAPI_OP_GEN_ERR_ROAMING_NOT_ALLOWED_IN_THIS_LOCATION_AREA, /* 113 */

	/* Errors related to a failure to Activate a Context */
	TAPI_OP_GEN_ERR_SVC_OPT_NOT_SUPPORTED = 132,            /* 132 */
	TAPI_OP_GEN_ERR_REQ_SVC_OPT_NOT_SUBSCRIBED,             /* 133 */
	TAPI_OP_GEN_ERR_SVC_OPT_TEMPORARILY_OUT_OF_ORDER,       /* 134 */
	TAPI_OP_GEN_ERR_UNSPECIFIED_GPRS_ERR = 148,             /* 148 */
	TAPI_OP_GEN_ERR_PDP_AUTHENTICATION_FAILURE,             /* 149 */
	TAPI_OP_GEN_ERR_INVALID_MOBILE_CLASS,                   /* 150 */

	/* VBS / VGCS and eMLPP -related errors */
	TAPI_OP_GEN_ERR_VBS_VGCS_NOT_SUPPORTED_BY_THE_NET = 151, /* 151 */
	TAPI_OP_GEN_ERR_NO_SVC_SUBSCRIPTION_ON_SIM,             /* 152 */
	TAPI_OP_GEN_ERR_NO_SUBSCRIPTION_FOR_GROUP_ID,           /* 153 */
	TAPI_OP_GEN_ERR_GROUP_ID_NOT_ACTIVATED_ON_SIM,          /* 154 */
	TAPI_OP_GEN_ERR_NO_MATCHING_NOTI = 155,                 /* 155 */
	TAPI_OP_GEN_ERR_VBS_VGCS_CALL_ALREADY_PRESENT,          /* 156 */
	TAPI_OP_GEN_ERR_CONGESTION,                             /* 157 */
	TAPI_OP_GEN_ERR_NET_FAILURE,                            /* 158 */
	TAPI_OP_GEN_ERR_UPLINK_BUSY,                            /* 159 */
	TAPI_OP_GEN_ERR_NO_ACCESS_RIGHTS_FOR_SIM_FILE = 160,    /* 160 */
	TAPI_OP_GEN_ERR_NO_SUBSCRIPTION_FOR_PRIORITY,           /* 161 */
	TAPI_OP_GEN_ERR_OPER_NOT_APPLICABLE_OR_NOT_POSSIBLE,    /* 162 */


	/************************************************************
	**                           SAMSUNG ADDED ERRORS
	************************************************************/
	TAPI_OP_GEN_ERR_NONE = 0x8000,                          /* 0x8000 : No Errors */

	/* General Common Errors : 0x8000 - 0x80FF */
	TAPI_OP_GEN_ERR_INVALID_FORMAT,                         /* 0x8001 : Invalid Parameter or Format */
	TAPI_OP_GEN_ERR_PHONE_OFFLINE,                          /* 0x8002 : */
	TAPI_OP_GEN_ERR_CMD_NOT_ALLOWED,                        /* 0x8003 : */
	TAPI_OP_GEN_ERR_PHONE_IS_INUSE,                         /* 0x8004 : */
	TAPI_OP_GEN_ERR_INVALID_STATE = 0x8005,                 /* 0x8005 : */

	TAPI_OP_GEN_ERR_NO_BUFFER,                              /* 0x8006 :  No internal free buffers */
	TAPI_OP_GEN_ERR_OPER_REJ,                               /* 0x8007 :  Operation Rejected */
	TAPI_OP_GEN_ERR_INSUFFICIENT_RESOURCE,                  /* 0x8008 : insufficient resource */
	TAPI_OP_GEN_ERR_NET_NOT_RESPOND,                        /* 0x8009 : Network not responding */
	TAPI_OP_GEN_ERR_SIM_PIN_ENABLE_REQ = 0x800A,            /* 0x800A : SIM Pin Enable Required */
	TAPI_OP_GEN_ERR_SIM_PERM_BLOCKED,                       /* 0x800B : SIM Permanent Blocked */
	TAPI_OP_GEN_ERR_SIM_PHONEBOOK_RESTRICTED,               /*0x800C: SIM Phonebook Restricted*/
	TAPI_OP_GEM_ERR_FIXED_DIALING_NUMBER_ONLY,              /*0x800D: Restricted By FDN Mode */

	/* Reserved : 0x800E ~ 0x80FF */
	TAPI_OP_GEN_ERR_800E_RESERVED_START = 0x800E,           /* 0x800E */

	TAPI_OP_GEN_ERR_80FF_RESERVED_END = 0x80ff,             /* 0x80FF */

	/* the other errors */
	TAPI_OP_GEN_ERR_OTHERS = 0xFFFE,                        /* 0xFFFE */

	TAPI_OP_GEN_ERR_MAX = 0xFFFF
} tapi_phone_err_t;


/*==================================================================================================
                                 STRUCTURES AND OTHER TYPEDEFS
==================================================================================================*/


/*==================================================================================================
                                     FUNCTION PROTOTYPES
==================================================================================================*/


#ifdef __cplusplus
}
#endif

#endif // _TEL_ERR_H_

/**
* @}
*/
