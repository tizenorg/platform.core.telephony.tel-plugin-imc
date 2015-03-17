/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Paresh Agarwal<paresh.agwl@samsung.com>
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

#ifndef __NVM_H__
#define __NVM_H__

/* Priority level for suspension of all updates */
#define UTA_FLASH_PLUGIN_PRIO_SUSPEND_ALL		4294967295 /* 0xFFFFFFFF */

/* Priority level for suspension of High priority updates */
#define UTA_FLASH_PLUGIN_PRIO_SUSPEND_HIGH		3221225472 /* 0xFFFFFFFF */

/* Priority level for suspension of all updates of dynamic data */
#define UTA_FLASH_PLUGIN_PRIO_SUSPEND_ALL_DYN	1610612735 /* 0x5FFFFFFF */

/* Priority level for suspension of Medium all updates */
#define UTA_FLASH_PLUGIN_PRIO_SUSPEND_MEDIUM	2147483648 /* 0x5FFFFFFF */

/* Priority level for suspension of Low updates of Medium */
#define UTA_FLASH_PLUGIN_PRIO_SUSPEND_LOW		1073741824 /* 0x5FFFFFFF */

/* Priority level for unsuspension of all updates */
#define UTA_FLASH_PLUGIN_PRIO_UNSUSPEND_ALL		0 /* 0x0 */

#define NVM_FUNCTION_ID_OFFSET		20
#define XDRV_INDICATION				0x04

#define XDRV_DISABLE					"0"
#define XDRV_ENABLE						"1"
#define XDRV_UNSUSPEND					"0"

/* Identifies our group with the xdrv AT command set */
#define IUFP_GROUP						"43"
#define IUFP_GROUP_ID					43

#define IUFP_REGISTER					0
#define IUFP_REGISTER_STR				"0"

#define IUFP_SUSPEND					1
#define IUFP_SUSPEND_STR				"1"

#define IUFP_FLUSH						2
#define IUFP_FLUSH_STR					"2"

#define IUFP_UPDATE_REQ				3
#define IUFP_UPDATE_REQ_STR			"3"

#define IUFP_UPDATE_REQ_ACK			3
#define IUFP_UPDATE_REQ_ACK_STR		"3"

#define IUFP_UPDATE						4
#define IUFP_UPDATE_STR				"4"

#define IUFP_UPDATE_ACK				4
#define IUFP_UPDATE_ACK_STR			"4"

#define IUFP_NO_PENDING_UPDATE		5
#define IUFP_NO_PENDING_UPDATE_STR	"5"

/*  XDRV command was executed without any error */
#define XDRV_RESULT_OK					0

typedef enum uta_common_return_codes {
	UTA_SUCCESS = 0,
	UTA_FAILURE = -1,
	UTA_ERROR_OUT_OF_MEMORY = -2,
	UTA_ERROR_INVALID_HANDLE = -3,
	UTA_ERROR_OUT_OF_RANGE_PARAM = -4,
	UTA_ERROR_INVALID_PARAM = -5,
	UTA_ERROR_TOO_SMALL_BUF_PARAM = -6,
	UTA_ERROR_NOT_SUPPORTED = -7,
	UTA_ERROR_TIMEOUT = -8,
	UTA_ERROR_WRONG_STATE = -9,
	UTA_ERROR_BAD_FORMAT = -10,
	UTA_ERROR_INSUFFICIENT_PERMISSIONS = -11,
	UTA_ERROR_IO_ERROR = -12,
	UTA_ERROR_OUT_OF_HANDLES = -13,
	UTA_ERROR_OPERATION_PENDING = -14,
	UTA_ERROR_SPECIFIC = -100
} nvm_return_codes;

typedef enum nvm_error_numbers {
	NVM_NO_ERR = 0,
	NVM_CMD_ERR,
	NVM_DATA_ERR,
	NVM_MEM_FULL_ERR,
	NVM_RES_ERR,
	NVM_WRITE_ERR,
	NVM_READ_ERR,
	NVM_RES_LEN_ERR,
	NVM_PCKT_ERR,
	NVM_REG_FAIL_ERR,
	NVM_DATA_LEN_ERR,
	NVM_FILE_ERR,
	NVM_AT_PORT_ERR,
	NVM_READ_AT_ERR,
	NVM_DATA_PORT_ERR,
	NVM_NO_PENDING_UPDATE,
	NVM_UPDATE,
	NVM_REGISTER_ERR,
	NVM_UNKNOWN_ERR
} nvm_error;

int nvm_sum_4_bytes(const char *pos);
gboolean nvm_create_nvm_data();
nvm_error nvm_process_nv_update(const char *data);

#endif	/* __NVM_H__ */
