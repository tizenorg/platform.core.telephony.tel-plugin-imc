/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Paresh Agarwal <paresh.agwl@samsung.com>
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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>

#include <sys/stat.h>
#include <tcore.h>
#include "nvm/nvm.h"

/* NVM file type */
#define NVM_TYPE_CALIB				0
#define NVM_TYPE_STATIC			1
#define NVM_TYPE_DYNAMIC			2
#define NVM_FILE_TYPE_POS			36

/* NVM Payload information */
#define NVM_PAYLOAD_OFFSET_0		48
#define NVM_PAYLOAD_LENGTH_0		52
#define NVM_PAYLOAD_OFFSET_1		64
#define NVM_PAYLOAD_LENGTH_1		68
#define NVM_DATA_LEN_POS			80

/* Image Path information */
#define MODEM_IMAGE_PATH				"/boot/modem.bin"
#define NVM_DIR_PATH 					"/csa/nv"
#define NV_FILE_PATH NVM_DIR_PATH 		"/nvdata.bin"

/* NV offsets and size */
#define MODEM_NV_OFFSET 				0xA00000
#define MAX_NVDATA_SIZE 				0x200000
#define NVM_CALIB_OFFSET				0x80000
#define NVM_STATIC_OFFSET				0x100000

struct nvm_payload_info {
	unsigned long m_offset_0;
	unsigned long m_length_0;
	unsigned long m_offset_1;
	unsigned long m_length_1;
};

static nvm_error __nvm_file_write(int nvm_type, const char *update_buf, int update_len, int offset)
{
	int nv_fd;
	nvm_error ret_val = NVM_NO_ERR;
	int ret;

	char err_str[256] = {0, };
	errno = 0;
	dbg("Entered");

	if (NULL == update_buf) {
		err("Buffer is invalid!!!");
		return NVM_WRITE_ERR;
	}

	switch (nvm_type) {
	case NVM_TYPE_CALIB:
		msg("		[NVM File] calib.nvm");
		offset = offset + NVM_CALIB_OFFSET;
		break;

	case NVM_TYPE_STATIC:
		msg("		[NVM File] static.nvm");
		offset = offset + NVM_STATIC_OFFSET;
		break;

	case NVM_TYPE_DYNAMIC:
		msg("		[NVM File] dynamic.nvm");
		break;

	default:
		err("[NVM File] Wrong NVM file type: [%d]", nvm_type);
		return NVM_FILE_ERR;
	}

	/* Open NVM file for Write operation */
	nv_fd = open(NV_FILE_PATH, O_RDWR);
	if (nv_fd < 0) {
		strerror_r(errno, err_str, 255);
		err("[OPEN] Failed: [%s]", err_str);
		return NVM_READ_ERR;
	}

	/* Seek the offset */
	ret = lseek(nv_fd, (long)offset, SEEK_SET);
	if (ret < 0) {
		strerror_r(errno, err_str, 255);
		err("[SEEK] Failed: [%s]", err_str);
		ret_val = NVM_RES_LEN_ERR;
	} else {
		dbg("Buffer: [0x%x] length: [%d]", update_buf, update_len);

		/* Write the buffer to file */
		ret = write(nv_fd, update_buf, update_len);
		if (ret > 0) {
			dbg("[WRITE] Successfully updated NVM data");
		} else if (ret == 0) {
			strerror_r(errno, err_str, 255);
			dbg("[WRITE] Nothing is written: [%s]", err_str);
		} else {
			strerror_r(errno, err_str, 255);
			err("[WRITE] Failed: [%s]", err_str);
			ret_val = NVM_MEM_FULL_ERR;
		}
	}

	/* Close 'fd' */
	close(nv_fd);

	return ret_val;
}

static nvm_error __nvm_write_payload_1(int nvm_type,
						const char *p_bin_buff, struct nvm_payload_info *nvm1)
{
	const char *p_buf_ptr = p_bin_buff;

	/* Write to file */
	return __nvm_file_write(nvm_type,
					(p_buf_ptr + NVM_DATA_LEN_POS + nvm1->m_length_0),
					nvm1->m_length_1,
					nvm1->m_offset_1);
}

static nvm_error __nvm_write_payload_0(int nvm_type,
						const char *p_bin_buff, struct nvm_payload_info *nvm)
{
	nvm_error ret_val;

	/* Write to file */
	ret_val = __nvm_file_write(nvm_type,
					(p_bin_buff + NVM_DATA_LEN_POS),
					nvm->m_length_0,
					nvm->m_offset_0);
	if (NVM_NO_ERR == ret_val) {
		/* The payload_0 has been done, so calls this method to write payload_1 to file */
		ret_val = __nvm_write_payload_1(nvm_type, p_bin_buff, nvm);
	} else {
		err("Failed to write to NV data file!!!");
	}

	return ret_val;
}

int nvm_sum_4_bytes(const char *pos)
{
	int sum = 0;
	sum = sum | (*(pos+3)) << 24;
	sum = sum | (*(pos+2)) << 16;
	sum = sum | (*(pos+1)) << 8;
	sum = sum | *pos;
	return sum;
}

nvm_error nvm_process_nv_update(const char *data)
{
	struct nvm_payload_info nvm_info;
	int nvm_type;
	nvm_error ret_val;
	dbg("Entered");

	memset(&nvm_info, 0x0, sizeof(struct nvm_payload_info));

	/* Determine lengths from the little-endian 4 bytes */
	nvm_info.m_length_0 = nvm_sum_4_bytes(&data[NVM_PAYLOAD_LENGTH_0]);
	nvm_info.m_offset_0 = nvm_sum_4_bytes(&data[NVM_PAYLOAD_OFFSET_0]);
	nvm_info.m_length_1 = nvm_sum_4_bytes(&data[NVM_PAYLOAD_LENGTH_1]);
	nvm_info.m_offset_1 = nvm_sum_4_bytes(&data[NVM_PAYLOAD_OFFSET_1]);
	dbg("Offsets - 0th: [%d] 1st: [%d]", nvm_info.m_offset_0, nvm_info.m_offset_1);

	nvm_type = *(data + NVM_FILE_TYPE_POS);
	if ((NVM_TYPE_CALIB <= nvm_type)
			&& (NVM_TYPE_DYNAMIC >= nvm_type)) {
		dbg("NVM type: [%d]", nvm_type);

		/* Write NVM data to file */
		ret_val = __nvm_write_payload_0(nvm_type, data, &nvm_info);
	} else {
		err("Wrong NVM file type: [%d]", nvm_type);
		ret_val = NVM_RES_ERR;
	}

	return ret_val;
}

gboolean nvm_create_nvm_data()
{
	int modem_fd;
	int nv_fd;
	char *buffer = NULL;
	char err_str[256] = {0, };

	gboolean ret_val = FALSE;
	dbg("Entered");

	/* Open modem binary */
	modem_fd = open(MODEM_IMAGE_PATH, O_RDONLY | O_NDELAY);
	if (modem_fd < 0) {
		strerror_r(errno, err_str, 255);
		err("[OPEN] Failed for (%s): [%s]", MODEM_IMAGE_PATH, err_str);
		return ret_val;
	}

	/* Create NV data folder if it doesn't exist */
	if (mkdir(NVM_DIR_PATH, 0755) < 0) {
		if (errno != EEXIST) {
			strerror_r(errno, err_str, 255);
			err("mkdir() failed: [%s]", err_str);

			/* Close 'modem_fd' */
			close(modem_fd);
			return ret_val;
		} else if (open(NV_FILE_PATH, O_EXCL) > 0) {
			/* NV data file already exists */
			dbg("File exists: [%s]", NV_FILE_PATH);

			/* Close 'modem_fd' */
			close(modem_fd);
			return TRUE;
		} else {
			dbg("File does't exsits... need to create!!!");
		}
	}

	/* Change directory permissions */
	if (chmod(NVM_DIR_PATH, 0755) < 0) {
		strerror_r(errno, err_str, 255);
		err("chmod() failed: [%s]", err_str);

		/* Close 'modem_fd' */
		close(modem_fd);
		return ret_val;
	}

	/* Open NV data file for different file operations */
	nv_fd = open(NV_FILE_PATH, O_RDWR | O_CREAT | O_SYNC, S_IRWXU);
	if (nv_fd < 0) {
		strerror_r(errno, err_str, 255);
		err("[OPEN] Failed for (%s): %s", NV_FILE_PATH, err_str);

		/* Close 'modem_fd' */
		close(modem_fd);
		return ret_val;
	}

	dbg("Setting the file descriptor offset to NV data in modem.bin");
	do {
		/* Seek pre-defined offset in modem binary */
		if (lseek(modem_fd, MODEM_NV_OFFSET, SEEK_SET) < 0) {
			strerror_r(errno, err_str, 255);
			err("[SEEK] Failed: [%s]", err_str);
			break;
		}

		/* Allocate memory */
		buffer = g_try_malloc0(MAX_NVDATA_SIZE);
		if (NULL == buffer) {
			err("Failed to allocate memory");
			break;
		}

		/* Read NV data from modem binary */
		if (read(modem_fd, buffer, MAX_NVDATA_SIZE) < 0) {
			strerror_r(errno, err_str, 255);
			err("[READ] Failed: [%s]", err_str);
			break;
	 	}

		/* Write the data read from modem binary to nvdata */
		if (write(nv_fd, buffer, MAX_NVDATA_SIZE) < 0) {
			strerror_r(errno, err_str, 255);
			err("[WRITE} Failed: [%s]", err_str);
			break;
		}

		ret_val = TRUE;
	} while (0);

	if (ret_val == FALSE) {
		err("nvdata (%s) creation Failed!!!", NV_FILE_PATH);
	} else {
		dbg("nvdata (%s) created Success", NV_FILE_PATH);
	}

	/* Close 'fds' */
	close(modem_fd);
	close(nv_fd);

	/* Free 'buffer' */
	g_free(buffer);

	return ret_val;
}
