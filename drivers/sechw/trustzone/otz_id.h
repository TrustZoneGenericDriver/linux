/*
 * OpenVirtualization:
 * For additional details and support contact developer@sierraware.com.
 * Additional documentation can be found at www.openvirtualization.org
 *
 * Copyright (C) 2011 SierraWare
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef __OTZ_ID_H_
#define __OTZ_ID_H_

#define SMC_ENOMEM          7
#define SMC_EOPNOTSUPP      6
#define SMC_EINVAL_ADDR     5
#define SMC_EINVAL_ARG      4
#define SMC_ERROR           3
#define SMC_INTERRUPTED     2
#define SMC_PENDING         1
#define SMC_SUCCESS         0

/**
 * @brief Encoding data type
 */
enum otz_enc_data_type {
	OTZ_ENC_INVALID_TYPE = 0,
	OTZ_ENC_UINT32,
	OTZ_ENC_ARRAY,
	OTZ_MEM_REF,
	OTZ_SECURE_MEM_REF
};

/**
 * @brief Service identifiers
 */
enum otz_svc_id {
	OTZ_SVC_INVALID = 0x0,
	OTZ_SVC_GLOBAL,
	OTZ_SVC_ECHO,
	OTZ_SVC_DRM,
	OTZ_SVC_CRYPT,
	OTZ_SVC_MUTEX_TEST,
	OTZ_SVC_VIRTUAL_KEYBOARD,
	OTZ_SVC_KERNEL_INTEGRITY_CHECK,
	OTZ_SVC_LINUX,
	OTZ_SVC_SHELL,
	OTZ_SVC_TEST_SUITE_KERNEL,
	OTZ_SVC_FFMPEG_TEST,
	OTZ_SVC_GP_INTERNAL,
	OTZ_SVC_TEST_SUITE_USER,
	OTZ_SVC_TEST_HEAP,
	OTZ_SVC_INT_CONTXT_SWITCH,
	OTZ_SVC_TEST_SHM,
	OTZ_SVC_TCXO
};

/**
 * @brief Command ID's for global service
 */
enum otz_global_cmd_id {
	OTZ_GLOBAL_CMD_ID_INVALID = 0x0,
	OTZ_GLOBAL_CMD_ID_BOOT_ACK,
	OTZ_GLOBAL_CMD_ID_OPEN_SESSION,
	OTZ_GLOBAL_CMD_ID_CLOSE_SESSION,
#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
	OTZ_GLOBAL_CMD_ID_REGISTER_NOTIFY_MEMORY,
	OTZ_GLOBAL_CMD_ID_UNREGISTER_NOTIFY_MEMORY,
#endif
	OTZ_GLOBAL_CMD_ID_RESUME_ASYNC_TASK,
	OTZ_GLOBAL_CMD_ID_UNKNOWN         = 0x7FFFFFFE,
	OTZ_GLOBAL_CMD_ID_MAX             = 0x7FFFFFFF
};

/**
 * @brief Enums used for crypto service task
 */
enum otz_crypt_cmd_id {
	OTZ_CRYPT_CMD_ID_INVALID = 0x0,
	OTZ_CRYPT_CMD_ID_LOAD_LIBS,
	OTZ_CRYPT_CMD_ID_UNLOAD_LIBS,
	OTZ_CRYPT_CMD_ID_ENCRYPT,
	OTZ_CRYPT_CMD_ID_DECRYPT,
	OTZ_CRYPT_CMD_ID_MD5,
	OTZ_CRYPT_CMD_ID_SHA1,
	OTZ_CRYPT_CMD_ID_SHA224,
	OTZ_CRYPT_CMD_ID_SHA256,
	OTZ_CRYPT_CMD_ID_SHA384,
	OTZ_CRYPT_CMD_ID_SHA512,
	OTZ_CRYPT_CMD_ID_HMAC_MD5,
	OTZ_CRYPT_CMD_ID_HMAC_SHA1,
	OTZ_CRYPT_CMD_ID_HMAC_SHA224,
	OTZ_CRYPT_CMD_ID_HMAC_SHA256,
	OTZ_CRYPT_CMD_ID_HMAC_SHA384,
	OTZ_CRYPT_CMD_ID_HMAC_SHA512,
	OTZ_CRYPT_CMD_ID_CIPHER_AES_128_CBC,
	OTZ_CRYPT_CMD_ID_CIPHER_AES_128_ECB,
	OTZ_CRYPT_CMD_ID_CIPHER_AES_128_CTR,
	OTZ_CRYPT_CMD_ID_CIPHER_AES_128_XTS,
	OTZ_CRYPT_CMD_ID_CIPHER_DES_ECB,
	OTZ_CRYPT_CMD_ID_CIPHER_DES_CBC,
	OTZ_CRYPT_CMD_ID_CIPHER_DES3_ECB,
	OTZ_CRYPT_CMD_ID_CIPHER_DES3_CBC,
	OTZ_CRYPT_CMD_ID_UNKNOWN = 0x7FFFFFFE,
	OTZ_CRYPT_CMD_ID_MAX = 0x7FFFFFFF
};

#define MD5_OUTPUT_LEN 16
#define SHA1_OUTPUT_LEN 20
#define SHA224_OUTPUT_LEN 28
#define SHA256_OUTPUT_LEN 32
#define SHA384_OUTPUT_LEN 48
#define SHA512_OUTPUT_LEN 64
#define HMAC_KEY_LEN 16
#define HMAC_DATA_LEN 50
#define HMAC_OUTPUT_LEN 16
#define AES_128_CBC_LEN 16
#define AES_128_ECB_LEN 16
#define AES_128_CTR_LEN 16
#define AES_128_XTS_LEN 16
#define DES_ECB_LEN 8
#define DES_CBC_LEN 8
#define DES3_CBC_LEN 8
#define DES3_ECB_LEN 8
#define CIPHER_ENCRYPT 2
#define CIPHER_DECRYPT 1
#define IGNORE_PARAM  0xff


/**
 * @brief Enums used for mutex test task
 *
 **/
enum open_tz_mutex_test_cmd_id {
	OTZ_MUTEX_TEST_CMD_ID_INVALID = 0x0,
	OTZ_MUTEX_TEST_CMD_ID_TEST,
	OTZ_MUTEX_TEST_CMD_ID_UNKNOWN = 0x7FFFFFFE,
	OTZ_MUTEX_TEST_CMD_ID_MAX = 0x7FFFFFFF
};


/**
 * @brief Enums used for echo service task
 */
enum otz_echo_cmd_id {
	OTZ_ECHO_CMD_ID_INVALID = 0x0,
	OTZ_ECHO_CMD_ID_SEND_CMD,
	OTZ_ECHO_CMD_ID_SEND_CMD_SHARED_BUF,
	OTZ_ECHO_CMD_ID_SEND_CMD_ARRAY_SPACE,
	OTZ_ECHO_CMD_ID_IPI_SEND_CMD,
#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
	OTZ_ECHO_CMD_ID_TEST_ASYNC_SEND_CMD,
#endif
	OTZ_ECHO_CMD_ID_UNKNOWN         = 0x7FFFFFFE,
	OTZ_ECHO_CMD_ID_MAX             = 0x7FFFFFFF
};

/**
 * @brief
 */
enum otz_virtual_keyboard_cmd_id {
	OTZ_VIRTUAL_KEYBOARD_CMD_ID_INVALID = 0x0,
	OTZ_VIRTUAL_KEYBOARD_CMD_ID_SHOW
};

/**
 * @brief Enums used for ffmpeg test task
 *
 **/
enum otz_ffmpeg_test_cmd_id {
	OTZ_FFMPEG_TEST_CMD_ID_INVALID = 0x0,
	OTZ_FFMPEG_TEST_CMD
};

enum otz_kernel_check_cmd_id {
	OTZ_KERNEL_IM_INVALID = 0x0,
	OTZ_KERNEL_IM

};

/**
 * @brief
 */
enum otz_drm_cmd_id {
	OTZ_DRM_CMD_ID_INVALID = 0x0,
	OTZ_DRM_CMD_ID_SEND_CMD,
	OTZ_DRM_CMD_ID_SEND_CMD_SHARED_BUF
};

/**
 * @brief Enums used for gp internal api test task
 */
enum otz_gp_internal_cmd_id {
	OTZ_GP_INTERNAL_CMD_ID_INVALID = 0x0,
	OTZ_GP_INTERNAL_CMD_ID_ARITHMATIC_API,
	OTZ_GP_INTERNAL_CMD_ID_STORAGE_API
};

/**
 * @brief Enums used for TCXO task
 */
enum otz_tcxo_cmd_id {
	OTZ_TCXO_CMD_ID_INVALID = 0x0,
	OTZ_TCXO_CMD_ID_COMMAND1,
	OTZ_TCXO_REQ_NEW_TS,
	OTZ_TCXO_REQ_CONTINUE_TS,
	OTZ_TCXO_REQ_NEW_CON,
	OTZ_TCXO_SEND_METADATA,
	OTZ_TCXO_INITIALIZE_METADATA,
	OTZ_TCXO_SEND_PAGE_TABLE,
	OTZ_TCXO_INITIALIZE_PAGE_TABLE,
	OTZ_TCXO_ENC_DATA_CHUNK,
	OTZ_TCXO_CLOSE_SESSION,
	OTZ_TCXO_TEST_DECRYPT,
	OTZ_TCXO_TEST_CMD,
};

/**
 * @brief Enums used for test suite
 */
enum otz_test_suite_kernel_cmd_id {
	OTZ_TEST_SUITE_CMD_ID_INVALID = 0x0,
	OTZ_TEST_SUITE_CMD_ID_ASYNC
};

enum otz_test_suite_user_cmd_id {
	OTZ_TEST_SUITE_USER_CMD_ID_INVALID = 0x0,
	OTZ_TEST_SUITE_CMD_ID_SHM,
	OTZ_TEST_SUITE_CMD_ID_MUTEX
};


#endif /* __OPEN_OTZ_ID_H_ */
