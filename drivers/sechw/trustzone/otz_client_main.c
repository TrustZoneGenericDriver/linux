/*
 * OpenVirtualization:
 * For additional details and support contact developer@sierraware.com.
 * Additional documentation can be found at www.openvirtualization.org
 *
 * Copyright (C) 2011 SierraWare
 * Copyright (C) 2014 Javier González
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

/* Sierraware Trustzone API interface driver. */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/platform_device.h>
#include <linux/debugfs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <asm/cacheflush.h>
#include <linux/mm.h>
#ifdef CONFIG_KIM
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include "md5.h"
#endif
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/trustzone.h>
#include "trustzone.h"
#include "otz_client.h"
#include "otz_api.h"
#include "otz_common.h"
#include "otz_id.h"
#include "smc_id.h"
#include "sw_config.h"


#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
#include <linux/smp.h>
#endif

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define OTZ_MEM_SERVICE_RW (0x2)

#ifdef CONFIG_KIM
#define KERN_TEXT_START 0xc0030000
#define KERN_TEXT_SIZE 0x3361f0
#define KERN_TEXT_END (KERN_TEXT_START + KERN_TEXT_SIZE - 1)

typedef struct file_struct {
	char		hash[33];
	int		file_reported;
	char		fullpath[256];
	/*
	dev_t		dev;
	ino_t		ino;
	mode_t		mode;
	nlink_t		hardlinks;
	uid_t		owner;
	gid_t		group;
	dev_t		rdev;
	off_t		size;
	unsigned long	blksize;
	unsigned long	blocks;
	struct timespec	atime;
	struct timespec	mtime;
	struct timespec	ctime;*/
} file_type;
#endif

static struct class *driver_class;
static dev_t otz_client_device_no;
static struct cdev otz_client_cdev;
static u32 cacheline_size;
static u32 device_file_cnt;
#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
static struct otzc_notify_data *notify_data;
static int current_guest_id;
#endif
static struct otz_smc_cdata otz_smc_cd[NR_CPUS];
static const char *otz_service_errorlist[] = {
	"Service Success",
	"Service Pending",
	"Service Interrupted",
	"Service Error",
	"Service - Invalid Argument",
	"Service - Invalid Address",
	"Service No Support",
	"Service No Memory",
};

static char *otz_strerror(int index)
{
	return (char *)otz_service_errorlist[index];
}

static DEFINE_MUTEX(in_lock);
static DEFINE_MUTEX(send_cmd_lock);
static DEFINE_MUTEX(smc_lock);
static DEFINE_MUTEX(encode_cmd_lock);
static DEFINE_MUTEX(im_check_lock);
static DEFINE_MUTEX(decode_cmd_lock);
static DEFINE_MUTEX(ses_open_lock);
static DEFINE_MUTEX(ses_close_lock);
static DEFINE_MUTEX(mem_free_lock);
static DEFINE_MUTEX(mem_alloc_lock);

static struct otz_dev_file_head {
	u32 dev_file_cnt;
	struct list_head dev_file_list;
} otzc_dev_file_head;

struct otz_shared_mem_head {
	int shared_mem_cnt;
	struct list_head shared_mem_list;
};

struct otz_dev_file {
	struct list_head head;
	u32 dev_file_id;
	u32 service_cnt;
	struct list_head services_list;
	struct otz_shared_mem_head dev_shared_mem_head;
};

struct otz_service {
	struct list_head head;
	u32 service_id;
	struct list_head sessions_list;
};

struct otz_session {
	struct list_head head;
	int session_id;
	struct list_head encode_list;
	struct list_head shared_mem_list;
};

struct otz_wait_data {
	wait_queue_head_t send_cmd_wq;
	int send_wait_flag;
};

struct otz_encode {
	struct list_head head;
	int encode_id;
	void *ker_req_data_addr;
	void *ker_res_data_addr;
	u32  enc_req_offset;
	u32  enc_res_offset;
	u32  enc_req_pos;
	u32  enc_res_pos;
	u32  dec_res_pos;
	u32  dec_offset;
	struct otz_wait_data wait_data;
	struct otzc_encode_meta *meta;
};

struct otz_shared_mem {
	struct list_head head;
	struct list_head s_head;
	void *index;
	void *k_addr;
	void *u_addr;
	u32  len;
};

static int otz_client_prepare_encode(void *private_data,
		struct otz_client_encode_cmd *enc,
		struct otz_encode **penc_context,
		struct otz_session **psession);

static u32 _otz_smc(u32 cmd_addr)
{
	register u32 r0 asm("r0") = CALL_TRUSTZONE_API;
	register u32 r1 asm("r1") = cmd_addr;
	register u32 r2 asm("r2") = OTZ_CMD_TYPE_NS_TO_SECURE;

	do {
		asm volatile(
#if USE_ARCH_EXTENSION_SEC
				".arch_extension sec\n\t"
#endif
				__asmeq("%0", "r0")
				__asmeq("%1", "r0")
				__asmeq("%2", "r1")
				__asmeq("%3", "r2")
				"smc    #0  @ switch to secure world\n"
				: "=r" (r0)
				: "r" (r0), "r" (r1), "r" (r2));
	} while (0);
	return r0;
}

static void secondary_otz_smc_handler(void *info)
{
	struct otz_smc_cdata *cd = (struct otz_smc_cdata *)info;

	rmb();
	pr_debug("secondary otz smc handler");
	cd->ret_val = _otz_smc(cd->cmd_addr);
	wmb();
	pr_debug("done smc on primary");
}

/**
 * This function takes care of posting the smc to the primary core
 */
static u32 post_otz_smc(int cpu_id, u32 cmd_addr)
{
	struct otz_smc_cdata *cd = &otz_smc_cd[cpu_id];

	pr_debug("post from secondary");
	cd->cmd_addr = cmd_addr;
	cd->ret_val  = 0;
	wmb();
	smp_call_function_single(0, secondary_otz_smc_handler, (void *)cd, 1);
	rmb();
	pr_debug("completed smc on secondary");
	return cd->ret_val;
}

/**
 * Wrapper to handle the multi core case
 */
static u32 otz_smc(u32 cmd_addr)
{
	int cpu_id = smp_processor_id();

	if (cpu_id != 0) {
		mb();
		return post_otz_smc(cpu_id, cmd_addr); /* post it to primary */
	} else
		return _otz_smc(cmd_addr); /* called directly on primary core */
}

/**
 * @brief Call SMC
 *
 * When the processor executes the Secure Monitor Call (SMC),
 * the core enters Secure Monitor mode to execute the Secure Monitor code
 *
 * @param svc_id  - service identifier
 * @param cmd_id  - command identifier
 * @param context - session context
 * @param enc_id - encoder identifier
 * @param cmd_buf - command buffer
 * @param cmd_len - command buffer length
 * @param resp_buf - response buffer
 * @param resp_len - response buffer length
 * @param meta_data
 * @param ret_resp_len
 *
 * @return
 */
static int otz_smc_call(u32 dev_file_id, u32 svc_id, u32 cmd_id,
		u32 context, u32 enc_id, const void *cmd_buf,
		size_t cmd_len, void *resp_buf, size_t resp_len,
		const void *meta_data, int *ret_resp_len,
		struct otz_wait_data *wq, void *arg_lock)
{
	int ret;
	u32 smc_cmd_phys;
	static struct otz_smc_cmd *smc_cmd;

	smc_cmd = kmalloc(sizeof(struct otz_smc_cmd),
			GFP_KERNEL);
	if (!smc_cmd) {
		pr_err("kmalloc failed for smc command\n");
		ret = -ENOMEM;
		goto out;
	}
	pr_debug("Allocate smc_cmd: %dB\n", sizeof(smc_cmd));

	if (ret_resp_len)
		*ret_resp_len = 0;

	smc_cmd->src_id = (svc_id << 10) | cmd_id;
	smc_cmd->src_context = task_tgid_vnr(current);
	smc_cmd->id = (svc_id << 10) | cmd_id;
	smc_cmd->context = context;
	smc_cmd->enc_id = enc_id;
	smc_cmd->dev_file_id = dev_file_id;
	smc_cmd->req_buf_len = cmd_len;
	smc_cmd->resp_buf_len = resp_len;
	smc_cmd->ret_resp_buf_len = 0;

	if (cmd_buf)
		smc_cmd->req_buf_phys = virt_to_phys((void *)cmd_buf);
	else
		smc_cmd->req_buf_phys = 0;

	if (resp_buf)
		smc_cmd->resp_buf_phys = virt_to_phys((void *)resp_buf);
	else
		smc_cmd->resp_buf_phys = 0;

	if (meta_data)
		smc_cmd->meta_data_phys = virt_to_phys(meta_data);
	else
		smc_cmd->meta_data_phys = 0;

	smc_cmd_phys = virt_to_phys((void *)smc_cmd);
	mutex_lock(&smc_lock);
	ret = otz_smc(smc_cmd_phys);
	mutex_unlock(&smc_lock);

#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
	if (ret == SMC_PENDING) {
		if (arg_lock)
			mutex_unlock(arg_lock);

		if (wq) {
			if (wait_event_interruptible(wq->send_cmd_wq,
						wq->send_wait_flag)) {
				ret = -ERESTARTSYS;
				goto out;
			}
			wq->send_wait_flag = 0;
		}

		if (arg_lock)
			mutex_lock(arg_lock);

		svc_id = OTZ_SVC_GLOBAL;
		cmd_id = OTZ_GLOBAL_CMD_ID_RESUME_ASYNC_TASK;
		smc_cmd->src_id = (svc_id << 10) | cmd_id;
		smc_cmd->id = (svc_id << 10) | cmd_id;
		mutex_lock(&smc_lock);
		ret = otz_smc(smc_cmd_phys);
		mutex_unlock(&smc_lock);
	}
#endif

	if (ret) {
		pr_err("smc_call returns error");
		goto out;
	}

	if (ret_resp_len)
		*ret_resp_len = smc_cmd->ret_resp_buf_len;

out:
	if (smc_cmd) {
		pr_debug("Freeing smc_cmd: %dB", sizeof(smc_cmd));
		kfree(smc_cmd);
	}
	return ret;
}

#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
static void ipi_secure_notify(struct pt_regs *regs)
{
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	struct otz_encode *enc_temp;

	int enc_found = 0;

	if (!notify_data)
		return;

	if (notify_data->guest_no != current_guest_id) {
		pr_err("Invalid notification from guest id %d",
				notify_data->guest_no);
	}
	pr_debug("guest id %d", notify_data->guest_no);
	pr_debug("otz_client pid 0x%x", notify_data->client_pid);
	pr_debug("otz_client_notify_handler service id 0x%x \
			session id 0x%x and encoder id 0x%x",
			notify_data->service_id, notify_data->session_id,
			notify_data->enc_id);

	/* TODO: This needs to be refactored */
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == notify_data->dev_file_id) {
			pr_debug("dev file id %d", temp_dev_file->dev_file_id);
			list_for_each_entry(temp_svc,
					&temp_dev_file->services_list, head){
				if (temp_svc->service_id == notify_data->service_id) {
					pr_debug("send cmd ser id %d", temp_svc->service_id);
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id == notify_data->session_id) {
							pr_debug("send cmd ses id %d",
									temp_ses->session_id);
							list_for_each_entry(enc_temp, &temp_ses->encode_list,
									head) {
								if (enc_temp->encode_id == notify_data->enc_id) {
									pr_debug("send cmd enc id 0x%x",
											enc_temp->encode_id);
									enc_found = 1;
									break;
								}
							}
						}
						break;
					}
					break;
				}
			}
			break;
		}
	}

	if (enc_found) {
		if (!enc_temp->wait_data.send_wait_flag) {
			enc_temp->wait_data.send_wait_flag = 1;
			wake_up_interruptible(&enc_temp->wait_data.send_cmd_wq);
		}
	}

	return;
}
#endif

/**
 * @brief
 *
 * Clears session id and closes the session
 *
 * @param private_data
 * @param temp_svc
 * @param temp_ses
 *
 */
static void otz_client_close_session_for_service(
		u32 dev_file_id,
		struct otz_service *temp_svc,
		struct otz_session *temp_ses)
{
	struct otz_encode *temp_encode, *enc_context;
	struct otz_shared_mem *shared_mem, *temp_shared;

	if (!temp_svc || !temp_ses)
		return;

	pr_debug("freeing ses_id %d", temp_ses->session_id);
	otz_smc_call(dev_file_id, OTZ_SVC_GLOBAL,
			OTZ_GLOBAL_CMD_ID_CLOSE_SESSION, 0, 0,
			&temp_svc->service_id,
			sizeof(temp_svc->service_id), &temp_ses->session_id,
			sizeof(temp_ses->session_id), NULL, NULL, NULL, NULL);

	list_del(&temp_ses->head);

	if (!list_empty(&temp_ses->encode_list)) {
		list_for_each_entry_safe(enc_context, temp_encode,
				&temp_ses->encode_list, head) {
			list_del(&enc_context->head);
			if (enc_context->meta != NULL) {
				pr_debug("Freeing enc_context->meta: %dB",
						sizeof(enc_context->meta));
				kfree(enc_context->meta);
			}
			pr_debug("Freeing enc_context: %dB",
					sizeof(enc_context));
			kfree(enc_context);
		}
	}

	if (!list_empty(&temp_ses->shared_mem_list)) {
		list_for_each_entry_safe(shared_mem, temp_shared,
				&temp_ses->shared_mem_list, s_head) {
			list_del(&shared_mem->s_head);

			if (shared_mem->k_addr)
				free_pages((u32)shared_mem->k_addr,
					get_order(ROUND_UP(shared_mem->len,
					SZ_4K)));
			pr_debug("Freeing shared_mem%dB", sizeof(shared_mem));
			kfree(shared_mem);
		}
	}

	pr_debug("Freeing temp_ses%dB", sizeof(temp_ses));
	kfree(temp_ses);
}

static int otz_client_service_init(struct otz_dev_file *dev_file,
		int service_id)
{
	int ret_code = 0;
	struct otz_service *svc_new;
	struct otz_service *temp_pos;

	svc_new = kmalloc(sizeof(struct otz_service),
			GFP_KERNEL);
	if (!svc_new) {
		pr_err("kmalloc failed");
		ret_code = -ENOMEM;
		goto clean_prev_malloc;
	}

	pr_debug("Allocate svc_new: %dB", sizeof(svc_new));
	svc_new->service_id = service_id;
	dev_file->service_cnt++;
	INIT_LIST_HEAD(&svc_new->sessions_list);
	list_add(&svc_new->head, &dev_file->services_list);
	goto return_func;

clean_prev_malloc:
	if (!list_empty(&dev_file->services_list)) {
		list_for_each_entry_safe(svc_new, temp_pos,
				&dev_file->services_list, head) {
			list_del(&svc_new->head);
			pr_debug("Freeing svc_new: %dB", sizeof(svc_new));
			kfree(svc_new);
		}
	}

return_func:
	return ret_code;
}

static int otz_client_service_exit(u32 dev_file_id)
{
	struct otz_shared_mem *temp_shared_mem;
	struct otz_shared_mem  *temp_pos;
	struct otz_dev_file *tem_dev_file, *tem_dev_file_pos;
	struct otz_session *temp_ses, *temp_ses_pos;
	struct otz_service *tmp_svc = NULL, *tmp_pos;

	/*TODO: This needs to be refactored*/
	list_for_each_entry_safe(tem_dev_file, tem_dev_file_pos,
			&otzc_dev_file_head.dev_file_list, head) {
		if (tem_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry_safe(temp_shared_mem, temp_pos,
					&tem_dev_file->dev_shared_mem_head.shared_mem_list, head){
				list_del(&temp_shared_mem->head);
				if (temp_shared_mem->k_addr)
					free_pages((u32)temp_shared_mem->k_addr,
							get_order(ROUND_UP(temp_shared_mem->len, SZ_4K)));
				if (temp_shared_mem) {
					pr_debug("Freeing temp_shared_mem: %dB", sizeof(temp_shared_mem));
					kfree(temp_shared_mem);
				}
			}

			if (!list_empty(&tem_dev_file->services_list)) {
				list_for_each_entry_safe(tmp_svc, tmp_pos,
						&tem_dev_file->services_list, head) {
					list_for_each_entry_safe(temp_ses, temp_ses_pos,
							&tmp_svc->sessions_list, head) {
						otz_client_close_session_for_service(dev_file_id,
								tmp_svc, temp_ses);
					}
					list_del(&tmp_svc->head);
					pr_debug("Freeing tmp_svc: %dB", sizeof(tmp_svc));
					kfree(tmp_svc);
				}
			}

			list_del(&tem_dev_file->head);
			pr_debug("Freeing temp_dev_file: %dB", sizeof(tmp_svc));
			kfree(tem_dev_file);
			break;
		}
	}

	return OTZ_SUCCESS;
}

static int __otz_client_session_open(u32 device_id, struct ser_ses_id *ses_open,
		struct otz_session *ret_new_ses)
{
	struct otz_service *svc;
	struct otz_dev_file *temp_dev_file;
	struct otz_session *ses_new;
	int svc_found = 0;
	int ret_val = 0, ret_resp_len;
	u32 dev_file_id = (u32)device_id;

	pr_debug("service_id = %d", ses_open->service_id);
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(svc, &temp_dev_file->services_list,
					head){
				if (svc->service_id == ses_open->service_id) {
					svc_found = 1;
					break;
				}
			}
			break;
		}
	}

	if (!svc_found) {
		ret_val = -EINVAL;
		goto ret_error;
	}

	ses_new = kmalloc(sizeof(struct otz_session),
			GFP_KERNEL);
	if (!ses_new) {
		pr_err("kmalloc failed\n");
		ret_val =  -ENOMEM;
		goto ret_error;
	}

	pr_debug("service id 0x%x\n", ses_open->service_id);
	ret_val = otz_smc_call(dev_file_id, OTZ_SVC_GLOBAL,
			OTZ_GLOBAL_CMD_ID_OPEN_SESSION, 0, 0,
			&ses_open->service_id, sizeof(ses_open->service_id),
			&ses_new->session_id, sizeof(ses_new->session_id), NULL,
			&ret_resp_len, NULL, NULL);

	if (ret_val != SMC_SUCCESS) {
		pr_debug("Freeing ses_new: %dB", sizeof(ses_new));
		kfree(ses_new);
		goto ret_error;
	}

	if (ses_new->session_id == -1) {
		pr_err("invalid session id\n");
		ret_val =  -EINVAL;
		pr_debug("Freeing ses_new: %dB", sizeof(ses_new));
		kfree(ses_new);
		goto ret_error;
	}

	pr_debug("session id 0x%x for service id 0x%x", ses_new->session_id,
			ses_open->service_id);

	ses_open->session_id = ses_new->session_id;
	INIT_LIST_HEAD(&ses_new->encode_list);
	INIT_LIST_HEAD(&ses_new->shared_mem_list);
	list_add_tail(&ses_new->head, &svc->sessions_list);
	ret_new_ses = ses_new;

	return ret_val;

ret_error:
	ret_new_ses = NULL;
	return ret_val;
}

static int check_encode(struct otz_operation_t *ps_operation)
{
	if (!ps_operation)
		return -1;

	if (ps_operation->ui_state != OTZ_STATE_ENCODE) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ILLEGAL_STATE;
		return -1;
	}

	if (ps_operation->enc_dec.enc_error_state != OTZ_SUCCESS)
		return -1;

	return 0;
}

static int check_decode(struct otz_operation_t *ps_operation)
{
	if (!ps_operation)
		return -1;

	if (ps_operation->ui_state != OTZ_STATE_DECODE) {
		ps_operation->enc_dec.dec_error_state = OTZ_ERROR_ILLEGAL_STATE;
		return -1;
	}

	if (ps_operation->enc_dec.dec_error_state != OTZ_SUCCESS)
		return -1;

	return 0;
}

static int otz_client_prepare_decode(void *private_data,
		struct otz_client_encode_cmd *dec,
		struct otz_encode **pdec_context)
{
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	struct otz_encode *dec_context;
	int  session_found = 0, enc_found = 0;
	int ret = 0;
	u32 dev_file_id = (u32)private_data;

	/* TODO: You need to refactor this */
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == dec->service_id) {
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id == dec->session_id) {
							pr_debug("enc cmd ses id %d", temp_ses->session_id);
							session_found = 1;
							break;
						}
					}
					break;
				}
			}
			break;
		}
	}

	if (!session_found) {
		pr_err("session not found");
		ret = -EINVAL;
		goto return_func;
	}

	if (dec->encode_id != -1) {
		list_for_each_entry(dec_context, &temp_ses->encode_list, head) {
			if (dec_context->encode_id == dec->encode_id) {
				enc_found = 1;
				break;
			}
		}
	}

	if (!enc_found) {
		ret = -EINVAL;
		goto return_func;
	}
	*pdec_context = dec_context;

return_func:
	return ret;
}

static int __otz_client_encode_uint32(void *private_data,
		struct otz_client_encode_cmd *enc)
{
	struct otz_session *session;
	struct otz_encode *enc_context;
	int ret = 0;

	ret = otz_client_prepare_encode(private_data, enc, &enc_context,
			&session);
	if (ret)
		goto return_func;

	if (enc->param_type == OTZC_PARAM_IN) {
		if (!enc_context->ker_req_data_addr) {
			enc_context->ker_req_data_addr = kmalloc(OTZ_1K_SIZE,
					GFP_KERNEL);
			if (!enc_context->ker_req_data_addr) {
				pr_err("kmalloc failed");
				ret =  -ENOMEM;
				goto return_func;
			}
			pr_debug("Allocate enc_context->ker_req_data_addr: %dB", sizeof(enc_context->ker_req_data_addr));
		}

		if ((enc_context->enc_req_offset + sizeof(u32) <= OTZ_1K_SIZE)
			&& (enc_context->enc_req_pos < OTZ_MAX_REQ_PARAMS)) {
			*(u32 *)(enc_context->ker_req_data_addr +
				enc_context->enc_req_offset) =
				*((u32 *)enc->data);
			enc_context->enc_req_offset += sizeof(u32);
			enc_context->meta[enc_context->enc_req_pos].type
				= OTZ_ENC_UINT32;
			enc_context->meta[enc_context->enc_req_pos].len =
				sizeof(u32);
			enc_context->enc_req_pos++;
		} else {
			ret = -ENOMEM;/* Check this */
			goto return_func;
		}
	} else if (enc->param_type == OTZC_PARAM_OUT) {
		if (!enc_context->ker_res_data_addr) {
			enc_context->ker_res_data_addr = kmalloc(OTZ_1K_SIZE,
					GFP_KERNEL);
			if (!enc_context->ker_res_data_addr) {
				pr_err("kmalloc failed");
				ret = -ENOMEM;
				goto return_func;
			}
			pr_debug("Allocate enc_context->ker_res_data_addr: %dB",
					sizeof(enc_context->ker_res_data_addr));
		}

		if ((enc_context->enc_res_offset + sizeof(u32) <= OTZ_1K_SIZE)
				&& (enc_context->enc_res_pos <
				(OTZ_MAX_RES_PARAMS + OTZ_MAX_REQ_PARAMS))) {
			if (enc->data != NULL) {
				enc_context->meta[enc_context->enc_res_pos].usr_addr
					= (u32)enc->data;
			} else
				enc_context->meta[enc_context->enc_res_pos].usr_addr = 0;

			enc_context->enc_res_offset += sizeof(u32);
			enc_context->meta[enc_context->enc_res_pos].type =
				OTZ_ENC_UINT32;
			enc_context->meta[enc_context->enc_res_pos].len =
				sizeof(u32);
			enc_context->enc_res_pos++;
		} else {
			ret =  -ENOMEM; /* check this */
			goto return_func;
		}
	}

return_func:
	return ret;
}

static int otz_client_encode_uint32(void *private_data, void *argp)
{
	struct otz_client_encode_cmd enc;
	int ret = 0;

	if (copy_from_user(&enc, argp, sizeof(enc))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = __otz_client_encode_uint32(private_data, &enc);
	if (ret) {
		pr_err("otz_client error encoding uint32");
		if (ret == -ENOMEM)
			goto ret_encode_u32;
		else
			goto return_func;
	}

ret_encode_u32:
	if (copy_to_user(argp, &enc, sizeof(enc))) {
		pr_err("copy from user failed");
		return -EFAULT;
	}

return_func:
	return ret;
}

static int __otz_client_encode_array(void *private_data,
		struct otz_client_encode_cmd *enc, u8 flags)
{
	struct otz_session *session;
	struct otz_encode *enc_context;
	int ret = 0;

	ret = otz_client_prepare_encode(private_data, enc, &enc_context,
			&session);
	if (ret)
		goto return_func;

	pr_debug("enc_id 0x%x", enc_context->encode_id);

	/* TODO: Map PARAM_IN, OUT and INOUT correctly
	 * TODO: Use Linux LIST to do this
	 */
	if (enc->param_type == OTZC_PARAM_IN) {
		if (!enc_context->ker_req_data_addr) {
			pr_debug("allocate req data\n");
			enc_context->ker_req_data_addr =
				kmalloc(OTZ_1K_SIZE, GFP_KERNEL);
			if (!enc_context->ker_req_data_addr) {
				ret = -ENOMEM;
				goto return_func;
			}
			pr_debug("Allocate enc_context->ker_req_data_addr: %dB",
					sizeof(enc_context->ker_req_data_addr));
		}
		pr_debug("append encode data\n");
		/* TODO: Look at OTZ_1K_SIZE and see if we can increment it */
		if ((enc_context->enc_req_offset + enc->len <= OTZ_1K_SIZE) &&
			(enc_context->enc_req_pos < OTZ_MAX_REQ_PARAMS)) {
			if (flags == OTZ_USER_SPACE) {
				if (copy_from_user(
						enc_context->ker_req_data_addr +
						enc_context->enc_req_offset,
						enc->data,
						enc->len)) {
					pr_err("copy from user failed");
					ret = -EFAULT;
					goto return_func;
				}
			} else if (flags == OTZ_KERNEL_SPACE) {
				memcpy(enc_context->ker_req_data_addr +
					enc_context->enc_req_offset,
					enc->data,
					enc->len);
			} else {
				pr_err("encode array: unknown address space");
				goto return_func;
			}

			enc_context->enc_req_offset += enc->len;
			enc_context->meta[enc_context->enc_req_pos].type =
				OTZ_ENC_ARRAY;
			enc_context->meta[enc_context->enc_req_pos].len =
				enc->len;
			enc_context->enc_req_pos++;
		} else {
			ret = -ENOMEM; /* Check this */
			goto return_func;
		}
	} else if (enc->param_type == OTZC_PARAM_OUT) {
		if (!enc_context->ker_res_data_addr) {
			enc_context->ker_res_data_addr = kmalloc(OTZ_1K_SIZE,
					GFP_KERNEL);
			if (!enc_context->ker_res_data_addr) {
				pr_err("kmalloc failed");
				ret = -ENOMEM;
				goto return_func;
			}
			pr_debug("Allocate enc_context->ker_res_data_addr: %dB",
					sizeof(enc_context->ker_res_data_addr));
		}

		if ((enc_context->enc_res_offset + enc->len <= OTZ_1K_SIZE) &&
				(enc_context->enc_res_pos <
				 (OTZ_MAX_RES_PARAMS + OTZ_MAX_REQ_PARAMS))) {
			if (enc->data != NULL) {
				enc_context->meta[enc_context->enc_res_pos].usr_addr
					= (u32)enc->data;
			} else
				enc_context->meta[enc_context->enc_res_pos].usr_addr = 0;

			enc_context->enc_res_offset += enc->len;
			enc_context->meta[enc_context->enc_res_pos].type =
				OTZ_ENC_ARRAY;
			enc_context->meta[enc_context->enc_res_pos].len =
				enc->len;
			enc_context->enc_res_pos++;
		} else {
			ret = -ENOMEM;/* Check this */
			goto return_func;
		}
	}

return_func:
	return ret;
}

static int otz_client_encode_array(void *private_data, void *argp)
{
	struct otz_client_encode_cmd enc;
	int ret = 0;

	if (copy_from_user(&enc, argp, sizeof(enc))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = __otz_client_encode_array(private_data, &enc, OTZ_USER_SPACE);
	if (ret) {
		pr_err("otz_client error encoding array space");
		if (ret == -ENOMEM || ret == -EFAULT)
			goto ret_encode_array;
		else
			goto return_func;
	}

ret_encode_array:
	if (copy_to_user(argp, &enc, sizeof(enc))) {
		pr_err("copy from user failed");
		return -EFAULT;
	}

return_func:
	return ret;
}

static int __otz_client_decode_uint32(void *private_data,
		struct otz_client_encode_cmd *dec)
{
	struct otz_encode *dec_context;
	int ret = 0;

	ret = otz_client_prepare_decode(private_data, dec, &dec_context);
	if (ret)
		goto return_func;

	if ((dec_context->dec_res_pos <= dec_context->enc_res_pos) &&
			(dec_context->meta[dec_context->dec_res_pos].type
			 == OTZ_ENC_UINT32)) {
		if (dec_context->meta[dec_context->dec_res_pos].usr_addr) {
			dec->data =
				(void *)dec_context->meta[dec_context->dec_res_pos].usr_addr;
		}

		*(u32 *)dec->data =  *((u32 *)(dec_context->ker_res_data_addr
					+ dec_context->dec_offset));
		dec_context->dec_offset += sizeof(u32);
		dec_context->dec_res_pos++;
	}

return_func:
	return ret;
}

static int otz_client_decode_uint32(void *private_data, void *argp)
{
	struct otz_client_encode_cmd dec;
	int ret = 0;

	if (copy_from_user(&dec, argp, sizeof(dec))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = __otz_client_decode_uint32(private_data, &dec);
	if (ret) {
		pr_err("otz_client error decoding uint32");
		goto return_func;
	}

	if (copy_to_user(argp, &dec, sizeof(dec))) {
		pr_err("copy to user failed");
		return -EFAULT;
	}

return_func:
	return ret;
}

static void otz_encode_uint32(struct otz_operation_t *ps_operation,
		void const *data,
		int param_type)
{
	struct otz_client_encode_cmd enc;
	int ret;

	if (check_encode(ps_operation))
		return;

	enc.encode_id = ps_operation->enc_dec.encode_id;
	enc.cmd_id = ps_operation->enc_dec.cmd_id;
	enc.service_id = ps_operation->session->service_id;
	enc.session_id = ps_operation->session->session_id;
	enc.data = (void *)data;
	enc.len = sizeof(uint32_t);
	enc.param_type = param_type;

	mutex_lock(&encode_cmd_lock);
	ret = __otz_client_encode_uint32((void *)ps_operation->session->device.fd, &enc);
	mutex_unlock(&encode_cmd_lock);
	if (ret) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_MEMORY;
		ps_operation->s_errno = ret;
	} else {
		pr_debug("Encode UINT32 succeded");
		ps_operation->enc_dec.encode_id = enc.encode_id;
	}

	return;
}

/**
 * Encode binary array to the encoded message
 *
 * Append a binary array pointed to by array of length length bytes to the end
 * of the encoded message. The implementation must guarantee that when decoding
 * the array in the servide the base pointer is eight byte aligned to enable any
 * basic C data structure to be exchanged.
 */
static void otz_encode_array(struct otz_operation_t *ps_operation,
		void const *pk_array, uint32_t length, int param_type)
{
	struct otz_client_encode_cmd enc;
	int ret;

	if (check_encode(ps_operation))
		return;

	enc.encode_id = ps_operation->enc_dec.encode_id;
	enc.cmd_id = ps_operation->enc_dec.cmd_id;
	enc.service_id = ps_operation->session->service_id;
	enc.session_id = ps_operation->session->session_id;
	enc.data = (void *)pk_array;
	enc.len = length;
	enc.param_type = param_type;

	ret = __otz_client_encode_array((void *)ps_operation->session->device.fd,
			&enc, OTZ_KERNEL_SPACE);
	if (ret) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_MEMORY;
		ps_operation->s_errno = ret;
	} else
		ps_operation->enc_dec.encode_id = enc.encode_id;

	return;
}

/**
 *	Decode an unsigned 32-bit integer value from message
 *
 *	Decode a single item of type uint32_t from the current offset in the
 *	structured message returned by the secure world.
 */
static uint32_t otz_decode_uint32(struct otz_operation_t *ps_operation)
{
	struct otz_client_encode_cmd dec;
	int ret;

	if (check_decode(ps_operation)) {
		*((uint32_t *)dec.data) = 0;
		goto return_func;
	}

	dec.encode_id = ps_operation->enc_dec.encode_id;
	dec.cmd_id = ps_operation->enc_dec.cmd_id;
	dec.service_id = ps_operation->session->service_id;
	dec.session_id = ps_operation->session->session_id;
	dec.len = sizeof(uint32_t);

	ret = __otz_client_decode_uint32(&ps_operation->session->device.fd,
			&dec);
	if (ret) {
		ps_operation->enc_dec.dec_error_state =
			OTZ_ERROR_DECODE_NO_DATA;
		ps_operation->s_errno = ret;
		*((uint32_t *)dec.data) = 0;
		goto return_func;
	}

return_func:
	return (uint32_t)dec.data;
}

static int __otz_client_decode_array_space(void *private_data,
		struct otz_client_encode_cmd *dec, u8 flags)
{
	struct otz_encode *dec_context;
	int ret = 0;

	ret = otz_client_prepare_decode(private_data, dec, &dec_context);
	if (ret)
		goto return_func;

	if ((dec_context->dec_res_pos <= dec_context->enc_res_pos) &&
			(dec_context->meta[dec_context->dec_res_pos].type
			 == OTZ_ENC_ARRAY)) {
		if (dec_context->meta[dec_context->dec_res_pos].len >=
				dec_context->meta[dec_context->dec_res_pos].ret_len) {
			if (dec_context->meta[dec_context->dec_res_pos].usr_addr) {
				dec->data =
					(void *)dec_context->meta[dec_context->dec_res_pos].usr_addr;
			}

			if (flags == OTZ_USER_SPACE) {
				if (copy_to_user(dec->data,
						dec_context->ker_res_data_addr + dec_context->dec_offset,
						dec_context->meta[dec_context->dec_res_pos].ret_len)){
					pr_err("copy from user failed while copying array");
					ret = -EFAULT;
					goto return_func;
				}
			} else if (flags == OTZ_KERNEL_SPACE) {
				memcpy(dec->data,
					dec_context->ker_res_data_addr + dec_context->dec_offset,
					dec_context->meta[dec_context->dec_res_pos].ret_len);
			} else {
				pr_err("decode array: unknown address space");
				goto return_func;
			}
		} else {
			pr_err("buffer length is small. Length required %d \
				and supplied length %d",
				dec_context->meta[dec_context->dec_res_pos].ret_len,
				dec_context->meta[dec_context->dec_res_pos].len);
			ret = -EFAULT; /* check this */
			goto return_func;
		}

		dec->len = dec_context->meta[dec_context->dec_res_pos].ret_len;
		dec_context->dec_offset +=
			dec_context->meta[dec_context->dec_res_pos].len;
		dec_context->dec_res_pos++;
	} else if ((dec_context->dec_res_pos <= dec_context->enc_res_pos) &&
			(dec_context->meta[dec_context->dec_res_pos].type
			 == OTZ_MEM_REF)) {
		if (dec_context->meta[dec_context->dec_res_pos].len >=
				dec_context->meta[dec_context->dec_res_pos].ret_len) {
			dec->data =
				(void *)dec_context->meta[dec_context->dec_res_pos].usr_addr;
		} else {
			pr_err("buffer length is small. Length required %d \
				and supplied length %d\n",
				dec_context->meta[dec_context->dec_res_pos].ret_len,
				dec_context->meta[dec_context->dec_res_pos].len);
			ret = -EFAULT; /* Check this */
			goto return_func;
		}

		dec->len = dec_context->meta[dec_context->dec_res_pos].ret_len;
		dec_context->dec_offset += sizeof(u32);
		dec_context->dec_res_pos++;
	} else {
		pr_err("invalid data type or decoder at wrong position");
		ret = -EINVAL;
		goto return_func;
	}

return_func:
	return ret;
}

/**
 * Decode a block of binary data from the message
 *
 * Decodes a block of binary data from the current offset in the structured
 * message returned by the secure world.
 * The length of the block is returned in *pui_length and the base pointer is
 * the function return value
 */
static void *otz_decode_array_space(struct otz_operation_t *ps_operation,
		uint32_t *plength)
{
	struct otz_client_encode_cmd dec;
	int ret;

	if (check_decode(ps_operation)) {
		*plength = 0;
		dec.data = NULL;
		goto return_func;
	}

	dec.encode_id = ps_operation->enc_dec.encode_id;
	dec.cmd_id = ps_operation->enc_dec.cmd_id;
	dec.service_id = ps_operation->session->service_id;
	dec.session_id = ps_operation->session->session_id;

	mutex_lock(&decode_cmd_lock);
	ret = __otz_client_decode_array_space((void *)ps_operation->session->device.fd,
			&dec, OTZ_KERNEL_SPACE);
	mutex_unlock(&decode_cmd_lock);

	if (ret) {
		ps_operation->enc_dec.dec_error_state =
			OTZ_ERROR_DECODE_NO_DATA;
		ps_operation->s_errno = ret;
		dec.data = NULL;
		goto return_func;
	}

	*plength = dec.len;

return_func:
	return (void *)dec.data;
}

/**
 * @brief
 *
 * Open session for the requested service by getting the service ID
 * form the user. After opening the session, the session ID is copied back
 * to the user space.
 *
 * @param private_data - Holds the device file ID
 * @param argp - Contains the Service ID
 *
 * @return
 */
static int otz_client_session_open(void *private_data, void *argp)
{
	struct ser_ses_id ses_open;
	struct otz_session *ses_new;
	int ret_val;
	u32 dev_file_id = (u32)private_data;

	if (copy_from_user(&ses_open, argp, sizeof(ses_open))) {
		pr_err("copy from user failed");
		ret_val =  -EFAULT;
		goto return_func;
	}

	ret_val = __otz_client_session_open(dev_file_id, &ses_open, ses_new);
	if (ret_val) {
		pr_err("failed to open session");
		goto return_func;
	}

	if (copy_to_user(argp, &ses_open, sizeof(ses_open))) {
		pr_err("copy from user failed");
		ret_val =  -EFAULT;
		goto clean_hdr_buf;
	}

	goto return_func;

clean_hdr_buf:
	list_del(&ses_new->head);
	pr_debug("Freeing ses_new in clean_hdr_buf: %dB", sizeof(ses_new));
	kfree(ses_new);

return_func:
	return ret_val;
}

static int __otz_client_session_close(u32 dev_file_id,
		struct ser_ses_id *ses_close)
{
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	int ret_val = 0;

	pr_debug("Closing session");
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == ses_close->service_id) {
					list_for_each_entry(temp_ses,
							&temp_svc->sessions_list, head) {
						if (temp_ses->session_id == ses_close->session_id) {
							otz_client_close_session_for_service(dev_file_id,
									temp_svc, temp_ses);
							break;
						}
					}
					break;
				}
			}
			break;
		}
	}

	return ret_val;
}

/**
 * Closes the client session by getting the service ID and
 * session ID from user space.
 *
 * @param private_data - Contains the device file ID
 * @param argp - Contains the service ID and Session ID
 */
static int otz_client_session_close(void *private_data, void *argp)
{
	struct ser_ses_id ses_close;
	int ret_val = 0;
	u32 dev_file_id = (u32)private_data;

	if (copy_from_user(&ses_close, argp, sizeof(ses_close))) {
		pr_err("copy from user failed");
		ret_val = -EFAULT;
		goto return_func;
	}

	ret_val = __otz_client_session_close(dev_file_id, &ses_close);
	if (ret_val) {
		pr_err("failed to close session");
		goto return_func;
	}

return_func:
	return ret_val;
}

static int otz_client_register_service(void) __attribute__((used));
static int otz_client_register_service(void)
{
	/* Query secure and find out */
	return 0;
}

static int otz_client_unregister_service(void) __attribute__((used));
static int otz_client_unregister_service(void)
{
	/*Query secure and do*/
	return 0;
}

static void *kernel_mmap(u32 dev_file_id, uint32_t length)
{
	struct otz_shared_mem *mem_new;
	u32 *alloc_addr;
	struct otz_dev_file *temp_dev_file;

	pr_debug("Inside kernel_mmap. Length:%d", length);

	alloc_addr = kmalloc(length, GFP_KERNEL);
	if (!alloc_addr) {
		pr_err("get free pages failed");
		return NULL;
		/* TODO: Look into this to return the right return value */
		/* ret = -ENOMEM; */
		/* goto return_func; */
	}
	pr_debug("kernel_mmap k_addr %p", alloc_addr);

	mem_new = kmalloc(sizeof(struct otz_shared_mem), GFP_KERNEL);
	if (!mem_new) {
		pr_err("kmalloc failed");
		return NULL;
		/* ret = -ENOMEM; */
		/* goto return_func; */
	}
	pr_debug("Allocate mem_new: %dB", sizeof(mem_new));

	mem_new->k_addr = alloc_addr;
	mem_new->len = length;
	/* No userspace addresses, maintained to comply with Sierraware's
	 * driver
	 * */
	mem_new->u_addr = alloc_addr;
	mem_new->index = mem_new->u_addr;
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id)
			break;
	}
	temp_dev_file->dev_shared_mem_head.shared_mem_cnt++;
	list_add_tail(&mem_new->head,
			&temp_dev_file->dev_shared_mem_head.shared_mem_list);

/* return_func: */
	return alloc_addr;
}

/**
 * Creates shared memory between non secure world applicaion
 * and non secure world kernel.
 */
static int otz_client_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	struct otz_shared_mem *mem_new;
	u32 *alloc_addr;
	long length = vma->vm_end - vma->vm_start;
	struct otz_dev_file *temp_dev_file;

	alloc_addr =  (void *) __get_free_pages(GFP_KERNEL,
			get_order(ROUND_UP(length, SZ_4K)));
	if (!alloc_addr) {
		pr_err("get free pages failed");
		ret = -ENOMEM;
		goto return_func;
	}
	pr_debug("mmap k_addr %p", alloc_addr);

	if (remap_pfn_range(vma, vma->vm_start,
				((virt_to_phys(alloc_addr)) >> PAGE_SHIFT),
				length, vma->vm_page_prot)) {
		ret = -EAGAIN;
		goto return_func;
	}

	mem_new = kmalloc(sizeof(struct otz_shared_mem), GFP_KERNEL);
	if (!mem_new) {
		pr_err("kmalloc failed");
		ret = -ENOMEM;
		goto return_func;
	}
	pr_debug("Allocate mem_new: %dB", sizeof(mem_new));

	mem_new->k_addr = alloc_addr;
	mem_new->len = length;
	mem_new->u_addr = (void *)vma->vm_start;
	mem_new->index = mem_new->u_addr;
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == (u32)filp->private_data)
			break;
	}
	temp_dev_file->dev_shared_mem_head.shared_mem_cnt++;
	list_add_tail(&mem_new->head,
			&temp_dev_file->dev_shared_mem_head.shared_mem_list);

return_func:
	return ret;
}

/**
 * Sends a command from the non secure world Kernel to thesecure world.
 */
static int otz_client_kernel_send_cmd(void *private_data, void *argp)
{
	int ret = 0;
	int ret_resp_len = 0;
	u32 dev_file_id = (u32)private_data;
	struct otz_client_encode_cmd *enc =
		(struct otz_client_encode_cmd *)argp;
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	struct otz_encode *enc_temp;
	int enc_found = 0;

	pr_debug("enc id %d", enc->encode_id);
	pr_debug("dev file id %d", dev_file_id);
	pr_debug("ser id %d", enc->service_id);
	pr_debug("ses id %d", enc->session_id);

	/* TODO: This needs to be refactored*/
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == enc->service_id) {
					pr_debug("send cmd ser id %d", temp_svc->service_id);
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id
								== enc->session_id) {
							pr_debug("send cmd ses id %d",
									temp_ses->session_id);
							if (enc->encode_id != -1) {
								list_for_each_entry(enc_temp,
										&temp_ses->encode_list, head) {
									if (enc_temp->encode_id == enc->encode_id) {
										pr_debug("send cmd enc id 0x%x",
												enc_temp->encode_id);
										enc_found = 1;
										break;
									}
								}
							} else {
								ret = otz_client_prepare_encode(
										private_data,
										enc, &enc_temp, &temp_ses);
								if (!ret)
									enc_found = 1;
								break;
							}
						}
						break;
					}
					break;
				}
			}
			break;
		}
	}

	if (!enc_found) {
		ret = -EINVAL;
		goto return_func;
	}

	ret = otz_smc_call(dev_file_id, enc->service_id, enc->cmd_id,
			enc->session_id,
			enc->encode_id,
			enc_temp->ker_req_data_addr, enc_temp->enc_req_offset,
			enc_temp->ker_res_data_addr, enc_temp->enc_res_offset,
			enc_temp->meta, &ret_resp_len, &enc_temp->wait_data ,
			&send_cmd_lock);

	if (ret != SMC_SUCCESS) {
		pr_err("send cmd secure call failed");
		goto return_func;
	}

	pr_debug("smc_success");

return_func:
	return ret;
}

/**
 * Sends a command from the non secure application
 * to the secure world.
 */

static int otz_client_send_cmd(void *private_data, void *argp)
{
	struct otz_client_encode_cmd enc;
	int ret = 0;
	if (copy_from_user(&enc, argp, sizeof(enc))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = otz_client_kernel_send_cmd(private_data, &enc);
	if (ret == 0) {
		if (copy_to_user(argp, &enc, sizeof(enc))) {
			pr_err("copy to user failed");
			ret = -EFAULT;
			goto return_func;
		}
	}

return_func:
	return ret;

}

/**
 * Frees the encode context associated with a particular device and session
 */
static int __otz_client_kernel_operation_release(u32 dev_file_id, void *argp)
{

	struct otz_encode *enc_context = NULL;
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	int  session_found = 0, enc_found = 0;
	int ret = 0;
	struct otz_client_encode_cmd *enc = (struct otz_client_encode_cmd *)argp;

	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == enc->service_id) {
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id == enc->session_id) {
							session_found = 1;
							break;
						}
					}
					break;
				}
			}
			break;
		}
	}

	if (!session_found) {
		ret = -EINVAL;
		goto return_func;
	}

	if (enc->encode_id != -1) {
		list_for_each_entry(enc_context, &temp_ses->encode_list, head) {
			if (enc_context->encode_id == enc->encode_id) {
				enc_found = 1;
				break;
			}
		}
	}

	if (enc_found && enc_context) {
		if (enc_context->ker_req_data_addr) {
			pr_debug("Freeing enc_context->ker_req_data_addr: %dB",
					sizeof(enc_context->ker_req_data_addr));
			kfree(enc_context->ker_req_data_addr);
		}

		if (enc_context->ker_res_data_addr) {
			pr_debug("Freeing enc_context->ker_res_data_addr: %dB",
					sizeof(enc_context->ker_res_data_addr));
			kfree(enc_context->ker_res_data_addr);
		}

		list_del(&enc_context->head);
		kfree(enc_context->meta);
		kfree(enc_context);
	}
return_func:
	return ret;
}

/**
 * Same as __otz_client_kernel_operation_release() but this is for a
 * non-secure user application. So copy_from_user() is used.
 */
static int otz_client_operation_release(void *private_data, void *argp)
{
	struct otz_client_encode_cmd enc;
	u32 dev_file_id = (u32)private_data;
	int ret = 0;

	if (copy_from_user(&enc, argp, sizeof(enc))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = __otz_client_kernel_operation_release(dev_file_id, &enc);
	if (ret != 0)
		pr_err("Error in release");

return_func:
	return ret;
}

/**
 * Prepares and initializes the encode context.
 */
static int otz_client_prepare_encode(void *private_data,
		struct otz_client_encode_cmd *enc,
		struct otz_encode **penc_context,
		struct otz_session **psession)
{
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	struct otz_encode *enc_context;
	int  session_found = 0, enc_found = 0;
	int ret = 0;
	u32 dev_file_id = (u32)private_data;

	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == enc->service_id) {
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id == enc->session_id) {
							pr_debug("enc cmd ses id %d", temp_ses->session_id);
							session_found = 1;
							break;
						}
					}
					break;
				}
			}
			break;
		}
	}

	if (!session_found) {
		pr_err("session not found");
		pr_err("enc_sesid:%d", enc->session_id);
		ret = -EINVAL;
		goto return_func;
	}

	if (enc->encode_id != -1) {
		list_for_each_entry(enc_context, &temp_ses->encode_list, head) {
			if (enc_context->encode_id == enc->encode_id) {
				enc_found = 1;
				break;
			}
		}
	}

	if (!enc_found) {
		enc_context = kmalloc(sizeof(struct otz_encode), GFP_KERNEL);
		if (!enc_context) {
			pr_err("kmalloc failed");
			ret = -ENOMEM;
			goto return_func;
		}
		pr_debug("Allocate enc_context: %dB", sizeof(enc_context));

		enc_context->meta = kmalloc(sizeof(struct otzc_encode_meta) *
				(OTZ_MAX_RES_PARAMS + OTZ_MAX_REQ_PARAMS),
				GFP_KERNEL);

		if (!enc_context->meta) {
			pr_err("kmalloc failed");
			pr_debug("Freeing enc_context: %dB",
					sizeof(enc_context));
			kfree(enc_context);
			ret = -ENOMEM;
			goto return_func;
		}

		pr_debug("Allocate enc_context->meta: %dB",
				sizeof(enc_context->meta));

		enc_context->encode_id = (int)enc_context;
		enc->encode_id = enc_context->encode_id;
		enc_context->ker_req_data_addr = NULL;
		enc_context->ker_res_data_addr = NULL;
		enc_context->enc_req_offset = 0;
		enc_context->enc_res_offset = 0;
		enc_context->enc_req_pos = 0;
		enc_context->enc_res_pos = OTZ_MAX_REQ_PARAMS;
		enc_context->dec_res_pos = OTZ_MAX_REQ_PARAMS;
		enc_context->dec_offset = 0;

#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
		enc_context->wait_data.send_wait_flag = 0;
		init_waitqueue_head(&enc_context->wait_data.send_cmd_wq);
#endif
		list_add_tail(&enc_context->head, &temp_ses->encode_list);
	}

	*penc_context = enc_context;
	*psession = temp_ses;

return_func:
	return ret;
}

/**
 * Function to encode a memory reference (from kernel)
 */
static int __otz_client_kernel_encode_mem_ref(void *private_data, void *argp)
{
	int ret = 0, shared_mem_found = 0;
	struct otz_encode *enc_context;
	struct otz_session *session;
	struct otz_shared_mem *temp_shared_mem;
	struct otz_client_encode_cmd *enc =
		(struct otz_client_encode_cmd *)argp;

	ret = otz_client_prepare_encode(private_data, enc,
			&enc_context, &session);

	if (ret)
		goto return_func;

	list_for_each_entry(temp_shared_mem, &session->shared_mem_list, s_head) {
		if (temp_shared_mem->index == (u32 *)enc->data) {
			shared_mem_found = 1;
			break;
		}
	}
	if (!shared_mem_found) {
		struct otz_dev_file *temp_dev_file;

		list_for_each_entry(temp_dev_file,
				&otzc_dev_file_head.dev_file_list,
				head) {
			if (temp_dev_file->dev_file_id == (u32)private_data)
				break;
		}

		list_for_each_entry(temp_shared_mem,
				&temp_dev_file->dev_shared_mem_head.shared_mem_list, head) {
			pr_debug("dev id : %d shrd_mem_index : 0x%d",
					temp_dev_file->dev_file_id,
					(int *)temp_shared_mem->index);
			if (temp_shared_mem->index == (u32 *)enc->data) {
				shared_mem_found = 1;
				break;
			}
		}
	}

	if (!shared_mem_found) {
		pr_err("shared memory not registered for this session %d",
				session->session_id);
		ret = -EINVAL;
		goto return_func;
	}

	if (enc->param_type == OTZC_PARAM_IN) {
		if (!enc_context->ker_req_data_addr) {
			enc_context->ker_req_data_addr = kmalloc(OTZ_1K_SIZE,
					GFP_KERNEL);
			if (!enc_context->ker_req_data_addr) {
				pr_err("kmalloc failed");
				ret = -ENOMEM;
				goto ret_encode_array;
			}
			pr_debug("Allocate enc_context->ker_req_data_addr: %dB",
					sizeof(enc_context->ker_req_data_addr));
		}

		if ((enc_context->enc_req_offset + sizeof(u32) <=
					OTZ_1K_SIZE) &&
				(enc_context->enc_req_pos < OTZ_MAX_REQ_PARAMS)) {
			*((u32 *)enc_context->ker_req_data_addr +
					enc_context->enc_req_offset)
				= virt_to_phys(temp_shared_mem->k_addr+enc->offset);
			enc_context->enc_req_offset += sizeof(u32);
			enc_context->meta[enc_context->enc_req_pos].usr_addr
				= (u32)(temp_shared_mem->u_addr + enc->offset);
			enc_context->meta[enc_context->enc_req_pos].type = OTZ_MEM_REF;
			enc_context->meta[enc_context->enc_req_pos].len = enc->len;
			enc_context->enc_req_pos++;
		} else {
			ret = -ENOMEM; /* Check this */
			goto ret_encode_array;
		}
	} else if (enc->param_type == OTZC_PARAM_OUT) {
		if (!enc_context->ker_res_data_addr) {
			enc_context->ker_res_data_addr = kmalloc(OTZ_1K_SIZE,
					GFP_KERNEL);
			if (!enc_context->ker_res_data_addr) {
				pr_err("kmalloc failed");
				ret = -ENOMEM;
				goto ret_encode_array;
			}
			pr_debug("Allocate enc_context->ker_res_data_addr: %dB",
					sizeof(enc_context->ker_res_data_addr));
		}

		/* TODO: This needs to be refactored */
		if ((enc_context->enc_res_offset + sizeof(u32) <= OTZ_1K_SIZE)
				&& (enc_context->enc_res_pos <
				(OTZ_MAX_RES_PARAMS + OTZ_MAX_REQ_PARAMS))) {
			*((u32 *)enc_context->ker_res_data_addr +
					enc_context->enc_res_offset)
				= virt_to_phys(temp_shared_mem->k_addr + enc->offset);
			enc_context->enc_res_offset += sizeof(u32);
			enc_context->meta[enc_context->enc_res_pos].usr_addr
				= (u32)(temp_shared_mem->u_addr + enc->offset);
			enc_context->meta[enc_context->enc_res_pos].type
				=  OTZ_MEM_REF;
			enc_context->meta[enc_context->enc_res_pos].len = enc->len;
			enc_context->enc_res_pos++;
		} else {
			ret = -ENOMEM; /*Check this */
			goto ret_encode_array;
		}
	}
ret_encode_array:
return_func:
	return ret;
}

static int otz_client_encode_mem_ref(void *private_data, void *argp)
{
	struct otz_client_encode_cmd enc;
	int ret = 0;

	if (copy_from_user(&enc, argp, sizeof(enc))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = __otz_client_kernel_encode_mem_ref(private_data, &enc);
	if (enc.encode_id != -1) {
		if (copy_to_user(argp, &enc, sizeof(enc))) {
			pr_err("copy from user failed");
			return -EFAULT;
		}
	}

return_func:
	return ret;
}

static int otz_client_kernel_decode_array_space(void *private_data, void *argp)
	__attribute__((used));
static int otz_client_kernel_decode_array_space(void *private_data, void *argp)
{
	struct otz_client_encode_cmd *dec = NULL;
	int ret = 0;
	struct otz_encode *dec_context;
	dec = (struct otz_client_encode_cmd *)argp;

	ret = otz_client_prepare_decode(private_data, dec, &dec_context);
	if (ret)
		goto return_func;

	if ((dec_context->dec_res_pos <= dec_context->enc_res_pos) &&
			(dec_context->meta[dec_context->dec_res_pos].type
			 == OTZ_MEM_REF)) {
		if (dec_context->meta[dec_context->dec_res_pos].len >=
				dec_context->meta[dec_context->dec_res_pos].ret_len) {
			dec->data =
				(void *)dec_context->meta[dec_context->dec_res_pos].usr_addr;
		} else {
			pr_err("buffer length is small. Length required %d \
				and supplied length %d",
				dec_context->meta[dec_context->dec_res_pos].ret_len,
				dec_context->meta[dec_context->dec_res_pos].len);
			ret = -EFAULT;/* Check this */
			goto return_func;
		}

		dec->len = dec_context->meta[dec_context->dec_res_pos].ret_len;
		dec_context->dec_offset += sizeof(u32);
		dec_context->dec_res_pos++;
	} else {
		pr_err("invalid data type or decoder at wrong position");
		ret = -EINVAL;
		goto return_func;
	}

return_func:
	return ret;
}

static int otz_client_decode_array_space(void *private_data, void *argp)
{
	struct otz_client_encode_cmd dec;
	int ret = 0;

	if (copy_from_user(&dec, argp, sizeof(dec))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = __otz_client_decode_array_space(private_data, &dec,
			OTZ_USER_SPACE);
	if (ret) {
		pr_err("otz_client error decoding array space");
		goto return_func;
	}

	if (copy_to_user(argp, &dec, sizeof(dec))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

return_func:
	return ret;
}

static int otz_client_get_decode_type(void *private_data, void *argp)
{
	struct otz_client_encode_cmd dec;
	int ret = 0;
	struct otz_encode *dec_context;

	if (copy_from_user(&dec, argp, sizeof(dec))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = otz_client_prepare_decode(private_data, &dec, &dec_context);
	if (ret)
		goto return_func;

	pr_debug("decoder pos 0x%x and encoder pos 0x%x",
			dec_context->dec_res_pos, dec_context->enc_res_pos);

	if (dec_context->dec_res_pos <= dec_context->enc_res_pos)
		dec.data = (void *)dec_context->meta[dec_context->dec_res_pos].type;
	else {
		ret = -EINVAL; /* check this */
		goto return_func;
	}

	if (copy_to_user(argp, &dec, sizeof(dec))) {
		pr_err("copy to user failed");
		ret = -EFAULT;
		goto return_func;
	}

return_func:
	return ret;
}

static int otz_client_kernel_shared_mem_alloc(void *private_data, void *argp,
		struct otz_shared_mem *sh_mem) __attribute__((used));
static int otz_client_kernel_shared_mem_alloc(void *private_data, void *argp,
		struct otz_shared_mem *sh_mem)
{
	struct otz_session_shared_mem_info *mem_info;
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	struct otz_shared_mem *temp_shared_mem = sh_mem;
	int  session_found = 0;
	int ret = 0;
	u32 dev_file_id = (u32)private_data;
	mem_info = (struct otz_session_shared_mem_info *)argp;
	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == mem_info->service_id) {
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id ==
								mem_info->session_id) {
							session_found = 1;
							break;
						}
					}
					break;
				}
			}
			break;
		}
	}

	if (!session_found) {
		pr_err("Session not found!!");
		ret = -1;
		return ret;
	}

	list_add_tail(&temp_shared_mem->s_head, &temp_ses->shared_mem_list);
	return ret;
}

static int __otz_client_shared_mem_alloc(u32 dev_file_id,
		struct otz_session_shared_mem_info *mem_info)
{
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	struct otz_shared_mem *temp_shared_mem;
	int  session_found = 0;
	int ret = 0;

	pr_debug("service id %d session id %d user mem addr %p",
			mem_info->service_id,
			mem_info->session_id,
			mem_info->user_mem_addr);

	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == mem_info->service_id) {
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id ==
								mem_info->session_id) {
							session_found = 1;
							break;
						}
					}
					break;
				}
			}
			break;
		}
	}

	if (!session_found) {
		pr_err("session not found");
		ret = -EINVAL;
		goto return_func;
	}

	list_for_each_entry(temp_shared_mem,
			&temp_dev_file->dev_shared_mem_head.shared_mem_list, head) {
		if (temp_shared_mem->index == (u32 *)mem_info->user_mem_addr) {
			list_del(&temp_shared_mem->head);
			temp_dev_file->dev_shared_mem_head.shared_mem_cnt--;
			list_add_tail(&temp_shared_mem->s_head,
					&temp_ses->shared_mem_list);
			break;
		}
	}

return_func:
	return ret;
}

/**
 * Registers the shared memory from the device list to the session list. This is
 * because when we mmap, we cannot specify the session to which the memory has
 * to be mapped because the parameters do not allow us. So during mmap,
 * the memory is mapped to the device. Here, the memory which was mapped to
 * the device is mapped to the session shared memory list.
 */
static int otz_client_shared_mem_alloc(void *private_data, void *argp)
{
	struct otz_session_shared_mem_info mem_info;
	u32 dev_file_id = (u32)private_data;
	int ret = 0;

	if (copy_from_user(&mem_info, argp, sizeof(mem_info))) {
		pr_err("copy from user failed");
		ret = -EFAULT;
		goto return_func;
	}

	ret = __otz_client_shared_mem_alloc(dev_file_id, &mem_info);

return_func:
	return ret;
}

static int __otz_client_shared_mem_free(u32 dev_file_id,
		struct otz_session_shared_mem_info *mem_info)
{
	struct otz_shared_mem *temp_shared_mem;
	struct otz_dev_file *temp_dev_file;
	struct otz_service *temp_svc;
	struct otz_session *temp_ses;
	int  session_found = 0;
	int ret = 0;

	pr_debug("service id 0x%x session id 0x%x user mem addr 0x%x",
			mem_info->service_id,
			mem_info->session_id,
			mem_info->user_mem_addr);

	list_for_each_entry(temp_dev_file, &otzc_dev_file_head.dev_file_list,
			head) {
		if (temp_dev_file->dev_file_id == dev_file_id) {
			list_for_each_entry(temp_svc, &temp_dev_file->services_list, head) {
				if (temp_svc->service_id == mem_info->service_id) {
					list_for_each_entry(temp_ses, &temp_svc->sessions_list,
							head) {
						if (temp_ses->session_id == mem_info->session_id) {
							session_found = 1;
							break;
						}
					}
					break;
				}
			}
			break;
		}
	}

	if (!session_found) {
		pr_err("session not found");
		ret = -EINVAL;
		goto return_func;
	}

	list_for_each_entry(temp_shared_mem, &temp_ses->shared_mem_list, s_head) {
		if (temp_shared_mem->index == (u32 *)mem_info->user_mem_addr) {
			list_del(&temp_shared_mem->s_head);
			if (temp_shared_mem->k_addr)
				free_pages((u32)temp_shared_mem->k_addr,
					get_order(ROUND_UP(temp_shared_mem->len,
					SZ_4K)));

			if (temp_shared_mem) {
				pr_debug("Freeing temp_shared_mem: %dB",
						sizeof(temp_shared_mem));
				kfree(temp_shared_mem);
			}
			break;
		}
	}

return_func:
	return ret;
}

static int otz_client_shared_mem_free(void *private_data, void *argp)
{
	struct otz_session_shared_mem_info mem_info;
	int ret_val = 0;
	u32 dev_file_id = (u32)private_data;

	if (copy_from_user(&mem_info, argp, sizeof(mem_info))) {
		pr_err("copy from user failed");
		ret_val = -EFAULT;
		goto return_func;
	}

	ret_val = __otz_client_shared_mem_free(dev_file_id, &mem_info);
	if (ret_val) {
		pr_err("failed to free shared memory");
		goto return_func;
	}

return_func:
	return ret_val;
}

#ifdef CONFIG_KIM
/**
 * This function initializes the encode structure specifically
 * for the kernel integrity manager.
 */
struct otz_client_encode_cmd *prep_enc_struct(struct otz_client_im_check *im,
		unsigned int size, unsigned int param_type, unsigned int flag,
		void *data)
{
	struct otz_client_encode_cmd *enc = NULL;

	enc = kmalloc(sizeof(struct otz_client_encode_cmd), GFP_KERNEL);
	if (!enc)
		return NULL;

	pr_debug("Allocate enc: %dB", sizeof(enc));

	enc->encode_id = im->encode_id;
	enc->session_id = im->session_id;
	enc->cmd_id = im->cmd_id;
	enc->service_id = im->service_id;
	enc->data = NULL;
	enc->data = (void *) __get_free_pages(GFP_KERNEL,
			get_order(ROUND_UP(size, SZ_4K)));

	if (!(enc->data)) {
		pr_err("Unable to allocate space");
		return NULL;
	}
	memcpy(enc->data, (void *)data, size);
	enc->flags = flag;
	enc->offset = 0;
	enc->param_type = param_type;
	enc->len = size;

	return enc;
}

static int otz_client_enc(struct file *file, struct otz_client_encode_cmd *enc)
{
	int ret;

	mutex_lock(&encode_cmd_lock);
	ret = __otz_client_kernel_encode_mem_ref(file->private_data, enc);
	mutex_unlock(&encode_cmd_lock);
	if (ret) {
		pr_debug("failed otz_client_encode_cmd: %d", ret);
		return -1;
	}
	return 0;
}

/**
 * The Kernel Integriy Manager is not initiated from the non-secure world,
 * so this function helps to create an encode context because we are calling it
 * from the secure world itself.
 */
static struct otz_client_encode_cmd *encode_helper(struct file *file,
		struct otz_client_im_check *im , unsigned int size,
		unsigned int flag, unsigned int param_type, void *data)
{
	struct otz_shared_mem *mem_new = NULL;
	struct otz_session_shared_mem_info mem_info;
	struct otz_client_encode_cmd *enc = NULL;
	int ret = 0;

	enc = prep_enc_struct(im, size, flag, param_type, (void *)data);
	if (!enc) {
		pr_err("failed to prep_enc_struct");
		return NULL;
	}
	pr_debug("service id is %d and cmd id is"
			"%d session id is"
			"%d", enc->service_id, enc->cmd_id, enc->session_id);
	mem_new = kmalloc(sizeof(struct otz_shared_mem), GFP_KERNEL);

	if (!mem_new) {
		pr_err("Insufficient memory");
		return NULL;
	}
	pr_debug("Allocate mem_new: %dB", sizeof(mem_new));

	mem_new->k_addr = enc->data;
	mem_new->len = size;
	mem_new->u_addr = enc->data;
	mem_new->index = enc->data;
	mem_info.service_id = enc->service_id;
	mem_info.session_id = enc->session_id;
	mem_info.user_mem_addr = (unsigned int)enc->data;

	mutex_lock(&mem_alloc_lock);
	ret = otz_client_kernel_shared_mem_alloc((void *)file->private_data,
			&mem_info, mem_new);
	mutex_unlock(&mem_alloc_lock);

	ret = otz_client_enc(file, enc);
	if (ret == -1) {
		pr_err("otz_client_enc failed");
		return NULL;
	}

	return enc;
}

/*
 * XXX: This is a secure system primitive. Not sure it belongs here
 */
static int get_kernel_text_hash(void)
{
	char *kernel_text_start = (char *)KERN_TEXT_START;
	char *buffer = NULL;
	char *hash = NULL;
	buffer = kmalloc(KERN_TEXT_SIZE + 1 , GFP_KERNEL);
	if (!buffer) {
		pr_err("Unable to malloc,  try vmalloc()");
		buffer = vmalloc(KERN_TEXT_SIZE + 1);
		if (!buffer) {
			pr_err("kernel.text section alloc. failed for vmalloc\n");
			return NULL;
		}
	}
	pr_debug("Allocate buffer: %dB", sizeof(buffer));
	memcpy(buffer, kernel_text_start, KERN_TEXT_SIZE);
	buffer[KERN_TEXT_SIZE] = 0x0;
	hash = find_md5_hash(buffer);

	return hash;

}


/*
 * XXX: This is a secure system primitive. Not sure it belongs here
 */
static int check_kernel_integrity(struct file *file,
		struct otz_client_im_check *im)
{
	char hash[33];
	char *hash_ptr;
	unsigned int size = sizeof(hash);
	int ret = 0;
	struct otz_client_encode_cmd *enc = NULL;
	u32 dev_file_id;

	hash_ptr = get_kernel_text_hash();
	strncpy(hash, hash_ptr, 33);

	enc = encode_helper(file, im, size, 0x0, OTZC_PARAM_IN, (void *)hash);
	if (enc == NULL) {
		pr_err("failed in encode_data");
		ret = -1;
		goto ret_func;
	}

	/* Encode  again since we use the same input buffer for both
	 * request and response */
	enc->flags = 1;
	enc->param_type = 1;
	ret = otz_client_enc(file, enc);
	if (ret == -1) {
		pr_err("failed to encode data again");
		ret = -1;
		goto ret_func;
	}

	mutex_lock(&send_cmd_lock);
	ret = otz_client_kernel_send_cmd(file->private_data, enc);
	mutex_unlock(&send_cmd_lock);

	if (ret) {
		pr_debug("failed otz_client_send_cmd: %d", ret);
		ret = -1;
		goto ret_func;
	}
	mutex_lock(&decode_cmd_lock);
	ret = otz_client_kernel_decode_array_space(file->private_data, enc);
	mutex_unlock(&decode_cmd_lock);

	if (ret) {
		pr_debug("failed otz_client_decode_cmd: %d", ret);
		ret = -1;
		goto ret_func;
	}
	dev_file_id = (u32)file->private_data;

	ret = __otz_client_kernel_operation_release(dev_file_id, enc);
	if (ret) {
		pr_err("failed operation release: %d", ret);
		ret = -1;
		goto ret_func;
	}

	if (enc) {
		pr_debug("Freeing enc: %dB", sizeof(enc));
		kfree(enc);
		enc = NULL;
	}

ret_func:
	return ret;
}

static long otz_client_im_helper(struct file *file, void *argp)
{
	struct otz_client_encode_cmd *enc = NULL;
	int ret = 0;
	struct otz_client_im_check *im = (struct otz_client_im_check *)argp;

	ret = check_kernel_integrity(file, im);
	if (ret == -1) {
		pr_err("IM command failed");
		ret = -1;
		goto ret_func;
	}

ret_func:
	return ret;
}
#endif

static long otz_client_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	int ret = -EINVAL;
	void *argp = (void __user *) arg;

	switch (cmd) {
	case OTZ_CLIENT_IOCTL_SEND_CMD_REQ:
		mutex_lock(&send_cmd_lock);
		ret = otz_client_send_cmd(file->private_data, argp);
		mutex_unlock(&send_cmd_lock);
		if (ret)
			pr_err("failed otz_client_send_cmd: %d", ret);
		break;
#ifdef CONFIG_KIM
	case OTZ_CLIENT_IOCTL_IM_CHECK: {
		mutex_lock(im_check_lock);
		ret = otz_client_im_helper(file, argp);
		mutex_unlock(im_check_lock);
		if (ret == -1)
			pr_err("failed IM_CHECK");
		return ret;
	}
#endif
	case OTZ_CLIENT_IOCTL_ENC_UINT32: {
		mutex_lock(&encode_cmd_lock);
		ret = otz_client_encode_uint32(file->private_data, argp);
		mutex_unlock(&encode_cmd_lock);
		if (ret)
			pr_err("failed otz_client_encode_cmd: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_DEC_UINT32: {
		mutex_lock(&decode_cmd_lock);
		ret = otz_client_decode_uint32(file->private_data, argp);
		mutex_unlock(&decode_cmd_lock);
		if (ret)
			pr_err("failed otz_client_decode_cmd: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_ENC_ARRAY: {
		mutex_lock(&encode_cmd_lock);
		ret = otz_client_encode_array(file->private_data, argp);
		mutex_unlock(&encode_cmd_lock);
		if (ret)
			pr_err("failed otz_client_encode_cmd: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_DEC_ARRAY_SPACE: {
		mutex_lock(&decode_cmd_lock);
		ret = otz_client_decode_array_space(file->private_data, argp);
		mutex_unlock(&decode_cmd_lock);
		if (ret)
			pr_err("failed otz_client_decode_cmd: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_ENC_MEM_REF: {
		mutex_lock(&encode_cmd_lock);
		ret = otz_client_encode_mem_ref(file->private_data, argp);
		mutex_unlock(&encode_cmd_lock);
		if (ret)
			pr_err("failed otz_client_encode_cmd: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_ENC_ARRAY_SPACE: {
		mutex_lock(&encode_cmd_lock);
		ret = otz_client_encode_mem_ref(file->private_data, argp);
		mutex_unlock(&encode_cmd_lock);
		if (ret)
			pr_err("failed otz_client_encode_cmd: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_GET_DECODE_TYPE: {
		mutex_lock(&decode_cmd_lock);
		ret = otz_client_get_decode_type(file->private_data, argp);
		mutex_unlock(&decode_cmd_lock);
		if (ret)
			pr_err("failed otz_client_decode_cmd: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_SES_OPEN_REQ: {
		mutex_lock(&ses_open_lock);
		ret = otz_client_session_open(file->private_data, argp);
		mutex_unlock(&ses_open_lock);
		if (ret)
			pr_err("failed otz_client_session_open: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_SES_CLOSE_REQ:{
		mutex_lock(&ses_close_lock);
		ret = otz_client_session_close(file->private_data, argp);
		mutex_unlock(&ses_close_lock);
		if (ret)
			pr_err("failed otz_client_session_close: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_SHR_MEM_ALLOCATE_REQ: {
		mutex_lock(&mem_alloc_lock);
		ret = otz_client_shared_mem_alloc(file->private_data, argp);
		mutex_unlock(&mem_alloc_lock);
		if (ret)
			pr_err("failed otz_client_shared_mem_alloc: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_SHR_MEM_FREE_REQ: {
		mutex_lock(&mem_free_lock);
		ret = otz_client_shared_mem_free(file->private_data, argp);
		mutex_unlock(&mem_free_lock);
		if (ret)
			pr_err("failed otz_client_shared_mem_free: %d", ret);
		break;
	}

	case OTZ_CLIENT_IOCTL_OPERATION_RELEASE: {
		ret = otz_client_operation_release(file->private_data, argp);
		if (ret)
			pr_debug("failed operation release: %d", ret);
		break;
	}

	default:
		return -EINVAL;
	}
	return ret;
}

static int __otz_open_device(u32 *device_id)
{
	int ret;
	struct otz_dev_file *new_dev;

	*device_id = ++device_file_cnt;

	new_dev = kmalloc(sizeof(struct otz_dev_file), GFP_KERNEL);
	if (!new_dev) {
		pr_err("kmalloc failed for new dev file allocation\n");
		ret = -ENOMEM;
		goto ret_func;
	}

	pr_debug("Allocate new_dev: %dB", sizeof(new_dev));
	new_dev->dev_file_id = device_file_cnt;
	new_dev->service_cnt = 0;

	INIT_LIST_HEAD(&new_dev->services_list);
	memset(&new_dev->dev_shared_mem_head, 0, sizeof(struct otz_shared_mem_head));
	new_dev->dev_shared_mem_head.shared_mem_cnt = 0;
	INIT_LIST_HEAD(&new_dev->dev_shared_mem_head.shared_mem_list);

	list_add(&new_dev->head, &otzc_dev_file_head.dev_file_list);
	otzc_dev_file_head.dev_file_cnt++;

	/*TODO: Refactor this */
	if ((ret = otz_client_service_init(new_dev, OTZ_SVC_GLOBAL)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev, OTZ_SVC_ECHO)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_TEST_SUITE_USER)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_CRYPT)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_MUTEX_TEST)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_VIRTUAL_KEYBOARD)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev, OTZ_SVC_DRM)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_GP_INTERNAL)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_TEST_SUITE_KERNEL)) != 0)
		goto ret_func;
	else if ((ret = otz_client_service_init(new_dev, OTZ_SVC_TCXO)) != 0)
		goto ret_func;

#ifdef CONFIG_KIM
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_KERNEL_INTEGRITY_CHECK)) != 0)
		goto ret_func;
#endif

#ifdef CONFIG_FFMPEG
	else if ((ret = otz_client_service_init(new_dev,
					OTZ_SVC_FFMPEG_TEST)) != 0)
		goto ret_func;
#endif

#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
	if (!notify_data) {
		notify_data = kmalloc(sizeof(struct otzc_notify_data),
				GFP_KERNEL);

		if (!notify_data) {
			pr_err("kmalloc failed for notification data\n");
			ret = -ENOMEM;
			goto ret_func;
		}

		pr_debug("Allocate notify_data: %dB\n", sizeof(notify_data));
	}

	ret = otz_smc_call(new_dev->dev_file_id, OTZ_SVC_GLOBAL,
			OTZ_GLOBAL_CMD_ID_REGISTER_NOTIFY_MEMORY, 0, 0,
			notify_data, sizeof(struct otzc_notify_data), NULL, 0,
			NULL, NULL, NULL, NULL);

	if (ret != SMC_SUCCESS) {
		pr_err("Shared memory registration for \
				secure world notification failed");
		goto ret_func;
	}

	current_guest_id = notify_data->guest_no;
#endif

ret_func:
	return ret;
}

static int __otz_close_device(u32 dev_file_id)
{
#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
	int ret;
	ret = otz_smc_call(dev_file_id, OTZ_SVC_GLOBAL,
			OTZ_GLOBAL_CMD_ID_UNREGISTER_NOTIFY_MEMORY,
			0, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);

	if (ret != SMC_SUCCESS) {
		pr_err("Shared memory un-registration for \
				secure world notification failed");
	}
#endif

	pr_debug("otz_client_release: %d", dev_file_id);
	otz_client_service_exit(dev_file_id);

	if (list_empty(&otzc_dev_file_head.dev_file_list)) {
#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
		pr_debug("Freeing notify_data: %dB", sizeof(notify_data));
		kfree(notify_data);
		notify_data = NULL;
#endif
	}

	return 0;
}

static int otz_client_open(struct inode *inode, struct file *file)
{
	int ret = 0;
	u32 device_id;

	ret = __otz_open_device(&device_id);
	file->private_data = (void *)device_id;

	return ret;
}

static int otz_client_release(struct inode *inode, struct file *file)
{
	u32 dev_file_id = (u32)file->private_data;
	return __otz_close_device(dev_file_id);
}

static int otz_client_smc_init(void)
{
	u32 ctr;

	asm volatile("mrc p15, 0, %0, c0, c0, 1" : "=r" (ctr));
	cacheline_size =  4 << ((ctr >> 16) & 0xf);

	return 0;
}


/*
 * Wrapping operations for Sierraware's TrustZone driver
 *
 * TODO: Make them actually be operations that are attached to the
 * trustzone_operations hooks. Now they are directly called from the trustzone
 * common interface (trustzone.c).
 *
 * This is a kernel version of SierraWare's otz_api in Open Virtualization. Here
 * we initialize all the componentes that are necessary to use Sierraware's
 * TrustZone implementation, making it transparent to the service using the
 * general TrustZone interface (trustzone.c)
 *
 * XXX: At the moment we are using the same interface as user space
 * applications that communicate with Sierraware's otz_driver. We might want to
 * refactor Sierraware's code to sepparate this in the future...
 */

static otz_return_t __otz_operation_prepare_open(struct otz_device_t *ps_device,
		int pks_service, otz_login_t const *pks_login,
		otz_timelimit_t const *pks_timelimit,
		struct otz_session_t *ps_session,
		struct otz_operation_t *ps_operation)
{
	if (ps_device == NULL || pks_service == OTZ_SVC_INVALID ||
			ps_session == NULL || ps_operation == NULL) {
		pr_err("otz operation prepare open : Illegal argument\n");
		return OTZ_ERROR_ILLEGAL_ARGUMENT;
	}

	ps_session->ui_state = OTZ_STATE_INVALID;
	memcpy(&ps_session->device, ps_device, sizeof(struct otz_device_t));
	ps_session->operation_count = 0;
	ps_session->operation_count++;
	ps_session->service_id = pks_service;
	ps_session->shared_mem_cnt = 0;
	ps_operation->temp_mem_ref_count = 0;
	INIT_LIST_HEAD(&ps_session->shared_mem_list);
	ps_operation->type = OTZ_OPERATION_OPEN;
	ps_operation->ui_state = OTZ_STATE_ENCODE;
	ps_operation->session = ps_session;

	return OTZ_SUCCESS;
}

static otz_return_t __otz_operation_prepare_close(
		struct otz_session_t *ps_session,
		struct otz_operation_t *ps_operation)
{
	if (ps_session == NULL || ps_operation == NULL) {
		pr_err("otz operation prepare close : Illegal argument");
		return OTZ_ERROR_ILLEGAL_ARGUMENT;
	}

	if (ps_session->ui_state != OTZ_STATE_OPEN) {
		pr_err("otz operation prepare close : Illegal state");
		return OTZ_ERROR_ILLEGAL_STATE;
	}

	if (ps_operation->ui_state != OTZ_STATE_UNDEFINED) {
		pr_err("otz operation prepare close : Illegal state");
		return OTZ_ERROR_ILLEGAL_STATE;
	}

	ps_session->ui_state = OTZ_STATE_CLOSING;
	ps_session->operation_count++;
	ps_operation->session = ps_session;
	ps_operation->type = OTZ_OPERATION_CLOSE;
	ps_operation->ui_state = OTZ_STATE_PERFORMABLE;
	ps_operation->shared_mem_ref_count = 0;
	ps_operation->temp_mem_ref_count = 0;

	return OTZ_SUCCESS;
}

/**
 * Prepare operation for service request
 *
 * Loccally preparing an operation that cna be used to issue a command to a
 * service with which the client has already created a session
 */
static otz_return_t __otz_operation_prepare_invoke(
		struct otz_session_t *ps_session, uint32_t ui_command,
		otz_timelimit_t const *pks_timelimit,
		struct otz_operation_t *ps_operation)
{
	if (ps_session == NULL || ps_operation == NULL) {
		pr_err("otz operation prepare invoke: Illegal argument");
		return OTZ_ERROR_ILLEGAL_ARGUMENT;
	}

	if (ps_session->ui_state != OTZ_STATE_OPEN) {
		pr_err("otz operation prepare invoke: Illegal state (%d)",
				ps_session->ui_state);
		return OTZ_ERROR_ILLEGAL_STATE;
	}

	ps_operation->session = ps_session;
	ps_session->operation_count++;
	ps_operation->type = OTZ_OPERATION_INVOKE;
	ps_operation->ui_state = OTZ_STATE_ENCODE;
	ps_operation->enc_dec.encode_id = -1;
	ps_operation->enc_dec.cmd_id = ui_command;
	ps_operation->enc_dec.enc_error_state = OTZ_SUCCESS;
	ps_operation->enc_dec.dec_error_state = OTZ_SUCCESS;
	ps_operation->shared_mem_ref_count = 0;
	ps_operation->temp_mem_ref_count = 0;

	return OTZ_SUCCESS;
}

static int __otz_free_temp_shared_mem(struct otz_operation_t *ps_operation)
{
	struct otz_session_shared_mem_info mem_info;
	int i;
	int ret = 0;
	struct mm_struct *mm = current->mm;

	mem_info.service_id = ps_operation->session->service_id;
	mem_info.session_id = ps_operation->session->session_id;

	for (i = 0; i < ps_operation->temp_mem_ref_count; i++) {
		mem_info.user_mem_addr =
			(uint32_t)ps_operation->temp_mem[i].shared_mem;
		down_write(&mm->mmap_sem);
		ret = do_munmap(mm, (unsigned long)mem_info.user_mem_addr,
				ps_operation->temp_mem[i].length);
		up_write(&mm->mmap_sem);

		if (ret) {
			pr_err("otz do_munmap failed");
			ps_operation->s_errno = ret;
			return ret;
		}

		ret = __otz_client_shared_mem_free(
				ps_operation->session->device.fd, &mem_info);
		if (ret) {
			pr_err("otz free shared memory failed");
			ps_operation->s_errno = ret;
			return ret;
		}
	}

	return 0;
}

/**
 * Perform the previously prepared operation
 *
 * This function performs a previously prepared operation – issuing it to the
 * secure environment.
 * There are three kinds of operations that can be issued: opening a client
 * session, invoking a service command,
 * and closing a client session. Each type of operation is prepared with its
 * respective function, which returns the
 * operation structure to be used:
 *    otz_operation_prepare_open prepares an open session operation.
 *    otz_operation_prepare_invoke prepares an invoke service command operation.
 *    otz_operation_prepare_close prepares a close session operation.
 */
static otz_return_t otz_operation_perform(struct otz_operation_t *ps_operation,
		otz_return_t *pui_service_return)
{
	int ret = 0;
	struct ser_ses_id ses_close;
	struct ser_ses_id ses_open;
	struct otz_client_encode_cmd enc;
	struct otz_session ses_new;

	if (ps_operation == NULL || pui_service_return == NULL) {
		pr_err("operation_perform : Illegal argument");
		return OTZ_ERROR_ILLEGAL_ARGUMENT;
	}

	if (!(ps_operation->ui_state == OTZ_STATE_ENCODE ||
			ps_operation->ui_state == OTZ_STATE_PERFORMABLE)) {
		pr_err("operation_perform : Illegal state");
		return OTZ_ERROR_ILLEGAL_STATE;
	}

	ps_operation->ui_state = OTZ_STATE_RUNNING;

	/*
	 * For close operation the service cannot return a message
	 * The client cannot cancel or time-out the operation
	 * When this is complete irrespective of success or failure
	 * the session is considered close
	 *
	 * TODO: Convert into case
	 */
	if (ps_operation->type == OTZ_OPERATION_CLOSE) {
		if (ps_operation->session->operation_count == 1 &&
				ps_operation->session->shared_mem_cnt == 0){
			ses_close.service_id =
				ps_operation->session->service_id;
			ses_close.session_id =
				ps_operation->session->session_id;

			ret = __otz_client_session_close(
					ps_operation->session->device.fd,
					&ses_close);
			if (ret < 0) {
				*pui_service_return = OTZ_ERROR_GENERIC;
				ps_operation->ui_state = OTZ_STATE_INVALID;
				ps_operation->s_errno = ret;
				if (ret == -EFAULT)
					return OTZ_ERROR_ACCESS_DENIED;

				return OTZ_ERROR_UNDEFINED;
			} else if (ret > 0) {
				*pui_service_return = ret;
				ps_operation->ui_state = OTZ_STATE_INVALID;
				return OTZ_ERROR_SERVICE;
			}

			*pui_service_return = OTZ_SUCCESS;
			ps_operation->session->device.session_count--;
			memset(&ps_operation->session->device, 0,
					sizeof(struct otz_device_t));
			ps_operation->session->ui_state = OTZ_STATE_UNDEFINED;
			ps_operation->session->session_id = -1;
			ps_operation->session->service_id = OTZ_SVC_INVALID;
			ps_operation->ui_state = OTZ_STATE_INVALID;

			return OTZ_SUCCESS;
		} else {
			/* Undefined Behaviour */
			pr_err("Operation_cnt = %d  shared_mem_cnt = %d\n",
					ps_operation->session->operation_count,
					ps_operation->session->shared_mem_cnt);

			return OTZ_ERROR_GENERIC;
		}
	} else if (ps_operation->type == OTZ_OPERATION_OPEN) {
		ses_open.service_id = ps_operation->session->service_id;
		ret = __otz_client_session_open(
				ps_operation->session->device.fd,
				&ses_open, &ses_new);

		if (ret < 0) {
			*pui_service_return = OTZ_ERROR_GENERIC;
			ps_operation->ui_state = OTZ_STATE_INVALID;
			ps_operation->s_errno = ret;

			/*  The encoder ran out of space */
			if (ret == -ENOMEM)
				return OTZ_ERROR_MEMORY;
			if (ret == -EFAULT)
				return  OTZ_ERROR_ACCESS_DENIED;
			if (ret == -EINVAL)
				return  OTZ_ERROR_ILLEGAL_ARGUMENT;

			return OTZ_ERROR_UNDEFINED;
		} else if (ret > 0) {
			/* Operation reaches the service but it returns error */
			*pui_service_return = ret;
			/* The service may have a message for the client
			 * which can be decoded if needed */
			ps_operation->ui_state = OTZ_STATE_DECODE;

			return OTZ_ERROR_SERVICE;
		}

		ps_operation->session->device.session_count++;
		ps_operation->session->session_id = ses_open.session_id;
		*pui_service_return = OTZ_SUCCESS;
		ps_operation->ui_state = OTZ_STATE_DECODE;
		ps_operation->session->ui_state = OTZ_STATE_OPEN;

		return OTZ_SUCCESS;
	} else if (ps_operation->type == OTZ_OPERATION_INVOKE) {
		enc.encode_id = ps_operation->enc_dec.encode_id;
		enc.cmd_id = ps_operation->enc_dec.cmd_id;
		enc.service_id = ps_operation->session->service_id;
		enc.session_id = ps_operation->session->session_id;

		mutex_lock(&send_cmd_lock);
		ret = otz_client_kernel_send_cmd(
				(void *)ps_operation->session->device.fd,
				(void *)&enc);
		mutex_unlock(&send_cmd_lock);

		if (ret < 0) {
			*pui_service_return = OTZ_ERROR_GENERIC;
			ps_operation->ui_state = OTZ_STATE_INVALID;
			ps_operation->s_errno = ret;

			if (ret == -EFAULT)
				return  OTZ_ERROR_ACCESS_DENIED;
			if (ret == -EINVAL)
				return  OTZ_ERROR_ILLEGAL_ARGUMENT;

			return OTZ_ERROR_UNDEFINED;
		} else if (ret > 0) {
			/* Operation reaches the service but it returns error */
			*pui_service_return = ret;
			/* The service may have a message for the client
			 * which can be decoded if needed */
			ps_operation->ui_state = OTZ_STATE_DECODE;
			return OTZ_ERROR_SERVICE;
		}

		pr_debug("command succeded\n");
		*pui_service_return = OTZ_SUCCESS;
		ps_operation->ui_state = OTZ_STATE_DECODE;
		ps_operation->session->ui_state = OTZ_STATE_OPEN;
		ps_operation->enc_dec.encode_id = enc.encode_id;
		return OTZ_SUCCESS;
	}

	return OTZ_ERROR_UNDEFINED;
}

/**
 * Release an operation (open, send_command, close), and free all associated
 * resources.
 *
 * TODO: Look at return codes
 */
static int otz_operation_release(struct otz_operation_t *ps_operation)
{
	struct otz_client_encode_cmd enc;
	int ret = OTZ_SUCCESS;

	if (ps_operation == NULL) {
		pr_debug("ps_operation: Null operation");
		ret = -1;
		goto out;
	}

	if (!(ps_operation->ui_state == OTZ_STATE_ENCODE ||
			ps_operation->ui_state == OTZ_STATE_PERFORMABLE ||
			ps_operation->ui_state == OTZ_STATE_DECODE ||
			ps_operation->ui_state == OTZ_STATE_INVALID)) {
		pr_debug("ui_state: Illegal state - Undefined behaviour");
		ret = -1;
		goto out;
	}

	ps_operation->session->operation_count--;
	__otz_free_temp_shared_mem(ps_operation);

	if (ps_operation->ui_state == OTZ_STATE_ENCODE) {
		if (ps_operation->type == OTZ_OPERATION_OPEN) {
			ps_operation->session->device.session_count--;
			memset(&ps_operation->session->device, 0,
					sizeof(struct otz_device_t));
			ps_operation->session->ui_state = OTZ_STATE_UNDEFINED;
			ps_operation->session->session_id = -1;
			ps_operation->session->service_id = OTZ_SVC_INVALID;
		} else if (ps_operation->type == OTZ_OPERATION_INVOKE) {
			/* TODO: Perform necessary state reversal, etc */
		}
	} else if (ps_operation->ui_state == OTZ_STATE_PERFORMABLE) {
		/* Close operation has been prepared but not being given to service for
		 * implementation */
		if (ps_operation->type == OTZ_OPERATION_CLOSE)
			ps_operation->session->ui_state = OTZ_STATE_OPEN;
	} else if (ps_operation->ui_state == OTZ_STATE_DECODE) {
		enc.encode_id = ps_operation->enc_dec.encode_id;
		enc.cmd_id = ps_operation->enc_dec.cmd_id;
		enc.service_id = ps_operation->session->service_id;
		enc.session_id = ps_operation->session->session_id;

		ret = __otz_client_kernel_operation_release(
				ps_operation->session->device.fd, &enc);
		if (ret) {
			pr_err("otz_operation_release failed");
			ps_operation->s_errno = ret;
			goto out;
		}
	}

	ps_operation->session = NULL;
	ps_operation->ui_state = OTZ_STATE_UNDEFINED;
	ps_operation->type = OTZ_OPERATION_NONE;
	pr_debug("Releasing operation succeeded");

out:
	return ret;
}

static int otz_open_session(int service_id,
		struct trustzone_session *tz_session)
{
	struct otz_device_t device_otz;
	struct otz_session_t session_otz;
	struct otz_operation_t operation_otz;
	otz_return_t service_ret;
	u32 device_id;
	int ret = 0;

	ret = __otz_open_device(&device_id);
	if (ret) {
		pr_err("otz_open_session failed");
		goto out_error;
	}

	device_otz.fd = device_id;
	device_otz.ui_state = OTZ_STATE_OPEN;
	device_otz.session_count = 0;
	session_otz.ui_state = OTZ_STATE_UNDEFINED;
	operation_otz.ui_state = OTZ_STATE_UNDEFINED;

	ret = __otz_operation_prepare_open(&device_otz, service_id, NULL, NULL,
			&session_otz, &operation_otz);
	if (ret) {
		pr_err("otz session open prepare failed");
		goto out_error;
	}

	ret = otz_operation_perform(&operation_otz, &service_ret);
	if (ret != OTZ_SUCCESS) {
		if (ret == OTZ_ERROR_SERVICE)
			pr_err("%s\n", otz_strerror(service_ret));
		else
			pr_err("otz session open failed");

		session_otz.ui_state = OTZ_STATE_UNDEFINED;
		operation_otz.ui_state = OTZ_STATE_INVALID;
		otz_operation_release(&operation_otz);
		goto out_error;
	}

	ret = otz_operation_release(&operation_otz);
	if (ret != OTZ_SUCCESS) {
		pr_err("otz operation release failed");
		goto out_error;
	}

	tz_session->impl_session = kmalloc(sizeof(struct otz_session_t),
			GFP_KERNEL);
	if (tz_session->impl_session == NULL) {
		pr_err("kmalloc failed for otz_session_t");
		ret = -ENOMEM;
		goto out_error;
	}

	pr_debug("Allocate tz_session->impl_session: %dB",
			sizeof(tz_session->impl_session));
	memcpy(tz_session->impl_session, &session_otz,
			sizeof(struct otz_session_t));

	pr_debug("Return session information:\n \
		\t dev_file_id: %d\n \
		\t serv id: %d\n \
		\t ses id: %d\n",
		session_otz.device.fd,
		session_otz.service_id,
		session_otz.session_id);

out_error:
	return ret;
}

static int otz_close_session(struct trustzone_session *tz_session)
{
	struct otz_operation_t operation_otz;
	struct otz_session_t *session_otz;
	u32 device_id;
	otz_return_t service_ret;
	int ret = OTZ_SUCCESS;

	session_otz = (struct otz_session_t *)tz_session->impl_session;
	device_id = session_otz->device.fd;

	pr_debug("Closing session for:\n \
		\t dev_file_id: %d\n \
		\t serv id: %d\n \
		\t ses id: %d\n",
		session_otz->device.fd,
		session_otz->service_id,
		session_otz->session_id);

	operation_otz.ui_state = OTZ_STATE_UNDEFINED;

	ret = __otz_operation_prepare_close(session_otz, &operation_otz);
	if (ret != OTZ_SUCCESS) {
		pr_err("otz session close prepare failed");
		otz_operation_release(&operation_otz);
		goto out_error;
	}

	ret = otz_operation_perform(&operation_otz, &service_ret);
	if (ret != OTZ_SUCCESS) {
		if (ret == OTZ_ERROR_SERVICE)
			pr_err("%s\n", otz_strerror(service_ret));
		else
			pr_err("otz session close failed");

		operation_otz.ui_state = OTZ_STATE_INVALID;
		otz_operation_release(&operation_otz);
		goto out_error;
	}

	ret = otz_operation_release(&operation_otz);
	if (ret != OTZ_SUCCESS) {
		pr_err("otz operation release failed");
		goto out_error;
	}

	/* XXX: should this be placed in a separate trustzone operation? */
	ret = __otz_close_device(device_id);
	if (ret != OTZ_SUCCESS) {
		pr_err("otz close device failed");
		goto out_error;
	}

	pr_debug("Freeing session_otz: %dB", sizeof(session_otz));
	kfree(session_otz);
	pr_debug("Close session (and device) succeeded\n");

out_error:
	return ret;
}


/**
 * TODO: Describe
 *
 * It is the caller's responsability to free memory for each parameter
 * (input and output). Output parameters are allocated in here, since the size
 * of the output coming from the secure world can be unknown. It is however the
 * caller's responsability to specify the type of the return parameter
 * correctly.
 */
static int otz_invoke_command(struct trustzone_session *tz_session,
		struct trustzone_cmd *cmd,
		struct trustzone_parameter_list *params)
{
	struct otz_operation_t operation_otz;
	otz_return_t service_ret;
	struct otz_session_t *session_otz;
	uint32_t ui_command = (uint32_t)cmd->cmd;
	int out_params = 0, out_data_len, i;
	int ret = OTZ_SUCCESS, aux;
	struct trustzone_parameter *param;

	session_otz = (struct otz_session_t *)tz_session->impl_session;

	pr_debug("Invoke Command:\n \
		\t dev_file_id: %d\n \
		\t serv id: %d\n \
		\t ses id: %d\n",
		session_otz->device.fd,
		session_otz->service_id,
		session_otz->session_id);

	operation_otz.ui_state = OTZ_STATE_UNDEFINED;
	ret = __otz_operation_prepare_invoke(session_otz, ui_command, NULL,
			&operation_otz);
	if (ret != OTZ_SUCCESS) {
		pr_err("otz_invoke_command failed\n");
		/*
		 * TODO: Here we need to clean the session if it fails. This
		 * might have to happen in trustzone.c so that this is at a
		 * generic level...
		 */
	}

	if (params != NULL) {
		pr_debug("Sending command with %d parameters", params->n_params);
		param = params->params;
		for (i = 0; i < params->n_params; i++) {
			if (param->type == TZ_UINT8) {
				/* TODO */
			} else if (param->type == TZ_UINT32) {
				pr_debug("Encode UINT32. val:%d",
						*(int *)param->value);
				otz_encode_uint32(&operation_otz, param->value,
						param->inout);
				if (operation_otz.enc_dec.enc_error_state !=
						OTZ_SUCCESS) {
					pr_err("otz encode failed\n");
					ret = operation_otz.enc_dec.enc_error_state;
					goto out_release;
				}
			} else if (param->type == TZ_GENERIC) {
				pr_debug("Decode MEMREF (GENERIC)");
				otz_encode_array(&operation_otz, param->value,
						param->size, param->inout);
				/*
				 * TODO: We need to pass more parameters
				 * regarding shared memory, among them, how much
				 * shared memory it is going to be. It is still
				 * not clear weather the memory should be
				 * handled by the caller or here...
				 */
				/* shared_mem.ui_length = 1024; */

				/*
				 * TODO: Need to refine this and pass it as
				 * parameter - depeds of course of how the
				 * interfaces looks like in the end.
				 */
				/* shared_mem.ui_flags = OTZ_MEM_SERVICE_RW; */
				/* otz_shared_memory_allocate( */
						/* operation_otz.session,
						 * &shared_mem); */
				/* if (ret != OTZ_SUCCESS) { */
					/* pr_err("shared memory allocation failed\n"); */
					/* //TODO: Should we close session here? otzapp does */
					/* goto out_release; */
				/* } */

				/* otz_encode_memory_reference(&operation_otz, &shared_mem, 0, */
						/* param->size, OTZ_MEM_SERVICE_RW, OTZ_PARAM_OUT); */
				/* if(operation_otz.enc_dec.enc_error_state != OTZ_SUCCESS) { */
				/* printk(KERN_CRIT "encoding memory reference failed\n"); */
					/* goto out_release; */
				/* } */
			} else {
				pr_err("otz_invoke_command wrong parameter type");
				ret = OTZ_ERROR_ENCODE_FORMAT;
			}

			if (param->inout == TZ_PARAM_OUT)
				out_params++;

			if (param->nxt != NULL)
				param = param->nxt;
		}
	}

	ret = otz_operation_perform(&operation_otz, &service_ret);
	if (ret != OTZ_SUCCESS) {
		if (ret == OTZ_ERROR_SERVICE)
			pr_err("%s\n", otz_strerror(service_ret));
		else
			pr_err("otz invoke_command failed\n");

		goto out_release;
	}

	/* XXX: Do this more efficient. We should have a list of out parameters */
	if (params != NULL) {
		param = params->params;
		/* for (i = 0; out_params > 0; i++) { */
		for (i = 0; i < params->n_params; i++) {
			if (param->inout == TZ_PARAM_OUT) {
				if (param->type == TZ_UINT8) {
					/* XXX: TODO */
				} else if (param->type == TZ_UINT32) {
					pr_debug("Decode UINT32");
					aux = otz_decode_uint32(&operation_otz);
					param->value = (void *)&aux;
					if (operation_otz.enc_dec.enc_error_state ==
							OTZ_SUCCESS) {
						pr_debug("out data = %d, type: uint32_t",
								*(int *)param->value);
					} else {
						pr_err("otz_invoke_command decode datafailed\n");
						ret = operation_otz.enc_dec.enc_error_state;
						goto out_release;
					}
				} else if (param->type == TZ_GENERIC) {
					pr_debug("Decode MEMREF (GENERIC)");
					param->value = (void *)otz_decode_array_space(
							&operation_otz, &out_data_len);
					param->size = (uint32_t)out_data_len;
					if (operation_otz.enc_dec.enc_error_state == OTZ_SUCCESS) {
						pr_debug("out data = %s, type: generic",
								(char *)param->value);
					} else {
						pr_err("otz_invoke_command decode data failed");
						ret = operation_otz.enc_dec.enc_error_state;
						goto out_release;
					}
				}
			}

			if (param->nxt != NULL)
				param = param->nxt;

			/* if (i > out_params) { */
				/* printk(KERN_CRIT "otz_invoke_command internal decoding error\n"); */
				/* ret = OTZ_ERROR_DECODE_NO_DATA; */
				/* goto out_release; */
			/* } */
		}
	}

out_release:
	/* kfree(session_otz); */
	/* XXX:HERE WE NEED TO CLOSE SESSION */
	otz_operation_release(&operation_otz);
	if (ret != OTZ_SUCCESS) {
		pr_err("otz operation release failed");
		goto out_error;
	}

out_error:
	return ret;
}

static int otz_shared_mem_alloc(void)
{
	return 0;
}

static int otz_shared_mem_regist(void)
{
	return 0;
}

static int otz_shared_mem_free(void)
{
	return 0;
}

/**
 * Appends a reference of previously allocated shared block to the
 * encoded buffer
 *
 * Calling this function appends a reference to a range of a previously created
 * shared memory block.
 *
 * Memory references are used to provide a synchronization token protocol which
 * informs the service when it can read from or write to a portion of the shared
 * memory block. A memory reference is associated with a specific operation and
 * is valid only during the execution of that operation.
 */
void otz_encode_memory_reference(struct otz_operation_t *ps_operation,
		struct otz_shared_mem_t *ps_shared_mem,
		uint32_t offset,
		uint32_t length,
		uint32_t flags,
		int param_type)
{
	struct otz_client_encode_cmd enc;
	int ret;

	if (check_encode(ps_operation))
		goto return_func;

	if (ps_shared_mem == NULL) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_FORMAT;
		goto return_func;
	}

	if ((flags == OTZ_MEM_SERVICE_RO) &&
			(ps_shared_mem->ui_flags != OTZ_MEM_SERVICE_RO &&
			ps_shared_mem->ui_flags != OTZ_MEM_SERVICE_RW)) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_FORMAT;
		goto return_func;
	}

	if ((flags == OTZ_MEM_SERVICE_WO) &&
			(ps_shared_mem->ui_flags != OTZ_MEM_SERVICE_WO &&
			 ps_shared_mem->ui_flags != OTZ_MEM_SERVICE_RW)) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_FORMAT;
		goto return_func;
	}

	if (param_type == OTZ_PARAM_IN && flags == OTZ_MEM_SERVICE_WO) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_FORMAT;
		goto return_func;
	}

	if (param_type == OTZ_PARAM_OUT && flags == OTZ_MEM_SERVICE_RO) {
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_FORMAT;
		goto return_func;
	}

	if (((offset + length) >  ps_shared_mem->ui_length)) {
		ps_operation->enc_dec.enc_error_state =  OTZ_ERROR_ENCODE_MEMORY;
		goto return_func;
	}

	if (ps_operation->shared_mem_ref_count >= MAX_MEMBLOCKS_PER_OPERATION) {
		ps_operation->enc_dec.enc_error_state =  OTZ_ERROR_ENCODE_MEMORY;
		goto return_func;
	}

	enc.encode_id = ps_operation->enc_dec.encode_id;
	enc.cmd_id = ps_operation->enc_dec.cmd_id;
	enc.service_id = ps_operation->session->service_id ;
	enc.session_id = ps_operation->session->session_id ;
	enc.data = ps_shared_mem->p_block;
	enc.len  = length;
	enc.offset = offset;
	enc.flags = flags;
	enc.param_type = param_type;

	mutex_lock(&encode_cmd_lock);
	ret = __otz_client_kernel_encode_mem_ref(
			(void *)ps_operation->session->device.fd, &enc);
	mutex_unlock(&encode_cmd_lock);

	if (ret) {
		pr_err("error encoding kernel mem-ref for device %d",
				ps_operation->session->device.fd);
		ps_operation->enc_dec.enc_error_state = OTZ_ERROR_ENCODE_MEMORY;
		ps_operation->s_errno = ret;
	} else {
		ps_operation->enc_dec.encode_id = enc.encode_id;
		ps_operation->shared_mem[ps_operation->shared_mem_ref_count].shared_mem
			= ps_shared_mem;
		ps_operation->shared_mem[ps_operation->shared_mem_ref_count].offset
			= offset;
		ps_operation->shared_mem[ps_operation->shared_mem_ref_count].length
			= length;
		ps_operation->shared_mem[ps_operation->shared_mem_ref_count].param_type
			= param_type;
		ps_operation->shared_mem_ref_count++;
	}

return_func:
	return;
}


/**
 * This function allocates a block of memory, defined by the structure
 * pointed to by ps_shared_mem, which is shared between the client and the
 * service it is connected to.
 *
 * This function allocates a block of memory, defined by the structure pointed
 * to by ps_shared_mem, which is shared
 * between the client and the service it is connected to.
 */
static otz_return_t otz_shared_memory_allocate(struct otz_session_t *ps_session,
		struct otz_shared_mem_t *ps_shared_mem)
{
	int ret = 0;
	struct otz_session_shared_mem_info mem_info;

	if (ps_session == NULL || ps_shared_mem == NULL) {
		pr_err("shr_mem_allocate : Error Illegal argument\n");
		return OTZ_ERROR_ILLEGAL_ARGUMENT;
	}

	if (ps_session->ui_state != OTZ_STATE_OPEN ||
			ps_shared_mem->ui_length == 0 ||
			(ps_shared_mem->ui_flags != OTZ_MEM_SERVICE_RO &&
			 ps_shared_mem->ui_flags != OTZ_MEM_SERVICE_WO &&
			 ps_shared_mem->ui_flags != OTZ_MEM_SERVICE_RW)) {
		pr_err("shr_mem_allocate : Error Illegal state\n");
		return OTZ_ERROR_ILLEGAL_STATE;
	}

	ps_shared_mem->p_block = NULL;

	/* if(ps_shared_mem->ui_flags ==  OTZ_MEM_SERVICE_RO) */
		/* mmap_flags =  PROT_READ; */
	/* else if(ps_shared_mem->ui_flags ==  OTZ_MEM_SERVICE_WO) */
		/* mmap_flags =  PROT_WRITE; */
	/* else if(ps_shared_mem->ui_flags ==  OTZ_MEM_SERVICE_RW) */
		/* mmap_flags = PROT_READ | PROT_WRITE; */

	pr_debug("shared mem len %d", ps_shared_mem->ui_length);
	pr_debug("shared mem fd  %d", ps_session->device.fd);

	/* TODO:Look at the flags */
	ps_shared_mem->p_block = kernel_mmap(ps_session->device.fd,
			ps_shared_mem->ui_length);

	pr_debug("return from kernel_mmap");
	pr_debug("mmap u_addr  %p", (uint32_t *)ps_shared_mem->p_block);

	if (ps_shared_mem->p_block != NULL) {
		mem_info.service_id = ps_session->service_id;
		mem_info.session_id = ps_session->session_id;
		mem_info.user_mem_addr = (uint32_t)ps_shared_mem->p_block;
		ret = __otz_client_shared_mem_alloc(ps_session->device.fd,
				&mem_info);
	} else {
		pr_err("otz_shared_memory_allocate - kernel_mmap failed");
		ps_shared_mem->s_errno = ret;
		ret = -1;
	}

	if (ret == 0) {
		ps_shared_mem->ui_state = OTZ_STATE_OPEN;
		ps_shared_mem->session = ps_session;
		ps_shared_mem->operation_count = 0;
		INIT_LIST_HEAD(&ps_shared_mem->head_ref);
		list_add_tail(&ps_session->shared_mem_list,
				&ps_shared_mem->head_ref);
		ps_session->shared_mem_cnt++;
		return OTZ_SUCCESS;
	} else {
		pr_debug("shared_mem_allocation_failed");
		ps_shared_mem->s_errno = ret;
		ps_shared_mem->ui_state = OTZ_STATE_INVALID;
		ps_shared_mem->ui_length = 0 ;
		ps_shared_mem->ui_flags = OTZ_MEM_SERVICE_UNDEFINED;
		ps_shared_mem->p_block = NULL ;
		ps_shared_mem->session = NULL;
		return OTZ_ERROR_MEMORY;
	}

	return OTZ_ERROR_UNDEFINED;
}


/**
 * Device driver generic file operations
 */
static const struct file_operations otz_client_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = otz_client_ioctl,
	.open = otz_client_open,
	.mmap = otz_client_mmap,
	.release = otz_client_release
};

/* static struct attribute* otz_attrs[] = { */
	/* &dev_attr_pubek.attr, */
	/* &dev_attr_pcrs.attr, */
	/* &dev_attr_caps.attr, */
	/* &dev_attr_canter.attr, */
	/* NULL, */
/* }; */
/* struct attribute_group otz_attr_grp = { .attrs = otz_attrs}; */

/**
 * TrustZone generic operations
 */
static const struct trustzone_operations tz_sierra = {
	.name = "sierra_otz",
	/* .attr_group = &otz_attr_grp, */
	.miscdev = { .fops = &otz_client_fops},
	.open = otz_open_session,
	.close = otz_close_session,
	.invoke_command = otz_invoke_command,
	.install_task = NULL,
	.delete_task = NULL,
	.install_primitive = NULL,
	.delete_primitive = NULL,

	.memory_allocate = otz_shared_mem_alloc,
	.memory_register = otz_shared_mem_regist,
	.memory_free = otz_shared_mem_free,
};

static int otz_client_init(void)
{
	int ret_code = 0;
	struct device *class_dev;
	struct trustzone_chip *chip;

	pr_debug("OTZ_CLIENT_INIT_DEBUG");
	otz_client_smc_init();

	ret_code = alloc_chrdev_region(&otz_client_device_no, 0, 1,
			OTZ_CLIENT_DEV);
	if (ret_code < 0) {
		pr_err("alloc_chrdev_region failed %d", ret_code);
		return ret_code;
	}

	driver_class = class_create(THIS_MODULE, OTZ_CLIENT_DEV);
	if (IS_ERR(driver_class)) {
		ret_code = -ENOMEM;
		pr_err("class_create failed %d", ret_code);
		goto unregister_chrdev_region;
	}

	class_dev = device_create(driver_class, NULL, otz_client_device_no,
			NULL, OTZ_CLIENT_DEV);
	if (!class_dev) {
		pr_err("class_device_create failed %d", ret_code);
		ret_code = -ENOMEM;
		goto class_destroy;
	}

	cdev_init(&otz_client_cdev, &otz_client_fops);
	otz_client_cdev.owner = THIS_MODULE;

	ret_code = cdev_add(&otz_client_cdev,
			MKDEV(MAJOR(otz_client_device_no), 0), 1);
	if (ret_code < 0) {
		pr_err("cdev_add failed %d", ret_code);
		goto class_device_destroy;
	}

	/* Initialize structure for services and sessions*/
	pr_debug("Initializing list for servires\n");
	memset(&otzc_dev_file_head, 0, sizeof(otzc_dev_file_head));
	otzc_dev_file_head.dev_file_cnt = 0;
	INIT_LIST_HEAD(&otzc_dev_file_head.dev_file_list);

#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
	register_secure_notify_handler(ipi_secure_notify);
#endif

	/* Register as a TrustZone device */
	chip = trustzone_register_hardware(class_dev, &tz_sierra);
	if (!chip) {
		ret_code = -ENODEV;
		goto class_device_destroy;
	}

	/*
	 * XXX: You have to look into regions and iobase. I don't know if this
	 * is relevant her or not.
	 */

	return ret_code;

class_device_destroy:
	device_destroy(driver_class, otz_client_device_no);
class_destroy:
	class_destroy(driver_class);
unregister_chrdev_region:
	unregister_chrdev_region(otz_client_device_no, 1);
	return ret_code;
}

static void otz_client_exit(void)
{
	pr_debug("otz_client exit");

#ifdef OTZONE_ASYNC_NOTIFY_SUPPORT
	unregister_secure_notify_handler();
#endif
	device_destroy(driver_class, otz_client_device_no);
	class_destroy(driver_class);
	unregister_chrdev_region(otz_client_device_no, 1);
}

module_init(otz_client_init);
module_exit(otz_client_exit);

MODULE_AUTHOR("Sierraware  <sierraware.org>");
MODULE_AUTHOR("Javier Gonzalez <jgon@itu.dk>");
MODULE_DESCRIPTION("Sierraware TrustZone Driver");
MODULE_VERSION("1.00");
MODULE_LICENSE("GPL v2");

