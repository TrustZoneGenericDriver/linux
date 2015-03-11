/* * Copyright (c) 2015, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef TEE_PRIVATE_H
#define TEE_PRIVATE_H

#define TEE_MAX_DEV_NAME_LEN 32
struct tee_device {
	char name[TEE_MAX_DEV_NAME_LEN];
	const struct tee_desc *desc;
	struct device *dev;
	struct miscdevice miscdev;
	struct list_head list_shm;
	struct mutex mutex;
	void *driver_data;
};

struct tee_shm {
	struct list_head list_node;
	struct tee_device *teedev;
	struct tee_filp *teefilp;
	phys_addr_t paddr;
	void *kaddr;
	size_t size;
	struct dma_buf *dmabuf;
	u32 flags;
};

int tee_shm_fd(struct tee_shm *shm);
void tee_shm_free_by_teefilp(struct tee_filp *teefilp);


#endif /*TEE_PRIVATE_H*/
