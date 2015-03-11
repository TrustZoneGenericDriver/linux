/*
 * Copyright (c) 2015, Linaro Limited
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

#ifndef __TEE_DRV_H
#define __TEE_DRV_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/sec-hw/tee.h>

/*
 * The file describes the API provided by the generic TEE driver to the
 * specific TEE driver.
 */

#define TEE_SHM_MAPPED		0x1	/* Memory mapped by the kernel */
#define TEE_SHM_DMA_BUF		0x2	/* Memory with dma-buf handle */

#define TEE_UUID_SIZE		16

struct tee_device;
struct tee_shm;


/**
 * struct tee_filp - driver specific file pointer data
 * @teedev:	pointer to this drivers struct tee_device
 * @filp_data:	driver specific file pointer data, managed by the driver
 */
struct tee_filp {
	struct tee_device *teedev;
	void *filp_data;
};

/**
 * struct tee_driver_ops - driver operations vtable
 * @get_version:	returns version of driver
 * @open:		called when the device file is opened
 * @release:		release this open file
 * @cmd:		process a command from user space
 * @shm_share:		share some memory with Secure OS
 * @shm_unshare:	unshare some memory with Secure OS
 */
struct tee_driver_ops {
	void (*get_version)(struct tee_filp *teefilp, u32 *version, u8 *uuid);
	int (*open)(struct tee_filp *teefilp);
	void (*release)(struct tee_filp *teefilp);
	int (*cmd)(struct tee_filp *teefilp, void __user *buf, size_t len);
	int (*shm_share)(struct tee_shm *shm);
	void (*shm_unshare)(struct tee_shm *shm);
};

/**
 * struct tee_desc - Describes the TEE driver to the subsystem
 * @name:	name of driver
 * @ops:	driver operations vtable
 * @owner:	module providing the driver
 * @flags:	Extra properties of driver, defined by TEE_DESC_* below
 */
#define TEE_DESC_PRIVILEGED	0x1
struct tee_desc {
	const char *name;
	const struct tee_driver_ops *ops;
	struct module *owner;
	u32 flags;
};


/**
 * tee_register() - Register a specific TEE driver
 * @teedesc:		Descriptor for this driver
 * @dev:		Parent device for this driver
 * @driver_data:	Private driver data for this driver
 *
 * Once the specific driver has been probed it registers in the generic
 * driver with this function.
 *
 * @returns a pointer to struct tee_device
 */
struct tee_device *tee_register(const struct tee_desc *teedesc,
			struct device *dev, void *driver_data);

/**
 * tee_unregister() - Unregister a specific TEE driver
 * @teedev:	Driver to unregister
 */
void tee_unregister(struct tee_device *teedev);

/**
 * tee_get_drvdata() - Return driver_data pointer
 * @returns the driver_data pointer supplied to tee_register().
 */
void *tee_get_drvdata(struct tee_device *teedev);

/**
 * tee_shm_alloc() - Allocate shared memory
 * @teedev:	Driver that allocates the shared memory
 * @teefilp:	TEE file pointer when allocating global shared memory, must be
 *		NULL for driver private shared memory.
 * @size:	Requested size of shared memory
 * @flags:	Flags setting properties for the requested shared memory.
 *
 * Memory allocated as global shared memory is automatically freed when the
 * TEE file pointer is closed. The @flags field uses the bits defined by
 * TEE_SHM_* above. TEE_SHM_MAPPED must currently always be set. If
 * TEE_SHM_DMA_BUF global shared memory will be allocated and associated
 * with a dma-buf handle, else driver private memory.
 *
 * @returns a pointer to 'struct tee_shm'
 */
struct tee_shm *tee_shm_alloc(struct tee_device *teedev,
			struct tee_filp *teefilp, size_t size, u32 flags);

/**
 * tee_shm_free() - Free shared memory
 * @shm:	Handle to shared memory to free
 */
void tee_shm_free(struct tee_shm *shm);

/**
 * tee_shm_find_by_va() - Find a shared memory handle by a virtual address
 * @teedev:	The device that owns the shared memory
 * @flags:	Select which type of shared memory to locate, if
 *		TEE_SHM_DMA_BUF global shared memory else driver private
 *		shared memory.
 * @va:		Virtual address covered by the shared memory
 * @returns a Handle to shared memory
 */
struct tee_shm *tee_shm_find_by_va(struct tee_device *teedev, u32 flags,
			void *va);
/**
 * tee_shm_find_by_pa() - Find a shared memory handle by a physical address
 * @teedev:	The device that owns the shared memory
 * @flags:	Select which type of shared memory to locate, if
 *		TEE_SHM_DMA_BUF global shared memory else driver private
 *		shared memory.
 * @pa:		Physical address covered by the shared memory
 * @returns a Handle to shared memory
 */
struct tee_shm *tee_shm_find_by_pa(struct tee_device *teedev, u32 flags,
			phys_addr_t pa);

/**
 * tee_shm_va2pa() - Get physical address of a virtual address
 * @shm:	Shared memory handle
 * @va:		Virtual address to tranlsate
 * @pa:		Returned physical address
 * @returns 0 on success and < 0 on failure
 */
int tee_shm_va2pa(struct tee_shm *shm, void *va, phys_addr_t *pa);

/**
 * tee_shm_pa2va() - Get virtual address of a physical address
 * @shm:	Shared memory handle
 * @pa:		Physical address to tranlsate
 * @va:		Returned virtual address
 * @returns 0 on success and < 0 on failure
 */
int tee_shm_pa2va(struct tee_shm *shm, phys_addr_t pa, void **va);

/**
 * tee_shm_get_size() - Get size of a shared memory
 * @returns the size of the shared memory
 */
size_t tee_shm_get_size(struct tee_shm *shm);

/**
 * tee_shm_get_va() - Get virtual address of a shared memory plus an offset
 * @shm:	Shared memory handle
 * @offs:	Offset from start of this shared memory
 * @returns virtual address of the shared memory + offs if offs is within
 *	the bounds of this shared memory, else an ERR_PTR
 */
void *tee_shm_get_va(struct tee_shm *shm, size_t offs);

/**
 * tee_shm_get_pa() - Get physical address of a shared memory plus an offset
 * @shm:	Shared memory handle
 * @offs:	Offset from start of this shared memory
 * @pa:		Physical address to return
 * @returns 0 if offs is within the bounds of this shared memory, else an
 *	error code.
 */
int tee_shm_get_pa(struct tee_shm *shm, size_t offs, phys_addr_t *pa);

/**
 * tee_shm_get_from_fd() - Get a shared memory handle from a file descriptor
 * @fd:		A user space file descriptor
 *
 * This function increases the reference counter on the shared memory and
 * returns a handle.
 * @returns handle to shared memory
 */
struct tee_shm *tee_shm_get_from_fd(int fd);

/**
 * tee_shm_put() - Decrease reference count on a shared memory handle
 * @shm:	Shared memory handle
 */
void tee_shm_put(struct tee_shm *shm);

#endif /*__TEE_DRV_H*/
