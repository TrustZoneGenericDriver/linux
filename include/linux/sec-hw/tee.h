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

#ifndef __TEE_H
#define __TEE_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * This file describes the API provided by the generic TEE driver to user
 * space
 */


/* Helpers to make the ioctl defines */
#define TEE_IOC_MAGIC	0xa4
#define TEE_IOC_BASE	0
#define _TEE_IOR(nr, size)	_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + (nr), size)
#define _TEE_IOWR(nr, size)	_IOWR(TEE_IOC_MAGIC, TEE_IOC_BASE + (nr), size)
#define _TEE_IOW(nr, size)	_IOW(TEE_IOC_MAGIC, TEE_IOC_BASE + (nr), size)

/*
 * Version of the generic TEE subsystem, if it doesn't match what's
 * returned by TEE_IOC_VERSION this header is not in sync with the kernel.
 */
#define TEE_SUBSYS_VERSION	1


/* Flags relating to shared memory */
#define TEE_IOCTL_SHM_MAPPED	0x1	/* memory mapped in normal world */
#define TEE_IOCTL_SHM_DMA_BUF	0x2	/* dma-buf handle on shared memory */

/**
 * struct tee_version - TEE versions
 * @gen_version:	[out] Generic TEE driver version
 * @spec_version:	[out] Specific TEE driver version
 * @uuid:		[out] Specific TEE driver uuid, zero if not used
 *
 * Identifies the generic TEE driver, and the specific TEE driver.
 * Used as argument for TEE_IOC_VERSION below.
 */
struct tee_ioctl_version {
	uint32_t gen_version;
	uint32_t spec_version;
	uint8_t uuid[16];
};
/**
 * TEE_IOC_VERSION - query version of drivers
 *
 * Takes a tee_version struct and returns with the version numbers filled in.
 */
#define TEE_IOC_VERSION		_TEE_IOR(0, struct tee_ioctl_version)

/**
 * struct tee_cmd_data - Opaque command argument
 * @buf_ptr:	[in] A __user pointer to a command buffer
 * @buf_len:	[in] Length of the buffer above
 *
 * Opaque command data which is passed on to the specific driver. The command
 * buffer doesn't have to reside in shared memory.
 * Used as argument for TEE_IOC_CMD below.
 */
struct tee_ioctl_cmd_data {
	uint64_t buf_ptr;
	uint64_t buf_len;
};
/**
 * TEE_IOC_CMD - pass a command to the specific TEE driver
 *
 * Takes tee_cmd_data struct which is passed to the specific TEE driver.
 */
#define TEE_IOC_CMD		_TEE_IOR(1, struct tee_ioctl_cmd_data)

/**
 * struct tee_shm_alloc_data - Shared memory allocate argument
 * @size:	[in/out] Size of shared memory to allocate
 * @flags:	[in/out] Flags to/from allocation.
 * @fd:		[out] dma_buf file descriptor of the shared memory
 *
 * The flags field should currently be zero as input. Updated by the call
 * with actual flags as defined by TEE_IOCTL_SHM_* above.
 * This structure is used as argument for TEE_IOC_SHM_ALLOC below.
 */
struct tee_ioctl_shm_alloc_data {
	uint64_t size;
	uint32_t flags;
	int32_t fd;
};
/**
 * TEE_IOC_SHM_ALLOC - allocate shared memory
 *
 * Allocates shared memory between the user space process and secure OS.
 * The returned file descriptor is used to map the shared memory into user
 * space. The shared memory is freed when the descriptor is closed and the
 * memory is unmapped.
 */
#define TEE_IOC_SHM_ALLOC	_TEE_IOWR(2, struct tee_ioctl_shm_alloc_data)

/**
 * struct tee_mem_buf - share user space memory with Secure OS
 * @ptr:	A __user pointer to memory to share
 * @size:	Size of the memory to share
 * Used in 'struct tee_mem_share_data' below.
 */
struct tee_ioctl_mem_buf {
	uint64_t ptr;
	uint64_t size;
};

/**
 * struct tee_mem_dma_buf - share foreign dma_buf memory
 * @fd:		dma_buf file descriptor
 * @pad:	padding, set to zero by caller
 * Used in 'struct tee_mem_share_data' below.
 */
struct tee_ioctl_mem_dma_buf {
	int32_t fd;
	uint32_t pad;
};

/**
 * struct tee_mem_share_data - share memory with Secure OS
 * @buf:	[in] share user space memory
 * @dma_buf:	[in] share foreign dma_buf memory
 * @flags:	[in/out] Flags to/from sharing.
 * @pad:	[in/out] Padding, set to zero by caller
 *
 * The bits in @flags are defined by TEE_IOCTL_SHM_* above, undefined bits
 * should be seto to zero as input. If TEE_IOCTL_SHM_DMA_BUF is set in the
 * flags field use the dma_buf field, else the buf field in the union.
 *
 * Used as argument for TEE_IOC_MEM_SHARE and TEE_IOC_MEM_UNSHARE below.
 */
struct tee_ioctl_mem_share_data {
	union {
		struct tee_ioctl_mem_buf buf;
		struct tee_ioctl_mem_dma_buf dma_buf;
	};
	uint32_t flags;
	uint32_t pad;
};

/**
 * TEE_IOC_MEM_SHARE - share a portion of user space memory with secure OS
 *
 * Shares a portion of user space memory with secure OS.
 */
#define TEE_IOC_MEM_SHARE	_TEE_IOWR(3, struct tee_ioctl_mem_share_data)

/**
 * TEE_IOC_MEM_UNSHARE - unshares a portion shared user space memory
 *
 * Unshares a portion of previously shared user space memory.
 */
#define TEE_IOC_MEM_UNSHARE	_TEE_IOW(4, struct tee_ioctl_mem_share_data)

/*
 * Five syscalls are used when communicating with the generic TEE driver.
 * open(): opens the device associated with the driver
 * ioctl(): as described above operating on the file descripto from open()
 * close(): two cases
 *   - closes the device file descriptor
 *   - closes a file descriptor connected to allocated shared memory
 * mmap(): maps shared memory into user space
 * munmap(): unmaps previously shared memory
 */

#endif /*__TEE_H*/
