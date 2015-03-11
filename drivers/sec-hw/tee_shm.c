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
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/slab.h>
#include <linux/sec-hw/tee_drv.h>
#include "tee_private.h"

static DEFINE_MUTEX(teeshm_list_mutex);
static LIST_HEAD(teeshm_list);
static LIST_HEAD(teeshm_pending_free_list);

static void tee_shm_release(struct tee_shm *shm);

static struct sg_table *tee_shm_op_map_dma_buf(struct dma_buf_attachment
			*attach, enum dma_data_direction dir)
{
	return NULL;
}

static void tee_shm_op_unmap_dma_buf(struct dma_buf_attachment *attach,
			struct sg_table *table, enum dma_data_direction dir)
{
}

static void tee_shm_op_release(struct dma_buf *dmabuf)
{
	struct tee_shm *shm = dmabuf->priv;

	tee_shm_release(shm);
}

static void *tee_shm_op_kmap_atomic(struct dma_buf *dmabuf,
			unsigned long pgnum)
{
	return NULL;
}

static void *tee_shm_op_kmap(struct dma_buf *dmabuf, unsigned long pgnum)
{
	return NULL;
}

static int tee_shm_op_mmap(struct dma_buf *dmabuf,
			struct vm_area_struct *vma)
{
	struct tee_shm *shm = dmabuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	return remap_pfn_range(vma, vma->vm_start, shm->paddr >> PAGE_SHIFT,
			       size, vma->vm_page_prot);
}

static struct dma_buf_ops tee_shm_dma_buf_ops = {
	.map_dma_buf = tee_shm_op_map_dma_buf,
	.unmap_dma_buf = tee_shm_op_unmap_dma_buf,
	.release = tee_shm_op_release,
	.kmap_atomic = tee_shm_op_kmap_atomic,
	.kmap = tee_shm_op_kmap,
	.mmap = tee_shm_op_mmap,
};

struct tee_shm *tee_shm_alloc(struct tee_device *teedev,
			struct tee_filp *teefilp, size_t size, u32 flags)
{
	struct tee_shm *shm;
	void *ret;
	struct mutex *mutex;
	struct list_head *list_shm;

	if (!(flags & TEE_SHM_MAPPED)) {
		dev_err(teedev->dev, "only mapped allocations supported\n");
		return ERR_PTR(-EINVAL);
	}

	if ((flags & ~(TEE_SHM_MAPPED|TEE_SHM_DMA_BUF))) {
		dev_err(teedev->dev, "invalid shm flags 0x%x", flags);
		return ERR_PTR(-EINVAL);
	}

	shm = kzalloc(sizeof(struct tee_shm), GFP_KERNEL);
	if (!shm)
		return ERR_PTR(-ENOMEM);

	shm->flags = flags;

	if (flags & TEE_SHM_DMA_BUF) {
		int order = get_order(size);

		/* Global shm's must have a teefilp attached */
		if (!teefilp) {
			ret = ERR_PTR(-EINVAL);
			goto err;
		}

		shm->teefilp = teefilp;
		shm->size = (1 << order) << PAGE_SHIFT;
		/* Request zeroed pages to not leak information */
		shm->kaddr = (void *)__get_free_pages(GFP_KERNEL|__GFP_ZERO,
						      order);
		if (!shm->kaddr) {
			dev_err(teedev->dev,
				"failed to get order %d pages for shared memory\n",
				order);
			ret = ERR_PTR(-ENOMEM);
			goto err;
		}

		shm->dmabuf = dma_buf_export(shm, &tee_shm_dma_buf_ops,
					     shm->size, O_RDWR, NULL);
		if (IS_ERR(shm->dmabuf)) {
			ret = ERR_CAST(shm->dmabuf);
			goto err;
		}

		mutex = &teeshm_list_mutex;
		list_shm = &teeshm_list;
	} else {
		/* Driver private shm's must not have a teefilp attached */
		if (teefilp) {
			ret = ERR_PTR(-EINVAL);
			goto err;
		}
		shm->size = size;
		shm->kaddr = kzalloc(size, GFP_KERNEL);
		if (!shm->kaddr) {
			dev_err(teedev->dev,
				"failed to allocate %zu bytes of shared memory\n",
				size);
			ret = ERR_PTR(-ENOMEM);
			goto err;
		}

		mutex = &teedev->mutex;
		list_shm = &teedev->list_shm;
	}

	shm->teedev = teedev;
	shm->paddr = virt_to_phys(shm->kaddr);

	if (flags & TEE_SHM_DMA_BUF) {
		/*
		 * Only call share on global shm:s, as the driver private
		 * shm:s always originates from the driver itself.
		 */
		int rc = teedev->desc->ops->shm_share(shm);

		if (rc) {
			ret = ERR_PTR(rc);
			goto err;
		}
	}

	mutex_lock(mutex);
	list_add_tail(&shm->list_node, list_shm);
	mutex_unlock(mutex);

	return shm;
err:
	if (shm->kaddr) {
		if (shm->flags & TEE_SHM_DMA_BUF)
			free_pages((unsigned long)shm->kaddr, get_order(size));
		else
			kfree(shm->kaddr);
	}
	kfree(shm);
	return ret;
}
EXPORT_SYMBOL_GPL(tee_shm_alloc);

int tee_shm_fd(struct tee_shm *shm)
{
	u32 req_flags = TEE_SHM_MAPPED | TEE_SHM_DMA_BUF;

	if ((shm->flags & req_flags) != req_flags)
		return -EINVAL;

	return dma_buf_fd(shm->dmabuf, O_CLOEXEC);
}

static void tee_shm_release(struct tee_shm *shm)
{
	struct tee_device *teedev = shm->teedev;

	if (shm->flags & TEE_SHM_DMA_BUF) {
		/* Only unshare global shm:s */
		shm->teedev->desc->ops->shm_unshare(shm);

		free_pages((unsigned long)shm->kaddr, get_order(shm->size));
		mutex_lock(&teeshm_list_mutex);
		list_del(&shm->list_node);
		mutex_unlock(&teeshm_list_mutex);
	} else {
		kfree(shm->kaddr);
		mutex_lock(&teedev->mutex);
		list_del(&shm->list_node);
		mutex_unlock(&teedev->mutex);
	}

	kfree(shm);
}

void tee_shm_free_by_teefilp(struct tee_filp *teefilp)
{
	struct tee_shm *shm;
	struct tee_shm *tmp;
	LIST_HEAD(tmp_list);

	/*
	 * Move all matching shm:s to a temporary list
	 */
	mutex_lock(&teeshm_list_mutex);
	list_for_each_entry_safe(shm, tmp, &teeshm_list, list_node) {
		if (shm->teefilp == teefilp) {
			list_del(&shm->list_node);
			list_add_tail(&shm->list_node, &tmp_list);
		}
	}
	mutex_unlock(&teeshm_list_mutex);

	/*
	 * For each shm in the temporary list move it to the pending free
	 * list and call tee_shm_free(). Once the ref_count is 0 the shm
	 * will be removed from this list.
	 *
	 * Since the 'struct tee_filp' is about to be freed (the reason
	 * this function was called) set the teefilp to NULL. The only
	 * purpose of the teefilp in 'struct tee_shm' is to be able to find
	 * all shm:s related to a teefilp.
	 */
	while (true) {
		mutex_lock(&teeshm_list_mutex);
		shm = list_first_entry_or_null(&tmp_list,
					       struct tee_shm, list_node);
		if (shm) {
			list_del(&shm->list_node);
			list_add_tail(&shm->list_node,
				      &teeshm_pending_free_list);
			shm->teefilp = NULL;
		}
		mutex_unlock(&teeshm_list_mutex);
		if (!shm)
			break;
		tee_shm_free(shm);
	}

}

void tee_shm_free(struct tee_shm *shm)
{
	/*
	 * dma_buf_put() decreases the dmabuf reference counter and will
	 * call tee_shm_release() when the last reference is gone.
	 *
	 * In the case of anonymous memory we call tee_shm_release directly
	 * instead at it doesn't have a reference counter.
	 */
	if (shm->flags & TEE_SHM_DMA_BUF)
		dma_buf_put(shm->dmabuf);
	else
		tee_shm_release(shm);
}
EXPORT_SYMBOL_GPL(tee_shm_free);

static bool cmp_key_va(struct tee_shm *shm, uintptr_t va)
{
	uintptr_t shm_va = (uintptr_t)shm->kaddr;

	return (va >= shm_va) && (va < (shm_va + shm->size));
}

static bool cmp_key_pa(struct tee_shm *shm, uintptr_t pa)
{
	return (pa >= shm->paddr) && (pa < (shm->paddr + shm->size));
}

static struct tee_shm *tee_shm_find_by_key(struct tee_device *teedev, u32 flags,
			bool (*cmp)(struct tee_shm *shm, uintptr_t key),
			uintptr_t key)
{
	struct tee_shm *ret = NULL;
	struct tee_shm *shm;
	struct mutex *mutex;
	struct list_head *list_shm;

	if (flags & TEE_SHM_DMA_BUF) {
		mutex = &teeshm_list_mutex;
		list_shm = &teeshm_list;
	} else {
		mutex = &teedev->mutex;
		list_shm = &teedev->list_shm;
	}

	mutex_lock(mutex);
	list_for_each_entry(shm, list_shm, list_node) {
		if (cmp(shm, key)) {
			ret = shm;
			break;
		}
	}
	mutex_unlock(mutex);

	return ret;
}

struct tee_shm *tee_shm_find_by_va(struct tee_device *teedev, u32 flags,
			void *va)
{
	return tee_shm_find_by_key(teedev, flags, cmp_key_va, (uintptr_t)va);
}
EXPORT_SYMBOL_GPL(tee_shm_find_by_va);

struct tee_shm *tee_shm_find_by_pa(struct tee_device *teedev, u32 flags,
			phys_addr_t pa)
{
	return tee_shm_find_by_key(teedev, flags, cmp_key_pa, pa);
}
EXPORT_SYMBOL_GPL(tee_shm_find_by_pa);

int tee_shm_va2pa(struct tee_shm *shm, void *va, phys_addr_t *pa)
{
	/* Check that we're in the range of the shm */
	if ((char *)va < (char *)shm->kaddr)
		return -EINVAL;
	if ((char *)va >= ((char *)shm->kaddr + shm->size))
		return -EINVAL;

	if (pa)
		*pa = virt_to_phys(va);
	return 0;
}
EXPORT_SYMBOL_GPL(tee_shm_va2pa);

int tee_shm_pa2va(struct tee_shm *shm, phys_addr_t pa, void **va)
{
	/* Check that we're in the range of the shm */
	if (pa < shm->paddr)
		return -EINVAL;
	if (pa >= (shm->paddr + shm->size))
		return -EINVAL;

	if (va)
		*va = phys_to_virt(pa);
	return 0;
}
EXPORT_SYMBOL_GPL(tee_shm_pa2va);

void *tee_shm_get_va(struct tee_shm *shm, size_t offs)
{
	if (offs >= shm->size)
		return ERR_PTR(-EINVAL);
	return shm->kaddr;
}
EXPORT_SYMBOL_GPL(tee_shm_get_va);

int tee_shm_get_pa(struct tee_shm *shm, size_t offs, phys_addr_t *pa)
{
	if (offs >= shm->size)
		return -EINVAL;
	if (pa)
		*pa = shm->paddr + offs;
	return 0;
}
EXPORT_SYMBOL_GPL(tee_shm_get_pa);

static bool is_shm_dma_buf(struct dma_buf *dmabuf)
{
	return dmabuf->ops == &tee_shm_dma_buf_ops;
}

struct tee_shm *tee_shm_get_from_fd(int fd)
{
	struct dma_buf *dmabuf = dma_buf_get(fd);

	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	if (!is_shm_dma_buf(dmabuf))
		return ERR_PTR(-EINVAL);
	return dmabuf->priv;
}
EXPORT_SYMBOL_GPL(tee_shm_get_from_fd);

void tee_shm_put(struct tee_shm *shm)
{
	if (shm->flags & TEE_SHM_DMA_BUF)
		dma_buf_put(shm->dmabuf);
}
EXPORT_SYMBOL_GPL(tee_shm_put);
