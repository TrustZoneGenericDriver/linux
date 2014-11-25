/*
 * Copyright (C) 2014 Javier González
 *
 * Generic device driver for ARM TrustZone.
 *
 * TODO: All checkings
 * TODO: Revise return values
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "trustzone.h"

static LIST_HEAD(trustzone_chip_list);
static DEFINE_SPINLOCK(driver_lock);
static DECLARE_BITMAP(dev_mask, TRUSTZONE_NUM_DEVICES);

static struct trustzone_chip *tz_chip_find_get(u32 chip_num)
{
	struct trustzone_chip *pos, *chip = NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(pos, &trustzone_chip_list, list) {
		if (chip_num != TRUSTZONE_ANY_NUM && chip_num != pos->dev_num)
			continue;

		/* XXX: Look into this: struct platform_driver otz_driver */
		/* if (try_module_get(pos->dev->driver->owner)) { */
			chip = pos;
			break;
		/* } */
	}
	rcu_read_unlock();
	return chip;
}

int __tz_open(struct trustzone_chip *chip,
		struct trustzone_session *session, u8 primitive)
{
	int ret = 0;

	ret = chip->tz_ops.open(primitive, session);
	if (ret) {
		dev_err(chip->dev, "Open session failed in TrustZone"
				" chip (id:%d)\n", chip->dev_num);
		return ret;
	}

	/* TODO: We need to look into this: struct platform_driver otz_driver
	 * This problem occurs up too;
	 * */
	/* trustzone_chip_put(chip); */
	return ret;
}

int __tz_close(struct trustzone_chip *chip,
		struct trustzone_session *tz_session)
{
	int ret = 0;

	ret = chip->tz_ops.close(tz_session);
	if (ret) {
		dev_err(chip->dev, "Close session failed in TrustZone chip"
				" (id:%d)\n", chip->dev_num);
		return ret;
	}
	/* TODO: Look at the trustzone_chip_put(chip) to see if it is
	 * necessary to take the chip out of a list.
	 */
	return ret;
}

static int __tz_transmit(struct trustzone_chip *chip,
		struct trustzone_session *session, struct trustzone_cmd *cmd,
		struct trustzone_parameter_list *params)
{
	int ret = 0;

	ret = chip->tz_ops.invoke_command(session, cmd, params);
	if (ret) {
		dev_err(chip->dev, "Transmit command failed in TrustZone chip"
				" (id:%d)\n", chip->dev_num);
		goto out;
	}
	dev_dbg(chip->dev, "Transmit command succeeded\n");

out:
	return ret;
}


/**
 * TrustZone Generic Operations
 */

int tz_open(u32 chip_num, struct trustzone_session *session,
		u8 primitive)
{
	struct trustzone_chip *chip;
	int ret = 0;

	chip = tz_chip_find_get(chip_num);
	if (chip == NULL) {
		dev_err(chip->dev, "Could not find TrustZone chip (id:%d)"
				" registered\n", chip_num);
		return -ENODEV;
	}
	mutex_lock(&chip->tz_mutex);
	ret = __tz_open(chip, session, primitive);
	mutex_unlock(&chip->tz_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(tz_open);

int tz_close(u32 chip_num, struct trustzone_session *tz_session)
{
	struct trustzone_chip *chip;
	int ret = 0;

	chip = tz_chip_find_get(chip_num);
	if (chip == NULL) {
		dev_err(chip->dev, "Could not find TrustZone chip (id:%d)"
				" registered\n", chip_num);
		return -ENODEV;
	}
	mutex_lock(&chip->tz_mutex);
	ret = __tz_close(chip, tz_session);
	mutex_unlock(&chip->tz_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(tz_close);


/* XXX: Maybe we should have a general mapping of sessions where each session
 * has a general ID independently from the chip. This is future work.
 */
int tz_transmit(u32 chip_num, struct trustzone_session *session,
		struct trustzone_cmd *cmd,
		struct trustzone_parameter_list *params)
{
	struct trustzone_chip *chip;
	int ret = 0;

	chip = tz_chip_find_get(chip_num);
	if (chip == NULL) {
		dev_err(chip->dev, "Could not find TrustZone chip (id:%d)"
				" registered\n", chip_num);
		ret = -ENODEV;
		goto out;
	}
	mutex_lock(&chip->tz_mutex);
	ret = __tz_transmit(chip, session, cmd, params);
	mutex_unlock(&chip->tz_mutex);
	dev_dbg(chip->dev, "Transmit command succeeded\n");

out:
	return ret;
}
EXPORT_SYMBOL_GPL(tz_transmit);

/*
 * Perform an operation in the TEE.
 *
 * Performing an operation entails opening a TEE session, sending a single task
 * and closing the TEE session.
 *
 * This operation is recommended when sending a single task to the TEE. For
 * sending a series of tasks is better to explicetly opening and closing a
 * session, sending the desired tasks to the TEE in the middle
 */
int tz_send_operation(u32 chip_num, struct trustzone_session *session,
		struct trustzone_cmd *cmd,
		struct trustzone_parameter_list *params)
{
	return tz_transmit(chip_num, session, cmd, params);
}

/**
  * TODO: Are these operations necessary? We can either maintain a wimple
  * read/write interface and delegate the behaviour to the commands sent to the
  * secure world, or provide a richer interface for common operations (e.g.,
  * allocate shared memory
  */
#if 0
int tz_shared_memory_allocate(void)
{
	return 0;
}

int tz_shared_memory_register(void)
{
	return 0;
}

int tz_shared_memory_free(void)
{
	return 0;
}
#endif

/*
 *TODO: Secure system primitives should probably be located in a sepparate file.
 */
int tz_monitor_syscall(u32 chip_num, struct trustzone_session *tz_session,
		unsigned long sig, siginfo_t *sig_info)
{
	struct trustzone_cmd cmd;
	struct trustzone_session my_tz_session;
	struct trustzone_chip *chip;
	int ret = 0;

	cmd.cmd = TZ_SYSCALL_MONITOR;
	chip = tz_chip_find_get(chip_num);
	if (chip == NULL) {
		dev_err(chip->dev, "Could not find TrustZone chip (id:%d)"
				" registered\n", chip_num);
		return -ENODEV;
	}
	mutex_lock(&chip->tz_mutex);
	ret = __tz_open(chip, &my_tz_session,
		TZ_SECURE_PRIMITIVE_SVC);

	if (ret) {
		dev_err(chip->dev, "Open session failed for TZ_SYSCALL_MONITOR");
		return ret;
	}
	ret = __tz_transmit(chip, &my_tz_session, &cmd, NULL);

	if (ret) {
		dev_err(chip->dev, "Send TZ_SYSCALL_MONITOR to SW failed\n");
		goto out;
	}
	ret = __tz_close(chip, &my_tz_session);

	if (ret) {
		dev_err(chip->dev, "Close session failed during test\n");
		return ret;
	}
	mutex_unlock(&chip->tz_mutex);

out:
	return ret;
}

/*
 * If the vendor provides a release function, call it too
 */
void trustzone_vendor_release(struct trustzone_chip *chip)
{
	if (!chip)
		return;

	if (chip->tz_ops.release)
		chip->tz_ops.release(chip->dev);

	kfree(chip->tz_ops.miscdev.name);
}

static void trustzone_dev_release(struct device *dev)
{
	/* FIXME: You need to fix all this crap... */
	/* struct trustzone_chip *chip = dev_get_drvdata(dev); */
	/* struct trustzone_chip *chip; */

	/* if (!chip) */
		/* return; */

	/* trustzone_vendor_release(chip); */

	/* chip->release(dev); */
	/* kfree(chip); */
}
EXPORT_SYMBOL_GPL(trustzone_dev_release);

struct trustzone_chip *trustzone_register_hardware(struct device *dev,
		const struct trustzone_operations *entry)
{
	char *devname;
	struct trustzone_chip *chip;

	chip = kzalloc(sizeof(*chip), GFP_KERNEL);
	devname = kmalloc(TRUSTZONE_NAME_MAX, GFP_KERNEL);

	if (chip == NULL || devname == NULL)
		goto out_free;

	/* TODO: All mutexes and timers, as they do in the TPM module */
	mutex_init(&chip->tz_mutex);
	INIT_LIST_HEAD(&chip->list);
	memcpy(&chip->tz_ops, entry, sizeof(struct trustzone_operations));
	chip->dev_num = find_first_zero_bit(dev_mask, TRUSTZONE_NUM_DEVICES);

	if (chip->dev_num >= TRUSTZONE_NUM_DEVICES) {
		dev_err(dev, "No available trustzone device numbers\n");
		goto out_free;
	} else if (chip->dev_num == 0)
		chip->tz_ops.miscdev.minor = MISC_DYNAMIC_MINOR;

	set_bit(chip->dev_num, dev_mask);
	scnprintf(devname, TRUSTZONE_NAME_MAX, "%s%d", "tz", chip->dev_num);
	chip->tz_ops.miscdev.name = devname;
	chip->tz_ops.miscdev.parent = dev;
	chip->dev = get_device(dev);
	chip->release = dev->release;
	dev->release = trustzone_dev_release;
	dev_set_drvdata(dev, chip);

	if (misc_register(&chip->tz_ops.miscdev)) {
		dev_err(chip->dev,
				"unable to misc_register %s, minor %d\n",
				chip->tz_ops.miscdev.name,
				chip->tz_ops.miscdev.minor);
		goto put_device;
	}
	/* TODO: Add sysfs interface
	 * TODO: Add debugfs interface
	if (sysfs_create_group(&dev->kobj, chip->tz_ops.attr_group)) {
		misc_deregister(&chip->tz_ops.miscdev);
		goto put_device;
	}
	*/

	/* Make chip available */
	spin_lock(&driver_lock);
	list_add_rcu(&chip->list, &trustzone_chip_list);
	spin_unlock(&driver_lock);

	return chip;

put_device:
	put_device(chip->dev);
out_free:
	if (chip != NULL)
		kfree(chip);
	if (devname != NULL)
		kfree(devname);
	return NULL;
}
EXPORT_SYMBOL_GPL(trustzone_register_hardware);

MODULE_AUTHOR("Javier González (jgon@itu.dk)");
MODULE_DESCRIPTION("TrustZone Generic Driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
