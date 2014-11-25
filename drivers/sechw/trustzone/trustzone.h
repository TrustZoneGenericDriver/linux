/*
 * Copyright (C) 2014 Javier González
 *
 * Device driver for ARM TrustZone.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/trustzone.h>

/* Maximun number of letter for a TrustZone device name string */
#define TRUSTZONE_NAME_MAX	10

enum tpm_const {
	/* TRUSTZONE_MINOR = X, */
	TRUSTZONE_NUM_DEVICES = 256,
};

/**
 * Enums used for secure system primitives
 */
enum tz_secure_system_primitives {
	TZ_SYSCALL_MONITOR = 0x0,
};

struct trustzone_operations {
	char name[TRUSTZONE_NAME_MAX + 1];
	struct miscdevice miscdev;
	struct attribute_group *attr_group;
	struct list_head list;

	int (*open) (int, struct trustzone_session *);
	int (*close) (struct trustzone_session *);
	int (*invoke_command) (struct trustzone_session *,
		struct trustzone_cmd *, struct trustzone_parameter_list *);
	int (*install_task) (void);
	int (*delete_task) (void);
	int (*install_primitive) (void);
	int (*delete_primitive) (void);
	int (*memory_allocate) (void);
	int (*memory_register) (void);
	int (*memory_free) (void);
	void (*release) (struct device *);
};

struct trustzone_chip {
	struct device *dev;
	int dev_num;	/* /dev/trustzone# */

	/* Data transmitted from/to trustzone's secure world */
	u8 *data_buffer;
	u16 buffer_size;
	atomic_t data_pending;
	struct mutex tz_mutex;
	struct trustzone_operations tz_ops;
	struct list_head list;
	void (*release) (struct device *);
};

static inline void trustzone_chip_put(struct trustzone_chip *chip)
{
	module_put(chip->dev->driver->owner);
}

extern struct trustzone_chip *trustzone_register_hardware(struct device *dev,
		const struct trustzone_operations *entry);
