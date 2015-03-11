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
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/sec-hw/tee_drv.h>

#define DRIVER_NAME "tee-optee"
#define OPTEE_VERSION	1

struct optee {
	struct tee_device *supp_teedev;
	struct tee_device *teedev;
	struct device *dev;
};

struct optee_filp_state {
	int dummy;
};

static struct optee_filp_state *optee_new_filp_state(void)
{
	struct optee_filp_state *filpstate;

	filpstate = kzalloc(sizeof(struct optee_filp_state), GFP_KERNEL);
	return filpstate;
}

static void optee_destroy_filp_state(struct optee_filp_state *filpstate)
{
	if (filpstate)
		kzfree(filpstate);
}

static void optee_get_version(struct tee_filp *teefilp,
		u32 *version, u8 *uuid)
{
	*version = OPTEE_VERSION;
	memset(uuid, 0, TEE_UUID_SIZE);
}

static int optee_open(struct tee_filp *teefilp)
{
	teefilp->filp_data = optee_new_filp_state();
	if (!teefilp->filp_data)
		return -ENOMEM;
	return 0;
}

static void optee_release(struct tee_filp *teefilp)
{
	optee_destroy_filp_state(teefilp->filp_data);
	teefilp->filp_data = NULL;
}

static int optee_cmd(struct tee_filp *teefilp, void __user *buf, size_t len)
{
	return -EINVAL;
}

static int optee_shm_share(struct tee_shm *shm)
{
	/* No special action needed to share memory with OP-TEE */
	return 0;
}

static void optee_shm_unshare(struct tee_shm *shm)
{
}

static struct tee_driver_ops optee_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.cmd = optee_cmd,
	.shm_share = optee_shm_share,
	.shm_unshare = optee_shm_unshare,
};

static struct tee_desc optee_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &optee_ops,
	.owner = THIS_MODULE,
};

static int optee_supp_cmd(struct tee_filp *teefilp, void __user *buf,
			size_t len)
{
	return -EINVAL;
}

static struct tee_driver_ops optee_supp_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.cmd = optee_supp_cmd,
	.shm_share = optee_shm_share,
	.shm_unshare = optee_shm_unshare,
};

static struct tee_desc optee_supp_desc = {
	.name = DRIVER_NAME "-supp",
	.ops = &optee_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static int optee_probe(struct platform_device *pdev)
{
	struct optee *optee;
	int ret;

	optee = devm_kzalloc(&pdev->dev, sizeof(*optee), GFP_KERNEL);
	if (!optee)
		return -ENOMEM;

	optee->dev = &pdev->dev;

	optee->teedev = tee_register(&optee_desc, &pdev->dev, optee);
	if (!optee->teedev) {
		dev_err(&pdev->dev, "could not register client driver\n");
		ret = -EINVAL;
		goto err;
	}

	optee->supp_teedev = tee_register(&optee_supp_desc, &pdev->dev, optee);
	if (!optee->teedev) {
		dev_err(&pdev->dev,
			"could not register supplicant driver\n");
		ret = -EINVAL;
		goto err;
	}

	platform_set_drvdata(pdev, optee);

	dev_info(&pdev->dev, "initialized driver\n");
	return 0;
err:
	if (optee->teedev)
		tee_unregister(optee->teedev);
	devm_kfree(&pdev->dev, optee);
	return ret;
}

static int optee_remove(struct platform_device *pdev)
{
	struct optee *optee = platform_get_drvdata(pdev);

	tee_unregister(optee->teedev);
	tee_unregister(optee->supp_teedev);

	return 0;
}


static const struct of_device_id optee_match[] = {
	{ .compatible = "tee-optee" },
	{},
};

static struct platform_driver optee_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = optee_match,
	},
	.probe = optee_probe,
	.remove = optee_remove,
};

static int __init optee_init(void)
{
	pr_info("%s", __func__);

	return platform_driver_register(&optee_driver);
}

static void __exit optee_exit(void)
{
	pr_info("%s", __func__);
	platform_driver_unregister(&optee_driver);
}

module_init(optee_init);
module_exit(optee_exit);

MODULE_AUTHOR("Linaro");
MODULE_DESCRIPTION("OP-TEE TEE driver");
MODULE_SUPPORTED_DEVICE("");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
