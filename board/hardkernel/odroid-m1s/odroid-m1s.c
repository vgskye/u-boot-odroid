/*
 * SPDX-License-Identifier:     GPL-2.0+
 *
 * (C) Copyright 2020 Rockchip Electronics Co., Ltd
 */

#include <common.h>
#include <boot_rkimg.h>
#include <dwc3-uboot.h>
#include <usb.h>
#include <mmc.h>
#include <mtd_blk.h>
#include <mapmem.h>
#include <fs.h>
#include <environment.h>
#include <fdt_support.h>
#include <odroid-common.h>

DECLARE_GLOBAL_DATA_PTR;

#ifdef CONFIG_USB_DWC3
static struct dwc3_device dwc3_device_data = {
	.maximum_speed = USB_SPEED_HIGH,
	.base = 0xfcc00000,
	.dr_mode = USB_DR_MODE_PERIPHERAL,
	.index = 0,
	.dis_u2_susphy_quirk = 1,
	.usb2_phyif_utmi_width = 16,
};

int usb_gadget_handle_interrupts(void)
{
	dwc3_uboot_handle_interrupt(0);
	return 0;
}

int board_usb_init(int index, enum usb_init_type init)
{
	return dwc3_uboot_init(&dwc3_device_data);
}
#endif

int board_early_init_r(void)
{
	struct blk_desc *dev_desc = rockchip_get_bootdev();
	unsigned long addr = simple_strtoul(env_get("cramfsaddr"), NULL, 16);
	char env[CONFIG_ENV_SIZE];
	int ret = -EINVAL;
	int n;

	/* GPIO Init */
	odroid_gpio_init(74, 0); // 'gpiochip2/gpio10'

	/* Load environment value for display panel at very early stage */
	int sectors = CONFIG_ENV_SIZE / 512;
	int count = blk_dread(dev_desc, CONFIG_ENV_OFFSET / 512, sectors, (void*)env);
	if (count == sectors) {
		const char *panel = getenv_raw(env, CONFIG_ENV_SIZE, "panel");
		if (panel)
			set_panel_name(panel);
	}

	/* Clear memory at $crarmfsaddr */
	memset((void*)addr, 0, 256);

	for (n = 1; n <= 3; n++) {
		ret = load_from_mmc(addr, dev_desc->devnum, n, "ODROIDBIOS.BIN");
		if (!ret)
			return 0;
	}

	return 0;
}
