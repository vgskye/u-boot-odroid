/*
 * SPDX-License-Identifier:     GPL-2.0+
 *
 * (C) Copyright 2023 Hardkernel Co., Ltd
 */

#include <common.h>
#include <fs.h>
#include <lcd.h>
#include <malloc.h>
#include <mapmem.h>
#include <boot_rkimg.h>
#include <jffs2/load_kernel.h>
#include <asm/unaligned.h>	/* get_unaligned() */
#include "../../../drivers/video/drm/rockchip_display.h"

#ifndef CONFIG_MTD_NOR_FLASH
# define OFFSET_ADJUSTMENT	0
#else
# define OFFSET_ADJUSTMENT	(flash_info[id.num].start[0])
#endif

DECLARE_GLOBAL_DATA_PTR;

static char *panel = NULL;

extern int cramfs_check (struct part_info *info);
extern int cramfs_load (char *loadoffset, struct part_info *info, char *filename);

extern struct rockchip_logo_cache *find_or_alloc_logo_cache(const char *bmp);
extern void *get_display_buffer(int size);

int set_panel_name(const char *name)
{
	panel = (char *)name;

	return 0;
}

int load_from_mmc(unsigned long addr, int devnum, int partnum, char *filename)
{
	int ret;
	char buf[16];

	snprintf(buf, sizeof(buf), "%d:%d", devnum, partnum);

	ret = fs_set_blk_dev("mmc", buf, FS_TYPE_ANY);
	if (!ret) {
		loff_t len_read;
		ret = fs_read(filename, addr, 0, 0, &len_read);
		if (!ret) {
			printf("%llu bytes read\n", len_read);
			return 0;
		}
	}

	return ret;
}

int load_from_cramfs(unsigned long addr, char *filename)
{
	int size = 0;

	struct part_info part;
	struct mtd_device dev;
	struct mtdids id;

	ulong cramfsaddr;
	cramfsaddr = simple_strtoul(env_get("cramfsaddr"), NULL, 16);

	id.type = MTD_DEV_TYPE_NOR;
	id.num = 0;
	dev.id = &id;
	part.dev = &dev;
	part.offset = (u64)(uintptr_t) map_sysmem(cramfsaddr - OFFSET_ADJUSTMENT, 0);

	ulong offset = addr;
	char *offset_virt = map_sysmem(offset, 0);

	if (cramfs_check(&part))
		size = cramfs_load (offset_virt, &part, filename);

	if (size > 0) {
		printf("### CRAMFS load complete: %d bytes loaded to 0x%lx\n",
			size, offset);
		env_set_hex("filesize", size);
	}

	unmap_sysmem(offset_virt);
	unmap_sysmem((void *)(uintptr_t)part.offset);

	return !(size > 0);
}

int rk_board_late_init(void)
{
	char buf[1024] = "run distro_bootcmd";

	/* Load SPI firmware when boot device is SPI flash memory
	 * and environment value 'skip_spiboot' is not 'true'
	 */
	if (strcmp(env_get("skip_spiboot"), "true")) {
		snprintf(buf, sizeof(buf),
				"cramfsload $scriptaddr boot.scr;"
				"source $scriptaddr;"
				"%s", env_get("bootcmd"));
	}

	env_set("bootcmd", buf);

#if defined(CONFIG_TARGET_ODROID_M1)
	env_set("variant", "m1");
#elif defined(CONFIG_TARGET_ODROID_M1S)
	env_set("variant", "m1s");
#endif

	return 0;
}

int board_read_dtb_file(void *fdt_addr)
{
	int ret;

	ret = load_from_cramfs((unsigned long)fdt_addr, CONFIG_ROCKCHIP_EARLY_DISTRO_DTB_PATH);
	if (!ret) {
		if (panel) {
			char buf[1024];

			snprintf(buf, sizeof(buf), "%s.dtbo", panel);

			ret = load_from_cramfs(load_addr, buf);
			if (!ret) {
				ulong fdt_dtbo = env_get_ulong("loadaddr", 16, 0);

				fdt_increase_size(fdt_addr, fdt_totalsize((void *)fdt_dtbo));
				fdt_overlay_apply_verbose(fdt_addr, (void *)fdt_dtbo);
			}
		}
	} else {
		char *paths[] = {
			"dtb",
			"rockchip/"CONFIG_ROCKCHIP_EARLY_DISTRO_DTB_PATH,
		};
		struct blk_desc *dev_desc = rockchip_get_bootdev();
		int i;

		for (i = 0; i < ARRAY_SIZE(paths); i++) {
			ret = load_from_mmc((unsigned long)fdt_addr, dev_desc->devnum, 1, paths[i]);
			if (!ret)
				break;
		}
	}

	return fdt_check_header(fdt_addr);
}

#ifdef CONFIG_MISC_INIT_R
static int set_bmp_logo(const char *bmp_name, void *addr, int flip)
{
	struct logo_info *logo;
	struct rockchip_logo_cache *logo_cache;
	struct bmp_image *bmp = (struct bmp_image *)map_sysmem((ulong)addr, 0);
	struct bmp_header *header = (struct bmp_header *)bmp;
	void *src;
	void *dst;
	int stride;
	int i;

	if (!bmp_name || !addr)
		return -EINVAL;

	if (!((bmp->header.signature[0]=='B') &&
	      (bmp->header.signature[1]=='M')))
		return -EINVAL;

	logo_cache = find_or_alloc_logo_cache(bmp_name);
	if (!logo_cache)
		return -ENOMEM;

	logo = &logo_cache->logo;
	logo->bpp = get_unaligned_le16(&header->bit_count);
	if (logo->bpp != 24) {
		printf("Unsupported bpp=%d\n", logo->bpp);
		return -EINVAL;
	}

	logo->width = get_unaligned_le32(&header->width);
	logo->height = get_unaligned_le32(&header->height);
	logo->offset = get_unaligned_le32(&header->data_offset);
	logo->ymirror = 0;

	logo->mem = get_display_buffer(get_unaligned_le32(&header->file_size));
	if (!logo->mem)
		return -ENOMEM;

	src = addr + logo->offset;
	dst = logo->mem + logo->offset;
	stride = ALIGN(logo->width * 3, 4);

	if (flip)
		src += stride * (logo->height - 1);

	for (i = 0; i < logo->height; i++) {
		memcpy(dst, src, 3 * logo->width);
		dst += stride;
		src += stride;

		if (flip)
			src -= stride * 2;
	}

	flush_dcache_range((ulong)logo->mem,
			ALIGN((ulong)logo->mem
				+ (logo->width * logo->height * logo->bpp >> 3),
				CONFIG_SYS_CACHELINE_SIZE));

	return 0;
}

int misc_init_r(void)
{
	struct blk_desc *dev_desc = rockchip_get_bootdev();
	void *decomp;
	struct bmp_image *bmp;
	unsigned int loadaddr = (unsigned int)env_get_ulong("loadaddr", 16, 0);
	unsigned long len;
	char *logofile = "boot-logo.bmp.gz";

	int ret = load_from_mmc(loadaddr, dev_desc->devnum, 1, logofile);
	if (ret)
		ret = load_from_cramfs(load_addr, logofile);

	if (ret)
		return 0;	// No boot logo file in memory card

	bmp = (struct bmp_image *)map_sysmem(loadaddr, 0);

	/* Check if splash image is uncompressed */
	if (!((bmp->header.signature[0] == 'B')
				&& (bmp->header.signature[1] == 'M')))
		bmp = gunzip_bmp(loadaddr, &len, &decomp);

	if (bmp) {
		set_bmp_logo("logo.bmp", bmp, 1);
		set_bmp_logo("logo_kernel.bmp", bmp, 1);
	}

	if (decomp)
		free(decomp);

	return 0;
}
#endif