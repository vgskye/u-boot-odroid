// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2008-2018 Fuzhou Rockchip Electronics Co., Ltd
 *
 * Author: Wyon Bi <bivvy.bi@rock-chips.com>
 */

#include <asm/arch/cpu.h>
#include <config.h>
#include <common.h>
#include <errno.h>
#include <dm.h>
#include <div64.h>
#include <asm/io.h>
#include <linux/ioport.h>
#include <linux/iopoll.h>
#include <linux/math64.h>
#include <dm/of_access.h>

#include "rockchip_phy.h"

#define USEC_PER_SEC	1000000LL
#define PSEC_PER_SEC	1000000000000LL

#define UPDATE(x, h, l)	(((x) << (l)) & GENMASK((h), (l)))

/*
 * The offset address[7:0] is distributed two parts, one from the bit7 to bit5
 * is the first address, the other from the bit4 to bit0 is the second address.
 * when you configure the registers, you must set both of them. The Clock Lane
 * and Data Lane use the same registers with the same second address, but the
 * first address is different.
 */
#define FIRST_ADDRESS(x)		(((x) & 0x7) << 5)
#define SECOND_ADDRESS(x)		(((x) & 0x1f) << 0)
#define PHY_REG(first, second)		(FIRST_ADDRESS(first) | \
					 SECOND_ADDRESS(second))

/* Analog Register Part: reg00 */
#define BANDGAP_POWER_MASK			BIT(7)
#define BANDGAP_POWER_DOWN			BIT(7)
#define BANDGAP_POWER_ON			0
#define LANE_EN_MASK				GENMASK(6, 2)
#define LANE_EN_CK				BIT(6)
#define LANE_EN_3				BIT(5)
#define LANE_EN_2				BIT(4)
#define LANE_EN_1				BIT(3)
#define LANE_EN_0				BIT(2)
#define POWER_WORK_MASK				GENMASK(1, 0)
#define POWER_WORK_ENABLE			UPDATE(1, 1, 0)
#define POWER_WORK_DISABLE			UPDATE(2, 1, 0)
/* Analog Register Part: reg01 */
#define REG_SYNCRST_MASK			BIT(2)
#define REG_SYNCRST_RESET			BIT(2)
#define REG_SYNCRST_NORMAL			0
#define REG_LDOPD_MASK				BIT(1)
#define REG_LDOPD_POWER_DOWN			BIT(1)
#define REG_LDOPD_POWER_ON			0
#define REG_PLLPD_MASK				BIT(0)
#define REG_PLLPD_POWER_DOWN			BIT(0)
#define REG_PLLPD_POWER_ON			0
/* Analog Register Part: reg03 */
#define REG_FBDIV_HI_MASK			BIT(5)
#define REG_FBDIV_HI(x)				UPDATE(x, 5, 5)
#define REG_PREDIV_MASK				GENMASK(4, 0)
#define REG_PREDIV(x)				UPDATE(x, 4, 0)
/* Analog Register Part: reg04 */
#define REG_FBDIV_LO_MASK			GENMASK(7, 0)
#define REG_FBDIV_LO(x)				UPDATE(x, 7, 0)
/* Analog Register Part: reg05 */
#define SAMPLE_CLOCK_PHASE_MASK			GENMASK(6, 4)
#define SAMPLE_CLOCK_PHASE(x)			UPDATE(x, 6, 4)
#define CLOCK_LANE_SKEW_PHASE_MASK		GENMASK(2, 0)
#define CLOCK_LANE_SKEW_PHASE(x)		UPDATE(x, 2, 0)
/* Analog Register Part: reg06 */
#define DATA_LANE_3_SKEW_PHASE_MASK		GENMASK(6, 4)
#define DATA_LANE_3_SKEW_PHASE(x)		UPDATE(x, 6, 4)
#define DATA_LANE_2_SKEW_PHASE_MASK		GENMASK(2, 0)
#define DATA_LANE_2_SKEW_PHASE(x)		UPDATE(x, 2, 0)
/* Analog Register Part: reg07 */
#define DATA_LANE_1_SKEW_PHASE_MASK		GENMASK(6, 4)
#define DATA_LANE_1_SKEW_PHASE(x)		UPDATE(x, 6, 4)
#define DATA_LANE_0_SKEW_PHASE_MASK		GENMASK(2, 0)
#define DATA_LANE_0_SKEW_PHASE(x)		UPDATE(x, 2, 0)
/* Analog Register Part: reg08 */
#define PRE_EMPHASIS_ENABLE_MASK		BIT(7)
#define PRE_EMPHASIS_ENABLE			BIT(7)
#define PRE_EMPHASIS_DISABLE			0
#define PLL_POST_DIV_ENABLE_MASK		BIT(5)
#define PLL_POST_DIV_ENABLE			BIT(5)
#define PLL_POST_DIV_DISABLE			0
#define DATA_LANE_VOD_RANGE_SET_MASK		GENMASK(3, 0)
#define DATA_LANE_VOD_RANGE_SET(x)		UPDATE(x, 3, 0)
#define SAMPLE_CLOCK_DIRECTION_MASK		BIT(4)
#define SAMPLE_CLOCK_DIRECTION_REVERSE		BIT(4)
#define SAMPLE_CLOCK_DIRECTION_FORWARD		0
#define LOWFRE_EN_MASK				BIT(5)
#define PLL_OUTPUT_FREQUENCY_DIV_BY_1		0
#define PLL_OUTPUT_FREQUENCY_DIV_BY_2		1
/* Analog Register Part: reg0b */
#define CLOCK_LANE_VOD_RANGE_SET_MASK	GENMASK(3, 0)
#define CLOCK_LANE_VOD_RANGE_SET(x)	UPDATE(x, 3, 0)
#define VOD_MIN_RANGE			0x1
#define VOD_MID_RANGE			0x3
#define VOD_BIG_RANGE			0x7
#define VOD_MAX_RANGE			0xf
/* Analog Register Part: reg1e */
#define PLL_MODE_SEL_MASK			GENMASK(6, 5)
#define PLL_MODE_SEL_LVDS_MODE			0
#define PLL_MODE_SEL_MIPI_MODE			BIT(5)

/* Digital Register Part: reg00 */
#define REG_DIG_RSTN_MASK			BIT(0)
#define REG_DIG_RSTN_NORMAL			BIT(0)
#define REG_DIG_RSTN_RESET			0
/* Digital Register Part: reg01	*/
#define INVERT_TXCLKESC_MASK			BIT(1)
#define INVERT_TXCLKESC_ENABLE			BIT(1)
#define INVERT_TXCLKESC_DISABLE			0
#define INVERT_TXBYTECLKHS_MASK			BIT(0)
#define INVERT_TXBYTECLKHS_ENABLE		BIT(0)
#define INVERT_TXBYTECLKHS_DISABLE		0
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg05 */
#define T_LPX_CNT_MASK				GENMASK(5, 0)
#define T_LPX_CNT(x)				UPDATE(x, 5, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg06 */
#define T_HS_ZERO_CNT_HI_MASK			BIT(7)
#define T_HS_ZERO_CNT_HI(x)			UPDATE(x, 7, 7)
#define T_HS_PREPARE_CNT_MASK			GENMASK(6, 0)
#define T_HS_PREPARE_CNT(x)			UPDATE(x, 6, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg07 */
#define T_HS_ZERO_CNT_LO_MASK			GENMASK(5, 0)
#define T_HS_ZERO_CNT_LO(x)			UPDATE(x, 5, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg08 */
#define T_HS_TRAIL_CNT_MASK			GENMASK(6, 0)
#define T_HS_TRAIL_CNT(x)			UPDATE(x, 6, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg09 */
#define T_HS_EXIT_CNT_LO_MASK			GENMASK(4, 0)
#define T_HS_EXIT_CNT_LO(x)			UPDATE(x, 4, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg0a */
#define T_CLK_POST_CNT_LO_MASK			GENMASK(3, 0)
#define T_CLK_POST_CNT_LO(x)			UPDATE(x, 3, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg0c */
#define LPDT_TX_PPI_SYNC_MASK			BIT(2)
#define LPDT_TX_PPI_SYNC_ENABLE			BIT(2)
#define LPDT_TX_PPI_SYNC_DISABLE		0
#define T_WAKEUP_CNT_HI_MASK			GENMASK(1, 0)
#define T_WAKEUP_CNT_HI(x)			UPDATE(x, 1, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg0d */
#define T_WAKEUP_CNT_LO_MASK			GENMASK(7, 0)
#define T_WAKEUP_CNT_LO(x)			UPDATE(x, 7, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg0e */
#define T_CLK_PRE_CNT_MASK			GENMASK(3, 0)
#define T_CLK_PRE_CNT(x)			UPDATE(x, 3, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg10 */
#define T_CLK_POST_HI_MASK			GENMASK(7, 6)
#define T_CLK_POST_HI(x)			UPDATE(x, 7, 6)
#define T_TA_GO_CNT_MASK			GENMASK(5, 0)
#define T_TA_GO_CNT(x)				UPDATE(x, 5, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg11 */
#define T_HS_EXIT_CNT_HI_MASK			BIT(6)
#define T_HS_EXIT_CNT_HI(x)			UPDATE(x, 6, 6)
#define T_TA_SURE_CNT_MASK			GENMASK(5, 0)
#define T_TA_SURE_CNT(x)			UPDATE(x, 5, 0)
/* Clock/Data0/Data1/Data2/Data3 Lane Register Part: reg12 */
#define T_TA_WAIT_CNT_MASK			GENMASK(5, 0)
#define T_TA_WAIT_CNT(x)			UPDATE(x, 5, 0)
/* LVDS Register Part: reg00 */
#define LVDS_DIGITAL_INTERNAL_RESET_MASK	BIT(2)
#define LVDS_DIGITAL_INTERNAL_RESET_DISABLE	BIT(2)
#define LVDS_DIGITAL_INTERNAL_RESET_ENABLE	0
/* LVDS Register Part: reg01 */
#define LVDS_DIGITAL_INTERNAL_ENABLE_MASK	BIT(7)
#define LVDS_DIGITAL_INTERNAL_ENABLE		BIT(7)
#define LVDS_DIGITAL_INTERNAL_DISABLE		0
/* LVDS Register Part: reg03 */
#define MODE_ENABLE_MASK			GENMASK(2, 0)
#define TTL_MODE_ENABLE				BIT(2)
#define LVDS_MODE_ENABLE			BIT(1)
#define MIPI_MODE_ENABLE			BIT(0)
/* LVDS Register Part: reg0b */
#define LVDS_LANE_EN_MASK			GENMASK(7, 3)
#define LVDS_DATA_LANE0_EN			BIT(7)
#define LVDS_DATA_LANE1_EN			BIT(6)
#define LVDS_DATA_LANE2_EN			BIT(5)
#define LVDS_DATA_LANE3_EN			BIT(4)
#define LVDS_CLK_LANE_EN			BIT(3)
#define LVDS_PLL_POWER_MASK			BIT(2)
#define LVDS_PLL_POWER_OFF			BIT(2)
#define LVDS_PLL_POWER_ON			0
#define LVDS_BANDGAP_POWER_MASK			BIT(0)
#define LVDS_BANDGAP_POWER_DOWN			BIT(0)
#define LVDS_BANDGAP_POWER_ON			0

#define DSI_PHY_RSTZ			0xa0
#define PHY_ENABLECLK			BIT(2)
#define DSI_PHY_STATUS			0xb0
#define PHY_LOCK			BIT(0)

enum soc_type {
	PX30_VIDEO_PHY,
	PX30S_VIDEO_PHY,
	RK3128_VIDEO_PHY,
	RK3368_VIDEO_PHY,
	RK3568_VIDEO_PHY,
};

enum phy_max_rate {
	MAX_1GHZ,
	MAX_2_5GHZ,
};

struct inno_video_mipi_dphy_timing {
	unsigned int max_lane_mbps;
	u8 lpx;
	u8 hs_prepare;
	u8 clk_lane_hs_zero;
	u8 data_lane_hs_zero;
	u8 hs_trail;
};

struct inno_video_mipi_dphy_info {
	const struct inno_video_mipi_dphy_timing *inno_mipi_dphy_timing_table;
	const unsigned int num_timings;
	enum phy_max_rate phy_max_rate;
};

static const
struct inno_video_mipi_dphy_timing inno_mipi_dphy_timing_table_max_1GHz[] = {
	{ 110, 0x0, 0x20, 0x16, 0x02, 0x22},
	{ 150, 0x0, 0x06, 0x16, 0x03, 0x45},
	{ 200, 0x0, 0x18, 0x17, 0x04, 0x0b},
	{ 250, 0x0, 0x05, 0x17, 0x05, 0x16},
	{ 300, 0x0, 0x51, 0x18, 0x06, 0x2c},
	{ 400, 0x0, 0x64, 0x19, 0x07, 0x33},
	{ 500, 0x0, 0x20, 0x1b, 0x07, 0x4e},
	{ 600, 0x0, 0x6a, 0x1d, 0x08, 0x3a},
	{ 700, 0x0, 0x3e, 0x1e, 0x08, 0x6a},
	{ 800, 0x0, 0x21, 0x1f, 0x09, 0x29},
	{1000, 0x0, 0x09, 0x20, 0x09, 0x27},
};

static const
struct inno_video_mipi_dphy_timing inno_mipi_dphy_timing_table_max_2_5GHz[] = {
	{ 110, 0x02, 0x7f, 0x16, 0x02, 0x02},
	{ 150, 0x02, 0x7f, 0x16, 0x03, 0x02},
	{ 200, 0x02, 0x7f, 0x17, 0x04, 0x02},
	{ 250, 0x02, 0x7f, 0x17, 0x05, 0x04},
	{ 300, 0x02, 0x7f, 0x18, 0x06, 0x04},
	{ 400, 0x03, 0x7e, 0x19, 0x07, 0x04},
	{ 500, 0x03, 0x7c, 0x1b, 0x07, 0x08},
	{ 600, 0x03, 0x70, 0x1d, 0x08, 0x10},
	{ 700, 0x05, 0x40, 0x1e, 0x08, 0x30},
	{ 800, 0x05, 0x02, 0x1f, 0x09, 0x30},
	{1000, 0x05, 0x08, 0x20, 0x09, 0x30},
	{1200, 0x06, 0x03, 0x32, 0x14, 0x0f},
	{1400, 0x09, 0x03, 0x32, 0x14, 0x0f},
	{1600, 0x0d, 0x42, 0x36, 0x0e, 0x0f},
	{1800, 0x0e, 0x47, 0x7a, 0x0e, 0x0f},
	{2000, 0x11, 0x64, 0x7a, 0x0e, 0x0b},
	{2200, 0x13, 0x64, 0x7e, 0x15, 0x0b},
	{2400, 0x13, 0x33, 0x7f, 0x15, 0x6a},
	{2500, 0x15, 0x54, 0x7f, 0x15, 0x6a},
};

const struct inno_video_mipi_dphy_info inno_video_mipi_dphy_max_1GHz = {
	.inno_mipi_dphy_timing_table = inno_mipi_dphy_timing_table_max_1GHz,
	.num_timings = ARRAY_SIZE(inno_mipi_dphy_timing_table_max_1GHz),
	.phy_max_rate = MAX_1GHZ,
};

const struct inno_video_mipi_dphy_info inno_video_mipi_dphy_max_2_5GHz = {
	.inno_mipi_dphy_timing_table = inno_mipi_dphy_timing_table_max_2_5GHz,
	.num_timings = ARRAY_SIZE(inno_mipi_dphy_timing_table_max_2_5GHz),
	.phy_max_rate = MAX_2_5GHZ,
};

struct mipi_dphy_timing {
	unsigned int clkmiss;
	unsigned int clkpost;
	unsigned int clkpre;
	unsigned int clkprepare;
	unsigned int clksettle;
	unsigned int clktermen;
	unsigned int clktrail;
	unsigned int clkzero;
	unsigned int dtermen;
	unsigned int eot;
	unsigned int hsexit;
	unsigned int hsprepare;
	unsigned int hszero;
	unsigned int hssettle;
	unsigned int hsskip;
	unsigned int hstrail;
	unsigned int init;
	unsigned int lpx;
	unsigned int taget;
	unsigned int tago;
	unsigned int tasure;
	unsigned int wakeup;
};

struct inno_video_phy {
	struct udevice *dev;
	enum phy_mode mode;
	const struct inno_video_mipi_dphy_info *mipi_dphy_info;
	struct resource phy;
	struct resource host;
	int lanes;
	struct {
		u8 prediv;
		u16 fbdiv;
		unsigned long rate;
	} pll;
};

enum {
	REGISTER_PART_ANALOG,
	REGISTER_PART_DIGITAL,
	REGISTER_PART_CLOCK_LANE,
	REGISTER_PART_DATA0_LANE,
	REGISTER_PART_DATA1_LANE,
	REGISTER_PART_DATA2_LANE,
	REGISTER_PART_DATA3_LANE,
	REGISTER_PART_LVDS,
};

static inline void phy_update_bits(struct inno_video_phy *inno,
				   u8 first, u8 second, u8 mask, u8 val)
{
	u32 reg = PHY_REG(first, second) << 2;
	u32 tmp, orig;

	orig = readl(inno->phy.start + reg);
	tmp = orig & ~mask;
	tmp |= val & mask;
	writel(tmp, inno->phy.start + reg);
}

static inline void host_update_bits(struct inno_video_phy *inno,
				    u32 reg, u32 mask, u32 val)
{
	u32 tmp, orig;

	orig = readl(inno->host.start + reg);
	tmp = orig & ~mask;
	tmp |= val & mask;
	writel(tmp, inno->host.start + reg);
}

static void mipi_dphy_timing_get_default(struct mipi_dphy_timing *timing,
					 unsigned long period)
{
	/* Global Operation Timing Parameters */
	timing->clkmiss = 0;
	timing->clkpost = 70000 + 52 * period;
	timing->clkpre = 8 * period;
	timing->clkprepare = 65000;
	timing->clksettle = 95000;
	timing->clktermen = 0;
	timing->clktrail = 80000;
	timing->clkzero = 260000;
	timing->dtermen = 0;
	timing->eot = 0;
	timing->hsexit = 120000;
	timing->hsprepare = 65000 + 4 * period;
	timing->hszero = 145000 + 6 * period;
	timing->hssettle = 85000 + 6 * period;
	timing->hsskip = 40000;
	timing->hstrail = max(8 * period, 60000 + 4 * period);
	timing->init = 100000000;
	timing->lpx = 60000;
	timing->taget = 5 * timing->lpx;
	timing->tago = 4 * timing->lpx;
	timing->tasure = 2 * timing->lpx;
	timing->wakeup = 1000000000;
}

static const struct inno_video_mipi_dphy_timing *
inno_mipi_dphy_get_timing(struct inno_video_phy *inno)
{
	const struct inno_video_mipi_dphy_timing *timings;
	unsigned int num_timings;
	unsigned int lane_mbps = inno->pll.rate / USEC_PER_SEC;
	unsigned int i;

	timings = inno->mipi_dphy_info->inno_mipi_dphy_timing_table;
	num_timings = inno->mipi_dphy_info->num_timings;

	for (i = 0; i < num_timings; i++)
		if (lane_mbps <= timings[i].max_lane_mbps)
			break;

	if (i == num_timings)
		--i;

	return &timings[i];
}

static void inno_mipi_dphy_max_2_5GHz_pll_enable(struct inno_video_phy *inno)
{
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x03,
			REG_PREDIV_MASK, REG_PREDIV(inno->pll.prediv));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x03,
			REG_FBDIV_HI_MASK, REG_FBDIV_HI(inno->pll.fbdiv >> 8));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x04,
			REG_FBDIV_LO_MASK, REG_FBDIV_LO(inno->pll.fbdiv));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x08,
			PLL_POST_DIV_ENABLE_MASK, PLL_POST_DIV_ENABLE);
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x0b,
			CLOCK_LANE_VOD_RANGE_SET_MASK,
			CLOCK_LANE_VOD_RANGE_SET(VOD_MAX_RANGE));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x01,
			REG_LDOPD_MASK | REG_PLLPD_MASK,
			REG_LDOPD_POWER_ON | REG_PLLPD_POWER_ON);
}

static void inno_mipi_dphy_max_1GHz_pll_enable(struct inno_video_phy *inno)
{
	/* Configure PLL */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x03,
			REG_PREDIV_MASK, REG_PREDIV(inno->pll.prediv));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x03,
			REG_FBDIV_HI_MASK, REG_FBDIV_HI(inno->pll.fbdiv >> 8));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x04,
			REG_FBDIV_LO_MASK, REG_FBDIV_LO(inno->pll.fbdiv));
	/* Enable PLL and LDO */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x01,
			REG_LDOPD_MASK | REG_PLLPD_MASK,
			REG_LDOPD_POWER_ON | REG_PLLPD_POWER_ON);
}

static void inno_mipi_dphy_reset(struct inno_video_phy *inno)
{
	/* Reset analog */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x01,
			 REG_SYNCRST_MASK, REG_SYNCRST_RESET);
	udelay(1);
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x01,
			 REG_SYNCRST_MASK, REG_SYNCRST_NORMAL);
	/* Reset digital */
	phy_update_bits(inno, REGISTER_PART_DIGITAL, 0x00,
			 REG_DIG_RSTN_MASK, REG_DIG_RSTN_RESET);
	udelay(1);
	phy_update_bits(inno, REGISTER_PART_DIGITAL, 0x00,
			 REG_DIG_RSTN_MASK, REG_DIG_RSTN_NORMAL);
}

static void inno_mipi_dphy_timing_init(struct inno_video_phy *inno)
{
	struct mipi_dphy_timing gotp;
	u32 t_txbyteclkhs, t_txclkesc, ui;
	u32 txbyteclkhs, txclkesc, esc_clk_div;
	u32 hs_exit, clk_post, clk_pre, wakeup, lpx, ta_go, ta_sure, ta_wait;
	u32 hs_prepare, hs_trail, hs_zero, clk_lane_hs_zero, data_lane_hs_zero;
	const struct inno_video_mipi_dphy_timing *timing;
	unsigned int i;

	txbyteclkhs = inno->pll.rate / 8;
	t_txbyteclkhs = div_u64(PSEC_PER_SEC, txbyteclkhs);
	esc_clk_div = DIV_ROUND_UP(txbyteclkhs, 20000000);
	txclkesc = txbyteclkhs / esc_clk_div;
	t_txclkesc = div_u64(PSEC_PER_SEC, txclkesc);

	ui = div_u64(PSEC_PER_SEC, inno->pll.rate);

	memset(&gotp, 0, sizeof(gotp));
	mipi_dphy_timing_get_default(&gotp, ui);

	/*
	 * The value of counter for HS Ths-exit
	 * Ths-exit = Tpin_txbyteclkhs * value
	 */
	hs_exit = DIV_ROUND_UP(gotp.hsexit, t_txbyteclkhs);
	/*
	 * The value of counter for HS Tclk-post
	 * Tclk-post = Tpin_txbyteclkhs * value
	 */
	clk_post = DIV_ROUND_UP(gotp.clkpost, t_txbyteclkhs);
	/*
	 * The value of counter for HS Tclk-pre
	 * Tclk-pre = Tpin_txbyteclkhs * value
	 */
	clk_pre = DIV_ROUND_UP(gotp.clkpre, t_txbyteclkhs);

	/*
	 * The value of counter for HS Tlpx Time
	 * Tlpx = Tpin_txbyteclkhs * (2 + value)
	 */
	lpx = DIV_ROUND_UP(gotp.lpx, t_txbyteclkhs);
	if (lpx >= 2)
		lpx -= 2;

	/*
	 * The value of counter for HS Tta-go
	 * Tta-go for turnaround
	 * Tta-go = Ttxclkesc * value
	 */
	ta_go = DIV_ROUND_UP(gotp.tago, t_txclkesc);
	/*
	 * The value of counter for HS Tta-sure
	 * Tta-sure for turnaround
	 * Tta-sure = Ttxclkesc * value
	 */
	ta_sure = DIV_ROUND_UP(gotp.tasure, t_txclkesc);
	/*
	 * The value of counter for HS Tta-wait
	 * Tta-wait for turnaround
	 * Tta-wait = Ttxclkesc * value
	 */
	ta_wait = DIV_ROUND_UP(gotp.taget, t_txclkesc);

	timing = inno_mipi_dphy_get_timing(inno);

	/*
	 * The value of counter for HS Tlpx Time
	 * Tlpx = Tpin_txbyteclkhs * (2 + value)
	 */
	if (inno->mipi_dphy_info->phy_max_rate == MAX_1GHZ) {
		lpx = DIV_ROUND_UP(gotp.lpx, t_txbyteclkhs);
		if (lpx >= 2)
			lpx -= 2;
	} else {
		lpx = timing->lpx;
	}

	hs_prepare = timing->hs_prepare;
	hs_trail = timing->hs_trail;
	clk_lane_hs_zero = timing->clk_lane_hs_zero;
	data_lane_hs_zero = timing->data_lane_hs_zero;
	wakeup = 0x3ff;

	for (i = REGISTER_PART_CLOCK_LANE; i <= REGISTER_PART_DATA3_LANE; i++) {
		if (i == REGISTER_PART_CLOCK_LANE)
			hs_zero = clk_lane_hs_zero;
		else
			hs_zero = data_lane_hs_zero;

		phy_update_bits(inno, i, 0x05, T_LPX_CNT_MASK,
				T_LPX_CNT(lpx));
		phy_update_bits(inno, i, 0x06, T_HS_PREPARE_CNT_MASK,
				T_HS_PREPARE_CNT(hs_prepare));

		if (inno->mipi_dphy_info->phy_max_rate == MAX_2_5GHZ)
			phy_update_bits(inno, i, 0x06, T_HS_ZERO_CNT_HI_MASK,
					T_HS_ZERO_CNT_HI(hs_zero >> 6));

		phy_update_bits(inno, i, 0x07, T_HS_ZERO_CNT_LO_MASK,
				T_HS_ZERO_CNT_LO(hs_zero));
		phy_update_bits(inno, i, 0x08, T_HS_TRAIL_CNT_MASK,
				T_HS_TRAIL_CNT(hs_trail));

		if (inno->mipi_dphy_info->phy_max_rate == MAX_2_5GHZ)
			phy_update_bits(inno, i, 0x11, T_HS_EXIT_CNT_HI_MASK,
					T_HS_EXIT_CNT_HI(hs_exit >> 5));

		phy_update_bits(inno, i, 0x09, T_HS_EXIT_CNT_LO_MASK,
				T_HS_EXIT_CNT_LO(hs_exit));

		if (inno->mipi_dphy_info->phy_max_rate == MAX_2_5GHZ)
			phy_update_bits(inno, i, 0x10, T_CLK_POST_HI_MASK,
					T_CLK_POST_HI(clk_post >> 4));

		phy_update_bits(inno, i, 0x0a, T_CLK_POST_CNT_LO_MASK,
				T_CLK_POST_CNT_LO(clk_post));
		phy_update_bits(inno, i, 0x0e, T_CLK_PRE_CNT_MASK,
				T_CLK_PRE_CNT(clk_pre));
		phy_update_bits(inno, i, 0x0c, T_WAKEUP_CNT_HI_MASK,
				T_WAKEUP_CNT_HI(wakeup >> 8));
		phy_update_bits(inno, i, 0x0d, T_WAKEUP_CNT_LO_MASK,
				T_WAKEUP_CNT_LO(wakeup));
		phy_update_bits(inno, i, 0x10, T_TA_GO_CNT_MASK,
				T_TA_GO_CNT(ta_go));
		phy_update_bits(inno, i, 0x11, T_TA_SURE_CNT_MASK,
				T_TA_SURE_CNT(ta_sure));
		phy_update_bits(inno, i, 0x12, T_TA_WAIT_CNT_MASK,
				T_TA_WAIT_CNT(ta_wait));
	}
}

static void inno_mipi_dphy_lane_enable(struct inno_video_phy *inno)
{
	u8 val = LANE_EN_CK;

	switch (inno->lanes) {
	case 1:
		val |= LANE_EN_0;
		break;
	case 2:
		val |= LANE_EN_1 | LANE_EN_0;
		break;
	case 3:
		val |= LANE_EN_2 | LANE_EN_1 | LANE_EN_0;
		break;
	case 4:
	default:
		val |= LANE_EN_3 | LANE_EN_2 | LANE_EN_1 | LANE_EN_0;
		break;
	}

	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x00, LANE_EN_MASK, val);
}

static void inno_video_phy_mipi_mode_enable(struct inno_video_phy *inno)
{
	struct rockchip_phy *phy =
		(struct rockchip_phy *)dev_get_driver_data(inno->dev);

	/* Select MIPI mode */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x03,
			MODE_ENABLE_MASK, MIPI_MODE_ENABLE);

	/* set px30 pin_txclkesc_0 invert disable */
	if (phy->soc_type == PX30_VIDEO_PHY || phy->soc_type == PX30S_VIDEO_PHY)
		phy_update_bits(inno, REGISTER_PART_DIGITAL, 0x01,
				INVERT_TXCLKESC_MASK, INVERT_TXCLKESC_DISABLE);

	if (inno->mipi_dphy_info->phy_max_rate == MAX_2_5GHZ)
		inno_mipi_dphy_max_2_5GHz_pll_enable(inno);
	else
		inno_mipi_dphy_max_1GHz_pll_enable(inno);

	inno_mipi_dphy_reset(inno);
	inno_mipi_dphy_timing_init(inno);
	inno_mipi_dphy_lane_enable(inno);
}

static void inno_video_phy_lvds_mode_enable(struct inno_video_phy *inno)
{
	u8 prediv = 2;
	u16 fbdiv = 28;
	u32 val;
	int ret;

	/* Sample clock reverse direction */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x08,
			SAMPLE_CLOCK_DIRECTION_MASK | LOWFRE_EN_MASK,
			SAMPLE_CLOCK_DIRECTION_REVERSE |
			PLL_OUTPUT_FREQUENCY_DIV_BY_1);

	/* Reset LVDS digital logic */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x00,
			LVDS_DIGITAL_INTERNAL_RESET_MASK,
			LVDS_DIGITAL_INTERNAL_RESET_ENABLE);
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x00,
			LVDS_DIGITAL_INTERNAL_RESET_MASK,
			LVDS_DIGITAL_INTERNAL_RESET_DISABLE);

	/* Select LVDS mode */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x03,
			MODE_ENABLE_MASK, LVDS_MODE_ENABLE);

	/* Configure PLL */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x03,
			REG_PREDIV_MASK, REG_PREDIV(prediv));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x03,
			REG_FBDIV_HI_MASK, REG_FBDIV_HI(fbdiv >> 8));
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x04,
			REG_FBDIV_LO_MASK, REG_FBDIV_LO(fbdiv));
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x08, 0xff, 0xfc);

	/* Enable PLL and Bandgap */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x0b,
			LVDS_PLL_POWER_MASK | LVDS_BANDGAP_POWER_MASK,
			LVDS_PLL_POWER_ON | LVDS_BANDGAP_POWER_ON);

	ret = readl_poll_timeout(inno->host.start + DSI_PHY_STATUS,
				 val, val & PHY_LOCK, 10000);
	if (ret)
		dev_err(phy->dev, "PLL is not lock\n");

	/* Select PLL mode */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x1e,
			PLL_MODE_SEL_MASK, PLL_MODE_SEL_LVDS_MODE);

	/* Enable LVDS digital logic */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x01,
			LVDS_DIGITAL_INTERNAL_ENABLE_MASK,
			LVDS_DIGITAL_INTERNAL_ENABLE);
	/* Enable LVDS analog driver */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x0b,
			LVDS_LANE_EN_MASK, LVDS_CLK_LANE_EN |
			LVDS_DATA_LANE0_EN | LVDS_DATA_LANE1_EN |
			LVDS_DATA_LANE2_EN | LVDS_DATA_LANE3_EN);
}

static void inno_video_phy_ttl_mode_enable(struct inno_video_phy *inno)
{
	/* Reset digital logic */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x00,
			LVDS_DIGITAL_INTERNAL_RESET_MASK,
			LVDS_DIGITAL_INTERNAL_RESET_ENABLE);
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x00,
			LVDS_DIGITAL_INTERNAL_RESET_MASK,
			LVDS_DIGITAL_INTERNAL_RESET_DISABLE);

	/* Select TTL mode */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x03,
			MODE_ENABLE_MASK, TTL_MODE_ENABLE);
	/* Enable digital logic */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x01,
			LVDS_DIGITAL_INTERNAL_ENABLE_MASK,
			LVDS_DIGITAL_INTERNAL_ENABLE);
	/* Enable analog driver */
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x0b,
			LVDS_LANE_EN_MASK, LVDS_CLK_LANE_EN |
			LVDS_DATA_LANE0_EN | LVDS_DATA_LANE1_EN |
			LVDS_DATA_LANE2_EN | LVDS_DATA_LANE3_EN);
	/* Enable for clk lane in TTL mode */
	host_update_bits(inno, DSI_PHY_RSTZ, PHY_ENABLECLK, PHY_ENABLECLK);
}

static int inno_video_phy_power_on(struct rockchip_phy *phy)
{
	struct inno_video_phy *inno = dev_get_priv(phy->dev);

	/* Bandgap power on */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x00,
			BANDGAP_POWER_MASK, BANDGAP_POWER_ON);
	/* Enable power work */
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x00,
			POWER_WORK_MASK, POWER_WORK_ENABLE);

	switch (inno->mode) {
	case PHY_MODE_MIPI_DPHY:
		inno_video_phy_mipi_mode_enable(inno);
		break;
	case PHY_MODE_VIDEO_LVDS:
		inno_video_phy_lvds_mode_enable(inno);
		break;
	case PHY_MODE_VIDEO_TTL:
		inno_video_phy_ttl_mode_enable(inno);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int inno_video_phy_power_off(struct rockchip_phy *phy)
{
	struct inno_video_phy *inno = dev_get_priv(phy->dev);

	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x00, LANE_EN_MASK, 0);
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x01,
			REG_LDOPD_MASK | REG_PLLPD_MASK,
			REG_LDOPD_POWER_DOWN | REG_PLLPD_POWER_DOWN);
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x00,
			POWER_WORK_MASK, POWER_WORK_DISABLE);
	phy_update_bits(inno, REGISTER_PART_ANALOG, 0x00,
			BANDGAP_POWER_MASK, BANDGAP_POWER_DOWN);

	phy_update_bits(inno, REGISTER_PART_LVDS, 0x0b, LVDS_LANE_EN_MASK, 0);
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x01,
			LVDS_DIGITAL_INTERNAL_ENABLE_MASK,
			LVDS_DIGITAL_INTERNAL_DISABLE);
	phy_update_bits(inno, REGISTER_PART_LVDS, 0x0b,
			LVDS_PLL_POWER_MASK | LVDS_BANDGAP_POWER_MASK,
			LVDS_PLL_POWER_OFF | LVDS_BANDGAP_POWER_DOWN);

	return 0;
}

static unsigned long inno_video_phy_pll_round_rate(unsigned long prate,
						   unsigned long rate,
						   u8 *prediv, u16 *fbdiv)
{
	unsigned long best_freq = 0;
	unsigned long fref, fout;
	u8 min_prediv, max_prediv;
	u8 _prediv, best_prediv = 1;
	u16 _fbdiv, best_fbdiv = 1;
	u32 min_delta = 0xffffffff;

	/*
	 * The PLL output frequency can be calculated using a simple formula:
	 * PLL_Output_Frequency = (FREF / PREDIV * FBDIV) / 2
	 * PLL_Output_Frequency: it is equal to DDR-Clock-Frequency * 2
	 */
	fref = prate / 2;
	if (rate > 1000000000UL)
		fout = 1000000000UL;
	else
		fout = rate;

	/* 5Mhz < Fref / prediv < 40MHz */
	min_prediv = DIV_ROUND_UP(fref, 40000000);
	max_prediv = fref / 5000000;

	for (_prediv = min_prediv; _prediv <= max_prediv; _prediv++) {
		u64 tmp;
		u32 delta;

		tmp = (u64)fout * _prediv;
		do_div(tmp, fref);
		_fbdiv = tmp;

		/*
		 * The all possible settings of feedback divider are
		 * 12, 13, 14, 16, ~ 511
		 */
		if (_fbdiv == 15)
			continue;

		if (_fbdiv < 12 || _fbdiv > 511)
			continue;

		tmp = (u64)_fbdiv * fref;
		do_div(tmp, _prediv);

		delta = abs(fout - tmp);
		if (!delta) {
			best_prediv = _prediv;
			best_fbdiv = _fbdiv;
			best_freq = tmp;
			break;
		} else if (delta < min_delta) {
			best_prediv = _prediv;
			best_fbdiv = _fbdiv;
			best_freq = tmp;
			min_delta = delta;
		}
	}

	if (best_freq) {
		*prediv = best_prediv;
		*fbdiv = best_fbdiv;
	}

	return best_freq;
}

static unsigned long inno_video_phy_set_pll(struct rockchip_phy *phy,
					    unsigned long rate)
{
	struct inno_video_phy *inno = dev_get_priv(phy->dev);
	unsigned long fin, fout;
	u16 fbdiv = 1;
	u8 prediv = 1;

	fin = 24000000;
	fout = inno_video_phy_pll_round_rate(fin, rate, &prediv, &fbdiv);

	dev_dbg(phy->dev, "fin=%lu, fout=%lu, prediv=%u, fbdiv=%u\n",
		fin, fout, prediv, fbdiv);

	inno->pll.prediv = prediv;
	inno->pll.fbdiv = fbdiv;
	inno->pll.rate = fout;

	return fout;
}

static int inno_video_phy_set_mode(struct rockchip_phy *phy,
				   enum phy_mode mode)
{
	struct inno_video_phy *inno = dev_get_priv(phy->dev);

	switch (mode) {
	case PHY_MODE_MIPI_DPHY:
	case PHY_MODE_VIDEO_LVDS:
	case PHY_MODE_VIDEO_TTL:
		inno->mode = mode;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int inno_video_phy_probe(struct udevice *dev)
{
	struct inno_video_phy *inno = dev_get_priv(dev);
	struct rockchip_phy *tmp_phy;
	struct rockchip_phy *phy;
	int ret;

	phy = calloc(1, sizeof(*phy));
	if (!phy)
		return -ENOMEM;

	tmp_phy = (struct rockchip_phy *)dev_get_driver_data(dev);
	dev->driver_data = (ulong)phy;
	memcpy(phy, tmp_phy, sizeof(*phy));

	inno->dev = dev;
	inno->mipi_dphy_info = phy->data;
	if (soc_is_px30s())
		inno->mipi_dphy_info = &inno_video_mipi_dphy_max_2_5GHz;

	inno->lanes = ofnode_read_u32_default(dev->node, "inno,lanes", 4);

	ret = dev_read_resource(dev, 0, &inno->phy);
	if (ret < 0) {
		dev_err(dev, "resource \"phy\" not found\n");
		return ret;
	}

	ret = dev_read_resource(dev, 1, &inno->host);
	if (ret < 0) {
		int node;
		const fdt32_t *php = NULL;
		struct fdt_resource fres;

		fdt_for_each_subnode(node, gd->fdt_blob, 0) {
			php = fdt_getprop(gd->fdt_blob, node, "phys", NULL);
			if (fdt32_to_cpu(*php) == dev->node.np->phandle) {
				if (fdt_get_resource(gd->fdt_blob, node, "reg", 0, &fres))
					php = NULL;
				break;
			}
		}

		if (!php) {
			dev_err(dev, "resource \"host\" not found\n");
			return ret;
		}

		inno->host.start = fres.start;
		inno->host.end = fres.end;
	}

	phy->dev = dev;

	return 0;
}

static const struct rockchip_phy_funcs inno_video_phy_funcs = {
	.power_on = inno_video_phy_power_on,
	.power_off = inno_video_phy_power_off,
	.set_pll = inno_video_phy_set_pll,
	.set_mode = inno_video_phy_set_mode,
};

static struct rockchip_phy px30_inno_video_phy_driver_data = {
	.soc_type = PX30_VIDEO_PHY,
	.funcs = &inno_video_phy_funcs,
	.data = &inno_video_mipi_dphy_max_1GHz,
};

static struct rockchip_phy px30s_inno_video_phy_driver_data = {
	.soc_type = PX30S_VIDEO_PHY,
	.funcs = &inno_video_phy_funcs,
	.data = &inno_video_mipi_dphy_max_2_5GHz,
};

static struct rockchip_phy rk3128_inno_video_phy_driver_data = {
	.soc_type = RK3128_VIDEO_PHY,
	.funcs = &inno_video_phy_funcs,
	.data = &inno_video_mipi_dphy_max_1GHz,
};

static struct rockchip_phy rk3368_inno_video_phy_driver_data = {
	.soc_type = RK3368_VIDEO_PHY,
	.funcs = &inno_video_phy_funcs,
	.data = &inno_video_mipi_dphy_max_1GHz,
};

static struct rockchip_phy rk3568_inno_video_phy_driver_data = {
	.soc_type = RK3568_VIDEO_PHY,
	.funcs = &inno_video_phy_funcs,
	.data = &inno_video_mipi_dphy_max_2_5GHz,
};

static const struct udevice_id inno_video_phy_ids[] = {
	{
		.compatible = "rockchip,px30-video-phy",
		.data = (ulong)&px30_inno_video_phy_driver_data,
	},
	{
		.compatible = "rockchip,px30s-video-phy",
		.data = (ulong)&px30s_inno_video_phy_driver_data,
	},
	{
		.compatible = "rockchip,rk3128-video-phy",
		.data = (ulong)&rk3128_inno_video_phy_driver_data,
	},
	{
		.compatible = "rockchip,rk3368-video-phy",
		.data = (ulong)&rk3368_inno_video_phy_driver_data,
	},
	{
		.compatible = "rockchip,rk3568-video-phy",
		.data = (ulong)&rk3568_inno_video_phy_driver_data,
	},
#if defined(CONFIG_TARGET_ODROID_M1) || defined(CONFIG_TARGET_ODROID_M1S)
	{
		.compatible = "rockchip,rk3568-dsi-dphy",
		.data = (ulong)&rk3568_inno_video_phy_driver_data,
	},
#endif
	{}
};

U_BOOT_DRIVER(inno_video_combo_phy) = {
	.name = "inno_video_combo_phy",
	.id = UCLASS_PHY,
	.of_match = inno_video_phy_ids,
	.probe = inno_video_phy_probe,
	.priv_auto_alloc_size = sizeof(struct inno_video_phy),
};
