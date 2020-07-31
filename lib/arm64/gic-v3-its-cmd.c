/*
 * Copyright (C) 2020, Red Hat Inc, Eric Auger <eric.auger@redhat.com>
 *
 * Most of the code is copy-pasted from:
 * drivers/irqchip/irq-gic-v3-its.c
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/io.h>
#include <asm/gic.h>

#define ITS_ITT_ALIGN		SZ_256

static const char * const its_cmd_string[] = {
	[GITS_CMD_MAPD]		= "MAPD",
	[GITS_CMD_MAPC]		= "MAPC",
	[GITS_CMD_MAPTI]	= "MAPTI",
	[GITS_CMD_MAPI]		= "MAPI",
	[GITS_CMD_MOVI]		= "MOVI",
	[GITS_CMD_DISCARD]	= "DISCARD",
	[GITS_CMD_INV]		= "INV",
	[GITS_CMD_MOVALL]	= "MOVALL",
	[GITS_CMD_INVALL]	= "INVALL",
	[GITS_CMD_INT]		= "INT",
	[GITS_CMD_CLEAR]	= "CLEAR",
	[GITS_CMD_SYNC]		= "SYNC",
};

struct its_cmd_desc {
	union {
		struct {
			struct its_device *dev;
			u32 event_id;
		} its_inv_cmd;

		struct {
			struct its_device *dev;
			u32 event_id;
		} its_int_cmd;

		struct {
			struct its_device *dev;
			bool valid;
		} its_mapd_cmd;

		struct {
			struct its_collection *col;
			bool valid;
		} its_mapc_cmd;

		struct {
			struct its_device *dev;
			u32 phys_id;
			u32 event_id;
			u32 col_id;
		} its_mapti_cmd;

		struct {
			struct its_device *dev;
			struct its_collection *col;
			u32 event_id;
		} its_movi_cmd;

		struct {
			struct its_device *dev;
			u32 event_id;
		} its_discard_cmd;

		struct {
			struct its_device *dev;
			u32 event_id;
		} its_clear_cmd;

		struct {
			struct its_collection *col;
		} its_invall_cmd;

		struct {
			struct its_collection *col;
		} its_sync_cmd;
	};
	bool verbose;
};

typedef void (*its_cmd_builder_t)(struct its_cmd_block *,
				  struct its_cmd_desc *);

/* ITS COMMANDS */

static void its_mask_encode(u64 *raw_cmd, u64 val, int h, int l)
{
	u64 mask = GENMASK_ULL(h, l);
	*raw_cmd &= ~mask;
	*raw_cmd |= (val << l) & mask;
}

static void its_encode_cmd(struct its_cmd_block *cmd, u8 cmd_nr)
{
	its_mask_encode(&cmd->raw_cmd[0], cmd_nr, 7, 0);
}

static void its_encode_devid(struct its_cmd_block *cmd, u32 devid)
{
	its_mask_encode(&cmd->raw_cmd[0], devid, 63, 32);
}

static void its_encode_event_id(struct its_cmd_block *cmd, u32 id)
{
	its_mask_encode(&cmd->raw_cmd[1], id, 31, 0);
}

static void its_encode_phys_id(struct its_cmd_block *cmd, u32 phys_id)
{
	its_mask_encode(&cmd->raw_cmd[1], phys_id, 63, 32);
}

static void its_encode_size(struct its_cmd_block *cmd, u8 size)
{
	its_mask_encode(&cmd->raw_cmd[1], size, 4, 0);
}

static void its_encode_itt(struct its_cmd_block *cmd, u64 itt_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], itt_addr >> 8, 50, 8);
}

static void its_encode_valid(struct its_cmd_block *cmd, int valid)
{
	its_mask_encode(&cmd->raw_cmd[2], !!valid, 63, 63);
}

static void its_encode_target(struct its_cmd_block *cmd, u64 target_addr)
{
	its_mask_encode(&cmd->raw_cmd[2], target_addr >> 16, 50, 16);
}

static void its_encode_collection(struct its_cmd_block *cmd, u16 col)
{
	its_mask_encode(&cmd->raw_cmd[2], col, 15, 0);
}

static inline void its_fixup_cmd(struct its_cmd_block *cmd)
{
	/* Let's fixup BE commands */
	cmd->raw_cmd[0] = cpu_to_le64(cmd->raw_cmd[0]);
	cmd->raw_cmd[1] = cpu_to_le64(cmd->raw_cmd[1]);
	cmd->raw_cmd[2] = cpu_to_le64(cmd->raw_cmd[2]);
	cmd->raw_cmd[3] = cpu_to_le64(cmd->raw_cmd[3]);
}

static u64 its_cmd_ptr_to_offset(struct its_cmd_block *ptr)
{
	return (ptr - its_data.cmd_base) * sizeof(*ptr);
}

static struct its_cmd_block *its_post_commands(void)
{
	u64 wr = its_cmd_ptr_to_offset(its_data.cmd_write);

	writeq(wr, its_data.base + GITS_CWRITER);
	return its_data.cmd_write;
}

static struct its_cmd_block *its_allocate_entry(void)
{
	struct its_cmd_block *cmd;

	cmd = its_data.cmd_write++;
	if ((u64)its_data.cmd_write  == (u64)its_data.cmd_base + SZ_64K)
		its_data.cmd_write = its_data.cmd_base;
	return cmd;
}

static void its_wait_for_range_completion(struct its_cmd_block *from,
					  struct its_cmd_block *to)
{
	u64 rd_idx, from_idx, to_idx;
	u32 count = 1000000;    /* 1s! */

	from_idx = its_cmd_ptr_to_offset(from);
	to_idx = its_cmd_ptr_to_offset(to);
	while (1) {
		rd_idx = readq(its_data.base + GITS_CREADR);
		if (rd_idx >= to_idx || rd_idx < from_idx)
			break;

		count--;
		if (!count) {
			unsigned int cmd_id = from->raw_cmd[0] & 0xFF;

			assert_msg(false, "%s timeout!",
			       cmd_id <= 0xF ? its_cmd_string[cmd_id] :
			       "Unexpected");
		}
		udelay(1);
	}
}

static void its_send_single_command(its_cmd_builder_t builder,
				    struct its_cmd_desc *desc)
{
	struct its_cmd_block *cmd, *next_cmd;

	cmd = its_allocate_entry();
	builder(cmd, desc);
	next_cmd = its_post_commands();

	its_wait_for_range_completion(cmd, next_cmd);
}

static void its_build_mapd_cmd(struct its_cmd_block *cmd,
			       struct its_cmd_desc *desc)
{
	unsigned long itt_addr;
	u8 size = desc->its_mapd_cmd.dev->nr_ites;

	itt_addr = (unsigned long)(virt_to_phys(desc->its_mapd_cmd.dev->itt));
	itt_addr = ALIGN(itt_addr, ITS_ITT_ALIGN);

	its_encode_cmd(cmd, GITS_CMD_MAPD);
	its_encode_devid(cmd, desc->its_mapd_cmd.dev->device_id);
	its_encode_size(cmd, size - 1);
	its_encode_itt(cmd, itt_addr);
	its_encode_valid(cmd, desc->its_mapd_cmd.valid);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("ITS: MAPD devid=%d size = 0x%x itt=0x%lx valid=%d\n",
			desc->its_mapd_cmd.dev->device_id,
			size, itt_addr, desc->its_mapd_cmd.valid);
}

static void its_build_mapc_cmd(struct its_cmd_block *cmd,
			       struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MAPC);
	its_encode_collection(cmd, desc->its_mapc_cmd.col->col_id);
	its_encode_target(cmd, desc->its_mapc_cmd.col->target_address);
	its_encode_valid(cmd, desc->its_mapc_cmd.valid);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("MAPC col_id=%d target_addr = 0x%lx valid=%d\n",
		       desc->its_mapc_cmd.col->col_id,
		       desc->its_mapc_cmd.col->target_address,
		       desc->its_mapc_cmd.valid);
}

static void its_build_mapti_cmd(struct its_cmd_block *cmd,
				struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MAPTI);
	its_encode_devid(cmd, desc->its_mapti_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_mapti_cmd.event_id);
	its_encode_phys_id(cmd, desc->its_mapti_cmd.phys_id);
	its_encode_collection(cmd, desc->its_mapti_cmd.col_id);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("MAPTI dev_id=%d event_id=%d -> phys_id=%d, col_id=%d\n",
		       desc->its_mapti_cmd.dev->device_id,
		       desc->its_mapti_cmd.event_id,
		       desc->its_mapti_cmd.phys_id,
		       desc->its_mapti_cmd.col_id);
}

static void its_build_invall_cmd(struct its_cmd_block *cmd,
			      struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_INVALL);
	its_encode_collection(cmd, desc->its_invall_cmd.col->col_id);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("INVALL col_id=%d\n", desc->its_invall_cmd.col->col_id);
}

static void its_build_clear_cmd(struct its_cmd_block *cmd,
				struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_CLEAR);
	its_encode_devid(cmd, desc->its_clear_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_clear_cmd.event_id);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("CLEAR dev_id=%d event_id=%d\n", desc->its_clear_cmd.dev->device_id, desc->its_clear_cmd.event_id);
}

static void its_build_discard_cmd(struct its_cmd_block *cmd,
				  struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_DISCARD);
	its_encode_devid(cmd, desc->its_discard_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_discard_cmd.event_id);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("DISCARD dev_id=%d event_id=%d\n",
			desc->its_clear_cmd.dev->device_id, desc->its_clear_cmd.event_id);
}

static void its_build_inv_cmd(struct its_cmd_block *cmd,
			      struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_INV);
	its_encode_devid(cmd, desc->its_inv_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_inv_cmd.event_id);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("INV dev_id=%d event_id=%d\n",
		       desc->its_inv_cmd.dev->device_id,
		       desc->its_inv_cmd.event_id);
}

static void its_build_int_cmd(struct its_cmd_block *cmd,
			      struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_INT);
	its_encode_devid(cmd, desc->its_int_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_int_cmd.event_id);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("INT dev_id=%d event_id=%d\n",
		       desc->its_int_cmd.dev->device_id,
		       desc->its_int_cmd.event_id);
}

static void its_build_sync_cmd(struct its_cmd_block *cmd,
			       struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_SYNC);
	its_encode_target(cmd, desc->its_sync_cmd.col->target_address);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("SYNC target_addr = 0x%lx\n",
		       desc->its_sync_cmd.col->target_address);
}

static void its_build_movi_cmd(struct its_cmd_block *cmd,
			       struct its_cmd_desc *desc)
{
	its_encode_cmd(cmd, GITS_CMD_MOVI);
	its_encode_devid(cmd, desc->its_movi_cmd.dev->device_id);
	its_encode_event_id(cmd, desc->its_movi_cmd.event_id);
	its_encode_collection(cmd, desc->its_movi_cmd.col->col_id);
	its_fixup_cmd(cmd);
	if (desc->verbose)
		printf("MOVI dev_id=%d event_id = %d col_id=%d\n",
		       desc->its_movi_cmd.dev->device_id,
		       desc->its_movi_cmd.event_id,
		       desc->its_movi_cmd.col->col_id);
}

void __its_send_mapd(struct its_device *dev, int valid, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_mapd_cmd.dev = dev;
	desc.its_mapd_cmd.valid = !!valid;
	desc.verbose = verbose;

	its_send_single_command(its_build_mapd_cmd, &desc);
}

void __its_send_mapc(struct its_collection *col, int valid, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_mapc_cmd.col = col;
	desc.its_mapc_cmd.valid = !!valid;
	desc.verbose = verbose;

	its_send_single_command(its_build_mapc_cmd, &desc);
}

void __its_send_mapti(struct its_device *dev, u32 irq_id,
		      u32 event_id, struct its_collection *col, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_mapti_cmd.dev = dev;
	desc.its_mapti_cmd.phys_id = irq_id;
	desc.its_mapti_cmd.event_id = event_id;
	desc.its_mapti_cmd.col_id = col->col_id;
	desc.verbose = verbose;

	its_send_single_command(its_build_mapti_cmd, &desc);
}

void __its_send_int(struct its_device *dev, u32 event_id, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_int_cmd.dev = dev;
	desc.its_int_cmd.event_id = event_id;
	desc.verbose = verbose;

	its_send_single_command(its_build_int_cmd, &desc);
}

void __its_send_movi(struct its_device *dev, struct its_collection *col,
		     u32 id, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_movi_cmd.dev = dev;
	desc.its_movi_cmd.col = col;
	desc.its_movi_cmd.event_id = id;
	desc.verbose = verbose;

	its_send_single_command(its_build_movi_cmd, &desc);
}

void __its_send_invall(struct its_collection *col, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_invall_cmd.col = col;
	desc.verbose = verbose;

	its_send_single_command(its_build_invall_cmd, &desc);
}

void __its_send_inv(struct its_device *dev, u32 event_id, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_inv_cmd.dev = dev;
	desc.its_inv_cmd.event_id = event_id;
	desc.verbose = verbose;

	its_send_single_command(its_build_inv_cmd, &desc);
}

void __its_send_discard(struct its_device *dev, u32 event_id, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_discard_cmd.dev = dev;
	desc.its_discard_cmd.event_id = event_id;
	desc.verbose = verbose;

	its_send_single_command(its_build_discard_cmd, &desc);
}

void __its_send_clear(struct its_device *dev, u32 event_id, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_clear_cmd.dev = dev;
	desc.its_clear_cmd.event_id = event_id;
	desc.verbose = verbose;

	its_send_single_command(its_build_clear_cmd, &desc);
}

void __its_send_sync(struct its_collection *col, bool verbose)
{
	struct its_cmd_desc desc;

	desc.its_sync_cmd.col = col;
	desc.verbose = verbose;

	its_send_single_command(its_build_sync_cmd, &desc);
}

