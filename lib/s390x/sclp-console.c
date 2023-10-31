/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SCLP line mode and ASCII console driver
 * Some parts taken from the Linux kernel.
 *
 * Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 *
 * Copyright IBM Corp. 1999
 * Author(s): Martin Peschke <mpeschke@de.ibm.com>
 *	      Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#include <libcflat.h>
#include <string.h>
#include <asm/page.h>
#include <asm/arch_def.h>
#include <asm/io.h>
#include <asm/spinlock.h>
#include "hardware.h"
#include "sclp.h"

/*
 * ASCII (IBM PC 437) -> EBCDIC 037
 */
static uint8_t _ascebc[256] = {
 /*00 NUL   SOH   STX   ETX   EOT   ENQ   ACK   BEL */
     0x00, 0x01, 0x02, 0x03, 0x37, 0x2D, 0x2E, 0x2F,
 /*08  BS    HT    LF    VT    FF    CR    SO    SI */
 /*              ->NL                               */
     0x16, 0x05, 0x15, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
 /*10 DLE   DC1   DC2   DC3   DC4   NAK   SYN   ETB */
     0x10, 0x11, 0x12, 0x13, 0x3C, 0x3D, 0x32, 0x26,
 /*18 CAN    EM   SUB   ESC    FS    GS    RS    US */
 /*                               ->IGS ->IRS ->IUS */
     0x18, 0x19, 0x3F, 0x27, 0x22, 0x1D, 0x1E, 0x1F,
 /*20  SP     !     "     #     $     %     &     ' */
     0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D,
 /*28   (     )     *     +     ,     -    .      / */
     0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
 /*30   0     1     2     3     4     5     6     7 */
     0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
 /*38   8     9     :     ;     <     =     >     ? */
     0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
 /*40   @     A     B     C     D     E     F     G */
     0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
 /*48   H     I     J     K     L     M     N     O */
     0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
 /*50   P     Q     R     S     T     U     V     W */
     0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
 /*58   X     Y     Z     [     \     ]     ^     _ */
     0xE7, 0xE8, 0xE9, 0xBA, 0xE0, 0xBB, 0xB0, 0x6D,
 /*60   `     a     b     c     d     e     f     g */
     0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
 /*68   h     i     j     k     l     m     n     o */
     0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
 /*70   p     q     r     s     t     u     v     w */
     0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
 /*78   x     y     z     {     |     }     ~    DL */
     0xA7, 0xA8, 0xA9, 0xC0, 0x4F, 0xD0, 0xA1, 0x07,
 /*80*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*88*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*90*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*98*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*A0*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*A8*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*B0*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*B8*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*C0*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*C8*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*D0*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*D8*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*E0        sz	*/
     0x3F, 0x59, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*E8*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*F0*/
     0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F, 0x3F,
 /*F8*/
     0x90, 0x3F, 0x3F, 0x3F, 0x3F, 0xEA, 0x3F, 0xFF
};

static const uint8_t _ebcasc[] = {
	0x00, 0x01, 0x02, 0x03, 0x07, 0x09, 0x07, 0x7F,
	0x07, 0x07, 0x07, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x07, 0x0A, 0x08, 0x07,
	0x18, 0x19, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x07, 0x07, 0x1C, 0x07, 0x07, 0x0A, 0x17, 0x1B,
	0x07, 0x07, 0x07, 0x07, 0x07, 0x05, 0x06, 0x07,
	0x07, 0x07, 0x16, 0x07, 0x07, 0x07, 0x07, 0x04,
	0x07, 0x07, 0x07, 0x07, 0x14, 0x15, 0x07, 0x1A,
	0x20, 0xFF, 0x83, 0x84, 0x85, 0xA0, 0x07, 0x86,
	0x87, 0xA4, 0x5B, 0x2E, 0x3C, 0x28, 0x2B, 0x21,
	0x26, 0x82, 0x88, 0x89, 0x8A, 0xA1, 0x8C, 0x07,
	0x8D, 0xE1, 0x5D, 0x24, 0x2A, 0x29, 0x3B, 0x5E,
	0x2D, 0x2F, 0x07, 0x8E, 0x07, 0x07, 0x07, 0x8F,
	0x80, 0xA5, 0x07, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
	0x07, 0x90, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
	0x70, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
	0x07, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0xAE, 0xAF, 0x07, 0x07, 0x07, 0xF1,
	0xF8, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
	0x71, 0x72, 0xA6, 0xA7, 0x91, 0x07, 0x92, 0x07,
	0xE6, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x7A, 0xAD, 0xAB, 0x07, 0x07, 0x07, 0x07,
	0x9B, 0x9C, 0x9D, 0xFA, 0x07, 0x07, 0x07, 0xAC,
	0xAB, 0x07, 0xAA, 0x7C, 0x07, 0x07, 0x07, 0x07,
	0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x07, 0x93, 0x94, 0x95, 0xA2, 0x07,
	0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
	0x51, 0x52, 0x07, 0x96, 0x81, 0x97, 0xA3, 0x98,
	0x5C, 0xF6, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	0x59, 0x5A, 0xFD, 0x07, 0x99, 0x07, 0x07, 0x07,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x07, 0x07, 0x9A, 0x07, 0x07, 0x07,
};

static bool lpar_ascii_compat;

static char lm_buff[120];
static unsigned char lm_buff_off;
static struct spinlock lm_buff_lock;

static char read_buf[4096];
static int read_index = sizeof(read_buf) - 1;
static int read_buf_length = 0;

static void sclp_print_ascii(const char *str)
{
	int len = strlen(str);
	WriteEventData *sccb = (void *)_sccb;
	char *str_dest = (char *)&sccb->msg;
	int src_ind, dst_ind;

	sclp_mark_busy();
	memset(sccb, 0, sizeof(*sccb));

	for (src_ind = 0, dst_ind = 0;
	     src_ind < len && dst_ind < (PAGE_SIZE / 2);
	     src_ind++, dst_ind++) {
		str_dest[dst_ind] = str[src_ind];
		/* Add a \r to the \n for HMC ASCII console */
		if (str[src_ind] == '\n' && lpar_ascii_compat) {
			dst_ind++;
			str_dest[dst_ind] = '\r';
		}
	}

	/* Len might have changed because of the compat behavior */
	len = dst_ind;
	sccb->h.length = offsetof(WriteEventData, msg) + len;
	sccb->h.function_code = SCLP_FC_NORMAL_WRITE;
	sccb->ebh.length = sizeof(EventBufferHeader) + len;
	sccb->ebh.type = SCLP_EVENT_ASCII_CONSOLE_DATA;

	sclp_service_call(SCLP_CMD_WRITE_EVENT_DATA, sccb);
}

static void lm_print(const char *buff, int len)
{
	unsigned char *ptr, *end, ch;
	unsigned int count, offset;
	struct WriteEventData *sccb;
	struct mdb *mdb;
	struct mto *mto;
	struct go *go;

	sclp_mark_busy();
	sccb = (struct WriteEventData *) _sccb;
	end = (unsigned char *) sccb + 4096 - 1;
	memset(sccb, 0, sizeof(*sccb));
	ptr = (unsigned char *) &sccb->msg.mdb.mto;
	offset = 0;
	do {
		for (count = sizeof(*mto); offset < len; count++) {
			ch = buff[offset++];
			if (ch == 0x0a || ptr + count > end)
				break;
			ptr[count] = _ascebc[ch];
		}
		mto = (struct mto *) ptr;
		mto->length = count;
		mto->type = 4;
		mto->line_type_flags = LNTPFLGS_ENDTEXT;
		ptr += count;
	} while (offset < len && ptr + sizeof(*mto) <= end);
	len = ptr - (unsigned char *) sccb;
	sccb->h.length = len - offsetof(struct WriteEventData, h);
	sccb->h.function_code = SCLP_FC_NORMAL_WRITE;
	sccb->ebh.type = EVTYP_MSG;
	sccb->ebh.length = len - offsetof(struct WriteEventData, ebh);
	mdb = &sccb->msg.mdb;
	mdb->header.type = 1;
	mdb->header.tag = 0xD4C4C240;
	mdb->header.revision_code = 1;
	mdb->header.length = len - offsetof(struct WriteEventData, msg.mdb.header);
	go = &mdb->go;
	go->length = sizeof(*go);
	go->type = 1;
	sclp_service_call(SCLP_CMD_WRITE_EVENT_DATA, sccb);
}


/*
 * In contrast to the ascii console, linemode produces a new
 * line with every write of data. The report() function uses
 * several printf() calls to generate a line of data which
 * would all end up on different lines.
 *
 * Hence we buffer here until we encounter a \n or the buffer
 * is full. That means that linemode output can look a bit
 * different from ascii and that it takes a bit longer for
 * lines to appear.
 */
static void sclp_print_lm(const char *str)
{
	int i;
	const int len = strlen(str);

	spin_lock(&lm_buff_lock);

	for (i = 0; i < len; i++) {
		lm_buff[lm_buff_off++] = str[i];

		/* Buffer full or newline? */
		if (str[i] == '\n' || lm_buff_off == (ARRAY_SIZE(lm_buff) - 1)) {
			lm_print(lm_buff, lm_buff_off);
			lm_buff_off = 0;
		}
	}
	spin_unlock(&lm_buff_lock);
}

/*
 * SCLP needs to be initialized by setting a send and receive mask,
 * indicating which messages the control program (we) want(s) to
 * send/receive.
 */
static void sclp_write_event_mask(int receive_mask, int send_mask)
{
	WriteEventMask *sccb = (void *)_sccb;

	sclp_mark_busy();
	memset(_sccb, 0, sizeof(*sccb));
	sccb->h.length = sizeof(WriteEventMask);
	sccb->h.function_code = SCLP_FC_NORMAL_WRITE;
	sccb->mask_length = sizeof(sccb_mask_t);

	sccb->cp_receive_mask = receive_mask;
	sccb->cp_send_mask = send_mask;

	sclp_service_call(SCLP_CMD_WRITE_EVENT_MASK, sccb);
	assert(sccb->h.response_code == SCLP_RC_NORMAL_COMPLETION);
}

static void sclp_console_enable_read(void)
{
	sclp_write_event_mask(SCLP_EVENT_MASK_MSG_ASCII | SCLP_EVENT_MASK_OPCMD,
			      SCLP_EVENT_MASK_MSG_ASCII | SCLP_EVENT_MASK_MSG);
}

static void sclp_console_disable_read(void)
{
	sclp_write_event_mask(0, SCLP_EVENT_MASK_MSG_ASCII | SCLP_EVENT_MASK_MSG);
}

void sclp_console_setup(void)
{
	lpar_ascii_compat = detect_host() == HOST_IS_LPAR;

	/* We send ASCII and line mode. */
	sclp_write_event_mask(0, SCLP_EVENT_MASK_MSG_ASCII | SCLP_EVENT_MASK_MSG);
	/* Hard terminal reset to clear screen for HMC ASCII console */
	if (lpar_ascii_compat)
		sclp_print_ascii("\ec");
}

void sclp_print(const char *str)
{
	/*
	 * z/VM advertises a vt220 console which is not functional:
	 * (response code 05F0, "not active because of the state of
	 * the machine"). Hence testing the masks would only work if
	 * we also use stsi data to distinguish z/VM.
	 *
	 * Let's rather print on all available consoles.
	 */
	if (strlen(str) > (PAGE_SIZE / 2)) {
		sclp_print_ascii("Warning: Printing is limited to 2KB of data.");
		sclp_print_lm("Warning: Printing is limited to 2KB of data.");
		return;
	}
	sclp_print_ascii(str);
	sclp_print_lm(str);
}

static char *console_read_ascii(struct EventBufferHeader *ebh, int *len)
{
	struct ReadEventDataAsciiConsole *evdata = (void *)ebh;
	const int max_event_buffer_len = SCCB_SIZE - offsetof(ReadEventDataAsciiConsole, ebh);
	const int event_buffer_ascii_recv_header_len = offsetof(ReadEventDataAsciiConsole, data);

	assert(ebh->length <= max_event_buffer_len);
	assert(ebh->length > event_buffer_ascii_recv_header_len);

	*len = ebh->length - event_buffer_ascii_recv_header_len;
	return evdata->data;
}


static struct gds_vector *sclp_find_gds_vector(void *start, void *end, uint16_t id)
{
	struct gds_vector *v;

	for (v = start; (void *)v < end; v = (void *)v + v->length)
		if (v->gds_id == id)
			return v;
	return NULL;
}

static struct gds_subvector *sclp_eval_selfdeftextmsg(struct gds_subvector *sv)
{
	void *end;

	end = (void *)sv + sv->length;
	for (sv = sv + 1; (void *)sv < end; sv = (void *)sv + sv->length)
		if (sv->key == 0x30)
			return sv;
	return NULL;
}

static struct gds_subvector *sclp_eval_textcmd(struct gds_vector *v)
{
	struct gds_subvector *sv;
	void *end;

	end = (void *)v + v->length;
	for (sv = (struct gds_subvector *)(v + 1); (void *)sv < end;
	     sv = (void *)sv + sv->length)
		if (sv->key == GDS_KEY_SELFDEFTEXTMSG)
			return sclp_eval_selfdeftextmsg(sv);
	return NULL;
}

static struct gds_subvector *sclp_eval_cpmsu(struct gds_vector *v)
{
	void *end;

	end = (void *)v + v->length;
	for (v = v + 1; (void *)v < end; v = (void *)v + v->length)
		if (v->gds_id == GDS_ID_TEXTCMD)
			return sclp_eval_textcmd(v);
	return NULL;
}

static struct gds_subvector *sclp_eval_mdsmu(struct gds_vector *v)
{
	v = sclp_find_gds_vector(v + 1, (void *)v + v->length, GDS_ID_CPMSU);
	if (v)
		return sclp_eval_cpmsu(v);
	return NULL;
}

static char *console_read_lm(struct EventBufferHeader *ebh, int *len)
{
	struct gds_vector *v = (void *)ebh + sizeof(*ebh);
	struct gds_subvector *sv;

	v = sclp_find_gds_vector(v, (void *)ebh + ebh->length,
				 GDS_ID_MDSMU);
	if (!v)
		return NULL;

	sv = sclp_eval_mdsmu(v);
	if (!sv)
		return NULL;

	*len = sv->length - (sizeof(*sv));
	return (char *)(sv + 1);
}

static void ebc_to_asc(char *data, int len)
{
	int i;

	for (i = 0; i < len; i++)
		data[i] = _ebcasc[(uint8_t)data[i]];
}

static int console_refill_read_buffer(void)
{
	struct SCCBHeader *sccb = (struct SCCBHeader *)_sccb;
	struct EventBufferHeader *ebh = (void *)_sccb + sizeof(struct SCCBHeader);
	char *data;
	int ret = -1, len;

	sclp_console_enable_read();

	sclp_mark_busy();
	memset(_sccb, 0, SCCB_SIZE);
	sccb->length = PAGE_SIZE;
	sccb->function_code = SCLP_UNCONDITIONAL_READ;
	sccb->control_mask[2] = SCLP_CM2_VARIABLE_LENGTH_RESPONSE;

	sclp_service_call(SCLP_CMD_READ_EVENT_DATA, sccb);

	if (sccb->response_code == SCLP_RC_NO_EVENT_BUFFERS_STORED)
		goto out;

	switch (ebh->type) {
	case SCLP_EVENT_OP_CMD:
		data = console_read_lm(ebh, &len);
		if (data)
			ebc_to_asc(data, len);
		break;
	case SCLP_EVENT_ASCII_CONSOLE_DATA:
		data = console_read_ascii(ebh, &len);
		break;
	default:
		goto out;
	}

	if (!data)
		goto out;

	assert(len <= sizeof(read_buf));
	memcpy(read_buf, data, len);

	read_index = 0;
	ret = 0;

out:
	sclp_console_disable_read();

	return ret;
}

int __getchar(void)
{
	int ret;

	if (read_index >= read_buf_length) {
		ret = console_refill_read_buffer();
		if (ret < 0)
			return ret;
	}

	return read_buf[read_index++];
}
