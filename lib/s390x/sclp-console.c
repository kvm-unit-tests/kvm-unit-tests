/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SCLP ASCII access driver
 *
 * Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 */

#include <libcflat.h>
#include <string.h>
#include <asm/page.h>
#include <asm/arch_def.h>
#include <asm/io.h>
#include <asm/spinlock.h>
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

static char lm_buff[120];
static unsigned char lm_buff_off;
static struct spinlock lm_buff_lock;

static void sclp_print_ascii(const char *str)
{
	int len = strlen(str);
	WriteEventData *sccb = (void *)_sccb;

	sclp_mark_busy();
	memset(sccb, 0, sizeof(*sccb));
	sccb->h.length = offsetof(WriteEventData, msg) + len;
	sccb->h.function_code = SCLP_FC_NORMAL_WRITE;
	sccb->ebh.length = sizeof(EventBufferHeader) + len;
	sccb->ebh.type = SCLP_EVENT_ASCII_CONSOLE_DATA;
	memcpy(&sccb->msg, str, len);

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
static void sclp_set_write_mask(void)
{
	WriteEventMask *sccb = (void *)_sccb;

	sclp_mark_busy();
	memset(_sccb, 0, sizeof(*sccb));
	sccb->h.length = sizeof(WriteEventMask);
	sccb->h.function_code = SCLP_FC_NORMAL_WRITE;
	sccb->mask_length = sizeof(sccb_mask_t);

	/* For now we don't process sclp input. */
	sccb->cp_receive_mask = 0;
	/* We send ASCII and line mode. */
	sccb->cp_send_mask = SCLP_EVENT_MASK_MSG_ASCII | SCLP_EVENT_MASK_MSG;

	sclp_service_call(SCLP_CMD_WRITE_EVENT_MASK, sccb);
	assert(sccb->h.response_code == SCLP_RC_NORMAL_COMPLETION);
}

void sclp_console_setup(void)
{
	sclp_set_write_mask();
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
