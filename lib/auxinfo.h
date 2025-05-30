/*
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#ifndef _AUXINFO_H_
#define _AUXINFO_H_

#define AUXINFO_MMU_OFF (1 << 0)

#ifndef __ASSEMBLER__
struct auxinfo {
	const char *progname;
	unsigned long flags;
};

extern struct auxinfo auxinfo;
#endif
#endif
