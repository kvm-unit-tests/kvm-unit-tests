#ifndef _ASMPOWERPC_PPC_ASM_H
#define _ASMPOWERPC_PPC_ASM_H

#define LOAD_REG_IMMEDIATE(reg,expr)		\
	lis	reg,(expr)@highest;		\
	ori	reg,reg,(expr)@higher;		\
	rldicr	reg,reg,32,31;			\
	oris	reg,reg,(expr)@h;		\
	ori	reg,reg,(expr)@l;

#define LOAD_REG_ADDR(reg,name)			\
	ld	reg,name@got(r2)

#endif /* _ASMPOWERPC_PPC_ASM_H */
