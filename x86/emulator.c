#include <asm/debugreg.h>

#include "ioram.h"
#include "vm.h"
#include "libcflat.h"
#include "desc.h"
#include "types.h"
#include "processor.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "usermode.h"

#define TESTDEV_IO_PORT 0xe0

#define MAGIC_NUM 0xdeadbeefdeadbeefUL
#define GS_BASE 0x400000

static int exceptions;

/* Forced emulation prefix, used to invoke the emulator unconditionally.  */
#define KVM_FEP "ud2; .byte 'k', 'v', 'm';"
#define KVM_FEP_LENGTH 5
static int fep_available = 1;

struct regs {
	u64 rax, rbx, rcx, rdx;
	u64 rsi, rdi, rsp, rbp;
	u64 r8, r9, r10, r11;
	u64 r12, r13, r14, r15;
	u64 rip, rflags;
};
struct regs inregs, outregs, save;

struct insn_desc {
	u64 ptr;
	size_t len;
};

static char st1[] = "abcdefghijklmnop";

static void test_stringio(void)
{
	unsigned char r = 0;
	asm volatile("cld \n\t"
		     "movw %0, %%dx \n\t"
		     "rep outsb \n\t"
		     : : "i"((short)TESTDEV_IO_PORT),
		       "S"(st1), "c"(sizeof(st1) - 1));
	asm volatile("inb %1, %0\n\t" : "=a"(r) : "i"((short)TESTDEV_IO_PORT));
	report(r == st1[sizeof(st1) - 2], "outsb up"); /* last char */

	asm volatile("std \n\t"
		     "movw %0, %%dx \n\t"
		     "rep outsb \n\t"
		     : : "i"((short)TESTDEV_IO_PORT),
		       "S"(st1 + sizeof(st1) - 2), "c"(sizeof(st1) - 1));
	asm volatile("cld \n\t" : : );
	asm volatile("in %1, %0\n\t" : "=a"(r) : "i"((short)TESTDEV_IO_PORT));
	report(r == st1[0], "outsb down");
}

static void test_cmps_one(unsigned char *m1, unsigned char *m3)
{
	void *rsi, *rdi;
	long rcx, tmp;

	rsi = m1; rdi = m3; rcx = 30;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30, "repe/cmpsb (1)");

	rsi = m1; rdi = m3; rcx = 30;
	asm volatile("or $1, %[tmp]\n\t" // clear ZF
		     "repe cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30,
	       "repe cmpsb (1.zf)");

	rsi = m1; rdi = m3; rcx = 15;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsw"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30, "repe cmpsw (1)");

	rsi = m1; rdi = m3; rcx = 7;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsl"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 0 && rsi == m1 + 28 && rdi == m3 + 28, "repe cmpll (1)");

	rsi = m1; rdi = m3; rcx = 4;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 0 && rsi == m1 + 32 && rdi == m3 + 32, "repe cmpsq (1)");

	rsi = m1; rdi = m3; rcx = 130;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 29 && rsi == m1 + 101 && rdi == m3 + 101,
	       "repe cmpsb (2)");

	rsi = m1; rdi = m3; rcx = 65;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsw"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 14 && rsi == m1 + 102 && rdi == m3 + 102,
	       "repe cmpsw (2)");

	rsi = m1; rdi = m3; rcx = 32;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsl"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 6 && rsi == m1 + 104 && rdi == m3 + 104,
	       "repe cmpll (2)");

	rsi = m1; rdi = m3; rcx = 16;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 3 && rsi == m1 + 104 && rdi == m3 + 104,
	       "repe cmpsq (2)");

}

static void test_cmps(void *mem)
{
	unsigned char *m1 = mem, *m2 = mem + 1024;
	unsigned char m3[1024];

	for (int i = 0; i < 100; ++i)
		m1[i] = m2[i] = m3[i] = i;
	for (int i = 100; i < 200; ++i)
		m1[i] = (m3[i] = m2[i] = i) + 1;
	test_cmps_one(m1, m3);
	test_cmps_one(m1, m2);
}

static void test_scas(void *mem)
{
    bool z;
    void *di;

    *(ulong *)mem = 0x77665544332211;

    di = mem;
    asm ("scasb; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff11));
    report(di == mem + 1 && z, "scasb match");

    di = mem;
    asm ("scasb; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff54));
    report(di == mem + 1 && !z, "scasb mismatch");

    di = mem;
    asm ("scasw; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff2211));
    report(di == mem + 2 && z, "scasw match");

    di = mem;
    asm ("scasw; setz %0" : "=rm"(z), "+D"(di) : "a"(0xffdd11));
    report(di == mem + 2 && !z, "scasw mismatch");

    di = mem;
    asm ("scasl; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff44332211ul));
    report(di == mem + 4 && z, "scasd match");

    di = mem;
    asm ("scasl; setz %0" : "=rm"(z), "+D"(di) : "a"(0x45332211));
    report(di == mem + 4 && !z, "scasd mismatch");

    di = mem;
    asm ("scasq; setz %0" : "=rm"(z), "+D"(di) : "a"(0x77665544332211ul));
    report(di == mem + 8 && z, "scasq match");

    di = mem;
    asm ("scasq; setz %0" : "=rm"(z), "+D"(di) : "a"(3));
    report(di == mem + 8 && !z, "scasq mismatch");
}

static void test_cr8(void)
{
	unsigned long src, dst;

	dst = 777;
	src = 3;
	asm volatile("mov %[src], %%cr8; mov %%cr8, %[dst]"
		     : [dst]"+r"(dst), [src]"+r"(src));
	report(dst == 3 && src == 3, "mov %%cr8");
}

static void test_push(void *mem)
{
	unsigned long tmp;
	unsigned long *stack_top = mem + 4096;
	unsigned long *new_stack_top;
	unsigned long memw = 0x123456789abcdeful;

	memset(mem, 0x55, (void *)stack_top - mem);

	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "pushq $-7 \n\t"
		     "pushq %[reg] \n\t"
		     "pushq (%[mem]) \n\t"
		     "pushq $-7070707 \n\t"
		     "mov %%rsp, %[new_stack_top] \n\t"
		     "mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp), [new_stack_top]"=r"(new_stack_top)
		     : [stack_top]"r"(stack_top),
		       [reg]"r"(-17l), [mem]"r"(&memw)
		     : "memory");

	report(stack_top[-1] == -7ul, "push $imm8");
	report(stack_top[-2] == -17ul, "push %%reg");
	report(stack_top[-3] == 0x123456789abcdeful, "push mem");
	report(stack_top[-4] == -7070707, "push $imm");
}

static void test_pop(void *mem)
{
	unsigned long tmp, tmp3, rsp, rbp;
	unsigned long *stack_top = mem + 4096;
	unsigned long memw = 0x123456789abcdeful;
	static unsigned long tmp2;

	memset(mem, 0x55, (void *)stack_top - mem);

	asm volatile("pushq %[val] \n\t"
		     "popq (%[mem])"
		     : : [val]"m"(memw), [mem]"r"(mem) : "memory");
	report(*(unsigned long *)mem == memw, "pop mem");

	memw = 7 - memw;
	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "pushq %[val] \n\t"
		     "popq %[tmp2] \n\t"
		     "mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp), [tmp2]"=m"(tmp2)
		     : [val]"r"(memw), [stack_top]"r"(stack_top)
		     : "memory");
	report(tmp2 == memw, "pop mem (2)");

	memw = 129443 - memw;
	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "pushq %[val] \n\t"
		     "popq %[tmp2] \n\t"
		     "mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp), [tmp2]"=r"(tmp2)
		     : [val]"r"(memw), [stack_top]"r"(stack_top)
		     : "memory");
	report(tmp2 == memw, "pop reg");

	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "lea 1f(%%rip), %%rax \n\t"
		     "push %%rax \n\t"
		     "ret \n\t"
		     "2: jmp 2b \n\t"
		     "1: mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp) : [stack_top]"r"(stack_top)
		     : "memory", "rax");
	report_pass("ret");

	stack_top[-1] = 0x778899;
	asm volatile("mov %[stack_top], %%r8 \n\t"
		     "mov %%rsp, %%r9 \n\t"
		     "xchg %%rbp, %%r8 \n\t"
		     "leave \n\t"
		     "xchg %%rsp, %%r9 \n\t"
		     "xchg %%rbp, %%r8 \n\t"
		     "mov %%r9, %[tmp] \n\t"
		     "mov %%r8, %[tmp3]"
		     : [tmp]"=&r"(tmp), [tmp3]"=&r"(tmp3) : [stack_top]"r"(stack_top-1)
		     : "memory", "r8", "r9");
	report(tmp == (ulong)stack_top && tmp3 == 0x778899, "leave");

	rbp = 0xaa55aa55bb66bb66ULL;
	rsp = (unsigned long)stack_top;
	asm volatile("mov %[rsp], %%r8 \n\t"
		     "mov %[rbp], %%r9 \n\t"
		     "xchg %%rsp, %%r8 \n\t"
		     "xchg %%rbp, %%r9 \n\t"
		     "enter $0x1238, $0 \n\t"
		     "xchg %%rsp, %%r8 \n\t"
		     "xchg %%rbp, %%r9 \n\t"
		     "xchg %%r8, %[rsp] \n\t"
		     "xchg %%r9, %[rbp]"
		     : [rsp]"+a"(rsp), [rbp]"+b"(rbp) : : "memory", "r8", "r9");
	report(rsp == (unsigned long)stack_top - 8 - 0x1238
	       && rbp == (unsigned long)stack_top - 8
	       && stack_top[-1] == 0xaa55aa55bb66bb66ULL,
	       "enter");
}

static void test_ljmp(void *mem)
{
    unsigned char *m = mem;
    volatile int res = 1;

    *(unsigned long**)m = &&jmpf;
    asm volatile ("data16 mov %%cs, %0":"=m"(*(m + sizeof(unsigned long))));
    asm volatile ("rex64 ljmp *%0"::"m"(*m));
    res = 0;
jmpf:
    report(res, "ljmp");
}

static void test_incdecnotneg(void *mem)
{
    unsigned long *m = mem, v = 1234;
    unsigned char *mb = mem, vb = 66;

    *m = 0;

    asm volatile ("incl %0":"+m"(*m));
    report(*m == 1, "incl");
    asm volatile ("decl %0":"+m"(*m));
    report(*m == 0, "decl");
    asm volatile ("incb %0":"+m"(*m));
    report(*m == 1, "incb");
    asm volatile ("decb %0":"+m"(*m));
    report(*m == 0, "decb");

    asm volatile ("lock incl %0":"+m"(*m));
    report(*m == 1, "lock incl");
    asm volatile ("lock decl %0":"+m"(*m));
    report(*m == 0, "lock decl");
    asm volatile ("lock incb %0":"+m"(*m));
    report(*m == 1, "lock incb");
    asm volatile ("lock decb %0":"+m"(*m));
    report(*m == 0, "lock decb");

    *m = v;

    asm ("lock negq %0" : "+m"(*m)); v = -v;
    report(*m == v, "lock negl");
    asm ("lock notq %0" : "+m"(*m)); v = ~v;
    report(*m == v, "lock notl");

    *mb = vb;

    asm ("lock negb %0" : "+m"(*mb)); vb = -vb;
    report(*mb == vb, "lock negb");
    asm ("lock notb %0" : "+m"(*mb)); vb = ~vb;
    report(*mb == vb, "lock notb");
}

static void test_smsw(uint64_t *h_mem)
{
	char mem[16];
	unsigned short msw, msw_orig, *pmsw;
	int i, zero;

	msw_orig = read_cr0();

	asm("smsw %0" : "=r"(msw));
	report(msw == msw_orig, "smsw (1)");

	memset(mem, 0, 16);
	pmsw = (void *)mem;
	asm("smsw %0" : "=m"(pmsw[4]));
	zero = 1;
	for (i = 0; i < 8; ++i)
		if (i != 4 && pmsw[i])
			zero = 0;
	report(msw == pmsw[4] && zero, "smsw (2)");

	/* Trigger exit on smsw */
	*h_mem = 0x12345678abcdeful;
	asm volatile("smsw %0" : "+m"(*h_mem));
	report(msw == (unsigned short)*h_mem &&
	       (*h_mem & ~0xfffful) == 0x12345678ab0000ul, "smsw (3)");
}

static void test_lmsw(void)
{
	char mem[16];
	unsigned short msw, *pmsw;
	unsigned long cr0;

	cr0 = read_cr0();

	msw = cr0 ^ 8;
	asm("lmsw %0" : : "r"(msw));
	printf("before %lx after %lx\n", cr0, read_cr0());
	report((cr0 ^ read_cr0()) == 8, "lmsw (1)");

	pmsw = (void *)mem;
	*pmsw = cr0;
	asm("lmsw %0" : : "m"(*pmsw));
	printf("before %lx after %lx\n", cr0, read_cr0());
	report(cr0 == read_cr0(), "lmsw (2)");

	/* lmsw can't clear cr0.pe */
	msw = (cr0 & ~1ul) ^ 4;  /* change EM to force trap */
	asm("lmsw %0" : : "r"(msw));
	report((cr0 ^ read_cr0()) == 4 && (cr0 & 1), "lmsw (3)");

	/* back to normal */
	msw = cr0;
	asm("lmsw %0" : : "r"(msw));
}

static void test_xchg(void *mem)
{
	unsigned long *memq = mem;
	unsigned long rax;

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xchg %%al, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0xfedcba98765432ef && *memq == 0x123456789abcd10,
	       "xchg reg, r/m (1)");

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xchg %%ax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0xfedcba987654cdef && *memq == 0x123456789ab3210,
	       "xchg reg, r/m (2)");

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xchg %%eax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0x89abcdef && *memq == 0x123456776543210,
	       "xchg reg, r/m (3)");

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xchg %%rax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0x123456789abcdef && *memq == 0xfedcba9876543210,
	       "xchg reg, r/m (4)");
}

static void test_xadd(void *mem)
{
	unsigned long *memq = mem;
	unsigned long rax;

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xadd %%al, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0xfedcba98765432ef && *memq == 0x123456789abcdff,
	       "xadd reg, r/m (1)");

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xadd %%ax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0xfedcba987654cdef && *memq == 0x123456789abffff,
	       "xadd reg, r/m (2)");

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xadd %%eax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0x89abcdef && *memq == 0x1234567ffffffff,
	       "xadd reg, r/m (3)");

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xadd %%rax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory", "rax");
	report(rax == 0x123456789abcdef && *memq == 0xffffffffffffffff,
	       "xadd reg, r/m (4)");
}

static void test_btc(void *mem)
{
	unsigned int *a = mem;

	memset(mem, 0, 4 * sizeof(unsigned int));

	asm ("btcl $32, %0" :: "m"(a[0]) : "memory");
	asm ("btcl $1, %0" :: "m"(a[1]) : "memory");
	asm ("btcl %1, %0" :: "m"(a[0]), "r"(66) : "memory");
	report(a[0] == 1 && a[1] == 2 && a[2] == 4, "btcl imm8, r/m");

	asm ("btcl %1, %0" :: "m"(a[3]), "r"(-1) : "memory");
	report(a[0] == 1 && a[1] == 2 && a[2] == 0x80000004, "btcl reg, r/m");

	asm ("btcq %1, %0" : : "m"(a[2]), "r"(-1l) : "memory");
	report(a[0] == 1 && a[1] == 0x80000002 && a[2] == 0x80000004 && a[3] == 0,
	       "btcq reg, r/m");
}

static void test_bsfbsr(void *mem)
{
	unsigned long rax, *memq = mem;
	unsigned eax, *meml = mem;
	unsigned short ax, *memw = mem;
	unsigned char z;

	*memw = 0xc000;
	asm("bsfw %[mem], %[a]" : [a]"=a"(ax) : [mem]"m"(*memw));
	report(ax == 14, "bsfw r/m, reg");

	*meml = 0xc0000000;
	asm("bsfl %[mem], %[a]" : [a]"=a"(eax) : [mem]"m"(*meml));
	report(eax == 30, "bsfl r/m, reg");

	*memq = 0xc00000000000;
	asm("bsfq %[mem], %[a]" : [a]"=a"(rax) : [mem]"m"(*memq));
	report(rax == 46, "bsfq r/m, reg");

	*memq = 0;
	asm("bsfq %[mem], %[a]; setz %[z]"
	    : [a]"=a"(rax), [z]"=rm"(z) : [mem]"m"(*memq));
	report(z == 1, "bsfq r/m, reg");

	*memw = 0xc000;
	asm("bsrw %[mem], %[a]" : [a]"=a"(ax) : [mem]"m"(*memw));
	report(ax == 15, "bsrw r/m, reg");

	*meml = 0xc0000000;
	asm("bsrl %[mem], %[a]" : [a]"=a"(eax) : [mem]"m"(*meml));
	report(eax == 31, "bsrl r/m, reg");

	*memq = 0xc00000000000;
	asm("bsrq %[mem], %[a]" : [a]"=a"(rax) : [mem]"m"(*memq));
	report(rax == 47, "bsrq r/m, reg");

	*memq = 0;
	asm("bsrq %[mem], %[a]; setz %[z]"
	    : [a]"=a"(rax), [z]"=rm"(z) : [mem]"m"(*memq));
	report(z == 1, "bsrq r/m, reg");
}

static void test_imul(ulong *mem)
{
    ulong a;

    *mem = 51; a = 0x1234567812345678UL;
    asm ("imulw %1, %%ax" : "+a"(a) : "m"(*mem));
    report(a == 0x12345678123439e8, "imul ax, mem");

    *mem = 51; a = 0x1234567812345678UL;
    asm ("imull %1, %%eax" : "+a"(a) : "m"(*mem));
    report(a == 0xa06d39e8, "imul eax, mem");

    *mem = 51; a = 0x1234567812345678UL;
    asm ("imulq %1, %%rax" : "+a"(a) : "m"(*mem));
    report(a == 0xA06D39EBA06D39E8UL, "imul rax, mem");

    *mem  = 0x1234567812345678UL; a = 0x8765432187654321L;
    asm ("imulw $51, %1, %%ax" : "+a"(a) : "m"(*mem));
    report(a == 0x87654321876539e8, "imul ax, mem, imm8");

    *mem = 0x1234567812345678UL;
    asm ("imull $51, %1, %%eax" : "+a"(a) : "m"(*mem));
    report(a == 0xa06d39e8, "imul eax, mem, imm8");

    *mem = 0x1234567812345678UL;
    asm ("imulq $51, %1, %%rax" : "+a"(a) : "m"(*mem));
    report(a == 0xA06D39EBA06D39E8UL, "imul rax, mem, imm8");

    *mem  = 0x1234567812345678UL; a = 0x8765432187654321L;
    asm ("imulw $311, %1, %%ax" : "+a"(a) : "m"(*mem));
    report(a == 0x8765432187650bc8, "imul ax, mem, imm");

    *mem = 0x1234567812345678UL;
    asm ("imull $311, %1, %%eax" : "+a"(a) : "m"(*mem));
    report(a == 0x1d950bc8, "imul eax, mem, imm");

    *mem = 0x1234567812345678UL;
    asm ("imulq $311, %1, %%rax" : "+a"(a) : "m"(*mem));
    report(a == 0x1D950BDE1D950BC8L, "imul rax, mem, imm");
}

static void test_muldiv(long *mem)
{
    long a, d, aa, dd;
    u8 ex = 1;

    *mem = 0; a = 1; d = 2;
    asm (ASM_TRY("1f") "divq %3; movb $0, %2; 1:"
	 : "+a"(a), "+d"(d), "+q"(ex) : "m"(*mem));
    report(a == 1 && d == 2 && ex, "divq (fault)");

    *mem = 987654321098765UL; a = 123456789012345UL; d = 123456789012345UL;
    asm (ASM_TRY("1f") "divq %3; movb $0, %2; 1:"
	 : "+a"(a), "+d"(d), "+q"(ex) : "m"(*mem));
    report(a == 0x1ffffffb1b963b33ul && d == 0x273ba4384ede2ul && !ex,
           "divq (1)");
    aa = 0x1111111111111111; dd = 0x2222222222222222;
    *mem = 0x3333333333333333; a = aa; d = dd;
    asm("mulb %2" : "+a"(a), "+d"(d) : "m"(*mem));
    report(a == 0x1111111111110363 && d == dd, "mulb mem");
    *mem = 0x3333333333333333; a = aa; d = dd;
    asm("mulw %2" : "+a"(a), "+d"(d) : "m"(*mem));
    report(a == 0x111111111111c963 && d == 0x2222222222220369, "mulw mem");
    *mem = 0x3333333333333333; a = aa; d = dd;
    asm("mull %2" : "+a"(a), "+d"(d) : "m"(*mem));
    report(a == 0x962fc963 && d == 0x369d036, "mull mem");
    *mem = 0x3333333333333333; a = aa; d = dd;
    asm("mulq %2" : "+a"(a), "+d"(d) : "m"(*mem));
    report(a == 0x2fc962fc962fc963 && d == 0x369d0369d0369d0, "mulq mem");
}

typedef unsigned __attribute__((vector_size(16))) sse128;

static bool sseeq(uint32_t *v1, uint32_t *v2)
{
    bool ok = true;
    int i;

    for (i = 0; i < 4; ++i) {
	ok &= v1[i] == v2[i];
    }

    return ok;
}

static __attribute__((target("sse2"))) void test_sse(uint32_t *mem)
{
	sse128 vv;
	uint32_t *v = (uint32_t *)&vv;

	write_cr0(read_cr0() & ~6); /* EM, TS */
	write_cr4(read_cr4() | 0x200); /* OSFXSR */
	memset(&vv, 0, sizeof(vv));

#define TEST_RW_SSE(insn) do { \
		v[0] = 1; v[1] = 2; v[2] = 3; v[3] = 4; \
		asm(insn " %1, %0" : "=m"(*mem) : "x"(vv) : "memory"); \
		report(sseeq(v, mem), insn " (read)"); \
		mem[0] = 5; mem[1] = 6; mem[2] = 7; mem[3] = 8; \
		asm(insn " %1, %0" : "=x"(vv) : "m"(*mem) : "memory"); \
		report(sseeq(v, mem), insn " (write)"); \
} while (0)

	TEST_RW_SSE("movdqu");
	TEST_RW_SSE("movaps");
	TEST_RW_SSE("movapd");
	TEST_RW_SSE("movups");
	TEST_RW_SSE("movupd");
#undef TEST_RW_SSE
}

static void unaligned_movaps_handler(struct ex_regs *regs)
{
	extern char unaligned_movaps_cont;

	++exceptions;
	regs->rip = (ulong)&unaligned_movaps_cont;
}

static void cross_movups_handler(struct ex_regs *regs)
{
	extern char cross_movups_cont;

	++exceptions;
	regs->rip = (ulong)&cross_movups_cont;
}

static __attribute__((target("sse2"))) void test_sse_exceptions(void *cross_mem)
{
	sse128 vv;
	uint32_t *v = (uint32_t *)&vv;
	uint32_t *mem;
	uint8_t *bytes = cross_mem; // aligned on PAGE_SIZE*2
	void *page2 = (void *)(&bytes[4096]);
	struct pte_search search;
	pteval_t orig_pte;

	// setup memory for unaligned access
	mem = (uint32_t *)(&bytes[8]);

	// test unaligned access for movups, movupd and movaps
	v[0] = 1; v[1] = 2; v[2] = 3; v[3] = 4;
	mem[0] = 5; mem[1] = 6; mem[2] = 8; mem[3] = 9;
	asm("movups %1, %0" : "=m"(*mem) : "x"(vv) : "memory");
	report(sseeq(v, mem), "movups unaligned");

	v[0] = 1; v[1] = 2; v[2] = 3; v[3] = 4;
	mem[0] = 5; mem[1] = 6; mem[2] = 7; mem[3] = 8;
	asm("movupd %1, %0" : "=m"(*mem) : "x"(vv) : "memory");
	report(sseeq(v, mem), "movupd unaligned");
	exceptions = 0;
	handle_exception(GP_VECTOR, unaligned_movaps_handler);
	asm("movaps %1, %0\n\t unaligned_movaps_cont:"
			: "=m"(*mem) : "x"(vv));
	handle_exception(GP_VECTOR, 0);
	report(exceptions == 1, "unaligned movaps exception");

	// setup memory for cross page access
	mem = (uint32_t *)(&bytes[4096-8]);
	v[0] = 1; v[1] = 2; v[2] = 3; v[3] = 4;
	mem[0] = 5; mem[1] = 6; mem[2] = 7; mem[3] = 8;

	asm("movups %1, %0" : "=m"(*mem) : "x"(vv) : "memory");
	report(sseeq(v, mem), "movups unaligned crosspage");

	// invalidate second page
	search = find_pte_level(current_page_table(), page2, 1);
	orig_pte = *search.pte;
	install_pte(current_page_table(), 1, page2, 0, NULL);
	invlpg(page2);

	exceptions = 0;
	handle_exception(PF_VECTOR, cross_movups_handler);
	asm("movups %1, %0\n\t cross_movups_cont:" : "=m"(*mem) : "x"(vv) :
			"memory");
	handle_exception(PF_VECTOR, 0);
	report(exceptions == 1, "movups crosspage exception");

	// restore invalidated page
	install_pte(current_page_table(), 1, page2, orig_pte, NULL);
}

static void test_mmx(uint64_t *mem)
{
    uint64_t v;

    write_cr0(read_cr0() & ~6); /* EM, TS */
    asm volatile("fninit");
    v = 0x0102030405060708ULL;
    asm("movq %1, %0" : "=m"(*mem) : "y"(v));
    report(v == *mem, "movq (mmx, read)");
    *mem = 0x8070605040302010ull;
    asm("movq %1, %0" : "=y"(v) : "m"(*mem));
    report(v == *mem, "movq (mmx, write)");
}

static void test_rip_relative(unsigned *mem, char *insn_ram)
{
    /* movb $1, mem+2(%rip) */
    insn_ram[0] = 0xc6;
    insn_ram[1] = 0x05;
    *(unsigned *)&insn_ram[2] = 2 + (char *)mem - (insn_ram + 7);
    insn_ram[6] = 0x01;
    /* ret */
    insn_ram[7] = 0xc3;

    *mem = 0;
    asm("callq *%1" : "+m"(*mem) : "r"(insn_ram));
    report(*mem == 0x10000, "movb $imm, 0(%%rip)");
}

static void test_shld_shrd(u32 *mem)
{
    *mem = 0x12345678;
    asm("shld %2, %1, %0" : "+m"(*mem) : "r"(0xaaaaaaaaU), "c"((u8)3));
    report(*mem == ((0x12345678 << 3) | 5), "shld (cl)");
    *mem = 0x12345678;
    asm("shrd %2, %1, %0" : "+m"(*mem) : "r"(0x55555555U), "c"((u8)3));
    report(*mem == ((0x12345678 >> 3) | (5u << 29)), "shrd (cl)");
}

static void test_cmov(u32 *mem)
{
	u64 val;
	*mem = 0xabcdef12u;
	asm ("movq $0x1234567812345678, %%rax\n\t"
	     "cmpl %%eax, %%eax\n\t"
	     "cmovnel (%[mem]), %%eax\n\t"
	     "movq %%rax, %[val]\n\t"
	     : [val]"=r"(val) : [mem]"r"(mem) : "%rax", "cc");
	report(val == 0x12345678ul, "cmovnel");
}

static unsigned long rip_advance;

static void advance_rip_and_note_exception(struct ex_regs *regs)
{
    ++exceptions;
    regs->rip += rip_advance;
}

static void test_mmx_movq_mf(uint64_t *mem)
{
    /* movq %mm0, (%rax) */
    extern char movq_start, movq_end;

    uint16_t fcw = 0;  /* all exceptions unmasked */
    write_cr0(read_cr0() & ~6);  /* TS, EM */
    exceptions = 0;
    handle_exception(MF_VECTOR, advance_rip_and_note_exception);
    asm volatile("fninit; fldcw %0" : : "m"(fcw));
    asm volatile("fldz; fldz; fdivp"); /* generate exception */

    rip_advance = &movq_end - &movq_start;
    asm(KVM_FEP "movq_start: movq %mm0, (%rax); movq_end:");
    /* exit MMX mode */
    asm volatile("fnclex; emms");
    report(exceptions == 1, "movq mmx generates #MF");
    handle_exception(MF_VECTOR, 0);
}

static void test_jmp_noncanonical(uint64_t *mem)
{
	extern char nc_jmp_start, nc_jmp_end;

	*mem = 0x1111111111111111ul;

	exceptions = 0;
	rip_advance = &nc_jmp_end - &nc_jmp_start;
	handle_exception(GP_VECTOR, advance_rip_and_note_exception);
	asm volatile ("nc_jmp_start: jmp *%0; nc_jmp_end:" : : "m"(*mem));
	report(exceptions == 1, "jump to non-canonical address");
	handle_exception(GP_VECTOR, 0);
}

static void test_movabs(uint64_t *mem)
{
    /* mov $0x9090909090909090, %rcx */
    unsigned long rcx;
    asm(KVM_FEP "mov $0x9090909090909090, %0" : "=c" (rcx) : "0" (0));
    report(rcx == 0x9090909090909090, "64-bit mov imm2");
}

static void test_smsw_reg(uint64_t *mem)
{
	unsigned long cr0 = read_cr0();
	unsigned long rax;
	const unsigned long in_rax = 0x1234567890abcdeful;

	asm(KVM_FEP "smsww %w0\n\t" : "=a" (rax) : "0" (in_rax));
	report((u16)rax == (u16)cr0 && rax >> 16 == in_rax >> 16,
	       "16-bit smsw reg");

	asm(KVM_FEP "smswl %k0\n\t" : "=a" (rax) : "0" (in_rax));
	report(rax == (u32)cr0, "32-bit smsw reg");

	asm(KVM_FEP "smswq %q0\n\t" : "=a" (rax) : "0" (in_rax));
	report(rax == cr0, "64-bit smsw reg");
}

static void test_nop(uint64_t *mem)
{
	unsigned long rax;
	const unsigned long in_rax = 0x1234567890abcdeful;
	asm(KVM_FEP "nop\n\t" : "=a" (rax) : "0" (in_rax));
	report(rax == in_rax, "nop");
}

static void test_mov_dr(uint64_t *mem)
{
	unsigned long rax;

	asm(KVM_FEP "movq %0, %%dr6\n\t"
	    KVM_FEP "movq %%dr6, %0\n\t" : "=a" (rax) : "a" (0));

	if (this_cpu_has(X86_FEATURE_RTM))
		report(rax == (DR6_ACTIVE_LOW & ~DR6_RTM), "mov_dr6");
	else
		report(rax == DR6_ACTIVE_LOW, "mov_dr6");
}

static void test_push16(uint64_t *mem)
{
	uint64_t rsp1, rsp2;
	uint16_t r;

	asm volatile (	"movq %%rsp, %[rsp1]\n\t"
			"pushw %[v]\n\t"
			"popw %[r]\n\t"
			"movq %%rsp, %[rsp2]\n\t"
			"movq %[rsp1], %%rsp\n\t" :
			[rsp1]"=r"(rsp1), [rsp2]"=r"(rsp2), [r]"=r"(r)
			: [v]"m"(*mem) : "memory");
	report(rsp1 == rsp2, "push16");
}

static void test_crosspage_mmio(volatile uint8_t *mem)
{
    volatile uint16_t w, *pw;

    pw = (volatile uint16_t *)&mem[4095];
    mem[4095] = 0x99;
    mem[4096] = 0x77;
    asm volatile("mov %1, %0" : "=r"(w) : "m"(*pw) : "memory");
    report(w == 0x7799, "cross-page mmio read");
    asm volatile("mov %1, %0" : "=m"(*pw) : "r"((uint16_t)0x88aa));
    report(mem[4095] == 0xaa && mem[4096] == 0x88, "cross-page mmio write");
}

static void test_string_io_mmio(volatile uint8_t *mem)
{
	/* Cross MMIO pages.*/
	volatile uint8_t *mmio = mem + 4032;

	asm volatile("outw %%ax, %%dx  \n\t" : : "a"(0x9999), "d"(TESTDEV_IO_PORT));

	asm volatile ("cld; rep insb" : : "d" (TESTDEV_IO_PORT), "D" (mmio), "c" (1024));

	report(mmio[1023] == 0x99, "string_io_mmio");
}

/* kvm doesn't allow lidt/lgdt from mmio, so the test is disabled */
#if 0
static void test_lgdt_lidt(volatile uint8_t *mem)
{
    struct descriptor_table_ptr orig, fresh = {};

    sgdt(&orig);
    *(struct descriptor_table_ptr *)mem = (struct descriptor_table_ptr) {
	.limit = 0xf234,
	.base = 0x12345678abcd,
    };
    cli();
    asm volatile("lgdt %0" : : "m"(*(struct descriptor_table_ptr *)mem));
    sgdt(&fresh);
    lgdt(&orig);
    sti();
    report(orig.limit == fresh.limit && orig.base == fresh.base,
           "lgdt (long address)");

    sidt(&orig);
    *(struct descriptor_table_ptr *)mem = (struct descriptor_table_ptr) {
	.limit = 0x432f,
	.base = 0xdbca87654321,
    };
    cli();
    asm volatile("lidt %0" : : "m"(*(struct descriptor_table_ptr *)mem));
    sidt(&fresh);
    lidt(&orig);
    sti();
    report(orig.limit == fresh.limit && orig.base == fresh.base,
           "lidt (long address)");
}
#endif

static void ss_bad_rpl(struct ex_regs *regs)
{
    extern char ss_bad_rpl_cont;

    ++exceptions;
    regs->rip = (ulong)&ss_bad_rpl_cont;
}

static void test_sreg(volatile uint16_t *mem)
{
    u16 ss = read_ss();

    // check for null segment load
    *mem = 0;
    asm volatile("mov %0, %%ss" : : "m"(*mem));
    report(read_ss() == 0, "mov null, %%ss");

    // check for exception when ss.rpl != cpl on null segment load
    exceptions = 0;
    handle_exception(GP_VECTOR, ss_bad_rpl);
    *mem = 3;
    asm volatile("mov %0, %%ss; ss_bad_rpl_cont:" : : "m"(*mem));
    report(exceptions == 1 && read_ss() == 0,
           "mov null, %%ss (with ss.rpl != cpl)");
    handle_exception(GP_VECTOR, 0);
    write_ss(ss);
}

static uint64_t usr_gs_mov(void)
{
    static uint64_t dummy = MAGIC_NUM;
    uint64_t dummy_ptr = (uint64_t)&dummy;
    uint64_t ret;

    dummy_ptr -= GS_BASE;
    asm volatile("mov %%gs:(%%rcx), %%rax" : "=a"(ret): "c"(dummy_ptr) :);

    return ret;
}

static void test_iret(void)
{
    uint64_t val;
    bool raised_vector;

    /* Update GS base to 4MiB */
    wrmsr(MSR_GS_BASE, GS_BASE);

    /*
     * Per the SDM, jumping to user mode via `iret`, which is returning to
     * outer privilege level, for segment registers (ES, FS, GS, and DS)
     * if the check fails, the segment selector becomes null.
     *
     * In our test case, GS becomes null.
     */
    val = run_in_user((usermode_func)usr_gs_mov, GP_VECTOR,
                      0, 0, 0, 0, &raised_vector);

    report(val == MAGIC_NUM, "Test ret/iret with a nullified segment");
}

/* Broken emulation causes triple fault, which skips the other tests. */
#if 0
static void test_lldt(volatile uint16_t *mem)
{
    u64 gdt[] = { 0, /* null descriptor */
#ifdef __X86_64__
		  0, /* ldt descriptor is 16 bytes in long mode */
#endif
		  0x0000f82000000ffffull /* ldt descriptor */ };
    struct descriptor_table_ptr gdt_ptr = { .limit = sizeof(gdt) - 1,
					    .base = (ulong)&gdt };
    struct descriptor_table_ptr orig_gdt;

    cli();
    sgdt(&orig_gdt);
    lgdt(&gdt_ptr);
    *mem = 0x8;
    asm volatile("lldt %0" : : "m"(*mem));
    lgdt(&orig_gdt);
    sti();
    report(sldt() == *mem, "lldt");
}
#endif

static void test_ltr(volatile uint16_t *mem)
{
    struct descriptor_table_ptr gdt_ptr;
    uint64_t *gdt, *trp;
    uint16_t tr = str();
    uint64_t busy_mask = (uint64_t)1 << 41;

    sgdt(&gdt_ptr);
    gdt = (uint64_t *)gdt_ptr.base;
    trp = &gdt[tr >> 3];
    *trp &= ~busy_mask;
    *mem = tr;
    asm volatile("ltr %0" : : "m"(*mem) : "memory");
    report(str() == tr && (*trp & busy_mask), "ltr");
}

static void test_simplealu(u32 *mem)
{
    *mem = 0x1234;
    asm("or %1, %0" : "+m"(*mem) : "r"(0x8001));
    report(*mem == 0x9235, "or");
    asm("add %1, %0" : "+m"(*mem) : "r"(2));
    report(*mem == 0x9237, "add");
    asm("xor %1, %0" : "+m"(*mem) : "r"(0x1111));
    report(*mem == 0x8326, "xor");
    asm("sub %1, %0" : "+m"(*mem) : "r"(0x26));
    report(*mem == 0x8300, "sub");
    asm("clc; adc %1, %0" : "+m"(*mem) : "r"(0x100));
    report(*mem == 0x8400, "adc(0)");
    asm("stc; adc %1, %0" : "+m"(*mem) : "r"(0x100));
    report(*mem == 0x8501, "adc(0)");
    asm("clc; sbb %1, %0" : "+m"(*mem) : "r"(0));
    report(*mem == 0x8501, "sbb(0)");
    asm("stc; sbb %1, %0" : "+m"(*mem) : "r"(0));
    report(*mem == 0x8500, "sbb(1)");
    asm("and %1, %0" : "+m"(*mem) : "r"(0xfe77));
    report(*mem == 0x8400, "and");
    asm("test %1, %0" : "+m"(*mem) : "r"(0xf000));
    report(*mem == 0x8400, "test");
}

static void illegal_movbe_handler(struct ex_regs *regs)
{
	extern char bad_movbe_cont;

	++exceptions;
	regs->rip = (ulong)&bad_movbe_cont;
}

static void test_illegal_movbe(void)
{
	if (!this_cpu_has(X86_FEATURE_MOVBE)) {
		report_skip("illegal movbe");
		return;
	}

	exceptions = 0;
	handle_exception(UD_VECTOR, illegal_movbe_handler);
	asm volatile(".byte 0x0f; .byte 0x38; .byte 0xf0; .byte 0xc0;\n\t"
		     " bad_movbe_cont:" : : : "rax");
	report(exceptions == 1, "illegal movbe");
	handle_exception(UD_VECTOR, 0);
}

static void record_no_fep(struct ex_regs *regs)
{
	fep_available = 0;
	regs->rip += KVM_FEP_LENGTH;
}

int main(void)
{
	void *mem;
	void *insn_page;
	void *insn_ram;
	void *cross_mem;
	unsigned long t1, t2;

	setup_vm();
	handle_exception(UD_VECTOR, record_no_fep);
	asm(KVM_FEP "nop");
	handle_exception(UD_VECTOR, 0);

	mem = alloc_vpages(2);
	install_page((void *)read_cr3(), IORAM_BASE_PHYS, mem);
	// install the page twice to test cross-page mmio
	install_page((void *)read_cr3(), IORAM_BASE_PHYS, mem + 4096);
	insn_page = alloc_page();
	insn_ram = vmap(virt_to_phys(insn_page), 4096);
	cross_mem = vmap(virt_to_phys(alloc_pages(2)), 2 * PAGE_SIZE);

	// test mov reg, r/m and mov r/m, reg
	t1 = 0x123456789abcdef;
	asm volatile("mov %[t1], (%[mem]) \n\t"
		     "mov (%[mem]), %[t2]"
		     : [t2]"=r"(t2)
		     : [t1]"r"(t1), [mem]"r"(mem)
		     : "memory");
	report(t2 == 0x123456789abcdef, "mov reg, r/m (1)");

	test_simplealu(mem);
	test_cmps(mem);
	test_scas(mem);

	test_push(mem);
	test_pop(mem);

	test_xchg(mem);
	test_xadd(mem);

	test_cr8();

	test_smsw(mem);
	test_lmsw();
	test_ljmp(mem);
	test_stringio();
	test_incdecnotneg(mem);
	test_btc(mem);
	test_bsfbsr(mem);
	test_imul(mem);
	test_muldiv(mem);
	test_sse(mem);
	test_sse_exceptions(cross_mem);
	test_mmx(mem);
	test_rip_relative(mem, insn_ram);
	test_shld_shrd(mem);
	//test_lgdt_lidt(mem);
	test_sreg(mem);
	test_iret();
	//test_lldt(mem);
	test_ltr(mem);
	test_cmov(mem);

	if (fep_available) {
		test_mmx_movq_mf(mem);
		test_movabs(mem);
		test_smsw_reg(mem);
		test_nop(mem);
		test_mov_dr(mem);
	} else {
		report_skip("skipping register-only tests, "
			    "use kvm.force_emulation_prefix=1 to enable");
	}

	test_push16(mem);
	test_crosspage_mmio(mem);

	test_string_io_mmio(mem);

	test_jmp_noncanonical(mem);
	test_illegal_movbe();

	return report_summary();
}
