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

static int exceptions;

#ifdef __x86_64__
#include "emulator64.c"
#endif

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

#ifdef __x86_64__
	rsi = m1; rdi = m3; rcx = 4;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 0 && rsi == m1 + 32 && rdi == m3 + 32, "repe cmpsq (1)");
#endif

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

#ifdef __x86_64__
	rsi = m1; rdi = m3; rcx = 16;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report(rcx == 3 && rsi == m1 + 104 && rdi == m3 + 104,
	       "repe cmpsq (2)");
#endif
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

    *(uint64_t *)mem = 0x77665544332211;

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
    asm ("scasl; setz %0" : "=rm"(z), "+D"(di) : "a"((ulong)0xff44332211ul));
    report(di == mem + 4 && z, "scasd match");

    di = mem;
    asm ("scasl; setz %0" : "=rm"(z), "+D"(di) : "a"(0x45332211));
    report(di == mem + 4 && !z, "scasd mismatch");

#ifdef __x86_64__
    di = mem;
    asm ("scasq; setz %0" : "=rm"(z), "+D"(di) : "a"(0x77665544332211ul));
    report(di == mem + 8 && z, "scasq match");

    di = mem;
    asm ("scasq; setz %0" : "=rm"(z), "+D"(di) : "a"(3));
    report(di == mem + 8 && !z, "scasq mismatch");
#endif
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

#ifdef __x86_64__
	asm ("lock negq %0" : "+m"(*m)); v = -v;
	report(*m == v, "lock negl");
	asm ("lock notq %0" : "+m"(*m)); v = ~v;
	report(*m == v, "lock notl");
#endif

	*mb = vb;

	asm ("lock negb %0" : "+m"(*mb)); vb = -vb;
	report(*mb == vb, "lock negb");
	asm ("lock notb %0" : "+m"(*mb)); vb = ~vb;
	report(*mb == vb, "lock notb");
}

static void test_smsw(unsigned long *h_mem)
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
	*h_mem = -1ul;
	asm volatile("smsw %0" : "+m"(*h_mem));
	report(msw == (unsigned short)*h_mem &&
	       (*h_mem & ~0xfffful) == (-1ul & ~0xfffful), "smsw (3)");
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

#ifdef __x86_64__
	asm ("btcq %1, %0" : : "m"(a[2]), "r"(-1l) : "memory");
	report(a[0] == 1 && a[1] == 0x80000002 && a[2] == 0x80000004 && a[3] == 0,
	       "btcq reg, r/m");
#endif
}

static void test_bsfbsr(void *mem)
{
	unsigned eax, *meml = mem;
	unsigned short ax, *memw = mem;
#ifdef __x86_64__
	unsigned long rax, *memq = mem;
	unsigned char z;
#endif

	*memw = 0xc000;
	asm("bsfw %[mem], %[a]" : [a]"=a"(ax) : [mem]"m"(*memw));
	report(ax == 14, "bsfw r/m, reg");

	*meml = 0xc0000000;
	asm("bsfl %[mem], %[a]" : [a]"=a"(eax) : [mem]"m"(*meml));
	report(eax == 30, "bsfl r/m, reg");

#ifdef __x86_64__
	*memq = 0xc00000000000;
	asm("bsfq %[mem], %[a]" : [a]"=a"(rax) : [mem]"m"(*memq));
	report(rax == 46, "bsfq r/m, reg");

	*memq = 0;
	asm("bsfq %[mem], %[a]; setz %[z]"
	    : [a]"=a"(rax), [z]"=rm"(z) : [mem]"m"(*memq));
	report(z == 1, "bsfq r/m, reg");
#endif

	*memw = 0xc000;
	asm("bsrw %[mem], %[a]" : [a]"=a"(ax) : [mem]"m"(*memw));
	report(ax == 15, "bsrw r/m, reg");

	*meml = 0xc0000000;
	asm("bsrl %[mem], %[a]" : [a]"=a"(eax) : [mem]"m"(*meml));
	report(eax == 31, "bsrl r/m, reg");

#ifdef __x86_64__
	*memq = 0xc00000000000;
	asm("bsrq %[mem], %[a]" : [a]"=a"(rax) : [mem]"m"(*memq));
	report(rax == 47, "bsrq r/m, reg");

	*memq = 0;
	asm("bsrq %[mem], %[a]; setz %[z]"
	    : [a]"=a"(rax), [z]"=rm"(z) : [mem]"m"(*memq));
	report(z == 1, "bsrq r/m, reg");
#endif
}

static void test_imul(uint64_t *mem)
{
	ulong a;

	*mem = 51; a = 0x1234567812345678ULL & -1ul;;
	asm ("imulw %1, %%ax" : "+a"(a) : "m"(*mem));
	report(a == (0x12345678123439e8ULL & -1ul), "imul ax, mem");

	*mem = 51; a = 0x1234567812345678ULL & -1ul;;
	asm ("imull %1, %%eax" : "+a"(a) : "m"(*mem));
	report(a == 0xa06d39e8, "imul eax, mem");

	*mem  = 0x1234567812345678ULL; a = 0x8765432187654321ULL & -1ul;
	asm ("imulw $51, %1, %%ax" : "+a"(a) : "m"(*mem));
	report(a == (0x87654321876539e8ULL & -1ul), "imul ax, mem, imm8");

	*mem = 0x1234567812345678ULL;
	asm ("imull $51, %1, %%eax" : "+a"(a) : "m"(*mem));
	report(a == 0xa06d39e8, "imul eax, mem, imm8");

	*mem  = 0x1234567812345678ULL; a = 0x8765432187654321ULL & -1ul;
	asm ("imulw $311, %1, %%ax" : "+a"(a) : "m"(*mem));
	report(a == (0x8765432187650bc8ULL & -1ul), "imul ax, mem, imm");

	*mem = 0x1234567812345678ULL;
	asm ("imull $311, %1, %%eax" : "+a"(a) : "m"(*mem));
	report(a == 0x1d950bc8, "imul eax, mem, imm");

#ifdef __x86_64__
	*mem = 51; a = 0x1234567812345678UL;
	asm ("imulq %1, %%rax" : "+a"(a) : "m"(*mem));
	report(a == 0xA06D39EBA06D39E8UL, "imul rax, mem");

	*mem = 0x1234567812345678UL;
	asm ("imulq $51, %1, %%rax" : "+a"(a) : "m"(*mem));
	report(a == 0xA06D39EBA06D39E8UL, "imul rax, mem, imm8");

	*mem = 0x1234567812345678UL;
	asm ("imulq $311, %1, %%rax" : "+a"(a) : "m"(*mem));
	report(a == 0x1D950BDE1D950BC8L, "imul rax, mem, imm");
#endif
}
typedef unsigned __attribute__((vector_size(16))) sse128;

static bool sseeq(uint32_t *v1, uint32_t *v2)
{
	bool ok = true;
	int i;

	for (i = 0; i < 4; ++i)
		ok &= v1[i] == v2[i];

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
	handler old;

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
	old = handle_exception(GP_VECTOR, unaligned_movaps_handler);
	asm("movaps %1, %0\n\t unaligned_movaps_cont:"
			: "=m"(*mem) : "x"(vv));
	handle_exception(GP_VECTOR, old);
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
	old = handle_exception(PF_VECTOR, cross_movups_handler);
	asm("movups %1, %0\n\t cross_movups_cont:" : "=m"(*mem) : "x"(vv) :
			"memory");
	handle_exception(PF_VECTOR, old);
	report(exceptions == 1, "movups crosspage exception");

	// restore invalidated page
	install_pte(current_page_table(), 1, page2, orig_pte, NULL);
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

static void test_smsw_reg(uint64_t *mem)
{
	unsigned long cr0 = read_cr0();
	unsigned long rax;
	const unsigned long in_rax = 0x1234567890abcdefull & -1ul;

	asm(KVM_FEP "smsww %w0\n\t" : "=a" (rax) : "0" (in_rax));
	report((u16)rax == (u16)cr0 && rax >> 16 == in_rax >> 16,
	       "16-bit smsw reg");

	asm(KVM_FEP "smswl %k0\n\t" : "=a" (rax) : "0" (in_rax));
	report(rax == (u32)cr0, "32-bit smsw reg");

#ifdef __x86_64__
	asm(KVM_FEP "smswq %q0\n\t" : "=a" (rax) : "0" (in_rax));
	report(rax == cr0, "64-bit smsw reg");
#endif
}

static void test_nop(uint64_t *mem)
{
	unsigned long rax;
	const unsigned long in_rax = 0x12345678ul;
	asm(KVM_FEP "nop\n\t" : "=a" (rax) : "0" (in_rax));
	report(rax == in_rax, "nop");
}

static void test_mov_dr(uint64_t *mem)
{
	unsigned long rax;

	asm(KVM_FEP "mov %0, %%dr6\n\t"
	    KVM_FEP "mov %%dr6, %0\n\t" : "=a" (rax) : "a" (0));

	if (this_cpu_has(X86_FEATURE_RTM))
		report(rax == (DR6_ACTIVE_LOW & ~DR6_RTM), "mov_dr6");
	else
		report(rax == DR6_ACTIVE_LOW, "mov_dr6");
}

static void test_illegal_lea(void)
{
	unsigned int vector;

	asm volatile (ASM_TRY_FEP("1f")
		      ".byte 0x8d; .byte 0xc0\n\t"
		      "1:"
		      : : : "memory", "eax");

	vector = exception_vector();
	report(vector == UD_VECTOR,
	       "Wanted #UD on LEA with /reg, got vector = %u", vector);
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
	report(orig.limit == fresh.limit && orig.base == fresh.base, "lgdt (long address)");

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
	report(orig.limit == fresh.limit && orig.base == fresh.base, "lidt (long address)");
}
#endif

/* Broken emulation causes triple fault, which skips the other tests. */
#if 0
static void test_lldt(volatile uint16_t *mem)
{
	u64 gdt[] = { 0, /* null descriptor */
#ifdef __X86_64__
		0, /* ldt descriptor is 16 bytes in long mode */
#endif
		0x0000f82000000ffffull /* ldt descriptor */
	};
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

static void test_mov(void *mem)
{
	unsigned long t1, t2;

	// test mov reg, r/m and mov r/m, reg
	t1 = 0x123456789abcdefull & -1ul;
	asm volatile("mov %[t1], (%[mem]) \n\t"
		     "mov (%[mem]), %[t2]"
		     : [t2]"=r"(t2)
		     : [t1]"r"(t1), [mem]"r"(mem)
		     : "memory");
	report(t2 == (0x123456789abcdefull & -1ul), "mov reg, r/m (1)");
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

static void test_illegal_movbe(void)
{
	unsigned int vector;

	if (!this_cpu_has(X86_FEATURE_MOVBE)) {
		report_skip("MOVBE unsupported by CPU");
		return;
	}

	asm volatile(ASM_TRY("1f")
		     ".byte 0x0f; .byte 0x38; .byte 0xf0; .byte 0xc0;\n\t"
		     "1:"
		     : : : "memory", "rax");

	vector = exception_vector();
	report(vector == UD_VECTOR,
	       "Wanted #UD on MOVBE with /reg, got vector = %u", vector);
}

#ifdef __x86_64__
#define RIP_RELATIVE "(%%rip)"
#else
#define RIP_RELATIVE ""
#endif

static void handle_db(struct ex_regs *regs)
{
	++exceptions;
	regs->rflags |= X86_EFLAGS_RF;
}

static void test_mov_pop_ss_code_db(void)
{
	handler old_db_handler = handle_exception(DB_VECTOR, handle_db);
	bool fep_available = is_fep_available();
	/* On Intel, code #DBs are inhibited when MOV/POP SS blocking is active. */
	int nr_expected = is_intel() ? 0 : 1;

	write_dr7(DR7_FIXED_1 |
		  DR7_GLOBAL_ENABLE_DRx(0) |
		  DR7_EXECUTE_DRx(0) |
		  DR7_LEN_1_DRx(0));

#define MOV_POP_SS_DB(desc, fep1, fep2, insn, store_ss, load_ss)	\
({									\
	unsigned long r;						\
									\
	exceptions = 0;							\
	asm volatile("lea 1f " RIP_RELATIVE ", %0\n\t"			\
		     "mov %0, %%dr0\n\t"				\
		     store_ss						\
		     fep1 load_ss	   				\
		     fep2 "1: xor %0, %0\n\t"				\
		     "2:"						\
		     : "=r" (r)						\
		     :							\
		     : "memory");					\
	report(exceptions == nr_expected && !r,				\
	       desc ": #DB %s after " insn " SS",			\
	       nr_expected ? "occurred" : "suppressed");		\
})

#define MOV_SS_DB(desc, fep1, fep2)					\
	MOV_POP_SS_DB(desc, fep1, fep2, "MOV",				\
		      "mov %%ss, %0\n\t", "mov %0, %%ss\n\t")

	MOV_SS_DB("no fep", "", "");
	if (fep_available) {
		MOV_SS_DB("fep MOV-SS", KVM_FEP, "");
		MOV_SS_DB("fep XOR", "", KVM_FEP);
		MOV_SS_DB("fep MOV-SS/fep XOR", KVM_FEP, KVM_FEP);
	}

/* PUSH/POP SS are invalid in 64-bit mode. */
#ifndef __x86_64__
#define POP_SS_DB(desc, fep1, fep2)					\
	MOV_POP_SS_DB(desc, fep1, fep2,	"POP",				\
		      "push %%ss\n\t", "pop %%ss\n\t")

	POP_SS_DB("no fep", "", "");
	if (fep_available) {
		POP_SS_DB("fep POP-SS", KVM_FEP, "");
		POP_SS_DB("fep XOR", "", KVM_FEP);
		POP_SS_DB("fep POP-SS/fep XOR", KVM_FEP, KVM_FEP);
	}
#endif

	write_dr7(DR7_FIXED_1);

	handle_exception(DB_VECTOR, old_db_handler);
}

int main(void)
{
	void *mem;
	void *cross_mem;

	if (!is_fep_available())
		report_skip("Skipping tests the require forced emulation, "
			    "use kvm.force_emulation_prefix=1 to enable");

	setup_vm();

	mem = alloc_vpages(2);
	install_page((void *)read_cr3(), IORAM_BASE_PHYS, mem);
	// install the page twice to test cross-page mmio
	install_page((void *)read_cr3(), IORAM_BASE_PHYS, mem + 4096);
	cross_mem = vmap(virt_to_phys(alloc_pages(2)), 2 * PAGE_SIZE);

	test_mov(mem);
	test_simplealu(mem);
	test_cmps(mem);
	test_scas(mem);
	test_smsw(mem);
	test_lmsw();
	test_stringio();
	test_incdecnotneg(mem);
	test_btc(mem);
	test_bsfbsr(mem);
	test_imul(mem);
	test_sse(mem);
	test_sse_exceptions(cross_mem);
	test_shld_shrd(mem);
	//test_lgdt_lidt(mem);
	//test_lldt(mem);
	test_ltr(mem);

	if (is_fep_available()) {
		test_smsw_reg(mem);
		test_nop(mem);
		test_mov_dr(mem);
		test_illegal_lea();
	}

	test_crosspage_mmio(mem);

	test_string_io_mmio(mem);
	test_illegal_movbe();
	test_mov_pop_ss_code_db();

#ifdef __x86_64__
	test_emulator_64(mem);
#endif
	return report_summary();
}
