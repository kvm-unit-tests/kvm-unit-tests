#include "ioram.h"
#include "vm.h"
#include "libcflat.h"

#define memset __builtin_memset
#define TESTDEV_IO_PORT 0xe0

int fails, tests;

void report(const char *name, int result)
{
	++tests;
	if (result)
		printf("PASS: %s\n", name);
	else {
		printf("FAIL: %s\n", name);
		++fails;
	}
}

static char st1[] = "abcdefghijklmnop";

void test_stringio()
{
	unsigned char r = 0;
	asm volatile("cld \n\t"
		     "movw %0, %%dx \n\t"
		     "rep outsb \n\t"
		     : : "i"((short)TESTDEV_IO_PORT),
		       "S"(st1), "c"(sizeof(st1) - 1));
	asm volatile("inb %1, %0\n\t" : "=a"(r) : "i"((short)TESTDEV_IO_PORT));
	report("outsb up", r == st1[sizeof(st1) - 2]); /* last char */

	asm volatile("std \n\t"
		     "movw %0, %%dx \n\t"
		     "rep outsb \n\t"
		     : : "i"((short)TESTDEV_IO_PORT),
		       "S"(st1 + sizeof(st1) - 2), "c"(sizeof(st1) - 1));
	asm volatile("cld \n\t" : : );
	asm volatile("in %1, %0\n\t" : "=a"(r) : "i"((short)TESTDEV_IO_PORT));
	report("outsb down", r == st1[0]);
}

void test_cmps_one(unsigned char *m1, unsigned char *m3)
{
	void *rsi, *rdi;
	long rcx, tmp;

	rsi = m1; rdi = m3; rcx = 30;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsb (1)", rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30);

	rsi = m1; rdi = m3; rcx = 30;
	asm volatile("or $1, %[tmp]\n\t" // clear ZF
		     "repe/cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsb (1.zf)", rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30);

	rsi = m1; rdi = m3; rcx = 15;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsw"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsw (1)", rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30);

	rsi = m1; rdi = m3; rcx = 7;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsl"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpll (1)", rcx == 0 && rsi == m1 + 28 && rdi == m3 + 28);

	rsi = m1; rdi = m3; rcx = 4;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsq (1)", rcx == 0 && rsi == m1 + 32 && rdi == m3 + 32);

	rsi = m1; rdi = m3; rcx = 130;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsb (2)",
	       rcx == 29 && rsi == m1 + 101 && rdi == m3 + 101);

	rsi = m1; rdi = m3; rcx = 65;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsw"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsw (2)",
	       rcx == 14 && rsi == m1 + 102 && rdi == m3 + 102);

	rsi = m1; rdi = m3; rcx = 32;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsl"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpll (2)",
	       rcx == 6 && rsi == m1 + 104 && rdi == m3 + 104);

	rsi = m1; rdi = m3; rcx = 16;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsq (2)",
	       rcx == 3 && rsi == m1 + 104 && rdi == m3 + 104);

}

void test_cmps(void *mem)
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

void test_scas(void *mem)
{
    bool z;
    void *di;

    *(ulong *)mem = 0x77665544332211;

    di = mem;
    asm ("scasb; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff11));
    report("scasb match", di == mem + 1 && z);

    di = mem;
    asm ("scasb; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff54));
    report("scasb mismatch", di == mem + 1 && !z);

    di = mem;
    asm ("scasw; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff2211));
    report("scasw match", di == mem + 2 && z);

    di = mem;
    asm ("scasw; setz %0" : "=rm"(z), "+D"(di) : "a"(0xffdd11));
    report("scasw mismatch", di == mem + 2 && !z);

    di = mem;
    asm ("scasl; setz %0" : "=rm"(z), "+D"(di) : "a"(0xff44332211ul));
    report("scasd match", di == mem + 4 && z);

    di = mem;
    asm ("scasl; setz %0" : "=rm"(z), "+D"(di) : "a"(0x45332211));
    report("scasd mismatch", di == mem + 4 && !z);

    di = mem;
    asm ("scasq; setz %0" : "=rm"(z), "+D"(di) : "a"(0x77665544332211ul));
    report("scasq match", di == mem + 8 && z);

    di = mem;
    asm ("scasq; setz %0" : "=rm"(z), "+D"(di) : "a"(3));
    report("scasq mismatch", di == mem + 8 && !z);
}

void test_cr8(void)
{
	unsigned long src, dst;

	dst = 777;
	src = 3;
	asm volatile("mov %[src], %%cr8; mov %%cr8, %[dst]"
		     : [dst]"+r"(dst), [src]"+r"(src));
	report("mov %cr8", dst == 3 && src == 3);
}

void test_push(void *mem)
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

	report("push $imm8", stack_top[-1] == -7ul);
	report("push %reg", stack_top[-2] == -17ul);
	report("push mem", stack_top[-3] == 0x123456789abcdeful);
	report("push $imm", stack_top[-4] == -7070707);
}

void test_pop(void *mem)
{
	unsigned long tmp;
	unsigned long *stack_top = mem + 4096;
	unsigned long memw = 0x123456789abcdeful;
	static unsigned long tmp2;

	memset(mem, 0x55, (void *)stack_top - mem);

	asm volatile("pushq %[val] \n\t"
		     "popq (%[mem])"
		     : : [val]"m"(memw), [mem]"r"(mem) : "memory");
	report("pop mem", *(unsigned long *)mem == memw);

	memw = 7 - memw;
	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "pushq %[val] \n\t"
		     "popq %[tmp2] \n\t"
		     "mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp), [tmp2]"=m"(tmp2)
		     : [val]"r"(memw), [stack_top]"r"(stack_top)
		     : "memory");
	report("pop mem (2)", tmp2 == memw);

	memw = 129443 - memw;
	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "pushq %[val] \n\t"
		     "popq %[tmp2] \n\t"
		     "mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp), [tmp2]"=r"(tmp2)
		     : [val]"r"(memw), [stack_top]"r"(stack_top)
		     : "memory");
	report("pop reg", tmp2 == memw);

	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "push $1f \n\t"
		     "ret \n\t"
		     "2: jmp 2b \n\t"
		     "1: mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp) : [stack_top]"r"(stack_top)
		     : "memory");
	report("ret", 1);
}

void test_ljmp(void *mem)
{
    unsigned char *m = mem;
    volatile int res = 1;

    *(unsigned long**)m = &&jmpf;
    asm volatile ("data16/mov %%cs, %0":"=m"(*(m + sizeof(unsigned long))));
    asm volatile ("rex64/ljmp *%0"::"m"(*m));
    res = 0;
jmpf:
    report("ljmp", res);
}

void test_incdecnotneg(void *mem)
{
    unsigned long *m = mem, v = 1234;
    unsigned char *mb = mem, vb = 66;

    *m = 0;

    asm volatile ("incl %0":"+m"(*m));
    report("incl",  *m == 1);
    asm volatile ("decl %0":"+m"(*m));
    report("decl",  *m == 0);
    asm volatile ("incb %0":"+m"(*m));
    report("incb",  *m == 1);
    asm volatile ("decb %0":"+m"(*m));
    report("decb",  *m == 0);

    asm volatile ("lock incl %0":"+m"(*m));
    report("lock incl",  *m == 1);
    asm volatile ("lock decl %0":"+m"(*m));
    report("lock decl",  *m == 0);
    asm volatile ("lock incb %0":"+m"(*m));
    report("lock incb",  *m == 1);
    asm volatile ("lock decb %0":"+m"(*m));
    report("lock decb",  *m == 0);

    *m = v;

    asm ("lock negq %0" : "+m"(*m)); v = -v;
    report("lock negl", *m == v);
    asm ("lock notq %0" : "+m"(*m)); v = ~v;
    report("lock notl", *m == v);

    *mb = vb;

    asm ("lock negb %0" : "+m"(*mb)); vb = -vb;
    report("lock negb", *mb == vb);
    asm ("lock notb %0" : "+m"(*mb)); vb = ~vb;
    report("lock notb", *mb == vb);
}

void test_smsw(void)
{
	char mem[16];
	unsigned short msw, msw_orig, *pmsw;
	int i, zero;

	msw_orig = read_cr0();

	asm("smsw %0" : "=r"(msw));
	report("smsw (1)", msw == msw_orig);

	memset(mem, 0, 16);
	pmsw = (void *)mem;
	asm("smsw %0" : "=m"(pmsw[4]));
	zero = 1;
	for (i = 0; i < 8; ++i)
		if (i != 4 && pmsw[i])
			zero = 0;
	report("smsw (2)", msw == pmsw[4] && zero);
}

void test_lmsw(void)
{
	char mem[16];
	unsigned short msw, *pmsw;
	unsigned long cr0;

	cr0 = read_cr0();

	msw = cr0 ^ 8;
	asm("lmsw %0" : : "r"(msw));
	printf("before %lx after %lx\n", cr0, read_cr0());
	report("lmsw (1)", (cr0 ^ read_cr0()) == 8);

	pmsw = (void *)mem;
	*pmsw = cr0;
	asm("lmsw %0" : : "m"(*pmsw));
	printf("before %lx after %lx\n", cr0, read_cr0());
	report("lmsw (2)", cr0 == read_cr0());

	/* lmsw can't clear cr0.pe */
	msw = (cr0 & ~1ul) ^ 4;  /* change EM to force trap */
	asm("lmsw %0" : : "r"(msw));
	report("lmsw (3)", (cr0 ^ read_cr0()) == 4 && (cr0 & 1));

	/* back to normal */
	msw = cr0;
	asm("lmsw %0" : : "r"(msw));
}

void test_xchg(void *mem)
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
		     : "memory");
	report("xchg reg, r/m (1)",
	       rax == 0xfedcba98765432ef && *memq == 0x123456789abcd10);

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xchg %%ax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory");
	report("xchg reg, r/m (2)",
	       rax == 0xfedcba987654cdef && *memq == 0x123456789ab3210);

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xchg %%eax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory");
	report("xchg reg, r/m (3)",
	       rax == 0x89abcdef && *memq == 0x123456776543210);

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xchg %%rax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory");
	report("xchg reg, r/m (4)",
	       rax == 0x123456789abcdef && *memq == 0xfedcba9876543210);
}

void test_xadd(void *mem)
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
		     : "memory");
	report("xadd reg, r/m (1)",
	       rax == 0xfedcba98765432ef && *memq == 0x123456789abcdff);

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xadd %%ax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory");
	report("xadd reg, r/m (2)",
	       rax == 0xfedcba987654cdef && *memq == 0x123456789abffff);

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xadd %%eax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory");
	report("xadd reg, r/m (3)",
	       rax == 0x89abcdef && *memq == 0x1234567ffffffff);

	asm volatile("mov $0x123456789abcdef, %%rax\n\t"
		     "mov %%rax, (%[memq])\n\t"
		     "mov $0xfedcba9876543210, %%rax\n\t"
		     "xadd %%rax, (%[memq])\n\t"
		     "mov %%rax, %[rax]\n\t"
		     : [rax]"=r"(rax)
		     : [memq]"r"(memq)
		     : "memory");
	report("xadd reg, r/m (4)",
	       rax == 0x123456789abcdef && *memq == 0xffffffffffffffff);
}

void test_btc(void *mem)
{
	unsigned int *a = mem;

	memset(mem, 0, 3 * sizeof(unsigned int));

	asm ("btcl $32, %0" :: "m"(a[0]) : "memory");
	asm ("btcl $1, %0" :: "m"(a[1]) : "memory");
	asm ("btcl %1, %0" :: "m"(a[0]), "r"(66) : "memory");
	report("btcl imm8, r/m", a[0] == 1 && a[1] == 2 && a[2] == 4);

	asm ("btcl %1, %0" :: "m"(a[3]), "r"(-1) : "memory");
	report("btcl reg, r/m", a[0] == 1 && a[1] == 2 && a[2] == 0x80000004);
}

void test_bsfbsr(void *mem)
{
	unsigned long *memq = mem, rax;

	asm volatile("movw $0xC000, (%[memq])\n\t"
		     "bsfw (%[memq]), %%ax\n\t"
		     ::[memq]"r"(memq));
	asm ("mov %%rax, %[rax]": [rax]"=m"(rax));
	report("bsfw r/m, reg", rax == 14);

	asm volatile("movl $0xC0000000, (%[memq])\n\t"
		     "bsfl (%[memq]), %%eax\n\t"
		     ::[memq]"r"(memq));
	asm ("mov %%rax, %[rax]": [rax]"=m"(rax));
	report("bsfl r/m, reg", rax == 30);

	asm volatile("movq $0xC00000000000, %%rax\n\t"
		     "movq %%rax, (%[memq])\n\t"
		     "bsfq (%[memq]), %%rax\n\t"
		     ::[memq]"r"(memq));
	asm ("mov %%rax, %[rax]": [rax]"=m"(rax));
	report("bsfq r/m, reg", rax == 46);

	asm volatile("movq $0, %%rax\n\t"
		     "movq %%rax, (%[memq])\n\t"
		     "bsfq (%[memq]), %%rax\n\t"
		     "jnz 1f\n\t"
		     "movl $1, %[rax]\n\t"
		     "1:\n\t"
		     :[rax]"=m"(rax)
		     :[memq]"r"(memq));
	report("bsfq r/m, reg", rax == 1);

	asm volatile("movw $0xC000, (%[memq])\n\t"
		     "bsrw (%[memq]), %%ax\n\t"
		     ::[memq]"r"(memq));
	asm ("mov %%rax, %[rax]": [rax]"=m"(rax));
	report("bsrw r/m, reg", rax == 15);

	asm volatile("movl $0xC0000000, (%[memq])\n\t"
		     "bsrl (%[memq]), %%eax\n\t"
		     ::[memq]"r"(memq));
	asm ("mov %%rax, %[rax]": [rax]"=m"(rax));
	report("bsrl r/m, reg", rax == 31);

	asm volatile("movq $0xC00000000000, %%rax\n\t"
		     "movq %%rax, (%[memq])\n\t"
		     "bsrq (%[memq]), %%rax\n\t"
		     ::[memq]"r"(memq));
	asm ("mov %%rax, %[rax]": [rax]"=m"(rax));
	report("bsrq r/m, reg", rax == 47);

	asm volatile("movq $0, %%rax\n\t"
		     "movq %%rax, (%[memq])\n\t"
		     "bsrq (%[memq]), %%rax\n\t"
		     "jnz 1f\n\t"
		     "movl $1, %[rax]\n\t"
		     "1:\n\t"
		     :[rax]"=m"(rax)
		     :[memq]"r"(memq));
	report("bsrq r/m, reg", rax == 1);
}

int main()
{
	void *mem;
	unsigned long t1, t2;

	setup_vm();
	mem = vmap(IORAM_BASE_PHYS, IORAM_LEN);

	// test mov reg, r/m and mov r/m, reg
	t1 = 0x123456789abcdef;
	asm volatile("mov %[t1], (%[mem]) \n\t"
		     "mov (%[mem]), %[t2]"
		     : [t2]"=r"(t2)
		     : [t1]"r"(t1), [mem]"r"(mem)
		     : "memory");
	report("mov reg, r/m (1)", t2 == 0x123456789abcdef);

	test_cmps(mem);
	test_scas(mem);

	test_push(mem);
	test_pop(mem);

	test_xchg(mem);
	test_xadd(mem);

	test_cr8();

	test_smsw();
	test_lmsw();
	test_ljmp(mem);
	test_stringio();
	test_incdecnotneg(mem);
	test_btc(mem);
	test_bsfbsr(mem);

	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}
