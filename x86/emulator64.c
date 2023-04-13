#define MAGIC_NUM 0xdeadbeefdeadbeefUL
#define GS_BASE 0x400000

static unsigned long rip_advance;

static void advance_rip_and_note_exception(struct ex_regs *regs)
{
	++exceptions;
	regs->rip += rip_advance;
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
	report(a == 0x1ffffffb1b963b33ul && d == 0x273ba4384ede2ul && !ex, "divq (1)");

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


static void test_mmx_movq_mf(uint64_t *mem)
{
	/* movq %mm0, (%rax) */
	extern char movq_start, movq_end;
	handler old;

	uint16_t fcw = 0;  /* all exceptions unmasked */
	write_cr0(read_cr0() & ~6);  /* TS, EM */
	exceptions = 0;
	old = handle_exception(MF_VECTOR, advance_rip_and_note_exception);
	asm volatile("fninit; fldcw %0" : : "m"(fcw));
	asm volatile("fldz; fldz; fdivp"); /* generate exception */

	rip_advance = &movq_end - &movq_start;
	asm(KVM_FEP "movq_start: movq %mm0, (%rax); movq_end:");
	/* exit MMX mode */
	asm volatile("fnclex; emms");
	report(exceptions == 1, "movq mmx generates #MF");
	handle_exception(MF_VECTOR, old);
}

static void test_jmp_noncanonical(uint64_t *mem)
{
	extern char nc_jmp_start, nc_jmp_end;
	handler old;

	*mem = 0x1111111111111111ul;

	exceptions = 0;
	rip_advance = &nc_jmp_end - &nc_jmp_start;
	old = handle_exception(GP_VECTOR, advance_rip_and_note_exception);
	asm volatile ("nc_jmp_start: jmp *%0; nc_jmp_end:" : : "m"(*mem));
	report(exceptions == 1, "jump to non-canonical address");
	handle_exception(GP_VECTOR, old);
}

static void test_movabs(uint64_t *mem)
{
	/* mov $0x9090909090909090, %rcx */
	unsigned long rcx;
	asm(KVM_FEP "mov $0x9090909090909090, %0" : "=c" (rcx) : "0" (0));
	report(rcx == 0x9090909090909090, "64-bit mov imm2");
}

static void load_dpl0_seg(void)
{
	asm volatile(KVM_FEP "mov %0, %%fs" :: "r" (KERNEL_CS)); /* RPL=0 */
}

static void test_user_load_dpl0_seg(void)
{
	bool raised_vector;

	run_in_user((usermode_func)load_dpl0_seg, GP_VECTOR, 0, 0, 0, 0,
		    &raised_vector);

	report(raised_vector, "Wanted #GP on CPL=3 DPL=0 segment load");
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

static void test_sreg(volatile uint16_t *mem)
{
	u16 ss = read_ss();

	// check for null segment load
	*mem = 0;
	asm volatile("mov %0, %%ss" : : "m"(*mem));
	report(read_ss() == 0, "mov null, %%ss");

	// check for exception when ss.rpl != cpl on null segment load
	*mem = 3;
	asm volatile(ASM_TRY("1f") "mov %0, %%ss; 1:" : : "m"(*mem));
	report(exception_vector() == GP_VECTOR &&
	       exception_error_code() == 0 && read_ss() == 0,
	       "mov null, %%ss (with ss.rpl != cpl)");

	write_ss(ss);
}

static uint64_t usr_gs_mov(void)
{
	static uint64_t dummy = MAGIC_NUM;
	uint64_t dummy_ptr = (uint64_t)&dummy;
	uint64_t ret;

	dummy_ptr -= GS_BASE;
	asm volatile("mov %%gs:(%1), %0" : "=r"(ret) : "r"(dummy_ptr));

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

static void test_emulator_64(void *mem)
{
	void *insn_page = alloc_page();
	void *insn_ram  = vmap(virt_to_phys(insn_page), 4096);

	test_push(mem);
	test_pop(mem);

	test_xchg(mem);
	test_xadd(mem);

	test_cr8();

	test_ljmp(mem);
	test_muldiv(mem);
	test_mmx(mem);
	test_rip_relative(mem, insn_ram);
	test_iret();
	test_sreg(mem);
	test_cmov(mem);

	if (is_fep_available()) {
		test_mmx_movq_mf(mem);
		test_movabs(mem);
		test_user_load_dpl0_seg();
	}

	test_push16(mem);

	test_jmp_noncanonical(mem);
}
