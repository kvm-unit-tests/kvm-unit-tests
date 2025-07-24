#include "libcflat.h"
#include "vm.h"
#include "desc.h"
#include "alloc_page.h"
#include "fwcfg.h"

#define KVM_HYPERCALL_VMCALL	0x0f,0x01,0xc1	/* Intel */
#define KVM_HYPERCALL_VMMCALL	0x0f,0x01,0xd9	/* AMD */

#define test_hypercall(type, may_fail) \
	do {								\
		const char ref_insn[] = { KVM_HYPERCALL_##type };	\
		bool extra;						\
		extern const char hc_##type[];				\
									\
		asm volatile goto(ASM_TRY("%l["xstr(fault_##type)"]")	\
				  xstr(hc_##type) ":\n\t"		\
				  ".byte " xstr(KVM_HYPERCALL_##type)	\
				  : /* no outputs allowed */		\
				  : "a"(-1)				\
				  : "memory"				\
				  : fault_##type);			\
		extra = memcmp(hc_##type, ref_insn, sizeof(ref_insn));	\
		report(true, "Hypercall via " #type ": OK%s",		\
		       extra ? " (patched)" : "");			\
		break;							\
									\
	fault_##type:							\
		extra = exception_vector() != PF_VECTOR &&		\
			exception_vector() != UD_VECTOR;		\
		report((may_fail) && !extra,				\
			"Hypercall via " #type ": %s%s(%u)",		\
			extra ? "unexpected " : "",			\
			exception_mnemonic(exception_vector()),		\
			exception_error_code());			\
	} while (0)

#ifdef __x86_64__
#define NON_CANON_START	(1UL << 47)

static bool test_edge(bool may_fail)
{
	const char *addr = (void *)(NON_CANON_START - 3);
	char insn[3] = { addr[0], addr[1], addr[2] };

	static_assert(NON_CANON_START == 0x800000000000UL);
	asm volatile goto("jmpq *%[addr]; 1:"
			  ASM_EX_ENTRY("0x7ffffffffffd", "%l[insn_failed]")
			  ASM_EX_ENTRY("0x800000000000", "1b")
			  : /* no outputs allowed */
			  : "a"(-1), [addr]"r"(addr)
			  : "memory"
			  : insn_failed);
	printf("Return from %s(%u) with RIP = %lx%s\n",
	       exception_mnemonic(exception_vector()), exception_error_code(),
	       NON_CANON_START, memcmp(addr, insn, 3) ? ", patched" : "");
	return true;

insn_failed:
	printf("KVM hypercall failed%s\n",
	       may_fail ? ", as expected" : " unexpectedly!");
	return may_fail;
}
#endif

int main(int ac, char **av)
{
	/* VMCALL may be patched by KVM on AMD or fail with #UD on bare metal */
	test_hypercall(VMCALL, !is_intel());

	/* VMMCALL may be patched on Intel or fail with #UD in bare metal */
	test_hypercall(VMMCALL, is_intel());

#ifdef __x86_64__
	setup_vm();

	u8 *topmost = (void *) (NON_CANON_START - PAGE_SIZE);

	install_page(current_page_table(), virt_to_phys(alloc_page()), topmost);
	memset(topmost, 0xcc, PAGE_SIZE);

	memcpy(topmost + PAGE_SIZE - 3, (char []){ KVM_HYPERCALL_VMCALL }, 3);
	report(test_edge(!is_intel()),
	       "VMCALL on edge of canonical address space (Intel)");

	memcpy(topmost + PAGE_SIZE - 3, (char []){ KVM_HYPERCALL_VMMCALL }, 3);
	report(test_edge(is_intel()),
	       "VMMCALL on edge of canonical address space (AMD)");
#endif

	return report_summary();
}
