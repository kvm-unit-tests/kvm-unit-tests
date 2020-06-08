
#include "x86/msr.h"
#include "x86/processor.h"
#include "x86/apic-defs.h"
#include "x86/apic.h"
#include "x86/desc.h"
#include "x86/isr.h"
#include "alloc.h"
#include "setjmp.h"
#include "usermode.h"
#include "fault_test.h"

#include "libcflat.h"
#include <stdint.h>

#define VMWARE_BACKDOOR_PMC_HOST_TSC           0x10000
#define VMWARE_BACKDOOR_PMC_REAL_TIME          0x10001
#define VMWARE_BACKDOOR_PMC_APPARENT_TIME      0x10002

#define VMWARE_BACKDOOR_PORT	0x5658
#define VMWARE_MAGIC		0x564D5868

#define VMPORT_CMD_GETVERSION	0x0a
#define VMPORT_CMD_ILLEGAL	0xfff

#define VMPORT_DEFAULT_RETVAL	0xdeadbeef

#define RANDOM_IO_PORT		0x1234

struct backdoor_port_result {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
};

static bool vmware_backdoor_port_callback(struct fault_test_arg *arg)
{
	struct backdoor_port_result *res =
		(struct backdoor_port_result *) arg->retval;

	switch (arg->arg[2]) {
	case VMPORT_CMD_GETVERSION:
		return (res->rbx == VMWARE_MAGIC);
	case VMPORT_CMD_ILLEGAL:
		return (res->rbx == VMPORT_DEFAULT_RETVAL);
	}
	return false;
}

static uint64_t vmware_backdoor_port(uint64_t vmport, uint64_t vmport_magic,
		uint64_t command)
{
	struct backdoor_port_result *res =
		(struct backdoor_port_result *)
		malloc(sizeof(struct backdoor_port_result));

	res->rax = VMPORT_DEFAULT_RETVAL;
	res->rbx = VMPORT_DEFAULT_RETVAL;
	res->rcx = VMPORT_DEFAULT_RETVAL;
	res->rdx = VMPORT_DEFAULT_RETVAL;

	asm volatile(
		"mov %[rax], %%rax\n\t"
		"mov %[rdx], %%rdx\n\t"
		"mov %[rcx], %%rcx\n\t"
		"inl %%dx, %%eax\n\t"
		:
		"+a"(res->rax),
		"+b"(res->rbx),
		"+c"(res->rcx),
		"+d"(res->rdx)
		:
		[rax]"m"(vmport_magic),
		[rdx]"m"(vmport),
		[rcx]"m"(command)
		);

	return (uint64_t) res;
}

#define FAULT		true
#define NO_FAULT	false
#define USER_MODE	true
#define KERNEL_MODE	false

#define RDPMC_ARG(n, m, sf) {.usermode = m, \
	.func =  (test_fault_func) rdpmc, .fault_vector = GP_VECTOR, \
	.should_fault = sf, .arg = {n, 0, 0, 0}, .callback = NULL}

#define RDPMC_TEST(name, a, m, sf) FAULT_TEST("rdpmc_test: "name, \
		RDPMC_ARG(a, m, sf))

#define PORT_ARG(a, b, c, m, sf) {.usermode = m, \
	.func =  (test_fault_func) vmware_backdoor_port, \
	.fault_vector = GP_VECTOR, .should_fault = sf, .arg = {a, b, c, 0}, \
	.callback = vmware_backdoor_port_callback}

#define PORT_TEST(name, a, b, c, m, sf) FAULT_TEST("port_test: "name, \
		PORT_ARG(a, b, c, m, sf))


struct fault_test vmware_backdoor_tests[] = {
	RDPMC_TEST("HOST_TSC kernel", VMWARE_BACKDOOR_PMC_HOST_TSC,
			KERNEL_MODE, NO_FAULT),
	RDPMC_TEST("REAL_TIME kernel", VMWARE_BACKDOOR_PMC_REAL_TIME,
			KERNEL_MODE, NO_FAULT),
	RDPMC_TEST("APPARENT_TIME kernel", VMWARE_BACKDOOR_PMC_APPARENT_TIME,
			KERNEL_MODE, NO_FAULT),
	RDPMC_TEST("HOST_TSC user", VMWARE_BACKDOOR_PMC_HOST_TSC,
			USER_MODE, NO_FAULT),
	RDPMC_TEST("REAL_TIME user", VMWARE_BACKDOOR_PMC_REAL_TIME,
			USER_MODE, NO_FAULT),
	RDPMC_TEST("APPARENT_TIME user", VMWARE_BACKDOOR_PMC_APPARENT_TIME,
			USER_MODE, NO_FAULT),
	RDPMC_TEST("RANDOM PMC user", 0xfff, USER_MODE, FAULT),

	PORT_TEST("CMD_GETVERSION user", VMWARE_BACKDOOR_PORT, VMWARE_MAGIC,
			VMPORT_CMD_GETVERSION, USER_MODE, NO_FAULT),
	PORT_TEST("CMD_GETVERSION kernel", VMWARE_BACKDOOR_PORT, VMWARE_MAGIC,
			VMPORT_CMD_GETVERSION, KERNEL_MODE, NO_FAULT),
	PORT_TEST("CMD_ILLEGAL user", VMWARE_BACKDOOR_PORT, VMWARE_MAGIC,
			VMPORT_CMD_ILLEGAL, USER_MODE, NO_FAULT),
	PORT_TEST("RANDOM port user", RANDOM_IO_PORT, VMWARE_MAGIC, 0xfff,
			USER_MODE, FAULT),
	{ NULL },
};

/*
 * Set TSS IO Perm to throw GP on RANDOM_IO_PORT and VMWARE_BACKDOOR_PORT
 * from User Mode
 */
static void set_tss_ioperm(void)
{
	struct descriptor_table_ptr gdt;
	struct segment_desc64 *gdt_table;
	struct segment_desc64 *tss_entry;
	u16 tr = 0;
	tss64_t *tss;
	unsigned char *ioperm_bitmap;
	uint64_t tss_base;

	sgdt(&gdt);
	tr = str();
	gdt_table = (struct segment_desc64 *) gdt.base;
	tss_entry = &gdt_table[tr / sizeof(struct segment_desc64)];
	tss_base = ((uint64_t) tss_entry->base1 |
			((uint64_t) tss_entry->base2 << 16) |
			((uint64_t) tss_entry->base3 << 24) |
			((uint64_t) tss_entry->base4 << 32));
	tss = (tss64_t *)tss_base;
	tss->iomap_base = sizeof(*tss);
	ioperm_bitmap = ((unsigned char *)tss+tss->iomap_base);

	/* We want GP on RANDOM_IO_PORT and VMWARE_BACKDOOR_PORT */
	ioperm_bitmap[RANDOM_IO_PORT / 8] |=
		1 << (RANDOM_IO_PORT % 8);
	ioperm_bitmap[VMWARE_BACKDOOR_PORT / 8] |=
		1 << (VMWARE_BACKDOOR_PORT % 8);
	*(uint64_t *)tss_entry &= ~DESC_BUSY;

	/* Update TSS */
	ltr(tr);
}

static void check_vmware_backdoors(void)
{
	int i;

	/* Disable Permissions for IO PORTS */
	set_tss_ioperm();
	/* Disable Permission to run rdpmc from user mode */
	write_cr4(read_cr4() & ~X86_CR4_PCE);

	report_prefix_push("vmware_backdoors");

	for (i = 0; vmware_backdoor_tests[i].name != NULL; i++)
		test_run(&vmware_backdoor_tests[i]);

	report_prefix_pop();
}

int main(int ac, char **av)
{
	setup_vm();

	check_vmware_backdoors();

	return report_summary();
}
