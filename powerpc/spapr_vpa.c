/*
 * Test sPAPR "Per Virtual Processor Area" and H_REGISTER_VPA hypervisor call
 * (also known as VPA, also known as lppaca in the Linux pseries kernel).
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <libfdt/libfdt.h>
#include <devicetree.h>
#include <util.h>
#include <alloc.h>
#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/hcall.h>
#include <asm/vpa.h>
#include <asm/io.h> /* for endian accessors */

static int verbose;

static void print_vpa(struct vpa *vpa)
{
	printf("VPA\n");
	printf("descriptor:			0x%08x\n", be32_to_cpu(vpa->descriptor));
	printf("size:				    0x%04x\n", be16_to_cpu(vpa->size));
	printf("status:				      0x%02x\n", vpa->status);
	printf("fru_node_id:			0x%08x\n", be32_to_cpu(vpa->fru_node_id));
	printf("fru_proc_id:			0x%08x\n", be32_to_cpu(vpa->fru_proc_id));
	printf("vhpn_change_counters:		0x%02x %02x %02x %02x %02x %02x %02x %02x\n", vpa->vhpn_change_counters[0], vpa->vhpn_change_counters[1], vpa->vhpn_change_counters[2], vpa->vhpn_change_counters[3], vpa->vhpn_change_counters[4], vpa->vhpn_change_counters[5], vpa->vhpn_change_counters[6], vpa->vhpn_change_counters[7]);
	printf("vp_dispatch_count:		0x%08x\n", be32_to_cpu(vpa->vp_dispatch_count));
	printf("vp_dispatch_dispersion:		0x%08x\n", be32_to_cpu(vpa->vp_dispatch_dispersion));
	printf("vp_fault_count:			0x%08lx\n", be64_to_cpu(vpa->vp_fault_count));
	printf("vp_fault_tb:			0x%08lx\n", be64_to_cpu(vpa->vp_fault_tb));
	printf("purr_exprop_idle:		0x%08lx\n", be64_to_cpu(vpa->purr_exprop_idle));
	printf("spurr_exprop_idle:		0x%08lx\n", be64_to_cpu(vpa->spurr_exprop_idle));
	printf("purr_exprop_busy:		0x%08lx\n", be64_to_cpu(vpa->purr_exprop_busy));
	printf("spurr_exprop_busy:		0x%08lx\n", be64_to_cpu(vpa->spurr_exprop_busy));
	printf("purr_donate_idle:		0x%08lx\n", be64_to_cpu(vpa->purr_donate_idle));
	printf("spurr_donate_idle:		0x%08lx\n", be64_to_cpu(vpa->spurr_donate_idle));
	printf("purr_donate_busy:		0x%08lx\n", be64_to_cpu(vpa->purr_donate_busy));
	printf("spurr_donate_busy:		0x%08lx\n", be64_to_cpu(vpa->spurr_donate_busy));
	printf("vp_wait3_tb:			0x%08lx\n", be64_to_cpu(vpa->vp_wait3_tb));
	printf("vp_wait2_tb:			0x%08lx\n", be64_to_cpu(vpa->vp_wait2_tb));
	printf("vp_wait1_tb:			0x%08lx\n", be64_to_cpu(vpa->vp_wait1_tb));
	printf("purr_exprop_adjunct_busy:	0x%08lx\n", be64_to_cpu(vpa->purr_exprop_adjunct_busy));
	printf("spurr_exprop_adjunct_busy:	0x%08lx\n", be64_to_cpu(vpa->spurr_exprop_adjunct_busy));
	printf("purr_exprop_adjunct_idle:	0x%08lx\n", be64_to_cpu(vpa->purr_exprop_adjunct_idle));
	printf("spurr_exprop_adjunct_idle:	0x%08lx\n", be64_to_cpu(vpa->spurr_exprop_adjunct_idle));
	printf("adjunct_insns_executed:		0x%08lx\n", be64_to_cpu(vpa->adjunct_insns_executed));
	printf("dtl_index:			0x%08lx\n", be64_to_cpu(vpa->dtl_index));
}

#define SUBFUNC_RESERVED	(0ULL << 45)
#define SUBFUNC_REGISTER	(1ULL << 45)
#define SUBFUNC_DEREGISTER	(5ULL << 45)

/*
 * Test the H_REGISTER_VPA h-call register/deregister calls.
 */
static void test_register_vpa(void)
{
	struct vpa *vpa;
	uint32_t cpuid = fdt_boot_cpuid_phys(dt_fdt());
	int rc;

	report_prefix_push("H_REGISTER_VPA");

	vpa = memalign(4096, sizeof(*vpa));

	memset(vpa, 0, sizeof(*vpa));

	vpa->size = cpu_to_be16(sizeof(*vpa));

	rc = hcall(H_REGISTER_VPA, SUBFUNC_RESERVED, cpuid, vpa);
	report(rc == H_PARAMETER, "Reserved sub-function fails with H_PARAMETER");

	rc = hcall(H_REGISTER_VPA, SUBFUNC_REGISTER, 0xbadbad, vpa);
	report(rc == H_PARAMETER, "Register with invalid proc-no fails");

	rc = hcall(H_REGISTER_VPA, SUBFUNC_REGISTER, cpuid, (void *)vpa + 8);
	report(rc == H_PARAMETER, "Register with VPA not cacheline aligned fails");


	rc = hcall(H_REGISTER_VPA, SUBFUNC_REGISTER, cpuid, (void *)vpa + 4096 - 128);
	report(rc == H_PARAMETER, "Register with VPA spanning 4096 bytes fails");

	vpa->size = cpu_to_be16(632);
	rc = hcall(H_REGISTER_VPA, SUBFUNC_REGISTER, cpuid, (void *)vpa);
	report(rc == H_PARAMETER, "Register with VPA size < 640 bytes fails");
	vpa->size = cpu_to_be16(sizeof(*vpa));

	rc = hcall(H_REGISTER_VPA, SUBFUNC_REGISTER, cpuid, PHYSICAL_END);
	report(rc == H_PARAMETER, "Register with VPA outside guest real memory fails");


	rc = hcall(H_REGISTER_VPA, SUBFUNC_REGISTER, cpuid, vpa);
	report(rc == H_SUCCESS, "VPA registered");

	rc = hcall(H_REGISTER_VPA, SUBFUNC_DEREGISTER, cpuid, NULL);
	report(rc == H_SUCCESS, "VPA deregistered");

	/*
	 * From PAPR: "note no check is made that a valid VPA registration
	 * exists".
	 */
	rc = hcall(H_REGISTER_VPA, SUBFUNC_DEREGISTER, cpuid, NULL);
	report(rc == H_SUCCESS, "Deregister succeeds with no VPA registered");

	rc = hcall(H_REGISTER_VPA, SUBFUNC_DEREGISTER, 0xbadbad, NULL);
	report(rc == H_PARAMETER, "Deregister with invalid proc-no fails");

	report_prefix_pop();
}

/*
 * Test some VPA fields.
 */
static void test_vpa(void)
{
	struct vpa *vpa;
	uint32_t cpuid = fdt_boot_cpuid_phys(dt_fdt());
	int disp_count1, disp_count2;
	int rc;

	report_prefix_push("VPA");

	vpa = memalign(4096, sizeof(*vpa));

	memset(vpa, 0, sizeof(*vpa));

	vpa->size = cpu_to_be16(sizeof(*vpa));

	rc = hcall(H_REGISTER_VPA, SUBFUNC_REGISTER, cpuid, vpa);
	if (rc != H_SUCCESS) {
		report_skip("VPA could not be registered");
		return;
	}

	if (verbose)
		print_vpa(vpa);

	disp_count1 = be32_to_cpu(vpa->vp_dispatch_count);
	report(disp_count1 % 2 == 0, "Dispatch count is even while running");
	msleep(100);
	disp_count2 = be32_to_cpu(vpa->vp_dispatch_count);
	report(disp_count1 != disp_count2, "Dispatch count increments over H_CEDE");

	rc = hcall(H_REGISTER_VPA, SUBFUNC_DEREGISTER, cpuid, vpa);
	if (rc != H_SUCCESS)
		report_fail("Could not deregister after registration");

	disp_count1 = be32_to_cpu(vpa->vp_dispatch_count);
	report(disp_count1 % 2 == 1, "Dispatch count is odd after deregister");

	report_prefix_pop();
}

int main(int argc, char *argv[])
{
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			verbose = 1;
		}
	}

	test_register_vpa();

	test_vpa();

	return report_summary();
}
