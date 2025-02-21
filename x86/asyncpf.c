/*
 * Async PF test. For the test to actually do anything it needs to be started
 * in memory cgroup with 512M of memory and with more than 1G memory provided
 * to the guest.
 *
 * To identify the cgroup version on Linux:
 * stat -fc %T /sys/fs/cgroup/
 *
 * If the output is tmpfs, your system is using cgroup v1:
 * To create cgroup do as root:
 * mkdir /dev/cgroup
 * mount -t cgroup none -omemory /dev/cgroup
 * chmod a+rxw /dev/cgroup/
 *
 * From a shell you will start qemu from:
 * mkdir /dev/cgroup/1
 * echo $$ >  /dev/cgroup/1/tasks
 * echo 512M > /dev/cgroup/1/memory.limit_in_bytes
 *
 * If the output is cgroup2fs, your system is using cgroup v2:
 * mkdir /sys/fs/cgroup/cg1
 * echo $$ >  /sys/fs/cgroup/cg1/cgroup.procs
 * echo 512M > /sys/fs/cgroup/cg1/memory.max
 *
 */
#include "x86/processor.h"
#include "x86/apic.h"
#include "x86/isr.h"
#include "x86/vm.h"
#include "alloc.h"
#include "vmalloc.h"

#define KVM_PV_REASON_PAGE_NOT_PRESENT 1

#define MSR_KVM_ASYNC_PF_EN 0x4b564d02
#define MSR_KVM_ASYNC_PF_INT    0x4b564d06
#define MSR_KVM_ASYNC_PF_ACK    0x4b564d07

#define KVM_ASYNC_PF_ENABLED                    (1 << 0)
#define KVM_ASYNC_PF_SEND_ALWAYS                (1 << 1)
#define KVM_ASYNC_PF_DELIVERY_AS_INT            (1 << 3)

#define HYPERVISOR_CALLBACK_VECTOR	0xf3

struct kvm_vcpu_pv_apf_data {
      /* Used for 'page not present' events delivered via #PF */
      uint32_t  flags;

      /* Used for 'page ready' events delivered via interrupt notification */
      uint32_t  token;

      uint8_t  pad[56];
} apf_reason __attribute__((aligned(64)));

char *buf;
void* virt;
volatile uint64_t  i;
volatile uint64_t phys;
volatile uint32_t saved_token;
volatile unsigned asyncpf_num;

static inline uint32_t get_and_clear_apf_reason(void)
{
	uint32_t r = apf_reason.flags;
	apf_reason.flags = 0;
	return r;
}

static void handle_interrupt(isr_regs_t *regs)
{
	uint32_t apf_token = apf_reason.token;

	apf_reason.token = 0;
	wrmsr(MSR_KVM_ASYNC_PF_ACK, 1);

	if (apf_token == 0xffffffff) {
		report_pass("Wakeup all, got token 0x%" PRIx32, apf_token);
	} else if (apf_token == saved_token) {
		asyncpf_num++;
		install_pte(phys_to_virt(read_cr3()), 1, virt, phys | PT_PRESENT_MASK | PT_WRITABLE_MASK, 0);
		phys = 0;
	} else {
		report_fail("unexpected async pf int token 0x%" PRIx32, apf_token);
	}

	eoi();
}

static void handle_pf(struct ex_regs *r)
{
	virt = (void*)((ulong)(buf+i) & ~(PAGE_SIZE-1));
	uint32_t reason = get_and_clear_apf_reason();
	switch (reason) {
	case 0:
		report_fail("unexpected #PF at %#lx", read_cr2());
		exit(report_summary());
	case KVM_PV_REASON_PAGE_NOT_PRESENT:
		phys = virt_to_pte_phys(phys_to_virt(read_cr3()), virt);
		install_pte(phys_to_virt(read_cr3()), 1, virt, phys, 0);
		write_cr3(read_cr3());
		saved_token = read_cr2();
		while (phys) {
			safe_halt(); /* enables irq */
		}
		break;
	default:
		report_fail("unexpected async pf with reason 0x%" PRIx32, reason);
		exit(report_summary());
	}
}

#define MEM (1ull*1024*1024*1024)

int main(int ac, char **av)
{
	if (!this_cpu_has(KVM_FEATURE_ASYNC_PF)) {
		report_skip("KVM_FEATURE_ASYNC_PF is not supported\n");
		return report_summary();
	}

	if (!this_cpu_has(KVM_FEATURE_ASYNC_PF_INT)) {
		report_skip("KVM_FEATURE_ASYNC_PF_INT is not supported\n");
		return report_summary();
	}

	setup_vm();

	handle_exception(PF_VECTOR, handle_pf);
	handle_irq(HYPERVISOR_CALLBACK_VECTOR, handle_interrupt);
	memset(&apf_reason, 0, sizeof(apf_reason));

	wrmsr(MSR_KVM_ASYNC_PF_INT, HYPERVISOR_CALLBACK_VECTOR);
	wrmsr(MSR_KVM_ASYNC_PF_EN, virt_to_phys((void*)&apf_reason) |
			KVM_ASYNC_PF_SEND_ALWAYS | KVM_ASYNC_PF_ENABLED | KVM_ASYNC_PF_DELIVERY_AS_INT);

	buf = malloc(MEM);
	sti();

	/* access a lot of memory to make host swap it out */
	for (i = 0; i < MEM; i += 4096)
		buf[i] = 1;

	cli();
	if (!asyncpf_num)
		report_skip("No async page fault events, cgroup configuration likely needed");
	else
		report_pass("Serviced %d async page faults events (!PRESENT #PF + READY IRQ)",
			    asyncpf_num);
	return report_summary();
}
