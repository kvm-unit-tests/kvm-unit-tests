/*
 * Secondary cpu support
 *
 * Copyright 2016 Suraj Jitindar Singh, IBM.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

#include <alloc.h>
#include <devicetree.h>
#include <asm/atomic.h>
#include <asm/barrier.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/setup.h>
#include <asm/opal.h>
#include <asm/hcall.h>
#include <asm/rtas.h>
#include <asm/smp.h>

struct secondary_entry_data {
	secondary_entry_fn entry;
};

int nr_cpus_online = 1;

static void stop_self(int cpu_id)
{
	if (machine_is_powernv()) {
		if (opal_call(OPAL_RETURN_CPU, 0, 0, 0) != OPAL_SUCCESS) {
			printf("OPAL_RETURN_CPU failed\n");
		}
	} else {
		rtas_stop_self();
	}

	printf("failed to stop cpu %d\n", cpu_id);
	assert(0);
}

void main_secondary(struct cpu *cpu);
void main_secondary(struct cpu *cpu)
{
	mtspr(SPR_SPRG0, (unsigned long)cpu);
	__current_cpu = cpu;

	enable_mcheck();

	cpu_init_ipis();

	atomic_fetch_inc(&nr_cpus_online);

	cpu->entry(cpu->server_no);

	mb();
	atomic_fetch_dec(&nr_cpus_online);

	stop_self(cpu->server_no);
}

enum OpalThreadStatus {
        OPAL_THREAD_INACTIVE = 0x0,
        OPAL_THREAD_STARTED = 0x1,
        OPAL_THREAD_UNAVAILABLE = 0x2 /* opal-v3 */
};

#define H_EOI		0x64
#define H_CPPR		0x68
#define H_IPI		0x6c
#define H_XIRR		0x74

static void (*ipi_fn)(struct pt_regs *regs, void *data);

static void dbell_handler(struct pt_regs *regs, void *data)
{
	/* sync */
	ipi_fn(regs, data);
}

static void extint_handler(struct pt_regs *regs, void *data)
{
	int32_t xirr;
	int32_t xisr;
	int64_t rc;

	asm volatile("mr r3,%1 ; sc 1 ; mr %0,r4" : "=r"(xirr) : "r"(H_XIRR));
	xisr = xirr & 0xffffff;

	if (xisr == 2) { /* IPI */
		rc = hcall(H_IPI, smp_processor_id(), 0xff);
		assert(rc == H_SUCCESS);
	}

	xirr |= (5 << 24);
	rc = hcall(H_EOI, xirr);
	assert(rc == H_SUCCESS);

	/* lower IPI */
	ipi_fn(regs, data);
}

void cpu_init_ipis(void)
{
	if (machine_is_powernv()) {
		/* skiboot can leave some messages set */
		unsigned long rb = (5 << (63-36));
		asm volatile("msgclr	%0" :: "r"(rb) : "memory");
	}
}

void local_ipi_enable(void)
{
	if (machine_is_pseries()) {
		hcall(H_CPPR, 5);
	}
}

void local_ipi_disable(void)
{
	if (machine_is_pseries()) {
		hcall(H_CPPR, 0);
	}
}

void register_ipi(void (*fn)(struct pt_regs *, void *), void *data)
{
	ipi_fn = fn;
	if (machine_is_powernv()) {
		handle_exception(0xe80, &dbell_handler, data);
	} else {
		handle_exception(0x500, &extint_handler, data);
	}
}

void unregister_ipi(void)
{
	if (machine_is_powernv()) {
		handle_exception(0xe80, NULL, NULL);
	} else {
		handle_exception(0x500, NULL, NULL);
	}
}

void send_ipi(int cpu_id)
{
	if (machine_is_powernv()) {
		unsigned long rb = (5 << (63-36)) | cpu_id;
		asm volatile("lwsync" ::: "memory");
		asm volatile("msgsnd	%0" :: "r"(rb) : "memory");
	} else {
		hcall(H_IPI, cpu_id, 4);
	}
}

static int nr_started = 1;

extern void start_secondary(uint64_t server_no); /* asm entry point */

static bool cpu_is_running(int cpu_id)
{
	if (machine_is_powernv()) {
		int64_t ret;
		uint8_t status;

		ret = opal_call(OPAL_QUERY_CPU_STATUS, cpu_id, (unsigned long)&status, 0);
		if (ret != OPAL_SUCCESS) {
			printf("OPAL_QUERY_CPU_STATUS failed for cpu %d\n", cpu_id);
			return false;
		}
		return (status != OPAL_THREAD_INACTIVE);
	} else {
		uint32_t query_token;
		int outputs[1], ret;

		ret = rtas_token("query-cpu-stopped-state", &query_token);
		if (ret != 0) {
			printf("rtas token query-cpu-stopped-state failed\n");
			return false;
		}

		ret = rtas_call(query_token, 1, 2, outputs, cpu_id);
		if (ret) {
			printf("query-cpu-stopped-state failed for cpu %d\n", cpu_id);
			return ret;
		}
		if (outputs[0]) /* cpu not in stopped state */
			return true;
		return false;
	}
}

/*
 * Start stopped thread cpu_id at entry
 * Returns:	<0 on failure to start stopped cpu
 *		0  on success
 *		>0 on cpu not in stopped state
 */
static int start_thread(int cpu_id, secondary_entry_fn entry)
{
	struct cpu *cpu;
	uint64_t tb;

	if (nr_started >= NR_CPUS) {
		/* Reached limit */
		return -1;
	}

	if (cpu_id == smp_processor_id()) {
		/* Boot CPU already started */
		return -1;
	}

	tb = get_tb();
	while (cpu_is_running(cpu_id)) {
		if (get_tb() - tb > 3*tb_hz) {
			printf("Unable to start running CPU:%d\n", cpu_id);
			return 1;
		}
	}

	cpu = &cpus[nr_started];
	nr_started++;

	cpu_init(cpu, cpu_id);
	cpu->entry = entry;

	if (machine_is_powernv()) {
		if (opal_call(OPAL_START_CPU, cpu_id, (unsigned long)start_secondary, 0) != OPAL_SUCCESS) {
			printf("failed to start cpu %d\n", cpu_id);
			return -1;
		}
	} else {
		uint32_t start_token;
		int ret;

		ret = rtas_token("start-cpu", &start_token);
		assert(ret == 0);

		ret = rtas_call(start_token, 3, 1, NULL, cpu_id, start_secondary, cpu_id);
		if (ret) {
			printf("failed to start cpu %d\n", cpu_id);
			return ret;
		}
	}

	return 0;
}

/*
 * Start all stopped threads (vcpus) on cpu_node
 * Returns: Number of stopped cpus which were successfully started
 */
static void start_core(int cpu_node, secondary_entry_fn entry)
{
	int len, i, nr_threads;
	const struct fdt_property *prop;
	u32 *threads;

	/* Get the id array of threads on this cpu_node */
	prop = fdt_get_property(dt_fdt(), cpu_node,
				"ibm,ppc-interrupt-server#s", &len);
	assert(prop);

	nr_threads = len >> 2; /* Divide by 4 since 4 bytes per thread */

	threads = (u32 *)prop->data; /* Array of valid ids */

	for (i = 0; i < nr_threads; i++)
		start_thread(fdt32_to_cpu(threads[i]), entry);
}

static void start_each_secondary(int fdtnode, u64 regval __unused, void *info)
{
	struct secondary_entry_data *datap = info;

	start_core(fdtnode, datap->entry);
}

/*
 * Start all stopped cpus on the guest at entry with register 3 set to r3
 * We expect that we come in with only one thread currently started
 * Returns:	TRUE on success
 *		FALSE on failure
 */
bool start_all_cpus(secondary_entry_fn entry)
{
	struct secondary_entry_data data = { entry };
	uint64_t tb;
	int ret;

	assert(nr_cpus_online == 1);
	assert(nr_started == 1);
	ret = dt_for_each_cpu_node(start_each_secondary, &data);
	assert(ret == 0);
	assert(nr_started == nr_cpus_present);

	tb = get_tb();
	while (nr_cpus_online < nr_cpus_present) {
		if (get_tb() - tb > 3*tb_hz) {
			printf("failed to start all secondaries\n");
			assert(0);
		}
		cpu_relax();
	}

	return 1;
}

/*
 * Start stopped thread cpu_id at entry
 * Returns:	<0 on failure to start stopped cpu
 *		0  on success
 *		>0 on cpu not in stopped state
 */
static int wait_thread(int cpu_id)
{
	uint64_t tb;

	/* Skip the caller */
	if (cpu_id == smp_processor_id()) {
		return 0;
	}

	tb = get_tb();
	while (cpu_is_running(cpu_id)) {
		if (get_tb() - tb > 3*tb_hz) {
			printf("Timeout waiting to stop CPU:%d\n", cpu_id);
			return 1;
		}
	}

	return 0;
}

/*
 * Wait for running threads (vcpus) on cpu_node to stop
 */
static void wait_core(int cpu_node)
{
	int len, i, nr_threads;
	const struct fdt_property *prop;
	u32 *threads;

	/* Get the id array of threads on this cpu_node */
	prop = fdt_get_property(dt_fdt(), cpu_node,
				"ibm,ppc-interrupt-server#s", &len);
	assert(prop);

	nr_threads = len >> 2; /* Divide by 4 since 4 bytes per thread */

	threads = (u32 *)prop->data; /* Array of valid ids */

	for (i = 0; i < nr_threads; i++)
		wait_thread(fdt32_to_cpu(threads[i]));
}

static void wait_each_secondary(int fdtnode, u64 regval __unused, void *info)
{
	wait_core(fdtnode);
}

void stop_all_cpus(void)
{
	while (nr_cpus_online > 1)
		cpu_relax();

	dt_for_each_cpu_node(wait_each_secondary, NULL);
	mb();
	nr_started = 1;
}
