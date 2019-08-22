#include "fwcfg.h"
#include "smp.h"
#include "libcflat.h"

static struct spinlock lock;

static long fw_override[FW_CFG_MAX_ENTRY];
static bool fw_override_done;

bool no_test_device;

static void read_cfg_override(void)
{
	const char *str;
	int i;

	/* Initialize to negative value that would be considered as invalid */
	for (i = 0; i < FW_CFG_MAX_ENTRY; i++)
		fw_override[i] = -1;

	if ((str = getenv("NR_CPUS")))
		fw_override[FW_CFG_NB_CPUS] = atol(str);

	/* MEMSIZE is in megabytes */
	if ((str = getenv("MEMSIZE")))
		fw_override[FW_CFG_RAM_SIZE] = atol(str) * 1024 * 1024;

	if ((str = getenv("TEST_DEVICE")))
		no_test_device = !atol(str);

    fw_override_done = true;
}

static uint64_t fwcfg_get_u(uint16_t index, int bytes)
{
    uint64_t r = 0;
    uint8_t b;
    int i;

    if (!fw_override_done)
        read_cfg_override();

    if (index < FW_CFG_MAX_ENTRY && fw_override[index] >= 0)
	    return fw_override[index];

    spin_lock(&lock);
    asm volatile ("out %0, %1" : : "a"(index), "d"((uint16_t)BIOS_CFG_IOPORT));
    for (i = 0; i < bytes; ++i) {
        asm volatile ("in %1, %0" : "=a"(b) : "d"((uint16_t)(BIOS_CFG_IOPORT + 1)));
        r |= (uint64_t)b << (i * 8);
    }
    spin_unlock(&lock);
    return r;
}

uint8_t fwcfg_get_u8(unsigned index)
{
    return fwcfg_get_u(index, 1);
}

uint16_t fwcfg_get_u16(unsigned index)
{
    return fwcfg_get_u(index, 2);
}

uint32_t fwcfg_get_u32(unsigned index)
{
    return fwcfg_get_u(index, 4);
}

uint64_t fwcfg_get_u64(unsigned index)
{
    return fwcfg_get_u(index, 8);
}

unsigned fwcfg_get_nb_cpus(void)
{
    return fwcfg_get_u16(FW_CFG_NB_CPUS);
}
