#include "libcflat.h"
#include "acpi.h"

#ifdef CONFIG_EFI
struct rsdp_descriptor *efi_rsdp = NULL;

void set_efi_rsdp(struct rsdp_descriptor *rsdp)
{
	efi_rsdp = rsdp;
}

static struct rsdp_descriptor *get_rsdp(void)
{
	if (efi_rsdp == NULL) {
		printf("Can't find RSDP from UEFI, maybe set_efi_rsdp() was not called\n");
	}
	return efi_rsdp;
}
#else
static struct rsdp_descriptor *get_rsdp(void)
{
	struct rsdp_descriptor *rsdp;
	unsigned long addr;

	for (addr = 0xe0000; addr < 0x100000; addr += 16) {
		rsdp = (void *)addr;
		if (rsdp->signature == RSDP_SIGNATURE_8BYTE)
			break;
	}

	if (addr == 0x100000) {
		return NULL;
	}

	return rsdp;
}
#endif /* CONFIG_EFI */

void *find_acpi_table_addr(u32 sig)
{
	struct rsdp_descriptor *rsdp;
	struct rsdt_descriptor_rev1 *rsdt;
	void *end;
	int i;

	/* FACS is special... */
	if (sig == FACS_SIGNATURE) {
		struct fadt_descriptor_rev1 *fadt;
		fadt = find_acpi_table_addr(FACP_SIGNATURE);
		if (!fadt)
			return NULL;

		return (void *)(ulong) fadt->firmware_ctrl;
	}

	rsdp = get_rsdp();
	if (rsdp == NULL) {
		printf("Can't find RSDP\n");
		return NULL;
	}

	if (sig == RSDP_SIGNATURE)
		return rsdp;

	rsdt = (void *)(ulong) rsdp->rsdt_physical_address;
	if (!rsdt || rsdt->signature != RSDT_SIGNATURE)
		return NULL;

	if (sig == RSDT_SIGNATURE)
		return rsdt;

	end = (void *)rsdt + rsdt->length;
	for (i = 0; (void *)&rsdt->table_offset_entry[i] < end; i++) {
		struct acpi_table *t = (void *)(ulong) rsdt->table_offset_entry[i];
		if (t && t->signature == sig) {
			return t;
		}
	}
	return NULL;
}
