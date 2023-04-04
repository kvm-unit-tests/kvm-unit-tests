#include "libcflat.h"
#include "processor.h"
#include "x86/vm.h"
#include "access.h"

int main(void)
{
	int r;

	printf("starting test\n\n");
	r = ac_test_run(PT_LEVEL_PML4);

#ifndef CONFIG_EFI
	/*
	* Not supported yet for UEFI, because setting up 5
	* level page table requires entering real mode.
	*/
	if (this_cpu_has(X86_FEATURE_LA57)) {
		printf("starting 5-level paging test.\n\n");
		setup_5level_page_table();
		r = ac_test_run(PT_LEVEL_PML5);
	}
#endif

	return r ? 0 : 1;
}
