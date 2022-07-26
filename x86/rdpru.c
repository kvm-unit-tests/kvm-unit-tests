/* RDPRU test */

#include "libcflat.h"
#include "processor.h"
#include "desc.h"

static int rdpru_safe(void)
{
	asm volatile (ASM_TRY("1f")
		      ".byte 0x0f,0x01,0xfd \n\t" /* rdpru */
		      "1:" : : "c" (0) : "eax", "edx");
	return exception_vector();
}

int main(int ac, char **av)
{
	if (this_cpu_has(X86_FEATURE_RDPRU))
		report_skip("RDPRU raises #UD");
	else
		report(rdpru_safe() == UD_VECTOR, "RDPRU raises #UD");

	return report_summary();
}
