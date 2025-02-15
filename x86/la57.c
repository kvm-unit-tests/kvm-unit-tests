#include "libcflat.h"
#include "processor.h"
#include "desc.h"

int main(int ac, char **av)
{
	int vector = write_cr4_safe(read_cr4() | X86_CR4_LA57);
	bool is_64bit = rdmsr(MSR_EFER) & EFER_LMA;
	int expected = !is_64bit && this_cpu_has(X86_FEATURE_LA57) ? 0 : GP_VECTOR;

	report(vector == expected, "%s when CR4.LA57 %ssupported (in %u-bit mode)",
	       expected ? "#GP" : "No fault",
	       this_cpu_has(X86_FEATURE_LA57) ? "un" : "", is_64bit ? 64 : 32);

	return report_summary();
}
