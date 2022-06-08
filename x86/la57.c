#include "libcflat.h"
#include "processor.h"
#include "desc.h"

int main(int ac, char **av)
{
	int vector = write_cr4_safe(read_cr4() | X86_CR4_LA57);
	int expected = this_cpu_has(X86_FEATURE_LA57) ? 0 : 13;

	report(vector == expected, "%s when CR4.LA57 %ssupported",
	       expected ? "#GP" : "No fault", expected ? "un" : "");
	return report_summary();
}
